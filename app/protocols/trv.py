# app/protocols/trv_gt06.py
import asyncio, struct, binascii, logging, os
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

from app.usecases.save_position import save_position
from app.usecases.device_helpers import ensure_device_canonical

logger = logging.getLogger("trv_gt06")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"  # <- habilita logs no estilo antigo

# ============================================================
# Helpers de log legado
# ============================================================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ============================================================
# Checksums
# ============================================================
def crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc = ~crc & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================================================
# ACK (espelha checksum/serial)
# ============================================================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"
    # Normalize serial para 0/1/2 bytes conforme recebido (usamos como veio)
    serial = serial_bytes or b""
    body = bytes([msg_type]) + serial

    if checksum_mode == "CRC16":
        # para compatibilidade, garantir 2 bytes de serial
        if len(serial) == 0:
            serial = b"\x00\x00"
        elif len(serial) == 1:
            serial = b"\x00" + serial
        body = bytes([msg_type]) + serial
        length = 1 + len(serial) + 2  # type + serial(2) + crc(2)
        pkt_wo_crc = hdr + bytes([length]) + body
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM-8 (1 byte)
    length = 1 + len(serial) + 1  # type + serial + sum8
    pkt_wo_sum = hdr + bytes([length]) + body
    cs = sum8(pkt_wo_sum[2:])
    return pkt_wo_sum + bytes([cs]) + b"\x0D\x0A"

# ============================================================
# Utils
# ============================================================
def parse_datetime_bcd(dt6: bytes) -> datetime:
    if len(dt6) < 6:
        return datetime.now(timezone.utc)
    yy, mm, dd, hh, mi, ss = dt6[:6]
    year = 2000 + (yy % 100)
    try:
        return datetime(year, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def decode_bcd_imei(imei_bcd: bytes) -> str:
    # IMEI como BCD (8 bytes => 16 dígitos)
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd)
    return s.lstrip('0')

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    # [time6][flags1][lat4][lon4][speed1][course2]
    if len(payload) < 6+1+4+4+1+2:
        return None
    dt = parse_datetime_bcd(payload[0:6])
    flags = payload[6]
    lat_raw = struct.unpack(">i", payload[7:11])[0]
    lon_raw = struct.unpack(">i", payload[11:15])[0]
    speed = payload[15]
    course = struct.unpack(">H", payload[16:18])[0]
    valid = (flags & 0x80) != 0
    return {
        "time": dt,
        "lat": lat_raw / 1800000.0,
        "lon": lon_raw / 1800000.0,
        "speed_kmh": speed * 1.852,
        "course": course & 0x03FF,
        "valid": valid,
        "raw_flags": flags,
    }

# ============================================================
# Detector de checksum/serial
# ============================================================
def detect_checksum_and_serial(hdr: bytes, length: int, body_and_footer: bytes) -> Tuple[str, bytes, bytes]:
    """
    Retorna (checksum_mode, serial_bytes, payload_full)
    payload_full = [type(1)] + [payload... (+ possivel serial dentro)]
    """
    if len(body_and_footer) < 1 + 2:  # pelo menos type + CRLF
        return ("SUM8", b"", b"")

    if body_and_footer[-2:] != b"\x0D\x0A":
        return ("SUM8", b"", b"")

    core = body_and_footer[:-2]  # remove CRLF
    msg_type_b = core[:1]
    rest = core[1:]

    # 1) Tentar CRC16: últimos 2 bytes são CRC
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-2]
        crc_calc = crc16_x25(candidate[2:])
        if crc_calc == crc_recv:
            # serial = 2 bytes anteriores ao crc, se houver
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]  # inclui serial no final do payload; o parser que se vire
            return ("CRC16", serial, payload_full)

    # 2) Tentar SUM-8: último byte é soma
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-1]
        if sum8(candidate[2:]) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b""
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    # 3) Degrada (frames ultra-curtos)
    return ("SUM8", b"", msg_type_b + rest)

# ============================================================
# Sessão por conexão (armazenar device canônico pós-login)
# ============================================================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None  # {"id":..., "imei":...}
        self.imei_seen: Optional[str] = None

# ============================================================
# Handlers
# ============================================================
async def handle_login(payload: bytes, peer: str, state: ConnState):
    # LOGIN curto/long: geralmente 8 bytes BCD IMEI no início
    imei = decode_bcd_imei(payload[:8]) if len(payload) >= 8 else ""
    state.imei_seen = imei or state.imei_seen

    if not imei:
        logger.warning(f"[GT06] LOGIN sem IMEI decodificável (peer={peer})")
        return

    # 🔒 Rejeita IMEI inválido/curto antes de garantir
    if not imei.isdigit() or len(imei) < 15:
        msg = "[GT06] LOGIN (curto) — IMEI inválido/curto; sessão sem device."
        if LOG_LEGACY:
            logger.info(msg)
        else:
            logger.warning(msg)
        return

    device = await ensure_device_canonical("gt06", imei)
    if device:
        state.device = {"id": device.get("id"), "imei": device.get("imei")}
        logger.info(f"[GT06] LOGIN OK: device_id={state.device['id']} imei={state.device['imei']} peer={peer}")
    else:
        logger.warning(f"[GT06] LOGIN sem device canônico (IMEI válido). peer={peer}")

async def handle_gps(payload: bytes, raw_frame_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning(f"[GT06] GPS payload curto/indecifrável: {binascii.hexlify(payload).decode().upper()}")
        return

    # Garantir device canônico na sessão; se não houver (ex.: pulou login), tente via IMEI visto
    if not state.device:
        if state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) >= 15:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                state.device = {"id": dev.get("id"), "imei": dev.get("imei")}

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição para evitar IMEI curto.")
        return

    # Salvar por device_id (evita criação por IMEI dentro do save_position)
    payload_to_save = {
        "protocol": "gt06",
        "device_id": state.device["id"],
        "time": gps["time"].isoformat(),
        "lat": gps["lat"],
        "lon": gps["lon"],
        "speed_kmh": gps["speed_kmh"],
        "course": gps["course"],
        "valid": gps["valid"],
        "raw": raw_frame_hex,
    }
    await save_position(payload_to_save)
    logger.info(f"[GT06] POS salva device_id={state.device['id']} lat={gps['lat']:.6f} lon={gps['lon']:.6f} v={gps['speed_kmh']:.1f}")

# ============================================================
# Frame loop
# ============================================================
async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            raise asyncio.IncompleteReadError(buf, n)
        buf += chunk
    return buf

async def process_frame(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: str, state: ConnState):
    hdr = await read_exact(reader, 2)
    if hdr not in (b"\x78\x78", b"\x79\x79"):
        # Pode ser resposta ASCII
        try:
            line = hdr + await reader.readuntil(b"\x0D\x0A")
            logger.debug(f"[GT06] ASCII? {line!r}")
        except Exception:
            pass
        return

    length = (await read_exact(reader, 1))[0]
    body_and_footer = await read_exact(reader, length + 2)  # type+payload+checksum(?) + CRLF

    raw = hdr + bytes([length]) + body_and_footer
    raw_hex = binascii.hexlify(raw).decode().upper()

    # Log estilo legado do pacote bruto (CHUNK ...)
    if LOG_LEGACY:
        try:
            logger.info(f"[GT06] CHUNK {len(raw)}B from {peer}: {_hex_spaced(raw)}")
        except Exception:
            pass

    checksum_mode, serial_bytes, payload_full = detect_checksum_and_serial(hdr, length, body_and_footer)
    msg_type = payload_full[0] if payload_full else 0x00
    payload = payload_full[1:] if len(payload_full) > 1 else b""

    # Log estilo legado RX proto=... body_len=... cs_len=...
    if LOG_LEGACY:
        cs_len = 1 if checksum_mode == "SUM8" else 2
        body_len = max(0, length - (1 + cs_len + len(serial_bytes)))  # aprox. do corpo
        logger.info(f"[GT06] RX proto=0x{msg_type:02X} body_len={body_len} cs_len={cs_len} from={peer}")

    # ACK imediato
    ack = build_ack(0x7878 if hdr == b"\x78\x78" else 0x7979, msg_type, serial_bytes, checksum_mode)
    writer.write(ack)
    await writer.drain()

    # Logs atuais
    logger.info(f"[GT06] RX type=0x{msg_type:02X} len={length} chk={checksum_mode} serial={binascii.hexlify(serial_bytes).decode().upper() or '∅'}")
    ack_hex = binascii.hexlify(ack).decode().upper()
    logger.info(f"[GT06] TX_ACK={ack_hex}")

    # Logs no estilo legado adicionais
    if LOG_LEGACY:
        mode = "SUM" if checksum_mode == "SUM8" else "CRC16"
        logger.info(f"[GT06] 0x{msg_type:02X} TX_ACK={_hex_spaced(ack)} (mode={mode})")

        if msg_type == 0x13:
            payload_wo_serial = payload[:-len(serial_bytes)] if (len(serial_bytes) and len(payload) >= len(serial_bytes)) else payload
            logger.info(f"[GT06] STATUS(0x13) payload={_hex_spaced(payload_wo_serial) or '∅'} serial={binascii.hexlify(serial_bytes).decode().upper() or '∅'}")

        if msg_type == 0x08:
            # Heurística de keepalive mínimo
            cs_len = 1 if checksum_mode == "SUM8" else 2
            if length <= (1 + cs_len):
                logger.info(f"[GT06] SHORT(min) proto=0x08 TX_ACK={_hex_spaced(ack)} (mode={mode})")

    # Opcional: validar checksum (quando habilitado)
    if VALIDATE_GT06_CRC:
        # Já validamos no detector; aqui só logar se veio "degradado"
        pass

    # Dispatch
    if msg_type == 0x01:
        await handle_login(payload, peer, state)
        return

    if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
        await handle_gps(payload, raw_hex, state)
        return

    if msg_type in (0x13, 0x08):  # STATUS/KEEPALIVE
        # nada além do ACK
        return

    # Outros tipos: log e evolui sob demanda (alarmes, LBS-only, Wi-Fi, foto, etc.)
    logger.debug(f"[GT06] Tipo 0x{msg_type:02X} não tratado. payload={binascii.hexlify(payload).decode().upper()}")

# ============================================================
# Server
# ============================================================
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info(f"[TRV/GT06] Conexao de {peer}")
    state = ConnState()
    try:
        while True:
            await process_frame(reader, writer, str(peer), state)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception as e:
        logger.exception(f"[GT06] erro: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def run(port: int = 5010):
    server = await asyncio.start_server(gt06_server, "0.0.0.0", port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"[TRV/GT06] Servidor escutando em {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run(int(os.getenv("TRV_PORT", "5010"))))