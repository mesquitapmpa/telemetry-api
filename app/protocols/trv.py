# app/protocols/trv_gt06.py
import asyncio
import struct
import binascii
import logging
import os
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
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"  # habilita logs no estilo antigo (RX proto=..., TX_ACK=...)

# ============================================================
# Helpers de log legado
# ============================================================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ============================================================
# Checksums
# ============================================================
def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (refletido), init=0xFFFF, xorout=0xFFFF (endianness de campo: big-endian).
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc = ~crc & 0xFFFF
    # muitos firmwares esperam o campo em big-endian; retornamos já como inteiro "normal"
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================================================
# ACK (espelha checksum/serial)
# ============================================================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    """
    Monta ACK no formato do header recebido (0x7878 ou 0x7979) e mesmo modo de checksum.
    - Para CRC16: length = type(1) + serial(2) + CRC(2)
    - Para SUM-8: length = type(1) + serial(2) + SUM(1)
    """
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"

    # normaliza serial (muitos dispositivos esperam 2 bytes em ACK)
    serial = serial_bytes or b""
    if len(serial) == 0:
        serial = b"\x00\x00"
    elif len(serial) == 1:
        serial = b"\x00" + serial
    else:
        serial = serial[-2:]  # garante 2 bytes

    body_wo_chk = bytes([msg_type]) + serial

    if checksum_mode == "CRC16":
        length = 1 + len(serial) + 2
        pkt_wo_crc = hdr + bytes([length]) + body_wo_chk
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM-8
    length = 1 + len(serial) + 1
    pkt_wo_sum = hdr + bytes([length]) + body_wo_chk
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

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    payload do LOGIN (sem o byte de 'type' 0x01).
    Suporta:
      - 0x08 + 8 bytes BCD (padrão GT06)
      - 0x0F + 15 bytes ASCII
      - fallback: varrer janelas de 8 bytes plausíveis
    """
    if not payload:
        return None

    # ASCII 15 (0x0F)
    if len(payload) >= 1 and payload[0] == 0x0F and len(payload) >= 1 + 15:
        try:
            s = payload[1:1+15].decode()
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass

    # BCD 8 (0x08)
    if len(payload) >= 1 and payload[0] == 0x08 and len(payload) >= 1 + 8:
        s = decode_bcd_imei(payload[1:1+8])
        s = s[:15]
        if s.isdigit() and len(s) == 15:
            return s

    # Fallback: varrer janelas de 8 bytes
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei(payload[i:i+8])[:15]
        if s.isdigit() and len(s) == 15:
            return s
    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    GPS básico GT06 (0x10/0x11/0x12):
      [time6][flags1][lat4][lon4][speed1][course2]
    - lat/lon vêm SEM sinal; hemisfério está nos bits 12/13 do campo course/status.
    - bit11 => GPS fix (1=fixed)
    - bit12 => 1=West (lon negativa)
    - bit13 => 1=South (lat negativa)
    """
    if len(payload) < 6+1+4+4+1+2:
        return None

    dt = parse_datetime_bcd(payload[0:6])

    # flags1 (nem sempre usado; alguns firmwares colocam outras infos aqui)
    # Não confiamos nesse bit para 'valid'; usamos bit11 do course/status (padrão GT06)
    # flags = payload[6]

    lat_raw = int.from_bytes(payload[7:11], "big", signed=False)
    lon_raw = int.from_bytes(payload[11:15], "big", signed=False)
    speed_kmh = payload[15] * 1.852

    course_flags = struct.unpack(">H", payload[16:18])[0]
    course = float(course_flags & 0x03FF)
    gps_fixed = bool(course_flags & (1 << 11))
    west = bool(course_flags & (1 << 12))
    south = bool(course_flags & (1 << 13))

    lat = lat_raw / 1800000.0
    lon = lon_raw / 1800000.0
    if south:
        lat = -lat
    if west:
        lon = -lon

    return {
        "time": dt,
        "lat": lat,
        "lon": lon,
        "speed_kmh": speed_kmh,
        "course": course,
        "valid": gps_fixed,
        "raw_flags": course_flags,
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
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]  # inclui serial ao final (se houver)
            return ("CRC16", serial, payload_full)

    # 2) Tentar SUM-8: último byte é soma
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-1]
        if sum8(candidate[2:]) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b""
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    # 3) Degrada (frames ultra-curtos / keepalive mínimo)
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
    """
    LOGIN GT06 (type 0x01).
    payload pode vir como:
      0x08 <8 bytes BCD IMEI> [ ... ]
      0x0F <15 ASCII IMEI>    [ ... ]
    """
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei and imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido/decodificável; sessão sem device. peer=%s", peer)
        return

    device = await ensure_device_canonical("gt06", imei)
    if device:
        state.device = {"id": device.get("id"), "imei": device.get("imei")}
        logger.info("[GT06] LOGIN OK: device_id=%s imei=%s peer=%s",
                    state.device['id'], state.device['imei'], peer)
    else:
        logger.warning("[GT06] LOGIN com IMEI válido, mas sem device canônico. peer=%s", peer)

async def handle_gps(payload: bytes, raw_frame_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning("[GT06] GPS payload curto/indecifrável: %s",
                       binascii.hexlify(payload).decode().upper())
        return

    # Garante device canônico (se pulou login)
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) >= 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                state.device = {"id": dev.get("id"), "imei": dev.get("imei")}
        except Exception:
            pass

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição para evitar IMEI curto.")
        return

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
    logger.info("[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1fkm/h curso=%.1f valid=%s",
                state.device['id'], gps['lat'], gps['lon'], gps['speed_kmh'], gps['course'], gps['valid'])

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
        # Pode ser lixo/ASCII — tenta consumir até CRLF só pra limpar
        try:
            line = hdr + await reader.readuntil(b"\x0D\x0A")
            logger.debug("[GT06] ASCII? %r", line)
        except Exception:
            pass
        return

    length_b = await read_exact(reader, 1)
    length = length_b[0]

    # type + payload + checksum(?) + CRLF (2)
    body_and_footer = await read_exact(reader, length + 2)

    raw = hdr + length_b + body_and_footer
    raw_hex = binascii.hexlify(raw).decode().upper()

    # Log estilo legado do pacote bruto (CHUNK ...)
    if LOG_LEGACY:
        try:
            logger.info("[GT06] CHUNK %dB from %s: %s", len(raw), peer, _hex_spaced(raw))
        except Exception:
            pass

    checksum_mode, serial_bytes, payload_full = detect_checksum_and_serial(hdr, length, body_and_footer)
    if not payload_full:
        return

    msg_type = payload_full[0]
    payload = payload_full[1:]

    # Logs RX/ACK (atuais)
    logger.info("[GT06] RX type=0x%02X len=%d chk=%s serial=%s",
                msg_type, length, checksum_mode, binascii.hexlify(serial_bytes).decode().upper() or "∅")

    # ACK imediato
    ack = build_ack(0x7878 if hdr == b"\x78\x78" else 0x7979, msg_type, serial_bytes, checksum_mode)
    writer.write(ack)
    await writer.drain()
    ack_hex = binascii.hexlify(ack).decode().upper()
    logger.info("[GT06] TX_ACK=%s", ack_hex)

    # Logs no estilo legado adicionais
    if LOG_LEGACY:
        cs_len = 1 if checksum_mode == "SUM8" else 2
        # aproximação do body "útil": length - (type + serial + checksum)
        body_len = max(0, length - (1 + len(serial_bytes or b"\x00\x00") + cs_len))
        mode = "SUM" if checksum_mode == "SUM8" else "CRC16"
        logger.info("[GT06] RX proto=0x%02X body_len=%d cs_len=%d from=%s", msg_type, body_len, cs_len, peer)
        logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)

        # STATUS extra
        if msg_type == 0x13:
            payload_wo_serial = payload[:-len(serial_bytes)] if (len(serial_bytes) and len(payload) >= len(serial_bytes)) else payload
            logger.info("[GT06] STATUS(0x13) payload=%s serial=%s",
                        _hex_spaced(payload_wo_serial) or "∅",
                        binascii.hexlify(serial_bytes).decode().upper() or "∅")

        # keepalive curtíssimo (alguns clones mandam 0x08 sem payload)
        if msg_type == 0x08 and length <= (1 + cs_len):
            logger.info("[GT06] SHORT(min) proto=0x08 TX_ACK=%s (mode=%s)", _hex_spaced(ack), mode)

    # Opcional: validar checksum (já foi validado na detecção)
    if VALIDATE_GT06_CRC:
        pass

    # Dispatch
    if msg_type == 0x01:
        await handle_login(payload, peer, state)
        return

    if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
        await handle_gps(payload, raw_hex, state)
        return

    if msg_type in (0x13, 0x08):  # STATUS/KEEPALIVE
        return

    logger.debug("[GT06] Tipo 0x%02X não tratado. payload=%s",
                 msg_type, binascii.hexlify(payload).decode().upper())

# ============================================================
# Server
# ============================================================
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()
    try:
        while True:
            await process_frame(reader, writer, str(peer), state)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception as e:
        logger.exception("[GT06] erro: %s", e)
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