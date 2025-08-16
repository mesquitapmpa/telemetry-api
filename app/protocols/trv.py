# app/protocols/trv_gt06.py
import asyncio
import struct
import binascii
import logging
import os
import inspect
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

# Flags de depuração / validação
VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"  # logs estilo antigo

# ============================================================
# Helpers de log legado
# ============================================================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ============================================================
# Checksums (GT06)
# ============================================================
def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (refletido), init=0xFFFF, xorout=0xFFFF.
    Retorna inteiro já no 'byte order' esperado para empacotar em big-endian (>H).
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
    # inversão para combinar com muitos firmwares GT06
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================================================
# ACK (espelha cabeçalho e modo de checksum)
# ============================================================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    """
    Monta ACK com o mesmo header (0x7878/0x7979) e modo de checksum detectado.
    - CRC16: len = type(1) + serial(2) + CRC(2)
    - SUM8 : len = type(1) + serial(2) + SUM(1)
    - TRUNC: usa SUM8 com serial zerado (tolerante)
    """
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"

    # normaliza serial para 2 bytes
    serial = serial_bytes or b""
    if len(serial) == 0:
        serial = b"\x00\x00"
    elif len(serial) == 1:
        serial = b"\x00" + serial
    else:
        serial = serial[-2:]

    body_wo_chk = bytes([msg_type]) + serial

    if checksum_mode == "CRC16":
        length = 1 + len(serial) + 2
        pkt_wo_crc = hdr + bytes([length]) + body_wo_chk
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM8 ou TRUNC -> responde com SUM8
    length = 1 + len(serial) + 1
    pkt_wo_sum = hdr + bytes([length]) + body_wo_chk
    cs = sum8(pkt_wo_sum[2:])
    return pkt_wo_sum + bytes([cs]) + b"\x0D\x0A"

# ============================================================
# Utils (tempo / IMEI / GPS)
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
    # 8 bytes BCD => 16 dígitos; removemos zeros à esquerda e mantemos 15 dígitos
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd)
    return s.lstrip('0')[:15]

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    payload do LOGIN (sem o byte type=0x01).
      - 0x08 + 8 bytes BCD
      - 0x0F + 15 bytes ASCII
      - fallback: varre janelas de 8 bytes plausíveis
    """
    if not payload:
        return None

    # ASCII (0x0F + 15)
    if payload[0:1] == b"\x0F" and len(payload) >= 16:
        try:
            s = payload[1:16].decode()
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass

    # BCD (0x08 + 8)
    if payload[0:1] == b"\x08" and len(payload) >= 9:
        s = decode_bcd_imei(payload[1:9])
        if s.isdigit() and len(s) == 15:
            return s

    # Fallback: varrer janelas de 8 bytes
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei(payload[i:i+8])
        if s.isdigit() and len(s) == 15:
            return s
    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    Mensagem básica de posição (0x10/0x11/0x12):
      [time6][flags1][lat4][lon4][speed1][course2]
    - lat/lon sem sinal; sinais nos bits do campo course:
      bit11 => GPS fix
      bit12 => 1=West (lon negativa)
      bit13 => 1=South (lat negativa)
    """
    if len(payload) < 6+1+4+4+1+2:
        return None

    dt = parse_datetime_bcd(payload[0:6])

    lat_raw = int.from_bytes(payload[7:11], "big", signed=False)
    lon_raw = int.from_bytes(payload[11:15], "big", signed=False)
    speed_kmh = float(payload[15]) * 1.852

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
# Deframer / detector de checksum e serial
# ============================================================
def detect_checksum_and_serial(hdr: bytes, length: int, body_and_footer: bytes) -> Tuple[str, bytes, bytes]:
    """
    Retorna (checksum_mode, serial_bytes, payload_full)
    payload_full = [type(1)] + [payload ... (+ possivel serial antes do checksum)]
    checksum_mode ∈ {"CRC16", "SUM8", "TRUNC"}
    """
    # Esperamos ... [type + payload + (checksum?) + 0D 0A]
    if len(body_and_footer) < 1 + 2:
        return ("TRUNC", b"", b"")
    if body_and_footer[-2:] != b"\x0D\x0A":
        return ("TRUNC", b"", b"")

    core = body_and_footer[:-2]  # remove CRLF
    if len(core) < 1:
        return ("TRUNC", b"", b"")

    msg_type_b = core[:1]
    rest = core[1:]

    # 1) Tenta CRC16 (últimos 2 bytes)
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-2]
        crc_calc = crc16_x25(candidate[2:])
        if crc_calc == crc_recv:
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]  # inclui serial no final, se houver
            return ("CRC16", serial, payload_full)

    # 2) Tenta SUM-8 (último byte)
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-1]
        if sum8(candidate[2:]) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    # 3) TRUNC (sem checksum válido) — ainda assim seguimos em frente
    return ("TRUNC", b"", msg_type_b + rest)

# ============================================================
# Sessão por conexão
# ============================================================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None  # {"id":..., "imei":...}
        self.imei_seen: Optional[str] = None

def _device_as_dict(dev: Any) -> Optional[Dict[str, Any]]:
    """
    Converte o retorno de ensure_device_canonical em dict padronizado.
    Aceita objetos com atributos ('id', 'imei') ou dicts.
    """
    if dev is None:
        return None
    if isinstance(dev, dict):
        dev_id = dev.get("id")
        dev_imei = dev.get("imei")
        if dev_id and dev_imei:
            return {"id": dev_id, "imei": dev_imei}
        return None
    dev_id = getattr(dev, "id", None)
    dev_imei = getattr(dev, "imei", None)
    if dev_id and dev_imei:
        return {"id": dev_id, "imei": dev_imei}
    return None

# ============================================================
# Adaptador de compatibilidade para save_position
# ============================================================
def _normalize_param_name(name: str) -> str:
    n = name.lower()
    aliases = {
        "imei": "imei",
        "device_id": "device_id",

        "latitude": "lat", "lat": "lat",
        "longitude": "lon", "lng": "lon", "long": "lon",

        "fix_time": "fix_time", "fixtime": "fix_time", "time": "fix_time", "dt": "fix_time",

        "speed_knots": "speed_knots", "speed": "speed_knots", "spd": "speed_knots",
        "speed_kmh": "speed_kmh",

        "course": "course_deg", "course_deg": "course_deg", "heading": "course_deg",

        "valid": "valid",
        "raw": "raw",
    }
    return aliases.get(n, n)

async def _call_maybe_async(fn, *args, **kwargs):
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return await res
    return res

async def _save_position_compat(state_device: Dict[str, Any], gps: Dict[str, Any], raw_hex: str):
    """
    Chama save_position aceitando:
      - kwargs (lat/lon/fix_time/...) com 'device_id' ou 'imei'
      - forma posicional clássica: (imei, lat, lon, fix_time, speed_knots, course_deg, valid, raw)
    """
    imei = state_device.get("imei")
    dev_id = state_device.get("id")

    fix_time = gps["time"]
    lat = float(gps["lat"])
    lon = float(gps["lon"])
    speed_kmh = float(gps["speed_kmh"])
    speed_knots = speed_kmh * 0.539957
    course_deg = float(gps["course"])
    valid = bool(gps["valid"])

    # 1) Tenta por nomes (inspecionando a assinatura)
    try:
        sig = inspect.signature(save_position)
        params = list(sig.parameters.keys())
        kw = {}
        for p in params:
            pn = _normalize_param_name(p)
            if pn == "device_id" and dev_id:
                kw[p] = dev_id
            elif pn == "imei" and imei:
                kw[p] = imei
            elif pn == "lat":
                kw[p] = lat
            elif pn == "lon":
                kw[p] = lon
            elif pn == "fix_time":
                kw[p] = fix_time
            elif pn == "speed_knots":
                kw[p] = speed_knots
            elif pn == "speed_kmh":
                kw[p] = speed_kmh
            elif pn == "course_deg":
                kw[p] = course_deg
            elif pn == "valid":
                kw[p] = valid
            elif pn == "raw":
                kw[p] = raw_hex
        if kw:
            return await _call_maybe_async(save_position, **kw)
    except Exception:
        pass

    # 2) Fallback posicional clássico
    return await _call_maybe_async(
        save_position,
        imei,        # 1º
        lat,         # 2º
        lon,         # 3º
        fix_time,    # 4º
        speed_knots, # 5º
        course_deg,  # 6º
        valid,       # 7º
        raw_hex,     # 8º
    )

# ============================================================
# Handlers
# ============================================================
async def handle_login(payload: bytes, raw_hex: str, peer: str, state: ConnState):
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei and imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido/decodificável; sessão sem device. peer=%s", peer)
        return

    dev = await ensure_device_canonical("gt06", imei)
    devd = _device_as_dict(dev)
    if devd:
        state.device = devd
        logger.info("[GT06] LOGIN OK: device_id=%s imei=%s peer=%s",
                    state.device['id'], state.device['imei'], peer)
    else:
        logger.warning("[GT06] LOGIN com IMEI válido, mas sem device canônico. peer=%s", peer)

async def handle_gps(payload: bytes, raw_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning("[GT06] GPS payload curto/indecifrável: %s",
                       binascii.hexlify(payload).decode().upper())
        return

    # Se pulou login, tenta garantir o device pela última IMEI vista
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            devd = _device_as_dict(dev)
            if devd:
                state.device = devd
        except Exception:
            pass

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição.")
        return

    await _save_position_compat(state.device, gps, raw_hex)

    logger.info(
        "[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1f km/h curso=%.1f valid=%s",
        state.device["id"], gps["lat"], gps["lon"], gps["speed_kmh"], gps["course"], gps["valid"]
    )

# ============================================================
# Frame loop (deframer por conexão)
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
    # Cabeçalho: 0x78 0x78 ou 0x79 0x79
    hdr = await read_exact(reader, 2)
    if hdr not in (b"\x78\x78", b"\x79\x79"):
        # Pode ter vindo lixo/ASCII – tenta consumir até CRLF
        try:
            line = hdr + await reader.readuntil(b"\x0D\x0A")
            if LOG_LEGACY:
                logger.debug("[GT06] ASCII? %r", line)
        except Exception:
            pass
        return

    length_b = await read_exact(reader, 1)
    length = length_b[0]

    # (type + payload + checksum?) + CRLF (2)
    body_and_footer = await read_exact(reader, length + 2)
    raw = hdr + length_b + body_and_footer
    raw_hex = binascii.hexlify(raw).decode().upper()

    # Log estilo legado do pacote bruto
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

    # Logs (atuais)
    logger.info("[GT06] RX type=0x%02X len_byte=%d chk=%s serial=%s",
                msg_type, length, checksum_mode, binascii.hexlify(serial_bytes).decode().upper() or "∅")

    # Logs no estilo legado
    if LOG_LEGACY:
        cs_len = 0 if checksum_mode == "TRUNC" else (1 if checksum_mode == "SUM8" else 2)
        # aproxima body útil: length - (type + serial(2?) + checksum)
        ser_len = 2 if len(serial_bytes) else 0
        body_len_approx = max(0, length - (1 + ser_len + (0 if checksum_mode == "TRUNC" else cs_len)))
        logger.info("[GT06] RX proto=0x%02X body_len~%d cs_len=%d from=%s",
                    msg_type, body_len_approx, cs_len, peer)

    # ACK imediato
    ack = build_ack(0x7878 if hdr == b"\x78\x78" else 0x7979, msg_type, serial_bytes, checksum_mode)
    writer.write(ack)
    await writer.drain()
    if LOG_LEGACY:
        mode = "TRUNC" if checksum_mode == "TRUNC" else ("SUM" if checksum_mode == "SUM8" else "CRC16")
        logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)
    logger.info("[GT06] TX_ACK=%s", binascii.hexlify(ack).decode().upper())

    # Opcional: validação (já feita no detector)
    if VALIDATE_GT06_CRC:
        pass

    # Dispatch
    if msg_type == 0x01:                     # LOGIN
        await handle_login(payload, raw_hex, peer, state)
        return

    if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):  # POSIÇÃO
        await handle_gps(payload, raw_hex, state)
        return

    if msg_type in (0x13, 0x08):             # STATUS/KEEPALIVE
        return

    # Outros tipos
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