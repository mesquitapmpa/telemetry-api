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

# ===== Config =====
VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"
# habilita logs no estilo antigo (para casar com seu grep: RX proto=..., POS ok, save_position falhou)
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "true").lower() == "true"

# ============================================================
# Helpers / checksums
# ============================================================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (reflected), init=0xFFFF, xorout=0xFFFF.
    Campo no frame é big-endian. O Java calcula exatamente assim.
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
    # retornar no “wire order” (big-endian quando empacotar)
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================================================
# ACK (mesma convenção do encoder Java/Traccar)
# ============================================================
def build_ack(header: bytes, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    """
    Header 0x7878 -> length de 1 byte; header 0x7979 -> length de 2 bytes.
    Para ambos os modos, o Java usa length == 0x0005 (type + serial + checksum).
    SUM-8: soma sobre [length + type + serial]
    CRC16: CRC sobre [length + type + serial] (e gravado em 2 bytes)
    """
    if header == b"\x79\x79":
        length_f = b"\x00\x05"   # 2 bytes
    else:
        length_f = b"\x05"       # 1 byte

    # normaliza serial em 2 bytes (muitos dispositivos esperam isso no ACK)
    serial = (serial_bytes or b"")[-2:].rjust(2, b"\x00")

    core = bytes([msg_type]) + serial
    pkt_wo_chk = header + length_f + core

    if checksum_mode == "CRC16" or header == b"\x79\x79":
        crc = crc16_x25(pkt_wo_chk[2:])  # igual ao Java: sem o header no cálculo
        return pkt_wo_chk + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM-8 (0x7878)
    cs = sum8(pkt_wo_chk[2:])
    return pkt_wo_chk + bytes([cs]) + b"\x0D\x0A"

# ============================================================
# Utils: datas/IMEI/GPS
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
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd)
    return s.lstrip('0')[:15]

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    payload do LOGIN (sem o byte de 'type' 0x01).
    GT06 real/Traccar suportam:
      - 0x08 + 8 bytes BCD (padrão)
      - 0x0F + 15 bytes ASCII
      - fallback varrendo janelas de 8 bytes BCD
    """
    if not payload:
        return None

    if payload[0:1] == b"\x0F" and len(payload) >= 1 + 15:
        try:
            s = payload[1:1+15].decode()
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass

    if payload[0:1] == b"\x08" and len(payload) >= 1 + 8:
        s = decode_bcd_imei(payload[1:1+8])
        if s.isdigit() and len(s) == 15:
            return s

    # fallback
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei(payload[i:i+8])
        if s.isdigit() and len(s) == 15:
            return s
    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    GPS básico GT06 (0x10/0x11/0x12):
      [time6][flags1][lat4][lon4][speed1][course2]
    - lat/lon: raw/1800000.0
    - course/status:
        bits 0..9  => curso
        bit 11     => GPS fix (1=fixed)
        bit 12     => 1=West (lon negativa)
        bit 13     => 1=South (lat negativa)
    """
    if len(payload) < 6+1+4+4+1+2:
        return None

    dt = parse_datetime_bcd(payload[0:6])

    # flags = payload[6]  # pouco confiável, clones variam; usamos o campo course/status
    lat_raw = int.from_bytes(payload[7:11], "big", signed=False)
    lon_raw = int.from_bytes(payload[11:15], "big", signed=False)
    speed_kmh = float(payload[15])  # GT06 envia km/h (o Traccar converte para nós depois)
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
# Detector de checksum/serial (compatível com o Java)
# ============================================================
def detect_checksum_and_serial(header: bytes, length: int, body_and_footer: bytes) -> Tuple[str, bytes, bytes]:
    """
    Retorna (checksum_mode, serial_bytes, payload_full)
    payload_full = [type(1)] + [payload (... possivelmente com serial no fim)]
    - 0x7979: len de 2 bytes; final é CRC(2) + CRLF
    - 0x7878: len de 1 byte; final costuma ser SUM(1) + CRLF; mas clones “mínimos” não têm serial/checksum
    """
    if len(body_and_footer) < 1 + 2:
        return ("SUM8", b"", b"")  # incompleto

    if body_and_footer[-2:] != b"\x0D\x0A":
        return ("SUM8", b"", b"")

    core = body_and_footer[:-2]  # retira CRLF
    if len(core) < 1:
        return ("SUM8", b"", b"")

    msg_type_b = core[:1]
    rest = core[1:]

    # Tenta CRC16: dois últimos bytes antes do CRLF
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        # candidato inclui length (1 ou 2 bytes), type e payload (sem CRC)
        candidate = header + (length.to_bytes(2, "big") if header == b"\x79\x79" else bytes([length])) + msg_type_b + rest[:-2]
        crc_calc = crc16_x25(candidate[2:])
        if crc_calc == crc_recv:
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]  # inclui serial no final do payload (parser entende)
            return ("CRC16", serial, payload_full)

    # Tenta SUM-8 (se houver “sum”)
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = header + (length.to_bytes(2, "big") if header == b"\x79\x79" else bytes([length])) + msg_type_b + rest[:-1]
        if sum8(candidate[2:]) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b""
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    # Degrada (frames mínimos sem serial/checksum)
    return ("SUM8", b"", msg_type_b + rest)

# ============================================================
# Sessão por conexão (device canônico após login)
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
    imei = extract_login_imei_from_payload(payload) or ""
    if imei and imei.isdigit() and len(imei) == 15:
        state.imei_seen = imei
    else:
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

    # Se pulou login, tenta garantir pelo IMEI visto
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                state.device = {"id": dev.get("id"), "imei": dev.get("imei")}
        except Exception:
            pass

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição (evita IMEI curto).")
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
    try:
        await save_position(payload_to_save)
        # ===== linha para casar com seu grep =====
        logger.info("[GT06] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkm/h crs=%.1f t=%s v=%s",
                    state.device['imei'], gps['lat'], gps['lon'], gps['speed_kmh'],
                    gps['course'], gps['time'].isoformat(), gps['valid'])
    except Exception as e:
        logger.exception("[GT06] save_position falhou: %s", e)

# ============================================================
# Frame loop (porta direta do frame decoder Java)
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
    # header
    hdr = await read_exact(reader, 2)

    if hdr not in (b"\x78\x78", b"\x79\x79"):
        # pode ser ASCII/lixo: consome até CRLF para limpar (igual nossa versão anterior)
        try:
            line = hdr + await reader.readuntil(b"\x0D\x0A")
            if LOG_LEGACY:
                logger.debug("[GT06] ASCII? %r", line)
        except Exception:
            pass
        return

    # length
    if hdr == b"\x79\x79":
        length_b = await read_exact(reader, 2)
        length = int.from_bytes(length_b, "big")
    else:
        length_b = await read_exact(reader, 1)
        length = length_b[0]

    # body + checksum(opcional) + CRLF
    body_and_footer = await read_exact(reader, length + 2)

    raw = hdr + length_b + body_and_footer
    raw_hex = binascii.hexlify(raw).decode().upper()

    # Log estilo legado (CHUNK ...)
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

    # ===== logs RX (compat seu grep) =====
    if LOG_LEGACY:
        cs_len = 2 if checksum_mode == "CRC16" or hdr == b"\x79\x79" else 1
        # melhor aproximação do “body útil”: length - (type + serial(2?) + checksum(1/2))
        serial_len = 2 if len(serial_bytes) >= 2 else 0
        body_len = max(0, length - (1 + serial_len + cs_len))
        logger.info("[GT06] RX proto=0x%02X body_len=%d cs_len=%d from=%s",
                    msg_type, body_len, cs_len, peer)

    # ACK (igual traccar)
    ack = build_ack(hdr, msg_type, serial_bytes, checksum_mode)
    writer.write(ack)
    await writer.drain()

    ack_hex = binascii.hexlify(ack).decode().upper()
    logger.info("[GT06] TX_ACK=%s", ack_hex)
    if LOG_LEGACY:
        mode = "CRC16" if (checksum_mode == "CRC16" or hdr == b"\x79\x79") else "SUM"
        logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)
        if msg_type == 0x13:
            payload_wo_serial = payload[:-len(serial_bytes)] if (len(serial_bytes) and len(payload) >= len(serial_bytes)) else payload
            logger.info("[GT06] STATUS(0x13) payload=%s serial=%s",
                        _hex_spaced(payload_wo_serial) or "∅",
                        binascii.hexlify(serial_bytes).decode().upper() or "∅")
        if msg_type == 0x08 and length <= (1 + (0 if len(serial_bytes)==0 else 2) + (0 if len(payload)==0 else 0)):
            logger.info("[GT06] SHORT(min) proto=0x08 TX_ACK=%s (mode=%s)", _hex_spaced(ack), mode)

    # (opcional) validação estrita
    if VALIDATE_GT06_CRC:
        pass

    # Dispatch por tipo
    if msg_type == 0x01:             # LOGIN
        await handle_login(payload, peer, state)
        return

    if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):  # GPS básicos e variantes
        await handle_gps(payload, raw_hex, state)
        return

    if msg_type in (0x13, 0x08):     # STATUS/KEEPALIVE
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