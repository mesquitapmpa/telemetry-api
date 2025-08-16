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
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"

def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ---------------- Checksums ----------------
def crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    crc = ~crc & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ---------------- ACK builder ----------------
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"
    ser = serial_bytes or b""
    if len(ser) == 0:
        ser = b"\x00\x00"
    elif len(ser) == 1:
        ser = b"\x00" + ser
    else:
        ser = ser[-2:]
    body = bytes([msg_type]) + ser

    if checksum_mode == "CRC16":
        length = 1 + 2 + 2
        pkt_wo_crc = hdr + bytes([length]) + body
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    length = 1 + 2 + 1
    pkt_wo_sum = hdr + bytes([length]) + body
    cs = sum8(pkt_wo_sum[2:])
    return pkt_wo_sum + bytes([cs]) + b"\x0D\x0A"

# ---------------- Utils ----------------
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
    # 8 bytes BCD => 16 dígitos (muitos GT06 têm um '0' à esquerda)
    return "".join(f"{(b >> 4) & 0xF}{b & 0xF}" for b in imei_bcd)

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    Extrai IMEI de LOGIN (type 0x01) de forma tolerante:
    1) Tenta BCD nos 8 primeiros bytes (caso clássico: começa com 0x08 -> '0861...')
       - Se vier 16 dígitos e o 1º for '0', remove-o e retorna os 15 restantes.
       - Senão, retorna os últimos 15 dígitos.
    2) ASCII (alguns clones usam 0x0F + 15 ASCII).
    3) Variante '0x08 como marcador' (pouco comum, mas suportada).
    4) Varredura de janelas de 8 bytes no payload.
    """
    # 1) BCD direto no começo
    if len(payload) >= 8:
        s16 = decode_bcd_imei(payload[:8])
        if s16.isdigit():
            if len(s16) == 16 and s16[0] == "0":
                s15 = s16[1:16]
            else:
                s15 = s16[-15:]
            if len(s15) == 15 and s15.isdigit():
                return s15

    # 2) ASCII marcador 0x0F
    if payload[:1] == b"\x0F" and len(payload) >= 16:
        try:
            s = payload[1:16].decode()
            if len(s) == 15 and s.isdigit():
                return s
        except Exception:
            pass

    # 3) Variante '0x08 como marcador'
    if payload[:1] == b"\x08" and len(payload) >= 9:
        s16 = decode_bcd_imei(payload[1:9])
        if s16.isdigit():
            s15 = s16[-15:] if s16[0] != "0" else s16[1:16]
            if len(s15) == 15 and s15.isdigit():
                return s15

    # 4) Varredura
    for i in range(0, max(0, len(payload) - 7)):
        s16 = decode_bcd_imei(payload[i:i+8])
        if s16.isdigit():
            s15 = s16[-15:] if s16[0] != "0" else s16[1:16]
            if len(s15) == 15 and s15.isdigit():
                return s15
    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    # [time6][flags1][lat4][lon4][speed1][course2]
    if len(payload) < 6 + 1 + 4 + 4 + 1 + 2:
        return None
    dt = parse_datetime_bcd(payload[0:6])
    lat_raw = int.from_bytes(payload[7:11], "big")
    lon_raw = int.from_bytes(payload[11:15], "big")
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

# ---------------- checksum/serial detector ----------------
def detect_checksum_and_serial(hdr: bytes, length: int, body_and_footer: bytes) -> Tuple[str, bytes, bytes]:
    if len(body_and_footer) < 3 or body_and_footer[-2:] != b"\x0D\x0A":
        return ("SUM8", b"", b"")
    core = body_and_footer[:-2]
    msg_type_b = core[:1]
    rest = core[1:]

    # CRC16? (últimos 2 bytes)
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-2]
        if crc16_x25(candidate[2:]) == crc_recv:
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]
            return ("CRC16", serial, payload_full)

    # SUM-8? (último byte)
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-1]
        if sum8(candidate[2:]) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b""
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    return ("SUM8", b"", msg_type_b + rest)

# ---------------- Sessão ----------------
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None
        self.imei_seen: Optional[str] = None

# ---------------- Handlers ----------------
async def handle_login(payload: bytes, raw_hex: str, peer: str, state: ConnState):
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido (peer=%s, frame=%s)", peer, raw_hex)
        return

    device = await ensure_device_canonical("gt06", imei)
    if device:
        state.device = {"id": device.get("id"), "imei": device.get("imei")}
        logger.info("[GT06] LOGIN OK imei=%s device_id=%s peer=%s", imei, state.device['id'], peer)
    else:
        logger.warning("[GT06] LOGIN IMEI=%s sem device canônico (peer=%s)", imei, peer)

async def handle_gps(payload: bytes, raw_frame_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning("[GT06] GPS payload curto/indecifrável: %s",
                       binascii.hexlify(payload).decode().upper())
        return

    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                state.device = {"id": dev.get("id"), "imei": dev.get("imei")}
        except Exception:
            pass

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição.")
        return

    await save_position({
        "protocol": "gt06",
        "device_id": state.device["id"],
        "time": gps["time"].isoformat(),
        "lat": gps["lat"],
        "lon": gps["lon"],
        "speed_kmh": gps["speed_kmh"],
        "course": gps["course"],
        "valid": gps["valid"],
        "raw": raw_frame_hex,
    })
    logger.info("[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1fkm/h curso=%.1f valid=%s",
                state.device['id'], gps['lat'], gps['lon'], gps['speed_kmh'], gps['course'], gps['valid'])

# ---------------- Deframer (CRLF) ----------------
async def gt06_frame_loop(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: str, state: ConnState):
    buf = bytearray()
    while True:
        while True:
            i78 = buf.find(b"\x78\x78")
            i79 = buf.find(b"\x79\x79")
            idxs = [x for x in (i78, i79) if x != -1]
            if not idxs:
                break
            i = min(idxs)
            if i > 0:
                del buf[:i]
            if len(buf) < 4:
                break

            hdr = bytes(buf[:2])
            j = buf.find(b"\x0D\x0A", 3)
            if j < 0:
                break

            frame = bytes(buf[:j+2])
            del buf[:j+2]

            if not (frame.startswith(b"\x78\x78") or frame.startswith(b"\x79\x79")) or len(frame) < 5:
                continue

            hdr_b = frame[:2]
            len_b = frame[2]
            body_and_footer = frame[3:]
            checksum_mode, serial_bytes, payload_full = detect_checksum_and_serial(hdr_b, len_b, body_and_footer)
            if not payload_full:
                if LOG_LEGACY:
                    logger.info("[GT06] Frame malformado: %s", _hex_spaced(frame))
                continue

            msg_type = payload_full[0]
            payload = payload_full[1:]
            raw_hex = binascii.hexlify(frame).decode().upper()

            logger.info("[GT06] RX type=0x%02X len_byte=%d chk=%s serial=%s",
                        msg_type, len_b, checksum_mode, binascii.hexlify(serial_bytes).decode().upper() or "∅")

            # ACK
            try:
                ack = build_ack(0x7878 if hdr_b == b"\x78\x78" else 0x7979, msg_type, serial_bytes, checksum_mode)
                writer.write(ack)
                await writer.drain()
                if LOG_LEGACY:
                    logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack),
                                "SUM" if checksum_mode == "SUM8" else "CRC16")
            except Exception:
                logger.exception("[GT06] Falha ao enviar ACK")
                return

            try:
                if msg_type == 0x01:
                    await handle_login(payload, raw_hex, peer, state)
                elif msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
                    await handle_gps(payload, raw_hex, state)
                # 0x08/0x13 keepalive/status → sem ação além do ACK
            except Exception as e:
                logger.exception("[GT06] Erro no handler do tipo 0x%02X: %s", msg_type, e)

        chunk = await reader.read(1024)
        if not chunk:
            return
        buf += chunk

# ---------------- Server ----------------
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()
    try:
        await gt06_frame_loop(reader, writer, str(peer), state)
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
    addrs = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    logger.info(f"[TRV/GT06] Servidor escutando em {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run(int(os.getenv("TRV_PORT", "5010"))))