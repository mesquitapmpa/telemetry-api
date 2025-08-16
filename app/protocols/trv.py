# app/protocols/trv_gt06.py
import asyncio
import binascii
import logging
import os
import struct
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

# =========================
# Utils / checksums
# =========================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (ITU-T): reflected poly 0x8408, init 0xFFFF, xorout 0xFFFF.
    Campo no protocolo é big-endian.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc = (~crc) & 0xFFFF
    # retornamos inteiro "normal" (já pronto para pack(">H"))
    return crc

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

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
    payload após o byte type=0x01.
    Suporta:
      - 0x0F + 15 ASCII
      - 0x08 + 8 BCD
      - fallback: varre qualquer janela de 8 bytes plausível
    """
    if not payload:
        return None
    # ASCII 15
    if payload[0:1] == b"\x0F" and len(payload) >= 1 + 15:
        try:
            s = payload[1:16].decode()
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass
    # BCD 8
    if payload[0:1] == b"\x08" and len(payload) >= 1 + 8:
        s = decode_bcd_imei(payload[1:9])
        if s.isdigit() and len(s) == 15:
            return s
    # Varredura
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei(payload[i:i+8])
        if s.isdigit() and len(s) == 15:
            return s
    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    GT06 básico (0x10/0x11/0x12):
      [YY MM DD hh mm ss][flags?1][lat4][lon4][speed1(km/h)][course2]
    - sinal de lat/lon pelos bits:
       bit11 (1<<11): gps fix
       bit12: 1=West
       bit13: 1=South
    """
    if len(payload) < 6+1+4+4+1+2:
        return None
    dt = parse_datetime_bcd(payload[0:6])
    # flags = payload[6]  # alguns clones não usam
    lat_raw = int.from_bytes(payload[7:11], "big", signed=False)
    lon_raw = int.from_bytes(payload[11:15], "big", signed=False)
    speed_kmh = payload[15] * 1.0  # km/h já
    course_flags = struct.unpack(">H", payload[16:18])[0]
    course = float(course_flags & 0x03FF)
    fixed = bool(course_flags & (1 << 11))
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
        "valid": fixed,
        "flags": course_flags,
    }

# =========================
# ACK builder
# =========================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"
    serial = (serial_bytes or b"\x00\x00")[-2:].rjust(2, b"\x00")

    # GT06 usa 0x05 no length do ACK (type+serial+checksum)
    length = 0x05
    core = bytes([length, msg_type]) + serial

    if checksum_mode == "CRC16":
        crc = crc16_x25(core)
        return hdr + core + struct.pack(">H", crc) + b"\x0D\x0A"
    else:
        cs = sum8(core)
        return hdr + core + bytes([cs]) + b"\x0D\x0A"

# =========================
# Sessão
# =========================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None  # {"id":..., "imei":...}
        self.imei_seen: Optional[str] = None

# =========================
# Handlers lógicos
# =========================
# helper no topo do arquivo (perto das utils)
def _dev_fields(device) -> tuple[Optional[int], Optional[str]]:
    if device is None:
        return None, None
    if isinstance(device, dict):
        return device.get("id"), device.get("imei") or device.get("serial")
    # objeto (ORM/Pydantic/etc)
    return getattr(device, "id", None), getattr(device, "imei", getattr(device, "serial", None))

async def handle_login(payload: bytes, peer: str, state: ConnState):
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei and imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido; peer=%s payload=%s", peer, _hex_spaced(payload))
        return

    device = await ensure_device_canonical("gt06", imei)
    if not device:
        logger.warning("[GT06] LOGIN IMEI=%s sem device canônico; peer=%s", imei, peer)
        return

    dev_id, dev_imei = _dev_fields(device)
    if not dev_id:
        logger.warning("[GT06] Device retornado sem id; type=%s peer=%s", type(device).__name__, peer)
        return

    state.device = {"id": dev_id, "imei": dev_imei or imei}
    logger.info("[GT06] LOGIN OK: device_id=%s imei=%s peer=%s", dev_id, state.device["imei"], peer)


async def handle_gps(payload: bytes, raw_frame_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning("[GT06] GPS payload curto/indecifrável: %s", _hex_spaced(payload))
        return
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) >= 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                state.device = {"id": dev.get("id"), "imei": dev.get("imei")}
        except Exception:
            pass
    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição.")
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
                state.device["id"], gps["lat"], gps["lon"], gps["speed_kmh"], gps["course"], gps["valid"])

# =========================
# Deframer (por buffer)
# =========================
def _find_frame(buf: bytearray) -> Optional[Tuple[bytes, int, int, int]]:
    """
    Procura header 0x7878/0x7979, acha o próximo CRLF, e retorna:
      (pkt_bytes, header_int, length_byte, start_index)
    Se incompleto, retorna None.
    """
    # procura header
    i = buf.find(b"\x78\x78")
    j = buf.find(b"\x79\x79")
    if i < 0 and j < 0:
        # descarta lixo antes do próximo '#' CRLF-like (não é TRV aqui; só binário)
        # mantemos apenas últimos 3 bytes para chance de header cruzar chunks
        if len(buf) > 3:
            del buf[:-3]
        return None
    start = min([x for x in [i, j] if x >= 0])
    if len(buf) < start + 3:
        return None  # falta len
    header = int.from_bytes(buf[start:start+2], "big")
    length = buf[start+2]
    # precisa ter pelo menos algo e CRLF
    tail = buf.find(b"\x0D\x0A", start + 3)
    if tail < 0:
        return None  # aguarda mais bytes
    end = tail + 2  # exclusivo
    pkt = bytes(buf[start:end])
    # corta do buffer
    del buf[:end]
    return pkt, header, length, start

def _detect_checksum_and_serial(header: int, length: int, core: bytes) -> Tuple[str, bytes]:
    """
    core = bytes entre o byte 'length' e CRLF (exclui CRLF), ou seja:
      core = [type + ... + (possível serial + possível checksum)]

    Retorna (mode, serial):
      mode ∈ {"CRC16","SUM8","TRUNC"}
    """
    if not core:
        return ("TRUNC", b"")
    msg_type = core[0]
    rest = core[1:]
    # Tentar CRC16: últimos 2 bytes CRC, anteriores 2 bytes serial
    if len(rest) >= 4:
        serial = rest[-4:-2]
        data_wo_crc = bytes([length, msg_type]) + rest[:-2]
        got_crc = struct.unpack(">H", rest[-2:])[0]
        calc_crc = crc16_x25(data_wo_crc)
        if got_crc == calc_crc:
            return ("CRC16", serial)
    # Tentar SUM-8: último 1 byte soma, anteriores 2 bytes serial
    if len(rest) >= 3:
        serial = rest[-3:-1]
        data_wo_sum = bytes([length, msg_type]) + rest[:-1]
        got_sum = rest[-1]
        calc_sum = sum8(data_wo_sum)
        if got_sum == calc_sum:
            return ("SUM8", serial)
    # Truncado (ex.: 7878 0D 01 08 IMEI[8] 0D0A)
    return ("TRUNC", b"")

# =========================
# Loop de conexão
# =========================
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()
    buf = bytearray()
    try:
        while True:
            chunk = await reader.read(1024)
            if not chunk:
                # conexão fechada
                break
            buf += chunk

            # varre frames completos pelo CRLF
            while True:
                found = _find_frame(buf)
                if not found:
                    break
                pkt, header, length, _ = found
                # pkt = [hdr2][len1][core ...][0D0A]
                core = pkt[3:-2] if len(pkt) >= 5 else b""
                if not core:
                    continue

                msg_type = core[0]
                payload_full = core[1:]  # pode incluir serial/checksum no final
                # detectar checksum/serial
                mode, serial = _detect_checksum_and_serial(header, length, core)

                # ACK imediato (para TRUNC usamos SUM+serial=0000)
                ack = build_ack(header, msg_type, serial, "SUM8" if mode == "TRUNC" else mode)
                writer.write(ack)
                await writer.drain()

                if LOG_LEGACY:
                    cs_len = 1 if mode == "SUM8" else (2 if mode == "CRC16" else 0)
                    logger.info("[GT06] RX proto=0x%02X body_len~%d cs_len=%d from=%s",
                                msg_type, max(0, len(core) - (1 + len(serial) + cs_len)), cs_len, peer)
                    logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)

                logger.info("[GT06] RX type=0x%02X len=%d chk=%s serial=%s",
                            msg_type, length, mode, binascii.hexlify(serial).decode().upper() or "∅")
                logger.info("[GT06] TX_ACK=%s", binascii.hexlify(ack).decode().upper())

                # payload "útil" (sem serial/checksum quando presentes)
                payload = payload_full
                if mode == "CRC16" and len(payload_full) >= 2:
                    payload = payload_full[:-2]      # tira CRC
                if mode == "SUM8" and len(payload_full) >= 1:
                    payload = payload_full[:-1]      # tira SUM
                if len(payload) >= 2 and len(serial) == 2:
                    # muitos frames colocam serial no fim do payload
                    if payload[-2:] == serial:
                        payload = payload[:-2]

                raw_hex = binascii.hexlify(pkt).decode().upper()

                # despacho
                if msg_type == 0x01:  # LOGIN
                    await handle_login(payload, str(peer), state)
                    continue

                if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
                    await handle_gps(payload, raw_hex, state)
                    continue

                # STATUS/KEEPALIVE
                if msg_type in (0x13, 0x08):
                    # nada além do ACK
                    continue

                logger.debug("[GT06] Tipo 0x%02X não tratado. payload=%s",
                             msg_type, _hex_spaced(payload))

    except Exception as e:
        logger.exception("[GT06] erro na conexao %s: %s", peer, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# =========================
# Bootstrap server
# =========================
async def run(port: int = int(os.getenv("TRV_PORT", "5010"))):
    server = await asyncio.start_server(gt06_server, "0.0.0.0", port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("[TRV/GT06] Servidor escutando em %s", addrs)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run())