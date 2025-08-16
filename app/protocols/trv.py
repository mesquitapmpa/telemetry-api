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
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"  # logs “à la traccar” para depuração

# ============================
# Helpers de log/hex
# ============================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ============================
# Checksums
# ============================
def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (ITU-T): poly 0x8408 (reflected), init=0xFFFF, xorout=0xFFFF.
    Campo em big-endian.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc = ~crc & 0xFFFF
    # retornamos no “endianness” de campo: big-endian na hora do pack
    return crc

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================
# ACK (espelha header, type e serial)
# ============================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    """
    ACK GT06:
      header(2) + length(1=0x05) + type(1) + serial(2) + checksum(1 ou 2) + 0D0A
    Em CRC16, muitos firmwares aceitam ACK com SUM8; mas aqui espelhamos:
      - "CRC16" => usa CRC16
      - qualquer outro => SUM8
    """
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"
    serial = (serial_bytes or b"\x00\x00")[-2:].rjust(2, b"\x00")
    length = 0x05  # type(1)+serial(2)+chk(1) – o length é sempre 5 nos ACKs GT06

    core = bytes([length, msg_type]) + serial

    if checksum_mode == "CRC16":
        crc = crc16_x25(core)
        return hdr + core + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM-8 (default)
    cs = sum8(core)
    return hdr + core + bytes([cs]) + b"\x0D\x0A"

# ============================
# Utils
# ============================
def parse_datetime_bcd(dt6: bytes) -> datetime:
    if len(dt6) < 6:
        return datetime.now(timezone.utc)
    yy, mm, dd, hh, mi, ss = dt6[:6]
    year = 2000 + (yy % 100)
    try:
        return datetime(year, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def decode_bcd_imei_strict(imei_bcd8: bytes) -> str:
    """
    Converte 8 bytes BCD -> 16 dígitos; descarta último nibble (padding) e volta 15 dígitos.
    Não remove zeros à esquerda.
    """
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd8)
    if len(s) >= 16:
        s = s[:15]
    return s

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    payload de LOGIN (sem o byte type=0x01):
      - 0x08 + 8 bytes BCD (padrão GT06)
      - 0x0F + 15 bytes ASCII
      - fallback: janela de 8 bytes BCD plausível
    """
    if not payload:
        return None

    # ASCII puro (0x0F + 15 ASCII)
    if payload[0:1] == b"\x0F" and len(payload) >= 1 + 15:
        try:
            s = payload[1:1+15].decode("ascii", errors="strict")
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass

    # BCD (0x08 + 8 bytes)
    if payload[0:1] == b"\x08" and len(payload) >= 1 + 8:
        s = decode_bcd_imei_strict(payload[1:1+8])
        if s.isdigit() and len(s) == 15:
            return s

    # Fallback: varrer 8 bytes plausíveis
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei_strict(payload[i:i+8])
        if s.isdigit() and len(s) == 15:
            return s

    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    GT06 GPS básico (0x10/0x11/0x12/...):
      [time6][flags1][lat4][lon4][speed1][course2]
    - bit11 (course/status): GPS fix
    - bit12: 1 = West  (lon -)
    - bit13: 1 = South (lat -)
    """
    need = 6 + 1 + 4 + 4 + 1 + 2
    if len(payload) < need:
        return None

    dt = parse_datetime_bcd(payload[0:6])
    # flags1 = payload[6]  # muitos firmwares não usam esse bit para fix
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

# ============================
# Detector de checksum/serial (deframer)
# ============================
def detect_checksum_and_serial(hdr: bytes, length: int, body_and_footer: bytes) -> Tuple[str, bytes, bytes]:
    """
    Retorna (checksum_mode, serial_bytes, payload_full)
      checksum_mode: "CRC16" | "SUM8" | "TRUNC"
      serial_bytes : 2 bytes se encontrados; senão b""
      payload_full : type(1) + payload (com serial dentro, se houver)
    """
    # precisa ter ao menos type + CRLF
    if len(body_and_footer) < 1 + 2:
        return ("TRUNC", b"", b"")

    if body_and_footer[-2:] != b"\x0D\x0A":
        return ("TRUNC", b"", b"")

    core = body_and_footer[:-2]          # remove CRLF
    msg_type_b = core[:1]
    rest = core[1:]                      # payload + [serial?] + [chk?]

    # 1) CRC16: últimos 2 bytes
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        candidate = bytes([length]) + msg_type_b + rest[:-2]
        if crc16_x25(candidate) == crc_recv:
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            payload_full = msg_type_b + rest[:-2]
            return ("CRC16", serial, payload_full)

    # 2) SUM-8: último byte
    if len(rest) >= 1:
        cs_recv = rest[-1]
        candidate = bytes([length]) + msg_type_b + rest[:-1]
        if sum8(candidate) == cs_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b""
            payload_full = msg_type_b + rest[:-1]
            return ("SUM8", serial, payload_full)

    # 3) TRUNC – frame mínimo (ex.: 0x08 keepalive curtíssimo ou perda de cs)
    return ("TRUNC", b"", msg_type_b + rest)

# ============================
# Sessão por conexão
# ============================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None   # {"id":..., "imei":...}
        self.imei_seen: Optional[str] = None

def _dev_fields(device) -> tuple[Optional[Any], Optional[str]]:
    if device is None:
        return None, None
    if isinstance(device, dict):
        return device.get("id"), device.get("imei") or device.get("serial")
    return getattr(device, "id", None), getattr(device, "imei", getattr(device, "serial", None))

# ============================
# Handlers
# ============================
async def handle_login(payload: bytes, raw_hex: str, peer: str, state: ConnState):
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei and imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido; peer=%s payload=%s raw=%s",
                       peer, _hex_spaced(payload), raw_hex)
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
        logger.warning("[GT06] GPS payload curto/indecifrável: %s",
                       binascii.hexlify(payload).decode().upper())
        return

    # Se pulou login, tente armar pelo IMEI visto
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            if dev:
                dev_id, dev_imei = _dev_fields(dev)
                if dev_id:
                    state.device = {"id": dev_id, "imei": dev_imei or state.imei_seen}
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
    await save_position(payload_to_save)
    logger.info("[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1fkm/h curso=%.1f valid=%s",
                state.device['id'], gps['lat'], gps['lon'], gps['speed_kmh'], gps['course'], gps['valid'])

# ============================
# Frame loop (deframer + dispatcher)
# ============================
async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            raise asyncio.IncompleteReadError(buf, n)
        buf += chunk
    return buf

async def gt06_frame_loop(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()

    try:
        while True:
            # header
            hdr = await read_exact(reader, 2)
            if hdr not in (b"\x78\x78", b"\x79\x79"):
                # limpa lixo/ASCII até CRLF
                try:
                    line = hdr + await reader.readuntil(b"\x0D\x0A")
                    logger.debug("[GT06] ASCII? %r", line)
                except Exception:
                    pass
                continue

            # length + corpo (type+payload+chk) + CRLF(2)
            length_b = await read_exact(reader, 1)
            length = length_b[0]
            body_and_footer = await read_exact(reader, length + 2)

            raw = hdr + length_b + body_and_footer
            raw_hex = binascii.hexlify(raw).decode().upper()

            checksum_mode, serial_bytes, payload_full = detect_checksum_and_serial(hdr, length, body_and_footer)
            msg_type = payload_full[0] if payload_full else 0x00
            payload = payload_full[1:] if len(payload_full) > 1 else b""

            # Logs estilo “legado” (pré-ACK)
            if LOG_LEGACY:
                cs_len = 2 if checksum_mode == "CRC16" else (1 if checksum_mode == "SUM8" else 0)
                # aproximação de body útil
                body_len_est = max(0, length - (1 + (2 if serial_bytes else 0) + (cs_len if cs_len else 0)))
                logger.info("[GT06] RX proto=0x%02X body_len~%d cs_len=%d from=%s",
                            msg_type, body_len_est, cs_len, peer)

            # Log atual
            logger.info("[GT06] RX type=0x%02X len_byte=%d chk=%s serial=%s",
                        msg_type, length,
                        "TRUNC" if checksum_mode == "TRUNC" else checksum_mode,
                        (binascii.hexlify(serial_bytes).decode().upper() or "∅"))

            # ACK imediato (se checksum_mode for TRUNC, respondemos em SUM8)
            ack = build_ack(0x7878 if hdr == b"\x78\x78" else 0x7979,
                            msg_type, serial_bytes,
                            checksum_mode if checksum_mode in ("SUM8", "CRC16") else "SUM8")
            writer.write(ack)
            await writer.drain()

            if LOG_LEGACY:
                mode = "CRC16" if checksum_mode == "CRC16" else ("SUM" if checksum_mode == "SUM8" else "TRUNC")
                logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)

            logger.info("[GT06] TX_ACK=%s", binascii.hexlify(ack).decode().upper())

            # dispatch
            if msg_type == 0x01:
                try:
                    await handle_login(payload, raw_hex, str(peer), state)
                except Exception as e:
                    logger.exception("[GT06] Erro no handler do tipo 0x01: %s", e)
                continue

            if msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
                try:
                    await handle_gps(payload, raw_hex, state)
                except Exception as e:
                    logger.exception("[GT06] Erro no handler de GPS: %s", e)
                continue

            # status/keepalive — nada além do ACK
            if msg_type in (0x13, 0x08):
                continue

            logger.debug("[GT06] Tipo 0x%02X não tratado. payload=%s",
                         msg_type, binascii.hexlify(payload).decode().upper())

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

# ============================
# Server
# ============================
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    await gt06_frame_loop(reader, writer)

async def run(port: int = 5010):
    server = await asyncio.start_server(gt06_server, "0.0.0.0", port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"[TRV/GT06] Servidor escutando em {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run(int(os.getenv("TRV_PORT", "5010"))))