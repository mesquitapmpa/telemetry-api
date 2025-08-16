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

# Env flags
VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "false").lower() == "true"  # logs estilo antigo

# Protocols que carregam posição
PROTO_POS = {0x10, 0x11, 0x12, 0x16, 0x26}

# =========================
# Utils / checksums
# =========================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def crc16_x25(data: bytes) -> int:
    """CRC-16/X25 (reflected), init=0xFFFF, xorout=0xFFFF. Retorna inteiro big-endian."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc = ~crc & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

def decode_bcd_imei(imei_bcd: bytes) -> str:
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd)
    return s.lstrip('0')[:15]

def parse_datetime_bcd(dt6: bytes) -> datetime:
    if len(dt6) < 6:
        return datetime.now(timezone.utc)
    yy, mm, dd, hh, mi, ss = dt6[:6]
    year = 2000 + (yy % 100)
    try:
        return datetime(year, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    GT06 0x10/0x11/0x12/0x16/0x26:
    [time6][flags1][lat4][lon4][speed1][course2]
    - lat/lon sem sinal; hemisfério vem nos bits do course/status:
      bit11=GPS fix, bit12=West, bit13=South
    """
    if len(payload) < 6 + 1 + 4 + 4 + 1 + 2:
        return None

    dt = parse_datetime_bcd(payload[0:6])
    # flags1 = payload[6]  # não usamos para 'valid'
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

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    payload do LOGIN (sem o byte do 'type' 0x01).
    Suporta:
      - 0x0F + 15 ASCII
      - 0x08 + 8 bytes BCD
      - fallback: varredura de 8 bytes BCD plausíveis
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

    # fallback
    for i in range(0, max(0, len(payload) - 7)):
        s = decode_bcd_imei(payload[i:i+8])
        if s.isdigit() and len(s) == 15:
            return s
    return None

# =========================
# ACK builder
# =========================
def build_ack(hdr_le: bytes, msg_type: int, serial: bytes, mode: str) -> bytes:
    """
    GT06 ACK clássico usa length=0x05 (type+serial+CRC/SUM),
    e funciona bem inclusive em clones SUM-8.
    """
    hdr = b"\x78\x78" if hdr_le in (b"\x78\x78", b"\x79\x79") else b"\x78\x78"

    # Serial: 2 bytes
    s = (serial or b"\x00\x00")[-2:].rjust(2, b"\x00")

    # Sempre length=0x05 para compatibilidade (1 type + 2 serial + 2 CRC ou 1 SUM)
    if mode == "CRC16":
        body = bytes([msg_type]) + s
        length = 0x05
        pkt_wo_crc = hdr + bytes([length]) + body
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM8 (ou TRUNC: espelha SUM)
    body = bytes([msg_type]) + s
    length = 0x05
    pkt_wo_sum = hdr + bytes([length]) + body
    cs = sum8(pkt_wo_sum[2:])
    return pkt_wo_sum + bytes([cs]) + b"\x0D\x0A"

# =========================
# Deframer por varredura
# =========================
def _find_frame(buf: bytearray) -> Optional[Tuple[bytes, int, int, str, bytes, bytes]]:
    """
    Varre por um frame completo:
      retorno: (raw_frame, header_val, len_byte, checksum_mode, serial_bytes, payload_full)

    Estratégia:
      - encontra 0x7878/0x7979
      - encontra terminador 0D0A
      - tenta validar CRC16 ou SUM8; se falhar, aceita TRUNC
    """
    i = buf.find(b"\x78\x78")
    j = buf.find(b"\x79\x79")
    if i < 0 and j < 0:
        # sem header -> descarta lixo inicial
        if len(buf) > 512:
            del buf[:len(buf)-64]
        return None

    hdr_pos = min(x for x in (i, j) if x >= 0)
    if hdr_pos > 0:
        del buf[:hdr_pos]

    if len(buf) < 4:
        return None

    # header + len
    hdr = bytes(buf[:2])
    length = buf[2]

    # procurar CRLF do frame (não assumimos length correto em TRUNC)
    tail = buf.find(b"\x0D\x0A", 3)
    if tail < 0:
        return None
    end = tail + 2  # EXCLUSIVO

    pkt = bytes(buf[:end])

    # corpo entre "len" e checksum (segundo o protocol), mas como aceitamos TRUNC,
    # reconstruímos a área core sem confiar cegamente em length
    # formato nominal: hdr(2) + len(1) + type(1) + payload + [serial(2)] + [cs(1/2)] + CRLF(2)
    # Vamos tentar validar CRC e SUM; se nenhum bater, TRUNC.
    core = pkt[3:-2]  # tudo entre LEN e CRLF
    if not core:
        # keepalive curtíssimo (ex.: 78 78 01 08 0D 0A)
        msg_type = pkt[3] if len(pkt) >= 5 else 0x00
        payload_full = bytes([msg_type])
        serial = b""
        mode = "TRUNC"
        return (pkt, int.from_bytes(hdr, "big"), length, mode, serial, payload_full)

    # Tenta CRC16
    if len(core) >= 1 + 2:
        crc_recv = struct.unpack(">H", core[-2:])[0]
        calc = crc16_x25(pkt[2:-4])  # CRC sobre [len..type..payload..serial]
        if calc == crc_recv:
            msg_type = core[0]
            # serial são os 2 bytes anteriores ao CRC (se houver)
            serial = core[-4:-2] if len(core) >= 4 else b"\x00\x00"
            payload_full = core[:-2]  # type+payload+serial
            return (pkt, int.from_bytes(hdr, "big"), length, "CRC16", serial, payload_full)

    # Tenta SUM-8
    if len(core) >= 1 + 1:
        sum_recv = core[-1]
        calc = sum8(pkt[2:-3])  # SUM sobre [len..type..payload..serial]
        if (calc & 0xFF) == sum_recv:
            msg_type = core[0]
            serial = core[-3:-1] if len(core) >= 3 else b""
            payload_full = core[:-1]
            return (pkt, int.from_bytes(hdr, "big"), length, "SUM8", serial, payload_full)

    # TRUNC: aceita sem checksum
    msg_type = core[0]
    # se der, tente achar 2 bytes finais como serial (heurística: login costuma 0x08/0x0F no 2º byte)
    serial = b""
    payload_full = core  # type + payload (sem serial/cs)
    return (pkt, int.from_bytes(hdr, "big"), length, "TRUNC", serial, payload_full)

# =========================
# Sessão
# =========================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None  # {"id":..., "imei":...}
        self.imei_seen: Optional[str] = None

# =========================
# Handlers
# =========================
async def handle_login(payload: bytes, raw_hex: str, peer: str, state: ConnState):
    imei = extract_login_imei_from_payload(payload) or ""
    state.imei_seen = imei or state.imei_seen

    if not (imei and imei.isdigit() and len(imei) == 15):
        logger.warning("[GT06] LOGIN sem IMEI válido/decodificável; peer=%s raw=%s", peer, raw_hex)
        return

    device = await ensure_device_canonical("gt06", imei)
    # NOTE: ensure_device_canonical retorna um objeto/entidade, não dict
    dev_id = getattr(device, "id", None) if device is not None else None
    dev_imei = getattr(device, "imei", None) if device is not None else None
    if dev_id and dev_imei:
        state.device = {"id": dev_id, "imei": dev_imei}
        logger.info("[GT06] LOGIN OK: device_id=%s imei=%s peer=%s", dev_id, dev_imei, peer)
    else:
        logger.warning("[GT06] LOGIN com IMEI válido mas sem device canônico; peer=%s", peer)

async def handle_gps(payload: bytes, raw_hex: str, state: ConnState):
    gps = parse_gps_basic(payload)
    if not gps:
        logger.warning("[GT06] GPS payload curto/indecifrável: %s", binascii.hexlify(payload).decode().upper())
        return

    # Se pulou login, tenta pegar via state.imei_seen
    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            dev_id = getattr(dev, "id", None)
            dev_imei = getattr(dev, "imei", None)
            if dev_id and dev_imei:
                state.device = {"id": dev_id, "imei": dev_imei}
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
        "raw": raw_hex,
    }
    await save_position(payload_to_save)
    logger.info(
        "[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1fkm/h curso=%.1f valid=%s",
        state.device["id"], gps["lat"], gps["lon"], gps["speed_kmh"], gps["course"], gps["valid"]
    )

# =========================
# Loop da conexão (deframer)
# =========================
async def gt06_frame_loop(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()

    buf = bytearray()
    try:
        while True:
            # enche buffer
            chunk = await reader.read(1024)
            if not chunk:
                break
            buf += chunk

            # consome múltiplos frames se tiver
            while True:
                found = _find_frame(buf)
                if not found:
                    break

                pkt, header_val, len_byte, chk_mode, serial, payload_full = found
                raw_hex = binascii.hexlify(pkt).decode().upper()

                # remove frame do buffer
                del buf[:len(pkt)]

                # extrai msg_type/payload
                msg_type = payload_full[0] if payload_full else 0x00
                payload = payload_full[1:] if len(payload_full) > 1 else b""

                # Logs atuais
                logger.info("[GT06] RX type=0x%02X len_byte=%d chk=%s serial=%s",
                            msg_type, len_byte, chk_mode,
                            binascii.hexlify(serial).decode().upper() or "∅")

                # ACK imediato
                ack = build_ack(pkt[:2], msg_type, serial, "SUM8" if chk_mode in ("SUM8", "TRUNC") else "CRC16")
                writer.write(ack)
                await writer.drain()

                if LOG_LEGACY:
                    mode = "SUM" if chk_mode in ("SUM8", "TRUNC") else "CRC16"
                    # tentativa de estimar body_len útil
                    cs_len = 1 if chk_mode == "SUM8" else (2 if chk_mode == "CRC16" else 0)
                    serial_len = len(serial) if len(serial) else 0
                    body_len_est = max(0, len_byte - (1 + serial_len + cs_len))
                    logger.info("[GT06] RX proto=0x%02X body_len~%d cs_len=%d from=%s",
                                msg_type, body_len_est, cs_len, peer)
                    logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)

                # dispatch
                try:
                    if msg_type == 0x01:
                        await handle_login(payload, raw_hex, str(peer), state)
                    elif msg_type in PROTO_POS:
                        await handle_gps(payload, raw_hex, state)
                    elif msg_type in (0x08, 0x13):  # keepalive/status
                        pass  # ACK já enviado
                    else:
                        # ignora tipos não tratados
                        pass
                except Exception as e:
                    logger.exception("[GT06] Erro no handler do tipo 0x%02X: %s", msg_type, e)

    except Exception as e:
        logger.exception("[GT06] erro: %s", e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# =========================
# Servidor
# =========================
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