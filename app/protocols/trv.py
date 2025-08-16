import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

# Ajuste conforme seu projeto
from app.usecases.save_position import ensure_device, save_position

# ==========================
# Configurações
# ==========================
TRV_PORT = int(os.getenv("TRV_PORT", "5010"))
ALLOW_IP_CACHE = os.getenv("TRV_ALLOW_IP_CACHE", "false").lower() == "true"
VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"

logger = logging.getLogger("trv_gt06")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ==========================
# Utilitários – GT06
# ==========================

def _gt06_bcd_imei(b: bytes) -> str:
    """8 bytes BCD → 16 dígitos; retornamos 15 (IMEI), sem zeros à esquerda."""
    s = ''.join(f"{(x >> 4) & 0xF}{x & 0xF}" for x in b)
    return s.lstrip('0')[:15]

def _crc16_x25(data: bytes) -> int:
    """CRC-16/X25 (ITU), poly 0x8408 (reflected), init 0xFFFF, xorout 0xFFFF."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return (~crc) & 0xFFFF

def _sum_cs(data: bytes) -> int:
    """Checksum simples de 1 byte (soma & 0xFF)."""
    return sum(data) & 0xFF

def _ack_crc(proto: int, serial: bytes) -> bytes:
    """
    ACK com CRC-16 (2 bytes):
      78 78 05 <proto> <serial_hi> <serial_lo> <CRC_hi> <CRC_lo> 0D 0A
    CRC sobre [0x05, proto, serial_hi, serial_lo]
    """
    if len(serial) != 2:
        serial = serial[:2].rjust(2, b"\x00")
    body = bytes([0x05, proto]) + serial
    crc = _crc16_x25(body)
    return b"\x78\x78" + body + crc.to_bytes(2, "big") + b"\x0D\x0A"

def _ack_sum(proto: int, serial: bytes) -> bytes:
    """
    ACK com checksum de 1 byte (soma):
      78 78 05 <proto> <serial_hi> <serial_lo> <CS> 0D 0A
    CS = sum([0x05, proto, serial_hi, serial_lo]) & 0xFF
    """
    if len(serial) != 2:
        serial = serial[:2].rjust(2, b"\x00")
    body = bytes([0x05, proto]) + serial
    cs = _sum_cs(body[0:])  # igual ao que muitos clones usam
    return b"\x78\x78" + body + bytes([cs]) + b"\x0D\x0A"

def _loc_cs_style(buf: bytearray, i: int) -> Optional[Tuple[int, int]]:
    """
    Detecta o comprimento total do frame e o 'estilo' do checksum:
      - Retorna (frame_len, cs_len) com cs_len ∈ {1,2}
      - Procura 0D 0A após len e payload.
    Formato geral:
      78 78 | len(1) | payload(len) | cs(1 ou 2) | 0D 0A
    """
    if len(buf) < i + 3:
        return None
    ln = buf[i + 2]
    # candidatos:
    end_cs1 = i + 2 + 1 + ln + 1 + 2   # 1 byte cs
    end_crc = i + 2 + 1 + ln + 2 + 2   # 2 bytes crc
    # checa cauda 0D0A
    if len(buf) >= end_cs1 and buf[end_cs1-2:end_cs1] == b"\x0D\x0A":
        return (end_cs1, 1)
    if len(buf) >= end_crc and buf[end_crc-2:end_crc] == b"\x0D\x0A":
        return (end_crc, 2)
    return None  # incompleto (aguarda mais bytes)

def _gt06_validate(pkt: bytes, cs_len: int) -> bool:
    """Valida o frame opcionalmente, conforme o tipo de checksum detectado."""
    if not VALIDATE_GT06_CRC:
        return True
    ln = pkt[2]
    payload = pkt[3 : 3 + ln]
    if cs_len == 2:
        got = int.from_bytes(pkt[3 + ln : 3 + ln + 2], "big")
        return got == _crc16_x25(payload)
    else:
        got = pkt[3 + ln]
        return got == (_sum_cs(payload) & 0xFF)

def _gt06_parse_position(core: bytes):
    """Recebe payload SEM serial (proto + campos), para 0x12/0x10."""
    if len(core) < 19:
        return None
    proto = core[0]
    if proto not in (0x12, 0x10):
        return None
    yy, mm, dd, hh, mi, ss = core[1:7]
    try:
        dt = datetime(2000 + yy, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)
    lat_raw = int.from_bytes(core[8:12], "big", signed=False)
    lon_raw = int.from_bytes(core[12:16], "big", signed=False)
    lat = lat_raw / 1800000.0
    lon = lon_raw / 1800000.0
    spd_knots = core[16] * 0.539957  # km/h → nós
    course = int.from_bytes(core[17:19], "big") & 0x03FF
    return lat, lon, float(spd_knots), float(course), dt

# ==========================
# Utilitários – TRV (GF22)
# ==========================

_trv_login_re = re.compile(r"^TRVAP00(?P<imei>\d{15})#$")

def _trv_ack_login() -> str:
    now = datetime.now(timezone.utc)
    return f"TRVBP00{now:%y%m%d%H%M%S}#"

def _trv_ack_heartbeat() -> str:
    return "TRVZP16#"

def _trv_parse_yp14(line: str):
    m = re.search(
        r"TRVYP14(?P<d>\d{6})(?P<v>[AV])"
        r"(?P<latdeg>\d{2})(?P<latmin>\d{2}\.\d+)(?P<lats>[NS])"
        r"(?P<londeg>\d{3})(?P<lonmin>\d{2}\.\d+)(?P<lons>[EW])"
        r"(?P<spd>\d+\.\d+)(?P<crs>\d+\.\d+)#",
        line,
    )
    if not m:
        return None
    d = m.group("d")  # YYMMDD
    base = datetime.strptime(d, "%y%m%d").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    fix_time = base.replace(hour=now.hour, minute=now.minute, second=now.second)

    lat_deg = int(m.group("latdeg"))
    lat_min = float(m.group("latmin"))
    lon_deg = int(m.group("londeg"))
    lon_min = float(m.group("lonmin"))
    lat = lat_deg + (lat_min / 60.0)
    lon = lon_deg + (lon_min / 60.0)
    if m.group("lats") == "S":
        lat = -lat
    if m.group("lons") == "W":
        lon = -lon
    spd_knots = float(m.group("spd"))
    crs = float(m.group("crs"))
    valid = m.group("v") == "A"
    return lat, lon, spd_knots, crs, fix_time, valid

# ==========================
# Caches simples
# ==========================
_peer_cache: dict[str, str] = {}       # TRV  : IP → IMEI
_gt06_peer_cache: dict[str, str] = {}  # GT06 : IP → IMEI

# ==========================
# Handler TCP com autodetecção
# ==========================

async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if isinstance(peer, tuple) else None

    buf = bytearray()
    gt06_imei: Optional[str] = None

    logger.info("[TRV/GT06] Conexao de %s", peer)

    try:
        while True:
            chunk = await reader.read(1024)
            logger.info("[GT06] CHUNK %dB from %s: %s", len(chunk), peer, chunk.hex(" "))
            if not chunk:
                logger.info("[TRV/GT06] %s desconectou", peer)
                break
            buf += chunk

            # 1) GT06 (binário)
            while True:
                i = buf.find(b"\x78\x78")
                if i < 0 or len(buf) < i + 3:
                    break

                det = _loc_cs_style(buf, i)
                if det is None:
                    break  # incompleto, aguardar mais bytes
                end, cs_len = det

                pkt = bytes(buf[i:end])
                del buf[:end]

                ln = pkt[2]
                payload = pkt[3 : 3 + ln]  # inclui proto ... serial(2)
                proto = payload[0]
                serial = payload[-2:]

                if not _gt06_validate(pkt, cs_len):
                    logger.warning("[GT06] Checksum invalido (cs_len=%d) de %s: %s", cs_len, peer, pkt.hex(" "))
                    # Continua, mas ignora esse frame
                    continue

                logger.info("[GT06] RX proto=0x%02X len=%d cs_len=%d from=%s", proto, ln, cs_len, peer)

                # 0x01 LOGIN
                if proto == 0x01 and len(payload) >= 1 + 8 + 2:
                    imei_bcd = payload[1:9]
                    gt06_imei = _gt06_bcd_imei(imei_bcd)

                    try:
                        await ensure_device(gt06_imei, protocol="gt06", model="gf22")
                    except Exception as e:
                        logger.exception("[GT06] ensure_device falhou: %s", e)

                    if peer_ip:
                        _gt06_peer_cache[peer_ip] = gt06_imei

                    ack = _ack_sum(0x01, serial) if cs_len == 1 else _ack_crc(0x01, serial)
                    try:
                        writer.write(ack)
                        await writer.drain()
                        logger.info("[GT06] LOGIN imei=%s serial=%02X%02X TX_ACK=%s (mode=%s)",
                                    gt06_imei, serial[0], serial[1], ack.hex(" "), "SUM" if cs_len == 1 else "CRC")
                    except Exception as e:
                        logger.exception("[GT06] Falha ao enviar ACK LOGIN: %s", e)

                # 0x08 HEARTBEAT
                elif proto == 0x08:
                    ack = _ack_sum(0x08, serial) if cs_len == 1 else _ack_crc(0x08, serial)
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[GT06] HEARTBEAT TX_ACK=%s (mode=%s)",
                                ack.hex(" "), "SUM" if cs_len == 1 else "CRC")

                # 0x12/0x10 POSIÇÃO
                elif proto in (0x12, 0x10):
                    core = payload[:-2]  # remove serial
                    parsed = _gt06_parse_position(core)
                    if parsed:
                        lat, lon, spd_knots, crs, dt = parsed
                        imei_to_use = gt06_imei or (peer_ip and _gt06_peer_cache.get(peer_ip))
                        if imei_to_use:
                            try:
                                await save_position(
                                    imei_to_use,
                                    lat,
                                    lon,
                                    dt,
                                    spd_knots,
                                    crs,
                                    True,
                                    pkt.hex(),
                                )
                                logger.info("[GT06] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkn crs=%.1f t=%s",
                                            imei_to_use, lat, lon, spd_knots, crs, dt.isoformat())
                            except Exception as e:
                                logger.exception("[GT06] save_position falhou: %s", e)

                    ack = _ack_sum(proto, serial) if cs_len == 1 else _ack_crc(proto, serial)
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[GT06] POS TX_ACK=%s (mode=%s)",
                                ack.hex(" "), "SUM" if cs_len == 1 else "CRC")

                else:
                    logger.info("[GT06] Proto nao tratado: 0x%02X (cs_len=%d)", proto, cs_len)

            # 2) TRV (texto, linhas terminadas em '#')
            while True:
                j = buf.find(b"#")
                if j < 0:
                    break
                line = bytes(buf[: j + 1]).decode(errors="ignore").strip()
                del buf[: j + 1]
                if not line or not line.startswith("TRV"):
                    continue

                # Login TRV: TRVAP00<IMEI15>#
                m = _trv_login_re.match(line)
                if m:
                    imei = m.group("imei")
                    try:
                        await ensure_device(imei, protocol="trv", model="gf22")
                    except Exception as e:
                        logger.exception("[TRV] ensure_device falhou: %s", e)

                    if peer_ip:
                        _peer_cache[peer_ip] = imei

                    ack = _trv_ack_login().encode()
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[TRV] LOGIN imei=%s ack=%s", imei, ack.decode())
                    continue

                # Heartbeat TRVYP16
                if line.startswith("TRVYP16"):
                    ack = _trv_ack_heartbeat().encode()
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[TRV] HEARTBEAT ack=%s", ack.decode())
                    continue

                # Posição TRVYP14
                if line.startswith("TRVYP14"):
                    parsed = _trv_parse_yp14(line)
                    if parsed:
                        lat, lon, spd_knots, crs, fix_time, valid = parsed
                        imei_for_trv: Optional[str] = None
                        if ALLOW_IP_CACHE and peer_ip:
                            imei_for_trv = _peer_cache.get(peer_ip)
                        if imei_for_trv:
                            try:
                                await save_position(
                                    imei_for_trv,
                                    lat,
                                    lon,
                                    fix_time if valid else datetime.now(timezone.utc),
                                    spd_knots,
                                    crs,
                                    valid,
                                    line,
                                )
                                logger.info("[TRV] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkn crs=%.1f t=%s v=%s",
                                            imei_for_trv, lat, lon, spd_knots, crs, fix_time.isoformat(), valid)
                            except Exception as e:
                                logger.exception("[TRV] save_position falhou: %s", e)
                    continue

                logger.info("[TRV] Linha nao tratada: %s", line)

    except Exception as e:
        logger.exception("[TRV/GT06] Erro na conexao %s: %s", peer, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def start_trv_server():
    server = await asyncio.start_server(_handle, "0.0.0.0", TRV_PORT)
    sockets = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    logger.info("[TRV/GT06] Servidor escutando em %s", sockets)
    return server