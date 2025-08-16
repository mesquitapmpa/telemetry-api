import asyncio
import logging
import os
import re
import inspect
from datetime import datetime, timezone
from typing import Optional, Tuple, Any, Dict

# Ajuste conforme seu projeto (mantive seus imports)
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
# Utils de compatibilidade (sync/async e assinaturas)
# ==========================

async def _call_maybe_async(fn, *args, **kwargs):
    try:
        res = fn(*args, **kwargs)
    except TypeError:
        # Tenta sem kwargs se houver conflito de nomes
        res = fn(*args)
    if inspect.isawaitable(res):
        return await res
    return res

async def _ensure_device_safe(imei: str, protocol: str, model: Optional[str] = None):
    """
    Chama ensure_device como:
    - ensure_device(imei, protocol, model)  (posicional)
    - ensure_device(imei=..., protocol=..., model=...) (nomeado)
    Funciona sync/async.
    """
    try:
        # primeiro tenta posicional (menos chance de conflito com nomes diferentes)
        return await _call_maybe_async(ensure_device, imei, protocol, model)
    except Exception as e1:
        try:
            return await _call_maybe_async(ensure_device, imei=imei, protocol=protocol, model=model)
        except Exception as e2:
            logger.exception("[ensure_device] falhou (posicional=%s / nomeado=%s)", e1, e2)
            return None

def _normalize_param_name(name: str) -> str:
    name = name.lower()
    aliases = {
        "latitude": "lat", "lat": "lat",
        "longitude": "lon", "lng": "lon", "long": "lon",
        "fix_time": "fix_time", "fixtime": "fix_time", "ts": "fix_time", "dt": "fix_time",
        "speed": "speed_knots", "speed_knots": "speed_knots", "spd": "speed_knots", "vel": "speed_knots",
        "course": "course_deg", "course_deg": "course_deg", "crs": "course_deg", "heading": "course_deg",
        "valid": "valid",
        "raw": "raw",
        "imei": "imei",
    }
    return aliases.get(name, name)

async def _save_position_safe(imei: str, lat: float, lon: float, dt: datetime,
                              speed_knots: Optional[float], course_deg: Optional[float],
                              valid: bool, raw: str):
    """
    Tenta mapear por nomes se disponíveis; senão cai para ordens posicionais comuns.
    Funciona com save_position sync ou async.
    """
    # 1) Tenta por nomes (introspecção)
    try:
        sig = inspect.signature(save_position)
        params = list(sig.parameters.keys())
        # Monta kwargs com os nomes reconhecidos
        kw: Dict[str, Any] = {}
        for p in params:
            pn = _normalize_param_name(p)
            if pn == "imei": kw[p] = imei
            elif pn == "lat": kw[p] = lat
            elif pn == "lon": kw[p] = lon
            elif pn == "fix_time": kw[p] = dt
            elif pn == "speed_knots": kw[p] = speed_knots
            elif pn == "course_deg": kw[p] = course_deg
            elif pn == "valid": kw[p] = valid
            elif pn == "raw": kw[p] = raw
        if kw:
            return await _call_maybe_async(save_position, **kw)
    except Exception:
        pass

    # 2) Tenta ordens posicionais mais comuns do seu stack
    attempts = [
        # (imei, lat, lon, fix_time, speed_knots, course_deg, valid, raw)
        (imei, lat, lon, dt, speed_knots, course_deg, valid, raw),
        # (imei, lat, lon, speed_knots, course_deg, fix_time, valid, raw)
        (imei, lat, lon, speed_knots, course_deg, dt, valid, raw),
        # (imei, dt, lat, lon, speed_knots, course_deg, valid, raw)
        (imei, dt, lat, lon, speed_knots, course_deg, valid, raw),
    ]
    last_err = None
    for args in attempts:
        try:
            return await _call_maybe_async(save_position, *args)
        except TypeError as e:
            last_err = e
            continue
    if last_err:
        raise last_err

# ==========================
# Utilitários – GT06
# ==========================

def _gt06_bcd_imei(b: bytes) -> str:
    s = ''.join(f"{(x >> 4) & 0xF}{x & 0xF}" for x in b)
    return s.lstrip('0')[:15]

def _crc16_x25(data: bytes) -> int:
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
    return sum(data) & 0xFF

def _ack_crc(proto: int, serial: bytes) -> bytes:
    if len(serial) != 2:
        serial = serial[:2].rjust(2, b"\x00")
    body = bytes([0x05, proto]) + serial
    crc = _crc16_x25(body)
    return b"\x78\x78" + body + crc.to_bytes(2, "big") + b"\x0D\x0A"

def _ack_sum(proto: int, serial: bytes) -> bytes:
    if len(serial) != 2:
        serial = serial[:2].rjust(2, b"\x00")
    body = bytes([0x05, proto]) + serial
    cs = _sum_cs(body)  # vários clones usam soma direta do body
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
    end_cs1 = i + 2 + 1 + ln + 1 + 2   # cs 1B + CRLF
    end_crc = i + 2 + 1 + ln + 2 + 2   # cs 2B + CRLF
    if len(buf) >= end_cs1 and buf[end_cs1-2:end_cs1] == b"\x0D\x0A":
        return (end_cs1, 1)
    if len(buf) >= end_crc and buf[end_crc-2:end_crc] == b"\x0D\x0A":
        return (end_crc, 2)
    return None

def _gt06_validate(pkt: bytes, cs_len: int) -> bool:
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
    """Payload SEM serial (proto + campos), para 0x12/0x10."""
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

    lat_deg = int(m.group("latdeg")); lat_min = float(m.group("latmin"))
    lon_deg = int(m.group("londeg")); lon_min = float(m.group("lonmin"))
    lat = lat_deg + (lat_min / 60.0); lon = lon_deg + (lon_min / 60.0)
    if m.group("lats") == "S": lat = -lat
    if m.group("lons") == "W": lon = -lon
    spd_knots = float(m.group("spd")); crs = float(m.group("crs"))
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
            if not chunk:
                logger.info("[TRV/GT06] %s desconectou", peer)
                break
            # debug do que chegou
            logger.info("[GT06] CHUNK %dB from %s: %s", len(chunk), peer, chunk.hex(" "))
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
                    continue

                logger.info("[GT06] RX proto=0x%02X len=%d cs_len=%d from=%s", proto, ln, cs_len, peer)

                # 0x01 LOGIN
                if proto == 0x01 and len(payload) >= 1 + 8 + 2:
                    imei_bcd = payload[1:9]
                    gt06_imei = _gt06_bcd_imei(imei_bcd)

                    # nunca bloqueie o ACK por falha de BD
                    try:
                        await _ensure_device_safe(gt06_imei, "gt06", "gf22")
                    except Exception as e:
                        logger.exception("[GT06] ensure_device (safe) falhou: %s", e)

                    if peer_ip:
                        _gt06_peer_cache[peer_ip] = gt06_imei

                    ack = _ack_sum(0x01, serial) if cs_len == 1 else _ack_crc(0x01, serial)
                    try:
                        writer.write(ack); await writer.drain()
                        logger.info("[GT06] LOGIN imei=%s serial=%02X%02X TX_ACK=%s (mode=%s)",
                                    gt06_imei, serial[0], serial[1], ack.hex(" "),
                                    "SUM" if cs_len == 1 else "CRC")
                    except Exception as e:
                        logger.exception("[GT06] Falha ao enviar ACK LOGIN: %s", e)

                # 0x08 HEARTBEAT
                elif proto == 0x08:
                    ack = _ack_sum(0x08, serial) if cs_len == 1 else _ack_crc(0x08, serial)
                    writer.write(ack); await writer.drain()
                    logger.info("[GT06] HEARTBEAT TX_ACK=%s (mode=%s)", ack.hex(" "), "SUM" if cs_len == 1 else "CRC")

                # 0x12/0x10 POSIÇÃO
                elif proto in (0x12, 0x10):
                    core = payload[:-2]  # remove serial
                    parsed = _gt06_parse_position(core)
                    if parsed:
                        lat, lon, spd_knots, crs, dt = parsed
                        imei_to_use = gt06_imei or (peer_ip and _gt06_peer_cache.get(peer_ip))
                        if imei_to_use:
                            try:
                                await _save_position_safe(
                                    str(imei_to_use), lat, lon, dt, spd_knots, crs, True, pkt.hex()
                                )
                                logger.info("[GT06] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkn crs=%.1f t=%s",
                                            imei_to_use, lat, lon, spd_knots, crs, dt.isoformat())
                            except Exception as e:
                                logger.exception("[GT06] save_position falhou: %s", e)

                    ack = _ack_sum(proto, serial) if cs_len == 1 else _ack_crc(proto, serial)
                    writer.write(ack); await writer.drain()
                    logger.info("[GT06] POS TX_ACK=%s (mode=%s)", ack.hex(" "), "SUM" if cs_len == 1 else "CRC")

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
                        await _ensure_device_safe(imei, "trv", "gf22")
                    except Exception as e:
                        logger.exception("[TRV] ensure_device (safe) falhou: %s", e)

                    if peer_ip:
                        _peer_cache[peer_ip] = imei

                    ack = _trv_ack_login().encode()
                    writer.write(ack); await writer.drain()
                    logger.info("[TRV] LOGIN imei=%s ack=%s", imei, ack.decode())
                    continue

                # Heartbeat TRVYP16
                if line.startswith("TRVYP16"):
                    ack = _trv_ack_heartbeat().encode()
                    writer.write(ack); await writer.drain()
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
                                await _save_position_safe(
                                    imei_for_trv, lat, lon,
                                    fix_time if valid else datetime.now(timezone.utc),
                                    spd_knots, crs, valid, line
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