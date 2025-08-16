import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Optional

from app.usecases.save_position import ensure_device, save_position

TRV_PORT = int(os.getenv("TRV_PORT", "5010"))
ALLOW_IP_CACHE = os.getenv("TRV_ALLOW_IP_CACHE", "false").lower() == "true"

# ==========================
# Utilitários – GT06
# ==========================

def _gt06_bcd_imei(b: bytes) -> str:
    # 8 bytes em BCD -> 16 dígitos; tomamos os 15 primeiros, sem zeros à esquerda
    s = ''.join(f"{(x>>4)&0xF}{x&0xF}" for x in b)
    return s.lstrip('0')[:15]


def _gt06_login_ack(serial: bytes) -> bytes:
    # 78 78 05 01 <serial> <cs> 0D 0A
    base = b"\x78\x78\x05\x01" + serial
    cs = (sum(base[2:]) & 0xFF).to_bytes(1, "big")
    return base + cs + b"\x0D\x0A"


def _gt06_parse_position(payload: bytes):
    """
    payload (sem len,cs,crlf), começando em 0x12 ou 0x10:
    [0] proto (0x12/0x10)
    [1:7] YY MM DD hh mm ss
    [7] sat/status
    [8:12] lat, [12:16] lon (escala típica 1/1800000)
    [16] speed (km/h)
    [17:19] course/status (10 bits de course)
    """
    if len(payload) < 19:
        return None
    proto = payload[0]
    if proto not in (0x12, 0x10):
        return None
    yy, mm, dd, hh, mi, ss = payload[1:7]
    dt = datetime(2000 + yy, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    lat_raw = int.from_bytes(payload[8:12], "big", signed=False)
    lon_raw = int.from_bytes(payload[12:16], "big", signed=False)
    lat = lat_raw / 1800000.0
    lon = lon_raw / 1800000.0
    spd_knots = payload[16] * 0.539957  # km/h → nós
    course = int.from_bytes(payload[17:19], "big") & 0x03FF
    return lat, lon, float(spd_knots), float(course), dt


# ==========================
# Utilitários – TRV (GF22)
# ==========================

_trv_login_re = re.compile(r"^TRVAP00(?P<imei>\d{15})#$")


def _trv_ack_login() -> str:
    # Ex.: TRVBP00YYMMDDHHMMSS# (padrão visto nos seus testes)
    now = datetime.now(timezone.utc)
    return f"TRVBP00{now:%y%m%d%H%M%S}#"


def _trv_ack_heartbeat() -> str:
    return "TRVZP16#"


def _trv_parse_yp14(line: str):
    """Parsers básicos para a linha TRVYP14…
    Exemplo visto: TRVYP14250815A0107.5297S04858.0058W001.15123.45#
    Retorna: lat, lon, spd_knots, course, fix_time(utc), valid
    """
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
    # Alguns firmwares não trazem hora; usamos agora UTC
    fix_time = datetime.strptime(d, "%y%m%d").replace(tzinfo=timezone.utc)
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
# Handler TCP com autodetecção
# ==========================

async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    buf = bytearray()
    gt06_imei: Optional[str] = None
    try:
        while True:
            chunk = await reader.read(1024)
            if not chunk:
                break
            buf += chunk

            # 1) Frames GT06 (binário: 0x78 0x78 ... 0x0D0A)
            while True:
                i = buf.find(b"\x78\x78")
                if i < 0:
                    break
                if len(buf) < i + 3:
                    break
                ln = buf[i + 2]
                end = i + 3 + ln + 2  # 78 78 | len | payload(len-2) | cs | 0D0A
                if len(buf) < end:
                    break
                pkt = bytes(buf[i:end])
                payload = pkt[3 : 3 + ln - 2]
                proto = payload[0]
                # Login (0x01)
                if proto == 0x01 and len(payload) >= 1 + 8 + 2 + 2:
                    gt06_imei = _gt06_bcd_imei(payload[1:9])
                    await ensure_device(gt06_imei, protocol="gt06", model="gf22")
                    serial = payload[-2:]
                    writer.write(_gt06_login_ack(serial))
                    await writer.drain()
                # Localização (0x12/0x10)
                elif proto in (0x12, 0x10) and gt06_imei:
                    parsed = _gt06_parse_position(payload)
                    if parsed:
                        lat, lon, spd_knots, crs, dt = parsed
                        await save_position(
                            imei=gt06_imei,
                            latitude=lat,
                            longitude=lon,
                            fix_time=dt,
                            speed_knots=spd_knots,
                            course_deg=crs,
                            valid=True,
                            raw=pkt.hex(),
                        )
                # Consumir frame
                del buf[:end]

            # 2) Linhas TRV (terminadas em '#')
            while True:
                j = buf.find(b"#")
                if j < 0:
                    break
                line = bytes(buf[: j + 1]).decode(errors="ignore").strip()
                del buf[: j + 1]
                if not line:
                    continue
                if line.startswith("TRV"):
                    # Login TRV
                    m = _trv_login_re.match(line)
                    if m:
                        imei = m.group("imei")
                        await ensure_device(imei, protocol="trv", model="gf22")
                        # associe IP→IMEI (cache opcional para YP14 em outra conexão)
                        try:
                            peer_ip = peer[0] if isinstance(peer, tuple) else str(peer)
                            _peer_cache[peer_ip] = imei
                        except Exception:
                            pass
                        ack = _trv_ack_login()
                        writer.write(ack.encode())
                        await writer.drain()
                        continue
                    # Heartbeat TRVYP16
                    if line.startswith("TRVYP16"):
                        writer.write(_trv_ack_heartbeat().encode())
                        await writer.drain()
                        continue
                    # Posição TRVYP14
                    if line.startswith("TRVYP14"):
                        parsed = _trv_parse_yp14(line)
                        if parsed:
                            lat, lon, spd_knots, crs, fix_time, valid = parsed
                            # IMEI via cache IP (se disponível)
                            imei: Optional[str] = None
                            try:
                                peer_ip = peer[0] if isinstance(peer, tuple) else str(peer)
                                imei = _peer_cache.get(peer_ip)
                            except Exception:
                                pass
                            if imei:
                                await save_position(
                                    imei=imei,
                                    latitude=lat,
                                    longitude=lon,
                                    fix_time=fix_time if valid else datetime.now(timezone.utc),
                                    speed_knots=spd_knots,
                                    course_deg=crs,
                                    valid=valid,
                                    raw=line,
                                )
                        continue
                # Demais linhas: ignore
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# cache simples IP→IMEI para TRV (quando login chega numa conexão e posição em outra)
_peer_cache: dict[str, str] = {}

async def start_trv_server():
    server = await asyncio.start_server(_handle, "0.0.0.0", TRV_PORT)
    return server