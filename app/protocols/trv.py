import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

# Ajuste esses imports conforme sua estrutura
from app.usecases.save_position import ensure_device, save_position

# ==========================
# Configurações
# ==========================
TRV_PORT = int(os.getenv("TRV_PORT", "5010"))
ALLOW_IP_CACHE = os.getenv("TRV_ALLOW_IP_CACHE", "false").lower() == "true"
VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"

logger = logging.getLogger("trv_gt06")
if not logger.handlers:
    # Garante saída no stdout mesmo se o root não estiver configurado
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
    """
    CRC-16/X25 (ITU), polinômio 0x1021 refletido (0x8408), init 0xFFFF, final XOR 0xFFFF.
    Retorna inteiro (0..65535).
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _gt06_ack(proto: int, serial: bytes) -> bytes:
    """
    Constrói ACK do GT06:
      78 78 05 <proto> <serial_hi> <serial_lo> <CRC_hi> <CRC_lo> 0D 0A
    Onde CRC = CRC-16/X25 sobre os bytes [0x05, proto, serial_hi, serial_lo]
    """
    if len(serial) != 2:
        serial = serial[:2].rjust(2, b"\x00")
    body = bytes([0x05, proto]) + serial
    crc = _crc16_x25(body)
    return b"\x78\x78" + body + crc.to_bytes(2, "big") + b"\x0D\x0A"


def _gt06_calc_frame_len(buf: bytearray, i: int) -> Optional[int]:
    """
    Calcula o comprimento total do frame a partir do índice i (onde buf[i:i+2] == 0x78 0x78).
    Formato geral:
      header(2=0x78,0x78) + len(1) + payload(len bytes) + crc(2) + tail(2=0x0D,0x0A)
    """
    if len(buf) < i + 3:
        return None
    ln = buf[i + 2]
    # hdr(2) + len(1) + payload(ln) + CRC(2) + CRLF(2)
    return 2 + 1 + ln + 2 + 2


def _gt06_validate_crc(pkt: bytes) -> bool:
    """
    Valida CRC do frame GT06 (opcional). 'pkt' é o frame completo (inclui 78 78 ... 0D 0A).
    """
    if len(pkt) < 7:
        return False
    ln = pkt[2]
    payload = pkt[3 : 3 + ln]          # len bytes
    crc_in = int.from_bytes(pkt[3 + ln : 3 + ln + 2], "big")
    crc_calc = _crc16_x25(payload)
    return crc_in == crc_calc


def _gt06_parse_position(core: bytes):
    """Recebe payload SEM serial (proto + campos), para 0x12/0x10.
    Estrutura esperada:
      [0]    proto (0x12/0x10)
      [1:7]  YY MM DD hh mm ss
      [7]    sat/status
      [8:12] lat_raw (1/1_800_000)
      [12:16] lon_raw (1/1_800_000)
      [16]   speed_kmh
      [17:19] course/status (10 bits de rumo)
    Retorna (lat, lon, speed_knots, course_deg, dt_utc) ou None.
    """
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
    # Ex.: TRVBP00YYMMDDHHMMSS# (padrão visto nos seus testes)
    now = datetime.now(timezone.utc)
    return f"TRVBP00{now:%y%m%d%H%M%S}#"


def _trv_ack_heartbeat() -> str:
    return "TRVZP16#"


def _trv_parse_yp14(line: str):
    """Parser para TRVYP14.
    Exemplo: TRVYP14250815A0107.5297S04858.0058W001.15123.45#
    Retorna: (lat, lon, spd_knots, course, fix_time_utc, valid) ou None.
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
    # Alguns firmwares não trazem hora; usamos data do frame + hora atual (UTC) como fallback simples
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

# TRV: associa IP→IMEI para o caso de YP14 chegar em outra conexão
_peer_cache: dict[str, str] = {}
# GT06: idem, para posições que chegam sem login na mesma conexão
_gt06_peer_cache: dict[str, str] = {}


# ==========================
# Handler TCP com autodetecção
# ==========================

async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    peer_ip = None
    if isinstance(peer, tuple):
        peer_ip = peer[0]

    buf = bytearray()
    gt06_imei: Optional[str] = None

    logger.info("[TRV/GT06] Conexao de %s", peer)

    try:
        while True:
            chunk = await reader.read(1024)
            if not chunk:
                logger.info("[TRV/GT06] %s desconectou", peer)
                break
            buf += chunk

            # 1) Frames GT06 (binário: 0x78 0x78 ... CRC(2) ... 0x0D 0x0A)
            while True:
                i = buf.find(b"\x78\x78")
                if i < 0 or len(buf) < i + 3:
                    break

                frame_len = _gt06_calc_frame_len(buf, i)
                if frame_len is None:
                    break  # incompleto

                end = i + frame_len
                if len(buf) < end:
                    break  # frame incompleto

                # Captura frame completo e consume do buffer
                pkt = bytes(buf[i:end])
                del buf[:end]

                if VALIDATE_GT06_CRC and not _gt06_validate_crc(pkt):
                    logger.warning("[GT06] CRC invalido de %s: %s", peer, pkt.hex(" "))
                    continue

                ln = pkt[2]
                payload = pkt[3 : 3 + ln]  # proto.. + serial(2)
                proto = payload[0]
                serial = payload[-2:]

                # Debug básico
                logger.info("[GT06] RX proto=0x%02X len=%d from=%s", proto, ln, peer)

                # Login (0x01). Formato comum: 78 78 0D 01 08 [IMEI(8B BCD)] [serial(2)] [crc(2)] 0D 0A
                if proto == 0x01 and len(payload) >= 1 + 8 + 2:
                    imei_bcd = payload[1:9]
                    gt06_imei = _gt06_bcd_imei(imei_bcd)
                    try:
                        await ensure_device(gt06_imei, protocol="gt06", model="gf22")
                    except Exception as e:
                        logger.exception("[GT06] ensure_device falhou: %s", e)

                    # cache IP→IMEI
                    if peer_ip:
                        _gt06_peer_cache[peer_ip] = gt06_imei

                    # ACK (eco do serial + CRC X25)
                    ack = _gt06_ack(0x01, serial)
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[GT06] LOGIN imei=%s serial=%02X%02X ack=%s",
                                gt06_imei, serial[0], serial[1], ack.hex(" "))

                # Heartbeat (0x08)
                elif proto == 0x08:
                    ack = _gt06_ack(0x08, serial)
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[GT06] HEARTBEAT ack=%s", ack.hex(" "))

                # Localização (0x12/0x10)
                elif proto in (0x12, 0x10):
                    # 'payload' inclui [proto ... serial(2)], então:
                    core = payload[:-2]  # remove os 2 bytes do serial
                    parsed = _gt06_parse_position(core)
                    if parsed:
                        lat, lon, spd_knots, crs, dt = parsed
                        imei_to_use = gt06_imei
                        if not imei_to_use and peer_ip:
                            imei_to_use = _gt06_peer_cache.get(peer_ip)

                        if imei_to_use:
                            try:
                                await save_position(
                                    imei=imei_to_use,
                                    latitude=lat,
                                    longitude=lon,
                                    fix_time=dt,
                                    speed_knots=spd_knots,
                                    course_deg=crs,
                                    valid=True,
                                    raw=pkt.hex(),
                                )
                                logger.info("[GT06] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkn crs=%.1f t=%s",
                                            imei_to_use, lat, lon, spd_knots, crs, dt.isoformat())
                            except Exception as e:
                                logger.exception("[GT06] save_position falhou: %s", e)

                    # ACK posição mantém sessão viva
                    ack = _gt06_ack(proto, serial)
                    writer.write(ack)
                    await writer.drain()
                    logger.info("[GT06] POS ACK=%s", ack.hex(" "))

                else:
                    # Outros protos: log básico
                    logger.info("[GT06] Proto nao tratado: 0x%02X", proto)

            # 2) Linhas TRV (terminadas em '#')
            while True:
                j = buf.find(b"#")
                if j < 0:
                    break
                line = bytes(buf[: j + 1]).decode(errors="ignore").strip()
                del buf[: j + 1]
                if not line:
                    continue

                if not line.startswith("TRV"):
                    # demais linhas: ignorar silenciosamente
                    continue

                # Login TRV: TRVAP00<IMEI 15d>#
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
                                    imei=imei_for_trv,
                                    latitude=lat,
                                    longitude=lon,
                                    fix_time=fix_time if valid else datetime.now(timezone.utc),
                                    speed_knots=spd_knots,
                                    course_deg=crs,
                                    valid=valid,
                                    raw=line,
                                )
                                logger.info("[TRV] POS ok imei=%s lat=%.6f lon=%.6f spd=%.1fkn crs=%.1f t=%s v=%s",
                                            imei_for_trv, lat, lon, spd_knots, crs,
                                            fix_time.isoformat(), valid)
                            except Exception as e:
                                logger.exception("[TRV] save_position falhou: %s", e)
                    continue

                # Outros TRV*: ignore ou log
                logger.info("[TRV] Linha nao tratada: %s", line)

    except Exception as e:
        # Evita derrubar o servidor por frame malformado
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