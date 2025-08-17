# app/protocols/trv.py
import asyncio
import sys
import socket
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

VALIDATE_GT06_CRC = os.getenv("GT06_VALIDATE_CRC", "false").lower() == "true"
LOG_LEGACY = os.getenv("GT06_LOG_LEGACY", "true").lower() == "true"

# ============================
# Helpers de log legado
# ============================
def _hex_spaced(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ============================
# Checksums
# ============================
def crc16_x25(data: bytes) -> int:
    """
    CRC-16/X25 (CRC-16/IBM-SDLC): init=0xFFFF, poly=0x1021 (refin/refout), xorout=0xFFFF.
    Aqui implementado pelo clássico 0x8408 em little pass e retorno byte-swapped big-endian.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    crc = ~crc & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

# ============================
# ACK (espelha header e modo)
# ============================
def build_ack(header: int, msg_type: int, serial_bytes: bytes, checksum_mode: str) -> bytes:
    """
    Constrói ACK compatível com o modo detectado no frame recebido.
    - CRC16: len = 1(type)+2(serial)+2(crc) = 0x05
    - SUM8/TRUNC: usamos len = 0x05 também (serial=ecoado quando disponível, senão 0000) + 1 byte de SUM8.
    """
    hdr = b"\x78\x78" if header == 0x7878 else b"\x79\x79"

    serial = serial_bytes or b"\x00\x00"
    if len(serial) == 1:
        serial = b"\x00" + serial
    elif len(serial) >= 2:
        serial = serial[-2:]

    body = bytes([msg_type]) + serial

    if checksum_mode == "CRC16":
        length = 0x05
        pkt_wo_crc = hdr + bytes([length]) + body
        crc = crc16_x25(pkt_wo_crc[2:])
        return pkt_wo_crc + struct.pack(">H", crc) + b"\x0D\x0A"

    # SUM8 e TRUNC → responder com SUM8 (compat clones), ecoando serial quando houver
    length = 0x05
    pkt_wo_sum = hdr + bytes([length]) + body
    cs = sum8(pkt_wo_sum[2:])
    return pkt_wo_sum + bytes([cs]) + b"\x0D\x0A"

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

def _decode_bcd_pairs(b: bytes) -> str:
    # Converte bytes BCD em string de dígitos (dois dígitos por byte)
    return ''.join(f"{(x >> 4) & 0xF}{x & 0xF}" for x in b)

def decode_bcd_imei(imei_bcd: bytes) -> str:
    """
    Decodifica IMEI BCD de 8 bytes (formato GT06).
    Regra: remover APENAS o primeiro '0' inicial (nibble alto de 0x08), preservando zeros legítimos.
    Ex.: b'\x08\x61\x26\x10\x29\x74\x03\x19' -> '861261029740319'
    """
    logger.debug("[GT06] IMEI_BCD_RAW=%s", binascii.hexlify(imei_bcd).decode().upper())
    s = ''.join(f"{(b>>4)&0xF}{b&0xF}" for b in imei_bcd)  # p.ex.: '0861261029740319' ou '8612610297403196'
    if s and s[0] == '0':  # caso '08...'
        s = s[1:]
    return s[:15]          # garante 15 dígitos

def _is_bcd_digits(b: bytes) -> bool:
    # True se todos os nibbles forem 0–9 (evita “falsos positivos” no fallback)
    return all((((x >> 4) & 0xF) <= 9 and (x & 0xF) <= 9) for x in b)

def extract_login_imei_from_payload(payload: bytes) -> Optional[str]:
    """
    Extrai IMEI do payload do login:
    - ASCII: 0x0F + 15 dígitos
    - BCD:   8 BYTES diretamente (o 1º byte do IMEI muitas vezes é 0x08 — não é um “marcador”, é o próprio BCD)
    - Fallback robusto: procura uma janela de 8 bytes BCD começando por 0x08 OU a primeira janela BCD válida.
    """
    if not payload:
        return None

    # ASCII 0x0F
    if payload[:1] == b"\x0F" and len(payload) >= 16:
        try:
            s = payload[1:16].decode(errors="ignore")
            if s.isdigit() and len(s) == 15:
                return s
        except Exception:
            pass

    # BCD: muitos firmwares começam com 0x08 no PRIMEIRO byte do IMEI (não é prefixo separado!)
    # Portanto, se o 1º byte já é BCD (geralmente 0x08 ou 0x86), pegamos os PRIMEIROS 8 BYTES.
    if len(payload) >= 8 and _is_bcd_digits(payload[0:8]):
        s = decode_bcd_imei(payload[0:8])
        if s.isdigit() and len(s) == 15:
            return s

    # -------- Fallback robusto --------
    # 1) Procura a janela “clássica”: 8 bytes BCD cujo 1º byte seja 0x08.
    for i in range(0, max(0, len(payload) - 7)):
        win = payload[i:i+8]
        if not _is_bcd_digits(win):
            continue
        if win[0] == 0x08:
            s = decode_bcd_imei(win)
            if s.isdigit() and len(s) == 15:
                return s

    # 2) Se não achou, aceita a primeira janela BCD válida (menos rigorosa, mas evita desalinhamento).
    for i in range(0, max(0, len(payload) - 7)):
        win = payload[i:i+8]
        if not _is_bcd_digits(win):
            continue
        s = decode_bcd_imei(win)
        if s.isdigit() and len(s) == 15:
            return s

    return None

def parse_gps_basic(payload: bytes) -> Optional[dict]:
    """
    [time6][flags1][lat4][lon4][speed1][course2]
    bit11 fix, bit12 W, bit13 S
    """
    if len(payload) < 6+1+4+4+1+2:
        return None
    dt = parse_datetime_bcd(payload[0:6])
    lat_raw = int.from_bytes(payload[7:11], "big", signed=False)
    lon_raw = int.from_bytes(payload[11:15], "big", signed=False)
    speed_kmh = float(payload[15]) * 1.852
    cflags = struct.unpack(">H", payload[16:18])[0]
    course = float(cflags & 0x03FF)
    gps_fixed = bool(cflags & (1 << 11))
    west = bool(cflags & (1 << 12))
    south = bool(cflags & (1 << 13))
    lat = lat_raw / 1800000.0
    lon = lon_raw / 1800000.0
    if south: lat = -lat
    if west:  lon = -lon
    return {
        "time": dt,
        "lat": lat,
        "lon": lon,
        "speed_kmh": speed_kmh,
        "course": course,
        "valid": gps_fixed,
        "raw_flags": cflags,
    }

# ============================
# Sessão por conexão
# ============================
class ConnState:
    __slots__ = ("device", "imei_seen")
    def __init__(self):
        self.device: Optional[Dict[str, Any]] = None
        self.imei_seen: Optional[str] = None

def _device_as_dict(dev: Any) -> Optional[Dict[str, Any]]:
    if dev is None:
        return None
    if isinstance(dev, dict):
        did = dev.get("id"); imei = dev.get("imei")
        return {"id": did, "imei": imei} if did and imei else None
    did = getattr(dev, "id", None); imei = getattr(dev, "imei", None)
    return {"id": did, "imei": imei} if did and imei else None

# ============================
# save_position compat
# ============================
def _normalize_param_name(name: str) -> str:
    n = name.lower()
    aliases = {
        "imei": "imei", "device_id": "device_id",
        "latitude": "lat", "lat": "lat",
        "longitude": "lon", "lng": "lon", "long": "lon",
        "fix_time": "fix_time", "fixtime": "fix_time", "time": "fix_time", "dt": "fix_time",
        "speed_knots": "speed_knots", "speed": "speed_knots", "spd": "speed_knots",
        "speed_kmh": "speed_kmh",
        "course": "course_deg", "course_deg": "course_deg", "heading": "course_deg",
        "valid": "valid", "raw": "raw",
    }
    return aliases.get(n, n)

async def _call_maybe_async(fn, *args, **kwargs):
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return await res
    return res

async def _save_position_compat(state_device: Dict[str, Any], gps: Dict[str, Any], raw_hex: str):
    imei = state_device.get("imei")
    dev_id = state_device.get("id")

    fix_time = gps["time"]
    lat = float(gps["lat"])
    lon = float(gps["lon"])
    speed_kmh = float(gps["speed_kmh"])
    speed_knots = speed_kmh * 0.539957
    course_deg = float(gps["course"])
    valid = bool(gps["valid"])

    # kwargs 1º
    try:
        sig = inspect.signature(save_position)
        kw = {}
        for p in sig.parameters.keys():
            pn = _normalize_param_name(p)
            if pn == "device_id" and dev_id: kw[p] = dev_id
            if pn == "imei" and imei:        kw[p] = imei
            if pn == "lat":                  kw[p] = lat
            if pn == "lon":                  kw[p] = lon
            if pn == "fix_time":             kw[p] = fix_time
            if pn == "speed_knots":          kw[p] = speed_knots
            if pn == "speed_kmh":            kw[p] = speed_kmh
            if pn == "course_deg":           kw[p] = course_deg
            if pn == "valid":                kw[p] = valid
            if pn == "raw":                  kw[p] = raw_hex
        if kw:
            return await _call_maybe_async(save_position, **kw)
    except Exception:
        pass

    # posicional clássico
    return await _call_maybe_async(
        save_position,
        imei, lat, lon, fix_time, speed_knots, course_deg, valid, raw_hex
    )

# ============================
# Deframer por buffer
# ============================
def _find_next_header(buf: bytearray, start: int = 0) -> Tuple[int, Optional[int]]:
    i = buf.find(b"\x78\x78", start)
    j = buf.find(b"\x79\x79", start)
    if i == -1 and j == -1:
        return -1, None
    if i == -1:
        return j, 0x7979
    if j == -1:
        return i, 0x7878
    return (i, 0x7878) if i < j else (j, 0x7979)

def _detect_checksum_from_raw(raw: bytes) -> Tuple[str, bytes, bytes]:
    """
    raw = [hdr2][len1][type+payload(+serial?)(+chk?)] [0D 0A]
    Retorna (checksum_mode, serial_bytes, payload_full = [type]+payload[+serial?]).
    """
    if len(raw) < 7 or raw[-2:] != b"\x0D\x0A":
        return ("TRUNC", b"", b"")
    hdr = raw[:2]
    length = raw[2]
    content = raw[3:-2]  # entre len e CRLF
    if len(content) < 1:
        return ("TRUNC", b"", b"")
    msg_type_b = content[:1]
    rest = content[1:]

    # CRC16
    if len(rest) >= 2:
        crc_recv = struct.unpack(">H", rest[-2:])[0]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-2]
        if crc16_x25(candidate[2:]) == crc_recv:
            serial = rest[-4:-2] if len(rest) >= 4 else b"\x00\x00"
            return ("CRC16", serial, msg_type_b + rest[:-2])

    # SUM8
    if len(rest) >= 1:
        sum_recv = rest[-1]
        candidate = hdr + bytes([length]) + msg_type_b + rest[:-1]
        if (sum8(candidate[2:]) & 0xFF) == sum_recv:
            serial = rest[-3:-1] if len(rest) >= 3 else b"\x00\x00"
            return ("SUM8", serial, msg_type_b + rest[:-1])

    # --- TRUNC ---
    # Heurística para recuperar SERIAL em frames sem checksum reconhecido.
    # Útil no LOGIN (0x01) de alguns clones que omitem CRC/SUM.
    serial_guess = b""
    try:
        msg_t = msg_type_b[0]
        if msg_t == 0x01:
            # Com CRC no login: 0x01 + IMEI(8) + SERIAL(2) + CRC(2)  -> len(rest) >= 12, length ~ 0x0D
            if len(rest) >= 12 and length in (0x0D, 13):
                serial_guess = rest[-4:-2]
            # Sem CRC no login: 0x01 + IMEI(8) + SERIAL(2)           -> len(rest) >= 10
            elif len(rest) >= 10:
                serial_guess = rest[-2:]
            # Clones TRUNC com SERIAL de 1 byte: 0x01 + IMEI(8) + SERIAL(1) -> len(rest) >= 9
            elif len(rest) >= 9:
                serial_guess = rest[-1:]       # 1 byte
        
        elif msg_t == 0x13:
            # Heartbeat TRUNC: muitos clones colocam o SERIAL nos 2 últimos bytes do body
            # Exemplo do seu frame: 78 78 07 13 5B 60 08 19 37 0D 0A  -> serial = 0x19 0x37
            if len(rest) >= 2:
                serial_guess = rest[-2:]
    except Exception:
        pass

    return ("TRUNC", serial_guess, msg_type_b + rest)

async def _frame_loop(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: str, state: ConnState):
    buf = bytearray()
    while True:
        try:
            chunk = await reader.read(4096)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            return
        if not chunk:
            return
        buf += chunk

        if LOG_LEGACY:
            try:
                logger.info("[GT06] CHUNK %dB from %s: %s", len(chunk), peer, _hex_spaced(chunk))
            except Exception:
                pass

        while True:
            i, header_val = _find_next_header(buf, 0)
            if i < 0 or len(buf) < i + 3:
                break

            hdr = bytes(buf[i:i+2])
            length = buf[i+2]
            end_decl = i + 2 + 1 + length + 2  # hdr2 + len1 + body + CRLF2

            if len(buf) < end_decl:
                tail_pos = buf.find(b"\x0D\x0A", i + 3)
                if tail_pos < 0:
                    break
                end = tail_pos + 2
            else:
                end = end_decl if buf[end_decl-2:end_decl] == b"\x0D\x0A" else (buf.find(b"\x0D\x0A", i + 3) + 2)

            if end <= 0 or end > len(buf):
                break

            raw = bytes(buf[i:end])
            del buf[:end]

            if len(raw) < 7 or raw[:2] not in (b"\x78\x78", b"\x79\x79") or raw[-2:] != b"\x0D\x0A":
                continue

            checksum_mode, serial_bytes, payload_full = _detect_checksum_from_raw(raw)
            if not payload_full:
                continue

            msg_type = payload_full[0]
            payload = payload_full[1:]

            length_byte = raw[2]
            logger.info("[GT06] RX type=0x%02X len_byte=%d chk=%s serial=%s",
                        msg_type, length_byte, checksum_mode,
                        binascii.hexlify(serial_bytes).decode().upper() or "∅")

            if LOG_LEGACY:
                cs_len = 0 if checksum_mode == "TRUNC" else (1 if checksum_mode == "SUM8" else 2)
                ser_len = 2 if len(serial_bytes) else 0
                body_len_approx = max(0, int(length_byte) - (1 + ser_len + (0 if checksum_mode == "TRUNC" else cs_len)))
                logger.info("[GT06] RX proto=0x%02X body_len~%d cs_len=%d from=%s",
                            msg_type, body_len_approx, cs_len, peer)

            # ACK (ecoando serial quando disponível; checksum no mesmo modo do RX)
            ack = build_ack(0x7878 if hdr == b"\x78\x78" else 0x7979, msg_type, serial_bytes, checksum_mode)
            try:
                writer.write(ack)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                return

            mode = "TRUNC" if checksum_mode == "TRUNC" else ("SUM" if checksum_mode == "SUM8" else "CRC16")
            if LOG_LEGACY:
                logger.info("[GT06] 0x%02X TX_ACK=%s (mode=%s)", msg_type, _hex_spaced(ack), mode)
            logger.info("[GT06] TX_ACK=%s", binascii.hexlify(ack).decode().upper())

            # Dispatch
            try:
                if msg_type == 0x01:
                    await handle_login(payload, binascii.hexlify(raw).decode().upper(), peer, state)
                elif msg_type in (0x10, 0x11, 0x12, 0x16, 0x26):
                    await handle_gps(payload, binascii.hexlify(raw).decode().upper(), state)
                # 0x13/0x08/0x30/0x80 -> só ACK acima (mantido)
            except Exception as e:
                logger.exception("[GT06] Erro no handler do tipo 0x%02X: %s", msg_type, e)

# ============================
# Handlers
# ============================
async def handle_login(payload: bytes, raw_hex: str, peer: str, state: ConnState):
    # Logar payload do login ajuda a auditar o alinhamento (deve começar com 08 ou 86 na maioria dos BCDs)
    logger.info("[GT06] LOGIN payload=%s", binascii.hexlify(payload).decode().upper())

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
        logger.warning("[GT06] GPS payload curto/indecifrável: %s", binascii.hexlify(payload).decode().upper())
        return

    if not state.device and state.imei_seen and state.imei_seen.isdigit() and len(state.imei_seen) == 15:
        try:
            dev = await ensure_device_canonical("gt06", state.imei_seen)
            state.device = _device_as_dict(dev)
        except Exception:
            pass

    if not state.device:
        logger.warning("[GT06] Sem device canônico; descartando posição.")
        return

    await _save_position_compat(state.device, gps, raw_hex)
    logger.info("[GT06] POS salva device_id=%s lat=%.6f lon=%.6f v=%.1f km/h curso=%.1f valid=%s",
                state.device["id"], gps["lat"], gps["lon"], gps["speed_kmh"], gps["course"], gps["valid"])

def _set_tcp_keepalive(sock, idle=30, interval=10, count=3, user_timeout_ms=45000):
    """
    Liga keepalive no socket de forma portátil.
    idle/interval/count em segundos (user_timeout em ms, Linux).
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception as e:
        logger.debug("[GT06] SO_KEEPALIVE falhou: %s", e)

    plat = sys.platform

    # --- Linux ---
    if plat.startswith("linux"):
        def _try_opt(opt_name, val):
            opt = getattr(socket, opt_name, None)
            if opt is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, opt, val)
                except Exception as e:
                    logger.debug("[GT06] %s falhou: %s", opt_name, e)

        _try_opt("TCP_KEEPIDLE", idle)
        _try_opt("TCP_KEEPINTVL", interval)
        _try_opt("TCP_KEEPCNT", count)

        # TCP_USER_TIMEOUT (ms) – pode não existir; em muitos sistemas é 18
        opt_user_to = getattr(socket, "TCP_USER_TIMEOUT", 18)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt_user_to, user_timeout_ms)
        except Exception as e:
            logger.debug("[GT06] TCP_USER_TIMEOUT falhou: %s", e)

    # --- macOS ---
    elif plat == "darwin":
        opt = getattr(socket, "TCP_KEEPALIVE", None)
        if opt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, idle)
            except Exception as e:
                logger.debug("[GT06] TCP_KEEPALIVE (macOS) falhou: %s", e)

    # --- Windows ---
    elif plat == "win32":
        # Usa SIO_KEEPALIVE_VALS: (onoff, keepalivetime_ms, keepaliveinterval_ms)
        import struct as _struct
        SIO_KEEPALIVE_VALS = 0x98000004
        try:
            sock.ioctl(SIO_KEEPALIVE_VALS, _struct.pack("III", 1, idle * 1000, interval * 1000))
        except Exception as e:
            logger.debug("[GT06] SIO_KEEPALIVE_VALS falhou: %s", e)

    # --- Outros (BSDs etc.) ---
    else:
        for name, val in (
            ("TCP_KEEPIDLE", idle),
            ("TCP_KEEPINTVL", interval),
            ("TCP_KEEPCNT", count),
            ("TCP_KEEPALIVE", idle),
        ):
            opt = getattr(socket, name, None)
            if opt is None:
                continue
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, val)
            except Exception as e:
                logger.debug("[GT06] %s falhou: %s", name, e)

# ============================
# Server
# ============================
async def gt06_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # --- socket options (keepalive) ---
  
    sock = writer.get_extra_info("socket")
    if sock is not None:
        _set_tcp_keepalive(sock, idle=30, interval=10, count=3, user_timeout_ms=45000)

    peer = writer.get_extra_info("peername")
    logger.info("[TRV/GT06] Conexao de %s", peer)
    state = ConnState()
    try:
        await _frame_loop(reader, writer, str(peer), state)

    except asyncio.IncompleteReadError:
        # EOF do peer: ele fechou primeiro
        logger.info("[TRV/GT06] Peer encerrou a conexao: %s", peer)

    except (ConnectionResetError, BrokenPipeError):
        logger.info("[TRV/GT06] Conexao resetada/quebrada: %s", peer)

    except Exception as e:
        logger.exception("[GT06] erro: %s", e)

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info("[TRV/GT06] Conexao finalizada: %s", peer)

async def run(port: int = 5010):
    server = await asyncio.start_server(gt06_server, "0.0.0.0", port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"[TRV/GT06] Servidor escutando em {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run(int(os.getenv("TRV_PORT", "5010"))))