import asyncio, re, os, time
from datetime import datetime, timezone
from app.usecases.save_position import ensure_device, save_position

TRV_PORT = int(os.getenv("TRV_PORT", "5010"))
ALLOW_IP_CACHE = os.getenv("TRV_ALLOW_IP_CACHE", "false").lower() == "true"
IP_CACHE_TTL = 300  # segundos

# cache simples imei por IP
LAST_IMEI_BY_IP: dict[str, tuple[str, float]] = {}  # ip -> (imei, ts)

class SessionState:
    def __init__(self): self.imei: str | None = None

IMEI_RE = re.compile(r"^TRVAP00(?P<imei>\d{15})#$")
HEART_RE = re.compile(r"^TRVYP16,.*#$")
POS14_RE = re.compile(
    r"^TRVYP14(?P<date>\d{6})(?P<valid>[AV])"
    r"(?P<lat>\d{4}\.\d+)(?P<ns>[NS])"
    r"(?P<lon>\d{5}\.\d+)(?P<ew>[EW])"
    r"(?P<speed>\d+\.\d+)"
    r"(?P<course>\d+\.\d+).*$"
)

def dm_to_deg(dm: str, is_lat: bool) -> float:
    if is_lat:
        deg = int(dm[:2]); minutes = float(dm[2:])
    else:
        deg = int(dm[:3]); minutes = float(dm[3:])
    return deg + minutes/60.0

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if isinstance(peer, tuple) else "unknown"
    state = SessionState()
    try:
        while not reader.at_eof():
            raw = await reader.readuntil(b"#")
            line = raw.decode("ascii", errors="ignore")
            print(f"[TRV] {peer} :: {line.strip()}")

            # LOGIN
            m = IMEI_RE.match(line)
            if m:
                state.imei = m.group("imei")
                LAST_IMEI_BY_IP[ip] = (state.imei, time.time())
                await ensure_device(state.imei, protocol="trv", model="gf22")
                utc = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                writer.write(f"TRVBP00{utc}#".encode("ascii"))
                await writer.drain()
                continue

            # HEARTBEAT
            if HEART_RE.match(line):
                writer.write(b"TRVZP16#"); await writer.drain()
                continue

            # POSIÇÃO
            m = POS14_RE.match(line)
            if m:
                imei = state.imei
                if not imei and ALLOW_IP_CACHE:
                    cached = LAST_IMEI_BY_IP.get(ip)
                    if cached and time.time() - cached[1] <= IP_CACHE_TTL:
                        imei = cached[0]
                if not imei:
                    # sem IMEI associado, ignore com log
                    print(f"[TRV] {peer} :: YP14 ignorado (sem IMEI na sessão)")
                    continue

                valid = m.group("valid") == "A"
                lat = dm_to_deg(m.group("lat"), is_lat=True)
                if m.group("ns") == "S": lat = -lat
                lon = dm_to_deg(m.group("lon"), is_lat=False)
                if m.group("ew") == "W": lon = -lon
                speed = float(m.group("speed"))
                course = float(m.group("course"))
                await save_position(
                    imei=imei,
                    lat=lat, lon=lon,
                    fix_time=None,
                    speed_knots=speed, course_deg=course,
                    valid=valid, raw=line
                )
                continue

            # fallback para outros YP*
            if line.startswith("TRVY") and line.endswith("#"):
                if "P16" in line:
                    writer.write(b"TRVZP16#"); await writer.drain()
                continue
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        try: writer.close(); await writer.wait_closed()
        except Exception: pass

async def start_trv_server():
    server = await asyncio.start_server(handle, "0.0.0.0", TRV_PORT)
    return server