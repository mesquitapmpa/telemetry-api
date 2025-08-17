from datetime import datetime, timezone
from sqlalchemy import select
from app.infra.db import AsyncSessionLocal
from app.domain.models import Device, Position

KNOT_TO_KMH = 1.852

async def ensure_device(imei: str, protocol: str = "trv", model: str = "gf22") -> Device:
    async with AsyncSessionLocal() as sess:
        res = await sess.execute(select(Device).where(Device.imei == imei))
        dev = res.scalar_one_or_none()
        if not dev:
            dev = Device(imei=imei, protocol=protocol, model=model)
            sess.add(dev)
            await sess.commit()
            await sess.refresh(dev)
        return dev

async def save_position(imei: str, lat: float, lon: float, fix_time: datetime | None,
                        speed_knots: float, course_deg: float, valid: bool, raw: str):
    
    if fix_time is None:
        fix_time = datetime.now(timezone.utc)
    
    dev = await ensure_device(imei)
    async with AsyncSessionLocal() as sess:
        pos = Position(
            device_id=dev.id,
            fix_time=fix_time or datetime.now(timezone.utc),
            latitude=lat, longitude=lon,
            speed_knots=speed_knots,
            speed_kmh=round(speed_knots * KNOT_TO_KMH, 3),   # NOVO
            course_deg=course_deg,
            valid=valid, raw=raw
        )
        sess.add(pos)
        await sess.commit()
        return pos