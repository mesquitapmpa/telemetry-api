from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select
from app.infra.db import AsyncSessionLocal
from app.domain.models import Device, Position
import os

router = APIRouter()
TRACK_DEFAULT_LIMIT = int(os.getenv("TRACK_DEFAULT_LIMIT", "50"))

@router.get("/health")
async def health():
    return {"status": "ok"}

@router.get("/", include_in_schema=False)
def root():
    # redireciona a raiz para a documentação
    # return RedirectResponse(url="/docs")
    # (alternativa) retornar JSON:
    return {"status": "ok", "docs": "/docs", "health": "/health"}

@router.get("/devices")
async def list_devices():
    async with AsyncSessionLocal() as sess:
        res = await sess.execute(select(Device))
        return [ {"imei": d.imei, "model": d.model, "protocol": d.protocol} for d in res.scalars() ]

@router.get("/positions/latest")
async def latest(imei: str):
    async with AsyncSessionLocal() as sess:
        dev = (await sess.execute(select(Device).where(Device.imei == imei))).scalar_one_or_none()
        if not dev: raise HTTPException(404, "device not found")
        res = await sess.execute(
            select(Position).where(Position.device_id == dev.id).order_by(Position.fix_time.desc()).limit(1)
        )
        p = res.scalar_one_or_none()
        if not p: raise HTTPException(404, "no positions")
        return {
            "imei": imei,
            "latitude": p.latitude,
            "longitude": p.longitude,
            "speed_knots": p.speed_knots,
            "speed_kmh": p.speed_kmh,
            "course_deg": p.course_deg,
            "fix_time": p.fix_time.isoformat(),
            "valid": p.valid
        }

@router.get("/positions/track")
async def track(imei: str, limit: int = Query(TRACK_DEFAULT_LIMIT, ge=1, le=1000)):
    """
    Retorna as últimas N posições (ordem cronológica crescente por fix_time).
    """
    async with AsyncSessionLocal() as sess:
        dev = (await sess.execute(select(Device).where(Device.imei == imei))).scalar_one_or_none()
        if not dev: raise HTTPException(404, "device not found")
        res = await sess.execute(
            select(Position).where(Position.device_id == dev.id)
            .order_by(Position.fix_time.desc())
            .limit(limit)
        )
        rows = list(res.scalars())
        if not rows: raise HTTPException(404, "no positions")
        rows = list(reversed(rows))  # crescente por fix_time
        return [
            {
                "fix_time": p.fix_time.isoformat(),
                "lat": p.latitude,
                "lon": p.longitude,
                "speed_knots": p.speed_knots,
                "speed_kmh": p.speed_kmh,
                "course_deg": p.course_deg,
                "valid": p.valid,
            } for p in rows
        ]