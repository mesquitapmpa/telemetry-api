# app/routes/status_history.py
from __future__ import annotations

from fastapi import APIRouter, Query
from typing import Optional
from datetime import datetime

from app.usecases.list_device_status import list_device_status

router = APIRouter(prefix="", tags=["status-history"])

@router.get("/devices/{key}/status-history")
async def get_status_history(
    key: str,                                # id OU imei
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    order: str = Query("desc", pattern="^(?i)(asc|desc)$"),
):
    items = await list_device_status(key=key, since=since, until=until, limit=limit, order=order)
    return {
        "device_key": key,
        "count": len(items),
        "items": items,
    }