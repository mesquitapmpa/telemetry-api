# app/api/status_history.py
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Literal
from datetime import datetime

router = APIRouter(prefix="/devices", tags=["devices"])

try:
    from app.usecases.list_device_status import list_device_status
except Exception as e:
    raise RuntimeError(f"Faltou implementar list_device_status: {e}")

Order = Literal["asc", "desc"]

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        # aceita ...Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Parâmetro de data inválido. Use ISO 8601, ex.: 2025-08-17T14:00:00Z",
        )

@router.get("/{device_key}/status-history")
async def status_history_by_key(
    device_key: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    order: Order = "desc",
):
    items = await list_device_status(
        key=device_key,
        since=_parse_dt(since),
        until=_parse_dt(until),
        limit=limit,
        order=order,
    )
    return {"device": device_key, "count": len(items), "items": items}

@router.get("/imei/{imei}/status-history")
async def status_history_by_imei(
    imei: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    order: Order = "desc",
):
    items = await list_device_status(
        key=imei,
        since=_parse_dt(since),
        until=_parse_dt(until),
        limit=limit,
        order=order,
    )
    return {"device": imei, "count": len(items), "items": items}

@router.get("/id/{device_id}/status-history")
async def status_history_by_id(
    device_id: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    order: Order = "desc",
):
    items = await list_device_status(
        key=device_id,
        since=_parse_dt(since),
        until=_parse_dt(until),
        limit=limit,
        order=order,
    )
    return {"device": device_id, "count": len(items), "items": items}