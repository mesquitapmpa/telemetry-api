# app/routes/status_history.py
from typing import List, Optional, Literal
from datetime import datetime
import inspect

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(tags=["status"])

class DeviceStatusOut(BaseModel):
    when: datetime
    battery_pct: Optional[int] = None
    gsm_pct: Optional[int] = None
    charging: Optional[bool] = None
    acc_on: Optional[bool] = None
    gps_fix: Optional[bool] = None
    raw_voltage: Optional[int] = None
    raw_gsm: Optional[int] = None

async def _call_maybe_async(fn, *args, **kwargs):
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return await res
    return res

@router.get("/devices/{key}/status-history", response_model=List[DeviceStatusOut])
async def status_history(
    key: str,  # pode ser device_id ou imei (gravamos em ambos)
    since: Optional[datetime] = Query(None, description="Filtra a partir desta data/hora (UTC/ISO)"),
    until: Optional[datetime] = Query(None, description="Filtra até esta data/hora (UTC/ISO)"),
    limit: int = Query(100, ge=1, le=1000),
    order: Literal["asc", "desc"] = Query("desc"),
):
    """
    Retorna histórico de status do dispositivo.
    Backend padrão: buffer em memória preenchido por trv._save_status_efficient.
    Se 'list_device_status' existir em app.usecases, usa-o (banco) automaticamente.
    """
    # Se existir um usecase de banco, use-o
    try:
        from app.usecases.list_device_status import list_device_status  # opcional
        rows = await _call_maybe_async(
            list_device_status, key=key, since=since, until=until, limit=limit, order=order
        )
        # Espera-se que rows seja iterável de dicts compatíveis; se necessário, adapte aqui.
        return rows
    except Exception:
        # fallback para buffer em memória
        pass

    # Fallback: STATUS_HISTORY (memória)
    try:
        from app.protocols.trv import STATUS_HISTORY
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"STATUS_HISTORY não acessível: {e}")

    items = list(STATUS_HISTORY.get(key, []))
    if not items:
        # tenta também a outra chave (se veio imei, tenta como device_id e vice-versa)
        # não sabemos mapear aqui; então apenas retorna vazio se não houver
        return []

    # filtros
    if since:
        items = [x for x in items if x["when"] >= since]
    if until:
        items = [x for x in items if x["when"] <= until]

    # ordenação
    items.sort(key=lambda x: x["when"], reverse=(order == "desc"))

    # corte
    items = items[:limit]

    # Pydantic converte dict->model
    return items