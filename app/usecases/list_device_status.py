# app/usecases/list_device_status.py
from __future__ import annotations

from typing import List, Optional, Literal, Dict, Any
from datetime import datetime

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.infra.db import async_session_maker  # ajuste o nome se for diferente
from app.infra.db import Base  # só para manter consistência de import do seu projeto
from app.domain.models import Device, DeviceStatusHistory  # se seus modelos moram noutro módulo, ajuste

Order = Literal["asc", "desc"]

async def list_device_status(
    key: str,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
    order: Order = "desc",
) -> List[Dict[str, Any]]:
    """
    Retorna histórico de status do dispositivo identificado por `key` (device_id OU imei).
    """
    # abre sessão (ajuste para o seu factory se necessário)
    async with async_session_maker() as session:  # type: AsyncSession
        # 1) resolver device pelo id OU imei
        dev = await _get_device_by_key(session, key)
        if not dev:
            return []

        # 2) montar query
        q = select(DeviceStatusHistory).where(DeviceStatusHistory.device_id == dev.id)

        if since is not None:
            q = q.where(DeviceStatusHistory.when >= since)
        if until is not None:
            q = q.where(DeviceStatusHistory.when <= until)

        if order == "asc":
            q = q.order_by(DeviceStatusHistory.when.asc())
        else:
            q = q.order_by(DeviceStatusHistory.when.desc())

        if limit:
            q = q.limit(max(1, min(1000, int(limit))))

        rows = (await session.execute(q)).scalars().all()

        # 3) serializar no formato esperado pela rota
        out = []
        for r in rows:
            out.append({
                "when": r.when,
                "battery_pct": r.battery_pct,
                "gsm_pct": r.gsm_pct,
                "charging": r.charging,
                "acc_on": r.acc_on,
                "gps_fix": r.gps_fix,
                "raw_voltage": r.raw_voltage,
                "raw_gsm": r.raw_gsm,
            })
        return out


async def _get_device_by_key(session: AsyncSession, key: str) -> Optional[Device]:
    # tenta id exato OU imei exato
    q = select(Device).where((Device.id == key) | (Device.imei == key))
    return await session.scalar(q)