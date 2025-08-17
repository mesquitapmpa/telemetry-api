# app/usecases/save_device_status.py
from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone
import os, uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

# 1) Tenta usar a fábrica de sessão async do seu projeto
async_session = None
try:
    # ajuste se sua factory tiver outro nome (ex.: async_session_maker)
    from app.infra.db import async_session as _project_async_session
    async_session = _project_async_session
except Exception:
    async_session = None

# 2) Tenta importar os models ORM (usamos como "melhor caminho"); se faltar, caímos no SQL cru
Device = None
try:
    # tente o caminho que você realmente usa para os models:
    from app.domain.models import Device as _Device   # <-- ajuste se necessário
    Device = _Device
except Exception:
    try:
        from app.domain.models import Device as _Device
        Device = _Device
    except Exception:
        Device = None  # vamos usar UPDATE/INSERT com SQL cru

def _now() -> datetime:
    return datetime.now(timezone.utc)

# 3) Se não houver async_session no projeto, criamos uma "de emergência" via DATABASE_URL
_engine = None
_session_factory = None
if async_session is None:
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL or not DATABASE_URL.startswith("postgresql+asyncpg://"):
        raise RuntimeError(
            "DATABASE_URL async (postgresql+asyncpg) não encontrado e app.infra.db.async_session indisponível."
        )
    _engine = create_async_engine(DATABASE_URL, future=True)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

async def _get_session() -> AsyncSession:
    if async_session is not None:
        # assume que async_session é um factory async: async with async_session() as s:
        return await async_session().__aenter__()  # devolve sessão já aberta; chamaremos __aexit__ ao final
    else:
        return await _session_factory().__aenter__()

async def _close_session(sess: AsyncSession):
    # fecha o context manager criado acima
    try:
        if async_session is not None:
            await async_session().__aexit__(None, None, None)
        else:
            await _session_factory().__aexit__(None, None, None)
    except Exception:
        # em último caso, tenta fechar direto
        await sess.close()

async def save_device_status(
    *,
    device_id: Optional[str] = None,
    imei: Optional[str] = None,
    battery_pct: Optional[int] = None,
    gsm_pct: Optional[int] = None,
    charging: Optional[bool] = None,
    acc_on: Optional[bool] = None,
    gps_fix: Optional[bool] = None,
    raw_voltage: Optional[int] = None,
    raw_gsm: Optional[int] = None,
    when: Optional[datetime] = None,
    record_history: bool = True,
    session: Optional[AsyncSession] = None,
) -> None:
    """
    Atualiza snapshot em `devices` e insere uma linha em `device_status_history` (se record_history=True).
    Aceita `device_id` OU `imei`. Usa AsyncSession do projeto se disponível; senão cria uma.
    """
    when = when or _now()
    own = False

    if session is None:
        session = await _get_session()
        own = True

    try:
        # 1) Obter o ID do device
        dev_id = device_id
        if not dev_id:
            # Buscar por IMEI
            res = await session.execute(text("SELECT id FROM devices WHERE imei = :imei LIMIT 1"), {"imei": imei})
            row = res.first()
            if not row:
                # não existe device — nada a fazer
                return
            dev_id = row[0]

        # 2) Atualizar snapshot (ORM se possível; caso contrário, SQL cru)
        if Device is not None:
            dev_obj = await session.get(Device, dev_id)
            if dev_obj is None:
                return
            updated = False
            if battery_pct is not None: dev_obj.battery_pct = int(battery_pct); updated = True
            if gsm_pct is not None:     dev_obj.gsm_pct = int(gsm_pct);         updated = True
            if charging is not None:    dev_obj.charging = bool(charging);      updated = True
            if acc_on is not None:      dev_obj.acc_on = bool(acc_on);          updated = True
            if gps_fix is not None:     dev_obj.gps_fix = bool(gps_fix);        updated = True
            if updated:
                dev_obj.status_updated_at = when
        else:
            sets = []
            params = {"id": dev_id, "when": when}
            if battery_pct is not None: sets.append("battery_pct = :battery_pct"); params["battery_pct"] = int(battery_pct)
            if gsm_pct is not None:     sets.append("gsm_pct = :gsm_pct");         params["gsm_pct"] = int(gsm_pct)
            if charging is not None:    sets.append("charging = :charging");       params["charging"] = bool(charging)
            if acc_on is not None:      sets.append("acc_on = :acc_on");           params["acc_on"] = bool(acc_on)
            if gps_fix is not None:     sets.append("gps_fix = :gps_fix");         params["gps_fix"] = bool(gps_fix)
            if sets:
                sets.append("status_updated_at = :when")
                sql = "UPDATE devices SET " + ", ".join(sets) + " WHERE id = :id"
                await session.execute(text(sql), params)

        # 3) Inserir histórico (sempre que record_history=True)
        if record_history:
            hid = str(uuid.uuid4())
            await session.execute(
                text("""
                    INSERT INTO device_status_history
                       (id, device_id, "when", battery_pct, gsm_pct, charging, acc_on, gps_fix, raw_voltage, raw_gsm)
                    VALUES
                       (:id, :device_id, :when, :battery_pct, :gsm_pct, :charging, :acc_on, :gps_fix, :raw_voltage, :raw_gsm)
                """),
                {
                    "id": hid,
                    "device_id": dev_id,
                    "when": when,
                    "battery_pct": int(battery_pct) if battery_pct is not None else None,
                    "gsm_pct": int(gsm_pct) if gsm_pct is not None else None,
                    "charging": bool(charging) if charging is not None else None,
                    "acc_on": bool(acc_on) if acc_on is not None else None,
                    "gps_fix": bool(gps_fix) if gps_fix is not None else None,
                    "raw_voltage": int(raw_voltage) if raw_voltage is not None else None,
                    "raw_gsm": int(raw_gsm) if raw_gsm is not None else None,
                }
            )

        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        if own:
            # fecha o context manager / sessão criada aqui
            try:
                await session.close()
            except Exception:
                pass
