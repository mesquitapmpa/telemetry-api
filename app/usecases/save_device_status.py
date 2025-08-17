# app/usecases/save_device_status.py
from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.infra.db import SessionLocal  # adapte se o seu projeto expõe a Session de outra forma
from app.infra.db import Base          # opcional, apenas para tipagem
from app.domain.models import Device, DeviceStatusHistory  # ajuste o caminho conforme seu projeto

def _now():
    return datetime.now(timezone.utc)

def save_device_status(
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
    session: Optional[Session] = None,
) -> None:
    """
    Atualiza o snapshot de status em `devices` e (opcionalmente) grava uma linha no histórico.

    - Informe `device_id` OU `imei`.
    - Se `session` não for passada, a função abre/fecha uma session própria.
    """
    when = when or _now()

    own_session = False
    if session is None:
        session = SessionLocal()  # <- garanta que exista em app.infra.db
        own_session = True

    try:
        # 1) carrega o device
        if device_id:
            device = session.get(Device, device_id)
        else:
            device = session.query(Device).filter(Device.imei == imei).first()

        if not device:
            # não aborta o fluxo do servidor; apenas não há onde gravar
            if own_session:
                session.close()
            return

        # 2) atualiza snapshot se algo foi informado
        updated = False
        if battery_pct is not None:
            device.battery_pct = int(battery_pct)
            updated = True
        if gsm_pct is not None:
            device.gsm_pct = int(gsm_pct)
            updated = True
        if charging is not None:
            device.charging = bool(charging)
            updated = True
        if acc_on is not None:
            device.acc_on = bool(acc_on)
            updated = True
        if gps_fix is not None:
            device.gps_fix = bool(gps_fix)
            updated = True
        if updated:
            device.status_updated_at = when

        # 3) histórico (opcional)
        if record_history:
            hist = DeviceStatusHistory(
                device_id=device.id,
                when=when,
                battery_pct=battery_pct,
                gsm_pct=gsm_pct,
                charging=charging,
                acc_on=acc_on,
                gps_fix=gps_fix,
                raw_voltage=raw_voltage,
                raw_gsm=raw_gsm,
            )
            session.add(hist)

        if updated or record_history:
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if own_session:
            session.close()
