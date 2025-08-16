# app/usecases/device_helpers.py
from typing import Optional, Dict
from app.usecases.device_identifiers import resolve_device_by_last10
from app.usecases.save_position import ensure_device as _ensure_device

async def ensure_device_canonical(protocol: str, imei: str) -> Optional[Dict]:
    """
    - Se IMEI >= 15: garante/retorna device normal.
    - Se IMEI < 15: busca canônico por last10; se achar, retorna canônico; se não, NÃO cria.
    """
    if imei and len(imei) >= 15:
        return await _ensure_device(protocol=protocol, imei=imei)

    last10 = (imei or "")[-10:]
    if not last10:
        return None

    row = await resolve_device_by_last10(last10)
    if row:
        # canonical_lookup=True evita side-effects no ensure_device, se você implementou essa flag
        return await _ensure_device(protocol=protocol, imei=row["imei"], canonical_lookup=True)

    return None  # <- sem vírgula!