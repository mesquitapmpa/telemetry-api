import os
import asyncio
import logging
from typing import List, Optional, Dict, Any

import aiohttp

log = logging.getLogger("gt06_mls")

MLS_URL = os.getenv("MLS_URL", "https://location.services.mozilla.com/v1/geolocate")
MLS_KEY = os.getenv("MLS_API_KEY", "test")  # use "test" só para dev; tem limites severos

def _norm_rssi(val) -> Optional[int]:
    """
    Normaliza RSSI para dBm negativo (o MLS espera dBm < 0).
    Muitos firmwares mandam 0..100 (magnitude). Se vier positivo, invertemos o sinal.
    """
    if val is None:
        return None
    try:
        v = int(val)
    except Exception:
        return None
    if v > 0:
        v = -v
    # clamp defensivo
    if v < -200:
        v = -200
    if v > -1:
        v = -1
    return v

async def geolocate_network(
    wifi: List[dict],
    cells: List[dict],
    mcc: Optional[int],
    mnc: Optional[int],
) -> Optional[Dict[str, Any]]:
    """
    Recebe listas produzidas por parse_net_1a_1b() e consulta o MLS.
    Retorna: {"lat": float, "lon": float, "accuracy": float, "provider": "MLS"} ou None.
    """
    if not wifi and not cells:
        return None

    # Wi-Fi → MLS
    wifi_access_points = []
    for ap in wifi:
        mac = ap.get("bssid")
        if not mac:
            continue
        rssi = _norm_rssi(ap.get("rssi"))
        entry = {"macAddress": str(mac).lower()}
        if rssi is not None:
            entry["signalStrength"] = rssi
        wifi_access_points.append(entry)

    # Células → MLS
    cell_towers = []
    for c in cells:
        lac = c.get("lac")
        cid = c.get("cid")
        if lac is None or cid is None:
            continue
        cell = {
            "locationAreaCode": int(lac),
            "cellId": int(cid),
        }
        if mcc is not None:
            cell["mobileCountryCode"] = int(mcc)
        if mnc is not None:
            cell["mobileNetworkCode"] = int(mnc)
        rssi = _norm_rssi(c.get("rssi"))
        if rssi is not None:
            cell["signalStrength"] = rssi
        cell_towers.append(cell)

    body: Dict[str, Any] = {"considerIp": False}
    if wifi_access_points:
        body["wifiAccessPoints"] = wifi_access_points
    if cell_towers:
        body["cellTowers"] = cell_towers

    params = {"key": MLS_KEY}
    timeout = aiohttp.ClientTimeout(total=4)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(MLS_URL, params=params, json=body) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    loc = data.get("location") or {}
                    acc = data.get("accuracy")
                    if "lat" in loc and "lng" in loc:
                        return {
                            "lat": float(loc["lat"]),
                            "lon": float(loc["lng"]),
                            "accuracy": float(acc) if acc is not None else None,
                            "provider": "MLS",
                        }
                    log.warning("MLS sem location no payload: %s", data)
                else:
                    text = await resp.text()
                    log.warning("MLS HTTP %s: %s", resp.status, text[:300])
    except asyncio.TimeoutError:
        log.warning("MLS timeout")
    except Exception as e:
        log.exception("MLS erro: %s", e)

    return None