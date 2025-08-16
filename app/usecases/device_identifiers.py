import os
import asyncio
from typing import Optional, Dict, Any

import asyncpg

# ---------------------------------------------------------------------------
# Config DB
# ---------------------------------------------------------------------------
# Aceita DATABASE_URL (formato asyncpg) e cai no default do docker-compose.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgres://telemetry:telemetry@db:5432/telemetry",
)

_pool: Optional[asyncpg.Pool] = None
_pool_lock = asyncio.Lock()


async def _ensure_pool() -> asyncpg.Pool:
    """
    Singleton de pool asyncpg com criação sob demanda.
    """
    global _pool
    if _pool and not _pool._closed:
        return _pool
    async with _pool_lock:
        if _pool and not _pool._closed:
            return _pool
        _pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=1,
            max_size=int(os.getenv("PG_MAX_POOL_SIZE", "10")),
        )
    return _pool


# ---------------------------------------------------------------------------
# Upsert de identificadores auxiliares (ex.: gt06_last10)
# ---------------------------------------------------------------------------
async def upsert_device_identifier_by_device_id(
    device_id: str,
    id_type: str,
    id_value: str,
) -> Dict[str, Any]:
    """
    Insere ou atualiza (upsert) um identificador auxiliar para um device.
    - device_id: devices.id (UUID/char(36))
    - id_type:   ex.: 'gt06_last10'
    - id_value:  ex.: '6126102974'
    """
    pool = await _ensure_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO device_identifiers (device_id, id_type, id_value)
                VALUES ($1, $2, $3)
                ON CONFLICT (id_type, id_value)
                DO UPDATE SET
                  device_id  = EXCLUDED.device_id,
                  updated_at = now()
                RETURNING id, device_id, id_type, id_value, created_at, updated_at
                """,
                device_id,
                id_type,
                id_value,
            )
            return dict(row) if row else {}


# ---------------------------------------------------------------------------
# Resolução de device por "last10" via VIEW device_by_last10
# -------------------------------------------------------------------------