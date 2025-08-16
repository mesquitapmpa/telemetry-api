# app/usecases/device_identifiers.py
import os
import asyncpg
from typing import Optional, Dict

_pool = None

def _normalize_asyncpg_dsn(url: Optional[str]) -> str:
    """
    Aceita DATABASE_URL estilo SQLAlchemy (ex.: postgresql+asyncpg://)
    e normaliza para o formato aceito pelo asyncpg (postgresql://).
    """
    if not url:
        user = os.getenv("PGUSER", os.getenv("POSTGRES_USER", "telemetry"))
        pwd  = os.getenv("PGPASSWORD", os.getenv("POSTGRES_PASSWORD", "telemetry"))
        host = os.getenv("PGHOST", os.getenv("POSTGRES_HOST", "db"))
        port = os.getenv("PGPORT", "5432")
        db   = os.getenv("PGDATABASE", os.getenv("POSTGRES_DB", "telemetry"))
        return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

    if url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + url.split("postgresql+asyncpg://", 1)[1]
    if url.startswith("postgres+asyncpg://"):
        return "postgres://" + url.split("postgres+asyncpg://", 1)[1]
    return url

async def _ensure_pool():
    global _pool
    if _pool is None:
        raw = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URI")
        dsn = _normalize_asyncpg_dsn(raw)
        _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    return _pool

async def resolve_device_by_last10(last10: str) -> Optional[Dict]:
    """
    Busca o canônico pela view/tabela device_by_last10.
    Retorna dict mínimo: {"id": <uuid|int>, "imei": <str>} ou None.
    """
    pool = await _ensure_pool()
    async with pool.acquire() as con:
        row = await con.fetchrow("""
            SELECT canonical_id AS id, canonical_imei AS imei
            FROM device_by_last10
            WHERE last10 = $1
            LIMIT 1
        """, last10)
        if not row:
            return None
        return {"id": row["id"], "imei": row["imei"]}