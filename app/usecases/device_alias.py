import os
import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Engine próprio do módulo (fallback). Se seu projeto já fornece um engine/sessão,
# você pode adaptar para receber por injeção de dependência.
_ENGINE: Optional[AsyncEngine] = None

def _get_engine() -> AsyncEngine:
    global _ENGINE
    if _ENGINE is None:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL não configurada para device_alias.upsert_device_identifier")
        if "+asyncpg" not in db_url:
            # força driver assíncrono típico do SQLAlchemy 2.x
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://")
        _ENGINE = create_async_engine(db_url, pool_pre_ping=True, future=True)
    return _ENGINE

async def upsert_device_identifier(imei: str, id_type: str, id_value: str) -> bool:
    """
    Cria/atualiza um identificador alternativo (alias) vinculado ao device pelo IMEI completo.
    - Retorna True se inseriu/atualizou; False se não conseguiu vincular (ex.: device inexistente).
    - Pré-condição: o device já deve existir (o handler chama ensure_device antes).
    """
    if not imei or not imei.isdigit() or len(imei) != 15:
        logger.warning("[ALIAS] IMEI inválido para upsert: %r", imei)
        return False
    if not id_type or not id_value:
        logger.warning("[ALIAS] id_type/id_value inválidos")
        return False

    engine = _get_engine()
    async with engine.begin() as conn:
        # 1) pega o device_id pelo IMEI
        res = await conn.execute(text("SELECT id FROM devices WHERE imei = :imei"), {"imei": imei})
        row = res.first()
        if not row:
            logger.warning("[ALIAS] device não encontrado para IMEI=%s; pulei upsert (crie o device antes).", imei)
            return False
        device_id = row[0]

        # 2) UPSERT no alias (migrável e idempotente)
        # Se (id_type, id_value) já existe, atualiza o device_id e updated_at.
        await conn.execute(
            text("""
            INSERT INTO device_identifiers (device_id, id_type, id_value, created_at, updated_at)
            VALUES (:device_id, :id_type, :id_value, now(), now())
            ON CONFLICT (id_type, id_value)
            DO UPDATE SET device_id = EXCLUDED.device_id, updated_at = now();
            """),
            {"device_id": device_id, "id_type": id_type, "id_value": id_value},
        )
        logger.info("[ALIAS] upsert ok: (%s, %s) -> device_id=%s", id_type, id_value, device_id)
        # como usamos engine.begin(), o commit é automático
        return True