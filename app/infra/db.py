from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_async_engine(DATABASE_URL, future=True, echo=False)
AsyncSessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()
async_session_maker = AsyncSessionLocal  # alias compatível

async def get_async_session():
    async with AsyncSessionLocal() as session:
        yield session

async def init_db():
    async with engine.begin() as conn:
        # cria tabelas se não existirem
        from app.domain.models import Device, Position, DeviceStatusHistory  # <-- inclua aqui
        await conn.run_sync(Base.metadata.create_all)