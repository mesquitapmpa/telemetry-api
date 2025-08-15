from app.infra.db import Base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Boolean, ForeignKey, DateTime, Float, Text, Index
from datetime import datetime, timezone
import uuid

def _uuid() -> str:
    import uuid as _uuid
    return str(_uuid.uuid4())

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    imei: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    model: Mapped[str] = mapped_column(String(64), default="unknown")
    protocol: Mapped[str] = mapped_column(String(32), default="trv")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    positions: Mapped[list["Position"]] = relationship("Position", back_populates="device")

class Position(Base):
    __tablename__ = "positions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), index=True)
    fix_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    latitude: Mapped[float] = mapped_column(Float)
    longitude: Mapped[float] = mapped_column(Float)
    speed_knots: Mapped[float] = mapped_column(Float, default=0.0)
    speed_kmh: Mapped[float] = mapped_column(Float, default=0.0)  # NOVO
    course_deg: Mapped[float] = mapped_column(Float, default=0.0)
    valid: Mapped[bool] = mapped_column(Boolean, default=False)
    raw: Mapped[str] = mapped_column(Text)
    device: Mapped["Device"] = relationship("Device", back_populates="positions")

    __table_args__ = (
        Index("idx_positions_device_fix", "device_id", "fix_time"),
    )