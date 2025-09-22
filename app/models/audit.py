from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime
from datetime import datetime, timezone
from app.models.user import Base

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))
    actor: Mapped[str] = mapped_column(String(254))     # email or system
    action: Mapped[str] = mapped_column(String(64))     # "request.create", "key.add", etc.
    object: Mapped[str] = mapped_column(String(64))     # "server:host123" / "user:42"
    details: Mapped[str] = mapped_column(String(1024))  # summary (keep short)
    prev_hash: Mapped[str | None] = mapped_column(String(128))
    curr_hash: Mapped[str | None] = mapped_column(String(128))