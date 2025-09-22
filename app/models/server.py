from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, JSON, Boolean, Integer
from app.models.user import Base

class Server(Base):
    __tablename__ = "servers"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. {"env":"prod","group":"db"}
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=0)  # bump to trigger agent reconcile