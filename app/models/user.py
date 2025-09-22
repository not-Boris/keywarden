from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

# only for Alembic discovery, not used here
from app.db.session import engine  # noqa: F401

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="user")  # user|admin|auditor
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)