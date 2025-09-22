import asyncio
import os
import pathlib
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from alembic import context

# Ensure project root is importable
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import metadata (should NOT import settings)
from app.db.base import Base  # Base.metadata must include all models  # noqa: E402

# Alembic config & logging
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Get DB URL from env (prefer KEYWARDEN_ prefix, fall back to unprefixed, then a sane default for local)
DB_URL = (
    os.getenv("KEYWARDEN_POSTGRES_DSN")
    or os.getenv("POSTGRES_DSN")
    or "postgresql+asyncpg://postgres:postgres@localhost:5432/keywarden"
)


def run_migrations_offline():
    context.configure(
        url=DB_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online():
    connectable: AsyncEngine = create_async_engine(DB_URL, poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())