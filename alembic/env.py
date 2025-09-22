import sys, pathlib

# Add project root (parent of the "alembic" dir) to sys.path
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from logging.config import fileConfig
from alembic import context

# Import your app's config & models
from app.core.config import settings
from app.db.base import Base  # imports all models via app/models/__init__.py

# Alembic Config object
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata (for autogenerate)
target_metadata = Base.metadata

# DSN from your app config (e.g. postgresql+asyncpg://…)
DB_URL = settings.POSTGRES_DSN


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = DB_URL
    context.configure(
        url=url,
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
    """Run migrations in 'online' mode with async engine."""
    connectable: AsyncEngine = create_async_engine(
        DB_URL,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())