"""
Alembic migration environment.

Imports Base.metadata and settings.DATABASE_URL_SYNC from the app itself
(rather than duplicating config) so migrations always reflect the current
ORM models and the actual configured database — one source of truth.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings
from app.core.database import Base

# Import all models here so Base.metadata is fully populated before
# autogenerate compares it against the database. As new models are added,
# add their import here.
from app.models.user import User  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.threat_history import ThreatHistory  # noqa: F401
from app.models.report import Report  # noqa: F401
from app.models.setting import Setting  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.response_action import ResponseAction  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = create_async_engine(get_url(), poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
