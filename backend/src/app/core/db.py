"""Async SQLite engine, session factory and schema creation.

Everything in the application talks to the database through
``AsyncSession``. There is no synchronous engine to fall back to.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel

from app.core.config import settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def _async_url(url: str) -> str:
    """Translate a sync SQLite URL into the aiosqlite driver URL."""
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return url


def make_engine(url: str | None = None) -> AsyncEngine:
    """Create a new async engine.

    ``get_engine`` caches the application engine; this factory always returns a
    fresh one so tests can point an isolated database at the app.
    """
    url = url or settings.database_url
    if url.startswith("sqlite") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    engine = create_async_engine(
        _async_url(url),
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
        # NullPool keeps one connection per session. It avoids reusing an
        # aiosqlite connection across different event loops (tests, TestClient)
        # and keeps SQLite writer contention short-lived.
        poolclass=NullPool if url.startswith("sqlite") else None,
    )
    if url.startswith("sqlite"):
        event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
    return engine


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = make_engine()
    return _engine


def set_engine(engine: AsyncEngine) -> None:
    """Bind the process-wide engine and reset the session factory.

    Used by the application lifespan and by tests that run against an isolated
    database file.
    """
    global _engine, _session_factory
    _engine = engine
    _session_factory = None


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _session_factory


async def init_db(engine: AsyncEngine | None = None) -> None:
    """Create every table and apply the tiny forward migration."""
    # Import is required so SQLModel sees every table before create_all.
    from app.domain import models  # noqa: F401

    engine = engine or get_engine()
    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)

    if engine.url.get_backend_name() == "sqlite":
        await _add_missing_columns(engine)


async def _add_missing_columns(engine: AsyncEngine) -> None:
    """Forward migration for the disposable demo database.

    SQLModel's create_all does not add columns to existing tables. A real
    deployment would use Alembic; this keeps the hackathon demo from dying on a
    stale local database.
    """
    additions = {
        "assessment": {"risk_score": "FLOAT"},
        "step": {"target": "TEXT"},
        "approval": {"detail": "JSON"},
        "message": {"client_message_id": "TEXT"},
    }
    async with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {
                row[1]
                for row in (
                    await connection.exec_driver_sql(f"PRAGMA table_info({table})")
                ).fetchall()
            }
            for name, sql_type in columns.items():
                if name not in existing:
                    await connection.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"
                    )


@asynccontextmanager
async def get_async_session_ctx() -> AsyncIterator[AsyncSession]:
    """Async context manager yielding an AsyncSession."""
    async with get_session_factory()() as session:
        yield session


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an AsyncSession per request."""
    async with get_session_factory()() as session:
        yield session
