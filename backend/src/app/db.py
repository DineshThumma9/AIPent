"""SQLite engine and schema creation."""

from pathlib import Path

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from app.config import settings

_engine: Engine | None = None


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def make_engine(url: str | None = None) -> Engine:
    url = url or settings.database_url
    if url.startswith("sqlite") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _sqlite_pragmas)
    return engine


def init_db(engine: Engine) -> None:
    # Import is required so SQLModel sees every table before create_all.
    from app import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    if engine.url.get_backend_name() == "sqlite":
        _add_missing_columns(engine)


def _add_missing_columns(engine: Engine) -> None:
    """Tiny forward migration for the disposable demo database.

    SQLModel's create_all does not add columns to existing tables. A real
    deployment would use Alembic; this keeps the hackathon demo from dying on a
    stale local database.
    """
    additions = {
        "assessment": {"risk_score": "FLOAT"},
        "step": {"target": "TEXT"},
        "approval": {"detail": "JSON"},
    }
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {
                row[1]
                for row in connection.exec_driver_sql(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            for name, sql_type in columns.items():
                if name not in existing:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"
                    )


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = make_engine()
    return _engine


def get_session():
    # expire_on_commit=False: routes read the object after commit (and after
    # writing an audit row), so it must not be expired out from under them.
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
