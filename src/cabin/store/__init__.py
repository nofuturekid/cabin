"""Database access and schema migrations."""

from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


class Base(DeclarativeBase):
    """Shared declarative base for ORM models (schema itself is Alembic-owned)."""


def run_migrations(db_url: str) -> None:
    """Apply all pending schema migrations (idempotent)."""
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")


def _enforce_sqlite_foreign_keys(dbapi_connection: DBAPIConnection, _: ConnectionPoolEntry) -> None:
    """SQLite ignores every ``FOREIGN KEY`` in the schema unless told
    otherwise, and it is told per-connection, not per-database -- a pragma
    set once does not stick to connections the pool hands out later. This
    listener fires on "connect", which SQLAlchemy raises for every DBAPI
    connection the pool creates (including ones opened after the first),
    so there is no connection that slips through unenforced.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_session_factory(db_url: str) -> sessionmaker[Session]:
    """Build a sync SQLAlchemy session factory bound to ``db_url``."""
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    engine = create_engine(db_url, connect_args=connect_args)
    if db_url.startswith("sqlite"):
        event.listen(engine, "connect", _enforce_sqlite_foreign_keys)
    return sessionmaker(bind=engine, expire_on_commit=False)
