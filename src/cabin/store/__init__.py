"""Database access and schema migrations."""

from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


class Base(DeclarativeBase):
    """Shared declarative base for ORM models (schema itself is Alembic-owned)."""


def run_migrations(db_url: str) -> None:
    """Apply all pending schema migrations (idempotent)."""
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")


def create_session_factory(db_url: str) -> sessionmaker[Session]:
    """Build a sync SQLAlchemy session factory bound to ``db_url``."""
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    engine = create_engine(db_url, connect_args=connect_args)
    return sessionmaker(bind=engine, expire_on_commit=False)
