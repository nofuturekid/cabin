"""Database access and schema migrations."""

from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def run_migrations(db_url: str) -> None:
    """Apply all pending schema migrations (idempotent)."""
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")
