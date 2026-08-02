"""Runtime configuration, resolved with precedence flag > env > default."""

import argparse
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORT = 8080
DEFAULT_DATA_DIR = "data"


class ConfigError(Exception):
    """Invalid runtime configuration."""


def ensure_data_dir_writable(data_dir: Path) -> None:
    """Refuse to start when DATA_DIR cannot be written, and say why.

    This is the first-run failure: a bind-mounted volume that belongs to
    another uid, which is exactly what the README, the compose file and the
    Unraid template all warn about. Left to the database layer it surfaces as
    a SQLAlchemy traceback that names neither the directory, nor the uid it
    tried to write as, nor the fix -- so it is checked here instead, before
    anything opens a connection.
    """
    ids = f"uid {os.geteuid()}:{os.getegid()}"
    fix = f"chown -R {os.geteuid()}:{os.getegid()} <the host directory mounted there>"
    try:
        data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise ConfigError(
            f"data directory {data_dir} cannot be created as {ids} "
            f"({exc.strerror}); create it or fix its ownership: {fix}"
        ) from exc
    if not os.access(data_dir, os.W_OK | os.X_OK):
        raise ConfigError(
            f"data directory {data_dir} is not writable by {ids}; fix its ownership: {fix}"
        )


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ConfigError(f"invalid port: {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"port out of range: {port}")
    return port


@dataclass(frozen=True)
class Config:
    port: int
    data_dir: Path
    db_url: str
    master_passphrase: str | None = field(default=None, repr=False)
    cookie_secure: bool = False

    @classmethod
    def load(
        cls,
        argv: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> "Config":
        if env is None:
            env = os.environ
        parser = argparse.ArgumentParser(prog="cabin", description="all-in-one internal CA")
        parser.add_argument("--port", help=f"listen port (default {DEFAULT_PORT})")
        parser.add_argument("--data-dir", dest="data_dir", help="data directory (default ./data)")
        args = parser.parse_args(list(argv) if argv is not None else None)

        port = _parse_port(args.port or env.get("PORT") or str(DEFAULT_PORT))
        data_dir = Path(args.data_dir or env.get("DATA_DIR") or DEFAULT_DATA_DIR)
        db_url = env.get("CABIN_DB_URL") or f"sqlite:///{data_dir}/cabin.db"
        master_passphrase = env.get("CABIN_MASTER_PASSPHRASE") or None
        cookie_secure = (env.get("COOKIE_SECURE") or "").strip().lower() in (
            "true",
            "1",
        )
        return cls(
            port=port,
            data_dir=data_dir,
            db_url=db_url,
            master_passphrase=master_passphrase,
            cookie_secure=cookie_secure,
        )
