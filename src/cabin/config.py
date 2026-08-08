"""Runtime configuration, resolved with precedence flag > env > default."""

import argparse
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger(__name__)

DEFAULT_PORT = 8080
DEFAULT_DATA_DIR = "data"
#: Spec 0022 FR-12: the plaintext PKI listener's port, used only when
#: ``tls`` is on.
DEFAULT_HTTP_PORT = 8081


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
    #: Spec 0022 FR-12. The multi-worker refusal (FR-8) is `cabin.server`
    #: work, not this module's -- these two fields exist here so it has
    #: something typed to build against.
    tls: bool = False
    http_port: int = DEFAULT_HTTP_PORT

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
        cookie_secure_requested = (env.get("COOKIE_SECURE") or "").strip().lower() in (
            "true",
            "1",
        )
        tls = (env.get("CABIN_TLS") or "").strip().lower() in ("true", "1")
        http_port = _parse_port(env.get("CABIN_HTTP_PORT") or str(DEFAULT_HTTP_PORT))

        if tls and http_port == port:
            raise ConfigError(
                f"CABIN_HTTP_PORT ({http_port}) must not equal PORT ({port}) when "
                "CABIN_TLS is on -- the TLS listener and the plaintext PKI listener "
                "would be indistinguishable"
            )
        if not tls and "CABIN_HTTP_PORT" in env:
            _log.warning("CABIN_HTTP_PORT is set but CABIN_TLS is off; ignoring it")

        # FR-11: cabin is the TLS terminator, so there is no deployment in
        # which an explicit COOKIE_SECURE=false is right and TLS being on is
        # wrong -- the flag wins unconditionally, and the override is logged.
        cookie_secure = cookie_secure_requested or tls
        if tls and "COOKIE_SECURE" in env and not cookie_secure_requested:
            _log.warning(
                "COOKIE_SECURE=%r is overridden to true because CABIN_TLS is on",
                env["COOKIE_SECURE"],
            )

        return cls(
            port=port,
            data_dir=data_dir,
            db_url=db_url,
            master_passphrase=master_passphrase,
            cookie_secure=cookie_secure,
            tls=tls,
            http_port=http_port,
        )
