"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from cabin import __version__
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.store import run_migrations


def create_app(config: Config) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not config.data_dir.exists():
            config.data_dir.mkdir(parents=True, mode=0o700)
        run_migrations(config.db_url)
        app.state.secrets = SecretStore.open(config.data_dir, config.master_passphrase)
        yield

    app = FastAPI(title="cabin", version=__version__, lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
