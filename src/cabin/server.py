"""Process startup (spec 0022 FR-1/FR-2/FR-7/FR-10).

`uvicorn.run()` -- what `cli.py` called until this module existed -- builds
its own `Config` and `Server` internally and never returns either
(`uvicorn/main.py:494+`), so there is no handle to the `SSLContext` a later
phase needs to swap a certificate onto. That is the whole reason this module
exists: `run` builds `uvicorn.Config`/`uvicorn.Server` itself and keeps the
`Config` reachable (see `cabin.tls.TlsManager.attach`), confirmed against a
real handshake in the spec's TLS spike.

**Two traps, both handled here rather than left for a later phase to
rediscover:**

1. `uvicorn.Server.serve()` installs `SIGINT`/`SIGTERM` handlers with plain
   `signal.signal` (`uvicorn/server.py:323-341` in the installed 0.52.0),
   and offers no way to opt out. Run two servers in one process and the
   second one to start simply overwrites the first's handler -- a signal
   then stops only whichever server registered last, and the other is left
   for the container runtime to `SIGKILL` once its grace period expires.
   `_serve` below does not rely on either server's own signal handling: it
   awaits every server task with `asyncio.wait(..., return_when=
   FIRST_COMPLETED)`, and the moment *any* one of them finishes -- for any
   reason, a caught signal included -- it sets `should_exit = True` on
   every other server and waits for them too. Whichever server the signal
   actually reached, the rest stop anyway.
2. The plaintext PKI listener's application (`create_public_app`) has no
   lifespan of its own and therefore no `app.state.db` / `app.state.secrets`
   until the *main* app's lifespan has run. Starting both servers
   concurrently would race that. So the primary server is started first and
   `_wait_until_started` blocks until `uvicorn.Server.started` is true --
   which uvicorn only sets after its lifespan startup has completed -- before
   the second server (with TLS on) is started at all.

Certificate issuance, renewal and the live swap (FR-3 through FR-9) are not
implemented here: `cabin.tls.TlsManager` is a Phase-0 skeleton that does
nothing, so with TLS on this module wires up both listeners and the seam a
certificate will later be swapped through, but serves whatever
`TlsManager.ensure_current` produced -- which right now is nothing. That is
expected; it is a later phase's job.
"""

import asyncio
import ssl
from collections.abc import Callable, Generator

import uvicorn
from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker

from cabin.app import create_app
from cabin.config import Config
from cabin.tls import TlsManager
from cabin.web.crl_ui import router as crl_router
from cabin.web.deps import get_db, get_secrets

#: How often `_wait_until_started` re-checks `Server.started`. Local process
#: state, not I/O, so a tight poll costs nothing and keeps the FR-7 wait
#: from adding noticeable latency to the plaintext listener's startup.
_STARTUP_POLL_INTERVAL = 0.01


def run(config: Config) -> None:
    """Start cabin. The only caller is `cli.main`."""
    asyncio.run(_serve(config))


async def _serve(config: Config) -> None:
    tls = TlsManager(config.data_dir) if config.tls else None
    app = create_app(config, tls=tls)
    primary, *rest = _build_servers(config, app, tls)

    servers = [primary]
    tasks = [asyncio.create_task(primary.serve())]

    if rest:
        # Trap 2 (module docstring): don't start the plaintext listener
        # until the main app's lifespan -- which populates app.state.db and
        # app.state.secrets -- has actually run.
        await _wait_until_started(primary, tasks[0])
        if primary.started:
            for server in rest:
                servers.append(server)
                tasks.append(asyncio.create_task(server.serve()))

    # Trap 1 (module docstring): whichever server a signal actually reached,
    # tell every other one to stop too, rather than trusting each server's
    # own (mutually clobbering) signal handler.
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for server in servers:
        server.should_exit = True
    await asyncio.wait(tasks)

    for task in tasks:
        task.result()  # re-raise the first exception any server exited with


async def _wait_until_started(server: uvicorn.Server, task: "asyncio.Task[None]") -> None:
    """Block until `server.started` is true, or until `task` finishes first
    (a bind failure, for instance) so a server that will never start does
    not hang this forever."""
    while not server.started and not task.done():
        await asyncio.sleep(_STARTUP_POLL_INTERVAL)


def _build_servers(config: Config, app: FastAPI, tls: TlsManager | None) -> list[uvicorn.Server]:
    """Construct, but do not serve, every `uvicorn.Server` this process
    needs: the application listener always, plus the plaintext PKI listener
    when TLS is on. Kept separate from `_serve` so a test can assert on the
    constructed objects directly -- e.g. "exactly one application Server"
    with TLS off -- without monkeypatching `uvicorn.Server.__init__`.
    """
    if config.tls:
        primary_config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=config.port,
            ssl_context_factory=_bare_ssl_context_factory,
        )
    else:
        primary_config = uvicorn.Config(app, host="0.0.0.0", port=config.port)
    if tls is not None:
        tls.attach(primary_config)

    servers = [uvicorn.Server(primary_config)]
    if config.tls:
        public_config = uvicorn.Config(
            create_public_app(app), host="0.0.0.0", port=config.http_port
        )
        servers.append(uvicorn.Server(public_config))
    return servers


def _bare_ssl_context_factory(
    config: uvicorn.Config, default_factory: Callable[[], ssl.SSLContext]
) -> ssl.SSLContext:
    """Give `Config.load()` a real, live `SSLContext` with no certificate
    loaded yet, so `TlsManager.attach` has something to hand real material
    to later (FR-6/FR-7). uvicorn's own default factory needs `ssl_certfile`
    on disk, and in Phase 0 -- before any certificate has ever been issued
    -- there isn't one.
    """
    del config, default_factory
    return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


def create_public_app(main_app: FastAPI) -> FastAPI:
    """FR-10: the plaintext PKI listener's application.

    Exactly `crl_router` and nothing else -- no lifespan, no static mount,
    no session middleware, no catch-all that could grow a `Location` header
    later. `redirect_slashes=False` because FastAPI's default would put a
    307 with a `Location` header on a bare-slash PKI path, and no response
    from this listener may ever carry one (FR-10 calls that a security
    property, not a routing detail).

    It opens no database and no secret store of its own: `get_db` and
    `get_secrets` are overridden with closures that read `main_app.state`
    per request, which is safe because nothing serves a request here until
    `_serve`'s FR-7 wait has already confirmed the main app's lifespan ran.
    """
    app = FastAPI(title="cabin (public)", redirect_slashes=False)
    app.include_router(crl_router)
    app.dependency_overrides[get_db] = _public_get_db(main_app)
    app.dependency_overrides[get_secrets] = lambda: main_app.state.secrets
    return app


def _public_get_db(main_app: FastAPI) -> Callable[[], Generator[Session]]:
    def _get_db() -> Generator[Session]:
        factory: sessionmaker[Session] = main_app.state.db
        db = factory()
        try:
            yield db
        finally:
            db.close()

    return _get_db
