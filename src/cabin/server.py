"""Process startup (spec 0022 FR-1/FR-2/FR-7/FR-9/FR-10).

`uvicorn.run()` -- what `cli.py` called until this module existed -- builds
its own `Config` and `Server` internally and never returns either
(`uvicorn/main.py:494+`), so there is no handle to the `SSLContext` a later
phase needs to swap a certificate onto. That is the whole reason this module
exists: `run` builds `uvicorn.Config`/`uvicorn.Server` itself and keeps the
`Config` reachable (see `cabin.tls.TlsManager.attach`), confirmed against a
real handshake in the spec's TLS spike.

**Three traps, all handled here rather than left for a later phase to
rediscover:**

1. `uvicorn.Server.serve()` installs `SIGINT`/`SIGTERM` handlers with plain
   `signal.signal` (`uvicorn/server.py:323-341` in the installed 0.52.0),
   and offers no way to opt out. Run two servers in one process and the
   second one to start simply overwrites the first's handler -- a signal
   then stops only whichever server registered last, and the other is left
   for the container runtime to `SIGKILL` once its grace period expires.
   `_serve` below does not rely on either server's own signal handling: it
   awaits every task -- both servers and the renewal loop -- with
   `asyncio.wait(..., return_when=FIRST_COMPLETED)`, and the moment *any*
   one of them finishes -- for any reason, a caught signal included -- it
   sets `should_exit = True` on every server and the renewal loop's stop
   event too. Whichever task the signal actually reached, the rest stop
   anyway.
2. The plaintext PKI listener's application (`create_public_app`) has no
   lifespan of its own and therefore no `app.state.db` / `app.state.secrets`
   until the *main* app's lifespan has run. Starting both servers
   concurrently would race that. So the primary server is started first and
   `_wait_until_started` blocks until `uvicorn.Server.started` is true --
   which uvicorn only sets after its lifespan startup has completed -- before
   the second server (with TLS on) is started at all. The renewal loop
   (FR-9) reads the same `app.state`, so it waits for the same signal.
3. Stopping the renewal loop must not delay shutdown (AC-22.3, measured by
   `test_sigterm_stops_both_listeners`'s timing bound): it is given the
   *same* `asyncio.Event` `should_exit` maps onto, set in the same place as
   every server's `should_exit`, and awaited in the same final
   `asyncio.wait(tasks)` -- never a separate wait with its own timeout.

**FR-8: refused before any of the above.** `run` starts exactly one
`uvicorn.Server` for the application listener, never a worker pool. The
spike behind this spec found that a live certificate swap
(`cabin.tls.TlsManager.ensure_current`) mutates one process's `SSLContext`
in place -- a second worker process would keep answering every handshake
with whichever certificate it started with, forever, with nothing in any
log to say so. So with TLS on, a worker count above one is refused, loudly,
before anything below is built, let alone bound.
"""

import asyncio
import os
import ssl
from collections.abc import Callable, Generator, Mapping

import uvicorn
from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker

import cabin.tls as tls_mod
from cabin.app import create_app
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.tls import TlsManager
from cabin.web.crl_ui import router as crl_router
from cabin.web.deps import get_db, get_secrets

#: How often `_wait_until_started` re-checks `Server.started`. Local process
#: state, not I/O, so a tight poll costs nothing and keeps the FR-7 wait
#: from adding noticeable latency to the plaintext listener's startup.
_STARTUP_POLL_INTERVAL = 0.01

#: The conventional env var a worker count arrives through -- the same one
#: `uvicorn.Config.__init__` still reads (`workers = int(env[...])` when
#: `workers` is not passed explicitly). `run` never hands that value to
#: anything that would actually spawn a second process, so with TLS off it
#: is already silently inert; FR-8 is what stops it from being silent with
#: TLS on too.
_WEB_CONCURRENCY = "WEB_CONCURRENCY"


def run(config: Config) -> None:
    """Start cabin. The only caller is `cli.main`."""
    _refuse_multi_worker_with_tls(config, os.environ)
    asyncio.run(_serve(config))


def _refuse_multi_worker_with_tls(config: Config, env: Mapping[str, str]) -> None:
    """FR-8: more than one worker requested while TLS is on is a refusal,
    not a warning -- called first in `run`, before `_build_servers`
    constructs a single `uvicorn.Server`, let alone binds one.

    The failure mode this guards against has no other symptom: a swap
    reaches the one process that receives it and silently does not reach
    any other, so some fraction of connections would keep the stale
    certificate with nothing anywhere logging it. An operator can act on a
    refusal; an operator cannot act on a problem that never announces
    itself. TLS off takes the early return -- the binding this refuses to
    make is inert without TLS, and an operator not using cabin's TLS must
    not be obstructed by it.
    """
    raw = env.get(_WEB_CONCURRENCY)
    if raw is None or not config.tls:
        return
    if int(raw) > 1:
        raise SystemExit(
            f"cabin: {_WEB_CONCURRENCY}={raw} is not supported while CABIN_TLS is on -- "
            "a live certificate swap mutates one worker process's SSLContext in place, "
            "so with more than one worker the swap would silently reach only one of "
            f"them; unset {_WEB_CONCURRENCY} or turn CABIN_TLS off"
        )


async def _serve(config: Config) -> None:
    tls = TlsManager(config.data_dir) if config.tls else None
    app = create_app(config, tls=tls)
    primary, *rest = _build_servers(config, app, tls)

    servers = [primary]
    tasks = [asyncio.create_task(primary.serve())]
    # Shared by every server's should_exit *and* the renewal loop's stop
    # signal below -- see module docstring, trap 3.
    should_exit = asyncio.Event()

    if rest:
        # Trap 2 (module docstring): don't start the plaintext listener
        # until the main app's lifespan -- which populates app.state.db and
        # app.state.secrets -- has actually run.
        await _wait_until_started(primary, tasks[0])
        if primary.started:
            for server in rest:
                servers.append(server)
                tasks.append(asyncio.create_task(server.serve()))
            if tls is not None:
                # FR-9: the same app.state wait FR-10's listener needed
                # applies here -- ensure_current reads app.state.db and
                # app.state.secrets, which only exist once the main app's
                # lifespan has run.
                tasks.append(asyncio.create_task(_renewal_task(app, tls, should_exit)))

    # Trap 1 (module docstring): whichever task a signal actually reached,
    # tell every other one to stop too, rather than trusting each server's
    # own (mutually clobbering) signal handler.
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for server in servers:
        server.should_exit = True
    should_exit.set()
    await asyncio.wait(tasks)

    for task in tasks:
        task.result()  # re-raise the first exception any task exited with


async def _wait_until_started(server: uvicorn.Server, task: "asyncio.Task[None]") -> None:
    """Block until `server.started` is true, or until `task` finishes first
    (a bind failure, for instance) so a server that will never start does
    not hang this forever."""
    while not server.started and not task.done():
        await asyncio.sleep(_STARTUP_POLL_INTERVAL)


async def _renewal_task(app: FastAPI, tls: TlsManager, stop: asyncio.Event) -> None:
    """FR-9: supervise `cabin.tls.renewal_loop` alongside the servers.

    Reached through `tls_mod.renewal_loop` / `tls_mod.CHECK_INTERVAL`
    (module-attribute access via `import cabin.tls as tls_mod`), not a
    `from cabin.tls import renewal_loop, CHECK_INTERVAL` at the top of this
    file. `cabin.tls` is still the Phase-0 skeleton on disk -- neither name
    exists there yet, only in the Interface Contract this is written
    against -- and a top-level `from...import` would turn every test that
    merely imports `cabin.server` (most of the suite, `test_public_app.py`
    included) into a collection error the moment this lane's code lands
    ahead of the TLS lane's, rather than failing only the tests that
    actually exercise TLS. `tests/test_tls.py` already makes the identical
    trade for the identical reason (see its module docstring): an
    `AttributeError` right here, once TLS is actually turned on, instead of
    everything refusing to even collect.
    """
    await tls_mod.renewal_loop(tls_mod.CHECK_INTERVAL, _renewal_tick(app, tls), stop)


def _renewal_tick(app: FastAPI, tls: TlsManager) -> Callable[[], None]:
    """Build the synchronous `tick` `renewal_loop` calls on its own
    interval: open a session against the main app's database, hand it and
    the main app's secret store to `ensure_current`, close the session.
    Closed over `app`/`tls` rather than reading them from globals, so a
    second `_serve` call in the same process (there is none today, but
    nothing here should assume that) cannot cross-wire two instances.
    """

    def tick() -> None:
        session_factory: sessionmaker[Session] = app.state.db
        secrets: SecretStore = app.state.secrets
        db = session_factory()
        try:
            tls.ensure_current(db, secrets)
        finally:
            db.close()

    return tick


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
    later.

    Three constructor arguments here are load-bearing, not stylistic
    defaults, and must never be dropped by whoever next adds a second app
    to this process:

    - `redirect_slashes=False`, because FastAPI's default would put a 307
      with a `Location` header on a bare-slash PKI path, and no response
      from this listener may ever carry one (FR-10 calls that a security
      property, not a routing detail).
    - `docs_url=None`, `redoc_url=None`, `openapi_url=None`, because
      FastAPI mounts `/docs`, `/redoc` and `/openapi.json` on *every*
      `FastAPI()` instance unless these are turned off explicitly -- three
      more working, unauthenticated pages on the one listener whose entire
      job is to serve nothing but a CRL and a CA certificate over
      unencrypted HTTP. `_ALLOWED_PATHS`-style route-set assertions cannot
      catch a missing one of these on their own: FastAPI excludes its own
      docs routes from `openapi()["paths"]` by definition, so only a direct
      HTTP request proves them unreachable (see
      `test_public_app_disables_its_own_auto_generated_docs`).

    It opens no database and no secret store of its own: `get_db` and
    `get_secrets` are overridden with closures that read `main_app.state`
    per request, which is safe because nothing serves a request here until
    `_serve`'s FR-7 wait has already confirmed the main app's lifespan ran.
    """
    app = FastAPI(
        title="cabin (public)",
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
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
