"""FastAPI application factory."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from cabin import __version__
from cabin.acme.api import router as acme_router
from cabin.acme.errors import AcmeError
from cabin.acme.http import acme_error_handler, acme_response_headers
from cabin.api.v1 import router as api_v1_router
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations
from cabin.web import STATIC_DIR
from cabin.web.acme_ui import router as acme_ui_router
from cabin.web.audit_ui import router as audit_router
from cabin.web.ca_ui import router as ca_router
from cabin.web.certs_download_ui import router as certs_download_router
from cabin.web.certs_ui import router as certs_router
from cabin.web.crl_ui import router as crl_router
from cabin.web.deps import SESSION_COOKIE, AuthRedirect, set_session_cookie
from cabin.web.settings_ui import router as settings_router
from cabin.web.tokens_ui import router as tokens_router
from cabin.web.ui import router as ui_router


def create_app(config: Config) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not config.data_dir.exists():
            config.data_dir.mkdir(parents=True, mode=0o700)
        run_migrations(config.db_url)
        app.state.config = config
        app.state.secrets = SecretStore.open(config.data_dir, config.master_passphrase)
        app.state.db = create_session_factory(config.db_url)
        yield

    app = FastAPI(title="cabin", version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def _refresh_session_cookie(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """FR-3: re-issue the cookie when get_current_user slid the expiry.

        The dependency can't set this itself: FastAPI only merges headers
        from a dependency-injected Response into endpoints that *don't*
        return their own Response, and every UI route here returns one
        (TemplateResponse/RedirectResponse). Skip it if the route already
        touched the cookie itself (e.g. /logout deleting it).
        """
        response = await call_next(request)
        token = getattr(request.state, "session_cookie_refresh", None)
        if token is not None:
            already_set = any(
                name.lower() == b"set-cookie" and SESSION_COOKIE.encode() in value
                for name, value in response.headers.raw
            )
            if not already_set:
                set_session_cookie(response, request, token)
        return response

    # Spec 0010 FR-4: a fresh Replay-Nonce and the directory Link on every
    # ACME response. Middleware, so that an error raised anywhere below --
    # including inside a dependency -- still comes back with a nonce the
    # client can retry with.
    app.middleware("http")(acme_response_headers)
    app.add_exception_handler(AcmeError, acme_error_handler)

    @app.exception_handler(AuthRedirect)
    async def _auth_redirect_handler(request: Request, exc: AuthRedirect) -> RedirectResponse:
        return RedirectResponse(exc.location, status_code=303)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(ui_router)
    app.include_router(ca_router)
    app.include_router(certs_router)
    app.include_router(certs_download_router)
    app.include_router(settings_router)
    # Before the ACME protocol router below, and mounted at /acme/admin: that
    # router owns every other path under /acme (including a catch-all that
    # answers 404 for anything it does not know), which is what keeps ACME
    # invisible while it is switched off -- see cabin.web.acme_ui.
    app.include_router(acme_ui_router)
    app.include_router(tokens_router)
    app.include_router(audit_router)
    # Mounted at the root and, unlike every other router, without an auth
    # dependency: a CRL is public by design (spec 0007 FR-5).
    app.include_router(crl_router)
    # Bearer tokens only, no cookies, no CSRF -- the API and the UI are two
    # separate front doors (spec 0008 FR-3).
    app.include_router(api_v1_router)
    # A third front door, and the only one whose authentication is a
    # signature rather than a credential cabin issued: ACME (spec 0010).
    # Every route behind an acme_enabled gate that answers 404 when off.
    app.include_router(acme_router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app
