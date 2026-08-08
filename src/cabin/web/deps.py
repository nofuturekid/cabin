"""FastAPI dependencies: DB session, current user, role guards, CSRF.

Auth failures raise :class:`AuthRedirect` rather than returning a value;
the app registers an exception handler that turns it into a 303 redirect
to /login (or /setup while there are zero users) — see FR-5/FR-6.
"""

import hmac
from collections.abc import Callable, Generator

from fastapi import Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker
from starlette.responses import Response

from cabin import sessions, users
from cabin.audit import Actor, user_actor
from cabin.ca.certs import Certificate, get_certificate
from cabin.issuer_grants import Principal, user_principal
from cabin.secrets import SecretStore
from cabin.sessions import SESSION_LIFETIME, UserSession
from cabin.settings import TRUST_PROXY, get_flag
from cabin.users import Role, User

SESSION_COOKIE = "cabin_session"

#: The roles that may change things (viewers may only look). Shared here so
#: route guards and per-page visibility checks can't drift apart on what
#: "admin" means -- use ADMIN_ROLES for the latter, never a re-inlined tuple.
ADMIN_ROLES = (Role.admin, Role.superadmin)

#: Width of audit_events.ip -- enough for an IPv4-mapped IPv6 address, and a
#: bound on what a forwarded header may write into that column.
MAX_IP_LENGTH = 45


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    """Set the session cookie with the flags required by FR-3."""
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.app.state.config.cookie_secure,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
    )


def base_context(request: Request, user: User) -> dict[str, object]:
    """Context every authenticated page needs: current user, the session's
    csrf_token (layout.html's logout form needs this on *every* page -- see
    ui.py's BUG 1 regression test), and the nav flags below, for use across
    UI routers. ``version`` is a Jinja global, not per-route context.

    Spec 0008 FR-6: ``nav`` says which entries this role can actually use,
    so the menu stops offering pages that only answer 403. It is cosmetic --
    every route still guards itself with its own dependency -- but a nav
    full of dead ends is a bug report waiting to happen.
    """
    session_row: UserSession = request.state.session
    role = Role(user.role)
    return {
        "user": user,
        "csrf_token": session_row.csrf_token,
        "nav": {
            "issue": role in ADMIN_ROLES,
            "settings": role in ADMIN_ROLES,
            "acme": role in ADMIN_ROLES,
            "tokens": role == Role.superadmin,
        },
    }


def certificate_or_404(db: Session, cert_id: int) -> Certificate:
    """One stored certificate, or a 404 with one wording. Shared by the UI
    pages, the downloads and the API so a missing certificate cannot answer
    three different ways depending on which door was used."""
    row = get_certificate(db, cert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such certificate")
    return row


class AuthRedirect(Exception):
    """Short-circuit a request to a redirect (first-run setup or login)."""

    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


def get_db(request: Request) -> Generator[Session]:
    factory: sessionmaker[Session] = request.app.state.db
    db = factory()
    try:
        yield db
    finally:
        db.close()


def get_secrets(request: Request) -> SecretStore:
    """Spec 0022 FR-10: the accessor `crl_ui` uses in place of reading
    `request.app.state.secrets` directly, so the plaintext PKI listener's
    application (`server.create_public_app`, which has no secret store of
    its own) can override this dependency to reach the main app's instead.
    """
    return request.app.state.secrets  # type: ignore[no-any-return]


def redirect_if_no_users(db: Session = Depends(get_db)) -> None:
    """FR-5: first run — every request redirects to /setup until a user exists."""
    if users.count_users(db) == 0:
        raise AuthRedirect("/setup")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Resolve the logged-in user from the session cookie, or redirect.

    FastAPI does not merge headers set via a dependency-injected ``Response``
    into an endpoint that returns its own ``Response`` (which every UI route
    here does), so a refreshed expiry can't be turned into a Set-Cookie right
    here. Instead we stash the token on ``request.state`` and let the
    ``refresh_session_cookie`` middleware (app.py) re-issue the cookie on
    whatever response actually comes back — see FR-3.
    """
    redirect_if_no_users(db)
    token = request.cookies.get(SESSION_COOKIE)
    session_row = sessions.get_session(db, token) if token else None
    if session_row is None:
        raise AuthRedirect("/login")
    # Check the user exists BEFORE touching the session: a session row for a
    # since-deleted user (orphaned despite our cleanup, e.g. old data) must
    # not be perpetually kept alive by the sliding-expiry touch.
    user = db.get(User, session_row.user_id)
    if user is None:
        raise AuthRedirect("/login")
    if sessions.touch_session(db, session_row):
        request.state.session_cookie_refresh = token
    request.state.session = session_row
    return user


def current_actor(user: User = Depends(get_current_user)) -> Actor:
    """Spec 0009 FR-5: who the audit log should blame for whatever this UI
    request changes. The API's equivalent is :func:`cabin.audit.token_actor`
    applied to the token its own dependency already resolved -- the two front
    doors stay separate, as everywhere else."""
    return user_actor(user)


def client_ip(request: Request, db: Session) -> str | None:
    """Spec 0009 FR-5: the address to record for this request.

    ``X-Forwarded-For`` is only consulted when the ``trust_proxy`` setting is
    on, because it is a header any client can send: believing it by default
    would let anyone choose which address the audit log blames. When it is
    on, only the *first* entry is taken -- everything after it was added by
    the proxies in between and is no more trustworthy than the header itself.
    """
    if get_flag(db, TRUST_PROXY):
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:MAX_IP_LENGTH]
    return request.client.host if request.client is not None else None


def require_role(*roles: Role) -> Callable[[User], User]:
    """Dependency factory: 403 unless the current user has one of ``roles``."""

    def _dep(user: User = Depends(get_current_user)) -> User:
        if Role(user.role) not in roles:
            raise HTTPException(status_code=403, detail="forbidden for this role")
        return user

    return _dep


#: The guard for every mutating (and mutation-only) page.
require_admin = require_role(*ADMIN_ROLES)


def current_principal(user: User = Depends(require_admin)) -> Principal:
    """Spec 0018 FR-5: the principal to check issuer grants against, for
    routes that already require :data:`require_admin`. This is ergonomics,
    not enforcement -- the enforcement is the required ``principal``
    parameter on ``issue_and_store``/``sign_csr_and_store``/
    ``revoke_certificate`` themselves.
    """
    return user_principal(user)


def verify_csrf(
    request: Request,
    csrf_token: str | None = Form(None),
    user: User = Depends(get_current_user),
) -> None:
    """FR-4: every mutating UI POST must carry the session's csrf_token."""
    session_row: UserSession = request.state.session
    # Compare as bytes: hmac.compare_digest on two str requires both to be
    # ASCII-only and raises TypeError otherwise -- a non-ASCII csrf_token
    # must be a clean 403, not a 500.
    if csrf_token is None or not hmac.compare_digest(
        csrf_token.encode("utf-8"), session_row.csrf_token.encode("utf-8")
    ):
        raise HTTPException(status_code=403, detail="csrf token mismatch")
