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
from cabin.sessions import SESSION_LIFETIME, UserSession
from cabin.users import Role, User

SESSION_COOKIE = "cabin_session"


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
    """Context every authenticated page needs: current user and the
    session's csrf_token (layout.html's logout form needs this on *every*
    page -- see ui.py's BUG 1 regression test), for use across UI routers.
    ``version`` is a Jinja global, not per-route context.
    """
    session_row: UserSession = request.state.session
    return {"user": user, "csrf_token": session_row.csrf_token}


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


def require_role(*roles: Role) -> Callable[[User], User]:
    """Dependency factory: 403 unless the current user has one of ``roles``."""

    def _dep(user: User = Depends(get_current_user)) -> User:
        if Role(user.role) not in roles:
            raise HTTPException(status_code=403, detail="forbidden for this role")
        return user

    return _dep


#: The roles that may change things (viewers may only look). Shared here so
#: route guards and per-page visibility checks can't drift apart on what
#: "admin" means -- use ADMIN_ROLES for the latter, never a re-inlined tuple.
ADMIN_ROLES = (Role.admin, Role.superadmin)

#: The guard for every mutating (and mutation-only) page.
require_admin = require_role(*ADMIN_ROLES)


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
