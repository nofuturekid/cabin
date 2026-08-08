"""Bearer-token authentication for the REST API (spec 0008 FR-3).

Deliberately separate from :mod:`cabin.web.deps`: the API and the UI are two
mutually exclusive front doors. Nothing here reads a cookie, nothing here
checks CSRF (there is no ambient credential a foreign page could ride on),
and every failure is a JSON body -- never the UI's 303 to /login.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from cabin import api_tokens
from cabin.api_tokens import ApiToken
from cabin.issuer_grants import Principal, token_principal
from cabin.users import Role
from cabin.web.deps import ADMIN_ROLES, get_db

#: ``auto_error=False`` so a missing or non-Bearer Authorization header ends
#: up in our own 401 below -- with a JSON body and a WWW-Authenticate header --
#: instead of FastAPI's bare 403. Declaring it as a dependency also puts the
#: scheme into the OpenAPI document (FR-7).
_bearer = HTTPBearer(
    scheme_name="ApiToken",
    description="An API token, e.g. `Authorization: Bearer cabin_...`",
    auto_error=False,
)

_UNAUTHENTICATED = "a valid API token is required: Authorization: Bearer <token>"
_FORBIDDEN = "this token's role is not allowed to use this endpoint"


def _unauthenticated() -> HTTPException:
    """One answer for "no header", "junk header", "unknown, revoked or
    expired token": which of them it was is none of the caller's business."""
    return HTTPException(
        status_code=401,
        detail=_UNAUTHENTICATED,
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_api_role(*roles: Role) -> Callable[..., ApiToken]:
    """Dependency factory: authenticate the bearer token and require one of
    ``roles``. Returns the token row so a route can see who is calling."""

    def _dep(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        db: Session = Depends(get_db),
    ) -> ApiToken:
        if credentials is None or not credentials.credentials:
            raise _unauthenticated()
        token = api_tokens.verify_token(db, credentials.credentials)
        if token is None:
            raise _unauthenticated()
        if Role(token.role) not in roles:
            raise HTTPException(status_code=403, detail=_FORBIDDEN)
        return token

    return _dep


#: Any live token may read (FR-4: "viewer+").
require_api_read = require_api_role(Role.viewer, *ADMIN_ROLES)
#: Issuance, signing and revocation are "admin+" -- the same line the UI
#: draws, taken from the same constant so the two cannot drift.
require_api_write = require_api_role(*ADMIN_ROLES)


def api_write_principal(token: ApiToken = Depends(require_api_write)) -> Principal:
    """Spec 0018 FR-5: the REST API's equivalent of
    :func:`cabin.web.deps.current_principal` -- ergonomics, not enforcement."""
    return token_principal(token)
