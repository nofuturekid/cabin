"""Bearer-token authentication for the MCP server (spec 0013 FR-2).

MCP is the fourth front door onto cabin, and it opens with the same key as
the REST API: an API token from spec 0008, presented as
``Authorization: Bearer <secret>``. No cookies, no CSRF, no OAuth -- and
deliberately no credential of its own, so that revoking a token in /tokens
takes MCP access away with it.

Two halves, split because they run at different times:

* :class:`CabinTokenVerifier` runs at the *transport*. FastMCP hands it the
  bearer token before any MCP message is parsed; returning None there is
  what makes a missing, unknown, revoked or expired token a plain 401 rather
  than a JSON-RPC error a client would have to unwrap (FR-2).
* :func:`current_token` runs inside a tool, on that tool's own database
  session, and answers "who is this?" for the role gate and the audit log.
  It re-reads the row rather than trusting the claims, so a tool acts on the
  token as it is *now*.

:func:`cabin.api_tokens.verify_token` is synchronous, like the rest of
cabin's database access, so it is called in a worker thread: the ASGI event
loop must not block on SQLite.
"""

from collections.abc import Callable
from datetime import UTC

from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from cabin import api_tokens
from cabin.api_tokens import ApiToken

#: Where :class:`CabinTokenVerifier` puts the id of the row it authenticated
#: so that :func:`current_token` can find it again.
TOKEN_ID_CLAIM = "cabin_token_id"

#: The same answer for "no header", "junk header" and "unknown, revoked or
#: expired token" -- which of them it was is none of the caller's business.
UNAUTHENTICATED = "a valid API token is required: Authorization: Bearer <token>"


class CabinTokenVerifier(TokenVerifier):
    """Verify a bearer token against the ``api_tokens`` table.

    Takes a session factory rather than a session: the verifier lives as
    long as the application, and each verification is one short-lived
    session of its own -- the same rule the tools follow.
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        super().__init__()
        self._session_factory = session_factory

    async def verify_token(self, token: str) -> AccessToken | None:
        return await run_in_threadpool(self._verify, token)

    def _verify(self, token: str) -> AccessToken | None:
        db = self._session_factory()
        try:
            row = api_tokens.verify_token(db, token)
            if row is None:
                return None
            return AccessToken(
                token=token,
                client_id=str(row.id),
                scopes=[],
                # Told to the transport as well, so its own expiry check and
                # cabin's cannot disagree about when a token stops working.
                expires_at=(
                    int(row.expires_at.replace(tzinfo=UTC).timestamp())
                    if row.expires_at is not None
                    else None
                ),
                claims={TOKEN_ID_CLAIM: row.id},
            )
        finally:
            db.close()


def current_token(db: Session) -> ApiToken:
    """The token row behind the request a tool is running for.

    Raises :class:`ToolError` if there is none, which cannot happen through
    the HTTP transport -- the 401 above comes first -- and is therefore
    stated rather than assumed.
    """
    access = get_access_token()
    if access is None:  # pragma: no cover - the transport refuses these first
        raise ToolError(UNAUTHENTICATED)
    row = db.get(ApiToken, access.claims[TOKEN_ID_CLAIM])
    if row is None:  # pragma: no cover - tokens are revoked, never deleted
        raise ToolError(UNAUTHENTICATED)
    return row
