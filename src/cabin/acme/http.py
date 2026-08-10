"""The HTTP mechanics every ACME route shares (spec 0010 FR-4, FR-5).

Routes live in :mod:`cabin.acme.api` and its two siblings; what they all
need -- where cabin publishes itself, the enablement gate, the headers RFC
8555 requires on every response, and how a stored row becomes a protocol
object -- lives here, so that none of it can drift between them.

Three things are deliberately structural rather than left to each route:

* **The enablement gate is a router dependency**, so no route can be reached
  while ``acme_enabled`` is off. Off means invisible, i.e. 404 (FR-5).
* **The Replay-Nonce and Link headers come from middleware**, not from the
  routes. RFC 8555 wants a fresh nonce on the answer to every POST, errors
  included; attaching it once, after the response exists, is the only
  version of that rule a future route cannot forget.
* **Every URL cabin hands out is built from the configured base URL**, and
  never from the request. A client signs the URL it was told to use, so the
  URL cabin compares against has to be the one it published -- which behind
  a reverse proxy is not the one the request arrived on, and which an
  attacker must not be able to choose with a ``Host`` header
  (FR-4 / RFC 8555 6.4).
"""

import json
from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.acme import jws, nonces, service
from cabin.acme.errors import CONTENT_TYPE, AcmeError, ErrorType
from cabin.acme.jws import KeyMode, VerifiedRequest
from cabin.acme.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeChallenge,
    AcmeOrder,
)
from cabin.settings import ACME_ENABLED, BASE_URL, get_flag, get_setting
from cabin.web.deps import get_db

ACME_PREFIX = "/acme"
#: The per-issuer segment (spec 0019 FR-2): the only place an issuer appears
#: in a URL. Everything else -- accounts, orders, authorizations,
#: challenges, certificates -- is an opaque object URL that already knows
#: its issuer through the account that owns it.
CA_PREFIX = f"{ACME_PREFIX}/ca/"
NEW_NONCE_PATH = f"{ACME_PREFIX}/new-nonce"
NEW_ORDER_PATH = f"{ACME_PREFIX}/new-order"
KEY_CHANGE_PATH = f"{ACME_PREFIX}/key-change"
REVOKE_CERT_PATH = f"{ACME_PREFIX}/revoke-cert"
#: Resource prefixes; an id is appended to each. ``kid`` verification needs
#: the account one as a prefix rather than a formatted URL, which is why
#: these are written this way round.
ACCOUNT_PREFIX = f"{ACME_PREFIX}/account/"
ORDER_PREFIX = f"{ACME_PREFIX}/order/"
AUTHZ_PREFIX = f"{ACME_PREFIX}/authz/"
CHALLENGE_PREFIX = f"{ACME_PREFIX}/chal/"
#: Spec 0012 FR-2. The id here is the ``certificates`` row id, which is a
#: small integer and therefore guessable -- which is fine, and deliberately
#: so: the route authenticates the JWS and checks that the account owns the
#: order that produced the certificate, exactly as every order URL does.
CERT_PREFIX = f"{ACME_PREFIX}/cert/"

#: RFC 8555 7.4.2: what a certificate is served as.
PEM_CHAIN_CONTENT_TYPE = "application/pem-certificate-chain"


def directory_path(issuer_id: int) -> str:
    """Spec 0019 FR-2: this issuer's directory path. Not validated against
    the database here -- ``issuer_id`` may name nothing at all -- because
    this function is a pure path builder used both by the route that
    resolves it for real and by :func:`issuer_in_path`'s counterpart at the
    boundary, where a wrong id has to become a 404, not an exception raised
    two layers away from the request."""
    return f"{CA_PREFIX}{issuer_id}/directory"


def new_account_path(issuer_id: int) -> str:
    """Spec 0019 FR-2: this issuer's new-account path. See
    :func:`directory_path` for why ``issuer_id`` is not checked here."""
    return f"{CA_PREFIX}{issuer_id}/new-account"


def directory_url(db: Session, issuer_id: int) -> str | None:
    """The URL to hand an ACME client for one issuer, or None while no base
    URL is set (FR-5). Mirrors :func:`cabin.ca.crl.distribution_url`: a URL
    cabin puts in front of an operator has to be one that works from
    elsewhere, and only the configured base URL is known to be that."""
    base = get_setting(db, BASE_URL)
    return f"{base}{directory_path(issuer_id)}" if base else None


def issuer_in_path(path: str) -> int | None:
    """Spec 0019 FR-11: which issuer, if any, this request path names --
    a pure function of the path string, so :func:`require_acme_enabled` is
    its only caller and the middleware below never parses a URL of its own.

    Returns the id for any path under :data:`CA_PREFIX` with a numeric
    second segment, and ``None`` for every resource prefix
    (``/acme/cert/…``, ``/acme/account/…``) and for a non-numeric one
    (``/acme/ca/abc/directory``) -- the latter falls through to the
    catch-all's 404 before FR-4 ever gets a say, and this function does not
    know or care whether the id resolves to a real row. That last point
    decides R7: a 404 for an unknown or non-numeric id under the prefix
    still carries an ``index`` link naming the directory the client asked
    about, because resolving it here would mean this function stops being
    pure -- it would need the database to decide a header on a request that
    is about to fail anyway.
    """
    if not path.startswith(CA_PREFIX):
        return None
    segment = path[len(CA_PREFIX) :].split("/", 1)[0]
    return int(segment) if segment.isdigit() else None


def origin(db: Session) -> str:
    """Where cabin publishes itself.

    Only ever the configured base URL. The request's own ``Host`` header is
    not an alternative and not a fallback: a client that could choose it
    could make cabin publish a directory full of URLs pointing at the
    attacker, and RFC 8555 6.4 -- which binds a signature to the URL it
    covers -- would then be comparing against a value the attacker asserted.
    :func:`require_acme_enabled` refuses to serve ACME at all without one, so
    reaching the fallback below means the gate was bypassed.
    """
    base = get_setting(db, BASE_URL)
    if not base:  # pragma: no cover - the gate does not let ACME run without one
        raise AcmeError(ErrorType.server_internal, "no base URL is configured")
    return base


def url(db: Session, path: str) -> str:
    return f"{origin(db)}{path}"


def require_acme_enabled(request: Request, db: Session = Depends(get_db)) -> None:
    """FR-5: 404, not 403 -- an internal CA does not advertise the protocols
    it declines to speak.

    "No base URL configured" is treated exactly like "switched off", because
    without one there is no trustworthy answer to "what are cabin's URLs?"
    (see :func:`origin`). /settings refuses to tick the box without one; this
    is the backstop for a database edited by hand.

    Marking the request is also what tells the middleware below that this
    response is an ACME one.
    """
    base = get_setting(db, BASE_URL)
    if not get_flag(db, ACME_ENABLED) or not base:
        raise HTTPException(status_code=404, detail="not found")
    # Carried on the request so the middleware, which runs afterwards on a
    # session of its own, does not have to read the setting a second time --
    # and cannot observe a different answer if it changed in between.
    request.state.acme_enabled = True
    request.state.acme_origin = base
    # Spec 0019 FR-11: only a request under CA_PREFIX gets an `index` link,
    # and only to its own directory -- see acme_response_headers below for
    # why this is a path parse rather than a lookup through the account.
    issuer_id = issuer_in_path(request.url.path)
    if issuer_id is not None:
        request.state.acme_directory_path = directory_path(issuer_id)


#: What RFC 8555 6.2 requires an ACME POST to announce.
JOSE_CONTENT_TYPE = "application/jose+json"


def require_jose_content_type(request: Request) -> None:
    """RFC 8555 6.2: an ACME POST carries a JWS, so it must say so -- 415
    otherwise.

    Worth enforcing rather than shrugging at: a request that cabin will read
    as a signed instruction should not be one that a cross-origin form or a
    default ``fetch()`` could have produced, since those cannot set this
    header. Media type parameters (``; charset=utf-8``) are part of the
    syntax, not of the identity, so they are stripped before comparing.
    """
    if request.method != "POST":
        return
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != JOSE_CONTENT_TYPE:
        raise AcmeError(
            ErrorType.malformed,
            f"an ACME POST must have Content-Type: {JOSE_CONTENT_TYPE}",
            status=415,
        )


def offer_nonce(request: Request) -> None:
    """Ask the middleware for a ``Replay-Nonce`` on this response.

    Only the nonce endpoint needs to call this; POSTs get one anyway (see
    below).
    """
    request.state.acme_nonce_offered = True


def _wants_nonce(request: Request) -> bool:
    """Which responses carry a nonce.

    RFC 8555 6.5 needs one on the answer to every POST -- that is what the
    client's *next* POST spends -- and on the nonce endpoint. Nothing else
    has a client waiting for one, and minting them anyway would be a real
    cost: a nonce is a stored row with a 24-hour life, so an unauthenticated
    ``GET /acme/directory`` loop would grow the table without bound, two
    commits at a time.
    """
    return request.method == "POST" or getattr(request.state, "acme_nonce_offered", False) is True


async def acme_response_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """FR-11: the directory ``Link`` on the two per-issuer responses, and a
    fresh ``Replay-Nonce`` on every response that could be followed by a
    POST -- success or failure alike.

    Middleware rather than a response helper: an error raised anywhere -- in
    a dependency, in the JWS layer, in a route -- still has to come back with
    a usable nonce, or the client cannot even retry. Requests that never
    passed the gate are left alone, so a disabled cabin still says nothing.

    Spec 0019 removed the single shared directory this header used to name
    unconditionally, and there is no longer one URL to put in its place: an
    account URL, an order URL and so on all know their issuer through the
    account, not through the path, so there is nothing in the request to
    build a link from except when :func:`require_acme_enabled` parsed one
    out of the path itself (``request.state.acme_directory_path``). RFC 8555
    7.1 describes ``index`` as present on resources other than the
    directory; deriving it from the account instead -- which would cover
    those other resources too -- means threading the request through
    :func:`verified` and its eleven call sites for a header the interop gate
    (AC-13) proves no client actually reads: certbot and acme.sh complete a
    full issuance with it absent from nine of their ten responses. So the
    two per-issuer routes carry a link to their own directory, and every
    other ACME response carries none -- a deliberate, partial deviation
    rather than a bug.
    """
    response = await call_next(request)
    if getattr(request.state, "acme_enabled", False) is not True:
        return response
    directory_for_link = getattr(request.state, "acme_directory_path", None)
    if directory_for_link is not None:
        # Appended, never assigned: a route may have set a Link of its own --
        # spec 0011's challenge trigger owes the client an ``up`` link to the
        # authorization -- and overwriting it here would take that away.
        response.headers.append(
            "Link", f'<{request.state.acme_origin}{directory_for_link}>;rel="index"'
        )
    if not _wants_nonce(request):
        return response
    db: Session = request.app.state.db()
    try:
        response.headers["Replay-Nonce"] = nonces.issue(db)
    finally:
        db.close()
    return response


async def acme_error_handler(request: Request, exc: Exception) -> Response:
    """Every :class:`AcmeError` as an RFC 7807 problem document."""
    if not isinstance(exc, AcmeError):  # pragma: no cover - registered for AcmeError
        raise exc
    return JSONResponse(
        exc.problem(),
        status_code=exc.status,
        media_type=CONTENT_TYPE,
        headers=exc.headers,
    )


async def acme_body(request: Request) -> bytes:
    """The raw request body. An async dependency so the routes themselves
    stay synchronous and keep running in the threadpool, like every other
    database-touching route in cabin.

    A declared ``Content-Length`` past the cap is refused before the body is
    buffered at all; :func:`cabin.acme.jws.verify_request` still checks what
    actually arrived, since a chunked request declares nothing.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > jws.MAX_BODY_BYTES:
        raise AcmeError(ErrorType.malformed, "the request body is too large")
    return await request.body()


def json_response(data: dict[str, object], *, status_code: int = 200, **headers: str) -> Response:
    return JSONResponse(data, status_code=status_code, headers=headers or None)


def verified(db: Session, body: bytes, path: str, mode: KeyMode) -> VerifiedRequest:
    """Authenticate a request against the URL cabin publishes for ``path`` --
    which is a function of the configured base URL alone, never of the
    request that arrived."""
    return jws.verify_request(
        db,
        body,
        url=url(db, path),
        mode=mode,
        account_url_prefix=url(db, ACCOUNT_PREFIX),
    )


def account_of(request: VerifiedRequest) -> AcmeAccount:
    account = request.account
    if account is None:  # pragma: no cover - KeyMode.kid always resolves one
        raise AcmeError(ErrorType.server_internal, "this request has no account context")
    return account


def not_found(what: str) -> AcmeError:
    """RFC 8555 has no "not found" problem type; ``malformed`` at 404 is what
    the ecosystem converged on, and it keeps the body a problem document."""
    return AcmeError(ErrorType.malformed, f"no such {what}", status=404)


def owned_order(db: Session, account: AcmeAccount, order: AcmeOrder | None) -> AcmeOrder:
    """A resource URL is unguessable, but it is still not a capability: only
    the account that placed an order may read it or anything under it."""
    if order is None:
        raise not_found("order")
    if order.account_id != account.id:
        raise AcmeError(ErrorType.unauthorized, "this order belongs to another account")
    return order


def own_account_or_403(account: AcmeAccount, account_id: str) -> None:
    if account.id != account_id:
        raise AcmeError(ErrorType.unauthorized, "this account URL is not yours")


# --- resource serialization ------------------------------------------------------------


def account_json(db: Session, account: AcmeAccount) -> dict[str, object]:
    body: dict[str, object] = {
        "status": account.status,
        "orders": url(db, f"{ACCOUNT_PREFIX}{account.id}/orders"),
    }
    contacts = service.account_contacts(account)
    if contacts:
        body["contact"] = contacts
    return body


def challenge_json(db: Session, challenge: AcmeChallenge) -> dict[str, object]:
    body: dict[str, object] = {
        "type": challenge.type,
        "url": url(db, f"{CHALLENGE_PREFIX}{challenge.id}"),
        "status": challenge.status,
        "token": challenge.token,
    }
    if challenge.validated_at:
        # RFC 8555 7.1.5: present exactly when the challenge is valid, and
        # the reason a client can tell "proven just now" from "proven last
        # week" without keeping state of its own.
        body["validated"] = challenge.validated_at
    if challenge.error_json:
        # Spec 0011 FR-7: why the attempt failed, as the problem document
        # the validator produced -- the same wording the audit log has.
        body["error"] = json.loads(challenge.error_json)
    return body


def authz_json(db: Session, authz: AcmeAuthorization) -> dict[str, object]:
    body: dict[str, object] = {
        # Computed, not read: an authorization past its expiry says so.
        "status": service.authorization_status(authz),
        "expires": authz.expires_at,
        "identifier": {"type": authz.identifier_type, "value": authz.identifier_value},
        "challenges": [
            challenge_json(db, challenge) for challenge in service.challenges_of(db, authz)
        ],
    }
    if authz.wildcard:
        # RFC 8555 7.1.4: present only when true, and then the identifier
        # above is the name *without* the "*." in front of it.
        body["wildcard"] = True
    return body


def order_json(db: Session, order: AcmeOrder) -> dict[str, object]:
    body: dict[str, object] = {
        # Computed, not read: an order whose authorizations are all valid is
        # ready, and one that expired underneath them is invalid.
        "status": service.order_status(db, order),
        "expires": order.expires_at,
        "identifiers": service.order_identifiers(order),
        "authorizations": [
            url(db, f"{AUTHZ_PREFIX}{authz.id}") for authz in service.authorizations_of(db, order)
        ],
        "finalize": url(db, f"{ORDER_PREFIX}{order.id}/finalize"),
    }
    if order.not_before:
        body["notBefore"] = order.not_before
    if order.not_after:
        body["notAfter"] = order.not_after
    if order.certificate_id is not None:
        # RFC 8555 7.1.3: present exactly when there is a certificate to
        # fetch, which is what a client polls a finalized order for.
        body["certificate"] = url(db, f"{CERT_PREFIX}{order.certificate_id}")
    if order.error_json:
        body["error"] = json.loads(order.error_json)
    return body
