"""The ACME router (spec 0010 FR-4, FR-5): the two unauthenticated routes,
and the assembly of everything else.

Public routes: no session, no cookie, no CSRF token. The JWS *is* the
authentication (:mod:`cabin.acme.jws`), which is why nothing here consults
:mod:`cabin.web.deps`' user machinery.

The order of registration below is load-bearing. Resource routes first, then
an explicit GET for each POST-only path, then a catch-all that matches
anything else under ``/acme`` with any method. Because the enablement gate
is a dependency of *this* router, that last route is what makes "off means
404 everywhere" a property of the router rather than of whoever remembers to
add the next path (AC-6).
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.acme import api_account, api_finalize, api_order
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.http import (
    ACME_PREFIX,
    KEY_CHANGE_PATH,
    NEW_NONCE_PATH,
    NEW_ORDER_PATH,
    REVOKE_CERT_PATH,
    json_response,
    new_account_path,
    not_found,
    offer_nonce,
    require_acme_enabled,
    require_jose_content_type,
    url,
)
from cabin.ca import service as ca_service
from cabin.settings import ACME_REQUIRE_EAB, BASE_URL, get_flag, get_setting
from cabin.web.deps import get_db

router = APIRouter(
    prefix=ACME_PREFIX,
    # Order matters: the gate first, so that a request arriving while ACME is
    # off is a 404 and learns nothing -- not even that its Content-Type was
    # wrong.
    dependencies=[Depends(require_acme_enabled), Depends(require_jose_content_type)],
    # ACME is a protocol for machines, not an endpoint an operator browses;
    # cabin's OpenAPI document describes the REST API of spec 0008.
    include_in_schema=False,
)


@router.get("/ca/{issuer_id:int}/directory")
def directory(issuer_id: int, db: Session = Depends(get_db)) -> Response:
    """Spec 0019 FR-3/FR-4: the shared ``/acme/directory`` is gone with no
    alias -- there is no longer a single directory to serve, and inventing
    one would reintroduce the default-issuer rule this spec removes. An id
    naming no row, or a root rather than an intermediate, is the same
    ``not_found`` problem document as any other unknown ACME resource: a
    root signs no leaf, so its directory would be a URL that could never
    produce a certificate. A *retired* intermediate still gets one -- 0017
    FR-9's precedent for its CRL -- so its existing accounts keep polling
    and are refused precisely where it matters (new-account, new-order),
    not here.
    """
    try:
        issuer = ca_service.get_ca(db, issuer_id)
    except ca_service.UnknownIssuerError as exc:
        raise not_found("ACME resource") from exc
    if issuer.kind != "intermediate":
        raise not_found("ACME resource")
    website = get_setting(db, BASE_URL)
    meta: dict[str, object] = {
        # RFC 8555 9.7.6 / spec 0012 FR-4: a client reads this before it
        # builds a registration, so that "you need credentials" is something
        # it learns from the directory rather than from a 403. No
        # cabin-specific member names the issuer here (Out of Scope): the
        # registry does not grant one, and the ``/ca`` page answers that
        # question for the audience that asks it.
        "externalAccountRequired": get_flag(db, ACME_REQUIRE_EAB)
    }
    if website:
        meta["website"] = website
    return json_response(
        {
            "newNonce": url(db, NEW_NONCE_PATH),
            "newAccount": url(db, new_account_path(issuer_id)),
            "newOrder": url(db, NEW_ORDER_PATH),
            "revokeCert": url(db, REVOKE_CERT_PATH),
            "keyChange": url(db, KEY_CHANGE_PATH),
            "meta": meta,
        }
    )


@router.api_route("/new-nonce", methods=["GET", "HEAD"])
def new_nonce(request: Request) -> Response:
    """RFC 8555 7.2: 200 to a HEAD, 204 to a GET. The nonce itself is
    attached by the middleware -- this is the one non-POST route that asks
    for one."""
    offer_nonce(request)
    return Response(
        status_code=200 if request.method == "HEAD" else 204,
        # A cached nonce is a nonce that will be refused.
        headers={"Cache-Control": "no-store"},
    )


router.include_router(api_account.router)
router.include_router(api_order.router)
router.include_router(api_finalize.router)


#: Resources that are read with POST-as-GET. Each gets an explicit GET route
#: so that a browser's idea of "just open the URL" is answered with 405 --
#: and, while ACME is off, with the gate's 404 like every other path here.
_POST_ONLY_PATHS = (
    "/ca/{issuer_id:int}/new-account",
    "/new-order",
    "/key-change",
    "/revoke-cert",
    "/account/{account_id}",
    "/account/{account_id}/orders",
    "/order/{order_id}",
    "/order/{order_id}/finalize",
    "/authz/{authz_id}",
    "/chal/{challenge_id}",
    "/cert/{cert_id}",
)


def _method_not_allowed() -> Response:
    raise AcmeError(
        ErrorType.malformed,
        "this ACME resource is read with a POST-as-GET request, not a GET",
        status=405,
        # RFC 7231 6.5.5 makes this header mandatory on a 405, and it is the
        # one line that tells a client what to do instead.
        headers={"Allow": "POST"},
    )


for _path in _POST_ONLY_PATHS:
    router.add_api_route(_path, _method_not_allowed, methods=["GET"])


#: Every method, so that nothing under /acme can answer without having
#: passed the gate -- and so that a wrong method on a real path is a 404
#: here rather than a 405 from Starlette that never ran the gate.
_ANY_METHOD = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


@router.api_route("", methods=_ANY_METHOD)
def unknown_root() -> Response:
    """``/acme`` itself. Registered explicitly because otherwise Starlette
    matches nothing, notices that ``/acme/`` would match the catch-all below,
    and answers 307 -- which tells anyone asking that something lives here
    even while ACME is switched off."""
    raise not_found("ACME resource")


@router.api_route("/{rest:path}", methods=_ANY_METHOD)
def unknown_resource(rest: str) -> Response:
    """AC-6: registered last and matching every method, so that *no* path
    under ``/acme`` can answer without having gone through the gate -- the
    404 of a disabled cabin is then a property of this router, not of
    someone having remembered to add a route."""
    raise not_found("ACME resource")
