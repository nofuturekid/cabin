"""Order resources (spec 0010 FR-4, FR-5, FR-7): new-order, the order, its
authorizations and their challenges.

RFC 8555 sections 7.4, 7.5. Everything here is read with POST-as-GET and
belongs to exactly one account; nothing here validates a challenge or issues
a certificate -- those are specs 0011 and 0012.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import service
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.http import (
    AUTHZ_PREFIX,
    CHALLENGE_PREFIX,
    NEW_ORDER_PATH,
    ORDER_PREFIX,
    account_of,
    acme_body,
    authz_json,
    challenge_json,
    json_response,
    not_found,
    order_json,
    owned_order,
    url,
    verified,
)
from cabin.acme.jws import KeyMode
from cabin.audit import AuditAction, acme_actor
from cabin.ca import service as ca_service
from cabin.web.deps import client_ip, get_db

router = APIRouter()

#: Spec 0012 owns finalization and revocation. Until then the URLs are
#: advertised -- the directory and every order have to name them -- but they
#: answer honestly rather than 404ing without a nonce, which would strand a
#: client mid-flow.
#:
#: The two stubs below take no body and verify nothing, which is safe only
#: because they do nothing. Spec 0012 MUST give them the same
#: ``verified(...)`` treatment as every other POST route here before they
#: gain any effect -- a finalize that signs a CSR without checking the JWS
#: would issue certificates to anyone who can guess an order URL.
_NOT_IMPLEMENTED_STATUS = 501


@router.post("/new-order")
def new_order(
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    verification = verified(db, body, NEW_ORDER_PATH, KeyMode.kid)
    account = account_of(verification)
    payload = verification.payload
    if payload is None:
        raise AcmeError(ErrorType.malformed, "new-order needs a payload")

    identifiers = service.parse_identifiers(payload.get("identifiers"))
    not_before = service.parse_timestamp(payload.get("notBefore"), "notBefore")
    not_after = service.parse_timestamp(payload.get("notAfter"), "notAfter")
    if ca_service.get_ca(db) is None:
        # FR-5: the directory still answers without a CA, but an order that
        # could never become a certificate is refused with a reason an
        # operator can act on rather than accepted and left to rot.
        raise AcmeError(
            ErrorType.server_internal,
            "no CA is configured on this cabin instance, so it cannot issue certificates yet",
        )

    order = service.create_order(
        db, account, identifiers, not_before=not_before, not_after=not_after
    )
    audit.record(
        db,
        acme_actor(account.jwk_thumbprint),
        AuditAction.acme_order_created,
        summary="created ACME order for " + ", ".join(i.value for i in identifiers),
        target_type="acme_order",
        target_id=order.id,
        detail={"identifiers": [f"{i.type}:{i.value}" for i in identifiers]},
        ip=client_ip(request, db),
    )
    return json_response(
        order_json(db, order),
        status_code=201,
        Location=url(db, f"{ORDER_PREFIX}{order.id}"),
    )


@router.post("/order/{order_id}")
def order_resource(
    order_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    verification = verified(db, body, f"{ORDER_PREFIX}{order_id}", KeyMode.kid)
    order = owned_order(db, account_of(verification), service.get_order(db, order_id))
    return json_response(order_json(db, order))


@router.post("/authz/{authz_id}")
def authz_resource(
    authz_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    verification = verified(db, body, f"{AUTHZ_PREFIX}{authz_id}", KeyMode.kid)
    authz = service.get_authorization(db, authz_id)
    if authz is None:
        raise not_found("authorization")
    owned_order(db, account_of(verification), service.get_order(db, authz.order_id))
    return json_response(authz_json(db, authz))


@router.post("/chal/{challenge_id}")
def challenge_resource(
    challenge_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """POST-as-GET reads the challenge. A ``{}`` payload is RFC 8555 7.5.1's
    "please validate this" -- spec 0011's trigger; until then it reads the
    same, which is a truthful answer for a challenge nothing has started
    validating."""
    verification = verified(db, body, f"{CHALLENGE_PREFIX}{challenge_id}", KeyMode.kid)
    challenge = service.get_challenge(db, challenge_id)
    if challenge is None:
        raise not_found("challenge")
    authz = service.get_authorization(db, challenge.authz_id)
    if authz is None:  # pragma: no cover - a challenge always has its authz
        raise not_found("authorization")
    owned_order(db, account_of(verification), service.get_order(db, authz.order_id))
    return json_response(challenge_json(db, challenge))


def _unimplemented(what: str) -> AcmeError:
    return AcmeError(
        ErrorType.server_internal,
        f"{what} is not implemented yet on this cabin instance",
        status=_NOT_IMPLEMENTED_STATUS,
    )


@router.post("/revoke-cert")
def revoke_cert() -> Response:
    raise _unimplemented("certificate revocation over ACME")


@router.post("/order/{order_id}/finalize")
def finalize_order(order_id: str) -> Response:
    raise _unimplemented("order finalization")
