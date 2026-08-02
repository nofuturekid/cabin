"""Order resources (spec 0010 FR-4, FR-5, FR-7): new-order, the order, its
authorizations and their challenges.

RFC 8555 sections 7.4, 7.5. Everything here is read with POST-as-GET and
belongs to exactly one account. Finalization, the certificate itself and
revocation -- the three routes that mint or retire one -- live next door in
:mod:`cabin.acme.api_finalize`.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, Request
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
from cabin.acme.validation import validate_challenge
from cabin.audit import AuditAction, acme_actor
from cabin.ca import service as ca_service
from cabin.web.deps import client_ip, get_db

router = APIRouter()


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
    background: BackgroundTasks,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """Read a challenge, or start it (spec 0011 FR-2, FR-3).

    One URL, two meanings, told apart by the payload alone: an *empty*
    payload is POST-as-GET and only reads, an empty JSON *object* is RFC
    8555 7.5.1's "I am ready, go and check" and schedules the validation.
    Getting that distinction wrong in either direction would be a bug a
    client cannot work around -- polling would keep re-validating, or the
    trigger would never fire.

    The response never waits for the validation (FR-3): it reports
    ``processing`` and the client polls the authorization, which is what the
    ``up`` link below is for.
    """
    verification = verified(db, body, f"{CHALLENGE_PREFIX}{challenge_id}", KeyMode.kid)
    challenge = service.get_challenge(db, challenge_id)
    if challenge is None:
        raise not_found("challenge")
    authz = service.get_authorization(db, challenge.authz_id)
    if authz is None:  # pragma: no cover - a challenge always has its authz
        raise not_found("authorization")
    owned_order(db, account_of(verification), service.get_order(db, authz.order_id))

    if verification.payload is not None and service.begin_challenge(db, challenge, authz):
        # The task is handed the *factory*, not this request's session: by
        # the time it runs, this one is closed (see cabin.acme.validation).
        background.add_task(validate_challenge, request.app.state.db, challenge.id)
    return json_response(
        challenge_json(db, challenge),
        # RFC 8555 7.5.1: which authorization to poll. Set here and appended
        # to by the middleware, which adds the directory link.
        Link=f'<{url(db, f"{AUTHZ_PREFIX}{authz.id}")}>;rel="up"',
    )
