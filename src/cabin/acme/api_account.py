"""Account resources (spec 0010 FR-4, FR-6): new-account, the account
itself, its order list, and key rollover.

RFC 8555 section 7.3. The one invariant that runs through all of it: an
account *is* its key. new-account is idempotent on the key rather than on
the request, the account URL is only a handle, and a rollover is the one
operation that may change which key that handle answers to.
"""

import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import jws, service
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.http import (
    ACCOUNT_PREFIX,
    KEY_CHANGE_PATH,
    NEW_ACCOUNT_PATH,
    ORDER_PREFIX,
    account_json,
    account_of,
    acme_body,
    json_response,
    own_account_or_403,
    url,
    verified,
)
from cabin.acme.jws import KeyMode
from cabin.acme.models import AccountStatus, AcmeAccount
from cabin.audit import AuditAction, acme_actor
from cabin.web.deps import client_ip, get_db

router = APIRouter()


def _reject_unusable(account: AcmeAccount) -> None:
    """RFC 8555 7.3.6: a deactivated account may do nothing further, and
    finding it by key is "nothing further" too."""
    if account.status != AccountStatus.valid:
        raise AcmeError(ErrorType.unauthorized, f"this account is {account.status}")


@router.post("/new-account")
def new_account(
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    verification = verified(db, body, NEW_ACCOUNT_PATH, KeyMode.jwk)
    payload = verification.payload
    if payload is None:
        raise AcmeError(ErrorType.malformed, "new-account needs a payload")

    existing = service.find_account_by_key(db, verification.key.thumbprint)
    if existing is not None:
        _reject_unusable(existing)
        return json_response(
            account_json(db, existing),
            Location=url(db, f"{ACCOUNT_PREFIX}{existing.id}"),
        )
    if payload.get("onlyReturnExisting"):
        raise AcmeError(ErrorType.account_does_not_exist, "no account is registered for this key")

    contacts = service.parse_contacts(payload["contact"]) if "contact" in payload else None
    account, created = service.get_or_create_account(
        db,
        verification.key,
        contacts=contacts,
        tos_agreed=bool(payload.get("termsOfServiceAgreed")),
    )
    if created:
        audit.record(
            db,
            acme_actor(account.jwk_thumbprint),
            AuditAction.acme_account_created,
            summary="registered ACME account",
            target_type="acme_account",
            target_id=account.id,
            detail={"thumbprint": account.jwk_thumbprint},
            ip=client_ip(request, db),
        )
    return json_response(
        account_json(db, account),
        status_code=201 if created else 200,
        Location=url(db, f"{ACCOUNT_PREFIX}{account.id}"),
    )


@router.post("/account/{account_id}")
def account_resource(
    account_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """POST-as-GET, a contact update, or deactivation (RFC 8555 7.3.2/7.3.6)."""
    verification = verified(db, body, f"{ACCOUNT_PREFIX}{account_id}", KeyMode.kid)
    account = account_of(verification)
    own_account_or_403(account, account_id)

    payload = verification.payload
    if payload:
        status = payload.get("status")
        if status is not None:
            if status != AccountStatus.deactivated:
                raise AcmeError(
                    ErrorType.malformed,
                    "an account may only be updated to 'deactivated'",
                )
            service.deactivate_account(db, account)
            audit.record(
                db,
                acme_actor(account.jwk_thumbprint),
                AuditAction.acme_account_deactivated,
                summary="deactivated ACME account",
                target_type="acme_account",
                target_id=account.id,
                detail={"thumbprint": account.jwk_thumbprint},
                ip=client_ip(request, db),
            )
        elif "contact" in payload:
            service.set_contacts(db, account, service.parse_contacts(payload["contact"]))
    return json_response(account_json(db, account))


@router.post("/account/{account_id}/orders")
def account_orders(
    account_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """RFC 8555 7.1.2.1: the account's orders, read with POST-as-GET."""
    verification = verified(db, body, f"{ACCOUNT_PREFIX}{account_id}/orders", KeyMode.kid)
    account = account_of(verification)
    own_account_or_403(account, account_id)
    return json_response(
        {
            "orders": [
                url(db, f"{ORDER_PREFIX}{order.id}") for order in service.orders_of(db, account)
            ]
        }
    )


@router.post("/key-change")
def key_change(
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """RFC 8555 7.3.5. Implemented rather than stubbed: it is the only way a
    client can recover from a compromised account key without abandoning its
    account, and the whole of it is two signatures that have to agree.

    The outer JWS (old key) says this account wants the change; the inner one
    (new key) says the new key wants this account. Neither alone is enough.
    """
    verification = verified(db, body, KEY_CHANGE_PATH, KeyMode.kid)
    account = account_of(verification)
    new_key, inner = jws.verify_embedded(verification.payload, url=url(db, KEY_CHANGE_PATH))

    if inner.get("account") != url(db, f"{ACCOUNT_PREFIX}{account.id}"):
        raise AcmeError(ErrorType.malformed, "the key change names a different account")
    if inner.get("oldKey") != json.loads(account.jwk_json):
        raise AcmeError(ErrorType.malformed, "the key change does not quote the current key")

    conflict = service.find_account_by_key(db, new_key.thumbprint)
    if conflict is not None:
        # RFC 8555 7.3.5 step 9: no account may end up sharing a key -- which
        # also rules out "rotating" to the key already in use here.
        raise AcmeError(
            ErrorType.malformed,
            "an account already exists for that key",
            status=409,
            headers={"Location": url(db, f"{ACCOUNT_PREFIX}{conflict.id}")},
        )
    service.rotate_account_key(db, account, new_key)
    return json_response(account_json(db, account))
