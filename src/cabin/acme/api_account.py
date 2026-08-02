"""Account resources (spec 0010 FR-4, FR-6): new-account, the account
itself, its order list, and key rollover.

RFC 8555 section 7.3. The one invariant that runs through all of it: an
account *is* its key. new-account is idempotent on the key rather than on
the request, the account URL is only a handle, and a rollover is the one
operation that may change which key that handle answers to.
"""

import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import eab, jws, service
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
from cabin.settings import ACME_REQUIRE_EAB, get_flag
from cabin.web.deps import client_ip, get_db

router = APIRouter()


def _reject_unusable(account: AcmeAccount) -> None:
    """RFC 8555 7.3.6: a deactivated account may do nothing further, and
    finding it by key is "nothing further" too."""
    if account.status != AccountStatus.valid:
        raise AcmeError(ErrorType.unauthorized, f"this account is {account.status}")


def _external_account(
    db: Session,
    request: Request,
    verification: jws.VerifiedRequest,
    payload: dict[str, object],
) -> eab.AcmeEabKey | None:
    """Spec 0012 FR-4: the external account binding, verified but not yet
    spent.

    Runs only for a registration that will actually create an account: an
    existing account has already returned above, which is what keeps a
    client that re-registers (certbot does, routinely) from being asked for
    a credential it used months ago and no longer has.

    A binding that is *presented* is always verified, whether or not the
    setting requires one. Accepting an unverified binding would be worse
    than accepting none: it would tell the operator, in the UI, that a key
    was used by an account that never proved it held it.
    """
    binding = payload.get("externalAccountBinding")
    if binding is None:
        if get_flag(db, ACME_REQUIRE_EAB):
            raise AcmeError(
                ErrorType.external_account_required,
                "this server requires an external account binding: ask its operator for a key "
                "identifier and HMAC key",
            )
        return None
    return eab.verify(
        db,
        request.app.state.secrets,
        binding,
        new_account_url=url(db, NEW_ACCOUNT_PATH),
        account_jwk=verification.key.jwk,
    )


def _spend_binding(
    db: Session, binding: eab.AcmeEabKey, account: AcmeAccount, created: bool
) -> None:
    """One key, one account (FR-4).

    ``created`` is False when two registrations with the same account key
    raced and this one read back the winner's row; the key is then already
    bound to that same account, and re-binding would fail for a reason that
    is not the client's.

    When the claim genuinely loses -- two *different* account keys, one EAB
    key -- the account this request just created is removed again. Leaving
    it would hand out an account the client was told it could not have, and
    it has nothing attached to it yet.

    The mirror image -- one account key, two *different* EAB keys -- loses
    against the unique index on ``bound_account_id`` instead of against the
    conditional UPDATE, because both registrations end up at the same
    account and only one key may be bound to it. That is the same refusal
    and has to read like one: an ``IntegrityError`` escaping here would be a
    500 telling the client nothing about a rule it broke. The account is
    left alone in that case -- it is already carrying somebody's binding.
    """
    if binding.bound_account_id == account.id:
        return
    try:
        bound = eab.bind(db, binding, account)
    except IntegrityError as exc:
        db.rollback()
        raise eab.refused() from exc
    if not bound:
        if created:
            db.delete(account)
            db.commit()
        raise eab.refused()


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

    binding = _external_account(db, request, verification, payload)
    contacts = service.parse_contacts(payload["contact"]) if "contact" in payload else None
    account, created = service.get_or_create_account(
        db,
        verification.key,
        contacts=contacts,
        tos_agreed=bool(payload.get("termsOfServiceAgreed")),
    )
    if binding is not None:
        _spend_binding(db, binding, account, created)
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
