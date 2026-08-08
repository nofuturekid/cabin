"""Shared test scaffolding for issuer grants (spec 0018 Phase 0).

Builds ``user_issuers`` / ``token_issuers`` rows directly against the ORM,
the same choice :mod:`tests.ca_fixtures` made for CA hierarchy rows, and
for the same reason here specifically: :mod:`cabin.issuer_grants` does not
yet hold a ``grant``/``set_issuers`` function to route through (that lands
with the principal type and the grant policy, in a follow-up commit), and
even once it does, a fixture that calls the module under test to build the
state a test on that same module then asserts on would make the module its
own oracle. Tests that exercise ``issuer_grants.grant`` / ``set_issuers``
*as the thing under test* must keep calling them directly, not this module.

Two functions per identity kind, named after the kind rather than shared
under one name that takes "an id": :func:`grant_user`/:func:`revoke_user`
take a :class:`~cabin.users.User`, :func:`grant_token`/:func:`revoke_token`
take an :class:`~cabin.api_tokens.ApiToken`. The two join tables are
structurally identical -- both a foreign key to an identity table plus a
foreign key to ``ca_certificates`` -- so a single ``grant(db, id, issuer_id)``
taking a raw integer would let a user id and a token id be transposed
in silence. Passing the typed row instead makes that a mypy error, not a
silently wrong grant.
"""

import uuid

from sqlalchemy.orm import Session

from cabin.api_tokens import ApiToken
from cabin.issuer_grants import Principal, TokenIssuer, UserIssuer, user_principal
from cabin.users import Role, User, create_user


def grant_user(db: Session, user: User, ca_certificate_id: int) -> UserIssuer:
    """Grant ``user`` issuer ``ca_certificate_id``. Idempotent: granting an
    already-granted pair returns the existing row instead of racing the
    composite primary key for an ``IntegrityError``, so a fixture can be
    called defensively without the caller tracking what is already granted.
    """
    existing = db.get(UserIssuer, (user.id, ca_certificate_id))
    if existing is not None:
        return existing
    row = UserIssuer(user_id=user.id, ca_certificate_id=ca_certificate_id)
    db.add(row)
    db.commit()
    return row


def revoke_user(db: Session, user: User, ca_certificate_id: int) -> None:
    """Take ``ca_certificate_id`` away from ``user``. A no-op if it was
    never granted, matching :func:`grant_user`'s idempotence."""
    row = db.get(UserIssuer, (user.id, ca_certificate_id))
    if row is not None:
        db.delete(row)
        db.commit()


def grant_token(db: Session, token: ApiToken, ca_certificate_id: int) -> TokenIssuer:
    """Grant ``token`` issuer ``ca_certificate_id``. See :func:`grant_user`
    for the idempotence rationale."""
    existing = db.get(TokenIssuer, (token.id, ca_certificate_id))
    if existing is not None:
        return existing
    row = TokenIssuer(api_token_id=token.id, ca_certificate_id=ca_certificate_id)
    db.add(row)
    db.commit()
    return row


def revoke_token(db: Session, token: ApiToken, ca_certificate_id: int) -> None:
    """Take ``ca_certificate_id`` away from ``token``. A no-op if it was
    never granted, matching :func:`grant_token`'s idempotence."""
    row = db.get(TokenIssuer, (token.id, ca_certificate_id))
    if row is not None:
        db.delete(row)
        db.commit()


def granted_admin(db: Session, *issuer_ids: int) -> Principal:
    """A fresh admin, granted exactly ``issuer_ids``, as a :class:`Principal`.

    For call sites in tests that predate spec 0018 -- multi-CA and
    revocation mechanics, not the grant policy itself -- and now need
    *some* principal to satisfy ``issue_and_store``/``sign_csr_and_store``/
    ``revoke_certificate``'s required ``principal`` parameter. Deliberately
    a plain admin granted explicitly rather than a superadmin: a
    superadmin's grant set is implicit (``Principal.unrestricted``), so a
    test built on one would keep passing even if the grant check being
    exercised here were deleted outright. The username is a fresh uuid so
    repeated calls within one test don't collide on the unique column.
    """
    user = create_user(db, f"granted-{uuid.uuid4().hex[:10]}", "whatever12345", Role.admin)
    for issuer_id in issuer_ids:
        grant_user(db, user, issuer_id)
    return user_principal(user)
