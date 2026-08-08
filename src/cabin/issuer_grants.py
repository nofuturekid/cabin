"""Issuer grants: which users and API tokens may issue and revoke through
which CA intermediate (spec 0018).

This module holds the whole policy: the two join tables (spec 0018 Phase 0),
the principal type a permission is checked against, and every rule that
reads or writes a grant. Nothing outside this module decides who may use
which issuer -- ``cabin.ca.certs`` and ``cabin.ca.crl`` call in here rather
than each growing their own copy of the question.

Import direction, checked and deliberate (spec 0018 FR-2): this module
imports ``cabin.users``, ``cabin.api_tokens`` and ``cabin.ca.service``, and
is imported by ``cabin.ca.certs`` and ``cabin.ca.crl``. ``cabin.ca.service``
imports none of the identity modules, so there is no cycle -- and
``cabin.users.delete_user`` reaches back in with a *local* import for the
same reason ``cabin.ca.certs`` reaches into ``cabin.ca.crl`` with one: the
alternative, a module-level import on both sides, would be an actual cycle
rather than a checked absence of one.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.api_tokens import ApiToken
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    IssuerRequiredError,
    active_issuers,
    get_ca,
    resolve_issuer,
)
from cabin.store import Base
from cabin.users import Role, User


class UserIssuer(Base):
    """One user's grant to sign and revoke through one CA intermediate.

    No surrogate id and no ``granted_at``/``granted_by`` column: the
    composite primary key over both columns is what makes granting
    idempotent at the database -- re-granting the same pair is an
    IntegrityError, not a second row -- and who changed a grant and when is
    what the audit log is for (spec 0018 FR-12), not a second thing this
    table would have to keep true.
    """

    __tablename__ = "user_issuers"

    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), primary_key=True)
    ca_certificate_id: Mapped[int] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), primary_key=True
    )


class TokenIssuer(Base):
    """One API token's grant to sign and revoke through one CA intermediate.

    A separate table from :class:`UserIssuer` rather than one table with a
    polymorphic owner column: API tokens have no owning user
    (``api_tokens.py``, spec 0008 -- deliberate, so a token cannot inherit a
    user's grants), so a token's grants cannot be expressed as a user's. See
    :class:`UserIssuer` for why there is no surrogate id.
    """

    __tablename__ = "token_issuers"

    api_token_id: Mapped[int] = mapped_column(sa.ForeignKey("api_tokens.id"), primary_key=True)
    ca_certificate_id: Mapped[int] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), primary_key=True
    )


class PrincipalKind(StrEnum):
    """Which kind of identity a :class:`Principal` speaks for (FR-2)."""

    user = "user"
    token = "token"
    #: FR-7: an ACME account -- a key thumbprint, no cabin row behind it.
    acme = "acme"
    #: FR-7: cabin acting for nobody (its own TLS certificate).
    system = "system"


@dataclass(frozen=True)
class Principal:
    """The identity a permission is checked against.

    Built only by :func:`user_principal`, :func:`token_principal`, or one of
    the two exempt module constants below (FR-2) -- never anything else, and
    never authenticated here: a ``Principal`` is derived from an identity
    that has *already* been authenticated and role-checked, and this type
    does not repeat either of those steps.
    """

    kind: PrincipalKind
    id: int | None
    role: Role | None

    @property
    def unrestricted(self) -> bool:
        """True for a superadmin user or token, and for both exempt
        constants (FR-3) -- none of the four needs a grant row to use every
        active issuer. False for every other role, including a viewer
        holding a grant row on every active issuer (AC-3): the role gate
        comes first, and a grant never substitutes for it.
        """
        return self.kind in (PrincipalKind.acme, PrincipalKind.system) or (
            self.role == Role.superadmin
        )


def user_principal(user: User) -> Principal:
    """The principal a logged-in ``user`` acts as, for every UI request."""
    return Principal(kind=PrincipalKind.user, id=user.id, role=Role(user.role))


def token_principal(token: ApiToken) -> Principal:
    """The principal an API ``token`` acts as, for both REST and MCP -- the
    same construction either way, so the two transports resolve one token's
    grants identically (FR-2)."""
    return Principal(kind=PrincipalKind.token, id=token.id, role=Role(token.role))


#: FR-7: there is no cabin user and no API token behind an ACME finalize or
#: an ACME revoke-cert -- the account is a key thumbprint, and there is
#: nothing to look a grant up by. A named constant rather than
#: ``principal=None``: ``None`` meaning "skip the check" would make a
#: forgotten call site a silent bypass instead of the TypeError AC-8 relies
#: on, and this constant is greppable at exactly the two call sites FR-7
#: names (AC-18).
ACME_PRINCIPAL = Principal(kind=PrincipalKind.acme, id=None, role=None)

#: FR-7: cabin issuing its own TLS certificate is not acting for anybody --
#: no session, no bearer token, and on the hourly renewal tick no request at
#: all. Mirrors ``audit.SYSTEM_ACTOR``, which already attributes the same
#: operation, so the two answers to "who did this" agree. See
#: :data:`ACME_PRINCIPAL` for why this is a named constant and not
#: ``principal=None``.
SYSTEM_PRINCIPAL = Principal(kind=PrincipalKind.system, id=None, role=None)


class IssuerForbiddenError(Exception):
    """This principal has no grant on the issuer it named, or on the row a
    revocation is already loading (spec 0018 FR-14)."""


class NoGrantedIssuerError(Exception):
    """No ``issuer_id`` was given and this principal has no granted active
    issuer (spec 0018 FR-14). Distinct from :class:`CANotConfiguredError`
    (``cabin.ca.service``), which means there is no active issuer for
    *anyone* -- the UI tells the two apart because the advice differs:
    "create a hierarchy" is exactly wrong for an operator who merely is not
    granted one that already exists.
    """


def _grant_ids(db: Session, principal: Principal) -> set[int]:
    """The raw set of ``ca_certificate_id`` a *restricted* principal holds a
    row for, regardless of status -- the shared read behind both
    :func:`granted_issuers` (further filtered to active issuers) and
    :func:`may_use_issuer` (status-blind, this set as-is; FR-3/FR-6).

    Never called for an unrestricted principal: every caller here checks
    ``Principal.unrestricted`` first, so landing in the ``else`` branch below
    for :data:`ACME_PRINCIPAL`/:data:`SYSTEM_PRINCIPAL` would be this
    module's own bug, not a state a caller can reach.
    """
    if principal.kind == PrincipalKind.user:
        stmt = select(UserIssuer.ca_certificate_id).where(UserIssuer.user_id == principal.id)
    elif principal.kind == PrincipalKind.token:
        stmt = select(TokenIssuer.ca_certificate_id).where(TokenIssuer.api_token_id == principal.id)
    else:
        raise AssertionError(f"{principal.kind} has no grant table to query")
    return set(db.scalars(stmt))


def granted_issuers(db: Session, principal: Principal) -> list[CACertificate]:
    """The **active** intermediates this principal may sign with, ordered by
    id (FR-3). For an unrestricted principal this is exactly
    ``active_issuers(db)``; for anyone else it is that set intersected with
    the principal's grant rows. A grant on a retired issuer therefore never
    appears here -- a retired issuer is not offered to anyone, granted or
    not. See :func:`may_use_issuer` for the lookup revocation uses instead,
    which does not filter on status.
    """
    issuers = active_issuers(db)
    if principal.unrestricted:
        return issuers
    granted = _grant_ids(db, principal)
    return [issuer for issuer in issuers if issuer.id in granted]


def may_use_issuer(db: Session, principal: Principal, ca_certificate_id: int) -> bool:
    """Whether ``principal`` holds a grant on ``ca_certificate_id`` --
    **status-blind**, unlike :func:`granted_issuers` (FR-3). True for every
    unrestricted principal.

    This, not :func:`granted_issuers`, is what :func:`cabin.ca.crl.
    revoke_certificate` asks (FR-6): a certificate signed by a
    since-retired issuer must still be revocable by the same people who were
    allowed to issue it, so the check must not filter on status the way
    issuing does.
    """
    if principal.unrestricted:
        return True
    return ca_certificate_id in _grant_ids(db, principal)


def resolve_granted_issuer(
    db: Session, principal: Principal, issuer_id: int | None
) -> CACertificate:
    """0017's "exactly one active issuer" narrowed to "exactly one *granted*
    issuer" (FR-4).

    With an explicit ``issuer_id``, 0017's own checks run first, unchanged,
    by delegating to :func:`cabin.ca.service.resolve_issuer`: existence,
    then kind and status. Only once those pass is the grant checked, via
    :func:`may_use_issuer` (status already established by ``resolve_issuer``
    at that point, so either lookup would agree; this one is chosen for what
    it *means* -- "may this principal use this issuer" -- not because it
    happens to filter the same rows here). A retired issuer therefore
    answers ``IssuerRetiredError`` whether or not it was ever granted: the
    retirement is the operative fact, and FR-13 keeps every issuer visible
    to every logged-in identity anyway, so there is no existence to conceal.

    Omitted, the **granted** set decides, not the active set: zero granted
    active issuers is :class:`NoGrantedIssuerError` when some are active
    anywhere, or ``CANotConfiguredError`` when none are; exactly one
    resolves to it however many are active in total (the single-CA
    experience on a multi-CA instance); two or more is
    ``IssuerRequiredError`` -- one rule, applied to a set that differs per
    principal.
    """
    if issuer_id is not None:
        issuer = resolve_issuer(db, issuer_id)  # existence, kind, status -- 0017, unchanged
        if not may_use_issuer(db, principal, issuer.id):
            raise IssuerForbiddenError(f"principal not granted issuer {issuer_id}")
        return issuer

    granted = granted_issuers(db, principal)
    if len(granted) == 1:
        return granted[0]
    if len(granted) > 1:
        raise IssuerRequiredError("more than one granted issuer exists; an issuer_id is required")
    if active_issuers(db):
        raise NoGrantedIssuerError("no granted active issuer; ask an operator for a grant")
    raise CANotConfiguredError("no CA hierarchy has been created or imported yet")


@dataclass(frozen=True)
class Change:
    """What :func:`set_issuers` actually did (FR-3), so FR-12's audit log
    and FR-11's UI can report ``added``/``removed`` without re-diffing
    anything themselves."""

    added: list[int]
    removed: list[int]
    issuers: list[int]

    @property
    def changed(self) -> bool:
        """False when the posted set was already in place -- what the
        no-op audit rule (FR-12) checks before calling ``audit.record``."""
        return bool(self.added or self.removed)


def issuers_of(db: Session, principal: Principal) -> list[int]:
    """The raw grant set for ``principal``, sorted -- what :func:`set_issuers`
    diffs against and what FR-11's UI renders as checked boxes.

    Unlike :func:`granted_issuers`, this is not filtered by active status
    and does not special-case an unrestricted principal: "all issuers" for a
    superadmin is a fact the UI states about the *role* (FR-11), not a row
    anywhere, so this stays a plain read of what was actually granted.
    """
    if principal.kind not in (PrincipalKind.user, PrincipalKind.token):
        raise ValueError(f"{principal.kind} has no grants to list")
    return sorted(_grant_ids(db, principal))


def _replace_grant_rows(db: Session, principal: Principal, issuer_ids: set[int]) -> None:
    """Write ``principal``'s grant set as exactly ``issuer_ids``: delete
    every existing row for it, then insert one per id. Private to
    :func:`set_issuers`, which has already validated ``principal.kind`` and
    every id in ``issuer_ids`` -- so the ``assert`` below documents an
    invariant already established by the caller, not a check performed here.
    """
    assert principal.id is not None  # user_principal/token_principal always set it
    if principal.kind == PrincipalKind.user:
        db.execute(sa.delete(UserIssuer).where(UserIssuer.user_id == principal.id))
        db.add_all(
            UserIssuer(user_id=principal.id, ca_certificate_id=issuer_id)
            for issuer_id in issuer_ids
        )
    else:
        db.execute(sa.delete(TokenIssuer).where(TokenIssuer.api_token_id == principal.id))
        db.add_all(
            TokenIssuer(api_token_id=principal.id, ca_certificate_id=issuer_id)
            for issuer_id in issuer_ids
        )


def set_issuers(db: Session, principal: Principal, issuer_ids: Sequence[int]) -> Change:
    """Replace ``principal``'s whole grant set in one transaction (FR-3/
    FR-10). ``principal`` is the **target** identity being granted, not the
    actor performing the grant -- a typed ``Principal`` rather than a raw id,
    so that a caller cannot pass a user id where a token id was meant: the
    two join tables are otherwise structurally identical, and a transposed
    argument would grant the wrong identity in silence.

    Every id must name an active-or-retired intermediate (FR-10): a root
    signs no leaf and no CRL, so a grant on one could only ever be dead data
    that reads like permission. Checked before any row is written, so a bad
    id anywhere in the list leaves the existing set completely untouched.
    Raises ``ValueError`` for :data:`ACME_PRINCIPAL`/:data:`SYSTEM_PRINCIPAL`,
    neither of which has anywhere to store a grant against.

    Re-posting the identical set writes nothing and returns a ``Change``
    with empty ``added``/``removed`` (FR-12's no-op audit rule reads
    ``changed`` off exactly that).
    """
    if principal.kind not in (PrincipalKind.user, PrincipalKind.token):
        raise ValueError(f"{principal.kind} cannot be granted an issuer")
    for ca_certificate_id in issuer_ids:
        issuer = get_ca(db, ca_certificate_id)
        if issuer.kind != "intermediate":
            raise ValueError(f"CA certificate {ca_certificate_id} is not an intermediate")

    before = _grant_ids(db, principal)
    after = set(issuer_ids)
    added = sorted(after - before)
    removed = sorted(before - after)
    if added or removed:
        _replace_grant_rows(db, principal, after)
        db.commit()
    return Change(added=added, removed=removed, issuers=sorted(after))


def grant(db: Session, principal: Principal, ca_certificate_id: int) -> bool:
    """Add one issuer to ``principal``'s grant set, idempotently (FR-8):
    returns whether a row was actually written, so a caller like
    ``/ca/create``'s auto-grant of the creator can be idempotent without
    counting existing rows itself.

    Same validation as :func:`set_issuers`: only an intermediate may be
    granted, and :data:`ACME_PRINCIPAL`/:data:`SYSTEM_PRINCIPAL` raise
    ``ValueError``, since neither has anywhere to store a grant against.
    """
    if principal.kind not in (PrincipalKind.user, PrincipalKind.token):
        raise ValueError(f"{principal.kind} cannot be granted an issuer")
    issuer = get_ca(db, ca_certificate_id)
    if issuer.kind != "intermediate":
        raise ValueError(f"CA certificate {ca_certificate_id} is not an intermediate")

    assert principal.id is not None  # user_principal/token_principal always set it
    if principal.kind == PrincipalKind.user:
        if db.get(UserIssuer, (principal.id, ca_certificate_id)) is not None:
            return False
        db.add(UserIssuer(user_id=principal.id, ca_certificate_id=ca_certificate_id))
    else:
        if db.get(TokenIssuer, (principal.id, ca_certificate_id)) is not None:
            return False
        db.add(TokenIssuer(api_token_id=principal.id, ca_certificate_id=ca_certificate_id))
    db.commit()
    return True
