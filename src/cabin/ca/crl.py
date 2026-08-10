"""Revocation and CRL storage (spec 0007 FR-4/FR-5/FR-6; spec 0017 FR-9 for
one CRL per issuer): marking a stored certificate revoked, and keeping
exactly one current CRL per issuer in the database.

Layered on top of the pure builder in :mod:`cabin.ca.revocation`, the CA's
signing credentials from :mod:`cabin.ca.service`, and the certificate rows
of :mod:`cabin.ca.certs`. Kept out of ``certs.py`` so the dependency runs
one way only (crl -> certs) and neither file grows a second subject.
"""

from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.ca.certs import Certificate
from cabin.ca.leaf import public_http_origin
from cabin.ca.revocation import CRL_VALIDITY, RevocationReason, RevokedEntry, build_crl
from cabin.ca.service import signing_credentials
from cabin.issuer_grants import IssuerForbiddenError, Principal, may_use_issuer
from cabin.secrets import SecretStore
from cabin.settings import BASE_URL, get_setting
from cabin.store import Base

#: How long a served CRL may be cached (FR-5). :mod:`cabin.web.crl_ui` turns
#: this into the Cache-Control header, and :func:`current_crl` refreshes this
#: far ahead of nextUpdate -- a client that caches a CRL must never end up
#: holding an expired one.
CRL_MAX_AGE = timedelta(hours=1)


class RevocationError(Exception):
    """The certificate to revoke does not exist (FR-4)."""


class CRLState(Base):
    """The current CRL for one issuer: its DER bytes, the number it was
    published under, and when it was generated (spec 0017 FR-1/FR-9). One
    row per issuer, not one per instance -- a CRL is a current document,
    not a history."""

    __tablename__ = "crl_state"

    issuer_id: Mapped[int] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), primary_key=True, autoincrement=False
    )
    crl_number: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    crl_der: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)

    @property
    def next_update(self) -> datetime:
        """When this CRL goes stale. It is derived rather than stored because
        :func:`regenerate_crl` writes ``generated_at`` and the CRL's own
        nextUpdate from the same instant -- one source of truth, no drift."""
        return self.generated_at.replace(tzinfo=UTC) + CRL_VALIDITY


def distribution_url(db: Session, issuer_id: int) -> str | None:
    """The URL a newly issued certificate should name as its CRL
    distribution point, or None while no base URL is configured
    (spec 0007 FR-6; spec 0017 FR-9).

    Built through :func:`cabin.ca.leaf.public_http_origin` rather than the
    configured base URL directly, so this always names a plain-HTTP address
    (spec 0017 FR-12): a relying party validating a certificate would
    otherwise need a CRL it can only fetch over TLS, which needs a
    certificate that is not yet validated.
    """
    base = get_setting(db, BASE_URL)
    if not base:
        return None
    return f"{public_http_origin(base)}/crl/{issuer_id}"


def ca_issuers_url(db: Session, issuer_id: int) -> str | None:
    """The URL a newly issued leaf should name as its AIA ``caIssuers``
    access location, or None while no base URL is configured
    (spec 0017 FR-11/FR-12). Set for every row, root or intermediate --
    ``GET /ca/{id}.cer`` answers for both."""
    base = get_setting(db, BASE_URL)
    if not base:
        return None
    return f"{public_http_origin(base)}/ca/{issuer_id}.cer"


def _revoked_entries(db: Session, issuer_id: int) -> list[RevokedEntry]:
    rows = db.scalars(
        select(Certificate)
        .where(Certificate.issuer_id == issuer_id, Certificate.revoked_at.is_not(None))
        .order_by(Certificate.id)
    ).all()
    entries: list[RevokedEntry] = []
    for row in rows:
        revoked_at = row.revoked_at_dt
        assert revoked_at is not None  # guaranteed by the WHERE above
        entries.append(
            RevokedEntry(
                serial_number=int(row.serial_hex, 16),
                revoked_at=revoked_at,
                reason=RevocationReason(row.revocation_reason or RevocationReason.unspecified),
            )
        )
    return entries


def regenerate_crl(
    db: Session, secrets: SecretStore, issuer_id: int, now: datetime | None = None
) -> CRLState:
    """Rebuild ``issuer_id``'s CRL from its own revoked rows and store it
    (FR-4; spec 0017 FR-9: scoped to one issuer, not every revocation in the
    database).

    ``crl_number`` increments on every call for this issuer, so it only
    ever climbs -- a relying party rejects a CRL whose number went
    backwards.

    The state row is taken FOR UPDATE, which serializes concurrent
    regenerations of the *same issuer's* CRL on a database that supports row
    locks (PostgreSQL; a no-op on SQLite, where a write transaction is
    exclusive anyway). Without it two callers could not merely collide on a
    number: under READ COMMITTED each would read the revocation set as it
    stood before the other's commit, and the one that committed last would
    publish a CRL missing the other's revocation -- permanently, until
    something else regenerated. Holding the lock means the second caller
    reads the first one's committed revocations and its number.

    Commits, which also commits whatever the caller has pending in the same
    session: that is what makes revoke-then-publish a single transaction.

    Raises UnknownIssuerError/CANotConfiguredError per
    :func:`cabin.ca.service.signing_credentials`.
    """
    moment = now or datetime.now(UTC)
    issuer_cert, issuer_key = signing_credentials(db, secrets, issuer_id)
    state = db.get(CRLState, issuer_id, with_for_update=True)
    number = state.crl_number + 1 if state is not None else 1
    crl = build_crl(
        issuer_cert,
        issuer_key,
        _revoked_entries(db, issuer_id),
        crl_number=number,
        this_update=moment,
        next_update=moment + CRL_VALIDITY,
    )
    der = crl.public_bytes(serialization.Encoding.DER)
    naive = moment.astimezone(UTC).replace(tzinfo=None)
    if state is None:
        state = CRLState(issuer_id=issuer_id, crl_number=number, generated_at=naive, crl_der=der)
        db.add(state)
    else:
        state.crl_number = number
        state.generated_at = naive
        state.crl_der = der
    db.commit()
    return state


def stored_crl(db: Session, issuer_id: int) -> CRLState | None:
    """``issuer_id``'s stored CRL as-is, without regenerating anything --
    what is left to serve when its key cannot be used right now (FR-5)."""
    return db.get(CRLState, issuer_id)


def current_crl(
    db: Session, secrets: SecretStore, issuer_id: int, now: datetime | None = None
) -> CRLState:
    """The CRL to serve for ``issuer_id``, regenerating it if there is none
    yet or the stored one is within :data:`CRL_MAX_AGE` of its nextUpdate
    (FR-5).

    The margin is what keeps the cache header honest: a client that fetches
    just before the cutoff caches the answer for an hour, and that hour has
    to fit inside the CRL's remaining validity.

    This lazy refresh is deliberately the only scheduler cabin has, and it
    is scoped per issuer (spec 0017 FR-9): an issuer nobody asks a CRL from
    does not need a fresh one, and refreshing one issuer's CRL must not
    touch another's ``crl_number``.

    Raises UnknownIssuerError/CANotConfiguredError per
    :func:`cabin.ca.service.signing_credentials`.
    """
    moment = now or datetime.now(UTC)
    state = stored_crl(db, issuer_id)
    if state is None or moment + CRL_MAX_AGE >= state.next_update:
        return regenerate_crl(db, secrets, issuer_id, moment)
    return state


def revoke_certificate(
    db: Session,
    secrets: SecretStore,
    cert_id: int,
    reason: RevocationReason = RevocationReason.unspecified,
    *,
    principal: Principal,
    now: datetime | None = None,
) -> Certificate:
    """Mark a stored certificate revoked and republish its issuer's CRL
    (FR-4).

    The issuer still comes off the row this is already loading
    (``row.issuer_id``), unchanged from before spec 0017. Revoking a
    certificate whose issuer is retired still works and still republishes
    that issuer's CRL (spec 0017 FR-9) -- a retired issuer that could not
    publish revocations would be worse than one still issuing.

    ``principal`` is required and keyword-only, with no default (spec 0018
    FR-6): :func:`cabin.issuer_grants.may_use_issuer` is checked against
    ``row.issuer_id`` -- **not** :func:`cabin.issuer_grants.granted_issuers`,
    which would wrongly refuse revoking through a since-retired issuer
    (spec 0017 FR-9's guarantee that a retired issuer's CRL stays
    publishable). The check runs before anything is written, so a refused
    revocation leaves ``revoked_at``, ``crl_number`` and the stored CRL
    bytes untouched; raises IssuerForbiddenError.

    Idempotent: revoking an already-revoked certificate returns the existing
    row untouched and is NOT an error -- the revocation date a relying party
    was told about must not move, and a caller retrying after a timeout
    should get success, not a 409. The grant is still checked first, so an
    already-revoked certificate is not itself a way past the permission
    check.

    Raises RevocationError for an unknown certificate, CANotConfiguredError
    if its issuer has no usable signing key.
    """
    row = db.get(Certificate, cert_id)
    if row is None:
        raise RevocationError(f"no certificate with id {cert_id}")
    if not may_use_issuer(db, principal, row.issuer_id):
        raise IssuerForbiddenError(f"principal not granted issuer {row.issuer_id}")
    if row.revoked_at is not None:
        return row
    moment = now or datetime.now(UTC)
    row.revoked_at = moment.astimezone(UTC).isoformat()
    row.revocation_reason = str(reason)
    # Same session, one commit: the row and the CRL that lists it land
    # together or not at all. If publishing fails, the mark comes off again --
    # a certificate recorded as revoked that no CRL mentions would be a
    # revocation nobody can see.
    try:
        regenerate_crl(db, secrets, row.issuer_id, moment)
    except Exception:
        db.rollback()
        raise
    return row
