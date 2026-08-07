"""Revocation and CRL storage (spec 0007 FR-4/FR-5/FR-6): marking a stored
certificate revoked, and keeping exactly one current CRL in the database.

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
from cabin.ca.revocation import CRL_VALIDITY, RevocationReason, RevokedEntry, build_crl
from cabin.ca.service import signing_credentials
from cabin.secrets import SecretStore
from cabin.settings import BASE_URL, get_setting
from cabin.store import Base

#: Path the CRL is served under, appended to the configured base URL for the
#: CDP extension (FR-6). Must match the route in :mod:`cabin.web.crl_ui`.
CRL_PATH = "/crl"

#: How long a served CRL may be cached (FR-5). :mod:`cabin.web.crl_ui` turns
#: this into the Cache-Control header, and :func:`current_crl` refreshes this
#: far ahead of nextUpdate -- a client that caches a CRL must never end up
#: holding an expired one.
CRL_MAX_AGE = timedelta(hours=1)

#: The one row of ``crl_state`` (the table's CHECK constraint enforces it).
_STATE_ID = 1


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


def distribution_url(db: Session) -> str | None:
    """The URL a newly issued certificate should name as its CRL distribution
    point, or None while no base URL is configured (FR-6)."""
    base = get_setting(db, BASE_URL)
    return f"{base}{CRL_PATH}" if base else None


def _revoked_entries(db: Session) -> list[RevokedEntry]:
    rows = db.scalars(
        select(Certificate).where(Certificate.revoked_at.is_not(None)).order_by(Certificate.id)
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


def regenerate_crl(db: Session, secrets: SecretStore, now: datetime | None = None) -> CRLState:
    """Rebuild the CRL from every revoked row and store it (FR-4).

    ``crl_number`` increments on every call, so it only ever climbs -- a
    relying party rejects a CRL whose number went backwards.

    The state row is taken FOR UPDATE, which serializes concurrent
    regenerations on a database that supports row locks (PostgreSQL; a no-op
    on SQLite, where a write transaction is exclusive anyway). Without it two
    callers could not merely collide on a number: under READ COMMITTED each
    would read the revocation set as it stood before the other's commit, and
    the one that committed last would publish a CRL missing the other's
    revocation -- permanently, until something else regenerated. Holding the
    lock means the second caller reads the first one's committed revocations
    and its number.

    Commits, which also commits whatever the caller has pending in the same
    session: that is what makes revoke-then-publish a single transaction.

    Raises CANotConfiguredError if no CA exists.
    """
    moment = now or datetime.now(UTC)
    issuer_cert, issuer_key = signing_credentials(db, secrets)
    state = db.get(CRLState, _STATE_ID, with_for_update=True)
    number = state.crl_number + 1 if state is not None else 1
    crl = build_crl(
        issuer_cert,
        issuer_key,
        _revoked_entries(db),
        crl_number=number,
        this_update=moment,
        next_update=moment + CRL_VALIDITY,
    )
    der = crl.public_bytes(serialization.Encoding.DER)
    naive = moment.astimezone(UTC).replace(tzinfo=None)
    if state is None:
        state = CRLState(id=_STATE_ID, crl_number=number, generated_at=naive, crl_der=der)
        db.add(state)
    else:
        state.crl_number = number
        state.generated_at = naive
        state.crl_der = der
    db.commit()
    return state


def stored_crl(db: Session) -> CRLState | None:
    """The stored CRL as-is, without regenerating anything -- what is left to
    serve when the CA key cannot be used right now (FR-5)."""
    return db.get(CRLState, _STATE_ID)


def current_crl(db: Session, secrets: SecretStore, now: datetime | None = None) -> CRLState:
    """The CRL to serve, regenerating it if there is none yet or the stored
    one is within :data:`CRL_MAX_AGE` of its nextUpdate (FR-5).

    The margin is what keeps the cache header honest: a client that fetches
    just before the cutoff caches the answer for an hour, and that hour has
    to fit inside the CRL's remaining validity.

    This lazy refresh is deliberately the only scheduler cabin has: an
    instance nobody asks for a CRL from does not need a fresh one.

    Raises CANotConfiguredError if no CA exists.
    """
    moment = now or datetime.now(UTC)
    state = stored_crl(db)
    if state is None or moment + CRL_MAX_AGE >= state.next_update:
        return regenerate_crl(db, secrets, moment)
    return state


def revoke_certificate(
    db: Session,
    secrets: SecretStore,
    cert_id: int,
    reason: RevocationReason = RevocationReason.unspecified,
    now: datetime | None = None,
) -> Certificate:
    """Mark a stored certificate revoked and republish the CRL (FR-4).

    Idempotent: revoking an already-revoked certificate returns the existing
    row untouched and is NOT an error -- the revocation date a relying party
    was told about must not move, and a caller retrying after a timeout
    should get success, not a 409.

    Raises RevocationError for an unknown certificate, CANotConfiguredError
    if no CA exists.
    """
    row = db.get(Certificate, cert_id)
    if row is None:
        raise RevocationError(f"no certificate with id {cert_id}")
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
        regenerate_crl(db, secrets, moment)
    except Exception:
        db.rollback()
        raise
    return row
