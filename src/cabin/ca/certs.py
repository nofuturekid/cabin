"""Issued leaf certificates: DB storage on top of the pure issuance logic
in :mod:`cabin.ca.leaf`, the CA's signing credentials from
:mod:`cabin.ca.service`, and the secrets layer's AES-GCM sealing
(spec 0005 FR-5), plus the inventory query behind /certs (spec 0006
FR-2/FR-3).
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.ca import leaf
from cabin.ca.leaf import DEFAULT_DAYS, Profile
from cabin.ca.service import signing_credentials
from cabin.secrets import SecretsError, SecretStore
from cabin.store import Base

#: How long before not_after a certificate counts as "expiring" (FR-2).
EXPIRING_WINDOW = timedelta(days=30)
#: Inventory page size (FR-1).
PER_PAGE = 50
#: Cap on the free-text filter, so a pathological query can't be sent to the
#: database at all (FR-2).
MAX_QUERY_LENGTH = 200
#: Cap on the requested page. Past this there is nothing to fetch anyway, and
#: it keeps the computed OFFSET inside the integer range SQLite and
#: PostgreSQL can bind -- a hand-edited ?page= must be an empty page, never
#: an error (AC-2).
MAX_PAGE = 1_000_000


class Certificate(Base):
    """One issued leaf. ``key_sealed`` is NULL whenever the private key
    never existed here -- i.e. for every CSR-signed certificate."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    serial_hex: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    subject_cn: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    sans_json: Mapped[str] = mapped_column(sa.Text, nullable=False)
    profile: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    not_before: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    not_after: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    cert_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_sealed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    #: NULL until revoked; both columns are written together by
    #: :func:`cabin.ca.crl.revoke_certificate` (spec 0007 FR-4).
    revoked_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)

    @property
    def sans(self) -> list[str]:
        """The stored SAN strings ("DNS:nas.lan", ...), for UI rendering."""
        parsed: list[str] = json.loads(self.sans_json)
        return parsed

    @property
    def not_after_dt(self) -> datetime:
        """``not_after`` as an aware datetime; the column keeps the ISO-8601
        UTC form written by :func:`_store`."""
        return datetime.fromisoformat(self.not_after)

    @property
    def revoked_at_dt(self) -> datetime | None:
        """``revoked_at`` as an aware datetime, or None if not revoked."""
        return datetime.fromisoformat(self.revoked_at) if self.revoked_at else None


def _store(
    db: Session,
    cert: x509.Certificate,
    profile: Profile,
    sans: Sequence[str],
    key_sealed: str | None,
) -> Certificate:
    row = Certificate(
        serial_hex=format(cert.serial_number, "x"),
        subject_cn=cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        sans_json=json.dumps(list(sans)),
        profile=str(profile),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_sealed=key_sealed,
    )
    db.add(row)
    db.commit()
    return row


def _sealed_key(secrets: SecretStore, key: CertificateIssuerPrivateKeyTypes) -> str:
    return secrets.seal(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _cert_sans(cert: x509.Certificate) -> list[str]:
    """Read the SANs back off the finished certificate rather than trusting
    the request, so the stored row always describes what was actually
    issued."""
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return leaf.san_strings(san)


def issue_and_store(
    db: Session,
    secrets: SecretStore,
    *,
    profile: Profile,
    subject_cn: str,
    sans: Sequence[str],
    days: int = DEFAULT_DAYS,
    key_type: str = "ecdsa-p256",
    crl_url: str | None = None,
) -> Certificate:
    """Issue a leaf with a server-generated key and store it, sealing the
    key before it touches the DB (FR-5).

    ``crl_url`` (spec 0007 FR-6) is passed in rather than read from the
    settings table here, so this module keeps knowing nothing about where
    cabin itself is published.

    Raises CANotConfiguredError if no CA exists, IssueError for invalid
    input.
    """
    issuer_cert, issuer_key = signing_credentials(db, secrets)
    cert, key = leaf.issue_certificate(
        issuer_cert,
        issuer_key,
        profile,
        subject_cn,
        sans,
        days=days,
        key_type=key_type,
        crl_url=crl_url,
    )
    return _store(db, cert, profile, _cert_sans(cert), _sealed_key(secrets, key))


def sign_csr_and_store(
    db: Session,
    secrets: SecretStore,
    *,
    csr_pem: str,
    profile: Profile,
    days: int = DEFAULT_DAYS,
    sans_override: Sequence[str] | None = None,
    crl_url: str | None = None,
) -> Certificate:
    """Sign a pasted CSR and store the result. There is no key to seal --
    cabin never sees the requester's private key (FR-5)."""
    issuer_cert, issuer_key = signing_credentials(db, secrets)
    cert = leaf.sign_csr(
        issuer_cert,
        issuer_key,
        csr_pem.encode("utf-8"),
        profile,
        days=days,
        sans_override=sans_override,
        crl_url=crl_url,
    )
    return _store(db, cert, profile, _cert_sans(cert), None)


def get_certificate(db: Session, cert_id: int) -> Certificate | None:
    return db.get(Certificate, cert_id)


def key_pem(secrets: SecretStore, row: Certificate) -> str | None:
    """The stored private key in PEM form, unsealed on demand for display
    (FR-6), or None for a CSR-signed certificate."""
    if row.key_sealed is None:
        return None
    return secrets.unseal(row.key_sealed).decode("ascii")


#: One wording for "this key cannot be unsealed", wherever it surfaces -- the
#: detail page, a download, or the API.
KEY_UNAVAILABLE = (
    "the stored private key could not be decrypted: it was sealed with a different "
    "master key, or the stored value is damaged"
)


def key_material(secrets: SecretStore, row: Certificate) -> tuple[str | None, str | None]:
    """``(key_pem, error)`` for every caller that wants to *show* a key
    rather than use it: ``(None, None)`` when this certificate never had one,
    ``(None, message)`` when it has one that can no longer be unsealed.

    Shared so the UI page, the downloads and the API cannot drift on what a
    broken master key looks like -- and so none of them turns it into a 500.
    """
    if row.key_sealed is None:
        return None, None
    try:
        return key_pem(secrets, row), None
    except SecretsError:
        return None, KEY_UNAVAILABLE


class CertStatus(StrEnum):
    """Where a stored certificate is in its life (FR-2/FR-3)."""

    valid = "valid"
    expiring = "expiring"
    expired = "expired"
    #: Spec 0007 FR-7: revocation is a state of its own, not an expiry.
    revoked = "revoked"


#: Accepted ``?status=`` values; "all" means "no status filter" (FR-2).
STATUS_FILTERS: tuple[str, ...] = ("all", *CertStatus)


def certificate_status(
    not_after: datetime, now: datetime, revoked_at: datetime | None
) -> CertStatus:
    """Pure status logic (FR-3), taking the expiry instant rather than a row
    so it can be reasoned about (and tested) without a database.

    ``not_after`` is the last instant of validity, so a certificate whose
    not_after is exactly ``now`` is already expired; one ending exactly
    :data:`EXPIRING_WINDOW` from now is already expiring (AC-3).

    Revocation outranks the clock (spec 0007 FR-7): a revoked certificate
    reads "revoked" whether or not it has also expired, because that is the
    answer a relying party gets. ``revoked_at`` is required rather than
    defaulted so that no future caller can forget it and quietly render a
    revoked certificate as valid.
    """
    if revoked_at is not None:
        return CertStatus.revoked
    if not_after <= now:
        return CertStatus.expired
    if not_after <= now + EXPIRING_WINDOW:
        return CertStatus.expiring
    return CertStatus.valid


def _iso(moment: datetime) -> str:
    """A point in time in the exact shape ``not_after`` is stored in.

    Both sides are then fixed-layout UTC ISO-8601 strings, which compare
    lexicographically in the same order as chronologically -- so the status
    filter is one plain string comparison that SQLite (which has no date
    type) and PostgreSQL evaluate identically. Sub-second precision is
    dropped because X.509 validity is second-granular.
    """
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def _filters(q: str, status: str, now: datetime) -> list[sa.ColumnElement[bool]]:
    conditions: list[sa.ColumnElement[bool]] = []
    term = q.strip()[:MAX_QUERY_LENGTH].lower()
    if term:
        # The term is a bound parameter, never interpolated into SQL; its
        # LIKE metacharacters are escaped so searching for "10%" finds a
        # literal "10%" instead of matching every row.
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        conditions.append(
            sa.or_(
                sa.func.lower(Certificate.subject_cn).like(pattern, escape="\\"),
                sa.func.lower(Certificate.sans_json).like(pattern, escape="\\"),
                sa.func.lower(Certificate.serial_hex).like(pattern, escape="\\"),
            )
        )
    if status == CertStatus.revoked:
        conditions.append(Certificate.revoked_at.is_not(None))
        return conditions
    if status in (CertStatus.expired, CertStatus.expiring, CertStatus.valid):
        # The four states partition the inventory, so the time-based filters
        # exclude revoked rows -- otherwise a row selected as "expired" would
        # be rendered with a "revoked" badge (spec 0007 FR-7).
        conditions.append(Certificate.revoked_at.is_(None))
    if status == CertStatus.expired:
        conditions.append(Certificate.not_after <= _iso(now))
    elif status == CertStatus.expiring:
        conditions.append(Certificate.not_after > _iso(now))
        conditions.append(Certificate.not_after <= _iso(now + EXPIRING_WINDOW))
    elif status == CertStatus.valid:
        conditions.append(Certificate.not_after > _iso(now + EXPIRING_WINDOW))
    return conditions


def list_certificates(
    db: Session,
    *,
    q: str = "",
    status: str = "all",
    page: int = 1,
    per_page: int = PER_PAGE,
    now: datetime | None = None,
) -> tuple[list[Certificate], int]:
    """One page of the inventory, newest first, plus the total number of
    matches (FR-3).

    ``q`` is a case-insensitive substring over CN, SANs and serial, capped
    at :data:`MAX_QUERY_LENGTH`; ``status`` is one of :data:`STATUS_FILTERS`
    and anything else is treated as "all". ``now`` fixes the clock the
    status filter is evaluated against -- the caller passes the same instant
    it renders the badges with, so a page can't straddle a tick -- and
    defaults to the current time.

    ``total`` counts the whole filtered set (not the page), so the pager
    knows whether another page exists. ``page`` is clamped to
    1..:data:`MAX_PAGE` here rather than in the route, so that no caller can
    turn a hand-edited page number into a negative or unbindable OFFSET: out
    of range is an empty page, not an error (AC-2).
    """
    conditions = _filters(q, status, now or datetime.now(UTC))
    page = min(max(page, 1), MAX_PAGE)
    total = db.scalar(select(sa.func.count()).select_from(Certificate).where(*conditions)) or 0
    rows = db.scalars(
        select(Certificate)
        .where(*conditions)
        .order_by(Certificate.created_at.desc(), Certificate.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()
    return list(rows), total
