"""Issued leaf certificates: DB storage on top of the pure issuance logic
in :mod:`cabin.ca.leaf`, the CA's signing credentials from
:mod:`cabin.ca.service`, and the secrets layer's AES-GCM sealing
(spec 0005 FR-5).
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.ca import leaf
from cabin.ca.leaf import DEFAULT_DAYS, Profile
from cabin.ca.service import signing_credentials
from cabin.secrets import SecretStore
from cabin.store import Base


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

    @property
    def sans(self) -> list[str]:
        """The stored SAN strings ("DNS:nas.lan", ...), for UI rendering."""
        parsed: list[str] = json.loads(self.sans_json)
        return parsed


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
) -> Certificate:
    """Issue a leaf with a server-generated key and store it, sealing the
    key before it touches the DB (FR-5).

    Raises CANotConfiguredError if no CA exists, IssueError for invalid
    input.
    """
    issuer_cert, issuer_key = signing_credentials(db, secrets)
    cert, key = leaf.issue_certificate(
        issuer_cert, issuer_key, profile, subject_cn, sans, days=days, key_type=key_type
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
