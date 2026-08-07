"""CA hierarchy: DB storage of certificates and sealed private keys,
orchestrated on top of the pure crypto in :mod:`cabin.ca.x509` and the
secrets layer's AES-GCM sealing (spec 0004 FR-3/FR-4).
"""

from dataclasses import dataclass
from datetime import UTC, datetime

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.ca import x509 as ca_x509
from cabin.secrets import SecretStore
from cabin.store import Base


class CAExistsError(Exception):
    """A CA hierarchy already exists; no rotation in v1 (FR-3)."""


class CANotConfiguredError(Exception):
    """No CA hierarchy has been created or imported yet."""


class CACertificate(Base):
    __tablename__ = "ca_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    #: Operator-facing label (spec 0017 FR-1). Not unique: a rotation
    #: deliberately produces a second row with the same name.
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Self-referential; NULL for a self-signed root (spec 0017 FR-1).
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), nullable=True
    )
    #: "active" or "retired" (spec 0017 FR-1/FR-4).
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="active", server_default="active"
    )
    cert_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_sealed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )


@dataclass(frozen=True)
class CAHierarchy:
    root: CACertificate
    intermediate: CACertificate


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def get_ca(db: Session) -> CAHierarchy | None:
    """The active hierarchy, or None if no CA has been created/imported yet."""
    root = db.scalar(
        select(CACertificate).where(CACertificate.kind == "root").order_by(CACertificate.id)
    )
    intermediate = db.scalar(
        select(CACertificate).where(CACertificate.kind == "intermediate").order_by(CACertificate.id)
    )
    if root is None or intermediate is None:
        return None
    return CAHierarchy(root=root, intermediate=intermediate)


def create_hierarchy(
    db: Session,
    secrets: SecretStore,
    name: str,
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    intermediate_years: int = 10,
) -> CAHierarchy:
    """Generate a fresh root+intermediate hierarchy and store both rows,
    sealing both private keys before insert (never plaintext in the DB).

    The root key is unsealed only in-memory here, to sign the intermediate,
    then sealed and stored (kept for future CRL-of-intermediates/rotation,
    not used elsewhere -- FR-4). Raises CAExistsError if a hierarchy
    already exists (no rotation in v1).
    """
    if get_ca(db) is not None:
        raise CAExistsError("a CA hierarchy already exists")

    root_cert, root_key = ca_x509.create_root(f"{name} Root CA", key_type, years=root_years)
    intermediate_cert, intermediate_key = ca_x509.create_intermediate(
        root_cert,
        root_key,
        f"{name} Intermediate CA",
        key_type,
        years=intermediate_years,
    )

    root_row = CACertificate(
        kind="root",
        cert_pem=_cert_pem(root_cert),
        key_sealed=secrets.seal(_key_pem(root_key)),
    )
    intermediate_row = CACertificate(
        kind="intermediate",
        cert_pem=_cert_pem(intermediate_cert),
        key_sealed=secrets.seal(_key_pem(intermediate_key)),
    )
    db.add(root_row)
    db.add(intermediate_row)
    try:
        db.commit()
    except IntegrityError as exc:
        # Backstop for the UniqueConstraint on kind (mirrors ui.py's setup
        # race handling): the check above only sees a COMPLETE hierarchy,
        # so a lone/partial row from some other path could otherwise let a
        # conflicting INSERT reach the DB.
        db.rollback()
        raise CAExistsError("a CA hierarchy already exists") from exc
    return CAHierarchy(root=root_row, intermediate=intermediate_row)


def import_hierarchy(
    db: Session,
    secrets: SecretStore,
    cert_pem: str,
    key_pem: str,
    key_passphrase: str | None,
    chain_pem: str,
) -> CAHierarchy:
    """Validate (see :func:`cabin.ca.x509.load_import`) and store an
    imported signing CA plus its parent/root certificate.

    The root's private key is never supplied for an import, so its
    key_sealed stays NULL. Raises CAExistsError if a hierarchy already
    exists, or CAImportError if validation fails (FR-2).
    """
    if get_ca(db) is not None:
        raise CAExistsError("a CA hierarchy already exists")

    cert, key, parent = ca_x509.load_import(
        cert_pem.encode("utf-8"),
        key_pem.encode("utf-8"),
        key_passphrase,
        chain_pem.encode("utf-8"),
    )
    # chain_pem is required here (unlike the pure load_import, where it's
    # optional), so load_import always parses and returns a parent.
    assert parent is not None
    # Store the PARSED parent certificate, not the raw submitted chain_pem:
    # an operator may paste a multi-cert bundle or an openssl "subject=/
    # issuer=" text preamble, and /ca/root.pem must serve exactly the one
    # clean certificate that the chain check above validated against (the
    # first certificate found in chain_pem -- a single-level parent check
    # is enough for v1, see FR-2).
    root_row = CACertificate(kind="root", cert_pem=_cert_pem(parent), key_sealed=None)
    intermediate_row = CACertificate(
        kind="intermediate",
        cert_pem=_cert_pem(cert),
        key_sealed=secrets.seal(_key_pem(key)),
    )
    db.add(root_row)
    db.add(intermediate_row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise CAExistsError("a CA hierarchy already exists") from exc
    return CAHierarchy(root=root_row, intermediate=intermediate_row)


def signing_credentials(
    db: Session, secrets: SecretStore
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """The active intermediate's certificate and unsealed private key, for
    issuance in later specs. Raises CANotConfiguredError if no CA exists.
    """
    hierarchy = get_ca(db)
    if hierarchy is None:
        raise CANotConfiguredError("no CA hierarchy has been created or imported yet")
    if hierarchy.intermediate.key_sealed is None:
        raise CANotConfiguredError("the intermediate's private key is not available")
    key_pem = secrets.unseal(hierarchy.intermediate.key_sealed)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ca_x509.SIGNING_KEY_TYPES):
        raise CANotConfiguredError("stored intermediate key is not a supported signing key type")
    cert = x509.load_pem_x509_certificate(hierarchy.intermediate.cert_pem.encode("utf-8"))
    return cert, key
