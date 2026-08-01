"""Tests for cabin.ca.service: DB storage of the CA hierarchy with sealed
private keys, on top of real certificates from cabin.ca.x509 (spec 0004
FR-3/FR-4)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.ca.service import (
    CACertificate,
    CAExistsError,
    CANotConfiguredError,
    create_hierarchy,
    get_ca,
    import_hierarchy,
    signing_credentials,
)
from cabin.ca.x509 import create_intermediate, create_root
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def secrets(tmp_path: Path) -> SecretStore:
    return SecretStore.open(tmp_path, None)


def _pem_cert_bytes(cert: object) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)  # type: ignore[attr-defined]


def _pem_key_str(key: object, *, password: bytes | None = None) -> str:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


# --- AC-1/AC-2: wizard create -> two sealed rows -----------------------------


def test_keys_sealed_in_db(db: Session, secrets: SecretStore) -> None:
    assert get_ca(db) is None

    create_hierarchy(db, secrets, "cabin")

    assert get_ca(db) is not None
    rows = {row.kind: row for row in db.scalars(select(CACertificate))}
    assert set(rows) == {"root", "intermediate"}
    for row in rows.values():
        assert row.key_sealed is not None
        # sealed tokens are base64url, not PEM -- never plaintext key material
        assert "BEGIN" not in row.key_sealed
        assert "PRIVATE KEY" not in row.key_sealed


# --- AC-2: unseal back to a working private key ------------------------------


def test_signing_credentials_roundtrip(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin")

    cert, key = signing_credentials(db, secrets)

    assert isinstance(key, ec.EllipticCurvePrivateKey)
    message = b"roundtrip-check"
    signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))  # no exception


# --- AC-4: second create/import attempt is rejected, DB unchanged -----------


def test_second_hierarchy_rejected(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin")

    with pytest.raises(CAExistsError):
        create_hierarchy(db, secrets, "cabin-two")

    root_cert, root_key = create_root("Other Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Other Intermediate CA", "ecdsa-p256"
    )
    with pytest.raises(CAExistsError):
        import_hierarchy(
            db,
            secrets,
            _pem_cert_bytes(intermediate_cert).decode("ascii"),
            intermediate_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            None,
            _pem_cert_bytes(root_cert).decode("ascii"),
        )

    rows = list(db.scalars(select(CACertificate)))
    assert len(rows) == 2


# --- FR-3: the UniqueConstraint on kind is a real DB-level backstop --------


def test_second_hierarchy_rejected_at_db_level_when_app_check_is_bypassed(
    db: Session, secrets: SecretStore
) -> None:
    """get_ca() only blocks a second hierarchy once BOTH rows exist. Seed a
    lone root row directly (as a partial/orphaned row from some other path
    might leave behind) so the application-level check sees "no complete
    hierarchy" and proceeds -- the UniqueConstraint on kind must still stop
    the conflicting INSERT, converted to CAExistsError."""
    db.add(CACertificate(kind="root", cert_pem="placeholder", key_sealed=None))
    db.commit()

    assert get_ca(db) is None  # app-level check: no COMPLETE hierarchy yet

    with pytest.raises(CAExistsError):
        create_hierarchy(db, secrets, "cabin")

    rows = list(db.scalars(select(CACertificate)))
    assert len(rows) == 1
    assert rows[0].cert_pem == "placeholder"  # failed insert left nothing behind


# --- AC-5: import stores the PARSED parent, not the raw submitted chain_pem -


def test_import_stores_only_direct_parent_from_multi_cert_chain(
    db: Session, secrets: SecretStore
) -> None:
    """A chain_pem bundle containing more than one certificate must not leak
    the extra cert(s) into the stored root row -- only the direct parent
    (the first certificate in the bundle, which is what load_import's chain
    check verifies against) is kept."""
    root_cert, root_key = create_root("Chain Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Chain Intermediate CA", "ecdsa-p256"
    )
    unrelated_cert, _unrelated_key = create_root("Unrelated CA", "ecdsa-p256")

    chain_pem = _pem_cert_bytes(root_cert).decode("ascii") + _pem_cert_bytes(unrelated_cert).decode(
        "ascii"
    )

    hierarchy = import_hierarchy(
        db,
        secrets,
        _pem_cert_bytes(intermediate_cert).decode("ascii"),
        _pem_key_str(intermediate_key),
        None,
        chain_pem,
    )

    stored_certs = x509.load_pem_x509_certificates(hierarchy.root.cert_pem.encode("ascii"))
    assert len(stored_certs) == 1
    assert stored_certs[0].subject.rfc4514_string() == "CN=Chain Root CA"


# --- AC-6: ed25519 hierarchy round-trips through the seal/unseal layer too --


def test_signing_credentials_roundtrip_ed25519(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin", key_type="ed25519")

    cert, key = signing_credentials(db, secrets)

    assert isinstance(key, ed25519.Ed25519PrivateKey)
    message = b"ed25519-roundtrip-check"
    signature = key.sign(message)
    cert.public_key().verify(signature, message)  # no exception -> success


# --- FR-4: signing_credentials with no CA configured -------------------------


def test_signing_credentials_raises_when_no_ca(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(CANotConfiguredError):
        signing_credentials(db, secrets)
