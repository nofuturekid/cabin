"""Tests for cabin.ca.certs: storing issued/signed leaf certificates with
sealed server-generated keys (spec 0005 FR-5, AC-5)."""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from cabin.ca.certs import (
    get_certificate,
    issue_and_store,
    key_pem,
    sign_csr_and_store,
)
from cabin.ca.leaf import IssueError, Profile
from cabin.ca.service import CANotConfiguredError, create_hierarchy, signing_credentials
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


def _spki(key: object) -> bytes:
    return key.public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _csr_pem(cn: str, sans: list[x509.GeneralName]) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_store_seals_key_server_flow(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "Store")

    row = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="nas.lan",
        sans=["DNS:nas.lan", "IP:10.0.0.5"],
        days=90,
        key_type="ecdsa-p256",
    )

    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    assert row.serial_hex == format(cert.serial_number, "x")
    assert row.subject_cn == "nas.lan"
    assert row.profile == "server"
    assert json.loads(row.sans_json) == ["DNS:nas.lan", "IP:10.0.0.5"]
    assert row.not_before == cert.not_valid_before_utc.isoformat()
    assert row.not_after == cert.not_valid_after_utc.isoformat()

    # AC-5: the key is sealed, never plaintext, and unseals to the key that
    # is actually in the certificate.
    assert row.key_sealed is not None
    assert "PRIVATE KEY" not in row.key_sealed
    unsealed = serialization.load_pem_private_key(secrets.unseal(row.key_sealed), password=None)
    assert _spki(unsealed.public_key()) == _spki(cert.public_key())
    assert key_pem(secrets, row) is not None
    assert "BEGIN PRIVATE KEY" in str(key_pem(secrets, row))

    # persisted, not just returned; SANs round-trip through the JSON column
    fetched = get_certificate(db, row.id)
    assert fetched is not None
    assert fetched.cert_pem == row.cert_pem
    assert fetched.sans == ["DNS:nas.lan", "IP:10.0.0.5"]

    intermediate_cert, _key = signing_credentials(db, secrets)
    cert.verify_directly_issued_by(intermediate_cert)


def test_store_no_key_csr_flow(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "Store")
    csr_pem = _csr_pem("app.lan", [x509.DNSName("app.lan"), x509.DNSName("www.app.lan")])

    row = sign_csr_and_store(db, secrets, csr_pem=csr_pem, profile=Profile.client, days=30)

    # AC-5: cabin never saw this private key, so there is nothing to store.
    assert row.key_sealed is None
    assert key_pem(secrets, row) is None
    assert row.profile == "client"
    assert row.subject_cn == "app.lan"
    assert json.loads(row.sans_json) == ["DNS:app.lan", "DNS:www.app.lan"]

    fetched = get_certificate(db, row.id)
    assert fetched is not None
    cert = x509.load_pem_x509_certificate(fetched.cert_pem.encode("ascii"))
    assert fetched.serial_hex == format(cert.serial_number, "x")


def test_store_requires_a_ca(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(CANotConfiguredError):
        issue_and_store(
            db,
            secrets,
            profile=Profile.server,
            subject_cn="nas.lan",
            sans=["DNS:nas.lan"],
        )


def test_store_rejects_invalid_input_without_writing_a_row(
    db: Session, secrets: SecretStore
) -> None:
    create_hierarchy(db, secrets, "Store")
    with pytest.raises(IssueError):
        issue_and_store(
            db,
            secrets,
            profile=Profile.server,
            subject_cn="Some Printer",
            sans=[],
            days=30,
        )
    assert get_certificate(db, 1) is None


def test_get_certificate_unknown_id(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "Store")
    assert get_certificate(db, 4242) is None


def test_store_sans_match_the_issued_certificate(db: Session, secrets: SecretStore) -> None:
    """The same name given twice must not put a duplicate SAN in the
    certificate while sans_json (which de-duplicates) claims otherwise."""
    create_hierarchy(db, secrets, "Store")

    row = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="nas.lan",
        sans=["nas.lan", "dns:nas.lan"],
        days=30,
    )

    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["nas.lan"]
    assert json.loads(row.sans_json) == ["DNS:nas.lan"]
    assert len(list(san)) == len(row.sans)
