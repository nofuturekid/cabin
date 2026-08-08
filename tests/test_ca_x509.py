"""Tests for cabin.ca.x509: pure X.509 crypto (spec 0004 FR-1/FR-2).

No FastAPI/DB fixtures here -- these exercise real certificates built with
pyca/cryptography directly, never mocks. The one exception is
``test_no_aia_on_root_and_intermediate_certificates``, which needs
``create_intermediate_under`` (spec 0017 FR-3, DB-backed) to cover all three
certificate kinds the spec's Test list names; it gets its own local
``db``/``secrets`` fixtures rather than pulling the whole file into
``cabin.web``/``TestClient`` territory.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from cabin.ca.service import create_hierarchy, create_intermediate_under
from cabin.ca.x509 import (
    CAImportError,
    create_intermediate,
    create_root,
    generate_key,
    load_import,
    renew_certificate,
)
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations

type _SigningKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: _SigningKey, *, password: bytes | None = None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def _self_signed(
    key: _SigningKey,
    cn: str,
    *,
    ca: bool = True,
    path_length: int | None = 0,
    key_cert_sign: bool = True,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> x509.Certificate:
    """A hand-built self-signed cert for the import-rejection tests -- full
    control over exactly which extension/validity is "broken"."""
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=5))
        .not_valid_after(not_after or now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not key_cert_sign,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm=algorithm)


# --- FR-1: generate_key -------------------------------------------------------


@pytest.mark.parametrize("key_type", ["ecdsa-p256", "ecdsa-p384", "rsa-4096", "ed25519"])
def test_generate_key_types(key_type: str) -> None:
    key = generate_key(key_type)
    if key_type == "ecdsa-p256":
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"
    elif key_type == "ecdsa-p384":
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp384r1"
    elif key_type == "rsa-4096":
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096
    else:
        assert isinstance(key, ed25519.Ed25519PrivateKey)


def test_generate_key_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="key type"):
        generate_key("dsa-1024")


# --- AC-1: create_root ---------------------------------------------------------


@pytest.mark.parametrize(
    ("key_type", "expected_oid"),
    [
        ("ecdsa-p256", x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256),
        ("ecdsa-p384", x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384),
        ("rsa-4096", x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256),
        ("ed25519", x509.oid.SignatureAlgorithmOID.ED25519),
    ],
)
def test_create_root_extensions(key_type: str, expected_oid: x509.ObjectIdentifier) -> None:
    cert, _key = create_root("cabin Root CA", key_type, years=20)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 1

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True

    cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)  # present

    assert cert.subject == cert.issuer  # self-signed
    cert.verify_directly_issued_by(cert)  # no exception -> signature verifies

    # the signature hash must match the signing key: SHA-384 for P-384,
    # SHA-256 for P-256/RSA, none (pure EdDSA) for Ed25519 -- never a
    # one-size-fits-all assumption baked into the signing helper.
    assert cert.signature_algorithm_oid == expected_oid

    now = datetime.now(UTC)
    assert now - timedelta(minutes=6) <= cert.not_valid_before_utc <= now - timedelta(minutes=4)
    assert cert.not_valid_after_utc > now + timedelta(days=365 * 19)


# --- AC-1: create_intermediate --------------------------------------------------


def test_create_intermediate_chain_verifies() -> None:
    root_cert, root_key = create_root("cabin Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "cabin Intermediate CA", "ecdsa-p256", years=10
    )

    bc = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0

    ku = intermediate_cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True

    aki = intermediate_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert aki.value.key_identifier == root_ski.value.key_identifier

    intermediate_cert.verify_directly_issued_by(root_cert)  # no exception -> signature verifies
    assert intermediate_key.public_key() != root_key.public_key()


def test_create_intermediate_not_valid_after_clamped_to_root() -> None:
    """An intermediate must never outlive its root: a short-lived root
    (1 year) plus a long-requested intermediate (10 years) must still come
    out no later than the root's own expiry."""
    root_cert, root_key = create_root("Short Root CA", "ecdsa-p256", years=1)
    intermediate_cert, _intermediate_key = create_intermediate(
        root_cert, root_key, "Long Intermediate CA", "ecdsa-p256", years=10
    )
    assert intermediate_cert.not_valid_after_utc == root_cert.not_valid_after_utc


# --- AC-6: ed25519 guard against sign-algorithm assumptions ---------------------


def test_ed25519_hierarchy() -> None:
    root_cert, root_key = create_root("cabin Root CA", "ed25519")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "cabin Intermediate CA", "ed25519"
    )
    assert isinstance(root_key, ed25519.Ed25519PrivateKey)
    assert isinstance(intermediate_key, ed25519.Ed25519PrivateKey)
    root_cert.verify_directly_issued_by(root_cert)  # no exception -> signature verifies
    intermediate_cert.verify_directly_issued_by(root_cert)


# --- FR-2/AC-3: load_import success ---------------------------------------------


def test_import_success_with_encrypted_key() -> None:
    root_cert, root_key = create_root("Test Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Test Intermediate CA", "ecdsa-p256"
    )
    encrypted_key_pem = _pem_key(intermediate_key, password=b"correct-passphrase")

    cert, key, parent = load_import(
        _pem_cert(intermediate_cert),
        encrypted_key_pem,
        "correct-passphrase",
        _pem_cert(root_cert),
    )

    assert cert.serial_number == intermediate_cert.serial_number
    assert parent is not None
    assert parent.serial_number == root_cert.serial_number
    encoding, fmt = (
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert key.public_key().public_bytes(encoding, fmt) == cert.public_key().public_bytes(
        encoding, fmt
    )


# --- FR-2/AC-3: the five rejection cases, each with a distinct message ----------


def test_import_rejects_mismatched_key() -> None:
    root_cert, root_key = create_root("Test Root CA", "ecdsa-p256")
    intermediate_cert, _real_key = create_intermediate(
        root_cert, root_key, "Test Intermediate CA", "ecdsa-p256"
    )
    wrong_key = generate_key("ecdsa-p256")

    with pytest.raises(CAImportError, match="match"):
        load_import(
            _pem_cert(intermediate_cert),
            _pem_key(wrong_key),
            None,
            _pem_cert(root_cert),
        )


def test_import_rejects_non_ca_cert() -> None:
    key = generate_key("ecdsa-p256")
    cert = _self_signed(key, "not-a-ca", ca=False)

    with pytest.raises(CAImportError, match=r"BasicConstraints|not a CA"):
        load_import(_pem_cert(cert), _pem_key(key), None, None)


def test_import_rejects_missing_keycertsign() -> None:
    key = generate_key("ecdsa-p256")
    cert = _self_signed(key, "no-keycertsign", ca=True, key_cert_sign=False)

    with pytest.raises(CAImportError, match=r"keyCertSign|KeyUsage"):
        load_import(_pem_cert(cert), _pem_key(key), None, None)


def test_import_rejects_expired() -> None:
    key = generate_key("ecdsa-p256")
    now = datetime.now(UTC)
    cert = _self_signed(
        key,
        "expired-ca",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=1),
    )

    with pytest.raises(CAImportError, match="expired"):
        load_import(_pem_cert(cert), _pem_key(key), None, None)


def test_import_rejects_not_yet_valid() -> None:
    key = generate_key("ecdsa-p256")
    now = datetime.now(UTC)
    cert = _self_signed(
        key,
        "not-yet-valid-ca",
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    with pytest.raises(CAImportError, match="not yet valid"):
        load_import(_pem_cert(cert), _pem_key(key), None, None)


def test_import_rejects_bad_chain() -> None:
    root_cert, root_key = create_root("Test Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Test Intermediate CA", "ecdsa-p256"
    )
    other_root_cert, _other_root_key = create_root("Unrelated Root CA", "ecdsa-p256")

    with pytest.raises(CAImportError, match="chain"):
        load_import(
            _pem_cert(intermediate_cert),
            _pem_key(intermediate_key),
            None,
            _pem_cert(other_root_cert),
        )


def test_import_rejects_self_as_parent() -> None:
    """Pasting the same self-signed cert into both cert_pem and chain_pem
    (operator confusion between "the signing CA" and "its root") must not
    silently succeed just because a self-signed cert trivially verifies
    against itself."""
    root_cert, root_key = create_root("Self Parent Root CA", "ecdsa-p256")

    with pytest.raises(CAImportError, match="itself"):
        load_import(
            _pem_cert(root_cert),
            _pem_key(root_key),
            None,
            _pem_cert(root_cert),
        )


def test_import_rejects_wrong_passphrase() -> None:
    root_cert, root_key = create_root("Test Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Test Intermediate CA", "ecdsa-p256"
    )
    encrypted_key_pem = _pem_key(intermediate_key, password=b"correct-passphrase")

    with pytest.raises(CAImportError, match="decrypt"):
        load_import(
            _pem_cert(intermediate_cert),
            encrypted_key_pem,
            "wrong-passphrase",
            _pem_cert(root_cert),
        )


# --- spec 0017 FR-13/AC-11: path_length is chosen when a root is created --------


def test_root_path_length_configurable() -> None:
    """AC-11: a root created with an explicit path_length round-trips to
    exactly that value in BasicConstraints, replacing the value that used to
    be hard-coded at path_length=1 in create_root."""
    cert, _key = create_root("Depth Root CA", "ecdsa-p256", path_length=2)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 2

    # counter-check: a different explicit value round-trips to that
    # different value -- not a coincidence of 2 happening to be readable.
    other_cert, _other_key = create_root("Depth Root CA 2", "ecdsa-p256", path_length=3)
    other_bc = other_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert other_bc.value.path_length == 3

    # AC-11: the default stays 1 when the parameter is omitted.
    default_cert, _default_key = create_root("Depth Root CA Default", "ecdsa-p256")
    default_bc = default_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert default_bc.value.path_length == 1


# --- spec 0017 FR-5: renew_certificate (pure helper) ----------------------------
#
# Interface Contract: renew_certificate(cert, parent_cert, parent_key,
# years) -> x509.Certificate. FR-5 requires this to be the ONLY place a
# renewal is built, so that no route reaches into a CertificateBuilder --
# without a test here, an implementation that inlines the builder into
# ca/service.py's renew_in_place and never writes this helper at all still
# passes the rest of the suite (Backend only covers renew_in_place at the
# service level).


def _public_key_der(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_renew_certificate_root_keeps_key_and_gets_new_serial_and_validity() -> None:
    """FR-5: for a root, parent_cert/parent_key are the certificate's own.
    Subject, public key, SKI, BasicConstraints and KeyUsage are carried
    over unchanged; only the serial and not_after actually move."""
    cert, key = create_root("Renew Root CA", "ecdsa-p256", years=1, path_length=2)

    renewed = renew_certificate(cert, cert, key, years=20)

    # the part that carries the weight: the SAME key, not a fresh one.
    assert _public_key_der(renewed) == _public_key_der(cert)
    assert renewed.subject == cert.subject

    ski_before = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    ski_after = renewed.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert ski_after.digest == ski_before.digest

    bc_before = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    bc_after = renewed.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc_after.ca == bc_before.ca is True
    assert bc_after.path_length == bc_before.path_length == 2

    ku_before = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    ku_after = renewed.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku_after.key_cert_sign == ku_before.key_cert_sign is True
    assert ku_after.crl_sign == ku_before.crl_sign is True

    # what actually changed.
    assert renewed.serial_number != cert.serial_number
    assert renewed.not_valid_after_utc > cert.not_valid_after_utc

    renewed.verify_directly_issued_by(renewed)  # still self-signed, still verifies


def test_renew_certificate_intermediate_keeps_key_and_still_chains_to_parent() -> None:
    """FR-5 for an intermediate: parent_cert/parent_key are the ROOT's, not
    the intermediate's own -- and the renewed certificate must still verify
    against that same parent, which only holds if the AKI (derived from the
    parent's SKI) and the reused key are both carried over correctly."""
    root_cert, root_key = create_root("Renew Parent Root CA", "ecdsa-p256", years=20)
    intermediate_cert, _intermediate_key = create_intermediate(
        root_cert, root_key, "Renew Intermediate CA", "ecdsa-p256", years=5
    )

    renewed = renew_certificate(intermediate_cert, root_cert, root_key, years=8)

    assert _public_key_der(renewed) == _public_key_der(intermediate_cert)
    assert renewed.subject == intermediate_cert.subject

    bc = renewed.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0  # create_intermediate's own path_length, carried over

    ku = renewed.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True
    assert ku.crl_sign is True

    assert renewed.serial_number != intermediate_cert.serial_number
    assert renewed.not_valid_after_utc > intermediate_cert.not_valid_after_utc

    renewed.verify_directly_issued_by(root_cert)


# --- spec 0017 FR-11: AIA is leaf-only ------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    session = create_session_factory(db_url)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def secrets(tmp_path: Path) -> SecretStore:
    return SecretStore.open(tmp_path, None)


def _no_aia(cert: x509.Certificate) -> None:
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)


def test_no_aia_on_root_and_intermediate_certificates(db: Session, secrets: SecretStore) -> None:
    """Spec's Test list: FR-11 gives AIA to leaves only, and the Out of
    Scope section repeats it -- but nothing asserted the absence before
    this. Checked on all three ways cabin produces a CA certificate: a
    generated root, its generated intermediate, and an intermediate from
    the rotation path (``create_intermediate_under``, spec 0017 FR-3)."""
    root_cert, _root_key = create_root("No AIA Root CA", "ecdsa-p256")
    _no_aia(root_cert)

    intermediate_cert, _intermediate_key = create_intermediate(
        root_cert, _root_key, "No AIA Intermediate CA", "ecdsa-p256"
    )
    _no_aia(intermediate_cert)

    hierarchy = create_hierarchy(db, secrets, "No AIA Hierarchy")
    rotated = create_intermediate_under(
        db, secrets, hierarchy.root.id, "No AIA Rotated Intermediate"
    )
    rotated_cert = x509.load_pem_x509_certificate(rotated.cert_pem.encode("ascii"))
    _no_aia(rotated_cert)
