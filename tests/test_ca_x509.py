"""Tests for cabin.ca.x509: pure X.509 crypto (spec 0004 FR-1/FR-2).

No FastAPI/DB fixtures here -- these exercise real certificates built with
pyca/cryptography directly, never mocks.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from cabin.ca.x509 import (
    CAImportError,
    create_intermediate,
    create_root,
    generate_key,
    load_import,
)

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
