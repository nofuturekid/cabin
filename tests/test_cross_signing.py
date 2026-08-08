"""Tests for spec 0021 (cross-signing): creation, import, renewal,
retirement, and the crypto layer underneath all four --
``cabin.ca.x509.cross_sign``/``load_cross``/``cross_path_length_error`` and
``cabin.ca.service.cross_sign_root``/``import_cross``, plus the schema and
audit/API surface those write to.

What gets *served* -- ``chains_for``, the doors, ACME's alternate link, the
``/ca`` page -- lives in ``tests/test_cross_chains.py``. This file is
everything that can be measured without asking "what chain comes back":
does the certificate cabin signs contain the right bytes, does the import
refuse the right forgeries, does renewal keep the key the same, does retire
cascade the way FR-10 says.

None of the names this spec adds exist on disk yet -- this branch is red by
design. Following ``tests/test_name_constraints.py``'s own technique for the
same reason: ``cabin.ca.x509``/``cabin.ca.service`` are imported as modules
(``ca_x509``/``ca_service``), and every new name (``cross_sign``,
``load_cross``, ``cross_path_length_error``, ``cross_sign_root``,
``import_cross``, ``CrossSignError``, ``Chain``, ``ChainSet``,
``chains_for``) is reached through the module rather than imported by name,
so a missing symbol is an ``AttributeError`` inside the one test that
touches it, not a collection error that swallows every other test's more
specific answer. Names that already exist today (``create_root``,
``create_intermediate``, ``retire``, ``retire_targets``, ``renew_in_place``,
``CACertificate``, ...) are imported directly.

``openssl verify -CAfile`` does not check the self-signature of what it is
handed -- everything about what a cross certificate *contains* (AC-1, AC-12,
AC-14) and about *who signed it* (AC-2, direct half) is asserted with
``cryptography`` against the parsed certificate. Where a chain check is the
point, only the trust anchor goes in ``-CAfile`` and everything else in
``-untrusted``, and one test (``test_openssl_passes_a_forged_cross_...``)
exists solely to prove the blind spot exists rather than assume it.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import cabin.store as store_pkg
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import Certificate
from cabin.ca.leaf import NameConstraintSpec, name_constraints_extension
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    UnknownIssuerError,
    active_issuers,
    create_hierarchy,
    get_ca,
    renew_in_place,
    retire,
    retire_targets,
)
from cabin.ca.x509 import CAImportError, create_root
from cabin.issuer_grants import SYSTEM_PRINCIPAL, TokenIssuer, UserIssuer
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations

_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")

# --- fixtures ----------------------------------------------------------------


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


# --- helpers -------------------------------------------------------------------


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _ski(cert: x509.Certificate) -> bytes:
    return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.key_identifier


def _spki_der(cert_or_key: x509.Certificate | CertificatePublicKeyTypes) -> bytes:
    public_key = (
        cert_or_key.public_key() if isinstance(cert_or_key, x509.Certificate) else cert_or_key
    )
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _root_row(
    db: Session, secrets: SecretStore, name: str, *, path_length: int = 1
) -> CACertificate:
    hierarchy = create_hierarchy(db, secrets, name, path_length=path_length)
    return hierarchy.root


def _two_roots(db: Session, secrets: SecretStore) -> tuple[CACertificate, CACertificate]:
    """A (signing root, ``path_length=2`` so it can cross-sign) and B (the
    subject root, cabin's ordinary default ``path_length=1``) -- the fixture
    every AC in this spec is built on (spec preamble)."""
    signer = _root_row(db, secrets, "alpha", path_length=2)
    subject = _root_row(db, secrets, "beta", path_length=1)
    return signer, subject


def _forged_ca_cert(
    *,
    subject: x509.Name,
    public_key: CertificatePublicKeyTypes,
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    ski: bytes | None = None,
    ca: bool = True,
    path_length: int | None = 0,
    key_cert_sign: bool = True,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> x509.Certificate:
    """A hand-built CA certificate for the negative import cases: whatever
    ``load_cross``'s checks are supposed to catch, built directly with
    ``cryptography`` rather than through ``cross_sign`` -- the function
    under test elsewhere -- so a bug in ``cross_sign`` cannot accidentally
    make one of these refusals untestable."""
    now = datetime.now(UTC)
    key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=5))
        .not_valid_after(not_after or now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier(ski if ski is not None else _ski_bytes(public_key)),
            critical=False,
        )
        .add_extension(ca_x509.authority_key_identifier(issuer_cert, issuer_key), critical=False)
    )
    return builder.sign(issuer_key, algorithm=ca_x509.signing_algorithm(issuer_key))


def _ski_bytes(public_key: CertificatePublicKeyTypes) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(public_key).digest


def _openssl_verify(
    tmp_path: Path, label: str, cafile_pem: str, untrusted_pem: str, leaf_pem: str
) -> subprocess.CompletedProcess[str]:
    d = tmp_path / "openssl" / label
    d.mkdir(parents=True)
    ca_path, untrusted_path, leaf_path = d / "ca.pem", d / "untrusted.pem", d / "leaf.pem"
    ca_path.write_text(cafile_pem)
    untrusted_path.write_text(untrusted_pem)
    leaf_path.write_text(leaf_pem)
    return subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(ca_path),
            "-untrusted",
            str(untrusted_path),
            str(leaf_path),
        ],
        capture_output=True,
        text=True,
    )


def _issue_leaf(
    db: Session, secrets: SecretStore, issuer_id: int, cn: str = "host.lan"
) -> Certificate:
    from cabin.ca.leaf import Profile

    issued = certs_service.issue_and_store(
        db,
        secrets,
        principal=SYSTEM_PRINCIPAL,
        profile=Profile.server,
        subject_cn=cn,
        sans=[f"DNS:{cn}"],
        issuer_id=issuer_id,
    )
    return issued.row


def _row_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(CACertificate)) or 0


# === FR-2 / AC-1: what cross_sign builds, field by field ========================


def test_cross_certificate_has_the_same_subject_bytes(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    assert cross.subject.public_bytes() == subject_cert.subject.public_bytes()


def test_cross_certificate_has_the_same_public_key(db: Session, secrets: SecretStore) -> None:
    """_Goes red if_: ``cross_sign`` generates a fresh key -- the exact
    mutation this spec is written against."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    assert _spki_der(cross) == _spki_der(subject_cert)


def test_cross_certificate_copies_the_subject_key_identifier(
    db: Session, secrets: SecretStore
) -> None:
    """_Goes red if_: the SKI is re-derived from the public key instead of
    copied byte for byte -- harmless for a cabin-created root (method 1
    derives to the same bytes) and silently wrong for an imported one."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    assert _ski(cross) == _ski(subject_cert)


def test_cross_certificate_has_an_aki_naming_the_signing_root(
    db: Session, secrets: SecretStore
) -> None:
    """The ``renew_certificate`` reuse mutation (FR-2's own warning): that
    function adds an AKI only when the input already carried one, and a
    self-signed root carries none -- so a cross certificate built by
    reusing it would have no AKI at all, which is the DST X3 pathology in
    miniature."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    aki = cross.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == _ski(signer_cert)


def test_cross_certificate_copies_basic_constraints_and_key_usage(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    cross_bc = cross.extensions.get_extension_for_class(x509.BasicConstraints).value
    subject_bc = subject_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert (cross_bc.ca, cross_bc.path_length) == (subject_bc.ca, subject_bc.path_length)
    cross_ku = cross.extensions.get_extension_for_class(x509.KeyUsage).value
    subject_ku = subject_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert cross_ku.key_cert_sign == subject_ku.key_cert_sign == True  # noqa: E712


def test_cross_certificate_carries_no_cdp_and_no_aia(db: Session, secrets: SecretStore) -> None:
    """cabin publishes neither for a root (FR-2); a CDP on a cross
    certificate would point at a CRL document that does not exist."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    with pytest.raises(x509.ExtensionNotFound):
        cross.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    with pytest.raises(x509.ExtensionNotFound):
        cross.extensions.get_extension_for_class(x509.AuthorityInformationAccess)


def test_cross_certificate_is_clamped_to_the_signing_roots_expiry(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key, years=200)

    assert cross.not_valid_after_utc <= signer_cert.not_valid_after_utc


def test_cross_certificate_serial_is_new(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    assert cross.serial_number != subject_cert.serial_number


def test_cross_sign_refuses_a_subject_with_no_ski(db: Session, secrets: SecretStore) -> None:
    """Interface Contract: ``cross_sign`` raises ``ValueError`` when
    ``subject_cert`` carries no SubjectKeyIdentifier -- cabin writes one on
    every CA it creates, so this only bites a hand-built input."""
    signer, _subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-ski Root CA")])
    no_ski = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, algorithm=ca_x509.signing_algorithm(key))
    )

    with pytest.raises(ValueError, match="SubjectKeyIdentifier"):
        ca_x509.cross_sign(no_ski, signer_cert, signer_key)


# === AC-2: A really signed it, direct and then in a chain ========================


def test_cross_sign_verifies_directly_issued_by_the_signing_root(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    cross.verify_directly_issued_by(signer_cert)  # raises on failure


def test_forged_cross_certificate_fails_direct_verification(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    unrelated_key = ec.generate_private_key(ec.SECP256R1())
    forged = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=unrelated_key,
        ski=_ski(subject_cert),
        path_length=subject_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length,
    )

    with pytest.raises(Exception):  # noqa: B017 - InvalidSignature or TypeError, both a failure
        forged.verify_directly_issued_by(signer_cert)


@_openssl
def test_openssl_builds_the_long_path(db: Session, secrets: SecretStore, tmp_path: Path) -> None:
    """AC-2 step 2: A alone in ``-CAfile``, X and I in ``-untrusted``."""
    a = create_hierarchy(db, secrets, "alpha", path_length=2)
    b = create_hierarchy(db, secrets, "beta")
    a_cert = x509.load_pem_x509_certificate(a.root.cert_pem.encode("ascii"))
    a_key = ca_service.signing_credentials(db, secrets, a.root.id)[1]
    b_cert = x509.load_pem_x509_certificate(b.root.cert_pem.encode("ascii"))
    cross = ca_x509.cross_sign(b_cert, a_cert, a_key)
    leaf = _issue_leaf(db, secrets, b.intermediate.id)

    proc = _openssl_verify(
        tmp_path, "long-path", a.root.cert_pem, _pem(cross) + b.intermediate.cert_pem, leaf.cert_pem
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@_openssl
def test_openssl_fails_without_the_cross_certificate(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-2 step 3: proves step 2 went *through* the cross certificate."""
    a = create_hierarchy(db, secrets, "alpha", path_length=2)
    b = create_hierarchy(db, secrets, "beta")
    leaf = _issue_leaf(db, secrets, b.intermediate.id)

    proc = _openssl_verify(
        tmp_path, "no-cross", a.root.cert_pem, b.intermediate.cert_pem, leaf.cert_pem
    )
    assert proc.returncode != 0
    assert "unable to get local issuer certificate" in (proc.stdout + proc.stderr).lower()


@_openssl
def test_openssl_fails_with_a_forged_cross_certificate(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-2 step 4."""
    a = create_hierarchy(db, secrets, "alpha", path_length=2)
    b = create_hierarchy(db, secrets, "beta")
    a_cert = x509.load_pem_x509_certificate(a.root.cert_pem.encode("ascii"))
    b_cert = x509.load_pem_x509_certificate(b.root.cert_pem.encode("ascii"))
    leaf = _issue_leaf(db, secrets, b.intermediate.id)
    unrelated_key = ec.generate_private_key(ec.SECP256R1())
    forged = _forged_ca_cert(
        subject=b_cert.subject,
        public_key=b_cert.public_key(),
        issuer_cert=a_cert,
        issuer_key=unrelated_key,
        ski=_ski(b_cert),
        path_length=1,
    )

    proc = _openssl_verify(
        tmp_path,
        "forged-untrusted",
        a.root.cert_pem,
        _pem(forged) + b.intermediate.cert_pem,
        leaf.cert_pem,
    )
    assert proc.returncode != 0


@_openssl
def test_openssl_passes_a_forged_cross_certificate_in_cafile(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """The blind spot, asserted so it cannot be relied on by accident
    (spec preamble): ``openssl verify`` never checks a trust anchor's own
    signature, so a certificate naming B's subject and B's public key --
    self-issued in shape, exactly what a trust anchor is expected to look
    like -- but actually signed by an unrelated key is *accepted* once
    placed directly in ``-CAfile``. A criterion that verified the long
    chain with a certificate in ``-CAfile`` would pass against one cabin
    signed with the wrong key entirely; this test exists so nobody reaches
    for that convenient invocation without knowing it proves nothing about
    the anchor's own signature.
    """
    b = create_hierarchy(db, secrets, "beta")
    b_cert = x509.load_pem_x509_certificate(b.root.cert_pem.encode("ascii"))
    leaf = _issue_leaf(db, secrets, b.intermediate.id)
    unrelated_key = ec.generate_private_key(ec.SECP256R1())
    forged = _forged_ca_cert(
        subject=b_cert.subject,
        public_key=b_cert.public_key(),
        issuer_cert=b_cert,  # self-issued in name -- what makes it a valid trust anchor
        issuer_key=unrelated_key,  # ...but NOT what actually signed it
        ski=_ski(b_cert),
        path_length=1,
    )

    proc = _openssl_verify(
        tmp_path, "forged-cafile", _pem(forged), b.intermediate.cert_pem, leaf.cert_pem
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# === FR-3 / AC-4: path_length is checked before anything is signed ==============


def test_path_length_error_names_the_value(db: Session, secrets: SecretStore) -> None:
    signer = _root_row(db, secrets, "alpha", path_length=1)
    subject = _root_row(db, secrets, "beta", path_length=1)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    message = ca_x509.cross_path_length_error(subject_cert, signer_cert)

    assert message is not None
    assert "path_length" in message
    assert "1" in message


def test_path_length_two_signing_root_is_accepted(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    assert ca_x509.cross_path_length_error(subject_cert, signer_cert) is None


def test_subject_root_with_path_length_zero_is_refused(db: Session, secrets: SecretStore) -> None:
    """The other half of FR-3: the cross certificate copies the subject's
    own BasicConstraints (FR-2), so a subject root built elsewhere with
    ``path_length=0`` (import) cannot be cross-signed by any signing root,
    however wide."""
    signer, _subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    zero_cert, _key = create_root("PL0 Root CA", "ecdsa-p256", path_length=0)

    assert ca_x509.cross_path_length_error(zero_cert, signer_cert) is not None


def test_path_length_one_signing_root_is_refused(db: Session, secrets: SecretStore) -> None:
    """The service-layer refusal, checked before anything is signed: no row
    is written."""
    signer = _root_row(db, secrets, "alpha", path_length=1)
    subject = _root_row(db, secrets, "beta", path_length=1)
    before = _row_count(db)

    with pytest.raises(ca_service.CrossSignError, match="path_length"):
        ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    assert _row_count(db) == before


@_openssl
def test_smuggled_cross_certificate_fails_path_length_in_openssl(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-4: a cross certificate built by calling ``cross_sign`` directly --
    bypassing the service-layer check -- is accepted by neither cabin's own
    check (previous test) nor a real validator."""
    a1 = create_hierarchy(db, secrets, "alpha1", path_length=1)
    b = create_hierarchy(db, secrets, "beta")
    a1_cert = x509.load_pem_x509_certificate(a1.root.cert_pem.encode("ascii"))
    a1_key = ca_service.signing_credentials(db, secrets, a1.root.id)[1]
    b_cert = x509.load_pem_x509_certificate(b.root.cert_pem.encode("ascii"))
    leaf = _issue_leaf(db, secrets, b.intermediate.id)

    smuggled = ca_x509.cross_sign(b_cert, a1_cert, a1_key)

    proc = _openssl_verify(
        tmp_path,
        "path-length-smuggled",
        a1.root.cert_pem,
        _pem(smuggled) + b.intermediate.cert_pem,
        leaf.cert_pem,
    )
    assert proc.returncode != 0


# === FR-4: cross_sign_root ========================================================


def test_cross_sign_root_writes_expected_row(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)

    row = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    assert row.kind == "cross"
    assert row.parent_id == signer.id
    assert row.cross_of_id == subject.id
    assert row.status == "active"
    assert row.key_sealed is None
    assert row.name == subject.name


def test_cross_sign_root_refuses_non_root_subject(db: Session, secrets: SecretStore) -> None:
    signer, _subject = _two_roots(db, secrets)
    intermediate = create_hierarchy(db, secrets, "gamma").intermediate
    before = _row_count(db)

    with pytest.raises(ValueError, match="root"):
        ca_service.cross_sign_root(db, secrets, intermediate.id, signer.id)

    assert _row_count(db) == before


def test_cross_sign_root_refuses_signing_root_without_key(
    db: Session, secrets: SecretStore
) -> None:
    """An imported root's key is never in cabin -- signing needs it, and
    only signing does (spec 0021's own worth-stating claim about not
    needing the *subject's* key does not apply here)."""
    _subject_placeholder, subject = _two_roots(db, secrets)
    imported_cert, _key = create_root("Imported Signer Root CA", "ecdsa-p256", path_length=2)
    imported_row = CACertificate(
        kind="root",
        name="Imported Signer Root CA",
        status="active",
        cert_pem=_pem(imported_cert),
        key_sealed=None,
    )
    db.add(imported_row)
    db.commit()
    before = _row_count(db)

    with pytest.raises(CANotConfiguredError, match="key"):
        ca_service.cross_sign_root(db, secrets, subject.id, imported_row.id)

    assert _row_count(db) == before


def test_cross_sign_root_refuses_duplicate_active_cross(db: Session, secrets: SecretStore) -> None:
    """A second identical path serves nobody and would make the default
    rule (FR-6) depend on a coin toss."""
    signer, subject = _two_roots(db, secrets)
    ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    before = _row_count(db)

    with pytest.raises(ca_service.CrossSignError):
        ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    assert _row_count(db) == before


def test_cross_sign_root_refuses_signing_a_root_with_itself(
    db: Session, secrets: SecretStore
) -> None:
    """Refused by the "different row" half of FR-4's ``signing_root_id``
    rule; the result would otherwise be a re-issued self-signed root, which
    is what ``renew_in_place`` is for."""
    signer, _subject = _two_roots(db, secrets)
    before = _row_count(db)

    with pytest.raises(ValueError):
        ca_service.cross_sign_root(db, secrets, signer.id, signer.id)

    assert _row_count(db) == before


def test_cross_sign_root_works_without_the_subjects_key(db: Session, secrets: SecretStore) -> None:
    """FR-4: cabin can cross-sign an imported root -- the one CA operation
    that works without the subject's private key."""
    signer, _placeholder = _two_roots(db, secrets)
    imported_cert, _key = create_root("Imported Subject Root CA", "ecdsa-p256", path_length=1)
    imported_row = CACertificate(
        kind="root",
        name="Imported Subject Root CA",
        status="active",
        cert_pem=_pem(imported_cert),
        key_sealed=None,
    )
    db.add(imported_row)
    db.commit()

    row = ca_service.cross_sign_root(db, secrets, imported_row.id, signer.id)

    assert row.kind == "cross"
    stored = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    assert _spki_der(stored) == _spki_der(imported_cert)


# === FR-5 / AC-5 / AC-6: import_cross =============================================


def test_import_refuses_a_matching_subject_with_a_different_key(
    db: Session, secrets: SecretStore
) -> None:
    """The staple attack AC-5 exists for: a CA certificate whose subject CN
    reads exactly what cabin generated for B, over a different key
    entirely."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    stranger_key = ec.generate_private_key(ec.SECP256R1())

    staple = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=stranger_key.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        path_length=1,
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(staple), signer.cert_pem)

    assert _row_count(db) == before


def test_load_cross_refuses_a_different_public_key_even_with_a_matching_ski(
    db: Session, secrets: SecretStore
) -> None:
    """Direct unit test of ``ca_x509.load_cross``'s own public-key
    comparison, deliberately bypassing ``ca_service.import_cross``.

    ``import_cross`` resolves which existing root a cross certificate is
    *for* through its own ``_same_ca`` helper, which already compares
    subject **and** public key before ``load_cross`` is ever called -- so
    every test that goes through ``import_cross`` (including the one above)
    is refused there first, on a subject+key mismatch, regardless of
    whether ``load_cross``'s own comparison exists at all. Nothing in this
    suite called ``load_cross`` directly before this test, which means its
    own check was unreachable by any input able to tell its presence from
    its absence: a mutation harness confirmed this by removing it and
    watching every existing test stay green.

    Calling ``load_cross`` directly, with the forged certificate's
    ``SubjectKeyIdentifier`` set to the REAL root's own (``ski=_ski(...)``,
    not the stranger key's derived one), is what isolates the public-key
    comparison from both of those other checks: the SKI comparison a few
    lines below it in ``load_cross`` cannot be what refuses this one.
    """
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    stranger_key = ec.generate_private_key(ec.SECP256R1())

    forged = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=stranger_key.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        path_length=1,
    )

    with pytest.raises(CAImportError, match="public key"):
        ca_x509.load_cross(_pem(forged).encode("ascii"), subject_cert, signer_cert)


def test_import_refuses_a_matching_key_with_a_different_subject(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    impostor = _forged_ca_cert(
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor CA")]),
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        path_length=1,
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(impostor), signer.cert_pem)

    assert _row_count(db) == before


def test_import_refuses_a_differently_encoded_subject(db: Session, secrets: SecretStore) -> None:
    """Two ``Name`` objects can compare equal in Python and still encode
    differently (``PrintableString`` against ``UTF8String``); the check
    must compare DER, not the Python object."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    [attr] = subject_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    differently_encoded = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, str(attr.value), _type=_ASN1Type.PrintableString)]
    )
    assert differently_encoded == subject_cert.subject  # Python equality: same string
    assert (
        differently_encoded.public_bytes() != subject_cert.subject.public_bytes()
    )  # DER: different

    forged = _forged_ca_cert(
        subject=differently_encoded,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        path_length=1,
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(forged), signer.cert_pem)

    assert _row_count(db) == before


def test_import_refuses_a_signature_from_a_third_root(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    third_cert, third_key = create_root("Gamma Root CA", "ecdsa-p256", path_length=2)

    actually_signed_by_gamma = ca_x509.cross_sign(subject_cert, third_cert, third_key)
    before = _row_count(db)

    # submitted (falsely) as signed by A
    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(actually_signed_by_gamma), signer.cert_pem)

    assert _row_count(db) == before


def test_import_refuses_a_mismatched_subject_key_identifier(
    db: Session, secrets: SecretStore
) -> None:
    """Equal public keys do not force equal SKIs; a cross certificate whose
    SKI differs from what every intermediate's AKI names cannot be chained
    through."""
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    wrong_ski = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=b"\x00" * 20,
        path_length=1,
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(wrong_ski), signer.cert_pem)

    assert _row_count(db) == before


def test_import_refuses_a_non_ca_certificate(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    before = _row_count(db)

    not_a_ca = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        ca=False,
        path_length=None,
    )
    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(not_a_ca), signer.cert_pem)
    assert _row_count(db) == before

    no_key_cert_sign = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        key_cert_sign=False,
        path_length=1,
    )
    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(no_key_cert_sign), signer.cert_pem)
    assert _row_count(db) == before


def test_import_refuses_an_expired_certificate(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    now = datetime.now(UTC)

    expired = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        path_length=1,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=1),
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(expired), signer.cert_pem)

    assert _row_count(db) == before


def test_import_reuses_an_existing_signing_root_row(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)
    before = _row_count(db)

    row = ca_service.import_cross(db, _pem(cross), signer.cert_pem)

    assert _row_count(db) == before + 1  # only the cross row, A's row is reused
    assert row.parent_id == signer.id


def test_import_inserts_an_unknown_signing_root_without_a_key(
    db: Session, secrets: SecretStore
) -> None:
    _signer_placeholder, subject = _two_roots(db, secrets)
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    unknown_cert, unknown_key = create_root("Unknown Signer Root CA", "ecdsa-p256", path_length=2)
    cross = ca_x509.cross_sign(subject_cert, unknown_cert, unknown_key)
    before = _row_count(db)

    row = ca_service.import_cross(db, _pem(cross), _pem(unknown_cert))

    assert _row_count(db) == before + 2  # the new root row, and the cross row
    assert row.parent_id is not None
    signing_row = get_ca(db, row.parent_id)
    assert signing_row.kind == "root"
    assert signing_row.key_sealed is None


def test_import_refuses_when_no_row_matches_the_subject(db: Session, secrets: SecretStore) -> None:
    """A certificate for a CA nothing on this instance holds."""
    unrelated_subject_cert, _k = create_root("Nobody's Root CA", "ecdsa-p256", path_length=1)
    signer_cert, signer_key = create_root("Elsewhere Signer Root CA", "ecdsa-p256", path_length=2)
    cross = ca_x509.cross_sign(unrelated_subject_cert, signer_cert, signer_key)
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(cross), _pem(signer_cert))

    assert _row_count(db) == before


def test_import_refuses_when_more_than_one_row_matches_the_subject(
    db: Session, secrets: SecretStore
) -> None:
    """A duplicate-root state cabin cannot resolve, so it refuses rather
    than guessing."""
    signer, subject = _two_roots(db, secrets)
    duplicate = CACertificate(
        kind="root", name=subject.name, status="active", cert_pem=subject.cert_pem, key_sealed=None
    )
    db.add(duplicate)
    db.commit()
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(cross), signer.cert_pem)

    assert _row_count(db) == before


def test_import_success_writes_the_expected_row(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    row = ca_service.import_cross(db, _pem(cross), signer.cert_pem)

    assert row.kind == "cross"
    assert row.parent_id == signer.id
    assert row.cross_of_id == subject.id
    assert row.key_sealed is None


def test_refused_import_changes_no_served_chain(db: Session, secrets: SecretStore) -> None:
    """AC-5: the negative cases are measured on the served chain, not only
    on the exception raised -- "the import was refused" and "the import
    was refused and nothing was written" are different claims."""
    signer, subject = _two_roots(db, secrets)
    intermediate = ca_service.create_intermediate_under(db, secrets, subject.id, "beta-int")
    before = list(ca_service.chain_for(db, intermediate.id))
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    stranger_key = ec.generate_private_key(ec.SECP256R1())
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    staple = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=stranger_key.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        path_length=1,
    )
    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(staple), signer.cert_pem)

    after = list(ca_service.chain_for(db, intermediate.id))
    assert [row.id for row in before] == [row.id for row in after]


# === FR-1 / AC-18: schema ==========================================================


def test_schema_admits_kind_cross_and_has_cross_of_id(db: Session, secrets: SecretStore) -> None:
    inspector = sa.inspect(db.get_bind())
    columns = {col["name"] for col in inspector.get_columns("ca_certificates")}
    assert "cross_of_id" in columns

    fks = inspector.get_foreign_keys("ca_certificates")
    assert any(
        fk["referred_table"] == "ca_certificates" and "cross_of_id" in fk["constrained_columns"]
        for fk in fks
    ), fks

    insert = (
        "INSERT INTO ca_certificates (kind, name, status, cert_pem, key_sealed, created_at) "
        "VALUES ('bogus', 'x', 'active', 'y', NULL, '2020-01-01 00:00:00')"
    )
    with pytest.raises(sa.exc.IntegrityError, match="ck_ca_certificates_kind"):
        db.execute(sa.text(insert))
    db.rollback()


def test_migration_chain_still_ends_at_0010(db: Session) -> None:
    version = db.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
    assert version == "0010"
    versions_dir = Path(store_pkg.__file__).resolve().parent / "migrations" / "versions"
    assert not list(versions_dir.glob("0011*"))


def test_every_cross_row_has_null_key_sealed_and_non_null_parent_and_cross_of(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    row = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    fresh = get_ca(db, row.id)
    assert fresh.key_sealed is None
    assert fresh.parent_id is not None
    assert fresh.cross_of_id is not None


def test_no_row_ever_has_a_cross_row_as_its_parent_id(db: Session, secrets: SecretStore) -> None:
    """FR-1's second invariant: a cross certificate is a second path to an
    existing CA, never a place to hang a new one."""
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    with pytest.raises(ValueError, match="root"):
        ca_service.cross_sign_root(db, secrets, subject.id, cross.id)


# === FR-12 / AC-14: name constraints are copied, never invented ===================


def test_name_constraints_are_copied_byte_for_byte(db: Session, secrets: SecretStore) -> None:
    signer_cert, signer_key = create_root("NC Signer Root CA", "ecdsa-p256", path_length=2)
    spec = NameConstraintSpec(permitted_dns=("example.com",))
    extension = name_constraints_extension(spec)
    assert extension is not None
    subject_key = ec.generate_private_key(ec.SECP256R1())
    subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NC Subject Root CA")])
    subject_cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False
        )
        .add_extension(extension, critical=True)
        .sign(subject_key, algorithm=ca_x509.signing_algorithm(subject_key))
    )

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    cross_nc = cross.extensions.get_extension_for_class(x509.NameConstraints)
    assert cross_nc.value.permitted_subtrees == extension.permitted_subtrees
    assert cross_nc.critical is True


def test_unconstrained_root_produces_an_unconstrained_cross_certificate(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))

    cross = ca_x509.cross_sign(subject_cert, signer_cert, signer_key)

    with pytest.raises(x509.ExtensionNotFound):
        cross.extensions.get_extension_for_class(x509.NameConstraints)


def test_import_refuses_a_narrowing_cross_certificate(db: Session, secrets: SecretStore) -> None:
    """FR-12: a cross certificate carrying constraints its subject root
    does not is refused -- narrowing on one path and not the other would
    let cabin issue certificates one of its own served chains rejects."""
    signer, subject = _two_roots(db, secrets)  # subject (B) carries no constraints
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
    signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
    narrowed = _forged_ca_cert(
        subject=subject_cert.subject,
        public_key=subject_cert.public_key(),
        issuer_cert=signer_cert,
        issuer_key=signer_key,
        ski=_ski(subject_cert),
        path_length=1,
    )
    extension = name_constraints_extension(NameConstraintSpec(permitted_dns=("example.com",)))
    assert extension is not None
    # rebuild with the NameConstraints extension added, since _forged_ca_cert has no hook for it
    narrowed = (
        x509.CertificateBuilder()
        .subject_name(subject_cert.subject)
        .issuer_name(signer_cert.subject)
        .public_key(subject_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(narrowed.not_valid_before_utc)
        .not_valid_after(narrowed.not_valid_after_utc)
        .add_extension(
            narrowed.extensions.get_extension_for_class(x509.BasicConstraints).value, critical=True
        )
        .add_extension(
            narrowed.extensions.get_extension_for_class(x509.KeyUsage).value, critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier(_ski(subject_cert)), critical=False)
        .add_extension(
            narrowed.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value,
            critical=False,
        )
        .add_extension(extension, critical=True)
        .sign(signer_key, algorithm=ca_x509.signing_algorithm(signer_key))
    )
    before = _row_count(db)

    with pytest.raises(CAImportError):
        ca_service.import_cross(db, _pem(narrowed), signer.cert_pem)

    assert _row_count(db) == before


# === FR-10: retire mechanics ======================================================


def test_retire_cross_certificate_never_raises_retire_error(
    db: Session, secrets: SecretStore
) -> None:
    """A cross row is not an intermediate, so ``active_issuers`` never
    counts it and ``RetireError`` can never fire for retiring one."""
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    retire(db, cross.id)  # must not raise

    assert get_ca(db, cross.id).status == "retired"


def test_retiring_the_signing_root_retires_the_cross_certificate(
    db: Session, secrets: SecretStore
) -> None:
    """``retire_targets`` returns every row whose ``parent_id`` is the root
    being retired, which now includes any cross certificate it signed."""
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    targets = retire_targets(db, signer.id)
    assert cross.id in targets

    retire(db, signer.id)
    assert get_ca(db, cross.id).status == "retired"


def test_retiring_the_subject_root_does_not_retire_the_cross_certificate(
    db: Session, secrets: SecretStore
) -> None:
    """Deliberate: the cross certificate's ``parent_id`` names the signing
    root, so it is outside the subject root's cascade -- everything the
    subject's intermediates already issued keeps a working chain."""
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    targets = retire_targets(db, subject.id)
    assert cross.id not in targets


def test_cross_row_is_never_an_active_issuer(db: Session, secrets: SecretStore) -> None:
    signer, subject = _two_roots(db, secrets)
    ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    assert all(row.kind != "cross" for row in active_issuers(db))


# === FR-11 / AC-12: renewal =========================================================


def test_renew_cross_certificate_keeps_key_ski_and_aki(db: Session, secrets: SecretStore) -> None:
    """_Goes red if_: the ``key_sealed`` guard stays where it is (a cross
    row can never renew) -- and would also go red if renewal regenerated
    the key, which a chain-shaped test alone would not catch."""
    signer, subject = _two_roots(db, secrets)
    # cross_sign_root's default years=10; renew for longer (15, well inside
    # A's 20-year budget) so a later not_after is unambiguous evidence of a
    # genuine renewal, not just "any renewal at all".
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    before = x509.load_pem_x509_certificate(cross.cert_pem.encode("ascii"))

    renewed_row = renew_in_place(db, secrets, cross.id, 15)

    after = x509.load_pem_x509_certificate(renewed_row.cert_pem.encode("ascii"))
    assert after.subject.public_bytes() == before.subject.public_bytes()
    assert _spki_der(after) == _spki_der(before)
    assert _ski(after) == _ski(before)
    aki_before = before.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    aki_after = after.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki_after.key_identifier == aki_before.key_identifier
    assert after.serial_number != before.serial_number
    assert after.not_valid_after_utc > before.not_valid_after_utc


def test_renew_cross_certificate_still_verifies_against_the_signing_root(
    db: Session, secrets: SecretStore
) -> None:
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))

    renewed_row = renew_in_place(db, secrets, cross.id, 5)

    renewed_cert = x509.load_pem_x509_certificate(renewed_row.cert_pem.encode("ascii"))
    renewed_cert.verify_directly_issued_by(signer_cert)  # raises on failure


@_openssl
def test_leaf_issued_before_the_renewal_still_validates(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    sub_hierarchy_intermediate = ca_service.create_intermediate_under(
        db, secrets, subject.id, "beta-real"
    )
    leaf = _issue_leaf(db, secrets, sub_hierarchy_intermediate.id)

    renew_in_place(db, secrets, cross.id, 5)
    renewed_cross_pem = get_ca(db, cross.id).cert_pem

    proc = _openssl_verify(
        tmp_path,
        "leaf-survives-renewal",
        signer.cert_pem,
        renewed_cross_pem + sub_hierarchy_intermediate.cert_pem,
        leaf.cert_pem,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_renew_imported_root_still_refuses(db: Session, secrets: SecretStore) -> None:
    """AC-12: moving the ``key_sealed`` guard inside the ``kind == "root"``
    branch must not remove it for an imported root."""
    imported_cert, _key = create_root("Imported Root CA", "ecdsa-p256")
    row = CACertificate(
        kind="root",
        name="Imported Root CA",
        status="active",
        cert_pem=_pem(imported_cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()

    with pytest.raises(CANotConfiguredError, match="key"):
        renew_in_place(db, secrets, row.id, 5)


def test_renew_intermediate_is_unchanged(db: Session, secrets: SecretStore) -> None:
    """Sanity check for the guard move: an ordinary intermediate renews
    exactly as it did before this spec."""
    hierarchy = create_hierarchy(db, secrets, "gamma")
    before = x509.load_pem_x509_certificate(hierarchy.intermediate.cert_pem.encode("ascii"))

    renewed = renew_in_place(db, secrets, hierarchy.intermediate.id, 5)

    after = x509.load_pem_x509_certificate(renewed.cert_pem.encode("ascii"))
    assert after.serial_number != before.serial_number
    assert _spki_der(after) == _spki_der(before)


# === AC-13: a cross certificate never issues anything =============================


def test_cross_certificate_cannot_issue_a_leaf(db: Session, secrets: SecretStore) -> None:
    from cabin.ca.leaf import Profile

    signer, subject = _two_roots(db, secrets)
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    before = db.scalar(select(func.count()).select_from(Certificate)) or 0

    with pytest.raises(UnknownIssuerError):
        certs_service.issue_and_store(
            db,
            secrets,
            principal=SYSTEM_PRINCIPAL,
            profile=Profile.server,
            subject_cn="nope.lan",
            sans=["DNS:nope.lan"],
            issuer_id=cross.id,
        )
    with pytest.raises(UnknownIssuerError):
        certs_service.sign_csr_and_store(
            db,
            secrets,
            principal=SYSTEM_PRINCIPAL,
            csr_pem="not-even-parsed-before-the-issuer-check-should-fail",
            profile=Profile.server,
            issuer_id=cross.id,
        )

    after = db.scalar(select(func.count()).select_from(Certificate)) or 0
    assert after == before
    assert cross.id not in {row.id for row in active_issuers(db)}


# === FR-14: audit and the API/MCP surface ==========================================


def test_audit_cross_signed_and_cross_imported(db: Session, secrets: SecretStore) -> None:
    """Two new ``AuditAction`` members, not folded into
    ``ca_created``/``ca_imported`` -- a log that cannot tell "extended an
    existing root's trust" from "created a hierarchy" cannot answer the one
    question anybody asks it afterwards."""
    from cabin.audit import record, user_actor
    from cabin.users import Role, create_user

    signer, subject = _two_roots(db, secrets)
    actor = user_actor(create_user(db, "auditor", "whatever12345", Role.admin))
    before = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
    cross = ca_service.cross_sign_root(db, secrets, subject.id, signer.id)
    # cross_sign_root itself writes no audit event (that is FR-14's door's
    # job, exercised over HTTP in test_cross_chains.py); this test only
    # pins the enum member and its shape, writing the event by hand the way
    # the door would.
    record(
        db,
        actor,
        AuditAction.ca_cross_signed,
        summary="cross-signed",
        target_type="ca_certificate",
        target_id=cross.id,
        detail={"signing_root_id": signer.id, "subject_root_id": subject.id, "years": 10},
    )
    record(
        db,
        actor,
        AuditAction.ca_cross_imported,
        summary="cross-imported",
        target_type="ca_certificate",
        target_id=cross.id,
    )
    after = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
    assert after == before + 2


def test_cross_signing_writes_no_grant(db: Session, secrets: SecretStore) -> None:
    """A cross certificate is not an issuer and can never sign a leaf, so
    there is nothing for a grant to authorise."""
    signer, subject = _two_roots(db, secrets)
    users_before = db.scalar(select(func.count()).select_from(UserIssuer)) or 0
    tokens_before = db.scalar(select(func.count()).select_from(TokenIssuer)) or 0

    ca_service.cross_sign_root(db, secrets, subject.id, signer.id)

    assert (db.scalar(select(func.count()).select_from(UserIssuer)) or 0) == users_before
    assert (db.scalar(select(func.count()).select_from(TokenIssuer)) or 0) == tokens_before


def test_crl_route_404_for_a_cross_row(db: Session, secrets: SecretStore, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from cabin.app import create_app
    from cabin.config import Config

    cfg = Config(
        port=8080, data_dir=tmp_path / "data", db_url=f"sqlite:///{tmp_path}/data/cabin.db"
    )
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        assert (
            client.post(
                "/setup", data={"username": "root", "password": "whatever12345"}
            ).status_code
            == 303
        )
        cfg_db = create_session_factory(cfg.db_url)()
        cfg_secrets = SecretStore.open(cfg.data_dir, cfg.master_passphrase)
        try:
            signer, subject = _two_roots(cfg_db, cfg_secrets)
            cross = ca_service.cross_sign_root(cfg_db, cfg_secrets, subject.id, signer.id)
        finally:
            cfg_db.close()

        resp = client.get(f"/crl/{cross.id}")
        assert resp.status_code == 404


def test_ca_cer_route_serves_a_cross_row(db: Session, secrets: SecretStore, tmp_path: Path) -> None:
    """A relying party repairing a chain may legitimately need a cross
    certificate's own bytes."""
    from fastapi.testclient import TestClient

    from cabin.app import create_app
    from cabin.config import Config

    cfg = Config(
        port=8080, data_dir=tmp_path / "data", db_url=f"sqlite:///{tmp_path}/data/cabin.db"
    )
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        assert (
            client.post(
                "/setup", data={"username": "root", "password": "whatever12345"}
            ).status_code
            == 303
        )
        cfg_db = create_session_factory(cfg.db_url)()
        cfg_secrets = SecretStore.open(cfg.data_dir, cfg.master_passphrase)
        try:
            signer, subject = _two_roots(cfg_db, cfg_secrets)
            cross = ca_service.cross_sign_root(cfg_db, cfg_secrets, subject.id, signer.id)
            expected_der = x509.load_pem_x509_certificate(
                cross.cert_pem.encode("ascii")
            ).public_bytes(serialization.Encoding.DER)
        finally:
            cfg_db.close()

        resp = client.get(f"/ca/{cross.id}.cer")
        assert resp.status_code == 200
        assert resp.content == expected_der
