"""Cross-cutting acceptance tests for spec 0017 (multi-CA): scenarios that
span :mod:`cabin.ca.service`, :mod:`cabin.ca.certs` and :mod:`cabin.ca.crl`
together, named in the spec's own Test list.

Wherever the spec asks for a chain or a CRL to be checked, this file shells
out to the real ``openssl`` CLI rather than comparing PEM strings -- a test
that only proves bytes came back proves nothing (spec 0017 Acceptance
Criteria preamble, and the work split's R3). Every positive check has a
matching negative one against the wrong material, with the two swapped to
prove the assertion is not vacuously true in one direction.
"""

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from cabin.ca.certs import Certificate, issue_and_store
from cabin.ca.crl import current_crl, revoke_certificate
from cabin.ca.leaf import Profile
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    chain_for,
    create_hierarchy,
    create_intermediate_under,
    get_ca,
    renew_in_place,
    retire,
)
from cabin.ca.x509 import create_root
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


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


def _chain_pem(db: Session, issuer_id: int) -> str:
    """Concatenated PEM of an issuer and its ancestors, root last -- what
    every chain-assembly call site (FR-8) is meant to build from
    ``chain_for``."""
    return "".join(row.cert_pem for row in chain_for(db, issuer_id))


def _openssl_verify(tmp_path: Path, label: str, leaf_pem: str, ca_chain_pem: str) -> bool:
    d = tmp_path / "verify" / label
    d.mkdir(parents=True)
    leaf_path = d / "leaf.pem"
    chain_path = d / "chain.pem"
    leaf_path.write_text(leaf_pem)
    chain_path.write_text(ca_chain_pem)
    # CAUTION: openssl treats the certificate(s) in -CAfile as trust anchors
    # and does NOT check their own self-signature -- only that the leaf
    # chains up to them. A root in ca_chain_pem whose self-signature is
    # cryptographically invalid (e.g. renewed with the wrong signing key)
    # still passes this call. A chain check via this helper alone never
    # proves a root itself is intact; that needs a direct
    # cert.verify_directly_issued_by(cert) check on the root, e.g. as done
    # in test_certs_issued_before_renewal_verify_against_renewed_ca below.
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(chain_path), str(leaf_path)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _openssl_crl_issuer(tmp_path: Path, label: str, crl_der: bytes) -> str:
    d = tmp_path / "crl" / label
    d.mkdir(parents=True)
    crl_path = d / "crl.der"
    crl_path.write_bytes(crl_der)
    result = subprocess.run(
        ["openssl", "crl", "-inform", "DER", "-in", str(crl_path), "-noout", "-issuer"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _imported_root(db: Session, name: str = "Imported") -> CACertificate:
    cert, _key = create_root(f"{name} Root CA", "ecdsa-p256")
    row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row


# --- AC-1: two hierarchies, each leaf verifies only against its own chain ---


def test_two_hierarchies_verify_against_own_chain_only(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    h1 = create_hierarchy(db, secrets, "Alpha")
    h2 = create_hierarchy(db, secrets, "Beta")

    issued_a = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="a.lan",
        sans=["DNS:a.lan"],
        issuer_id=h1.intermediate.id,
    )
    issued_b = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="b.lan",
        sans=["DNS:b.lan"],
        issuer_id=h2.intermediate.id,
    )

    chain1 = _chain_pem(db, h1.intermediate.id)
    chain2 = _chain_pem(db, h2.intermediate.id)

    assert _openssl_verify(tmp_path, "a-own", issued_a.row.cert_pem, chain1)
    assert _openssl_verify(tmp_path, "b-own", issued_b.row.cert_pem, chain2)
    # Swapped: both directions must fail, or the positive checks above are
    # not measuring anything (work split R3).
    assert not _openssl_verify(tmp_path, "a-wrong", issued_a.row.cert_pem, chain2)
    assert not _openssl_verify(tmp_path, "b-wrong", issued_b.row.cert_pem, chain1)


# --- AC-2: default-issuer rule -----------------------------------------------


def test_issuer_required_with_multiple_active(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "Alpha")
    create_hierarchy(db, secrets, "Beta")

    with pytest.raises(IssuerRequiredError):
        issue_and_store(db, secrets, profile=Profile.server, subject_cn="x.lan", sans=["DNS:x.lan"])

    assert db.query(Certificate).count() == 0


def test_issuer_defaulted_with_single_active(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "Alpha")

    issued = issue_and_store(
        db, secrets, profile=Profile.server, subject_cn="x.lan", sans=["DNS:x.lan"]
    )

    assert issued.row.issuer_id == hierarchy.intermediate.id


def test_issuer_defaults_to_remaining_active_after_retiring_one_of_two(
    db: Session, secrets: SecretStore
) -> None:
    h1 = create_hierarchy(db, secrets, "Alpha")
    h2 = create_hierarchy(db, secrets, "Beta")
    retire(db, h1.intermediate.id)

    issued = issue_and_store(
        db, secrets, profile=Profile.server, subject_cn="x.lan", sans=["DNS:x.lan"]
    )

    assert issued.row.issuer_id == h2.intermediate.id


# --- AC-3: retired issuer refuses new issuance, keeps serving --------------


def test_issue_with_retired_issuer_refused(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "Alpha")
    create_hierarchy(db, secrets, "Beta")  # keeps an active issuer elsewhere
    retire(db, h1.intermediate.id)

    before = db.query(Certificate).count()
    with pytest.raises(IssuerRetiredError):
        issue_and_store(
            db,
            secrets,
            profile=Profile.server,
            subject_cn="x.lan",
            sans=["DNS:x.lan"],
            issuer_id=h1.intermediate.id,
        )
    assert db.query(Certificate).count() == before


def test_retired_issuer_still_serves_chain_and_crl(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    h1 = create_hierarchy(db, secrets, "Alpha")
    create_hierarchy(db, secrets, "Beta")
    issued = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="x.lan",
        sans=["DNS:x.lan"],
        issuer_id=h1.intermediate.id,
    )
    retire(db, h1.intermediate.id)

    # chain_for still answers for the retired issuer, and the leaf issued
    # before retirement still verifies against it.
    chain = _chain_pem(db, h1.intermediate.id)
    assert _openssl_verify(tmp_path, "retired-still-verifies", issued.row.cert_pem, chain)

    # revoking under a retired issuer still works and republishes its CRL.
    revoke_certificate(db, secrets, issued.row.id, RevocationReason.superseded)
    state = current_crl(db, secrets, h1.intermediate.id)
    crl = x509.load_der_x509_crl(state.crl_der)
    assert crl.get_revoked_certificate_by_serial_number(int(issued.row.serial_hex, 16)) is not None


# --- FR-3: create_intermediate_under / AC-13 ---------------------------------


def test_create_intermediate_under_root(db: Session, secrets: SecretStore, tmp_path: Path) -> None:
    hierarchy = create_hierarchy(db, secrets, "Alpha")

    second = create_intermediate_under(db, secrets, hierarchy.root.id, "Alpha II", years=5)

    root_pem = get_ca(db, hierarchy.root.id).cert_pem
    assert _openssl_verify(tmp_path, "second-under-root", second.cert_pem, root_pem)


def test_create_intermediate_under_imported_root_errors(db: Session, secrets: SecretStore) -> None:
    """AC-13: refused with a message naming the missing key."""
    root = _imported_root(db)

    with pytest.raises(CANotConfiguredError, match="key"):
        create_intermediate_under(db, secrets, root.id, "under imported root")


# --- AC-4: rotation end to end -----------------------------------------------


def test_rotation_leaves_old_certs_valid(db: Session, secrets: SecretStore, tmp_path: Path) -> None:
    hierarchy = create_hierarchy(db, secrets, "Rotate")
    i1 = hierarchy.intermediate

    leaf_a = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="a.lan",
        sans=["DNS:a.lan"],
        issuer_id=i1.id,
    )
    # FR-4: the last active intermediate cannot be retired, so the
    # replacement is created before the old one is retired -- the rotation
    # order the spec's own user story describes.
    i2 = create_intermediate_under(db, secrets, hierarchy.root.id, "Rotate II", years=8)
    retire(db, i1.id)
    leaf_b = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="b.lan",
        sans=["DNS:b.lan"],
        issuer_id=i2.id,
    )

    chain1 = _chain_pem(db, i1.id)
    chain2 = _chain_pem(db, i2.id)

    assert _openssl_verify(tmp_path, "a-own-chain", leaf_a.row.cert_pem, chain1)
    assert _openssl_verify(tmp_path, "b-own-chain", leaf_b.row.cert_pem, chain2)
    assert not _openssl_verify(tmp_path, "a-wrong-chain", leaf_a.row.cert_pem, chain2)
    assert not _openssl_verify(tmp_path, "b-wrong-chain", leaf_b.row.cert_pem, chain1)


def test_crl_per_issuer_partitions_revocations(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-4: revoking a certificate from I1 puts its serial in I1's CRL and
    not in I2's, asserted in both directions, plus the CRL issuer name is per
    issuer as read by the real ``openssl crl`` CLI."""
    hierarchy = create_hierarchy(db, secrets, "Rotate")
    i1 = hierarchy.intermediate
    leaf_a = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="a.lan",
        sans=["DNS:a.lan"],
        issuer_id=i1.id,
    )
    # FR-4: the last active intermediate cannot be retired, so the
    # replacement is created before the old one is retired -- the rotation
    # order the spec's own user story describes.
    i2 = create_intermediate_under(db, secrets, hierarchy.root.id, "Rotate II", years=8)
    retire(db, i1.id)
    leaf_b = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="b.lan",
        sans=["DNS:b.lan"],
        issuer_id=i2.id,
    )

    revoke_certificate(db, secrets, leaf_a.row.id, RevocationReason.superseded)
    revoke_certificate(db, secrets, leaf_b.row.id, RevocationReason.key_compromise)

    crl1 = x509.load_der_x509_crl(current_crl(db, secrets, i1.id).crl_der)
    crl2 = x509.load_der_x509_crl(current_crl(db, secrets, i2.id).crl_der)

    serial_a = int(leaf_a.row.serial_hex, 16)
    serial_b = int(leaf_b.row.serial_hex, 16)

    assert crl1.get_revoked_certificate_by_serial_number(serial_a) is not None
    assert crl1.get_revoked_certificate_by_serial_number(serial_b) is None
    assert crl2.get_revoked_certificate_by_serial_number(serial_b) is not None
    assert crl2.get_revoked_certificate_by_serial_number(serial_a) is None

    i1_cert = x509.load_pem_x509_certificate(get_ca(db, i1.id).cert_pem.encode("ascii"))
    i2_cert = x509.load_pem_x509_certificate(get_ca(db, i2.id).cert_pem.encode("ascii"))
    issuer1 = _openssl_crl_issuer(tmp_path, "i1", current_crl(db, secrets, i1.id).crl_der)
    issuer2 = _openssl_crl_issuer(tmp_path, "i2", current_crl(db, secrets, i2.id).crl_der)
    assert i1_cert.subject.rfc4514_string() in issuer1
    assert i2_cert.subject.rfc4514_string() in issuer2
    assert issuer1 != issuer2


# --- AC-6: renewal without rekey ---------------------------------------------


def test_certs_issued_before_renewal_verify_against_renewed_ca(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    hierarchy = create_hierarchy(db, secrets, "Renew", root_years=1)
    original_root_pem = hierarchy.root.cert_pem
    leaf = issue_and_store(
        db,
        secrets,
        profile=Profile.server,
        subject_cn="pre-renewal.lan",
        sans=["DNS:pre-renewal.lan"],
        issuer_id=hierarchy.intermediate.id,
    )

    renew_in_place(db, secrets, hierarchy.root.id, years=30)

    # Direct check on the renewed root itself, independent of openssl: see
    # the CAUTION comment on _openssl_verify above for why a chain check
    # alone cannot prove the root's own self-signature is valid.
    original_root_cert = x509.load_pem_x509_certificate(original_root_pem.encode("ascii"))
    renewed_root_cert = x509.load_pem_x509_certificate(
        get_ca(db, hierarchy.root.id).cert_pem.encode("ascii")
    )
    assert renewed_root_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == original_root_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    renewed_root_cert.verify_directly_issued_by(renewed_root_cert)

    renewed_chain = _chain_pem(db, hierarchy.intermediate.id)
    assert _openssl_verify(tmp_path, "renewed-chain", leaf.row.cert_pem, renewed_chain)

    # Counter-check: a root rebuilt with a FRESH key instead (same subject,
    # different key material -- as if it had been re-created rather than
    # renewed) must fail the very same verification. This is what proves the
    # positive check above is measuring key reuse, not just PEM presence.
    fresh_root_cert, _fresh_root_key = create_root("Renew Root CA", "ecdsa-p256", years=30)
    rekeyed_chain = get_ca(db, hierarchy.intermediate.id).cert_pem + fresh_root_cert.public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")
    assert not _openssl_verify(tmp_path, "rekeyed-chain", leaf.row.cert_pem, rekeyed_chain)
