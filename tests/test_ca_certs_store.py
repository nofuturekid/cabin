"""Tests for cabin.ca.certs: storing issued/signed leaf certificates with
sealed server-generated keys (spec 0005 FR-5, AC-5) and the inventory
query behind /certs (spec 0006 FR-2/FR-3, AC-1..AC-3)."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from cabin.ca.certs import (
    Certificate,
    CertStatus,
    certificate_status,
    get_certificate,
    issue_and_store,
    key_pem,
    list_certificates,
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


# --- spec 0006 FR-2/FR-3: inventory query and status ---------------------------

_STUB_PEM = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"


def _insert(
    db: Session,
    *,
    cn: str = "host.lan",
    sans: list[str] | None = None,
    serial: str | None = None,
    days_left: int = 365,
    created_at: datetime | None = None,
    with_key: bool = True,
) -> Certificate:
    """A certificate row without going through issuance: the inventory query
    only reads columns, and a 60-row pagination fixture must not cost 60 key
    generations."""
    now = datetime.now(UTC)
    row = Certificate(
        serial_hex=serial if serial is not None else f"{db.query(Certificate).count() + 1:016x}",
        subject_cn=cn,
        sans_json=json.dumps(sans if sans is not None else [f"DNS:{cn}"]),
        profile="server",
        not_before=now.isoformat(),
        not_after=(now + timedelta(days=days_left)).isoformat(),
        cert_pem=_STUB_PEM,
        key_sealed="sealed" if with_key else None,
        created_at=(created_at or now).replace(tzinfo=None),
    )
    db.add(row)
    db.commit()
    return row


def _cns(rows: list[Certificate]) -> list[str]:
    return [row.subject_cn for row in rows]


def test_list_orders_newest_first(db: Session) -> None:
    now = datetime.now(UTC)
    _insert(db, cn="old.lan", created_at=now - timedelta(days=2))
    _insert(db, cn="middle.lan", created_at=now - timedelta(days=1))
    _insert(db, cn="new.lan", created_at=now)

    rows, total = list_certificates(db)

    assert _cns(rows) == ["new.lan", "middle.lan", "old.lan"]
    assert total == 3


def test_filter_q_matches_cn(db: Session) -> None:
    _insert(db, cn="nas.lan")
    _insert(db, cn="printer.lan")

    rows, total = list_certificates(db, q="NAS")

    assert _cns(rows) == ["nas.lan"]
    assert total == 1
    # FR-2: the term is trimmed, and an over-long one is capped rather than
    # handed to the database as-is
    assert _cns(list_certificates(db, q="  nas  ")[0]) == ["nas.lan"]
    assert list_certificates(db, q="x" * 5000)[1] == 0


def test_filter_q_matches_san(db: Session) -> None:
    _insert(db, cn="a.lan", sans=["DNS:a.lan", "DNS:vpn.example.org"])
    _insert(db, cn="b.lan", sans=["DNS:b.lan"])

    rows, total = list_certificates(db, q="vpn.example")

    assert _cns(rows) == ["a.lan"]
    assert total == 1


def test_filter_q_matches_serial(db: Session) -> None:
    _insert(db, cn="a.lan", serial="00ff1234abcd")
    _insert(db, cn="b.lan", serial="9911223344ee")

    # serials are stored lowercase hex; an operator pasting the uppercase
    # form from another tool must still find the certificate.
    rows, total = list_certificates(db, q="FF1234")

    assert _cns(rows) == ["a.lan"]
    assert total == 1


def test_filter_status_expired(db: Session) -> None:
    _insert(db, cn="gone.lan", days_left=-1)
    _insert(db, cn="soon.lan", days_left=10)
    _insert(db, cn="fine.lan", days_left=365)

    assert _cns(list_certificates(db, status="expired")[0]) == ["gone.lan"]
    # the three states partition the inventory: no row counted twice or lost
    assert _cns(list_certificates(db, status="expiring")[0]) == ["soon.lan"]
    assert _cns(list_certificates(db, status="valid")[0]) == ["fine.lan"]
    assert list_certificates(db, status="all")[1] == 3

    # the caller may fix the clock, so a page's filter and its badges agree
    # even across a tick -- and so this is testable at a chosen instant
    later = datetime.now(UTC) + timedelta(days=340)
    assert _cns(list_certificates(db, status="expiring", now=later)[0]) == ["fine.lan"]
    assert _cns(list_certificates(db, status="valid", now=later)[0]) == []


def test_filter_combined(db: Session) -> None:
    _insert(db, cn="nas.lan", days_left=-1)
    _insert(db, cn="nas-backup.lan", days_left=365)
    _insert(db, cn="printer.lan", days_left=-1)

    rows, total = list_certificates(db, q="nas", status="expired")

    assert _cns(rows) == ["nas.lan"]
    assert total == 1


def test_pagination_pages(db: Session) -> None:
    now = datetime.now(UTC)
    for i in range(60):
        _insert(db, cn=f"host{i:02d}.lan", created_at=now - timedelta(minutes=i))

    first, total = list_certificates(db, page=1)
    second, total_again = list_certificates(db, page=2)

    assert len(first) == 50
    assert len(second) == 10
    # total is the size of the whole filtered set, not of the page -- the
    # pager needs it to know there is a page 2 at all
    assert total == total_again == 60
    assert first[0].subject_cn == "host00.lan"
    assert second[-1].subject_cn == "host59.lan"
    assert not set(_cns(first)) & set(_cns(second))


def test_pagination_out_of_range(db: Session) -> None:
    _insert(db, cn="only.lan")

    rows, total = list_certificates(db, page=99)

    assert rows == []
    assert total == 1
    # a hand-edited ?page=0 must not turn into a negative OFFSET
    assert _cns(list_certificates(db, page=0)[0]) == ["only.lan"]
    # ...and one past the database's integer range must be clamped here, so
    # every caller is safe: an OFFSET that big is an error, not a big number
    assert list_certificates(db, page=2**63)[0] == []
    assert list_certificates(db, page=2**63)[1] == 1


def test_status_boundaries() -> None:
    now = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

    assert certificate_status(now + timedelta(days=31), now) == CertStatus.valid
    # exactly at the window edge the operator should already be warned
    assert certificate_status(now + timedelta(days=30), now) == CertStatus.expiring
    assert certificate_status(now + timedelta(seconds=1), now) == CertStatus.expiring
    assert certificate_status(now - timedelta(seconds=1), now) == CertStatus.expired
    # not_after is the last instant of validity; at exactly now it is over
    assert certificate_status(now, now) == CertStatus.expired
