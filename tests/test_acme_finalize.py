"""Spec 0012 FR-1/FR-2, AC-2/AC-3/AC-4: finalizing an order with a CSR and
downloading the certificate chain that comes out of it."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from acme_client import Acme, b64, rsa_key
from acme_orders import (
    BASE,
    Flow,
    assert_problem,
    csr_der,
    db_session,
    path_of,
    rsa_signing_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cabin.acme import service
from cabin.acme.api_finalize import RETRY_AFTER_SECONDS
from cabin.acme.models import AcmeOrder
from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate, CertSource
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory

PEM_CHAIN_TYPE = "application/pem-certificate-chain"
PROBLEM_TYPE = "application/problem+json"
#: 125 characters: a name new-order accepts (a DNS identifier may be 253)
#: and ``leaf.MAX_CN_LENGTH`` cannot hold.
LONG_NAME = f"{'a' * 60}.{'b' * 60}.lan"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        db = create_session_factory(cfg.db_url)()
        try:
            set_setting(db, BASE_URL, BASE)
            set_setting(db, ACME_ENABLED, TRUE)
            ca_service.create_hierarchy(
                db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin test"
            )
        finally:
            db.close()
        yield c


@pytest.fixture
def acme(client: TestClient) -> Acme:
    return Acme(client)


def certificates(cfg: Config) -> list[Certificate]:
    db = db_session(cfg)
    try:
        return list(db.scalars(select(Certificate).order_by(Certificate.id)).all())
    finally:
        db.close()


def count_certificates(cfg: Config) -> int:
    db = db_session(cfg)
    try:
        return db.scalar(select(func.count()).select_from(Certificate)) or 0
    finally:
        db.close()


def pem_blocks(text: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(text.encode("ascii"))


def test_finalize_happy_path(acme: Acme, cfg: Config) -> None:
    """FR-1: a ready order plus a matching CSR becomes a certificate, the
    order turns valid, and it names where the certificate can be fetched."""
    flow = Flow(acme, cfg, "nas.lan", "www.nas.lan")
    flow.make_ready()
    assert flow.order()["status"] == "ready"

    finalized = flow.finalize(csr_der("nas.lan", "www.nas.lan"))

    assert finalized.status_code == 200, finalized.text
    body = finalized.json()
    assert body["status"] == "valid"
    assert body["certificate"].startswith(f"{BASE}/acme/cert/")
    # ...and the order says the same thing when read back
    assert flow.order()["certificate"] == body["certificate"]

    rows = certificates(cfg)
    assert len(rows) == 1
    # FR-7: an ACME-issued certificate says so in the inventory
    assert rows[0].source == CertSource.acme
    assert set(rows[0].sans) == {"DNS:nas.lan", "DNS:www.nas.lan"}
    # spec 0007 FR-6: issued through the normal path, so it carries the CDP
    leaf = x509.load_pem_x509_certificate(rows[0].cert_pem.encode("ascii"))
    points = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert points[0].full_name is not None


def test_finalize_accepts_a_csr_without_a_subject(acme: Acme, cfg: Config) -> None:
    """RFC 8555 7.4 lets the CSR carry its names in the SAN alone -- which is
    exactly what the certbot library produces. The CN then comes from the
    order rather than from nowhere."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()

    finalized = flow.finalize(csr_der("nas.lan", common_name=None))

    assert finalized.status_code == 200, finalized.text
    assert certificates(cfg)[0].subject_cn == "nas.lan"


def test_finalize_issues_for_a_name_no_common_name_can_hold(acme: Acme, cfg: Config) -> None:
    """A DNS identifier may be 253 characters; a common name may be 64. The
    names that matter are the SANs, so a name too long to be a CN is issued
    with no subject at all rather than refused -- which is what it used to
    be, permanently, since the client's CSR was fine and retrying it could
    never help."""
    flow = Flow(acme, cfg, LONG_NAME)
    flow.make_ready()

    flow.finalize_ok(csr_der(LONG_NAME, common_name=None))

    leaf = flow.leaf()
    assert list(leaf.subject) == []
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == [LONG_NAME]
    # RFC 5280 4.2.1.6: an empty subject makes the SAN the only name in the
    # certificate, and it must then be marked critical.
    assert san.critical is True
    assert certificates(cfg)[0].subject_cn == ""


def test_finalize_takes_the_first_identifier_that_fits_the_common_name(
    acme: Acme, cfg: Config
) -> None:
    """FR-1: the CN is a courtesy copy of one of the order's names, so the
    order of the identifiers must not decide whether issuance works at all."""
    flow = Flow(acme, cfg, LONG_NAME, "nas.lan")
    flow.make_ready()

    flow.finalize_ok(csr_der(LONG_NAME, "nas.lan", common_name=None))

    leaf = flow.leaf()
    assert [attribute.value for attribute in leaf.subject] == ["nas.lan"]
    assert set(certificates(cfg)[0].sans) == {f"DNS:{LONG_NAME}", "DNS:nas.lan"}


def test_finalize_matches_wildcard_and_ip_identifiers(acme: Acme, cfg: Config) -> None:
    """FR-1: a wildcard identifier matches the wildcard SAN, and an IP
    identifier is compared as an address, not as text."""
    flow = Flow(acme, cfg, "*.nas.lan", "192.168.1.10")
    flow.make_ready()

    finalized = flow.finalize(csr_der("*.nas.lan", "192.168.1.10", common_name="*.nas.lan"))

    assert finalized.status_code == 200, finalized.text
    assert set(certificates(cfg)[0].sans) == {"DNS:*.nas.lan", "IP:192.168.1.10"}


def test_finalize_requires_ready_order(acme: Acme, cfg: Config) -> None:
    """FR-1: an order whose names are not proven yet cannot be finalized, and
    RFC 8555 7.4 has a problem type that says exactly that."""
    flow = Flow(acme, cfg, "nas.lan")

    refused = flow.finalize(csr_der("nas.lan"))

    assert_problem(refused, "orderNotReady", 403)
    assert flow.order()["status"] == "pending"
    assert count_certificates(cfg) == 0


def test_finalize_requires_a_verified_jws(acme: Acme, cfg: Config) -> None:
    """The 0010 stub verified nothing because it did nothing. Now that it
    issues, an unsigned or wrongly signed request must not get near the CA."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    path = path_of(f"{flow.order_url}/finalize")

    unsigned = acme.post_body(path, {"csr": b64(csr_der("nas.lan"))})
    assert unsigned.status_code == 400, unsigned.text

    # a JWS from a key that has no account here
    stranger = acme.post(path, rsa_key(), {"csr": b64(csr_der("nas.lan"))})
    assert stranger.status_code in (400, 403), stranger.text

    # ...and one signed by another account's key, naming its own kid
    other = Flow(acme, cfg, "other.lan")
    hijack = acme.post(
        path,
        other.key,
        {"csr": b64(csr_der("nas.lan"))},
        kid=other.kid,
        url=f"{BASE}{path}",
    )
    assert_problem(hijack, "unauthorized", 403)
    assert count_certificates(cfg) == 0


def test_finalize_csr_must_match_identifiers(acme: Acme, cfg: Config) -> None:
    """AC-2: the CSR's SAN set must *equal* the order's identifiers -- one
    name too many and one too few are both refused, and each says which."""
    flow = Flow(acme, cfg, "nas.lan", "www.nas.lan")
    flow.make_ready()

    extra = flow.finalize(csr_der("nas.lan", "www.nas.lan", "evil.lan"))
    assert_problem(extra, "badCSR", 400)
    assert "evil.lan" in extra.json()["detail"]

    missing = flow.finalize(csr_der("nas.lan"))
    assert_problem(missing, "badCSR", 400)
    assert "www.nas.lan" in missing.json()["detail"]

    # DNS is case-insensitive, so this one is not a mismatch at all
    ok = flow.finalize(csr_der("NAS.LAN", "WWW.NAS.LAN", common_name="NAS.LAN"))
    assert ok.status_code == 200, ok.text
    assert flow.order()["status"] == "valid"


def test_finalize_bad_csr_variants(acme: Acme, cfg: Config) -> None:
    """AC-2: every way a CSR can be unusable is its own ``badCSR`` detail,
    and none of them moves the order off ``ready``."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()

    details: list[str] = []
    for payload in (
        {"csr": b64(b"not a csr at all")},
        {"csr": b64(csr_der("nas.lan", tamper=True))},
        {"csr": b64(csr_der("nas.lan", common_name="other.lan"))},
        {"csr": b64(csr_der(common_name="nas.lan"))},
    ):
        refused = flow.post(f"{flow.order_url}/finalize", payload)
        assert_problem(refused, "badCSR", 400)
        details.append(refused.json()["detail"])
        assert flow.order()["status"] == "ready"

    # each case says something different -- "badCSR" alone is not actionable
    assert len(set(details)) == len(details), details
    assert "other.lan" in details[2]

    # a payload that is not base64url at all is malformed, not a bad CSR
    assert_problem(flow.post(f"{flow.order_url}/finalize", {"csr": "***"}), "malformed", 400)
    assert_problem(flow.post(f"{flow.order_url}/finalize", {}), "malformed", 400)
    assert count_certificates(cfg) == 0


def test_finalize_refuses_a_weak_csr_key(acme: Acme, cfg: Config) -> None:
    """A CSR names the key cabin is asked to certify for a year, so it is
    held to the same floor as an account key (``jws.MIN_RSA_BITS``). Without
    this, a 1024-bit RSA key -- factorable, and refused as an account key
    two requests earlier -- would come back signed by cabin's CA."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()

    refused = flow.finalize(csr_der("nas.lan", key=rsa_signing_key(1024)))

    assert_problem(refused, "badCSR", 400)
    assert "1024" in refused.json()["detail"]
    assert flow.order()["status"] == "ready"

    # ...and a curve cabin does not issue on is refused the same way
    weak_curve = flow.finalize(csr_der("nas.lan", key=ec.generate_private_key(ec.SECP192R1())))
    assert_problem(weak_curve, "badCSR", 400)
    assert count_certificates(cfg) == 0


def test_finalize_accepts_every_key_type_cabin_issues(acme: Acme, cfg: Config) -> None:
    """The other side of the floor: the key types a client may actually
    bring -- RSA at the minimum size, both allowed curves, Ed25519."""
    keys = [
        rsa_signing_key(2048),
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP384R1()),
        ed25519.Ed25519PrivateKey.generate(),
    ]
    for index, key in enumerate(keys):
        flow = Flow(acme, cfg, f"nas{index}.lan")
        flow.make_ready()

        finalized = flow.finalize(csr_der(f"nas{index}.lan", key=key))

        assert finalized.status_code == 200, finalized.text
    assert count_certificates(cfg) == len(keys)


def test_finalize_is_idempotent(acme: Acme, cfg: Config) -> None:
    """AC-3: finalizing twice hands back the same certificate. A client that
    lost the first response must not be charged a second certificate."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    csr = csr_der("nas.lan")

    first = flow.finalize(csr)
    second = flow.finalize(csr)
    # ...and a different CSR does not get a second certificate either
    third = flow.finalize(csr_der("nas.lan"))

    assert first.status_code == second.status_code == third.status_code == 200
    url = first.json()["certificate"]
    assert second.json()["certificate"] == url
    assert third.json()["certificate"] == url
    assert count_certificates(cfg) == 1


def test_only_one_finalize_can_claim_an_order(acme: Acme, cfg: Config) -> None:
    """AC-3, the race the idempotency test above cannot reach over HTTP: two
    finalize requests that arrive at the same moment both read a ready order,
    and if both were allowed to proceed the account would be charged two
    certificates for one authorization -- with only one of them reachable,
    since the order can name exactly one.

    Driven at the claim itself, which is where the guarantee lives: a
    threaded HTTP race would prove the same thing occasionally.
    """
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()

    first = db_session(cfg)
    second = db_session(cfg)
    try:
        order_a = service.get_order(first, flow.order_id)
        order_b = service.get_order(second, flow.order_id)
        assert order_a is not None and order_b is not None
        won = service.claim_for_issuance(first, order_a)
        lost = service.claim_for_issuance(second, order_b)
    finally:
        first.close()
        second.close()

    assert (won, lost) == (True, False)
    # ...and the loser's request is answered with the order, not an error
    assert flow.order()["status"] == "processing"


def test_a_finalize_that_loses_the_race_is_told_when_to_come_back(
    acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RFC 8555 7.4: the loser of the race above is answered with a
    ``processing`` order, and a client that is told to poll should be told
    how long to wait -- otherwise every client picks its own interval, and
    the impatient ones hammer the CA while it is signing.

    The race is forced rather than hoped for: the claim runs (so the order
    really is ``processing``, as the winner just left it) and then reports
    the loss this request would have seen a microsecond later.
    """
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    winner = service.claim_for_issuance

    def lost(db: Session, order: AcmeOrder) -> bool:
        winner(db, order)
        return False

    monkeypatch.setattr(service, "claim_for_issuance", lost)

    answered = flow.finalize(csr_der("nas.lan"))

    assert answered.status_code == 200, answered.text
    assert answered.json()["status"] == "processing"
    assert answered.headers["retry-after"] == str(RETRY_AFTER_SECONDS)
    assert count_certificates(cfg) == 0


def test_certificate_download_chain(acme: Acme, cfg: Config) -> None:
    """FR-2/AC-4: leaf, intermediate and root as one PEM chain, under the
    media type RFC 8555 7.4.2 names."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    url = flow.finalize(csr_der("nas.lan")).json()["certificate"]

    downloaded = flow.certificate(url)

    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.headers["content-type"].startswith(PEM_CHAIN_TYPE)
    chain = pem_blocks(downloaded.text)
    assert len(chain) == 3
    leaf, intermediate, root = chain
    assert {name.value for name in leaf.subject} == {"nas.lan"}
    # AC-1: the chain really chains -- each link is issued by the next
    assert leaf.issuer == intermediate.subject
    assert intermediate.issuer == root.subject
    assert root.issuer == root.subject
    stored = certificates(cfg)[0]
    assert leaf.public_bytes(serialization.Encoding.PEM).decode("ascii") == stored.cert_pem


def test_certificate_ownership_enforced(acme: Acme, cfg: Config) -> None:
    """AC-4: the certificate URL is not a capability. Only the account whose
    order produced it may fetch it."""
    owner = Flow(acme, cfg, "nas.lan")
    owner.make_ready()
    url = owner.finalize(csr_der("nas.lan")).json()["certificate"]

    stranger = Flow(acme, cfg, "other.lan")
    refused = stranger.certificate(url)

    assert_problem(refused, "unauthorized", 403)
    # ...and a certificate cabin issued outside ACME is not fetchable at all
    assert_problem(stranger.certificate(f"{BASE}/acme/cert/999999"), "malformed", 404)


def test_certificate_ids_that_cannot_be_rows_are_not_found(acme: Acme, cfg: Config) -> None:
    """FR-2: ``/acme/cert/{id}`` is a public path, so every id that is not a
    row is the same 404 problem document -- including the ones that merely
    look like integers.

    ``"9" * 23`` is past what the id column can hold, ``"²"`` is a digit to
    ``str.isdigit`` and not to ``int``, and ``01`` is a second spelling of 1.
    All three used to escape as a bare 500 with no ``Replay-Nonce``, which
    strands the client: the nonce it signed this request with has already
    been spent, and it has nothing to sign the next one with.
    """
    owner = Flow(acme, cfg, "nas.lan")
    owner.make_ready()
    real_id = owner.finalize_ok(csr_der("nas.lan")).rsplit("/", 1)[1]

    for raw in ("9" * 23, "²", f"0{real_id}", "-1", "1.0"):
        refused = owner.certificate(f"{BASE}/acme/cert/{raw}")

        assert_problem(refused, "malformed", 404)
        assert refused.headers["content-type"].startswith(PROBLEM_TYPE)
        assert refused.headers["replay-nonce"]
    # the canonical spelling of the same id still works
    assert owner.certificate(f"{BASE}/acme/cert/{real_id}").status_code == 200


def test_finalize_stores_the_default_resolved_issuer(acme: Acme, cfg: Config) -> None:
    """Spec 0017 FR-6: ACME passes no ``issuer_id`` (0019 gives it one), so a
    finalize with exactly one active issuer stores that issuer's id on the
    certificate row -- the default rule that keeps a single-CA instance
    working exactly as it did before this spec."""
    db = db_session(cfg)
    try:
        issuer_id = ca_service.active_issuers(db)[0].id
    finally:
        db.close()

    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    flow.finalize_ok(csr_der("nas.lan"))

    db = db_session(cfg)
    try:
        row = db.scalars(select(Certificate).order_by(Certificate.id)).first()
        assert row is not None
        assert row.issuer_id == issuer_id
    finally:
        db.close()


def test_finalize_with_multiple_active_issuers_is_a_clean_error(acme: Acme, cfg: Config) -> None:
    """Spec 0017 FR-6/Out of Scope: with two active issuers and no way for
    ACME to name one (0019's gap, not this spec's to close), a finalize must
    still answer with an RFC 8555 problem document -- not a raw crash -- and
    must not leave the order wedged: the claim is released so the client can
    retry once an operator has retired one of the two issuers."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    db = db_session(cfg)
    try:
        ca_service.create_hierarchy(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "second"
        )
    finally:
        db.close()

    failed = flow.finalize(csr_der("nas.lan"))

    assert_problem(failed, "serverInternal", 500)
    assert count_certificates(cfg) == 0
    db = db_session(cfg)
    try:
        order = db.get(AcmeOrder, flow.order_id)
        assert order is not None
        assert order.certificate_id is None
    finally:
        db.close()
    assert flow.order()["status"] == "ready"


def test_finalize_leaves_no_certificate_when_the_ca_is_missing(
    acme: Acme, cfg: Config, tmp_path: Path
) -> None:
    """The order must not be left claimed by a failed issuance: whatever went
    wrong, the client has to be able to try again."""
    flow = Flow(acme, cfg, "nas.lan")
    flow.make_ready()
    db = db_session(cfg)
    try:
        db.execute(ca_service.CACertificate.__table__.delete())
        db.commit()
    finally:
        db.close()

    failed = flow.finalize(csr_der("nas.lan"))

    assert failed.status_code == 500, failed.text
    assert count_certificates(cfg) == 0
    db = db_session(cfg)
    try:
        order = db.get(AcmeOrder, flow.order_id)
        assert order is not None
        assert order.certificate_id is None
    finally:
        db.close()
    assert flow.order()["status"] == "ready"
