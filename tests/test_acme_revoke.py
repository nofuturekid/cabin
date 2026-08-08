"""Spec 0012 FR-3/FR-6, AC-5: revoking a certificate over ACME, authorized
either by the account that ordered it or by the certificate's own key."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from acme_client import Acme, AcmeKey, b64, ec_key
from acme_orders import BASE, Flow, assert_problem, csr_der, db_session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select

from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import crl as ca_crl
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate
from cabin.ca.revocation import RevocationReason
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory

REVOKE_PATH = "/acme/revoke-cert"


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
        finally:
            db.close()
        yield c


@pytest.fixture
def issuer_id(client: TestClient, cfg: Config) -> int:
    db = create_session_factory(cfg.db_url)()
    try:
        hierarchy = ca_service.create_hierarchy(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin test"
        )
        return hierarchy.intermediate.id
    finally:
        db.close()


@pytest.fixture
def acme(client: TestClient, issuer_id: int) -> Acme:
    return Acme(client, issuer_id=issuer_id)


def issue(acme: Acme, cfg: Config, name: str = "nas.lan", key: AcmeKey | None = None) -> Flow:
    """One account, one order, one issued certificate."""
    flow = Flow(acme, cfg, name)
    flow.make_ready()
    flow.finalize_ok(csr_der(name, key=key.private if key is not None else None))
    return flow


def leaf_der(flow: Flow) -> bytes:
    return flow.leaf().public_bytes(serialization.Encoding.DER)


def revoke(acme: Acme, flow: Flow, der: bytes, reason: object = None) -> Response:
    payload: dict[str, Any] = {"certificate": b64(der)}
    if reason is not None:
        payload["reason"] = reason
    return acme.post(REVOKE_PATH, flow.key, payload, kid=flow.kid)


def crl_serials(cfg: Config) -> set[int]:
    """The serials on the CRL of whichever issuer signed the one certificate
    these tests issue.

    ``GET /crl`` is gone with no alias (spec 0017 AC-10); the replacement
    route ``/crl/{issuer_id}`` lives in ``web/crl_ui.py``, which is Security's
    file under the spec 0017 work split, so this goes through the service
    layer (:mod:`cabin.ca.crl`, Backend's) instead of a second front door's
    HTTP route.
    """
    issuer_id = stored(cfg).issuer_id
    db = db_session(cfg)
    try:
        state = ca_crl.current_crl(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), issuer_id
        )
    finally:
        db.close()
    crl = x509.load_der_x509_crl(state.crl_der)
    return {entry.serial_number for entry in crl}


def stored(cfg: Config) -> Certificate:
    db = db_session(cfg)
    try:
        row = db.scalars(select(Certificate).order_by(Certificate.id)).first()
        assert row is not None
        return row
    finally:
        db.close()


def test_revoke_by_account(acme: Acme, cfg: Config, client: TestClient) -> None:
    """AC-5: the account that ordered the certificate may revoke it, and the
    serial is on the CRL afterwards -- a revocation nobody can see is not one."""
    flow = issue(acme, cfg)
    der = leaf_der(flow)
    assert int(stored(cfg).serial_hex, 16) not in crl_serials(cfg)

    revoked = revoke(acme, flow, der, reason=1)

    assert revoked.status_code == 200, revoked.text
    assert revoked.content == b""
    after = stored(cfg)
    assert after.revoked_at is not None
    assert after.revocation_reason == RevocationReason.key_compromise
    assert int(after.serial_hex, 16) in crl_serials(cfg)


def test_revoke_by_certificate_key(acme: Acme, cfg: Config, client: TestClient) -> None:
    """FR-3/AC-5: RFC 8555 7.6's second door -- whoever holds the
    certificate's own private key may revoke it, with no account at all."""
    cert_key = ec_key()
    flow = issue(acme, cfg, key=cert_key)
    der = leaf_der(flow)

    # jwk mode: the JWS is signed by the certificate's key pair itself
    revoked = acme.post(REVOKE_PATH, cert_key, {"certificate": b64(der)})

    assert revoked.status_code == 200, revoked.text
    assert stored(cfg).revoked_at is not None
    assert int(stored(cfg).serial_hex, 16) in crl_serials(cfg)


def test_revoke_by_a_key_that_is_not_the_certificates(acme: Acme, cfg: Config) -> None:
    """The jwk door only opens for the *certificate's* key: any other key,
    with or without an account, is refused."""
    flow = issue(acme, cfg, key=ec_key())
    der = leaf_der(flow)

    refused = acme.post(REVOKE_PATH, ec_key(), {"certificate": b64(der)})

    assert_problem(refused, "unauthorized", 403)
    assert stored(cfg).revoked_at is None


def test_revoke_reason_validation(acme: Acme, cfg: Config) -> None:
    """AC-5: only the reasons spec 0007 can put on a CRL are accepted.
    ``removeFromCRL`` (8) implies delta CRLs cabin does not publish, and
    ``certificateHold`` (6) implies un-revocation it does not offer."""
    flow = issue(acme, cfg)
    der = leaf_der(flow)

    for code in (2, 6, 8, 9, 10, 42, -1):
        assert_problem(revoke(acme, flow, der, reason=code), "badRevocationReason", 400)
        assert stored(cfg).revoked_at is None

    # not a code at all
    assert_problem(revoke(acme, flow, der, reason="keyCompromise"), "malformed", 400)

    accepted = revoke(acme, flow, der, reason=4)
    assert accepted.status_code == 200, accepted.text
    assert stored(cfg).revocation_reason == RevocationReason.superseded


def test_revoke_already_revoked(acme: Acme, cfg: Config) -> None:
    """AC-5: RFC 8555 7.6 has a problem type for the second attempt, and the
    first revocation's date must not move."""
    flow = issue(acme, cfg)
    der = leaf_der(flow)
    assert revoke(acme, flow, der).status_code == 200
    first = stored(cfg).revoked_at

    again = revoke(acme, flow, der)

    assert_problem(again, "alreadyRevoked", 400)
    assert stored(cfg).revoked_at == first


def test_revoke_foreign_certificate(acme: Acme, cfg: Config) -> None:
    """AC-5: a certificate cabin did not issue is not cabin's to revoke --
    and that answer must not depend on the serial being unknown, so this one
    borrows a serial cabin *did* issue."""
    flow = issue(acme, cfg)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "elsewhere.lan")])
    now = datetime.now(UTC)
    foreign = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(int(stored(cfg).serial_hex, 16))
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    refused = revoke(acme, flow, foreign.public_bytes(serialization.Encoding.DER))

    assert_problem(refused, "unauthorized", 403)
    assert stored(cfg).revoked_at is None
    assert_problem(revoke(acme, flow, b"not a certificate"), "malformed", 400)


def test_revoke_needs_the_ordering_account(acme: Acme, cfg: Config) -> None:
    """AC-4/AC-5: another account's kid does not authorize a revocation."""
    flow = issue(acme, cfg)
    der = leaf_der(flow)
    stranger = Flow(acme, cfg, "other.lan")

    refused = acme.post(REVOKE_PATH, stranger.key, {"certificate": b64(der)}, kid=stranger.kid)

    assert_problem(refused, "unauthorized", 403)
    assert stored(cfg).revoked_at is None


def test_audit_acme_issue_revoke(acme: Acme, cfg: Config) -> None:
    """FR-6: both halves of a certificate's ACME life are in the log, with
    the account's key thumbprint as the actor."""
    flow = issue(acme, cfg)
    der = leaf_der(flow)
    assert revoke(acme, flow, der, reason=4).status_code == 200

    db = db_session(cfg)
    try:
        events = list(
            db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.action.in_(
                        [
                            AuditAction.acme_certificate_issued,
                            AuditAction.acme_certificate_revoked,
                        ]
                    )
                )
                .order_by(AuditEvent.id)
            ).all()
        )
    finally:
        db.close()

    assert [event.action for event in events] == [
        AuditAction.acme_certificate_issued,
        AuditAction.acme_certificate_revoked,
    ]
    assert all(event.actor_kind == "acme" for event in events)
    assert all(event.actor_label.startswith("acme:") for event in events)
    assert all(event.target_type == "certificate" for event in events)
    issued, revoked = events
    assert issued.detail is not None and issued.detail["sans"] == ["DNS:nas.lan"]
    assert revoked.detail is not None and revoked.detail["reason"] == "superseded"
    # the CSR itself is bulky and adds nothing the certificate does not say
    assert "csr" not in issued.detail
