"""Spec 0011: the challenge trigger, the background validation it schedules
and the status transitions that follow (FR-2, FR-3, FR-7, FR-8; AC-5, AC-6).

These tests drive the real HTTP surface with the hand-rolled client of spec
0010 and let the real validator talk to a real local server -- the only
substitution is where an identifier resolves to (see ``challenge_servers``).
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from acme_client import Acme, rsa_key
from challenge_servers import closed_port, http_server, point_at, serves
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.acme import service
from cabin.acme.models import AcmeAuthorization, AcmeChallenge
from cabin.acme.validation import dns01, keyauth
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import (
    ACME_ENABLED,
    ALLOW_PRIVATE_VALIDATION_TARGETS,
    BASE_URL,
    DNS_RESOLVERS,
    TRUE,
    get_flag,
    get_setting,
    set_setting,
)
from cabin.store import create_session_factory

BASE = "http://testserver"
ERROR_PREFIX = "urn:ietf:params:acme:error:"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        db = db_session(cfg)
        try:
            set_setting(db, BASE_URL, BASE)
            set_setting(db, ACME_ENABLED, TRUE)
        finally:
            db.close()
        yield c


@pytest.fixture
def issuer_id(client: TestClient, cfg: Config) -> int:
    db = db_session(cfg)
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


def db_session(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def path_of(url: str) -> str:
    return url.removeprefix(BASE)


class Flow:
    """One account, one order, and the challenge under test.

    A second, independent copy of ``acme_orders.Flow`` (spec 0019 work split
    R9): this file drives real HTTP validation against a local server, which
    ``acme_orders.Flow`` has no need to know about, so the two are not
    merged. It inherits its issuer from ``acme`` the same way, for the same
    reason -- see ``acme_orders.Flow``'s docstring.
    """

    def __init__(self, acme: Acme, *names: str) -> None:
        self.acme = acme
        self.key = rsa_key()
        registration = acme.post(acme.new_account_path, self.key, {"termsOfServiceAgreed": True})
        assert registration.status_code == 201, registration.text
        self.kid = registration.headers["location"]
        placed = acme.post(
            "/acme/new-order",
            self.key,
            {"identifiers": [{"type": "dns", "value": name} for name in names]},
            kid=self.kid,
        )
        assert placed.status_code == 201, placed.text
        self.order_url = placed.headers["location"]
        self.authz_urls: list[str] = placed.json()["authorizations"]

    def read(self, url: str) -> dict[str, Any]:
        """POST-as-GET: an empty payload, not an empty object."""
        response = self.acme.post(path_of(url), self.key, None, kid=self.kid)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    def order(self) -> dict[str, Any]:
        return self.read(self.order_url)

    def authz(self, index: int = 0) -> dict[str, Any]:
        return self.read(self.authz_urls[index])

    def challenge(self, kind: str, index: int = 0) -> dict[str, Any]:
        found: dict[str, Any] = next(
            entry for entry in self.authz(index)["challenges"] if entry["type"] == kind
        )
        return found

    def trigger(self, challenge: dict[str, Any]) -> Response:
        """RFC 8555 7.5.1's "please validate this": an empty JSON *object*."""
        return self.acme.post(path_of(challenge["url"]), self.key, {}, kid=self.kid)

    def key_authorization(self, challenge: dict[str, Any]) -> str:
        return keyauth.key_authorization(challenge["token"], self.key.thumbprint())


def well_known(challenge: dict[str, Any]) -> str:
    return f"/.well-known/acme-challenge/{challenge['token']}"


def assert_problem(resp: Response, kind: str, status: int) -> None:
    __tracebackhide__ = True
    assert resp.status_code == status, resp.text
    assert resp.json()["type"] == f"{ERROR_PREFIX}{kind}", resp.text


def events(cfg: Config, action: AuditAction) -> list[AuditEvent]:
    db = db_session(cfg)
    try:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all())
    finally:
        db.close()


# --- FR-2, FR-3, AC-5: the trigger ----------------------------------------------------


def test_trigger_sets_processing_and_is_idempotent(
    acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-5: the POST answers immediately with ``processing`` -- it does not
    wait for the validation -- and re-triggering never errors."""
    flow = Flow(acme, "nas.lan")
    challenge = flow.challenge("http-01")
    authorization = flow.key_authorization(challenge)

    with http_server(serves(authorization.encode(), path=well_known(challenge))) as server:
        point_at(monkeypatch, server.port)
        response = flow.trigger(challenge)

        assert response.status_code == 200, response.text
        body = response.json()
        # what the client is handed back is the *scheduled* challenge...
        assert body["status"] == "processing"
        assert body["url"] == challenge["url"]
        # ...with the Link RFC 8555 7.5.1 requires, so the client knows which
        # authorization to poll
        assert f'<{flow.authz_urls[0]}>;rel="up"' in response.headers["link"]
        # spec 0019 FR-11: /acme/chal/... is a global path -- it gains no
        # issuer segment, so unlike the two per-issuer paths it must not
        # also carry an index link naming a directory.
        assert 'rel="index"' not in response.headers["link"]

        # ...and by now the background task has run
        assert flow.challenge("http-01")["status"] == "valid"
        assert len(server.requests) == 1

        # re-triggering a valid challenge is a no-op, not an error
        again = flow.trigger(challenge)
        assert again.status_code == 200
        assert again.json()["status"] == "valid"
        assert len(server.requests) == 1

        # ...and neither is re-triggering one that is still being validated
        _set_status(cfg, challenge["url"], "processing")
        pending = flow.trigger(challenge)
        assert pending.status_code == 200
        assert pending.json()["status"] == "processing"
        assert len(server.requests) == 1


def test_trigger_needs_an_empty_object_not_a_post_as_get(
    acme: Acme, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-2: POST-as-GET reads the challenge and must not start anything --
    the two are the same URL and differ only in the payload."""
    flow = Flow(acme, "nas.lan")
    challenge = flow.challenge("http-01")

    with http_server(serves(b"wrong")) as server:
        point_at(monkeypatch, server.port)

        assert flow.read(challenge["url"])["status"] == "pending"
        assert server.requests == []


def _set_status(cfg: Config, challenge_url: str, status: str) -> None:
    """Put a challenge into a state the protocol cannot be driven into from
    outside -- ``processing`` only exists while a background task runs."""
    db = db_session(cfg)
    try:
        challenge = db.get(AcmeChallenge, challenge_url.rsplit("/", 1)[-1])
        assert challenge is not None
        challenge.status = status
        db.commit()
    finally:
        db.close()


# --- FR-7, AC-6: what a validated challenge changes ------------------------------------


def test_authorization_and_order_transitions(acme: Acme, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6: a valid challenge makes its authorization valid, and an order
    whose authorizations are all valid becomes ready."""
    flow = Flow(acme, "nas.lan", "www.nas.lan")
    first = flow.challenge("http-01", 0)

    with http_server(serves(flow.key_authorization(first).encode(), path=well_known(first))) as s:
        point_at(monkeypatch, s.port)
        flow.trigger(first)

    assert flow.authz(0)["status"] == "valid"
    assert flow.challenge("http-01", 0)["validated"]
    # one of two names is proven, so the order is not ready yet
    assert flow.authz(1)["status"] == "pending"
    assert flow.order()["status"] == "pending"

    second = flow.challenge("http-01", 1)
    with http_server(serves(flow.key_authorization(second).encode(), path=well_known(second))) as s:
        point_at(monkeypatch, s.port)
        flow.trigger(second)

    assert flow.authz(1)["status"] == "valid"
    assert flow.order()["status"] == "ready"

    # FR-2: nothing is left to prove for a valid authorization, so its other
    # challenges refuse to start
    assert_problem(flow.trigger(flow.challenge("dns-01", 0)), "malformed", 400)


def test_failed_challenge_keeps_authz_pending(acme: Acme, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6/FR-7: a failed challenge carries the problem document, and the
    authorization stays pending so the client can try another type."""
    flow = Flow(acme, "nas.lan")
    challenge = flow.challenge("http-01")

    with http_server(serves(b"not the key authorization")) as server:
        point_at(monkeypatch, server.port)
        flow.trigger(challenge)

    failed = flow.challenge("http-01")
    assert failed["status"] == "invalid"
    assert failed["error"]["type"] == f"{ERROR_PREFIX}incorrectResponse"
    assert "key authorization" in failed["error"]["detail"]
    assert failed["error"]["status"] == 400
    assert "validated" not in failed

    assert flow.authz()["status"] == "pending"
    assert flow.order()["status"] == "pending"
    # the other two challenge types are still startable
    assert flow.challenge("dns-01")["status"] == "pending"

    # FR-2: but this one is finished, and saying so beats pretending
    assert_problem(flow.trigger(failed), "malformed", 400)


def test_background_failure_never_leaves_a_challenge_processing(
    acme: Acme, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-3: whatever the validator does -- including raising something
    nobody anticipated -- the challenge ends up in a terminal state with a
    problem document rather than stuck in ``processing`` forever."""
    from cabin.acme.validation import http01

    def explode(attempt: object) -> None:
        raise RuntimeError("the validator itself is broken")

    monkeypatch.setattr(http01, "validate", explode)
    flow = Flow(acme, "nas.lan")

    flow.trigger(flow.challenge("http-01"))

    failed = flow.challenge("http-01")
    assert failed["status"] == "invalid"
    assert failed["error"]["type"] == f"{ERROR_PREFIX}serverInternal"


# --- FR-8: the audit trail -------------------------------------------------------------


def test_audit_challenge_events(acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-8: one event per attempt, naming the identifier and the challenge
    type -- and, when it failed, why."""
    flow = Flow(acme, "nas.lan")
    good = flow.challenge("http-01")

    with http_server(serves(flow.key_authorization(good).encode(), path=well_known(good))) as s:
        point_at(monkeypatch, s.port)
        flow.trigger(good)

    validated = events(cfg, AuditAction.acme_challenge_validated)
    assert len(validated) == 1
    assert validated[0].actor_kind == "acme"
    assert validated[0].target_type == "acme_challenge"
    assert validated[0].target_id == good["url"].rsplit("/", 1)[-1]
    assert validated[0].detail == {"identifier": "dns:nas.lan", "type": "http-01"}
    assert "nas.lan" in validated[0].summary

    other = Flow(acme, "other.lan")
    bad = other.challenge("http-01")
    with http_server(serves(b"", path="/nothing-here")) as server:
        point_at(monkeypatch, server.port)
        other.trigger(bad)

    failed = events(cfg, AuditAction.acme_challenge_failed)
    assert len(failed) == 1
    detail = failed[0].detail
    assert detail is not None
    assert detail["identifier"] == "dns:other.lan"
    assert detail["type"] == "http-01"
    assert "404" in detail["error"]
    # what the target answered is the client's own business, so here the log
    # and the challenge say the same thing
    assert detail["error"] == other.challenge("http-01")["error"]["detail"]


def test_connection_failures_do_not_describe_the_target_to_the_client(
    acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A challenge's error field is readable by whoever placed the order, and
    "connection refused" versus "refused by policy" versus "timed out" is a
    port scanner's read-out of an internal network. The client is told that
    cabin could not reach the name; the operator's audit log keeps the
    sentence that says why.
    """
    flow = Flow(acme, "nas.lan")
    challenge = flow.challenge("http-01")
    port = closed_port()
    point_at(monkeypatch, port)

    flow.trigger(challenge)

    shown = flow.challenge("http-01")["error"]
    assert shown["type"] == f"{ERROR_PREFIX}connection"
    assert "nas.lan" in shown["detail"]
    assert str(port) not in shown["detail"]
    assert "127.0.0.1" not in shown["detail"]
    assert "Connect" not in shown["detail"]

    logged = events(cfg, AuditAction.acme_challenge_failed)[0].detail
    assert logged is not None
    assert "could not connect" in logged["error"]
    assert str(port) in logged["error"]


# --- FR-2/FR-7: two triggers, one validation -------------------------------------------


def test_two_triggers_cannot_both_schedule_a_validation(acme: Acme, cfg: Config) -> None:
    """FR-2/FR-7: the move out of ``pending`` is a claim, not a read followed
    by a write.

    Two POSTs that arrive together both see a pending challenge; if both were
    allowed to schedule, two validations would race and one could write
    ``invalid`` over the other's ``valid`` -- leaving an order whose
    authorization is valid and whose challenge says it failed. The two
    sessions below are that race, deterministically.
    """
    flow = Flow(acme, "nas.lan")
    challenge_id = flow.challenge("http-01")["url"].rsplit("/", 1)[-1]

    first, second = db_session(cfg), db_session(cfg)
    try:
        one = service.get_challenge(first, challenge_id)
        two = service.get_challenge(second, challenge_id)
        assert one is not None and two is not None
        # both read the row while it was still pending
        assert one.status == "pending" and two.status == "pending"
        authz_one = service.get_authorization(first, one.authz_id)
        authz_two = service.get_authorization(second, two.authz_id)
        assert authz_one is not None and authz_two is not None

        assert service.begin_challenge(first, one, authz_one) is True
        assert service.begin_challenge(second, two, authz_two) is False
        assert two.status == "processing"
    finally:
        first.close()
        second.close()


def test_a_late_failure_cannot_undo_a_valid_challenge(acme: Acme, cfg: Config) -> None:
    """FR-7: a result only applies to the attempt that is still running. A
    straggler must not turn a proven challenge back into a failed one while
    its authorization stays valid."""
    flow = Flow(acme, "nas.lan")
    challenge_id = flow.challenge("http-01")["url"].rsplit("/", 1)[-1]
    db = db_session(cfg)
    try:
        challenge = service.get_challenge(db, challenge_id)
        assert challenge is not None
        authz = service.get_authorization(db, challenge.authz_id)
        assert authz is not None
        service.begin_challenge(db, challenge, authz)
        service.record_challenge_success(db, challenge, authz)

        service.record_challenge_failure(db, challenge, {"type": "late", "detail": "too late"})

        assert challenge.status == "valid"
        assert challenge.error_json is None
        assert authz.status == "valid"
    finally:
        db.close()


# --- FR-5/FR-9: the operator's side ----------------------------------------------------


def test_dns01_uses_the_configured_resolvers(
    acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-5: the setting is not decoration -- what an operator types into
    /settings is what the validator asks."""
    db = db_session(cfg)
    try:
        set_setting(db, DNS_RESOLVERS, "192.168.1.53, 10.0.0.53")
    finally:
        db.close()
    asked: list[tuple[str, tuple[str, ...]]] = []

    def lookup(name: str, resolvers: tuple[str, ...], timeout: float) -> list[str]:
        asked.append((name, resolvers))
        return []

    monkeypatch.setattr(dns01, "lookup_txt", lookup)
    flow = Flow(acme, "nas.lan")

    flow.trigger(flow.challenge("dns-01"))

    assert asked == [("_acme-challenge.nas.lan", ("192.168.1.53", "10.0.0.53"))]


def _setup_admin(client: TestClient, cfg: Config) -> str:
    """First-run setup, returning the session's CSRF token."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = db_session(cfg)
    try:
        session = get_session(db, client.cookies["cabin_session"])
        assert session is not None
        return session.csrf_token
    finally:
        db.close()


def test_settings_page_configures_validation(client: TestClient, cfg: Config) -> None:
    """FR-5/FR-9: both settings are configurable where every other setting
    is. A knob that only exists as a row in the database is not one an
    operator has."""
    csrf = _setup_admin(client, cfg)

    page = client.get("/settings").text
    assert "allow_private_validation_targets" in page
    assert "dns_resolvers" in page
    # FR-9: private targets are on unless someone turns them off, so the box
    # is ticked before anyone has saved anything
    assert page.count("checked") >= 1

    saved = client.post(
        "/settings",
        data={
            "base_url": BASE,
            "acme_enabled": "on",
            "dns_resolvers": " 192.168.1.53 ,10.0.0.53 ",
            "csrf_token": csrf,
        },
    )
    assert saved.status_code == 303, saved.text

    db = db_session(cfg)
    try:
        assert get_setting(db, DNS_RESOLVERS) == "192.168.1.53,10.0.0.53"
        # the checkbox was not submitted, so private targets are now refused
        assert get_flag(db, ALLOW_PRIVATE_VALIDATION_TARGETS, default=True) is False
    finally:
        db.close()
    assert "192.168.1.53,10.0.0.53" in client.get("/settings").text


def test_settings_page_refuses_a_resolver_that_is_not_an_address(
    client: TestClient, cfg: Config
) -> None:
    csrf = _setup_admin(client, cfg)

    rejected = client.post(
        "/settings",
        data={
            "base_url": BASE,
            "acme_enabled": "on",
            "dns_resolvers": "192.168.1.53, dns.example.org",
            "csrf_token": csrf,
        },
    )

    assert rejected.status_code == 400, rejected.text
    assert "dns.example.org" in rejected.text
    db = db_session(cfg)
    try:
        assert get_setting(db, DNS_RESOLVERS) is None
    finally:
        db.close()


def test_challenge_of_a_stale_authorization_is_not_validated(
    acme: Acme, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-7: an expired authorization cannot be proven -- the trigger is
    refused rather than sending cabin out to fetch something pointless."""
    flow = Flow(acme, "nas.lan")
    challenge = flow.challenge("http-01")
    db = db_session(cfg)
    try:
        authz = db.scalar(select(AcmeAuthorization))
        assert authz is not None
        authz.expires_at = "2020-01-01T00:00:00+00:00"
        db.commit()
    finally:
        db.close()

    assert_problem(flow.trigger(challenge), "malformed", 400)
