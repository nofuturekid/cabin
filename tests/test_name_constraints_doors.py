"""Tests for spec 0020 (name constraints): enforcement at every issuance
door.

The matching rules themselves (``check_name_constraints``'s FR-5) and the
extension/renewal crypto layer live in ``tests/test_name_constraints.py`` --
this file only asks one question, at each of the doors a leaf certificate
can come out of: does the check actually run here? Writing the extension
and hoping a door remembers to consult it is the failure spec 0020 exists to
prevent, so every door is named explicitly (AC-2's own framing) rather than
trusted to inherit the check through one shared call.

The doors: the two UI forms (``/certs/issue``, ``/certs/sign``), the two
REST endpoints, the two MCP tools, ACME's finalize, and cabin's own TLS
certificate -- eight in total, matching spec 0017/0018/0022's own count of
``issue_and_store``/``sign_csr_and_store`` callers. ACME matters most
(FR-4's own words: nobody is watching, the names arrive from outside, and a
refusal there would otherwise surface as a renewal that quietly stopped),
so it gets its own dedicated criteria (AC-14) beyond the shared AC-2 sweep.

Every principal used to reach a door here is a superadmin -- unrestricted
per ``cabin.issuer_grants.Principal.unrestricted`` and so exempt from spec
0018's grant check entirely. That is deliberate: a refusal in this file must
be *because of a name constraint*, never because of a missing grant, and an
unrestricted principal is the one identity no grant row can accidentally be
the reason for.

This branch is red by design: none of ``cabin.ca.leaf``'s new names exist on
disk yet, so ``leaf`` is imported as a module (``leaf_mod``) rather than by
name, following ``tests/test_issuer_permissions.py``'s own technique for the
same reason -- a missing symbol fails the one test that touches it, not
collection of the whole file.

``openssl verify -CAfile`` does not check the self-signature of what it is
handed -- it is a trust anchor, not something examined. AC-15 goes out of
its way to put the intermediate in ``-untrusted`` and only the root in
``-CAfile``, the one configuration in which a chain check is actually
proving something about the certificate's contents rather than about
nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from acme_client import Acme
from acme_orders import BASE, Flow, assert_problem, csr_der
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cabin.acme.models import AcmeOrder, OrderStatus
from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import certs as certs_service
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import Certificate
from cabin.config import Config
from cabin.mcp import MCP_PATH
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, MCP_ENABLED, TLS_ISSUER_ID, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.tls import TlsManager
from cabin.users import Role

_PASSWORD = "whatever12345"

# --- fixtures --------------------------------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _cert_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return db.scalar(select(func.count()).select_from(Certificate)) or 0
    finally:
        db.close()


def _issued_event_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == AuditAction.cert_issued)
            )
            or 0
        )
    finally:
        db.close()


@dataclass(frozen=True)
class TwoIssuers:
    """AC-2's own fixture: A constrained to permitted DNS ``example.com``,
    B unconstrained, both active, under different roots -- so "refused
    because of the constraint" cannot be confused with "refused because
    something else was wrong" (the ambiguity a single-issuer fixture cannot
    rule out)."""

    a: int
    b: int
    token: str


def _setup(client: TestClient, cfg: Config) -> TwoIssuers:
    assert (
        client.post("/setup", data={"username": "root", "password": _PASSWORD}).status_code == 303
    )
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, BASE)
        set_setting(db, ACME_ENABLED, TRUE)
        set_setting(db, MCP_ENABLED, TRUE)
        secrets = _secrets(cfg)
        hierarchy_a = ca_service.create_hierarchy(
            db,
            secrets,
            "alpha",
            constraints=leaf_mod.NameConstraintSpec(permitted_dns=("example.com",)),
        )
        hierarchy_b = ca_service.create_hierarchy(db, secrets, "beta")
        secret, _row = create_token(db, "door-token", Role.superadmin)
    finally:
        db.close()
    return TwoIssuers(a=hierarchy_a.intermediate.id, b=hierarchy_b.intermediate.id, token=secret)


def _csr_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --- MCP JSON-RPC, minimal (mirrors tests/test_mcp.py's own helpers) -----------

_MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _mcp_call(client: TestClient, name: str, arguments: dict[str, object], token: str) -> dict:
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token}"}
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    resp = client.post(MCP_PATH, headers=headers, json=body)
    assert resp.status_code == 200, resp.text
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            message = json.loads(line[len("data: ") :])
            assert "error" not in message, message
            result = message["result"]
            assert isinstance(result, dict)
            return result
    raise AssertionError(f"no JSON-RPC payload in {resp.text!r}")


# --- the six ordinary doors, enumerated -----------------------------------------


@dataclass(frozen=True)
class Attempt:
    refused: bool
    cert_id: int | None
    detail: str


def _ui_issue(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": f"dns:{cn}",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "issuer_id": issuer_id,
            "csrf_token": _csrf(client, cfg),
        },
    )
    if resp.status_code == 303:
        return Attempt(False, int(resp.headers["location"].rsplit("/", 1)[1]), "issued")
    assert resp.status_code == 400, f"UI issue: expected 303 or 400, got {resp.status_code}"
    return Attempt(True, None, resp.text)


def _ui_sign(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": _csr_pem(cn),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "issuer_id": issuer_id,
            "csrf_token": _csrf(client, cfg),
        },
    )
    if resp.status_code == 303:
        return Attempt(False, int(resp.headers["location"].rsplit("/", 1)[1]), "signed")
    assert resp.status_code == 400, f"UI sign: expected 303 or 400, got {resp.status_code}"
    return Attempt(True, None, resp.text)


def _api_issue(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    resp = client.post(
        "/api/v1/certificates",
        json={
            "subject_cn": cn,
            "sans": [cn],
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "issuer_id": issuer_id,
        },
        headers=_auth(token),
    )
    if resp.status_code == 201:
        return Attempt(False, resp.json()["id"], "issued")
    assert resp.status_code == 400, f"API issue: expected 201 or 400, got {resp.status_code}"
    return Attempt(True, None, resp.text)


def _api_sign(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    resp = client.post(
        "/api/v1/certificates/sign",
        json={"csr_pem": _csr_pem(cn), "profile": "server", "days": 60, "issuer_id": issuer_id},
        headers=_auth(token),
    )
    if resp.status_code == 201:
        return Attempt(False, resp.json()["id"], "signed")
    assert resp.status_code == 400, f"API sign: expected 201 or 400, got {resp.status_code}"
    return Attempt(True, None, resp.text)


def _mcp_issue(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    result = _mcp_call(
        client,
        "issue_certificate",
        {"subject_cn": cn, "sans": [cn], "issuer_id": issuer_id},
        token,
    )
    if result.get("isError") is not True:
        structured = result["structuredContent"]
        assert isinstance(structured, dict)
        return Attempt(False, int(structured["id"]), "issued")
    content = result["content"]
    assert isinstance(content, list) and content
    return Attempt(True, None, str(content[0]["text"]))


def _mcp_sign(client: TestClient, cfg: Config, token: str, issuer_id: int, cn: str) -> Attempt:
    result = _mcp_call(client, "sign_csr", {"csr_pem": _csr_pem(cn), "issuer_id": issuer_id}, token)
    if result.get("isError") is not True:
        structured = result["structuredContent"]
        assert isinstance(structured, dict)
        return Attempt(False, int(structured["id"]), "signed")
    content = result["content"]
    assert isinstance(content, list) and content
    return Attempt(True, None, str(content[0]["text"]))


@dataclass(frozen=True)
class Door:
    name: str
    attempt: Callable[[TestClient, Config, str, int, str], Attempt]


_DOORS: list[Door] = [
    Door("web/certs_ui.py:certs_issue", _ui_issue),
    Door("web/certs_ui.py:certs_sign", _ui_sign),
    Door("api/v1.py:issue_certificate", _api_issue),
    Door("api/v1.py:sign_csr", _api_sign),
    Door("mcp/server.py:issue_certificate", _mcp_issue),
    Door("mcp/server.py:sign_csr", _mcp_sign),
]


# === AC-2: the check runs at every door, including ACME, against one database ==


def test_check_runs_at_every_door_including_acme(client: TestClient, cfg: Config) -> None:
    """AC-2, in one test against one database: `nas.other.lan` from A is
    refused at all six ordinary doors AND at ACME finalize, with no
    `certificates` row written by any of the seven refusals; the same seven
    then issue `nas.example.com` from A, and all seven issue
    `nas.other.lan` from B.

    _Goes red if_: the check sits in `web/certs_ui.py` (the four non-UI
    doors would pass), in `ca/certs.py`'s two functions (a future door
    bypasses it, and ACME is what makes that visible today), or a refusal
    still writes a row.
    """
    issuers = _setup(client, cfg)
    before = _cert_count(cfg)

    for door in _DOORS:
        result = door.attempt(client, cfg, issuers.token, issuers.a, "nas.other.lan")
        assert result.refused, f"{door.name} issued nas.other.lan from a constrained issuer"

    acme_a = Acme(client, issuer_id=issuers.a)
    refused_flow = Flow(acme_a, cfg, "nas.other.lan")
    refused_flow.make_ready()
    refused = refused_flow.finalize(csr_der("nas.other.lan"))
    assert_problem(refused, "rejectedIdentifier", 400)

    assert _cert_count(cfg) == before, "a refusal wrote a certificates row"

    for door in _DOORS:
        result = door.attempt(client, cfg, issuers.token, issuers.a, "nas.example.com")
        assert not result.refused, f"{door.name} refused nas.example.com from A: {result.detail}"
        assert result.cert_id is not None

    ok_flow = Flow(acme_a, cfg, "nas.example.com")
    ok_flow.make_ready()
    cert_url = ok_flow.finalize_ok(csr_der("nas.example.com"))
    assert cert_url

    for door in _DOORS:
        result = door.attempt(client, cfg, issuers.token, issuers.b, "nas.other.lan")
        assert not result.refused, f"{door.name} refused nas.other.lan from B: {result.detail}"

    acme_b = Acme(client, issuer_id=issuers.b)
    b_flow = Flow(acme_b, cfg, "nas.other.lan")
    b_flow.make_ready()
    assert b_flow.finalize_ok(csr_der("nas.other.lan"))


def test_unconstrained_issuer_still_signs_everything(client: TestClient, cfg: Config) -> None:
    """The counter-check for AC-2's own trap: a check that refuses
    everything would pass a suite that only ever asserts refusal. B is
    unconstrained and must issue an arbitrary out-of-any-subtree name at
    every door -- covered above inside the mega test, and pinned down here
    on its own so a reviewer sees it as its own claim."""
    issuers = _setup(client, cfg)
    for door in _DOORS:
        result = door.attempt(client, cfg, issuers.token, issuers.b, "whatever.arbitrary.example")
        assert not result.refused, f"{door.name} refused an unconstrained issuer: {result.detail}"


def test_no_certificate_row_is_written_by_any_refusal(client: TestClient, cfg: Config) -> None:
    issuers = _setup(client, cfg)
    before = _cert_count(cfg)
    for door in _DOORS:
        result = door.attempt(client, cfg, issuers.token, issuers.a, "still.other.lan")
        assert result.refused
    assert _cert_count(cfg) == before


def test_refused_issuance_writes_no_certificate_issued_event(
    client: TestClient, cfg: Config
) -> None:
    """AC-16: a refused issuance is not a partial success -- no
    `cert_issued` audit event either, since nothing was issued."""
    issuers = _setup(client, cfg)
    before = _issued_event_count(cfg)
    result = _ui_issue(client, cfg, issuers.token, issuers.a, "nas.other.lan")
    assert result.refused
    assert _issued_event_count(cfg) == before


# === AC-14: ACME answers rejectedIdentifier, never serverInternal ===============


def test_acme_refusal_is_rejected_identifier_not_server_internal(
    client: TestClient, cfg: Config
) -> None:
    """_Goes red if_: `NameConstraintError` is matched by the existing
    `IssueError` arm first and answered `serverInternal` -- a 500-class
    problem type telling a correctly-behaving client to keep retrying a
    request that can never succeed."""
    issuers = _setup(client, cfg)
    acme = Acme(client, issuer_id=issuers.a)
    flow = Flow(acme, cfg, "nas.other.lan")
    flow.make_ready()

    resp = flow.finalize(csr_der("nas.other.lan"))
    assert_problem(resp, "rejectedIdentifier", 400)
    assert "nas.other.lan" in resp.text

    ok_flow = Flow(acme, cfg, "nas.example.com")
    ok_flow.make_ready()
    assert ok_flow.finalize_ok(csr_der("nas.example.com"))


def test_acme_refusal_carries_a_nonce_and_releases_the_claim(
    client: TestClient, cfg: Config
) -> None:
    """The order survives: its claim is released (back to `pending`, not
    stuck `processing`), so it can be finalized again -- proven by
    finalizing twice and getting the *same* answer both times, never
    `orderNotReady` (which a stuck-processing order would answer instead).
    No certificate row is written, and every response still carries the
    `Replay-Nonce` a client needs for its next request."""
    issuers = _setup(client, cfg)
    acme = Acme(client, issuer_id=issuers.a)
    flow = Flow(acme, cfg, "nas.other.lan")
    flow.make_ready()
    before = _cert_count(cfg)

    first = flow.finalize(csr_der("nas.other.lan"))
    assert_problem(first, "rejectedIdentifier", 400)
    assert "replay-nonce" in first.headers

    second = flow.finalize(csr_der("nas.other.lan"))
    assert_problem(second, "rejectedIdentifier", 400)
    assert "replay-nonce" in second.headers

    assert _cert_count(cfg) == before

    db = _db(cfg)
    try:
        order = db.get(AcmeOrder, flow.order_id)
        assert order is not None
        assert order.status == OrderStatus.pending
        assert order.certificate_id is None
    finally:
        db.close()


# === AC-8's door half: a renewal keeps refusing (and keeps issuing) ============


def test_renewal_still_refuses_the_same_name_through_acme(client: TestClient, cfg: Config) -> None:
    """FR-6: a renewal must not silently widen what an issuer may sign. A
    is renewed through the real route, and the same refusal/issuance split
    it had before still holds afterwards, over ACME."""
    issuers = _setup(client, cfg)
    assert (
        client.post(
            f"/ca/{issuers.a}/renew", data={"years": 5, "csrf_token": _csrf(client, cfg)}
        ).status_code
        == 303
    )

    acme = Acme(client, issuer_id=issuers.a)
    refused_flow = Flow(acme, cfg, "nas.other.lan")
    refused_flow.make_ready()
    assert_problem(refused_flow.finalize(csr_der("nas.other.lan")), "rejectedIdentifier", 400)

    ok_flow = Flow(acme, cfg, "nas.example.com")
    ok_flow.make_ready()
    assert ok_flow.finalize_ok(csr_der("nas.example.com"))


def test_renew_route_ignores_posted_constraint_fields(client: TestClient, cfg: Config) -> None:
    """AC-9: `POST /ca/{ca_id}/renew` takes `years` and only `years` --
    posting `permitted_names`/`excluded_names` alongside it changes nothing,
    because the route does not declare those fields at all. Measured on the
    certificate's own extension bytes before and after, not on the response,
    since a route silently ignoring unknown form fields would look identical
    whether or not this requirement held."""
    issuers = _setup(client, cfg)
    db = _db(cfg)
    try:
        row = ca_service.get_ca(db, issuers.a)
        before = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
        before_nc = before.extensions.get_extension_for_class(x509.NameConstraints)
    finally:
        db.close()

    resp = client.post(
        f"/ca/{issuers.a}/renew",
        data={
            "years": 5,
            "permitted_names": "evil-wide-open.example",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    db = _db(cfg)
    try:
        row = ca_service.get_ca(db, issuers.a)
        after = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
        after_nc = after.extensions.get_extension_for_class(x509.NameConstraints)
    finally:
        db.close()
    assert after_nc.value.permitted_subtrees == before_nc.value.permitted_subtrees
    assert after_nc.value.excluded_subtrees == before_nc.value.excluded_subtrees
    assert after.serial_number != before.serial_number  # a genuine renewal happened


# === AC-10's door half: an imported intermediate is enforced from its cert =====


def test_imported_intermediate_is_enforced_from_its_certificate(
    client: TestClient, cfg: Config
) -> None:
    """_Goes red if_: enforcement reads a cabin-side value rather than the
    certificate -- an imported CA has no cabin-side value, so it would be
    unconstrained."""
    _ = _setup(client, cfg)  # base URL, ACME/MCP flags, a token to use below
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        root_cert, root_key = ca_x509.create_root("Partner Root CA", "ecdsa-p256")
        spec = leaf_mod.NameConstraintSpec(permitted_dns=("partner.example",))
        intermediate_cert, intermediate_key = ca_x509.create_intermediate(
            root_cert,
            root_key,
            "Partner Intermediate CA",
            "ecdsa-p256",
            name_constraints=leaf_mod.name_constraints_extension(spec),
        )

        def _pem(obj: x509.Certificate) -> str:
            return obj.public_bytes(serialization.Encoding.PEM).decode("ascii")

        def _key_pem(key: object) -> str:
            return key.private_bytes(  # type: ignore[attr-defined]
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")

        hierarchy = ca_service.import_hierarchy(
            db,
            secrets,
            _pem(intermediate_cert),
            _key_pem(intermediate_key),
            None,
            _pem(root_cert),
        )
        issuer_id = hierarchy.intermediate.id
        secret, _row = create_token(db, "partner-token", Role.superadmin)
    finally:
        db.close()

    ok = _api_issue(client, cfg, secret, issuer_id, "www.partner.example")
    assert not ok.refused, ok.detail

    refused_api = _api_issue(client, cfg, secret, issuer_id, "www.other.example")
    assert refused_api.refused
    refused_ui = _ui_issue(client, cfg, secret, issuer_id, "www.other.example")
    assert refused_ui.refused


def test_imported_intermediate_with_an_unevaluable_form_refuses_that_san(
    client: TestClient, cfg: Config
) -> None:
    """FR-5 rule 8, at a real door: an imported intermediate additionally
    carrying an `rfc822Name` subtree refuses a leaf with an `EMAIL:` SAN
    while still issuing a DNS name inside its permitted set."""
    _ = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        root_cert, root_key = ca_x509.create_root("Email Root CA", "ecdsa-p256")
        nc = x509.NameConstraints(
            permitted_subtrees=[
                x509.DNSName("partner.example"),
                x509.RFC822Name("ops@partner.example"),
            ],
            excluded_subtrees=None,
        )
        intermediate_cert, intermediate_key = ca_x509.create_intermediate(
            root_cert, root_key, "Email Intermediate CA", "ecdsa-p256", name_constraints=nc
        )

        def _pem(obj: x509.Certificate) -> str:
            return obj.public_bytes(serialization.Encoding.PEM).decode("ascii")

        def _key_pem(key: object) -> str:
            return key.private_bytes(  # type: ignore[attr-defined]
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")

        hierarchy = ca_service.import_hierarchy(
            db, secrets, _pem(intermediate_cert), _key_pem(intermediate_key), None, _pem(root_cert)
        )
        issuer_id = hierarchy.intermediate.id
        secret, _row = create_token(db, "email-token", Role.superadmin)
    finally:
        db.close()

    resp = client.post(
        "/api/v1/certificates",
        json={
            "subject_cn": "someone@partner.example",
            "sans": ["email:someone@partner.example"],
            "profile": "client",
            "key_type": "ecdsa-p256",
            "issuer_id": issuer_id,
        },
        headers=_auth(secret),
    )
    assert resp.status_code == 400, resp.text

    ok = _api_issue(client, cfg, secret, issuer_id, "app.partner.example")
    assert not ok.refused, ok.detail


# === AC-13: cabin's own certificate is not exempt ===============================


def test_tls_certificate_is_not_exempt_from_the_check(cfg: Config, tmp_path: Path) -> None:
    """With TLS's own binding pointing at an issuer whose constraints
    exclude the base URL's hostname: `ensure_current` returns `False` on
    every one of three consecutive ticks, cabin keeps serving the material
    it already has, exactly one `tls_certificate_failed` audit event is
    written across all three, and no `certificates` row with
    `source="system"` is added. Rebinding to an issuer that permits the
    hostname then makes the very next tick succeed.

    _Goes red if_: `SYSTEM_PRINCIPAL`/`tls.py` is given an exemption from the
    check, or the failure takes the listener down (not exercised here --
    that is spec 0022's own suite), or the event is written once per tick.
    """
    hostname = "tls.example.lan"
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    from cabin.store import run_migrations

    run_migrations(db_url)
    db = create_session_factory(db_url)()
    secrets = SecretStore.open(tmp_path, None)
    try:
        set_setting(db, BASE_URL, f"https://{hostname}")
        open_hierarchy = ca_service.create_hierarchy(db, secrets, "open")
        set_setting(db, TLS_ISSUER_ID, str(open_hierarchy.intermediate.id))

        manager = TlsManager(tmp_path / "tls-data")
        assert manager.ensure_current(db, secrets) is True
        first_serial = _served_serial(manager)

        blocked_hierarchy = ca_service.create_hierarchy(
            db,
            secrets,
            "blocked",
            constraints=leaf_mod.NameConstraintSpec(excluded_dns=(hostname,)),
        )
        set_setting(db, TLS_ISSUER_ID, str(blocked_hierarchy.intermediate.id))

        rows_before = db.scalar(
            select(func.count()).select_from(Certificate).where(Certificate.source == "system")
        )
        events_before = db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == AuditAction.tls_certificate_failed)
        )

        results = [manager.ensure_current(db, secrets) for _ in range(3)]
        assert results == [False, False, False]
        assert _served_serial(manager) == first_serial

        rows_after = db.scalar(
            select(func.count()).select_from(Certificate).where(Certificate.source == "system")
        )
        events_after = db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == AuditAction.tls_certificate_failed)
        )
        assert rows_after == rows_before
        assert events_after == (events_before or 0) + 1

        # rebind to a second intermediate that permits the hostname -- not
        # back to `open_hierarchy`: its certificate is still what is being
        # served, under an unchanged name, so ensure_current's own
        # idempotency check would correctly decline that as a no-op and
        # prove nothing about the constraint. A genuinely different issuer
        # forces a reissue, and the next tick succeeds.
        permitted_hierarchy = ca_service.create_hierarchy(
            db,
            secrets,
            "permitted",
            constraints=leaf_mod.NameConstraintSpec(permitted_dns=(hostname,)),
        )
        set_setting(db, TLS_ISSUER_ID, str(permitted_hierarchy.intermediate.id))
        assert manager.ensure_current(db, secrets) is True
    finally:
        db.close()


def _served_serial(manager: TlsManager) -> int:
    from cabin.tls import cert_path

    cert = x509.load_pem_x509_certificate(cert_path(manager.data_dir).read_bytes())
    return cert.serial_number


# === AC-15: cabin and a real validator agree, in both directions ================


def _openssl_verify(
    tmp_path: Path, label: str, root_pem: str, intermediate_pem: str, leaf_pem: str
) -> subprocess.CompletedProcess[str]:
    """`-CAfile` gets only the root (a trust anchor); `-untrusted` gets the
    intermediate. Swapping the two would make the intermediate itself a
    trust anchor whose contents openssl never examines, which is exactly
    the blind spot this project has already been bitten by once."""
    d = tmp_path / "openssl" / label
    d.mkdir(parents=True)
    root_path, intermediate_path, leaf_path = d / "root.pem", d / "intermediate.pem", d / "leaf.pem"
    root_path.write_text(root_pem)
    intermediate_path.write_text(intermediate_pem)
    leaf_path.write_text(leaf_pem)
    return subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_path),
            "-untrusted",
            str(intermediate_path),
            str(leaf_path),
        ],
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_openssl_agrees_with_an_issued_name(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-15 step 1: a leaf cabin actually issued for a permitted name
    verifies against a real validator."""
    issuers = _setup(client, cfg)
    result = _api_issue(client, cfg, issuers.token, issuers.a, "www.example.com")
    assert not result.refused, result.detail
    assert result.cert_id is not None

    db = _db(cfg)
    try:
        row = certs_service.get_certificate(db, result.cert_id)
        assert row is not None
        leaf_pem = row.cert_pem
        chain = ca_service.chain_for(db, issuers.a)
        intermediate_pem = chain[0].cert_pem
        root_pem = chain[1].cert_pem
    finally:
        db.close()

    proc = _openssl_verify(tmp_path, "issued-ok", root_pem, intermediate_pem, leaf_pem)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_openssl_rejects_a_smuggled_name(client: TestClient, cfg: Config, tmp_path: Path) -> None:
    """AC-15 step 2: a leaf for an out-of-subtree name, built by signing
    directly with A's key and bypassing `_build_leaf`'s check entirely (so
    this measures the *extension cabin wrote*, not cabin's own matcher),
    fails verification with a permitted-subtree violation. Cabin's matcher
    and the certificate it writes have to agree in both directions (FR-7);
    this is the direction "cabin's check is laxer than the extension"
    would not otherwise be caught by, since every door already refuses this
    name before it is ever signed."""
    issuers = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        issuer_cert, issuer_key = ca_service.signing_credentials(db, secrets, issuers.a)
        chain = ca_service.chain_for(db, issuers.a)
        root_pem = chain[1].cert_pem
        intermediate_pem = chain[0].cert_pem
    finally:
        db.close()

    smuggled_key = ec.generate_private_key(ec.SECP256R1())
    smuggled = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas.other.lan")]))
        .issuer_name(issuer_cert.subject)
        .public_key(smuggled_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issuer_cert.not_valid_before_utc)
        .not_valid_after(issuer_cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("nas.other.lan")]), critical=False)
        .sign(issuer_key, algorithm=ca_x509.signing_algorithm(issuer_key))
    )
    leaf_pem = smuggled.public_bytes(serialization.Encoding.PEM).decode("ascii")

    proc = _openssl_verify(tmp_path, "smuggled", root_pem, intermediate_pem, leaf_pem)
    assert proc.returncode != 0
    assert "permitted" in (proc.stdout + proc.stderr).lower()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_openssl_agrees_on_excluded_subtree(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-15 step 3: the same two outcomes, over the excluded-subtree
    fixture rather than the permitted one -- excluded is a different code
    path in both the writer and the matcher, and FR-7 requires them to
    agree on both."""
    _ = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_service.create_hierarchy(
            db,
            secrets,
            "excl",
            constraints=leaf_mod.NameConstraintSpec(
                permitted_dns=("example.com",), excluded_dns=("secret.example.com",)
            ),
        )
        issuer_id = hierarchy.intermediate.id
        secret, _row = create_token(db, "excl-token", Role.superadmin)
        issuer_cert, issuer_key = ca_service.signing_credentials(db, secrets, issuer_id)
        root_pem = hierarchy.root.cert_pem
        intermediate_pem = hierarchy.intermediate.cert_pem
    finally:
        db.close()

    ok = _api_issue(client, cfg, secret, issuer_id, "www.example.com")
    assert not ok.refused, ok.detail
    db = _db(cfg)
    try:
        row = certs_service.get_certificate(db, ok.cert_id)
        assert row is not None
        leaf_pem = row.cert_pem
    finally:
        db.close()
    proc = _openssl_verify(tmp_path, "excluded-ok", root_pem, intermediate_pem, leaf_pem)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    smuggled_key = ec.generate_private_key(ec.SECP256R1())
    smuggled = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secret.example.com")]))
        .issuer_name(issuer_cert.subject)
        .public_key(smuggled_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issuer_cert.not_valid_before_utc)
        .not_valid_after(issuer_cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("secret.example.com")]), critical=False
        )
        .sign(issuer_key, algorithm=ca_x509.signing_algorithm(issuer_key))
    )
    smuggled_pem = smuggled.public_bytes(serialization.Encoding.PEM).decode("ascii")
    proc = _openssl_verify(tmp_path, "excluded-smuggled", root_pem, intermediate_pem, smuggled_pem)
    assert proc.returncode != 0
