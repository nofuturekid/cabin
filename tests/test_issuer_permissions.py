"""Cross-cutting enforcement suite for spec 0018 (per-issuer permissions).

This file is written against the spec's Interface Contract, not against the
Phase-0 skeleton that exists on disk today: migration ``0010`` and
:mod:`cabin.issuer_grants`'s two ORM models (:class:`UserIssuer`,
:class:`TokenIssuer`) are real; ``Principal``, ``user_principal``,
``token_principal``, ``ACME_PRINCIPAL``, ``SYSTEM_PRINCIPAL``,
``granted_issuers``, ``may_use_issuer``, ``resolve_granted_issuer``,
``set_issuers``, ``grant``, the two new exceptions, and the required
``principal`` parameter on ``issue_and_store``/``sign_csr_and_store``/
``revoke_certificate`` do not exist yet. Following the technique
``tests/test_tls.py`` already uses for the same reason: nothing not-yet-real
is imported by name at module level, so a missing piece is an
``AttributeError``/``TypeError`` inside the one test that touches it --
"the thing does not exist yet" -- rather than a single collection error that
would swallow every other test's more specific answer. ``cabin.issuer_grants``
is imported as ``grants_mod`` for exactly this reason, and ``from __future__
import annotations`` lets every helper still carry a full, precise type
annotation (``grants_mod.Principal`` and friends) without those names having
to resolve at import time.

The spec's own framing is the organizing idea: **a permission that is
enforced at one door and forgotten at another is not a permission.** So the
centre of this file is the eight callers of ``issue_and_store`` FR-5 names
(the spec's own text says seven; spec 0022 landed ``TlsManager._issue`` as an
eighth between the spec being written and being built) -- enumerated
explicitly as ``_DOORS`` plus two named exemption tests, never trusted to
propagate through one helper called once. If a ninth caller appears, the
absence of a ninth entry here is the thing that should look wrong.

Both exemptions (``ACME_PRINCIPAL``, ``SYSTEM_PRINCIPAL``) are tested as
properties that could not pass by accident: the ACME test insists on **zero**
rows in both grant tables while an ordinary ungranted admin is refused in the
same test against the same database, and the TLS test explicitly grants and
then strips the one admin in it, so that success afterwards cannot be
mistaken for "everyone in this fixture happened to be unrestricted anyway."

Revocation gets its own trap test: a grant on a **retired** issuer must still
allow revoking what it signed (0017 FR-9, 0018 AC-5(b)) -- the spec's own
author names ``may_use_issuer`` silently swapped for ``granted_issuers`` at
the revocation call site as the one mutation that would pass every other
criterion here.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import shutil
import subprocess
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import ca_fixtures
import grant_fixtures
import pytest
from acme_client import Acme
from acme_orders import BASE as ACME_BASE
from acme_orders import Flow as AcmeFlow
from acme_orders import csr_der
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import cabin.acme.api_finalize as acme_finalize_mod
import cabin.issuer_grants as grants_mod
import cabin.tls as tls_mod
from cabin.api_tokens import ApiToken, create_token
from cabin.app import create_app
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.leaf import Profile
from cabin.config import Config
from cabin.issuer_grants import TokenIssuer, UserIssuer
from cabin.mcp import MCP_PATH
from cabin.mcp.auth import TOKEN_ID_CLAIM, CabinTokenVerifier
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, MCP_ENABLED, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.tls import TlsManager, TlsMode
from cabin.users import Role, User, create_user

_PASSWORD = "whatever12345"


# --- fixtures ------------------------------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


# --- generic scaffolding ---------------------------------------------------------


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


def _login(client: TestClient, username: str, password: str = _PASSWORD) -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303, resp.text


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _token(cfg: Config, role: Role, label: str | None = None) -> tuple[str, int]:
    """A fresh admin+ token, returned as ``(secret, token_id)`` rather than
    the ORM row: the row is detached the moment its session closes, and
    every caller here only ever wants the id back to grant against later."""
    db = _db(cfg)
    try:
        secret, row = create_token(db, label or f"{role.value}-{uuid.uuid4().hex[:8]}", role)
        return secret, row.id
    finally:
        db.close()


def _grant_user_id(cfg: Config, user_id: int, issuer_id: int) -> None:
    db = _db(cfg)
    try:
        user = db.get(User, user_id)
        assert user is not None
        grant_fixtures.grant_user(db, user, issuer_id)
    finally:
        db.close()


def _revoke_user_grant(cfg: Config, user_id: int, issuer_id: int) -> None:
    db = _db(cfg)
    try:
        user = db.get(User, user_id)
        assert user is not None
        grant_fixtures.revoke_user(db, user, issuer_id)
    finally:
        db.close()


def _grant_token_id(cfg: Config, token_id: int, issuer_id: int) -> None:
    db = _db(cfg)
    try:
        token = db.get(ApiToken, token_id)
        assert token is not None
        grant_fixtures.grant_token(db, token, issuer_id)
    finally:
        db.close()


def _revoke_token_grant(cfg: Config, token_id: int, issuer_id: int) -> None:
    db = _db(cfg)
    try:
        token = db.get(ApiToken, token_id)
        assert token is not None
        grant_fixtures.revoke_token(db, token, issuer_id)
    finally:
        db.close()


def _grant_row_counts(cfg: Config) -> tuple[int, int]:
    """``(len(user_issuers), len(token_issuers))`` -- what AC-7's "zero rows
    in both grant tables" and AC-2's "row counts unchanged" are measured
    against, read straight off the tables rather than through anything
    ``cabin.issuer_grants`` might one day cache."""
    db = _db(cfg)
    try:
        users = db.scalar(select(func.count()).select_from(UserIssuer)) or 0
        tokens = db.scalar(select(func.count()).select_from(TokenIssuer)) or 0
        return users, tokens
    finally:
        db.close()


def _count_certificates(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return db.scalar(select(func.count()).select_from(certs_service.Certificate)) or 0
    finally:
        db.close()


def _certificate_issuer(cfg: Config, cert_id: int) -> int:
    db = _db(cfg)
    try:
        row = certs_service.get_certificate(db, cert_id)
        assert row is not None
        return row.issuer_id
    finally:
        db.close()


def _certificate_serial(cfg: Config, cert_id: int) -> int:
    db = _db(cfg)
    try:
        row = certs_service.get_certificate(db, cert_id)
        assert row is not None
        return int(row.serial_hex, 16)
    finally:
        db.close()


def _certificate_revoked_at(cfg: Config, cert_id: int) -> str | None:
    db = _db(cfg)
    try:
        row = certs_service.get_certificate(db, cert_id)
        assert row is not None
        return row.revoked_at
    finally:
        db.close()


def _crl_snapshot(cfg: Config, issuer_id: int) -> tuple[int, bytes] | None:
    """``(crl_number, crl_der)`` for one issuer, or ``None`` if it has never
    published one -- a plain tuple rather than the ORM row, so a refused
    revocation's "unchanged" assertion cannot be fooled by a detached
    instance that merely never re-read its own columns."""
    db = _db(cfg)
    try:
        state = crl_service.stored_crl(db, issuer_id)
        return (state.crl_number, state.crl_der) if state is not None else None
    finally:
        db.close()


def _issue_direct(
    cfg: Config,
    secrets: SecretStore,
    principal: grants_mod.Principal,
    issuer_id: int | None,
    cn: str,
) -> int:
    """Issue one certificate straight through the domain layer -- for tests
    that need a certificate already sitting in the database and are not
    measuring which front door produced it. Uses ``SYSTEM_PRINCIPAL`` from
    the call sites below, never a principal the test is trying to keep
    ungranted."""
    db = _db(cfg)
    try:
        issued = certs_service.issue_and_store(
            db,
            secrets,
            principal=principal,
            profile=Profile.server,
            subject_cn=cn,
            sans=[cn],
            issuer_id=issuer_id,
        )
        return issued.row.id
    finally:
        db.close()


def _csr_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _enable_doors(db: Session) -> None:
    """The base URL and the MCP flag every door test needs -- MCP so the
    MCP doors are reachable at all, the base URL because MCP refuses to
    switch on without one (spec 0013 FR-4)."""
    set_setting(db, BASE_URL, "https://ca.example.org")
    set_setting(db, MCP_ENABLED, TRUE)


# --- MCP JSON-RPC, minimal (mirrors tests/test_mcp.py's own helpers) -----------

_MCP_ACCEPT = "application/json, text/event-stream"
_MCP_HEADERS = {"Accept": _MCP_ACCEPT, "Content-Type": "application/json"}


def _mcp_post(
    client: TestClient, method: str, params: dict[str, object] | None, token: str
) -> Response:
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token}"}
    body: dict[str, object] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return client.post(MCP_PATH, headers=headers, json=body)


def _mcp_payload(resp: Response) -> dict[str, object]:
    assert resp.status_code == 200, resp.text
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            decoded: dict[str, object] = json.loads(line[len("data: ") :])
            return decoded
    raise AssertionError(f"no JSON-RPC payload in {resp.text!r}")


def _raw_call(
    client: TestClient, name: str, arguments: dict[str, object], *, token: str
) -> dict[str, object]:
    message = _mcp_payload(
        _mcp_post(client, "tools/call", {"name": name, "arguments": arguments}, token)
    )
    assert "error" not in message, message
    result = message["result"]
    assert isinstance(result, dict)
    return result


# --- the eight issuance entry points, enumerated ------------------------------


@dataclass(frozen=True)
class IssuanceResult:
    refused: bool
    cert_id: int | None
    detail: str


def _ui_issue(
    client: TestClient, cfg: Config, _token: str, issuer_id: int | None
) -> IssuanceResult:
    data: dict[str, object] = {
        "subject_cn": "door.lan",
        "sans": "door.lan",
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": "90",
        "csrf_token": _csrf(client, cfg),
    }
    if issuer_id is not None:
        data["issuer_id"] = issuer_id
    resp = client.post("/certs/issue", data=data)
    if resp.status_code == 303:
        return IssuanceResult(False, int(resp.headers["location"].rsplit("/", 1)[1]), "issued")
    assert resp.status_code == 403, (
        f"UI issue: expected 303 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return IssuanceResult(True, None, resp.text)


def _ui_sign(client: TestClient, cfg: Config, _token: str, issuer_id: int | None) -> IssuanceResult:
    data: dict[str, object] = {
        "csr_pem": _csr_pem("door-sign.lan"),
        "profile": "server",
        "days": "60",
        "sans_override": "",
        "csrf_token": _csrf(client, cfg),
    }
    if issuer_id is not None:
        data["issuer_id"] = issuer_id
    resp = client.post("/certs/sign", data=data)
    if resp.status_code == 303:
        return IssuanceResult(False, int(resp.headers["location"].rsplit("/", 1)[1]), "signed")
    assert resp.status_code == 403, (
        f"UI sign: expected 303 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return IssuanceResult(True, None, resp.text)


def _api_issue(
    client: TestClient, cfg: Config, token: str, issuer_id: int | None
) -> IssuanceResult:
    body: dict[str, object] = {
        "subject_cn": "door.lan",
        "sans": ["door.lan"],
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": 90,
    }
    if issuer_id is not None:
        body["issuer_id"] = issuer_id
    resp = client.post("/api/v1/certificates", json=body, headers=_auth(token))
    if resp.status_code == 201:
        return IssuanceResult(False, resp.json()["id"], "issued")
    assert resp.status_code == 403, (
        f"API issue: expected 201 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return IssuanceResult(True, None, resp.text)


def _api_sign(client: TestClient, cfg: Config, token: str, issuer_id: int | None) -> IssuanceResult:
    body: dict[str, object] = {
        "csr_pem": _csr_pem("door-sign.lan"),
        "profile": "server",
        "days": 60,
    }
    if issuer_id is not None:
        body["issuer_id"] = issuer_id
    resp = client.post("/api/v1/certificates/sign", json=body, headers=_auth(token))
    if resp.status_code == 201:
        return IssuanceResult(False, resp.json()["id"], "signed")
    assert resp.status_code == 403, (
        f"API sign: expected 201 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return IssuanceResult(True, None, resp.text)


def _mcp_issue(
    client: TestClient, cfg: Config, token: str, issuer_id: int | None
) -> IssuanceResult:
    args: dict[str, object] = {"subject_cn": "door.lan", "sans": ["door.lan"]}
    if issuer_id is not None:
        args["issuer_id"] = issuer_id
    result = _raw_call(client, "issue_certificate", args, token=token)
    if result.get("isError") is not True:
        structured = result["structuredContent"]
        assert isinstance(structured, dict)
        return IssuanceResult(False, int(structured["id"]), "issued")
    content = result["content"]
    assert isinstance(content, list) and content
    return IssuanceResult(True, None, str(content[0]["text"]))


def _mcp_sign(client: TestClient, cfg: Config, token: str, issuer_id: int | None) -> IssuanceResult:
    args: dict[str, object] = {"csr_pem": _csr_pem("door-sign.lan")}
    if issuer_id is not None:
        args["issuer_id"] = issuer_id
    result = _raw_call(client, "sign_csr", args, token=token)
    if result.get("isError") is not True:
        structured = result["structuredContent"]
        assert isinstance(structured, dict)
        return IssuanceResult(False, int(structured["id"]), "signed")
    content = result["content"]
    assert isinstance(content, list) and content
    return IssuanceResult(True, None, str(content[0]["text"]))


@dataclass(frozen=True)
class Door:
    """One of FR-5's identity-bearing issuance entry points. ``kind`` is
    what the refusal *shape* should look like (a role refusal reads
    differently per transport); ``grants`` is which join table a test must
    write a row into to grant this door's principal.
    """

    name: str
    kind: str  # "ui" | "api" | "mcp"
    grants: str  # "user" | "token"
    attempt: Callable[[TestClient, Config, str, int | None], IssuanceResult]


#: Enumerated explicitly, not derived: FR-5 names eight callers of
#: ``issue_and_store``/``sign_csr_and_store``. Six carry an identity and must
#: refuse an ungranted principal (AC-1); the other two are named exemptions
#: with their own tests below (ACME, and ``tls.py``'s system principal --
#: the eighth door 0018 was written before 0022 added). A test parameterized
#: over fewer than these six does not satisfy AC-1.
_DOORS: list[Door] = [
    Door("web/certs_ui.py:certs_issue -> issue_and_store", "ui", "user", _ui_issue),
    Door("web/certs_ui.py:certs_sign -> sign_csr_and_store", "ui", "user", _ui_sign),
    Door("api/v1.py:issue_certificate -> issue_and_store", "api", "token", _api_issue),
    Door("api/v1.py:sign_csr -> sign_csr_and_store", "api", "token", _api_sign),
    Door("mcp/server.py:issue_certificate -> issue_and_store", "mcp", "token", _mcp_issue),
    Door("mcp/server.py:sign_csr -> sign_csr_and_store", "mcp", "token", _mcp_sign),
]


@dataclass(frozen=True)
class DoorFixtureData:
    issuer_id: int
    admin_id: int
    token_secret: str
    token_id: int


def _prepare_doors(
    client: TestClient, cfg: Config, secrets: SecretStore, label: str
) -> DoorFixtureData:
    """One active, signing-capable issuer; one ungranted admin user logged
    into ``client``; one ungranted admin token -- the shared subject of both
    six-door tests below."""
    db = _db(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, label)
        issuer_id = hierarchy.intermediate.id
        admin = create_user(db, f"{label}-admin", _PASSWORD, Role.admin)
        admin_id = admin.id
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.admin, label=f"{label}-token")
    _login(client, f"{label}-admin")
    return DoorFixtureData(issuer_id, admin_id, secret, token_id)


# --- the three non-ACME revocation doors --------------------------------------


@dataclass(frozen=True)
class RevocationResult:
    refused: bool
    detail: str


def _ui_revoke(client: TestClient, cfg: Config, cert_id: int) -> RevocationResult:
    resp = client.post(
        f"/certs/{cert_id}/revoke",
        data={"reason": "key_compromise", "confirm": "on", "csrf_token": _csrf(client, cfg)},
    )
    if resp.status_code == 303:
        return RevocationResult(False, "revoked")
    assert resp.status_code == 403, (
        f"UI revoke: expected 303 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return RevocationResult(True, resp.text)


def _api_revoke(client: TestClient, cfg: Config, token: str, cert_id: int) -> RevocationResult:
    resp = client.post(
        f"/api/v1/certificates/{cert_id}/revoke",
        json={"reason": "key_compromise"},
        headers=_auth(token),
    )
    if resp.status_code == 200:
        return RevocationResult(False, "revoked")
    assert resp.status_code == 403, (
        f"API revoke: expected 200 or 403, got {resp.status_code}: {resp.text[:300]}"
    )
    return RevocationResult(True, resp.text)


def _mcp_revoke(client: TestClient, cfg: Config, token: str, cert_id: int) -> RevocationResult:
    result = _raw_call(
        client,
        "revoke_certificate",
        {"certificate_id": cert_id, "reason": "key_compromise"},
        token=token,
    )
    if result.get("isError") is not True:
        return RevocationResult(False, "revoked")
    content = result["content"]
    assert isinstance(content, list) and content
    return RevocationResult(True, str(content[0]["text"]))


def _openssl_crl_serials(tmp_path: Path, label: str, crl_der: bytes) -> set[int]:
    d = tmp_path / "crl" / label
    d.mkdir(parents=True)
    crl_path = d / "crl.der"
    crl_path.write_bytes(crl_der)
    result = subprocess.run(
        ["openssl", "crl", "-inform", "DER", "-in", str(crl_path), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    )
    return {
        int(line.split(":", 1)[1].strip().replace(":", ""), 16)
        for line in result.stdout.splitlines()
        if line.strip().startswith("Serial Number:")
    }


# === AC-1: the six identity-bearing doors refuse an ungranted admin ============


def test_ungranted_admin_refused_at_every_issuance_entry_point(
    client: TestClient, cfg: Config
) -> None:
    """AC-1's negative half, parameterized over all six doors in ``_DOORS``
    -- not five and a promise, six. Neither the certificate count nor either
    grant table moves."""
    secrets = _secrets(cfg)
    data = _prepare_doors(client, cfg, secrets, "ungranted")
    before_certs = _count_certificates(cfg)
    before_grants = _grant_row_counts(cfg)
    for door in _DOORS:
        result = door.attempt(client, cfg, data.token_secret, None)
        assert result.refused, (
            f"{door.name}: expected refusal for an ungranted admin, got: {result.detail}"
        )
    assert _count_certificates(cfg) == before_certs, "an ungranted admin issued something somewhere"
    assert _grant_row_counts(cfg) == before_grants


def test_granted_admin_issues_at_every_entry_point(client: TestClient, cfg: Config) -> None:
    """AC-1's positive half: granting the door's principal makes the same
    call succeed, and the stored certificate names the granted issuer --
    without this half, the negative test above would pass against a build
    that refuses everyone unconditionally."""
    secrets = _secrets(cfg)
    data = _prepare_doors(client, cfg, secrets, "granted")
    for door in _DOORS:
        if door.grants == "user":
            _grant_user_id(cfg, data.admin_id, data.issuer_id)
        else:
            _grant_token_id(cfg, data.token_id, data.issuer_id)
        result = door.attempt(client, cfg, data.token_secret, None)
        assert not result.refused, (
            f"{door.name}: expected success once granted, got: {result.detail}"
        )
        assert result.cert_id is not None
        assert _certificate_issuer(cfg, result.cert_id) == data.issuer_id
        if door.grants == "user":
            _revoke_user_grant(cfg, data.admin_id, data.issuer_id)
        else:
            _revoke_token_grant(cfg, data.token_id, data.issuer_id)


# === AC-2: enforcement is not the select box ===================================


def test_ungranted_issuer_posted_directly_is_refused(client: TestClient, cfg: Config) -> None:
    """AC-2, the criterion the whole spec rests on. Granted only A, posting
    ``issuer_id=B`` straight into the body -- a value the rendered form
    never offers -- is refused at all three transports, and writes nothing.
    An implementation that merely filters the select box and passes the
    posted id straight through to ``resolve_granted_issuer`` must fail this."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        a = ca_fixtures.make_hierarchy(db, secrets, "select-box-a").intermediate
        b = ca_fixtures.make_hierarchy(db, secrets, "select-box-b").intermediate
        a_id, b_id = a.id, b.id
        admin = create_user(db, "select-box-admin", _PASSWORD, Role.admin)
        grant_fixtures.grant_user(db, admin, a_id)
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.admin, label="select-box-token")
    _grant_token_id(cfg, token_id, a_id)
    _login(client, "select-box-admin")

    before = _count_certificates(cfg)
    ui_result = _ui_issue(client, cfg, "", b_id)
    assert ui_result.refused, ui_result.detail
    api_result = _api_issue(client, cfg, secret, b_id)
    assert api_result.refused, api_result.detail
    mcp_result = _mcp_issue(client, cfg, secret, b_id)
    assert mcp_result.refused, mcp_result.detail
    assert _count_certificates(cfg) == before


# === AC-3: superadmin is implicit; viewers are not =============================


def test_superadmin_needs_no_grant(client: TestClient, cfg: Config) -> None:
    """AC-3's positive half: a superadmin holding no grant row issues from
    the active issuer at every one of the six doors."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        ca_fixtures.make_hierarchy(db, secrets, "superadmin-doors")
        create_user(db, "root-admin", _PASSWORD, Role.superadmin)
        _enable_doors(db)
    finally:
        db.close()
    assert _grant_row_counts(cfg) == (0, 0)
    secret, _token_id = _token(cfg, Role.superadmin, label="superadmin-token")
    _login(client, "root-admin")

    before = _count_certificates(cfg)
    for door in _DOORS:
        result = door.attempt(client, cfg, secret, None)
        assert not result.refused, (
            f"{door.name}: a superadmin must not need a grant, got: {result.detail}"
        )
    assert _count_certificates(cfg) == before + len(_DOORS)


def test_granted_viewer_still_refused(client: TestClient, cfg: Config) -> None:
    """AC-3's decisive half. A viewer holding a grant on the only active
    issuer is refused at all six issuance doors *and* all three non-ACME
    revocation doors, with the role refusal -- not a grant refusal. This is
    what catches a ``may_use_issuer`` that returns True whenever a grant row
    exists, without also checking that the role may write at all."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "viewer-doors")
        issuer_id = hierarchy.intermediate.id
        viewer = create_user(db, "viewer-with-grant", _PASSWORD, Role.viewer)
        grant_fixtures.grant_user(db, viewer, issuer_id)
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.viewer, label="viewer-token")
    _grant_token_id(cfg, token_id, issuer_id)
    _login(client, "viewer-with-grant")

    before = _count_certificates(cfg)
    for door in _DOORS:
        result = door.attempt(client, cfg, secret, None)
        assert result.refused, f"{door.name}: a viewer must be refused despite holding every grant"
        if door.kind == "ui":
            assert "forbidden for this role" in result.detail, result.detail
        elif door.kind == "api":
            assert "not allowed to use this endpoint" in result.detail, result.detail
        else:
            assert "may only read" in result.detail, result.detail
    assert _count_certificates(cfg) == before

    cert_ui = _issue_direct(
        cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "viewer-ui-target.lan"
    )
    cert_api = _issue_direct(
        cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "viewer-api-target.lan"
    )
    cert_mcp = _issue_direct(
        cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "viewer-mcp-target.lan"
    )

    ui_res = _ui_revoke(client, cfg, cert_ui)
    assert ui_res.refused, ui_res.detail
    assert _certificate_revoked_at(cfg, cert_ui) is None

    api_res = _api_revoke(client, cfg, secret, cert_api)
    assert api_res.refused, api_res.detail
    assert _certificate_revoked_at(cfg, cert_api) is None

    mcp_res = _mcp_revoke(client, cfg, secret, cert_mcp)
    assert mcp_res.refused, mcp_res.detail
    assert _certificate_revoked_at(cfg, cert_mcp) is None


# === AC-5: a grant on a retired issuer ==========================================


def test_grant_on_retired_issuer_does_not_allow_issuing(client: TestClient, cfg: Config) -> None:
    """AC-5(a): a grant on an issuer that is later retired stops allowing
    new issuance -- and the reported reason is retirement
    (``IssuerRetiredError``), not that the grant is missing
    (``IssuerForbiddenError``): an operator reading the wrong message would
    spend the afternoon editing grants that were never the problem."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "will-retire")
        issuer_id = hierarchy.intermediate.id
        admin = create_user(db, "retiree-admin", _PASSWORD, Role.admin)
        grant_fixtures.grant_user(db, admin, issuer_id)
        principal = grants_mod.user_principal(admin)
        ca_service.retire(db, issuer_id)
    finally:
        db.close()

    db2 = _db(cfg)
    try:
        with pytest.raises(ca_service.IssuerRetiredError):
            certs_service.issue_and_store(
                db2,
                secrets,
                principal=principal,
                profile=Profile.server,
                subject_cn="retired-door.lan",
                sans=["retired-door.lan"],
                issuer_id=issuer_id,
            )
    finally:
        db2.close()

    _login(client, "retiree-admin")
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": "retired-door2.lan",
            "sans": "retired-door2.lan",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "issuer_id": issuer_id,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 400, resp.text
    assert "retire" in resp.text.lower(), resp.text


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_revoke_through_retired_granted_issuer_succeeds(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-5(b) -- the anti-mutation test. 0017 FR-9 requires a retired
    issuer's CRL to stay publishable, and the same grant that allowed
    issuing from an intermediate must keep working for revoking through it
    after it retires, at all three non-ACME doors: an operator who retires a
    compromised intermediate must still be able to revoke what it signed.

    The spec's own author names the mutation this test exists to catch:
    revocation rechecking ``granted_issuers`` (which excludes retired
    issuers by FR-3) instead of ``may_use_issuer`` (status-blind by design)
    passes every other criterion in this suite and only fails here.
    """
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "revoke-retired")
        issuer_id = hierarchy.intermediate.id
        admin = create_user(db, "revoker", _PASSWORD, Role.admin)
        grant_fixtures.grant_user(db, admin, issuer_id)
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.admin, label="revoke-retired-token")
    _grant_token_id(cfg, token_id, issuer_id)

    cert_ui = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "via-ui.lan")
    cert_api = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "via-api.lan")
    cert_mcp = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, issuer_id, "via-mcp.lan")

    db2 = _db(cfg)
    try:
        ca_service.retire(db2, issuer_id)
    finally:
        db2.close()

    _login(client, "revoker")
    ui_res = _ui_revoke(client, cfg, cert_ui)
    assert not ui_res.refused, ui_res.detail
    api_res = _api_revoke(client, cfg, secret, cert_api)
    assert not api_res.refused, api_res.detail
    mcp_res = _mcp_revoke(client, cfg, secret, cert_mcp)
    assert not mcp_res.refused, mcp_res.detail

    expected_serials = {
        _certificate_serial(cfg, cert_ui),
        _certificate_serial(cfg, cert_api),
        _certificate_serial(cfg, cert_mcp),
    }
    snapshot = _crl_snapshot(cfg, issuer_id)
    assert snapshot is not None
    on_crl = _openssl_crl_serials(tmp_path, "retired-revoke", snapshot[1])
    assert expected_serials <= on_crl, (expected_serials, on_crl)


# === AC-6: revocation requires the issuing grant, at all three non-ACME doors ===


def test_revocation_requires_the_issuing_grant(client: TestClient, cfg: Config) -> None:
    """AC-6: an admin granted issuer A cannot revoke a certificate B signed,
    at any of the three non-ACME doors -- and B's CRL (number and bytes) is
    untouched by each refusal. Granting B and repeating one of the three
    then revokes it and changes both.
    """
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        a = ca_fixtures.make_hierarchy(db, secrets, "grant-a").intermediate
        b = ca_fixtures.make_hierarchy(db, secrets, "grant-b").intermediate
        a_id, b_id = a.id, b.id
        admin = create_user(db, "granted-a", _PASSWORD, Role.admin)
        admin_id = admin.id
        grant_fixtures.grant_user(db, admin, a_id)
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.admin, label="grant-a-token")
    _grant_token_id(cfg, token_id, a_id)

    cert_ui = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, b_id, "ui-from-b.lan")
    cert_api = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, b_id, "api-from-b.lan")
    cert_mcp = _issue_direct(cfg, secrets, grants_mod.SYSTEM_PRINCIPAL, b_id, "mcp-from-b.lan")

    _login(client, "granted-a")
    before_b = _crl_snapshot(cfg, b_id)

    ui_res = _ui_revoke(client, cfg, cert_ui)
    assert ui_res.refused, ui_res.detail
    assert _certificate_revoked_at(cfg, cert_ui) is None
    assert _crl_snapshot(cfg, b_id) == before_b

    api_res = _api_revoke(client, cfg, secret, cert_api)
    assert api_res.refused, api_res.detail
    assert _certificate_revoked_at(cfg, cert_api) is None
    assert _crl_snapshot(cfg, b_id) == before_b

    mcp_res = _mcp_revoke(client, cfg, secret, cert_mcp)
    assert mcp_res.refused, mcp_res.detail
    assert _certificate_revoked_at(cfg, cert_mcp) is None
    assert _crl_snapshot(cfg, b_id) == before_b

    # Granting B and repeating one of the three revokes it and changes both.
    _grant_user_id(cfg, admin_id, b_id)
    ui_res2 = _ui_revoke(client, cfg, cert_ui)
    assert not ui_res2.refused, ui_res2.detail
    assert _certificate_revoked_at(cfg, cert_ui) is not None
    assert _crl_snapshot(cfg, b_id) != before_b


# === AC-7: ACME routes around grants; nothing else does ========================


def test_acme_issues_with_no_grants_while_ungranted_admin_is_refused(
    client: TestClient, cfg: Config
) -> None:
    """AC-7, deliberately kept as one test rather than two: an ACME order
    finalizes and revokes into a certificate with **zero** rows in either
    grant table, while in the very same test, against the very same
    database, an ordinary ungranted admin is refused at the plain UI door.
    Split across two tests this pair would pass a build that enforces
    nowhere at all; kept together, an implementation that checks grants
    unconditionally inside ``ca/certs.py`` fails the first half and one
    that checks them nowhere fails the second.
    """
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        ca_fixtures.make_hierarchy(db, secrets, "acme-hierarchy")
        set_setting(db, BASE_URL, ACME_BASE)
        set_setting(db, ACME_ENABLED, TRUE)
        create_user(db, "acme-admin", _PASSWORD, Role.admin)
    finally:
        db.close()
    assert _grant_row_counts(cfg) == (0, 0)

    acme = Acme(client)
    flow = AcmeFlow(acme, cfg, "acme-issued.lan")
    flow.make_ready()
    flow.finalize_ok(csr_der("acme-issued.lan"))
    leaf = flow.leaf()

    revoked = acme.post(
        "/acme/revoke-cert",
        flow.key,
        {"certificate": _b64(leaf.public_bytes(serialization.Encoding.DER))},
        kid=flow.kid,
    )
    assert revoked.status_code == 200, revoked.text
    assert _grant_row_counts(cfg) == (0, 0)

    _login(client, "acme-admin")
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": "not-acme.lan",
            "sans": "not-acme.lan",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 403, resp.text


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# === AC-18: cabin's own TLS certificate does not depend on anyone's grants =====


def test_tls_self_issuance_needs_no_grants(client: TestClient, cfg: Config) -> None:
    """AC-18, heeding the work split's own warning: a fixture that runs as
    a superadmin proves nothing, because every principal in it is
    unrestricted. The admin here is an ordinary admin, explicitly granted
    the one issuer that exists and then explicitly stripped of it -- zero
    rows in ``user_issuers`` when ``TlsManager.ensure_current`` runs -- so
    that reaching ``ca_issued`` afterwards can only be ``SYSTEM_PRINCIPAL``
    at work, never a grant nobody remembered to remove. In the same test an
    ungranted admin is refused at ``POST /certs/issue``, so this cannot be
    satisfied by a build that checks grants nowhere.
    """
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "tls-system")
        issuer_id = hierarchy.intermediate.id
        admin = create_user(db, "tls-admin", _PASSWORD, Role.admin)
        grant_fixtures.grant_user(db, admin, issuer_id)
        grant_fixtures.revoke_user(db, admin, issuer_id)
        set_setting(db, BASE_URL, "https://ca.example.org")
    finally:
        db.close()
    assert _grant_row_counts(cfg) == (0, 0)

    tls_manager = TlsManager(cfg.data_dir)
    db2 = _db(cfg)
    try:
        changed = tls_manager.ensure_current(db2, secrets)
    finally:
        db2.close()
    assert changed is True
    assert tls_manager.mode == TlsMode.ca_issued

    _login(client, "tls-admin")
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": "not-my-cert.lan",
            "sans": "not-my-cert.lan",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 403, resp.text


# === FR-7: both exemptions are named constants, never an absent principal =====


def test_principal_is_required_keyword_only(client: TestClient, cfg: Config) -> None:
    """AC-8: the choke point cannot be forgotten. All three functions
    declare ``principal`` keyword-only with no default, so a future entry
    point (or a mutation) that drops the argument is a ``TypeError``, not a
    silent bypass -- exactly the mechanism that caught ``tls.py:_issue`` as
    an eighth caller nobody had written down."""
    for target in (
        certs_service.issue_and_store,
        certs_service.sign_csr_and_store,
        crl_service.revoke_certificate,
    ):
        sig = inspect.signature(target)
        param = sig.parameters.get("principal")
        assert param is not None, f"{target.__name__} must declare a `principal` parameter"
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"{target.__name__}.principal must be keyword-only, got {param.kind}"
        )
        assert param.default is inspect.Parameter.empty, (
            f"{target.__name__}.principal must have no default"
        )

    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "signature-check")
        issuer_id = hierarchy.intermediate.id
        with pytest.raises(TypeError):
            certs_service.issue_and_store(
                db,
                secrets,
                profile=Profile.server,
                subject_cn="x.lan",
                sans=["x.lan"],
                issuer_id=issuer_id,
            )
        with pytest.raises(TypeError):
            certs_service.sign_csr_and_store(
                db, secrets, csr_pem=_csr_pem("y.lan"), profile=Profile.server, issuer_id=issuer_id
            )
        with pytest.raises(TypeError):
            crl_service.revoke_certificate(db, secrets, 99999)
    finally:
        db.close()


def test_exempt_principal_constants_used_at_exactly_the_expected_call_sites() -> None:
    """FR-7: both exemptions are named constants, and each is greppable at
    exactly the call sites the spec names -- ``SYSTEM_PRINCIPAL`` once in
    ``tls.py``, ``ACME_PRINCIPAL`` twice in ``acme/api_finalize.py``. Source
    inspection rather than behaviour on purpose: a mutation that swaps
    either constant for ``principal=None`` and teaches ``Principal`` (or a
    check upstream of it) to treat ``None`` as "skip the check" is invisible
    to every test that only calls the front doors, because ``None`` would
    still make the door succeed. Grepping for the constant's own name is
    the one check that would not survive that swap.
    """
    tls_source = Path(tls_mod.__file__).read_text()
    assert tls_source.count("SYSTEM_PRINCIPAL") == 1, (
        "SYSTEM_PRINCIPAL must appear at exactly one issue_and_store call site in tls.py"
    )
    finalize_source = Path(acme_finalize_mod.__file__).read_text()
    assert finalize_source.count("ACME_PRINCIPAL") == 2, (
        "ACME_PRINCIPAL must appear at exactly the two call sites in acme/api_finalize.py"
    )


# === AC-9: grants are read fresh, never cached for the life of a connection ====


def test_grant_change_takes_effect_on_the_next_request(client: TestClient, cfg: Config) -> None:
    """AC-9: withdrawing a grant is visible on the very next request, on the
    same session cookie and on the same token secret -- no logout, no
    restart, no token rotation. And the reverse: adding a grant back takes
    effect on the next request too, including the identical token secret
    used over MCP right after it was used over REST -- the two transports
    resolve the same token's grants from the same table on every call, not
    from anything ``mcp/auth.py`` might hold for the life of the transport.
    """
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "fresh-reads")
        issuer_id = hierarchy.intermediate.id
        admin = create_user(db, "fresh-admin", _PASSWORD, Role.admin)
        admin_id = admin.id
        _enable_doors(db)
    finally:
        db.close()
    secret, token_id = _token(cfg, Role.admin, label="fresh-token")
    _login(client, "fresh-admin")

    assert _ui_issue(client, cfg, "", None).refused
    _grant_user_id(cfg, admin_id, issuer_id)
    assert not _ui_issue(client, cfg, "", None).refused
    _revoke_user_grant(cfg, admin_id, issuer_id)
    assert _ui_issue(client, cfg, "", None).refused

    assert _api_issue(client, cfg, secret, None).refused
    _grant_token_id(cfg, token_id, issuer_id)
    assert not _api_issue(client, cfg, secret, None).refused
    _revoke_token_grant(cfg, token_id, issuer_id)
    assert _api_issue(client, cfg, secret, None).refused

    assert _mcp_issue(client, cfg, secret, None).refused
    _grant_token_id(cfg, token_id, issuer_id)
    assert not _mcp_issue(client, cfg, secret, None).refused


def test_mcp_access_token_claims_carry_no_scopes(client: TestClient, cfg: Config) -> None:
    """AC-9's last clause, and a regression test on a file this spec must
    not change (``mcp/auth.py``, read-only per the 0018 work split): the
    claims dict ``CabinTokenVerifier`` builds carries exactly
    ``TOKEN_ID_CLAIM`` and an empty scope list -- nothing that would let a
    withdrawn grant keep working for the life of the transport.
    """
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, "https://ca.example.org")
    finally:
        db.close()
    secret, _token_id = _token(cfg, Role.admin, label="claims-token")

    verifier = CabinTokenVerifier(lambda: _db(cfg))
    access = asyncio.run(verifier.verify_token(secret))
    assert access is not None
    assert access.scopes == []
    assert set(access.claims) == {TOKEN_ID_CLAIM}
