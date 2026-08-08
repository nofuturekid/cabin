"""Tests for the MCP server of spec 0013 (FR-1..FR-6, AC-1..AC-8).

The client here is a raw JSON-RPC POST rather than an MCP SDK client: the
transport is stateless streamable-HTTP, so one POST is one complete
request/response, and spelling it out keeps the tests honest about the
*wire* -- which is what AC-1, AC-3 and the mount-path check are actually
about.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import grant_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.api import views
from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.audit import AuditEvent
from cabin.ca.certs import MAX_PAGE, MAX_QUERY_LENGTH, Certificate, CertSource
from cabin.ca.crl import current_crl
from cabin.ca.leaf import MAX_CN_LENGTH, MAX_DAYS, MAX_SANS, MIN_DAYS
from cabin.ca.service import CACertificate, active_issuers
from cabin.config import Config
from cabin.mcp import MCP_PATH
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, MCP_ENABLED, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.users import Role

BASE = "https://ca.example.org"
# FR-12: URLs baked into a certificate (e.g. the CRL URL) are always
# http://, never https://, regardless of the configured (https) base_url.
HTTP_BASE = "http://ca.example.org"

#: What the streamable-HTTP transport requires a client to accept.
_ACCEPT = "application/json, text/event-stream"
_HEADERS = {"Accept": _ACCEPT, "Content-Type": "application/json"}

_TOOL_NAMES = {
    "get_ca_info",
    "list_certificates",
    "get_certificate",
    "issue_certificate",
    "sign_csr",
    "revoke_certificate",
}

#: Every method a client could send. The gate has to see all of them: a
#: method the endpoint does not implement must not be answered by the router
#: above it, or "switched off" would answer 405 while "does not exist"
#: answers 404 (AC-1).
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


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


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _configure(client: TestClient, cfg: Config, *, enable_mcp: bool) -> None:
    """A configured instance with no browser session left behind: MCP knows
    nothing about cookies, and every test here starts from that."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    assert (
        client.post(
            "/ca/create",
            data={
                "name": "cabin",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, BASE)
        if enable_mcp:
            set_setting(db, MCP_ENABLED, TRUE)
    finally:
        db.close()
    client.cookies.clear()


@pytest.fixture
def mcp(client: TestClient, cfg: Config) -> TestClient:
    _configure(client, cfg, enable_mcp=True)
    return client


@pytest.fixture
def off(client: TestClient, cfg: Config) -> TestClient:
    _configure(client, cfg, enable_mcp=False)
    return client


def _login(client: TestClient) -> None:
    """Take the browser session back, for the few assertions that are about
    what an operator *sees* rather than about MCP."""
    assert (
        client.post("/login", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _token(cfg: Config, role: Role, expires_at: datetime | None = None) -> str:
    db = _db(cfg)
    try:
        secret, _ = create_token(db, f"{role.value}-token", role, expires_at=expires_at)
        return secret
    finally:
        db.close()


def _granted_token(cfg: Config, role: Role, expires_at: datetime | None = None) -> str:
    """Like :func:`_token`, but also granted the instance's sole active
    issuer. Spec 0018 requires an explicit grant before a token may issue
    or revoke; a bare admin token is correctly refused, so every test here
    whose token actually issues or revokes uses this instead of ``_token``.
    """
    db = _db(cfg)
    try:
        secret, token = create_token(db, f"{role.value}-token", role, expires_at=expires_at)
        grant_fixtures.grant_token(db, token, active_issuers(db)[0].id)
        return secret
    finally:
        db.close()


def _post(
    client: TestClient,
    method: str,
    params: dict[str, object] | None = None,
    *,
    token: str | None,
    path: str = MCP_PATH,
) -> Response:
    headers = dict(_HEADERS)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    body: dict[str, object] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return client.post(path, headers=headers, json=body)


def _payload(resp: Response) -> dict[str, object]:
    """The one JSON-RPC message in a streamable-HTTP response."""
    assert resp.status_code == 200, resp.text
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            decoded: dict[str, object] = json.loads(line[len("data: ") :])
            return decoded
    raise AssertionError(f"no JSON-RPC payload in {resp.text!r}")


def _rpc(
    client: TestClient,
    method: str,
    params: dict[str, object] | None = None,
    *,
    token: str,
) -> dict[str, object]:
    message = _payload(_post(client, method, params, token=token))
    assert "error" not in message, message
    result = message["result"]
    assert isinstance(result, dict)
    return result


def _tools(client: TestClient, token: str) -> list[dict[str, object]]:
    tools = _rpc(client, "tools/list", token=token)["tools"]
    assert isinstance(tools, list)
    return tools


def _raw_call(
    client: TestClient, name: str, arguments: dict[str, object], *, token: str
) -> dict[str, object]:
    return _rpc(client, "tools/call", {"name": name, "arguments": arguments}, token=token)


def _call(
    client: TestClient,
    name: str,
    arguments: dict[str, object] | None = None,
    *,
    token: str,
) -> dict[str, object]:
    """One successful tool call, as its structured result."""
    result = _raw_call(client, name, arguments or {}, token=token)
    assert result.get("isError") is not True, result
    structured = result["structuredContent"]
    assert isinstance(structured, dict)
    return structured


def _call_error(
    client: TestClient,
    name: str,
    arguments: dict[str, object] | None = None,
    *,
    token: str,
    expect: str,
) -> str:
    """The message of a refused tool call.

    ``expect`` is required rather than optional: "it failed somehow" is not
    what FR-3 asks for -- the model has to be told what was wrong with the
    call, so every one of these tests names the sentence it wants.
    """
    result = _raw_call(client, name, arguments or {}, token=token)
    assert result.get("isError") is True, result
    content = result["content"]
    assert isinstance(content, list) and content
    text = content[0]["text"]
    assert isinstance(text, str) and text
    assert "Traceback" not in text
    assert expect in text, text
    return text


def _csr_pem(
    cn: str,
    sans: list[x509.GeneralName],
    extra: list[tuple[x509.ExtensionType, bool]] | None = None,
) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
    )
    for extension, critical in extra or []:
        builder = builder.add_extension(extension, critical=critical)
    return (
        builder.sign(key, algorithm=hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def _events(cfg: Config) -> list[AuditEvent]:
    db = _db(cfg)
    try:
        return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    finally:
        db.close()


# --- FR-4 / AC-1: off means invisible ------------------------------------------


def test_mcp_disabled_returns_404(off: TestClient, cfg: Config) -> None:
    """AC-1: while ``mcp_enabled`` is off, /mcp does not exist -- for an
    anonymous caller, for a perfectly good admin token, and for every method,
    including the ones the endpoint would not implement anyway.

    That last part is the one worth spelling out: a route that declares its
    methods lets the router answer 405 with an ``Allow`` header *before* the
    gate runs, and a 405 is an admission that the path exists.
    """
    admin = _token(cfg, Role.admin)
    for token in (None, admin):
        assert _post(off, "tools/list", token=token).status_code == 404

    auth = {**_HEADERS, "Authorization": f"Bearer {admin}"}
    for path in (MCP_PATH, f"{MCP_PATH}/", f"{MCP_PATH}/anything"):
        for method in _METHODS:
            resp = off.request(method, path, headers=auth)
            assert resp.status_code == 404, (method, path, resp.status_code)
            assert "allow" not in resp.headers, (method, path)


def test_mcp_enabled_answers_every_method_itself(mcp: TestClient, cfg: Config) -> None:
    """The other half of the gate: once MCP is on, every method reaches the
    endpoint and the endpoint decides -- 405 for the ones a stateless
    transport does not implement, never a 404 from the router above it."""
    auth = {**_HEADERS, "Authorization": f"Bearer {_token(cfg, Role.admin)}"}
    for method in _METHODS:
        resp = mcp.request(method, MCP_PATH, headers=auth)
        assert resp.status_code != 404, (method, resp.status_code)
    assert _post(mcp, "tools/list", token=_token(cfg, Role.admin)).status_code == 200


# --- FR-1 / FR-3 / AC-2: the endpoint and its tools ----------------------------


def test_mcp_mount_path_is_correct(mcp: TestClient, cfg: Config) -> None:
    """FR-1: the endpoint is at exactly /mcp under the mount prefix.

    The client is configured with ``https://ca.example.org/mcp``, so that
    path has to answer on its own -- not via a 307 to /mcp/, which is what a
    sub-app mounted one level too deep produces (python-sdk#1367), and not
    at /mcp/mcp, which is what a sub-app mounted one level too shallow does.
    """
    admin = _token(cfg, Role.admin)
    resp = _post(mcp, "tools/list", token=admin)
    assert resp.status_code == 200, resp.text
    assert resp.history == []
    assert "location" not in resp.headers

    for wrong in (f"{MCP_PATH}/", f"{MCP_PATH}/mcp"):
        assert _post(mcp, "tools/list", token=admin, path=wrong).status_code == 404, wrong


def test_mcp_lists_tools(mcp: TestClient, cfg: Config) -> None:
    """AC-2: exactly the six tools of FR-3, each with a schema and the
    docstring the model is meant to read."""
    tools = _tools(mcp, _token(cfg, Role.viewer))
    assert {tool["name"] for tool in tools} == _TOOL_NAMES
    for tool in tools:
        assert tool["description"], tool["name"]
        schema = tool["inputSchema"]
        assert isinstance(schema, dict)
        assert schema["type"] == "object"

    by_name = {tool["name"]: tool for tool in tools}
    issue = by_name["issue_certificate"]["inputSchema"]
    assert isinstance(issue, dict)
    properties = issue["properties"]
    assert isinstance(properties, dict)
    # FR-6: an MCP client must be able to select an issuer, or MCP can issue
    # nothing at all from the moment a second issuer exists -- optional, so
    # a single-issuer instance is unaffected and the FR-6 default still
    # applies when it is omitted.
    assert set(properties) == {"subject_cn", "sans", "profile", "key_type", "days", "issuer_id"}
    assert issue["required"] == ["subject_cn"]

    sign = by_name["sign_csr"]["inputSchema"]
    assert isinstance(sign, dict)
    sign_properties = sign["properties"]
    assert isinstance(sign_properties, dict)
    assert set(sign_properties) == {"csr_pem", "profile", "days", "sans", "issuer_id"}
    assert sign["required"] == ["csr_pem"]


# --- FR-2 / AC-3: tokens and roles ---------------------------------------------


def test_mcp_requires_token(mcp: TestClient, cfg: Config) -> None:
    """AC-3: no token is a transport-level 401, and so is every shape of
    credential that is not a live cabin token."""
    expired = _token(cfg, Role.admin, expires_at=datetime.now(UTC) - timedelta(minutes=1))
    for headers in (
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer cabin_" + "A" * 43},
        {"Authorization": f"Bearer {expired}"},
    ):
        resp = mcp.post(
            MCP_PATH,
            headers={**_HEADERS, **headers},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert resp.status_code == 401, headers
        assert resp.headers.get("www-authenticate", "").startswith("Bearer")


def test_mcp_cookie_does_not_authenticate(client: TestClient, cfg: Config) -> None:
    """FR-2: no session cookies. A logged-in browser is worth nothing here."""
    _configure(client, cfg, enable_mcp=True)
    _login(client)
    assert client.cookies.get("cabin_session")
    assert _post(client, "tools/list", token=None).status_code == 401


def test_mcp_role_enforced(mcp: TestClient, cfg: Config) -> None:
    """AC-3: a viewer reads; issuing, signing and revoking are admin+ and are
    refused with a message that says so, not with a crash."""
    viewer = _token(cfg, Role.viewer)
    admin = _granted_token(cfg, Role.admin)

    assert _call(mcp, "get_ca_info", token=viewer)["base_url"] == BASE
    assert _call(mcp, "list_certificates", token=viewer)["total"] == 0

    csr = _csr_pem("app.lan", [x509.DNSName("app.lan")])
    refused = {
        "issue_certificate": {"subject_cn": "nas.lan"},
        "sign_csr": {"csr_pem": csr},
        "revoke_certificate": {"certificate_id": 1},
    }
    for name, arguments in refused.items():
        message = _call_error(
            mcp, name, arguments, token=viewer, expect="this token's role is viewer"
        )
        assert "admin or superadmin role" in message

    issued = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)
    assert _call(mcp, "sign_csr", {"csr_pem": csr}, token=admin)["subject_cn"] == "app.lan"
    assert (
        _call(mcp, "revoke_certificate", {"certificate_id": issued["id"]}, token=admin)["status"]
        == "revoked"
    )


# --- FR-3: the read tools ------------------------------------------------------


def test_mcp_get_ca_info(mcp: TestClient, cfg: Config) -> None:
    """FR-3/AC-15: one entry per ``ca_certificates`` row -- the same shape
    GET /api/v1/ca reports, plus the ACME directory."""
    info = _call(mcp, "get_ca_info", token=_token(cfg, Role.viewer))
    assert info["base_url"] == BASE
    issuers = info["issuers"]
    assert isinstance(issuers, list)
    # ACME is off, so there is no directory URL to hand out.
    assert info["acme_directory_url"] is None

    db = _db(cfg)
    try:
        by_id = {row.id: row for row in active_issuers(db)}
        root = db.get(CACertificate, next(iter(by_id.values())).parent_id)
        assert root is not None
        expected = {
            "root": root.cert_pem,
            "intermediate": next(iter(by_id.values())).cert_pem,
        }
        set_setting(db, ACME_ENABLED, TRUE)
    finally:
        db.close()

    described_by_kind = {row["kind"]: row for row in issuers}
    for kind, pem in expected.items():
        described = described_by_kind[kind]
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        assert described["kind"] == kind
        assert described["status"] == "active"
        assert described["subject"] == cert.subject.rfc4514_string()
        assert (
            described["fingerprint"].replace(":", "").lower()
            == cert.fingerprint(hashes.SHA256()).hex()
        )
        assert described["not_valid_after"].startswith(cert.not_valid_after_utc.date().isoformat())
    assert described_by_kind["root"]["parent_id"] is None
    assert described_by_kind["intermediate"]["parent_id"] == described_by_kind["root"]["id"]

    again = _call(mcp, "get_ca_info", token=_token(cfg, Role.viewer))
    assert again["acme_directory_url"] == f"{BASE}/acme/directory"


def test_mcp_ca_info_matches_rest(mcp: TestClient, cfg: Config) -> None:
    """AC-15: the MCP tool and the REST endpoint report the same ids and
    statuses against the same database."""
    admin = _token(cfg, Role.admin)
    mcp_info = _call(mcp, "get_ca_info", token=admin)

    resp = mcp.get("/api/v1/ca", headers={"Authorization": f"Bearer {admin}"})
    assert resp.status_code == 200
    rest_issuers = resp.json()["issuers"]

    mcp_by_id = {row["id"]: (row["kind"], row["status"]) for row in mcp_info["issuers"]}  # type: ignore[union-attr]
    rest_by_id = {row["id"]: (row["kind"], row["status"]) for row in rest_issuers}
    assert mcp_by_id == rest_by_id


def test_mcp_list_and_get_certificate(mcp: TestClient, cfg: Config) -> None:
    """FR-3: the spec-0006 inventory with its filters, and one certificate
    with its chain."""
    admin = _granted_token(cfg, Role.admin)
    nas = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)
    _call(mcp, "issue_certificate", {"subject_cn": "app.lan"}, token=admin)

    listed = _call(mcp, "list_certificates", token=admin)
    assert listed["total"] == 2
    assert listed["page"] == 1
    assert listed["pages"] == 1
    items = listed["items"]
    assert isinstance(items, list)
    assert {item["subject_cn"] for item in items} == {"nas.lan", "app.lan"}
    # Metadata only: no PEM of any kind on an inventory row.
    assert all("cert_pem" not in item for item in items)

    filtered = _call(mcp, "list_certificates", {"query": "nas"}, token=admin)
    assert filtered["total"] == 1
    assert _call(mcp, "list_certificates", {"status": "revoked"}, token=admin)["total"] == 0
    assert _call(mcp, "list_certificates", {"page": 2}, token=admin)["items"] == []

    detail = _call(mcp, "get_certificate", {"certificate_id": nas["id"]}, token=admin)
    assert detail["subject_cn"] == "nas.lan"
    assert detail["status"] == "valid"
    assert detail["has_key"] is True
    leaf = x509.load_pem_x509_certificate(str(detail["cert_pem"]).encode("ascii"))
    assert leaf.subject.rfc4514_string() == "CN=nas.lan"
    chain = str(detail["chain_pem"])
    assert chain.count("BEGIN CERTIFICATE") == 2

    _call_error(
        mcp,
        "get_certificate",
        {"certificate_id": 9999},
        token=admin,
        expect="no such certificate: 9999",
    )


def test_mcp_get_certificate_never_returns_key(mcp: TestClient, cfg: Config) -> None:
    """FR-3/AC-4: no role, not even superadmin, gets key material back out of
    a lookup -- the field does not exist on the tool's result at all."""
    admin = _granted_token(cfg, Role.admin)
    issued = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)
    assert issued["key_pem"]

    for token in (_token(cfg, Role.viewer), admin, _token(cfg, Role.superadmin)):
        detail = _call(mcp, "get_certificate", {"certificate_id": issued["id"]}, token=token)
        assert "key_pem" not in detail
        assert "key_error" not in detail
        assert "PRIVATE KEY" not in json.dumps(detail)

    tools = {tool["name"]: tool for tool in _tools(mcp, admin)}
    for name in _TOOL_NAMES - {"issue_certificate"}:
        assert "key_pem" not in json.dumps(tools[name])


# --- FR-3 / FR-5 / AC-4: issuance ----------------------------------------------


def test_mcp_issue_certificate(mcp: TestClient, cfg: Config) -> None:
    """AC-4: a real certificate that chains to the intermediate, with the one
    private key any MCP tool ever returns -- and it matches."""
    admin = _granted_token(cfg, Role.admin)
    issued = _call(
        mcp,
        "issue_certificate",
        {
            "subject_cn": "nas.lan",
            "sans": ["nas.lan", "ip:10.0.0.5"],
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
        },
        token=admin,
    )
    cert = x509.load_pem_x509_certificate(str(issued["cert_pem"]).encode("ascii"))
    assert cert.subject.rfc4514_string() == "CN=nas.lan"
    assert issued["sans"] == ["DNS:nas.lan", "IP:10.0.0.5"]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]

    key = serialization.load_pem_private_key(str(issued["key_pem"]).encode("ascii"), password=None)
    assert key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    db = _db(cfg)
    try:
        issuer_row = active_issuers(db)[0]
        intermediate = x509.load_pem_x509_certificate(issuer_row.cert_pem.encode("ascii"))
    finally:
        db.close()
    assert cert.issuer == intermediate.subject
    intermediate.public_key().verify(  # type: ignore[call-arg,union-attr]
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )

    # AC-4: and it is in the inventory the UI and the API show.
    page = _call(mcp, "list_certificates", {"query": "nas.lan"}, token=admin)
    assert page["total"] == 1


def test_mcp_responses_are_never_cached(mcp: TestClient, cfg: Config) -> None:
    """One MCP response carries a private key and the rest carry certificate
    metadata, so nothing in between may keep a copy -- the same rule
    ``api/v1._no_store`` applies to the identical REST payload.

    Set on the endpoint rather than per tool because the transport gives a
    tool no handle on its own response; ``no-cache``/``no-transform``, which
    the streaming transport needs, survive alongside it.
    """
    admin = _granted_token(cfg, Role.admin)
    resp = _post(
        mcp,
        "tools/call",
        {"name": "issue_certificate", "arguments": {"subject_cn": "nas.lan"}},
        token=admin,
    )
    assert resp.status_code == 200, resp.text
    assert "PRIVATE KEY" in resp.text
    cache_control = resp.headers["cache-control"]
    assert "no-store" in cache_control
    assert "no-transform" in cache_control
    assert resp.headers["pragma"] == "no-cache"

    # Including the answers that are not 200s -- a 401 is not interesting to
    # cache, but the rule is the endpoint's, not the route's.
    assert "no-store" in _post(mcp, "tools/list", token=None).headers["cache-control"]


def test_mcp_issue_sets_source_mcp(mcp: TestClient, cfg: Config) -> None:
    """FR-5/AC-4: both mutating issuance paths record where the request came
    from, and the operator sees it on the row -- an assistant's work has to be
    recognizable in the inventory, not only in the database."""
    admin = _granted_token(cfg, Role.admin)
    _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)
    _call(
        mcp,
        "sign_csr",
        {"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")])},
        token=admin,
    )

    db = _db(cfg)
    try:
        rows = list(db.scalars(select(Certificate).order_by(Certificate.id)))
    finally:
        db.close()
    assert [row.source for row in rows] == [CertSource.mcp, CertSource.mcp]
    assert CertSource.mcp == "mcp"

    # The rendered page, not just the column: /certs badges every row with
    # where it came from (spec 0012 FR-7), and "mcp" is a value it has to
    # know about.
    _login(mcp)
    listing = mcp.get("/certs")
    assert listing.status_code == 200, listing.text
    assert listing.text.count("tag-source-mcp") == 2
    assert "tag-source-ui" not in listing.text


# --- FR-3 / AC-5: CSR signing --------------------------------------------------


def test_mcp_sign_csr(mcp: TestClient, cfg: Config) -> None:
    """FR-3: the CSR contributes its public key, CN and SANs; cabin never
    sees a key, so none comes back."""
    admin = _granted_token(cfg, Role.admin)
    csr = _csr_pem("app.lan", [x509.DNSName("app.lan"), x509.DNSName("www.app.lan")])
    signed = _call(mcp, "sign_csr", {"csr_pem": csr, "profile": "client", "days": 30}, token=admin)

    assert signed["subject_cn"] == "app.lan"
    assert signed["sans"] == ["DNS:app.lan", "DNS:www.app.lan"]
    assert signed["has_key"] is False
    assert "key_pem" not in signed
    cert = x509.load_pem_x509_certificate(str(signed["cert_pem"]).encode("ascii"))
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]

    overridden = _call(mcp, "sign_csr", {"csr_pem": csr, "sans": ["other.lan"]}, token=admin)
    assert overridden["sans"] == ["DNS:other.lan"]


def test_mcp_sign_csr_smuggling_blocked(mcp: TestClient, cfg: Config) -> None:
    """AC-5: the hostile CSR from spec 0005 yields an ordinary leaf, and a
    broken one a readable message."""
    admin = _granted_token(cfg, Role.admin)
    csr = _csr_pem(
        "evil.lan",
        [x509.DNSName("evil.lan")],
        extra=[
            (x509.BasicConstraints(ca=True, path_length=3), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
        ],
    )
    signed = _call(mcp, "sign_csr", {"csr_pem": csr}, token=admin)
    cert = x509.load_pem_x509_certificate(str(signed["cert_pem"]).encode("ascii"))
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is False
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.SERVER_AUTH
    ]

    _call_error(
        mcp,
        "sign_csr",
        {"csr_pem": "not a csr"},
        token=admin,
        expect="not a valid CSR PEM",
    )


# --- FR-3 / AC-6: revocation ---------------------------------------------------


def test_mcp_revoke_certificate(mcp: TestClient, cfg: Config) -> None:
    """AC-6: revoked, and the serial is on the published CRL."""
    admin = _granted_token(cfg, Role.admin)
    issued = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)

    revoked = _call(
        mcp,
        "revoke_certificate",
        {"certificate_id": issued["id"], "reason": "key_compromise"},
        token=admin,
    )
    assert revoked["status"] == "revoked"
    assert revoked["reason"] == "key_compromise"
    # FR-12: the CRL URL is always http://, never https://, even though the
    # configured base_url is https:// -- otherwise validating a cabin
    # certificate would require fetching its CRL over TLS, which would
    # require validating that certificate.
    assert str(revoked["crl_url"]).startswith(HTTP_BASE)
    assert not str(revoked["crl_url"]).startswith("https"), revoked["crl_url"]
    assert "/crl/" in str(revoked["crl_url"])

    # The route that serves /crl/{issuer_id} is Security's (spec 0017 work
    # split); checked here through the service layer instead.
    db = _db(cfg)
    try:
        issuer_id = active_issuers(db)[0].id
        state = current_crl(db, SecretStore.open(cfg.data_dir, None), issuer_id)
    finally:
        db.close()
    crl = x509.load_der_x509_crl(state.crl_der)
    assert crl.get_revoked_certificate_by_serial_number(int(str(issued["serial_hex"]), 16))

    detail = _call(mcp, "get_certificate", {"certificate_id": issued["id"]}, token=admin)
    assert detail["status"] == "revoked"

    _call_error(
        mcp,
        "revoke_certificate",
        {"certificate_id": 9999},
        token=admin,
        expect="no certificate with id 9999",
    )


def test_mcp_revoke_idempotent(mcp: TestClient, cfg: Config) -> None:
    """AC-6/AC-7: revoking twice succeeds, keeps the first date and reason,
    and does not write a second audit event."""
    admin = _granted_token(cfg, Role.admin)
    issued = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)

    first = _call(
        mcp,
        "revoke_certificate",
        {"certificate_id": issued["id"], "reason": "superseded"},
        token=admin,
    )
    second = _call(
        mcp,
        "revoke_certificate",
        {"certificate_id": issued["id"], "reason": "key_compromise"},
        token=admin,
    )
    assert second["revoked_at"] == first["revoked_at"]
    assert second["reason"] == "superseded"

    revocations = [event for event in _events(cfg) if event.action == "cert_revoked"]
    assert len(revocations) == 1


# --- FR-3 / AC-8: validation ---------------------------------------------------


def test_mcp_validation_errors(mcp: TestClient, cfg: Config) -> None:
    """AC-8: the REST API's limits, enforced here too, and reported as
    sentences rather than as stack traces."""
    admin = _granted_token(cfg, Role.admin)
    csr = _csr_pem("app.lan", [x509.DNSName("app.lan")])

    for arguments, expected in (
        (
            {"subject_cn": "nas.lan", "days": MIN_DAYS - 1},
            f"days: Input should be greater than or equal to {MIN_DAYS}",
        ),
        (
            {"subject_cn": "nas.lan", "days": MAX_DAYS + 1},
            f"days: Input should be less than or equal to {MAX_DAYS}",
        ),
        (
            {
                "subject_cn": "nas.lan",
                "sans": [f"h{index}.lan" for index in range(MAX_SANS + 1)],
            },
            f"sans: List should have at most {MAX_SANS} items",
        ),
        (
            {"subject_cn": "n" * (MAX_CN_LENGTH + 1)},
            f"subject_cn: String should have at most {MAX_CN_LENGTH} characters",
        ),
        ({"subject_cn": ""}, "subject_cn: String should have at least 1 character"),
        # Not a limit but a policy, and it comes from the domain layer rather
        # than from a request model -- both have to read as a sentence.
        (
            {"subject_cn": "nas.lan", "sans": ["!!"]},
            "not a valid hostname: '!!'",
        ),
        # A type the schema declares and the caller got wrong: rejected by the
        # transport's own argument validation, still without a traceback.
        (
            {"subject_cn": "nas.lan", "days": "many"},
            "Input should be a valid integer",
        ),
    ):
        _call_error(mcp, "issue_certificate", arguments, token=admin, expect=expected)

    _call_error(
        mcp,
        "sign_csr",
        {"csr_pem": csr, "days": 0},
        token=admin,
        expect=f"days: Input should be greater than or equal to {MIN_DAYS}",
    )

    # The inventory's page bound, the same one GET /api/v1/certificates
    # enforces -- an absurd page must be refused, not echoed back.
    for page, expected in (
        (0, "greater than or equal to 1"),
        (MAX_PAGE + 1, f"less than or equal to {MAX_PAGE}"),
    ):
        _call_error(mcp, "list_certificates", {"page": page}, token=admin, expect=expected)
    _call_error(
        mcp,
        "list_certificates",
        {"query": "x" * (MAX_QUERY_LENGTH + 1)},
        token=admin,
        expect=f"at most {MAX_QUERY_LENGTH} characters",
    )

    # Nothing was issued by any of them.
    assert _call(mcp, "list_certificates", token=admin)["total"] == 0


def test_mcp_no_ca_is_a_message(client: TestClient, cfg: Config) -> None:
    """A cabin without a CA answers the tools with a sentence, not a 500."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, BASE)
        set_setting(db, MCP_ENABLED, TRUE)
    finally:
        db.close()
    client.cookies.clear()

    admin = _token(cfg, Role.admin)
    _call_error(
        client,
        "get_ca_info",
        token=admin,
        expect="no CA has been created or imported yet",
    )
    _call_error(
        client,
        "issue_certificate",
        {"subject_cn": "nas.lan"},
        token=admin,
        expect="no CA hierarchy has been created or imported yet",
    )


def test_mcp_masks_unexpected_errors(
    mcp: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-3: a failure cabin did not anticipate says so and nothing else.

    fastmcp relays the text of an unhandled exception to the caller unless it
    is told not to, and the exceptions that reach it here are database ones:
    SQLAlchemy's ``StatementError`` puts the failing SQL *and its bound
    parameters* in its message, which for this application means a
    certificate PEM and a sealed private key, and SQLite's puts the path to
    the data directory in it. Any live token would receive that, viewer
    included -- so the check is that a marker planted inside an exception
    does not come back, while the messages cabin does mean to send still do.
    """
    marker = "s3cr3t-/var/lib/cabin/secret.key"

    def _boom(db: Session) -> None:
        raise RuntimeError(marker)

    monkeypatch.setattr(views, "ca_info", _boom)
    admin = _token(cfg, Role.admin)
    message = _call_error(mcp, "get_ca_info", token=admin, expect="get_ca_info")
    assert marker not in message
    assert "secret.key" not in message

    monkeypatch.undo()
    # ...and the messages that are meant for the caller are untouched.
    _call_error(
        mcp,
        "get_certificate",
        {"certificate_id": 9999},
        token=admin,
        expect="no such certificate: 9999",
    )
    assert _call(mcp, "get_ca_info", token=admin)["base_url"] == BASE


# --- FR-5 / AC-7: the audit log ------------------------------------------------


def test_mcp_audit_events(mcp: TestClient, cfg: Config) -> None:
    """AC-7: one event per mutating call, attributed to the token and marked
    as having come through MCP; the read tools write nothing."""
    admin = _granted_token(cfg, Role.admin)
    before = len(_events(cfg))

    for _ in range(2):
        _call(mcp, "get_ca_info", token=admin)
        _call(mcp, "list_certificates", token=admin)
    assert len(_events(cfg)) == before

    issued = _call(mcp, "issue_certificate", {"subject_cn": "nas.lan"}, token=admin)
    _call(
        mcp,
        "sign_csr",
        {"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")])},
        token=admin,
    )
    _call(mcp, "revoke_certificate", {"certificate_id": issued["id"]}, token=admin)
    _call(mcp, "get_certificate", {"certificate_id": issued["id"]}, token=admin)

    events = _events(cfg)[before:]
    assert [event.action for event in events] == [
        "cert_issued",
        "cert_signed",
        "cert_revoked",
    ]
    for event in events:
        assert event.actor_kind == "token"
        assert event.actor_label == "admin-token"
        assert event.detail is not None
        assert event.detail["via"] == "mcp"
        # FR-3 of spec 0009 still holds: metadata only.
        assert "key_pem" not in json.dumps(event.detail)
        assert "PRIVATE KEY" not in json.dumps(event.detail)
