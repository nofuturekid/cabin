"""spec 0017 Interface Contract, Test list -- the highest-value test the
reconciled contract calls out by name:

    Every existing FR-12 test either calls public_http_origin directly or
    hands a pre-built URL to issue_certificate. Nothing checks that the
    real issuance entry points -- web/certs_ui.py, api/v1.py,
    acme/api_finalize.py and mcp/server.py, FR-6's seven call sites between
    them -- actually route production traffic through the helper. An
    implementation that gets the helper exactly right and forgets to wire
    one door to it ships https:// CDP and AIA URLs into real certificates
    and passes every other test in this document.

This file drives all four front doors with a real https:// base URL
configured and parses the CDP/AIA off each resulting certificate. It is new
and unshared on purpose: it belongs to none of Database/Backend/Frontend's
existing files, and putting it in one of them would be exactly the kind of
two-agents-one-file collision the work split exists to avoid.
"""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from acme_client import Acme
from acme_orders import Flow, csr_der
from cryptography import x509
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.ca.certs import get_certificate
from cabin.config import Config
from cabin.mcp import MCP_PATH
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, MCP_ENABLED, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.users import Role

HTTPS_BASE_URL = "https://ca.example.org"

_MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


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


def _configured(client: TestClient, cfg: Config) -> None:
    """Superadmin, a real signed hierarchy built directly against the ORM
    (``/ca/create`` belongs to Frontend and is irrelevant to what this file
    tests -- the same shortcut ``test_acme_finalize.py`` already takes), an
    https:// base URL, and ACME/MCP switched on so all four doors answer."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = _db(cfg)
    try:
        ca_service.create_hierarchy(db, _secrets(cfg), "cabin")
        set_setting(db, BASE_URL, HTTPS_BASE_URL)
        set_setting(db, ACME_ENABLED, TRUE)
        set_setting(db, MCP_ENABLED, TRUE)
    finally:
        db.close()


def _cert_from_db(cfg: Config, cert_id: int) -> x509.Certificate:
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    finally:
        db.close()


def _assert_forced_to_http(cert: x509.Certificate, *, where: str) -> None:
    """AC-9, measured on the real, issued certificate -- not on the
    helper's return value, and not on a URL the test itself built."""
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name is not None
    cdp_uri = cdp[0].full_name[0].value
    assert isinstance(cdp_uri, str), where
    assert cdp_uri.startswith("http://"), f"{where}: CDP URL was {cdp_uri!r}"
    assert "https" not in cdp_uri, f"{where}: CDP URL was {cdp_uri!r}"

    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    aia_uri = next(iter(aia)).access_location.value
    assert isinstance(aia_uri, str), where
    assert aia_uri.startswith("http://"), f"{where}: AIA URL was {aia_uri!r}"
    assert "https" not in aia_uri, f"{where}: AIA URL was {aia_uri!r}"


def _mcp_structured_result(
    client: TestClient, token: str, tool: str, arguments: dict[str, object]
) -> dict[str, object]:
    resp = client.post(
        MCP_PATH,
        headers={**_MCP_HEADERS, "Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )
    assert resp.status_code == 200, resp.text
    payload: dict[str, object] | None = None
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
            break
    assert payload is not None, resp.text
    result = payload["result"]
    assert isinstance(result, dict)
    assert result.get("isError") is not True, result
    structured = result["structuredContent"]
    assert isinstance(structured, dict)
    return structured


def test_issuance_entry_points_use_the_forced_http_origin(client: TestClient, cfg: Config) -> None:
    """Four certificates, four front doors, one https:// setting -- every
    one of the four must come back with its CDP and AIA forced to http.
    A wrong implementation that gets public_http_origin exactly right but
    forgets to route one door through it fails exactly one of these four
    assertions and no other test in the project."""
    _configured(client, cfg)

    # --- web/certs_ui.py ---------------------------------------------------
    web_resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": "web-door.example.lan",
            "sans": "web-door.example.lan",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert web_resp.status_code == 303, web_resp.text
    web_cert_id = int(web_resp.headers["location"].rsplit("/", 1)[1])
    _assert_forced_to_http(_cert_from_db(cfg, web_cert_id), where="web/certs_ui.py")

    # --- api/v1.py -----------------------------------------------------------
    db = _db(cfg)
    try:
        api_token, _row = create_token(db, "api-door-token", Role.admin)
    finally:
        db.close()
    api_resp = client.post(
        "/api/v1/certificates",
        json={
            "subject_cn": "api-door.example.lan",
            "sans": ["api-door.example.lan"],
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
        },
        headers={"Authorization": f"Bearer {api_token}"},
    )
    assert api_resp.status_code == 201, api_resp.text
    api_cert = x509.load_pem_x509_certificate(str(api_resp.json()["cert_pem"]).encode("ascii"))
    _assert_forced_to_http(api_cert, where="api/v1.py")

    # --- acme/api_finalize.py -------------------------------------------------
    # make_ready() marks the authorization valid directly in the database
    # rather than re-proving an http-01 challenge -- spec 0011's subject,
    # not this file's (same shortcut acme_orders.py documents for itself).
    acme = Acme(client)
    flow = Flow(acme, cfg, "acme-door.example.lan")
    flow.make_ready()
    flow.finalize_ok(csr_der("acme-door.example.lan"))
    _assert_forced_to_http(flow.leaf(), where="acme/api_finalize.py")

    # --- mcp/server.py ---------------------------------------------------------
    db = _db(cfg)
    try:
        mcp_token, _row = create_token(db, "mcp-door-token", Role.admin)
    finally:
        db.close()
    structured = _mcp_structured_result(
        client, mcp_token, "issue_certificate", {"subject_cn": "mcp-door.example.lan"}
    )
    mcp_cert = x509.load_pem_x509_certificate(str(structured["cert_pem"]).encode("ascii"))
    _assert_forced_to_http(mcp_cert, where="mcp/server.py")
