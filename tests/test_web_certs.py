"""Web-layer tests for spec 0005: the /certs issue + sign UI, result page,
and role guards (FR-6/FR-7, AC-6)."""

import ipaddress
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.certs import get_certificate
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    factory = create_session_factory(cfg.db_url)
    return factory()


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _create_ca(client: TestClient, cfg: Config) -> None:
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _csr_pem(cn: str, sans: list[x509.GeneralName]) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _issue(client: TestClient, cfg: Config, **overrides: str) -> Response:
    data = {
        "subject_cn": "nas.lan",
        "sans": "nas.lan\nip:10.0.0.5",
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": "90",
        "csrf_token": _csrf(client, cfg),
    }
    data.update(overrides)
    return client.post("/certs/issue", data=data)


# --- FR-6/AC-6: direct issuance through the UI --------------------------------


def test_ui_issue_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)

    resp = client.get("/certs/new")
    assert resp.status_code == 200
    assert "Issue a certificate" in resp.text
    assert "Sign a CSR" in resp.text

    resp = _issue(client, cfg)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("/certs/")

    detail = client.get(location)
    assert detail.status_code == 200
    assert "nas.lan" in detail.text
    assert "10.0.0.5" in detail.text
    assert "BEGIN CERTIFICATE" in detail.text
    # FR-6: server-generated key is shown, with the "also stored" note
    assert "BEGIN PRIVATE KEY" in detail.text
    assert "stored encrypted" in detail.text

    db = _db(cfg)
    try:
        row = get_certificate(db, int(location.rsplit("/", 1)[1]))
        assert row is not None
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
        assert cert.subject.rfc4514_string() == "CN=nas.lan"
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert san.get_values_for_type(x509.DNSName) == ["nas.lan"]
        assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("10.0.0.5")]
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
        assert row.key_sealed is not None
    finally:
        db.close()


def test_ui_sign_csr_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)

    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")]),
            "profile": "client",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    location = resp.headers["location"]

    detail = client.get(location)
    assert detail.status_code == 200
    assert "app.lan" in detail.text
    assert "BEGIN CERTIFICATE" in detail.text
    # cabin never saw this key, so there is nothing to show or store
    assert "BEGIN PRIVATE KEY" not in detail.text

    db = _db(cfg)
    try:
        row = get_certificate(db, int(location.rsplit("/", 1)[1]))
        assert row is not None
        assert row.key_sealed is None
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    finally:
        db.close()


def test_ui_sign_csr_bad_input_rerenders_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)

    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nnot a csr\n",
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "Sign a CSR" in resp.text  # re-rendered form, not a JSON error body
    assert "CSR" in resp.text


def test_ui_issue_invalid_days_rerenders_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)

    resp = _issue(client, cfg, days="4000")
    assert resp.status_code == 400
    assert "3650" in resp.text


def test_ui_issue_without_ca_rerenders_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    resp = _issue(client, cfg)
    assert resp.status_code == 400
    assert "CA" in resp.text


# --- FR-6/AC-6: role visibility ------------------------------------------------


def test_ui_key_visibility_by_role(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_user(client, cfg, "vera", "viewer")
    resp = _issue(client, cfg)
    location = resp.headers["location"]

    admin_detail = client.get(location)
    assert "BEGIN PRIVATE KEY" in admin_detail.text

    _login(client, "vera")
    viewer_detail = client.get(location)
    assert viewer_detail.status_code == 200
    assert "BEGIN CERTIFICATE" in viewer_detail.text
    assert "BEGIN PRIVATE KEY" not in viewer_detail.text


def test_ui_viewer_403_on_new(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_user(client, cfg, "vera", "viewer")
    _login(client, "vera")

    assert client.get("/certs/new").status_code == 403
    assert _issue(client, cfg).status_code == 403

    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": _csr_pem("x.lan", [x509.DNSName("x.lan")]),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 403


def test_ui_requires_login(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    resp = _issue(client, cfg)
    location = resp.headers["location"]
    client.cookies.clear()

    for path in ("/certs/new", location):
        redirect = client.get(path)
        assert redirect.status_code == 303
        assert redirect.headers["location"] == "/login"


def test_ui_nav_has_issue_link(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/certs/new"' in resp.text


# --- FR-3/FR-6: a hostile CSR is a clean 400, never a 500 --------------------


@pytest.mark.parametrize(
    "san",
    [
        x509.DNSName("not a hostname!"),
        x509.DNSName(""),
        x509.RFC822Name("no-at-sign"),
        x509.IPAddress(ipaddress.ip_network("10.0.0.0/24")),
    ],
)
def test_ui_sign_csr_malformed_san_rerenders_form(
    client: TestClient, cfg: Config, san: x509.GeneralName
) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)

    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": _csr_pem("evil.lan", [san]),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "Sign a CSR" in resp.text


# --- FR-6: the result page holds a private key --------------------------------


def test_ui_detail_is_not_cached(client: TestClient, cfg: Config) -> None:
    """The page can render an unsealed private key, so no cache anywhere may
    keep a copy of it."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    location = _issue(client, cfg).headers["location"]

    detail = client.get(location)
    assert detail.headers["cache-control"] == "no-store"
    assert detail.headers["pragma"] == "no-cache"


def test_ui_detail_key_unavailable_is_not_a_500(client: TestClient, cfg: Config) -> None:
    """A key sealed with a different master key (or a corrupted column) must
    degrade to a note on an otherwise working page."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    location = _issue(client, cfg).headers["location"]

    db = _db(cfg)
    try:
        row = get_certificate(db, int(location.rsplit("/", 1)[1]))
        assert row is not None
        row.key_sealed = "A" * 40  # valid base64url, fails GCM authentication
        db.commit()
    finally:
        db.close()

    detail = client.get(location)
    assert detail.status_code == 200
    assert "BEGIN CERTIFICATE" in detail.text
    assert "BEGIN PRIVATE KEY" not in detail.text
    assert "could not be decrypted" in detail.text
