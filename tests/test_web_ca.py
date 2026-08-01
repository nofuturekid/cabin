"""Web-layer tests for spec 0004: CA wizard, info, PEM downloads, and role
guards (FR-5/FR-6, AC-1, AC-4, AC-5)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.service import get_ca, signing_credentials
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory


def make_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    factory = create_session_factory(cfg.db_url)
    return factory()


def _setup_superadmin(
    client: TestClient, username: str = "alice", password: str = "correcthorse1"
) -> None:
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303


def _csrf_token_for(cfg: Config, raw_token: str) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, raw_token)
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _create_user_as_superadmin(client: TestClient, cfg: Config, username: str, role: str) -> None:
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303


def _create_ca(client: TestClient, cfg: Config, name: str = "cabin") -> None:
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])
    resp = client.post(
        "/ca/create",
        data={
            "name": name,
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303


def _pem_key_str(key: object, *, password: bytes | None = None) -> str:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


def _pem_cert_str(cert: object) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]


# --- FR-5/FR-6/AC-1/AC-4: wizard create flow, dashboard hint -----------------


def test_ca_wizard_ui_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    # FR-5: dashboard hints at /ca before any CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" in resp.text

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "Create a new CA" in resp.text
    assert "Import an existing CA" in resp.text

    _create_ca(client, cfg, "cabin")

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "cabin Root CA" in resp.text
    assert "cabin Intermediate CA" in resp.text

    # the dashboard hint is gone once a CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" not in resp.text

    # AC-4: a second create attempt is rejected, DB unchanged
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])
    resp = client.post(
        "/ca/create",
        data={
            "name": "again",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 409

    resp = client.get("/ca")
    assert "cabin Root CA" in resp.text
    assert "again Root CA" not in resp.text


# --- AC-5: PEM downloads -------------------------------------------------------


def test_ca_downloads_pem(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")

    resp = client.get("/ca/root.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=cabin Root CA"

    resp = client.get("/ca/chain.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(chain_certs) == 2


def test_ca_downloads_404_before_ca_exists(client: TestClient) -> None:
    _setup_superadmin(client)

    assert client.get("/ca/root.pem").status_code == 404
    assert client.get("/ca/chain.pem").status_code == 404


# --- AC-5: viewer read-only ----------------------------------------------------


def test_viewer_readonly_on_ca(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    client.cookies.clear()

    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    viewer_csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    # viewer can GET everything under /ca
    assert client.get("/ca").status_code == 200
    assert client.get("/ca/root.pem").status_code == 200
    assert client.get("/ca/chain.pem").status_code == 200

    # but mutating POSTs are 403
    resp = client.post(
        "/ca/create",
        data={
            "name": "x",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": "irrelevant",
            "key_pem": "irrelevant",
            "chain_pem": "irrelevant",
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403


# --- AC-3/FR-3: import happy path (encrypted key, root key absent) ----------


def test_ca_import_happy_path_web_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    root_cert, root_key = create_root("Import Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Import Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"import-passphrase"),
            "key_passphrase": "import-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/ca"

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "Import Root CA" in resp.text
    assert "Import Intermediate CA" in resp.text

    db = _db(cfg)
    try:
        hierarchy = get_ca(db)
        assert hierarchy is not None
        assert hierarchy.root.key_sealed is None  # FR-3: root key absent on import
        assert hierarchy.intermediate.key_sealed is not None

        secrets = SecretStore.open(cfg.data_dir, None)
        cert, key = signing_credentials(db, secrets)
        message = b"web-import-roundtrip"
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
        cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))  # no exception
    finally:
        db.close()


# --- AC-5: import must not leak a chain_pem bundle/preamble into root.pem ---


def test_ca_import_root_pem_is_clean_despite_bundle_and_preamble(
    client: TestClient, cfg: Config
) -> None:
    """chain_pem may arrive as an openssl-style dump (subject=/issuer= text
    before the PEM block) or as a multi-cert bundle; either way, /ca/root.pem
    must serve exactly one clean certificate and /ca/chain.pem exactly two."""
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    root_cert, root_key = create_root("Junky Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Junky Intermediate CA", "ecdsa-p256"
    )
    unrelated_cert, _unrelated_key = create_root("Unrelated CA", "ecdsa-p256")
    junky_chain_pem = (
        "subject=CN=Junky Root CA\nissuer=CN=Junky Root CA\n"
        + _pem_cert_str(root_cert)
        + _pem_cert_str(unrelated_cert)
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key),
            "chain_pem": junky_chain_pem,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303

    resp = client.get("/ca/root.pem")
    assert resp.status_code == 200
    assert resp.content.decode("ascii").strip().startswith("-----BEGIN CERTIFICATE-----")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=Junky Root CA"

    resp = client.get("/ca/chain.pem")
    assert resp.status_code == 200
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(chain_certs) == 2


# --- FR-6: year-range validation errors re-render the wizard, not JSON ------


def test_ca_create_invalid_years_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 100,  # out of range: max is 50
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "root_years" in resp.text
    assert "Create a new CA" in resp.text  # re-rendered wizard, not a JSON error body

    # DB unchanged: no CA was created
    db = _db(cfg)
    try:
        assert get_ca(db) is None
    finally:
        db.close()


def test_ca_create_intermediate_years_exceeds_root_rerenders_error(
    client: TestClient, cfg: Config
) -> None:
    """An intermediate must never be requested to outlive its root."""
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 5,
            "intermediate_years": 10,  # exceeds root_years
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "intermediate_years" in resp.text

    db = _db(cfg)
    try:
        assert get_ca(db) is None
    finally:
        db.close()


def test_ca_create_invalid_key_type_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "dsa-1024",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "key_type" in resp.text

    db = _db(cfg)
    try:
        assert get_ca(db) is None
    finally:
        db.close()


# --- FR-2/AC-3: import failure path re-renders the wizard, not JSON --------


def test_ca_import_wrong_passphrase_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    root_cert, root_key = create_root("Wrong Passphrase Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Wrong Passphrase Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"correct-passphrase"),
            "key_passphrase": "wrong-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "decrypt" in resp.text.lower()

    db = _db(cfg)
    try:
        assert get_ca(db) is None
    finally:
        db.close()
