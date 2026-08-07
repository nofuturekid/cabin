"""Tests for the token-authenticated REST API of spec 0008 (FR-3/FR-4/FR-5,
AC-2..AC-6, AC-8's OpenAPI half)."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.api.models import IssueRequest, KeyType, StatusFilter
from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.ca.certs import STATUS_FILTERS, get_certificate
from cabin.ca.crl import current_crl
from cabin.ca.leaf import MAX_CN_LENGTH, MAX_DAYS, MAX_SANS, MIN_DAYS
from cabin.ca.service import active_issuers, create_hierarchy, get_ca, retire
from cabin.ca.x509 import KEY_TYPES
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.users import Role

BASE_URL = "https://ca.example.org"
# FR-12: CDP/AIA URLs baked into a certificate are always http://, even when
# the configured base_url is https://ca.example.org.
HTTP_BASE_URL = "http://ca.example.org"


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


def _set_base_url(client: TestClient, cfg: Config) -> None:
    resp = client.post("/settings", data={"base_url": BASE_URL, "csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303


@pytest.fixture
def api(client: TestClient, cfg: Config) -> TestClient:
    """A configured instance with NO session cookie left behind: every API
    test starts from "there is no browser session at all"."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _set_base_url(client, cfg)
    client.cookies.clear()
    return client


def _token(cfg: Config, role: Role, expires_at: datetime | None = None) -> str:
    db = _db(cfg)
    try:
        secret, _ = create_token(db, f"{role.value}-token", role, expires_at=expires_at)
        return secret
    finally:
        db.close()


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _issue_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "subject_cn": "nas.lan",
        "sans": ["nas.lan", "ip:10.0.0.5"],
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": 90,
    }
    body.update(overrides)
    return body


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


# --- FR-3: bearer auth, roles, and the cookie/token divide --------------------


def test_api_requires_bearer(api: TestClient, cfg: Config) -> None:
    """AC-2: no header, a junk header and a wrong secret are all 401 with a
    JSON body -- never an HTML redirect to /login."""
    for headers in (
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer cabin_" + "A" * 43},
        _auth("not-even-close"),
    ):
        resp = api.get("/api/v1/certificates", headers=headers)
        assert resp.status_code == 401, headers
        assert resp.headers["content-type"].startswith("application/json")
        assert isinstance(resp.json()["detail"], str)

    expired = _token(cfg, Role.admin, expires_at=datetime.now(UTC) - timedelta(minutes=1))
    resp = api.get("/api/v1/certificates", headers=_auth(expired))
    assert resp.status_code == 401
    assert resp.json()["detail"]


def test_api_role_enforced(api: TestClient, cfg: Config) -> None:
    """AC-2: a viewer may read and may not write."""
    viewer = _auth(_token(cfg, Role.viewer))
    admin = _auth(_token(cfg, Role.admin))

    assert api.get("/api/v1/certificates", headers=viewer).status_code == 200

    resp = api.post("/api/v1/certificates", json=_issue_body(), headers=viewer)
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["detail"]

    assert api.post("/api/v1/certificates", json=_issue_body(), headers=admin).status_code == 201


def test_cookie_does_not_authenticate_api(client: TestClient, cfg: Config) -> None:
    """AC-3, direction 1: a logged-in browser session is worth nothing here --
    on every data route, not just the one that is easy to check."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    assert client.cookies.get("cabin_session")

    for method, path, payload in (
        ("GET", "/api/v1/ca", None),
        ("GET", "/api/v1/certificates", None),
        ("GET", "/api/v1/certificates/1", None),
        ("POST", "/api/v1/certificates", _issue_body()),
        (
            "POST",
            "/api/v1/certificates/sign",
            {"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")])},
        ),
        ("POST", "/api/v1/certificates/1/revoke", {}),
    ):
        resp = client.request(method, path, json=payload)
        assert resp.status_code == 401, path
        assert resp.headers["content-type"].startswith("application/json"), path
        assert resp.json()["detail"]


def test_token_does_not_authenticate_ui(api: TestClient, cfg: Config) -> None:
    """AC-3, direction 2: an API token is not a session."""
    headers = _auth(_token(cfg, Role.superadmin))
    for path in ("/", "/certs", "/certs/new", "/tokens"):
        resp = api.get(path, headers=headers)
        assert resp.status_code == 303, path
        assert resp.headers["location"] == "/login"


# --- FR-4: the endpoints ------------------------------------------------------


def test_api_get_ca(api: TestClient, cfg: Config) -> None:
    """AC-15/FR-15: one entry per ``ca_certificates`` row, not a
    ``{root, intermediate}`` pair -- so the shape still describes an
    instance once a second hierarchy exists."""
    resp = api.get("/api/v1/ca", headers=_auth(_token(cfg, Role.viewer)))
    assert resp.status_code == 200
    body = resp.json()
    issuers = {row["name"]: row for row in body["issuers"]}
    assert issuers.keys() == {"cabin Root CA", "cabin Intermediate CA"}
    root = issuers["cabin Root CA"]
    intermediate = issuers["cabin Intermediate CA"]
    assert root["kind"] == "root"
    assert root["parent_id"] is None
    assert root["status"] == "active"
    assert intermediate["kind"] == "intermediate"
    assert intermediate["parent_id"] == root["id"]
    assert intermediate["subject"] == "CN=cabin Intermediate CA"
    assert intermediate["issuer"] == "CN=cabin Root CA"
    assert len(root["fingerprint"].split(":")) == 32
    assert intermediate["not_valid_after"] > intermediate["not_valid_before"]
    assert intermediate["crl_url"].endswith(f"/crl/{intermediate['id']}") or intermediate[
        "crl_url"
    ].endswith(f"/crl/{intermediate['id']}.pem")
    assert str(intermediate["id"]) in intermediate["ca_url"]


def test_api_get_ca_reports_retired_status(api: TestClient, cfg: Config) -> None:
    """AC-15: after retiring an issuer, the same call reports it retired --
    proven with a second issuer active, since the last active one may not be
    retired (FR-4)."""
    db = _db(cfg)
    try:
        active = active_issuers(db)
        assert len(active) == 1
        first_issuer_id = active[0].id
    finally:
        db.close()

    admin_headers = _auth(_token(cfg, Role.admin))
    # A second hierarchy so retiring the first one is legal.
    resp = api.get("/api/v1/ca", headers=admin_headers)
    root_id = next(row["id"] for row in resp.json()["issuers"] if row["kind"] == "root")

    db = _db(cfg)
    try:
        create_hierarchy(db, SecretStore.open(cfg.data_dir, None), "second")
        retire(db, first_issuer_id)
    finally:
        db.close()

    resp = api.get("/api/v1/ca", headers=_auth(_token(cfg, Role.viewer)))
    by_id = {row["id"]: row for row in resp.json()["issuers"]}
    assert by_id[first_issuer_id]["status"] == "retired"
    assert root_id in by_id


def test_api_list_and_get_certificate(api: TestClient, cfg: Config) -> None:
    admin = _auth(_token(cfg, Role.admin))
    created = api.post("/api/v1/certificates", json=_issue_body(), headers=admin).json()
    api.post(
        "/api/v1/certificates",
        json=_issue_body(subject_cn="app.lan", sans=["app.lan"]),
        headers=admin,
    )

    viewer = _auth(_token(cfg, Role.viewer))
    listing = api.get("/api/v1/certificates", headers=viewer)
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 2
    assert body["page"] == 1
    assert body["pages"] == 1
    assert {item["subject_cn"] for item in body["items"]} == {"nas.lan", "app.lan"}

    filtered = api.get("/api/v1/certificates", params={"q": "app"}, headers=viewer).json()
    assert [item["subject_cn"] for item in filtered["items"]] == ["app.lan"]
    assert filtered["total"] == 1

    empty = api.get("/api/v1/certificates", params={"status": "revoked"}, headers=viewer).json()
    assert empty["items"] == []

    detail = api.get(f"/api/v1/certificates/{created['id']}", headers=viewer)
    assert detail.status_code == 200
    got = detail.json()
    assert got["subject_cn"] == "nas.lan"
    assert got["sans"] == ["DNS:nas.lan", "IP:10.0.0.5"]
    assert got["status"] == "valid"
    assert got["has_key"] is True
    assert "BEGIN CERTIFICATE" in got["cert_pem"]
    assert got["chain_pem"].count("BEGIN CERTIFICATE") == 2

    assert api.get("/api/v1/certificates/9999", headers=viewer).status_code == 404


def test_api_issue_certificate(api: TestClient, cfg: Config) -> None:
    """AC-4: a real certificate, a matching key, and a chain that verifies."""
    admin = _auth(_token(cfg, Role.admin))
    resp = api.post("/api/v1/certificates", json=_issue_body(), headers=admin)
    assert resp.status_code == 201
    body = resp.json()

    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode("ascii"))
    assert cert.subject.rfc4514_string() == "CN=nas.lan"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["nas.lan"]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]

    key = serialization.load_pem_private_key(body["key_pem"].encode("ascii"), password=None)
    assert key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    intermediate = x509.load_pem_x509_certificate(body["chain_pem"].encode("ascii"))
    cert.verify_directly_issued_by(intermediate)

    # The CRL distribution point comes from the configured base URL (0007)
    # and, since spec 0017 FR-9/FR-10, names the issuer that actually signed
    # this leaf rather than a single instance-wide /crl.
    db = _db(cfg)
    try:
        issuer_id = active_issuers(db)[0].id
    finally:
        db.close()
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name is not None
    cdp_url = cdp[0].full_name[0].value
    # FR-12: the CRL URL baked into the certificate is always http://, never
    # https://, even though the configured base_url is https -- otherwise
    # validating a cabin certificate would require fetching its CRL over
    # TLS, which would require validating that certificate.
    assert cdp_url.startswith(HTTP_BASE_URL)
    assert not cdp_url.startswith("https"), cdp_url
    assert f"/crl/{issuer_id}" in cdp_url

    listing = api.get("/api/v1/certificates", headers=admin).json()
    assert [item["id"] for item in listing["items"]] == [body["id"]]


def test_api_chain_pem_comes_from_the_leafs_own_issuer(api: TestClient, cfg: Config) -> None:
    """FR-8: the chain in a REST response is built from the *issuing* CA
    hierarchy, not "the" hierarchy -- with two active issuers, each leaf's
    ``chain_pem`` verifies against its own issuer and fails against the
    other's, in both directions (work split R3)."""
    admin = _auth(_token(cfg, Role.admin))
    db = _db(cfg)
    try:
        first_issuer_id = active_issuers(db)[0].id
        second = create_hierarchy(db, SecretStore.open(cfg.data_dir, None), "second")
        second_issuer_id = second.intermediate.id
    finally:
        db.close()

    body_a = api.post(
        "/api/v1/certificates",
        json=_issue_body(subject_cn="a.lan", sans=["a.lan"]) | {"issuer_id": first_issuer_id},
        headers=admin,
    ).json()
    body_b = api.post(
        "/api/v1/certificates",
        json=_issue_body(subject_cn="b.lan", sans=["b.lan"]) | {"issuer_id": second_issuer_id},
        headers=admin,
    ).json()

    cert_a = x509.load_pem_x509_certificate(body_a["cert_pem"].encode("ascii"))
    cert_b = x509.load_pem_x509_certificate(body_b["cert_pem"].encode("ascii"))
    chain_a = x509.load_pem_x509_certificate(body_a["chain_pem"].encode("ascii"))
    chain_b = x509.load_pem_x509_certificate(body_b["chain_pem"].encode("ascii"))

    cert_a.verify_directly_issued_by(chain_a)
    cert_b.verify_directly_issued_by(chain_b)
    with pytest.raises(Exception):  # noqa: B017 -- any verification failure, wrong chain
        cert_a.verify_directly_issued_by(chain_b)
    with pytest.raises(Exception):  # noqa: B017
        cert_b.verify_directly_issued_by(chain_a)


# --- AC-7: a clamped validity is reported, not silently granted -------------


def test_api_capped_validity_reported_in_response(client: TestClient, cfg: Config) -> None:
    """AC-7: requesting more than the issuer has left comes back clamped to
    the issuer's own expiry, and ``validity_capped_from`` names what was
    actually requested."""
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 5,
            "intermediate_years": 1,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    _set_base_url(client, cfg)
    client.cookies.clear()
    admin = _auth(_token(cfg, Role.admin))

    resp = client.post("/api/v1/certificates", json=_issue_body(days=3650), headers=admin)
    assert resp.status_code == 201
    body = resp.json()
    assert body["validity_capped_from"] is not None

    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode("ascii"))
    db = _db(cfg)
    try:
        issuer = get_ca(db, active_issuers(db)[0].id)
    finally:
        db.close()
    issuer_cert = x509.load_pem_x509_certificate(issuer.cert_pem.encode("ascii"))
    assert cert.not_valid_after_utc == issuer_cert.not_valid_after_utc


def test_api_uncapped_issuance_reports_nothing(api: TestClient, cfg: Config) -> None:
    """AC-7: the field is absent from the response, not ``null``-and-present,
    when nothing was clamped (the default fixture's issuer has ten years
    left, far more than the default 90-day request)."""
    admin = _auth(_token(cfg, Role.admin))

    resp = api.post("/api/v1/certificates", json=_issue_body(), headers=admin)

    assert resp.status_code == 201
    assert "validity_capped_from" not in resp.json()


def test_api_issue_key_visibility_by_role(api: TestClient, cfg: Config) -> None:
    """FR-5: key_pem is absent -- not null -- whenever the caller may not or
    cannot have it."""
    admin = _auth(_token(cfg, Role.admin))
    issued = api.post("/api/v1/certificates", json=_issue_body(), headers=admin).json()
    assert "BEGIN PRIVATE KEY" in issued["key_pem"]

    detail = api.get(f"/api/v1/certificates/{issued['id']}", headers=admin)
    assert "BEGIN PRIVATE KEY" in detail.json()["key_pem"]

    viewer_detail = api.get(
        f"/api/v1/certificates/{issued['id']}", headers=_auth(_token(cfg, Role.viewer))
    )
    assert viewer_detail.status_code == 200
    assert "key_pem" not in viewer_detail.json()
    assert "BEGIN PRIVATE KEY" not in viewer_detail.text

    signed = api.post(
        "/api/v1/certificates/sign",
        json={"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")]), "days": 60},
        headers=admin,
    ).json()
    assert "key_pem" not in signed
    # cabin never had this key, so not even an admin gets one back.
    assert "key_pem" not in api.get(f"/api/v1/certificates/{signed['id']}", headers=admin).json()


def test_api_key_responses_are_not_cached(api: TestClient, cfg: Config) -> None:
    """The two responses that can carry an unsealed private key must be as
    uncacheable as the UI page that shows one -- no proxy, no browser and no
    htmx cache may keep a copy."""
    admin = _auth(_token(cfg, Role.admin))
    issued = api.post("/api/v1/certificates", json=_issue_body(), headers=admin)
    detail = api.get(f"/api/v1/certificates/{issued.json()['id']}", headers=admin)

    for resp in (issued, detail):
        assert "BEGIN PRIVATE KEY" in resp.text
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["pragma"] == "no-cache"


def test_api_unsealable_keys_are_reported_not_crashed(api: TestClient, cfg: Config) -> None:
    """A key the master key can no longer open is a 409 where it blocks the
    request (the CA's own key) and a message where it does not (one leaf's
    key on an otherwise perfectly readable certificate) -- never a 500."""
    admin = _auth(_token(cfg, Role.admin))
    issued = api.post("/api/v1/certificates", json=_issue_body(), headers=admin).json()

    db = _db(cfg)
    try:
        row = get_certificate(db, issued["id"])
        assert row is not None
        row.key_sealed = "A" * 40  # valid base64url, fails GCM authentication
        db.commit()
    finally:
        db.close()

    detail = api.get(f"/api/v1/certificates/{issued['id']}", headers=admin)
    assert detail.status_code == 200
    body = detail.json()
    assert "key_pem" not in body
    assert "could not be decrypted" in body["key_error"]
    assert "BEGIN CERTIFICATE" in body["cert_pem"]

    db = _db(cfg)
    try:
        issuer = get_ca(db, active_issuers(db)[0].id)
        issuer.key_sealed = "A" * 40
        db.commit()
    finally:
        db.close()

    for path, payload in (
        ("/api/v1/certificates", _issue_body()),
        (
            "/api/v1/certificates/sign",
            {"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")])},
        ),
        (f"/api/v1/certificates/{issued['id']}/revoke", {}),
    ):
        resp = api.post(path, json=payload, headers=admin)
        assert resp.status_code == 409, path
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.json()["detail"]


def test_api_sign_csr(api: TestClient, cfg: Config) -> None:
    admin = _auth(_token(cfg, Role.admin))
    resp = api.post(
        "/api/v1/certificates/sign",
        json={
            "csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")]),
            "profile": "client",
            "days": 60,
        },
        headers=admin,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["has_key"] is False

    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode("ascii"))
    assert cert.subject.rfc4514_string() == "CN=app.lan"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]


def test_api_sign_csr_smuggling_blocked(api: TestClient, cfg: Config) -> None:
    """AC-5: the hostile CSR from spec 0005 yields an ordinary leaf, and a
    broken CSR a 400 with a message."""
    admin = _auth(_token(cfg, Role.admin))
    csr_pem = _csr_pem(
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
    resp = api.post("/api/v1/certificates/sign", json={"csr_pem": csr_pem}, headers=admin)
    assert resp.status_code == 201

    cert = x509.load_pem_x509_certificate(resp.json()["cert_pem"].encode("ascii"))
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False
    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.key_cert_sign is False
    assert key_usage.crl_sign is False
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]

    bad = api.post(
        "/api/v1/certificates/sign",
        json={"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nnope\n"},
        headers=admin,
    )
    assert bad.status_code == 400
    assert bad.headers["content-type"].startswith("application/json")
    assert "CSR" in bad.json()["detail"]


def test_api_revoke_updates_crl(api: TestClient, cfg: Config) -> None:
    """AC-6/FR-9: the serial shows up in the revoking issuer's own CRL.

    The route that serves ``/crl/{issuer_id}`` is Security's (spec 0017 work
    split), so this checks the CRL through the service layer this API route
    actually calls -- :func:`cabin.ca.crl.current_crl` -- rather than a
    second front door's HTTP route.
    """
    admin = _auth(_token(cfg, Role.admin))
    issued = api.post("/api/v1/certificates", json=_issue_body(), headers=admin).json()

    resp = api.post(
        f"/api/v1/certificates/{issued['id']}/revoke",
        json={"reason": "key_compromise"},
        headers=admin,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "revoked"
    assert body["reason"] == "key_compromise"
    assert body["revoked_at"]
    assert body["crl_url"] is not None
    # FR-12: always http://, never https://, same reasoning as
    # test_api_issue_certificate above.
    assert body["crl_url"].startswith(HTTP_BASE_URL)
    assert not body["crl_url"].startswith("https"), body["crl_url"]
    assert "/crl/" in body["crl_url"]

    db = _db(cfg)
    try:
        issuer_id = active_issuers(db)[0].id
        state = current_crl(db, SecretStore.open(cfg.data_dir, None), issuer_id)
    finally:
        db.close()
    crl = x509.load_der_x509_crl(state.crl_der)
    assert [entry.serial_number for entry in crl] == [int(issued["serial_hex"], 16)]

    detail = api.get(f"/api/v1/certificates/{issued['id']}", headers=admin).json()
    assert detail["status"] == "revoked"
    assert detail["revocation_reason"] == "key_compromise"

    assert api.post("/api/v1/certificates/9999/revoke", json={}, headers=admin).status_code == 404


def test_api_revoke_idempotent(api: TestClient, cfg: Config) -> None:
    """AC-6: revoking twice succeeds twice and does not move the date."""
    admin = _auth(_token(cfg, Role.admin))
    issued = api.post("/api/v1/certificates", json=_issue_body(), headers=admin).json()
    path = f"/api/v1/certificates/{issued['id']}/revoke"

    first = api.post(path, json={"reason": "superseded"}, headers=admin)
    second = api.post(path, json={"reason": "key_compromise"}, headers=admin)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first.json()["revoked_at"]
    assert second.json()["reason"] == "superseded"


def test_api_errors_are_json_not_tracebacks(client: TestClient, cfg: Config) -> None:
    """FR-4: every domain failure is a 4xx JSON body with a message."""
    _setup_superadmin(client)
    admin = _auth(_token(cfg, Role.admin))
    client.cookies.clear()

    # No CA at all yet -> a state conflict, not a crash.
    for path, payload in (
        ("/api/v1/certificates", _issue_body()),
        (
            "/api/v1/certificates/sign",
            {"csr_pem": _csr_pem("app.lan", [x509.DNSName("app.lan")])},
        ),
    ):
        resp = client.post(path, json=payload, headers=admin)
        assert resp.status_code == 409, path
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.json()["detail"]

    resp = client.get("/api/v1/ca", headers=admin)
    assert resp.status_code == 409
    assert resp.json()["detail"]

    resp = client.get("/api/v1/certificates/1", headers=admin)
    assert resp.status_code == 404
    assert resp.json()["detail"]

    # Input the models reject never reaches the CA at all.
    for payload in (
        _issue_body(days=4000),
        _issue_body(days=0),
        _issue_body(subject_cn="x" * 65),
        _issue_body(sans=[f"host{n}.lan" for n in range(101)]),
        _issue_body(profile="root"),
        _issue_body(key_type="rot13"),
    ):
        resp = client.post("/api/v1/certificates", json=payload, headers=admin)
        assert resp.status_code == 422, payload
        assert resp.headers["content-type"].startswith("application/json")

    # ... and with a CA in place, input only the domain layer can reject --
    # a SAN that is not a hostname, a CSR that is not a CSR -- is a clean 400.
    assert (
        client.post("/login", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    _create_ca(client, cfg)
    client.cookies.clear()

    for payload in (
        _issue_body(sans=["not a hostname!"]),
        _issue_body(subject_cn="\x07bell"),
    ):
        resp = client.post("/api/v1/certificates", json=payload, headers=admin)
        assert resp.status_code == 400, payload
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.json()["detail"]


def test_api_models_mirror_domain_limits() -> None:
    """FR-5: the request models are the UI's limits, spelled for OpenAPI.
    If a key type or status filter is ever added to the domain, this fails
    until the schema learns about it too."""
    assert set(get_args(KeyType)) == set(KEY_TYPES)
    assert set(get_args(StatusFilter)) == set(STATUS_FILTERS)

    limits = {
        name: {type(constraint).__name__: constraint for constraint in field.metadata}
        for name, field in IssueRequest.model_fields.items()
    }
    assert limits["subject_cn"]["MaxLen"].max_length == MAX_CN_LENGTH
    assert limits["sans"]["MaxLen"].max_length == MAX_SANS
    assert limits["days"]["Ge"].ge == MIN_DAYS
    assert limits["days"]["Le"].le == MAX_DAYS


# --- FR-7: the API documents itself ------------------------------------------


def test_openapi_served(api: TestClient) -> None:
    """FR-7: schema and docs, no token required -- they document, they do
    not expose data."""
    schema = api.get("/api/v1/openapi.json")
    assert schema.status_code == 200
    assert schema.headers["content-type"].startswith("application/json")
    paths = schema.json()["paths"]
    assert {
        "/api/v1/ca",
        "/api/v1/certificates",
        "/api/v1/certificates/{cert_id}",
        "/api/v1/certificates/sign",
        "/api/v1/certificates/{cert_id}/revoke",
    } <= set(paths)
    # The response models are documented, not just the paths (FR-4/FR-5).
    assert "CertificateDetail" in schema.json()["components"]["schemas"]

    docs = api.get("/api/v1/docs")
    assert docs.status_code == 200
    assert docs.headers["content-type"].startswith("text/html")
    assert "/api/v1/openapi.json" in docs.text


def test_api_docs_are_self_contained(api: TestClient) -> None:
    """cabin ships as one container onto networks with no way out: the docs
    page must not reach for a CDN, or it renders blank exactly where it is
    needed most."""
    docs = api.get("/api/v1/docs")
    assert re.findall(r"https?://[^\"'\s]+", docs.text) == []

    for asset in ("/static/swagger-ui-bundle.js", "/static/swagger-ui.css"):
        assert asset in docs.text
        served = api.get(asset)
        assert served.status_code == 200, asset
        assert served.content

    # SwaggerUI's default "validate against validator.swagger.io" badge is
    # another outbound request, and one that would post our schema.
    assert '"validatorUrl": null' in docs.text
