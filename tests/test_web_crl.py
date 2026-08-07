"""Web-layer tests for spec 0007: the public CRL endpoints (FR-5, AC-4),
the CDP driven by ``base_url`` (FR-6, AC-5) and the revoke form
(FR-7, AC-6)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.certs import get_certificate
from cabin.ca.crl import CRLState
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory

BASE_URL = "https://ca.example.org"


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


def _create_viewer(client: TestClient, cfg: Config) -> None:
    resp = client.post(
        "/users",
        data={
            "username": "vera",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _issue(client: TestClient, cfg: Config, cn: str = "nas.lan") -> int:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": cn,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _sign_csr(client: TestClient, cfg: Config, cn: str = "csr.lan") -> int:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _set_base_url(client: TestClient, cfg: Config, value: str) -> int:
    resp = client.post(
        "/settings",
        data={"base_url": value, "csrf_token": _csrf(client, cfg)},
    )
    return resp.status_code


def _revoke(
    client: TestClient,
    cfg: Config,
    cert_id: int,
    reason: str = "key_compromise",
    confirm: bool = True,
) -> int:
    data = {"reason": reason, "csrf_token": _csrf(client, cfg)}
    if confirm:
        data["confirm"] = "on"
    return client.post(f"/certs/{cert_id}/revoke", data=data).status_code


def _cert(cfg: Config, cert_id: int) -> x509.Certificate:
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    finally:
        db.close()


def _serial(cfg: Config, cert_id: int) -> int:
    return _cert(cfg, cert_id).serial_number


def _cdp_urls(cert: x509.Certificate) -> list[str]:
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert cdp.critical is False  # a CDP is informational, never critical
    urls: list[str] = []
    for point in cdp.value:
        assert point.full_name is not None
        urls.extend(
            name.value
            for name in point.full_name
            if isinstance(name, x509.UniformResourceIdentifier)
        )
    return urls


# --- FR-5, AC-4: the public CRL endpoints ---------------------------------------


def test_crl_endpoint_der_public(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)
    assert _revoke(client, cfg, cert_id) == 303

    # a relying party has no session and never will -- a CRL is public.
    client.cookies.clear()
    resp = client.get("/crl")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pkix-crl")
    assert resp.headers["cache-control"] == "public, max-age=3600"
    crl = x509.load_der_x509_crl(resp.content)
    assert crl.get_revoked_certificate_by_serial_number(_serial(cfg, cert_id)) is not None


def test_crl_endpoint_pem_public(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    client.cookies.clear()

    resp = client.get("/crl.pem")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    assert resp.headers["cache-control"] == "public, max-age=3600"
    assert resp.text.startswith("-----BEGIN X509 CRL-----")
    # nothing revoked yet is still a valid, signed statement (FR-4)
    assert len(x509.load_pem_x509_crl(resp.content)) == 0


def test_crl_endpoint_404_without_ca(client: TestClient, cfg: Config) -> None:
    """Without a CA there is nothing to sign a CRL with -- and, with zero
    users, the first-run redirect must still not swallow a public route."""
    for path in ("/crl", "/crl.pem"):
        resp = client.get(path)
        assert resp.status_code == 404, path

    _setup_superadmin(client)
    client.cookies.clear()
    assert client.get("/crl").status_code == 404


def test_crl_lazy_regeneration_when_stale(client: TestClient, cfg: Config) -> None:
    """AC-4: no scheduler -- an expired CRL is rebuilt by the next request."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    client.cookies.clear()
    assert client.get("/crl").status_code == 200

    db = _db(cfg)
    try:
        state = db.get(CRLState, 1)
        assert state is not None
        first_number = state.crl_number
        state.generated_at = state.generated_at - timedelta(days=8)
        db.commit()
    finally:
        db.close()

    resp = client.get("/crl")

    assert resp.status_code == 200
    crl = x509.load_der_x509_crl(resp.content)
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number > first_number
    assert crl.next_update_utc is not None
    assert crl.next_update_utc > datetime.now(UTC)


def _swap_ca_key(cfg: Config, sealed: str | None = None, *, issuer_id: int | None = None) -> str:
    """Swap the given intermediate's sealed key for one that fails GCM
    authentication (or put the original back), the way a restored backup with
    the wrong master key would. Returns the value that was there before.

    Takes an explicit issuer_id (spec 0017 work split R7) rather than
    ``.where(kind == "intermediate").one()``: with more than one
    intermediate in the database, ``.one()`` raises MultipleResultsFound --
    a failure that would show up far from here, in whichever multi-issuer
    test happened to run after this file. Defaulting to the lowest id keeps
    every existing single-hierarchy call site unchanged.
    """
    db = _db(cfg)
    try:
        if issuer_id is not None:
            row = db.get(CACertificate, issuer_id)
        else:
            row = db.scalars(
                select(CACertificate)
                .where(CACertificate.kind == "intermediate")
                .order_by(CACertificate.id)
            ).first()
        assert row is not None
        original = row.key_sealed
        assert original is not None
        row.key_sealed = sealed if sealed is not None else "A" * 40
        db.commit()
        return original
    finally:
        db.close()


def _age_stored_crl(cfg: Config, by: timedelta) -> None:
    db = _db(cfg)
    try:
        state = db.get(CRLState, 1)
        assert state is not None
        state.generated_at = state.generated_at - by
        db.commit()
    finally:
        db.close()


def test_crl_survives_an_unusable_ca_key(client: TestClient, cfg: Config) -> None:
    """FR-5: a CRL that cannot be re-signed is still worth serving. Relying
    parties that cannot fetch one may fail closed, so the last good CRL beats
    a 500 -- but there must be no pretending when nothing was ever published.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg)
    original = _swap_ca_key(cfg)
    client.cookies.clear()

    # nothing stored yet and no key to sign with: say so, don't invent a CRL
    assert client.get("/crl").status_code == 500

    _swap_ca_key(cfg, original)
    first = client.get("/crl")
    assert first.status_code == 200
    published = x509.load_der_x509_crl(first.content)

    # now make it due for a refresh that cannot happen
    _age_stored_crl(cfg, timedelta(days=8))
    _swap_ca_key(cfg)
    stale = client.get("/crl")

    assert stale.status_code == 200
    assert x509.load_der_x509_crl(stale.content).signature == published.signature
    assert client.get("/crl.pem").status_code == 200


# --- FR-6, AC-5: the CRL distribution point --------------------------------------


def test_cdp_present_with_base_url(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    assert _set_base_url(client, cfg, BASE_URL) == 303

    issued = _cert(cfg, _issue(client, cfg, cn="cdp.lan"))

    assert _cdp_urls(issued) == [f"{BASE_URL}/crl"]
    # the CA page stops nagging once the URL is set, and points at the CRL
    page = client.get("/ca")
    assert f"{BASE_URL}/crl" in page.text


def test_cdp_present_for_signed_csr(client: TestClient, cfg: Config) -> None:
    """FR-6 covers every certificate cabin issues, not just the ones whose
    key it generated -- a CSR-signed leaf needs the same CDP."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    assert _set_base_url(client, cfg, BASE_URL) == 303

    signed = _cert(cfg, _sign_csr(client, cfg))

    assert _cdp_urls(signed) == [f"{BASE_URL}/crl"]


def test_cdp_absent_without_base_url(client: TestClient, cfg: Config) -> None:
    """FR-6: no base URL means no CDP -- a broken CRL URL in a certificate
    that lives for a year is worse than none at all."""
    _setup_superadmin(client)
    _create_ca(client, cfg)

    issued = _cert(cfg, _issue(client, cfg, cn="nocdp.lan"))

    with pytest.raises(x509.ExtensionNotFound):
        issued.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    # ...and the CA page says so, so an operator can find out why
    assert "base URL" in client.get("/ca").text


def test_base_url_validation(client: TestClient, cfg: Config) -> None:
    """AC-5: only an absolute http(s) URL without a trailing slash is
    accepted; anything else re-renders the form with a 400."""
    _setup_superadmin(client)
    _create_ca(client, cfg)

    for bad in (
        "ca.example.org",
        "/crl",
        "ftp://ca.example.org",
        f"{BASE_URL}/",
        "https://",
        # userinfo would be baked into every future CDP -- and into every
        # relying party's fetch of it
        "https://user:pass@ca.example.org",
        "https://user@ca.example.org",
        # a backslash is a slash to browsers but not to urlparse, so it is a
        # way to make the host read one way here and another there
        "https://ca.example.org\\@evil.example",
        "https://ca.example.org\\.evil.example",
    ):
        resp = client.post("/settings", data={"base_url": bad, "csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 400, bad
        assert "base_url" in resp.text  # the form comes back, not a bare error

    assert _set_base_url(client, cfg, BASE_URL) == 303
    assert BASE_URL in client.get("/settings").text
    # a sub-path deployment behind a reverse proxy is legitimate
    assert _set_base_url(client, cfg, f"{BASE_URL}/cabin") == 303


def test_base_url_normalization(client: TestClient, cfg: Config) -> None:
    """What is stored is what goes into every future certificate, so it is
    stored canonically: scheme and host lowercased, no query or fragment."""
    _setup_superadmin(client)
    _create_ca(client, cfg)

    assert _set_base_url(client, cfg, "HTTPS://CA.Example.ORG:8443/Cabin") == 303
    # the path keeps its case (it is case-sensitive), the host does not
    assert "https://ca.example.org:8443/Cabin" in client.get("/settings").text

    assert _set_base_url(client, cfg, f"{BASE_URL}?ref=mail#top") == 303
    stored = client.get("/settings").text
    assert f'value="{BASE_URL}"' in stored
    assert "ref=mail" not in stored

    # CSRF is enforced like on every other mutating form
    assert client.post("/settings", data={"base_url": BASE_URL}).status_code == 403
    # ...and so is the admin role
    _create_viewer(client, cfg)
    _login(client, "vera")
    assert client.get("/settings").status_code == 403
    assert client.post("/settings", data={"base_url": BASE_URL}).status_code == 403


# --- FR-7, AC-6: the revoke form ---------------------------------------------------


def test_ui_revoke_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    detail = client.get(f"/certs/{cert_id}")
    assert f"/certs/{cert_id}/revoke" in detail.text

    # the confirm checkbox is not decoration: without it nothing happens
    assert _revoke(client, cfg, cert_id, confirm=False) == 400
    # neither does a cross-site post
    assert client.post(f"/certs/{cert_id}/revoke", data={"reason": "superseded"}).status_code == 403
    assert _cert(cfg, cert_id) is not None
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revoked_at is None
    finally:
        db.close()

    assert _revoke(client, cfg, cert_id, reason="key_compromise") == 303

    page = client.get(f"/certs/{cert_id}")
    assert page.status_code == 200
    assert "key_compromise" in page.text
    assert "Revoked" in page.text
    # AC-6: revoking again is not offered
    assert f"/certs/{cert_id}/revoke" not in page.text
    # ...and a hand-made second post is a no-op, not a rewritten history
    assert _revoke(client, cfg, cert_id, reason="superseded") == 303
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revocation_reason == "key_compromise"
    finally:
        db.close()

    client.cookies.clear()
    crl = x509.load_der_x509_crl(client.get("/crl").content)
    assert crl.get_revoked_certificate_by_serial_number(_serial(cfg, cert_id)) is not None


def test_ui_revoke_unknown_reason_is_refused(client: TestClient, cfg: Config) -> None:
    """A reason cabin does not know must not be quietly downgraded to
    "unspecified": the operator would be told the certificate was revoked for
    a reason that never reaches the CRL."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    assert _revoke(client, cfg, cert_id, reason="because-i-said-so") == 400

    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revoked_at is None
    finally:
        db.close()


def test_ui_revoke_requires_admin(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_viewer(client, cfg)
    cert_id = _issue(client, cfg)

    _login(client, "vera")
    page = client.get(f"/certs/{cert_id}")

    assert page.status_code == 200
    assert f"/certs/{cert_id}/revoke" not in page.text
    assert _revoke(client, cfg, cert_id) == 403
