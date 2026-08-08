"""Web-layer tests for spec 0005: the /certs issue + sign UI, result page,
and role guards (FR-6/FR-7, AC-6); spec 0017 FR-6/FR-7/FR-8/FR-14 (AC-2,
AC-7, AC-12): the issuer selector, a clamped validity said out loud, and
downloads that follow the leaf's own issuer.
"""

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.ca.certs import get_certificate
from cabin.ca.service import CACertificate
from cabin.ca.x509 import create_root
from cabin.config import Config
from cabin.secrets import SecretStore
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


def _create_ca(client: TestClient, cfg: Config, name: str = "cabin") -> None:
    resp = client.post(
        "/ca/create",
        data={
            "name": name,
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


def _sign(client: TestClient, cfg: Config, cn: str = "app.lan", **overrides: str) -> Response:
    data = {
        "csr_pem": _csr_pem(cn, [x509.DNSName(cn)]),
        "profile": "client",
        "days": "60",
        "sans_override": "",
        "csrf_token": _csrf(client, cfg),
    }
    data.update(overrides)
    return client.post("/certs/sign", data=data)


def _rows(cfg: Config) -> list[CACertificate]:
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        for row in rows:
            _ = row.id, row.kind, row.name, row.status
        db.expunge_all()
        return rows
    finally:
        db.close()


def _issuer_id(cfg: Config, name: str) -> int:
    matches = [row.id for row in _rows(cfg) if row.name == name]
    assert len(matches) == 1, f"expected exactly one issuer named {name!r}"
    return matches[0]


class _SelectFinder(HTMLParser):
    """Parses out a ``<select name="...">`` and its options -- AC-12
    explicitly requires the control's *parsed* absence, not the absence of a
    substring (the word "issuer" already appears in unrelated chrome)."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self.found = False
        self.options: list[str] = []
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "select" and attrs_dict.get("name") == self._name:
            self.found = True
            self._inside = True
        elif tag == "option" and self._inside:
            value = attrs_dict.get("value")
            if value is not None:
                self.options.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._inside = False


def _select(html: str, name: str) -> _SelectFinder:
    parser = _SelectFinder(name)
    parser.feed(html)
    return parser


def _key_pem_bytes(key: object) -> bytes:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_pem_str(cert: object) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]


def _near_expiry_hierarchy(
    db: Session, secrets: SecretStore, delta: timedelta, *, name: str = "Capped"
) -> tuple[int, int]:
    """A root + an active intermediate that expires in ``delta`` -- built
    locally rather than via ca_fixtures/create_intermediate (both only take
    a whole number of years), because AC-7 needs an issuer just a few days
    from expiry. Returns (root_id, intermediate_id)."""
    root_cert, root_key = create_root(f"{name} Root CA", "ecdsa-p256", years=20)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Intermediate CA")])
        )
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + delta)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski),
            critical=False,
        )
        .sign(root_key, algorithm=hashes.SHA256())
    )

    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=_cert_pem_str(root_cert),
        key_sealed=secrets.seal(_key_pem_bytes(root_key)),
    )
    db.add(root_row)
    db.flush()
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status="active",
        cert_pem=_cert_pem_str(intermediate_cert),
        key_sealed=secrets.seal(_key_pem_bytes(key)),
    )
    db.add(intermediate_row)
    db.commit()
    return root_row.id, intermediate_row.id


# --- FR-6/AC-6 (spec 0005): direct issuance through the UI -------------------


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

    resp = _sign(client, cfg, "app.lan")
    assert resp.status_code == 303
    location = resp.headers["location"]

    detail = client.get(location)
    assert detail.status_code == 200
    assert "app.lan" in detail.text
    assert "BEGIN CERTIFICATE" in detail.text
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


# --- FR-6/AC-6: role visibility ----------------------------------------------


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
    assert _sign(client, cfg, "x.lan").status_code == 403


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


# --- FR-3/FR-6 (spec 0005): a hostile CSR is a clean 400, never a 500 -------


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


# --- FR-6: the result page holds a private key ------------------------------


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


# --- spec 0017 AC-12: the issuer selector ------------------------------------


def test_issuer_select_hidden_when_single(client: TestClient, cfg: Config) -> None:
    """With exactly one active issuer, neither issuance form renders an
    issuer select at all -- checked by parsing the HTML, since the word
    "issuer" legitimately appears elsewhere on both pages."""
    _setup_superadmin(client)
    _create_ca(client, cfg)

    for path in ("/certs/new", "/certs/sign"):
        html = client.get(path).text
        sel = _select(html, "issuer_id")
        assert not sel.found, f"{path}: unexpected issuer_id select with a single active issuer"


def test_issuer_select_posts_stored_issuer(client: TestClient, cfg: Config) -> None:
    """With two active issuers the select lists both, submitting without a
    choice is rejected, and submitting with a choice issues from that
    issuer -- verified by reading the resulting certificate's issuer_id, not
    by trusting the redirect."""
    _setup_superadmin(client)
    _create_ca(client, cfg, name="alpha")
    _create_ca(client, cfg, name="beta")
    alpha_id = _issuer_id(cfg, "alpha Intermediate CA")
    beta_id = _issuer_id(cfg, "beta Intermediate CA")

    new_page = client.get("/certs/new").text
    sel = _select(new_page, "issuer_id")
    assert sel.found
    assert set(sel.options) == {str(alpha_id), str(beta_id)}

    sign_page = client.get("/certs/sign").text
    sign_sel = _select(sign_page, "issuer_id")
    assert sign_sel.found
    assert set(sign_sel.options) == {str(alpha_id), str(beta_id)}

    # counter-check: no issuer chosen, several active -> rejected, no row
    rejected = _issue(client, cfg, subject_cn="ambiguous.lan", sans="ambiguous.lan")
    assert rejected.status_code == 400

    # a choice is honoured: the STORED issuer_id is beta's, not alpha's
    resp = _issue(client, cfg, subject_cn="picked.lan", sans="picked.lan", issuer_id=str(beta_id))
    assert resp.status_code == 303
    cert_id = int(resp.headers["location"].rsplit("/", 1)[1])
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        assert row.issuer_id == beta_id
        assert row.issuer_id != alpha_id
    finally:
        db.close()

    # the sign form obeys the same rule
    signed = _sign(client, cfg, "signed-picked.lan", issuer_id=str(alpha_id))
    assert signed.status_code == 303
    signed_id = int(signed.headers["location"].rsplit("/", 1)[1])
    db = _db(cfg)
    try:
        row = get_certificate(db, signed_id)
        assert row is not None
        assert row.issuer_id == alpha_id
    finally:
        db.close()


def test_issue_and_sign_reject_missing_issuer_choice_ui(client: TestClient, cfg: Config) -> None:
    """AC-2's UI half: with two active issuers, posting either issuance form
    without picking one is a clean 400 with the form re-rendered -- never a
    500, never a silent default to whichever issuer happens to sort first --
    and the rest of what the user typed survives the re-render rather than
    being thrown away."""
    # Imported locally: an otherwise-unused top-level import gets stripped.
    from cabin.ca.certs import Certificate

    _setup_superadmin(client)
    _create_ca(client, cfg, name="alpha")
    _create_ca(client, cfg, name="beta")

    issue_resp = _issue(client, cfg, subject_cn="no-issuer-picked.lan", sans="no-issuer-picked.lan")
    assert issue_resp.status_code == 400
    # the typed subject survives the re-render -- a rejection is not licence
    # to throw away everything else the operator entered
    assert "no-issuer-picked.lan" in issue_resp.text

    db = _db(cfg)
    try:
        assert (
            db.query(Certificate).filter(Certificate.subject_cn == "no-issuer-picked.lan").count()
            == 0
        )
    finally:
        db.close()

    csr_pem = _csr_pem("no-issuer-sign.lan", [x509.DNSName("no-issuer-sign.lan")])
    sign_resp = _sign(client, cfg, csr_pem=csr_pem)
    assert sign_resp.status_code == 400
    # the pasted CSR itself survives the re-render, not just its subject
    assert csr_pem in sign_resp.text

    db = _db(cfg)
    try:
        assert (
            db.query(Certificate).filter(Certificate.subject_cn == "no-issuer-sign.lan").count()
            == 0
        )
    finally:
        db.close()


# --- spec 0017 AC-7: a clamped validity is said out loud ---------------------


def test_capped_validity_reported_in_ui(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    secrets = SecretStore.open(cfg.data_dir, None)
    db = _db(cfg)
    try:
        _root_id, near_issuer_id = _near_expiry_hierarchy(
            db, secrets, timedelta(days=3), name="Capped"
        )
    finally:
        db.close()

    resp = _issue(client, cfg, subject_cn="capped.lan", sans="capped.lan", days="365")
    assert resp.status_code == 303
    location = resp.headers["location"]
    detail = client.get(location)
    assert detail.status_code == 200

    db = _db(cfg)
    try:
        row = get_certificate(db, int(location.rsplit("/", 1)[1]))
        assert row is not None
        assert row.issuer_id == near_issuer_id
        # the real cap: nowhere near the 365 days that were requested
        assert row.not_after_dt < datetime.now(UTC) + timedelta(days=10)
        granted = row.not_after_dt
    finally:
        db.close()

    # AC-7: both the requested (365) and the granted expiry are named
    assert "365" in detail.text
    assert granted.strftime("%Y-%m-%d") in detail.text

    # counter-check: the same request against a fresh (uncapped) issuer
    # reports neither -- run against a second, healthy hierarchy so the
    # near-expiry one is no longer the (sole) active issuer to pick from.
    db = _db(cfg)
    try:
        capped_row = next(
            r for r in ca_service.list_cas(db, kind="intermediate") if r.id == near_issuer_id
        )
        capped_row.status = "retired"
        db.commit()
    finally:
        db.close()
    _create_ca(client, cfg, name="fresh")

    fresh_resp = _issue(client, cfg, subject_cn="uncapped.lan", sans="uncapped.lan", days="365")
    assert fresh_resp.status_code == 303
    fresh_location = fresh_resp.headers["location"]
    fresh_detail = client.get(fresh_location)
    assert fresh_detail.status_code == 200

    db = _db(cfg)
    try:
        fresh_row = get_certificate(db, int(fresh_location.rsplit("/", 1)[1]))
        assert fresh_row is not None
        # granted what was asked for, day-for-day
        expected = datetime.now(UTC) + timedelta(days=365)
        assert abs((fresh_row.not_after_dt - expected).total_seconds()) < 3600
    finally:
        db.close()
    assert granted.strftime("%Y-%m-%d") not in fresh_detail.text


# --- spec 0017 FR-8: downloads follow the leaf's own issuer -----------------


def test_download_chain_and_p12_use_the_leafs_own_issuer(client: TestClient, cfg: Config) -> None:
    """With two hierarchies, a leaf issued from the second one must download
    the second one's chain -- never material from the first."""
    _setup_superadmin(client)
    _create_ca(client, cfg, name="alpha")
    _create_ca(client, cfg, name="beta")
    beta_issuer_id = _issuer_id(cfg, "beta Intermediate CA")

    resp = _issue(
        client, cfg, subject_cn="leaf2.lan", sans="leaf2.lan", issuer_id=str(beta_issuer_id)
    )
    assert resp.status_code == 303
    cert_id = int(resp.headers["location"].rsplit("/", 1)[1])

    chain = client.get(f"/certs/{cert_id}/download/chain.pem")
    assert chain.status_code == 200
    certs = x509.load_pem_x509_certificates(chain.content)
    cns = [c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value for c in certs]
    assert cns == ["leaf2.lan", "beta Intermediate CA", "beta Root CA"]
    assert not any("alpha" in cn for cn in cns)

    p12 = client.post(
        f"/certs/{cert_id}/download/bundle.p12",
        data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
    )
    assert p12.status_code == 200
    _key, _cert, p12_chain = pkcs12.load_key_and_certificates(p12.content, b"hunter2hunter2")
    assert p12_chain is not None
    p12_cns = {c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value for c in p12_chain}
    assert p12_cns == {"beta Intermediate CA", "beta Root CA"}
