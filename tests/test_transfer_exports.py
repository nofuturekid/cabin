"""Web-layer tests for spec 0025 (Transfer): what the three exports actually
*produce* -- the trust bundle parses to exactly the anchors, the inventory
file is the whole filtered set with the API's own field names, and the CA
key export's PKCS#12 bundle actually opens with a private key that matches
the certificate beside it. Routing and guards for the five pages live in
`tests/test_transfer.py`.

The CA key export is the one export this file is strictest about, per the
brief: both halves of every guard are in one test (a refusal that also
refuses the superadmin must fail it, same as one that admits an admin), the
bundle is opened and its key is checked against its certificate rather than
merely "the response was not empty", nothing lands on disk even transiently,
and a successful export is audited while a refused one is not.

Scoping follows `test_web_ca_pages.py`'s `_row(...)`/`_SelectOptions`: the
actual element that wraps a marker, never a fixed-character window and never
a bare substring search over the whole page.

This branch is red by design: none of `/transfer/*` exists yet, and neither
does `cabin.ca.certs.export_certificates`.
"""

import csv
import io
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import ca_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.api.views import certificate_fields
from cabin.app import create_app
from cabin.audit import AuditEvent
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import PER_PAGE
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.web.certs_download_ui import MIN_P12_PASSWORD

# --- fixtures and low-level plumbing, duplicated from test_web_ca_pages.py
# rather than imported: this project has no conftest.py, and each web test
# file owns its own client/session/csrf helpers. ------------------------


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


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


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


def _csrf(client: TestClient, cfg: Config) -> str:
    return _csrf_token_for(cfg, client.cookies["cabin_session"])


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


def _cert_pem_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).cert_pem
    finally:
        db.close()


def _fingerprint(cert_pem: str) -> str:
    """SHA-256, colon-hex -- computed independently here rather than
    imported, so this is a check against the certificate, not against the
    code under test (following `test_web_ca_pages.py`'s own `_fingerprint`)."""
    digest = x509.load_pem_x509_certificate(cert_pem.encode("ascii")).fingerprint(hashes.SHA256())
    return ":".join(f"{b:02x}" for b in digest)


def _spki(key: object) -> bytes:
    """DER-encoded SubjectPublicKeyInfo -- the one representation that
    compares a private key's public half against a certificate's public key
    uniformly across every key type cabin issues (EC, RSA, Ed25519)."""
    public_key = key.public_key()  # type: ignore[attr-defined]
    return public_key.public_bytes(  # type: ignore[no-any-return]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _events(cfg: Config, action: str) -> list[AuditEvent]:
    db = _db(cfg)
    try:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))
    finally:
        db.close()


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem_str(key: CertificateIssuerPrivateKeyTypes) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


@dataclass(frozen=True)
class _Fixture:
    """The spec preamble's own fixture: hierarchy alpha and hierarchy beta
    (both generated -- root + intermediate, both with stored keys), one
    imported hierarchy (root with no stored key, intermediate with one --
    FR-9's whole point), and one cross certificate for alpha's root, signed
    by beta's (beta needs `path_length=2` to be able to sign it)."""

    alpha_root: int
    alpha_intermediate: int
    beta_root: int
    beta_intermediate: int
    cross_id: int
    imported_root: int
    imported_intermediate: int


def _seed_full_fixture(db: Session, secrets: SecretStore) -> _Fixture:
    alpha = ca_service.create_hierarchy(db, secrets, "Alpha Root", "Alpha Root Intermediate")
    beta = ca_service.create_hierarchy(
        db, secrets, "Beta Root", "Beta Root Intermediate", path_length=2
    )
    cross = ca_service.cross_sign_root(db, secrets, alpha.root.id, beta.root.id, years=10)

    ext_root_cert, ext_root_key = ca_x509.create_root("Imported Root CA", "ecdsa-p256")
    ext_intermediate_cert, ext_intermediate_key = ca_x509.create_intermediate(
        ext_root_cert, ext_root_key, "Imported Intermediate CA", "ecdsa-p256"
    )
    imported = ca_service.import_hierarchy(
        db,
        secrets,
        _pem(ext_intermediate_cert),
        _key_pem_str(ext_intermediate_key),
        None,
        _pem(ext_root_cert),
    )
    return _Fixture(
        alpha_root=alpha.root.id,
        alpha_intermediate=alpha.intermediate.id,
        beta_root=beta.root.id,
        beta_intermediate=beta.intermediate.id,
        cross_id=cross.id,
        imported_root=imported.root.id,
        imported_intermediate=imported.intermediate.id,
    )


# --- HTML scoping helpers ---------------------------------------------------

_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
_TAG_RE = re.compile(r"""<(/?)([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>""")
_CLASS_RE = re.compile(r'class="([^"]*)"')


def _row(html: str, marker: str, *, class_name: str, tag: str | None = "div") -> str:
    """The full outer HTML of the innermost element carrying `class_name`
    that contains `marker`'s first occurrence -- scoped by parsing the
    actual tag nesting (`test_web_ca_pages.py:184`)."""
    marker_idx = html.index(marker)
    stack: list[tuple[str, str, int]] = []
    for m in _TAG_RE.finditer(html):
        closing, name, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if name in _VOID_TAGS or attrs.rstrip().endswith("/"):
            continue
        if not closing:
            stack.append((name, attrs, m.start()))
            continue
        if not stack or stack[-1][0] != name:
            continue
        open_name, open_attrs, open_start = stack.pop()
        if open_start <= marker_idx < m.end():
            classes = _CLASS_RE.search(open_attrs)
            matches_tag = tag is None or open_name == tag
            if matches_tag and classes is not None and class_name in classes.group(1).split():
                return html[open_start : m.end()]
    raise AssertionError(f"no <{tag or '*'} class={class_name!r}> element wraps {marker!r}")


class _FormActions(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.actions: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "form":
            self.actions.append(dict(attrs).get("action"))


def _form_actions(html: str) -> list[str | None]:
    parser = _FormActions()
    parser.feed(html)
    return parser.actions


class _SelectOptions(HTMLParser):
    """Whether a `<select name=...>` is present, and the `value` of every
    `<option>` inside it (`test_web_ca_pages.py:287`)."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self.found = False
        self.option_values: list[str | None] = []
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "select" and attrs_dict.get("name") == self._name:
            self.found = True
            self._inside = True
        elif tag == "option" and self._inside:
            self.option_values.append(attrs_dict.get("value"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._inside = False


def _select(html: str, name: str) -> _SelectOptions:
    parser = _SelectOptions(name)
    parser.feed(html)
    return parser


def _strip_select(html: str, name: str) -> str:
    """`html` with the `<select name=...>...</select>` block removed, so a
    check for text elsewhere on the page (AC-8's row list) cannot be
    satisfied by option text inside that select."""
    pattern = re.compile(rf'<select[^>]*name="{name}"[^>]*>.*?</select>', re.S)
    return pattern.sub("", html)


# === AC-4: the trust bundle is the anchors, and nothing else ===============


def test_trust_bundle_is_active_roots_only(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    resp = client.get("/transfer/trust-bundle.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    assert resp.headers["content-disposition"] == 'attachment; filename="cabin-trust-bundle.pem"'
    assert b"PRIVATE KEY" not in resp.content

    certs = x509.load_pem_x509_certificates(resp.content)
    fingerprints = {c.fingerprint(hashes.SHA256()) for c in certs}
    expected = {
        x509.load_pem_x509_certificate(_cert_pem_of(cfg, fixture.alpha_root).encode()).fingerprint(
            hashes.SHA256()
        ),
        x509.load_pem_x509_certificate(_cert_pem_of(cfg, fixture.beta_root).encode()).fingerprint(
            hashes.SHA256()
        ),
        x509.load_pem_x509_certificate(
            _cert_pem_of(cfg, fixture.imported_root).encode()
        ).fingerprint(hashes.SHA256()),
    }
    assert len(certs) == 3
    assert fingerprints == expected


def test_trust_bundle_for_one_hierarchy(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    resp = client.get(f"/transfer/trust-bundle.pem?ca={fixture.alpha_root}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    assert resp.headers["content-disposition"].startswith("attachment")
    assert resp.headers["content-disposition"].endswith(f'-{fixture.alpha_root}-trust-bundle.pem"')

    certs = x509.load_pem_x509_certificates(resp.content)
    assert len(certs) == 2
    expected_root = x509.load_pem_x509_certificate(_cert_pem_of(cfg, fixture.alpha_root).encode())
    expected_intermediate = x509.load_pem_x509_certificate(
        _cert_pem_of(cfg, fixture.alpha_intermediate).encode()
    )
    encoding = serialization.Encoding.DER
    assert certs[0].public_bytes(encoding) == expected_root.public_bytes(encoding)
    assert certs[1].public_bytes(encoding) == expected_intermediate.public_bytes(encoding)

    assert (
        client.get(f"/transfer/trust-bundle.pem?ca={fixture.alpha_intermediate}").status_code == 404
    )
    assert client.get("/transfer/trust-bundle.pem?ca=999999").status_code == 404


# === AC-5: the inventory export is the whole filtered set, API field names =


def test_inventory_export_covers_every_matching_row(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        issuer_id = ca_fixtures.sole_active_issuer(db)
        sample = None
        for i in range(PER_PAGE + 5):
            sample = ca_fixtures.insert_cert(db, issuer_id=issuer_id, cn=f"host{i}.example.com")
        assert sample is not None
    finally:
        db.close()

    csv_resp = client.get("/transfer/inventory.csv")
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"] == "text/csv; charset=utf-8"
    assert csv_resp.headers["content-disposition"] == 'attachment; filename="cabin-inventory.csv"'
    rows = list(csv.reader(io.StringIO(csv_resp.text)))
    assert len(rows) == PER_PAGE + 5 + 1  # header + every row, not just one page

    expected_header = list(certificate_fields(sample, datetime.now(UTC)).keys())
    assert rows[0] == expected_header

    json_resp = client.get("/transfer/inventory.json")
    assert json_resp.status_code == 200
    assert json_resp.headers["content-type"].startswith("application/json")
    assert json_resp.headers["content-disposition"] == (
        'attachment; filename="cabin-inventory.json"'
    )
    body = json_resp.json()
    assert body["total"] == PER_PAGE + 5
    assert len(body["items"]) == PER_PAGE + 5
    assert set(body["items"][0].keys()) == set(expected_header)


def test_inventory_export_fields_match_the_api(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        issuer_id = ca_fixtures.sole_active_issuer(db)
        ca_fixtures.insert_cert(
            db,
            issuer_id=issuer_id,
            cn="active.example.com",
            sans=["DNS:active.example.com", "IP:10.0.0.1"],
            with_key=True,
        )
        ca_fixtures.insert_cert(
            db,
            issuer_id=issuer_id,
            cn="revoked.example.com",
            revoked_at=datetime.now(UTC),
            with_key=False,
        )
    finally:
        db.close()

    revoked_csv = list(
        csv.reader(io.StringIO(client.get("/transfer/inventory.csv?status=revoked").text))
    )
    assert len(revoked_csv) == 2  # header + exactly the one revoked row
    header, row = revoked_csv
    idx = {name: i for i, name in enumerate(header)}
    assert row[idx["subject_cn"]] == "revoked.example.com"
    assert row[idx["revocation_reason"]] == "superseded"
    assert row[idx["revoked_at"]] != ""

    revoked_json = client.get("/transfer/inventory.json?status=revoked").json()
    assert revoked_json["filter"] == {"q": "", "status": "revoked"}
    assert len(revoked_json["items"]) == 1
    item = revoked_json["items"][0]
    assert item["subject_cn"] == "revoked.example.com"
    assert item["revocation_reason"] == "superseded"
    assert item["revoked_at"] is not None

    all_rows = list(csv.reader(io.StringIO(client.get("/transfer/inventory.csv").text)))
    all_header = all_rows[0]
    all_idx = {name: i for i, name in enumerate(all_header)}
    active_row = next(r for r in all_rows[1:] if r[all_idx["subject_cn"]] == "active.example.com")
    assert active_row[all_idx["sans"]] == "DNS:active.example.com IP:10.0.0.1"
    assert active_row[all_idx["has_key"]] == "true"
    assert active_row[all_idx["revoked_at"]] == ""
    assert active_row[all_idx["revocation_reason"]] == ""

    all_json = client.get("/transfer/inventory.json").json()
    assert all_json["filter"] == {"q": "", "status": "all"}
    active_item = next(i for i in all_json["items"] if i["subject_cn"] == "active.example.com")
    assert active_item["sans"] == ["DNS:active.example.com", "IP:10.0.0.1"]
    assert active_item["has_key"] is True
    assert active_item["revoked_at"] is None
    assert active_item["revocation_reason"] is None


# === AC-6: the CA key export works for a superadmin, refused for everybody
# else, and the bundle it produces actually opens =============================


def test_ca_key_export_roundtrips_and_is_superadmin_only(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()
    _create_user(client, cfg, "vera", "viewer")
    _create_user(client, cfg, "adam", "admin")

    resp = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-pkcs12"
    assert resp.headers["content-disposition"].startswith("attachment")
    assert resp.headers["cache-control"] == "no-store"

    key, cert, additional = pkcs12.load_key_and_certificates(resp.content, b"correcthorse")
    assert key is not None
    assert cert is not None
    assert additional is not None

    encoding = serialization.Encoding.DER
    expected_cert = x509.load_pem_x509_certificate(
        _cert_pem_of(cfg, fixture.alpha_intermediate).encode()
    )
    assert cert.public_bytes(encoding) == expected_cert.public_bytes(encoding)
    # The decisive check: the private key really belongs to this certificate.
    assert _spki(key) == cert.public_key().public_bytes(
        encoding, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    expected_root = x509.load_pem_x509_certificate(_cert_pem_of(cfg, fixture.alpha_root).encode())
    assert [c.public_bytes(encoding) for c in additional] == [expected_root.public_bytes(encoding)]

    _login(client, "adam")
    admin_resp = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert admin_resp.status_code == 403
    assert admin_resp.headers.get("content-type") != "application/x-pkcs12"

    _login(client, "vera")
    viewer_resp = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert viewer_resp.status_code == 403
    assert viewer_resp.headers.get("content-type") != "application/x-pkcs12"


# === AC-7: the password is required, checked, before anything is unsealed ==


def test_ca_key_export_password_is_required_and_checked(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    missing = client.post(
        "/transfer/ca-key",
        data={"ca_id": fixture.alpha_intermediate, "csrf_token": _csrf(client, cfg)},
    )
    assert missing.status_code == 400  # not 422 -- FastAPI's default-empty-Form defect
    assert missing.headers.get("content-type") != "application/x-pkcs12"
    assert "/transfer/ca-key" in _form_actions(missing.text)
    # Anchored to the error box itself: "8" alone would match `charset="utf-8"`
    # in the page head first, and "at least 8 characters" also appears in the
    # password field's own label. "must be at least ... characters" is the
    # handler's own wording and appears nowhere else on the page.
    message = f"must be at least {MIN_P12_PASSWORD} characters"
    error = _row(missing.text, message, class_name="error", tag=None)
    assert message in error

    short = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "short12",  # 7 characters
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert short.status_code == 400
    assert short.headers.get("content-type") != "application/x-pkcs12"
    assert "/transfer/ca-key" in _form_actions(short.text)

    assert _events(cfg, "ca_key_exported") == []

    good = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "exactly8",  # 8 characters
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert good.status_code == 200
    _key, cert, _additional = pkcs12.load_key_and_certificates(good.content, b"exactly8")
    assert cert is not None


# === AC-8: what has no key is not offered, and what has one is =============


def test_ca_key_select_offers_only_rows_with_a_key(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    html = client.get("/transfer/ca-key").text
    select = _select(html, "ca_id")
    assert select.found is True
    expected = {
        str(fixture.alpha_root),
        str(fixture.alpha_intermediate),
        str(fixture.beta_root),
        str(fixture.beta_intermediate),
        str(fixture.imported_intermediate),
    }
    assert set(select.option_values) == expected
    assert str(fixture.imported_root) not in select.option_values
    assert str(fixture.cross_id) not in select.option_values

    # The page's row list still shows the two rows the select refuses,
    # marked as having no key -- not silently dropped (FR-9's second half).
    rest = _strip_select(html, "ca_id")
    assert rest.count("no private key on this instance") == 2


# === AC-9: the export is audited; a refusal is not ==========================


def test_ca_key_export_is_audited_and_a_refusal_is_not(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    short = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "short12",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert short.status_code == 400
    keyless = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.imported_root,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert keyless.status_code == 400
    assert _events(cfg, "ca_key_exported") == []

    resp = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.alpha_intermediate,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 200

    events = _events(cfg, "ca_key_exported")
    assert len(events) == 1
    event = events[0]
    assert event.target_type == "ca_certificate"
    assert str(event.target_id) == str(fixture.alpha_intermediate)

    detail = event.detail
    assert detail is not None
    intermediate_cert = x509.load_pem_x509_certificate(
        _cert_pem_of(cfg, fixture.alpha_intermediate).encode()
    )
    assert detail.get("kind") == "intermediate"
    assert detail.get("subject") == intermediate_cert.subject.rfc4514_string()
    assert detail.get("fingerprint") == _fingerprint(_cert_pem_of(cfg, fixture.alpha_intermediate))

    blob = event.summary + (event.detail_json or "")
    assert "correcthorse" not in blob


# === AC-10: nothing touches the disk ========================================

#: SQLite's own rollback-journal artifacts, which appear and disappear
#: around every committed write (including the audit event this export
#: itself writes) regardless of what the export does with a CA key --
#: excluded here for the same reason AC-19.3's own watcher checked content,
#: not just names: a filename this ordinary would drown out the one that
#: actually matters, a temporary file carrying key material.
_DB_ARTIFACT_RE = re.compile(r"\.db(-journal|-wal|-shm)?$")


def _watch_dir(root: Path, stop: threading.Event, seen: set[str]) -> None:
    """Poll `root` continuously (no sleep -- the tighter the loop, the
    better the odds of catching a transient write) and record every
    filename ever observed, following `test_tls.py`'s `_watch_tls_dir`."""
    while not stop.is_set():
        try:
            entries = list(root.rglob("*"))
        except OSError:
            continue
        for path in entries:
            if path.is_file():
                seen.add(str(path.relative_to(root)))


def test_ca_key_export_writes_nothing_to_disk(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    before = {str(p.relative_to(cfg.data_dir)) for p in cfg.data_dir.rglob("*") if p.is_file()}

    stop = threading.Event()
    seen: set[str] = set()
    watcher = threading.Thread(target=_watch_dir, args=(cfg.data_dir, stop, seen), daemon=True)
    watcher.start()
    try:
        resp = client.post(
            "/transfer/ca-key",
            data={
                "ca_id": fixture.alpha_intermediate,
                "password": "correcthorse",
                "csrf_token": _csrf(client, cfg),
            },
        )
    finally:
        stop.set()
        watcher.join(timeout=5)

    assert resp.status_code == 200
    after = {str(p.relative_to(cfg.data_dir)) for p in cfg.data_dir.rglob("*") if p.is_file()}
    assert after == before, (
        f"DATA_DIR's file set changed: new={after - before} gone={before - after}"
    )

    assert seen, "the watcher never observed the directory at all -- it did not run concurrently"
    new_names = {name for name in (seen - before) if not _DB_ARTIFACT_RE.search(name)}
    assert new_names == set(), f"a new file appeared under DATA_DIR during the export: {new_names}"


# === AC-11: every refusal has its own status code ===========================


def test_ca_key_export_refusal_status_codes(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        fixture = _seed_full_fixture(db, _secrets(cfg))
    finally:
        db.close()

    unknown = client.post(
        "/transfer/ca-key",
        data={"ca_id": 999999, "password": "correcthorse", "csrf_token": _csrf(client, cfg)},
    )
    assert unknown.status_code == 404
    assert unknown.headers.get("content-type") != "application/x-pkcs12"

    keyless = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.imported_root,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert keyless.status_code == 400
    assert keyless.headers.get("content-type") != "application/x-pkcs12"

    # A row that exists, has a key, but cannot be unsealed -- the same
    # corruption `test_web_certs_inventory.py`'s own 409 test plants: valid
    # base64url, fails GCM authentication.
    corrupt_db = _db(cfg)
    try:
        row = ca_service.get_ca(corrupt_db, fixture.beta_intermediate)
        row.key_sealed = "A" * 40
        corrupt_db.commit()
    finally:
        corrupt_db.close()

    broken = client.post(
        "/transfer/ca-key",
        data={
            "ca_id": fixture.beta_intermediate,
            "password": "correcthorse",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert broken.status_code == 409
    assert broken.headers.get("content-type") != "application/x-pkcs12"

    assert _events(cfg, "ca_key_exported") == []
