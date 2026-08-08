"""Web-layer tests for spec 0025 (Transfer): the five pages under the new
`Transfer` rail group -- their routing, their guards, and the rail chrome
that has to carry sixteen entries now. What the three exports actually
*produce* (a parsed trust bundle, a parsed inventory file, an opened PKCS#12
bundle) is `tests/test_transfer_exports.py`'s job, not this file's.

Scoping follows `test_web_ca_pages.py`'s `_row(...)`/`_FormActions`/
`_SelectOptions`: the actual element that wraps a marker, or the actual
`<form>`/`<a>` elements themselves, never a bare substring search over the
whole page and never a fixed-character window.

This branch is red by design: none of `/transfer/*` exists yet, the five
`transfer_*.html` templates don't exist, and `ca_import.html` still carries
both import forms on one page.
"""

import json
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import ca_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
STATIC = Path(__file__).resolve().parents[1] / "src/cabin/web/static"
WEB_DIR = TEMPLATES_DIR.parent

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


def _row_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return len(ca_service.list_cas(db))
    finally:
        db.close()


# --- HTML scoping helpers ---------------------------------------------------


def _marked_labels(html: str) -> list[str]:
    """Every rail entry marked `aria-current="page"`, by its label text."""
    return re.findall(r'<a href="[^"]*" aria-current="page">([^<]+)</a>', html)


_NAV_RE = re.compile(r"<nav>(.*?)</nav>", re.S)


def _nav_html(html: str) -> str:
    match = _NAV_RE.search(html)
    assert match is not None, "no <nav> element in page"
    return match.group(1)


def _nav_hrefs(html: str) -> list[str]:
    """Every `<a href=...>` inside the rail's `<nav>`, in document order --
    what AC-1 counts (16) and checks for `/transfer/*` and the departed
    `/ca/import`."""
    return re.findall(r'<a href="([^"]*)"', _nav_html(html))


def _nav_group_labels(html: str) -> list[str]:
    return re.findall(r'<span class="nav-group">([^<]+)</span>', _nav_html(html))


class _FormActions(HTMLParser):
    """The `action` attribute of every `<form>` on the page, in document
    order -- so "the page has exactly one form" is a count over actual
    `<form>` elements, never a substring search."""

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


_CERTS_DOWNLOAD_RE = re.compile(r'(?:href|action)="[^"]*/certs/\d')


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem_str(key: CertificateIssuerPrivateKeyTypes) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


# === AC-1: five pages, five rail entries, sixteen in the rail ===============


def test_transfer_pages_mark_their_rail_entries(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    expected = {
        "/transfer/ca-import": "Import a CA",
        "/transfer/cross-import": "Import a cross certificate",
        "/transfer/trust-bundle": "Trust bundle",
        "/transfer/ca-key": "CA key",
        "/transfer/inventory": "Inventory export",
    }
    for path, label in expected.items():
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert _marked_labels(resp.text) == [label], f"{path}: {_marked_labels(resp.text)}"


def test_rail_has_sixteen_entries_and_a_transfer_group(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    html = client.get("/").text

    assert "Transfer" in _nav_group_labels(html)
    hrefs = _nav_hrefs(html)
    assert len(hrefs) == 16, hrefs
    assert "/ca/import" not in hrefs


# === AC-2: role gating, both directions, one test ===========================


def test_transfer_guards_for_viewer_admin_and_superadmin(client: TestClient, cfg: Config) -> None:
    """AC-2: a viewer is let into the two read-only exports and refused the
    other three; an admin gets everything but the CA key page; a superadmin
    gets all five. Both halves of every gate are in this one test, the way
    the spec preamble requires -- a build that refuses everybody and a build
    that refuses nobody must each fail it.
    """
    _setup_superadmin(client)
    _create_user(client, cfg, "vera", "viewer")
    _create_user(client, cfg, "adam", "admin")

    read_only = ("/transfer/trust-bundle", "/transfer/inventory")
    admin_only = ("/transfer/ca-import", "/transfer/cross-import")
    superadmin_only = "/transfer/ca-key"

    _login(client, "vera")
    for path in read_only:
        assert client.get(path).status_code == 200, path
    for path in (*admin_only, superadmin_only):
        assert client.get(path).status_code == 403, path
    viewer_hrefs = _nav_hrefs(client.get("/transfer/trust-bundle").text)
    assert "/transfer/trust-bundle" in viewer_hrefs
    assert "/transfer/ca-key" not in viewer_hrefs

    _login(client, "adam")
    for path in (*read_only, *admin_only):
        assert client.get(path).status_code == 200, path
    assert client.get(superadmin_only).status_code == 403
    admin_hrefs = _nav_hrefs(client.get("/transfer/trust-bundle").text)
    assert "/transfer/ca-import" in admin_hrefs
    assert "/transfer/cross-import" in admin_hrefs
    assert "/transfer/ca-key" not in admin_hrefs

    _login(client, "alice", "correcthorse1")
    for path in (*read_only, *admin_only, superadmin_only):
        assert client.get(path).status_code == 200, path
    super_hrefs = _nav_hrefs(client.get("/transfer/trust-bundle").text)
    for path in (*read_only, *admin_only, superadmin_only):
        assert path in super_hrefs, path


# === AC-3: the imports split, and their errors land on their own page ======


def test_import_forms_are_two_pages_and_errors_stay_on_them(
    client: TestClient, cfg: Config
) -> None:
    assert not (TEMPLATES_DIR / "ca_import.html").exists()
    # A bare substring check would also match "transfer_ca_import.html", the
    # filename FR-1 itself mandates for the page that replaces this one --
    # so this looks for "ca_import.html" as its own token (not preceded by
    # a word character), which "transfer_ca_import.html" never is.
    old_page_reference = re.compile(r"(?<![\w])ca_import\.html")
    for py in WEB_DIR.rglob("*.py"):
        assert old_page_reference.search(py.read_text()) is None, py

    ca_import_templates: set[str] = set()
    cross_import_templates: set[str] = set()
    for path in TEMPLATES_DIR.glob("*.html"):
        actions = _form_actions(path.read_text())
        if "/ca/import" in actions:
            ca_import_templates.add(path.name)
        if "/ca/cross-import" in actions:
            cross_import_templates.add(path.name)
    assert len(ca_import_templates) == 1, ca_import_templates
    assert len(cross_import_templates) == 1, cross_import_templates
    assert ca_import_templates != cross_import_templates

    _setup_superadmin(client)
    before = _row_count(cfg)

    bad_import = client.post(
        "/ca/import",
        data={
            "cert_pem": "not a pem",
            "key_pem": "not a pem",
            "chain_pem": "not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert bad_import.status_code == 400
    assert _marked_labels(bad_import.text) == ["Import a CA"]

    bad_cross = client.post(
        "/ca/cross-import",
        data={
            "cross_pem": "not a pem",
            "issuer_pem": "not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert bad_cross.status_code == 400
    assert _marked_labels(bad_cross.text) == ["Import a cross certificate"]
    assert _row_count(cfg) == before

    root_cert, root_key = ca_x509.create_root("Splitpage Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = ca_x509.create_intermediate(
        root_cert, root_key, "Splitpage Intermediate CA", "ecdsa-p256"
    )
    good_import = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem(intermediate_cert),
            "key_pem": _key_pem_str(intermediate_key),
            "chain_pem": _pem(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert good_import.status_code == 303
    assert good_import.headers["location"] == "/ca"
    assert _row_count(cfg) == before + 2


# === AC-12: per-certificate downloads did not move ==========================


def test_per_certificate_downloads_did_not_move(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    ca_fixtures.create_ca_via_http(client, cfg, name="Downloads Stay")
    issued = client.post(
        "/certs/issue",
        data={
            "subject_cn": "stays.example.com",
            "sans": "stays.example.com",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert issued.status_code == 303
    cert_path = issued.headers["location"]
    cert_id = cert_path.rsplit("/", 1)[-1]

    detail = client.get(cert_path).text
    assert f'href="/certs/{cert_id}/download/cert.pem"' in detail
    assert f'href="/certs/{cert_id}/download/chain.pem"' in detail
    assert f'href="/certs/{cert_id}/download/key.pem"' in detail
    assert f"/certs/{cert_id}/download/bundle.p12" in _form_actions(detail)

    cert_resp = client.get(f"/certs/{cert_id}/download/cert.pem")
    assert cert_resp.status_code == 200
    assert cert_resp.headers["content-type"].startswith("application/x-pem-file")

    key_resp = client.get(f"/certs/{cert_id}/download/key.pem")
    assert key_resp.status_code == 200
    assert "BEGIN PRIVATE KEY" in key_resp.text

    p12_resp = client.post(
        f"/certs/{cert_id}/download/bundle.p12",
        data={"password": "correcthorse1", "csrf_token": _csrf(client, cfg)},
    )
    assert p12_resp.status_code == 200
    assert p12_resp.headers["content-type"] == "application/x-pkcs12"

    # None of the five transfer pages link to, or post to, a per-certificate
    # download -- FR-14: a certificate's own files stay on its own page.
    for path in (
        "/transfer/ca-import",
        "/transfer/cross-import",
        "/transfer/trust-bundle",
        "/transfer/ca-key",
        "/transfer/inventory",
    ):
        page = client.get(path)
        assert page.status_code == 200, path
        assert _CERTS_DOWNLOAD_RE.search(page.text) is None, path


# === AC-13: the rail still ends in a reachable logout button, and it is the
# nav list's own internal scroll that makes that true (headless Chrome) =====

CHROME = "/opt/google/chrome/chrome"

RAIL_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    window.scrollTo(0, document.body.scrollHeight);
    setTimeout(function () {
      var button = document.querySelector('.rail-foot button');
      var nav = document.querySelector('.rail nav');
      var r = button ? button.getBoundingClientRect() : null;
      var out = document.createElement('div');
      out.id = 'probe-result';
      out.textContent = JSON.stringify({
        found: !!button,
        top: r ? Math.round(r.top) : null,
        bottom: r ? Math.round(r.bottom) : null,
        viewport: document.documentElement.clientHeight,
        navScrollHeight: nav ? nav.scrollHeight : null,
        navClientHeight: nav ? nav.clientHeight : null
      });
      document.body.appendChild(out);
    }, 200);
  }, 300);
});
</script>
"""


def _serve(root: Path) -> tuple[ThreadingHTTPServer, int]:
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _probe(url: str, width: int, height: int) -> dict[str, object]:
    dom = subprocess.run(
        [
            CHROME,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--window-size={width},{height}",
            "--virtual-time-budget=6000",
            "--dump-dom",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=90,
    ).stdout
    found = re.search(r'<div id="probe-result">(.*?)</div>', dom, re.S)
    assert found is not None, "probe did not run -- Chrome rendered nothing"
    result: dict[str, object] = json.loads(
        found.group(1).replace("&quot;", '"').replace("&amp;", "&")
    )
    return result


@pytest.mark.skipif(not Path(CHROME).exists(), reason="headless Chrome not installed")
def test_rail_stays_in_view_with_sixteen_entries(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-13: re-measured at 1440x700 for a superadmin, whose rail now
    carries all sixteen entries. The logout button staying on screen is not
    enough on its own -- a viewport the rail merely fits into would pass
    that assertion without the internal scroll (`cabin.css:143-152`) ever
    engaging, which is exactly the vacuous pass the spec warns about. So
    this also asserts the `<nav>` itself is actually taller than its own
    box (`scrollHeight > clientHeight`), proving the scroll is real.
    """
    _setup_superadmin(client)
    ca_fixtures.create_ca_via_http(client, cfg, name="Sixteen Entries")
    issued = client.post(
        "/certs/issue",
        data={
            "subject_cn": "sixteen.example.com",
            "sans": "sixteen.example.com",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert issued.status_code == 303
    cert_path = issued.headers["location"]

    root = tmp_path / "sixteen"
    root.mkdir()
    shutil.copytree(STATIC, root / "static")
    page = client.get(cert_path)
    assert page.status_code == 200
    # Tie the test's own name to real evidence: this must be the sixteen-
    # entry rail, not today's twelve, which already scrolls at this height
    # and would let this test pass without spec 0025 in place at all.
    assert len(_nav_hrefs(page.text)) == 16
    (root / "cert.html").write_text(page.text.replace("</body>", RAIL_PROBE + "</body>"))

    httpd, port = _serve(root)
    try:
        result = _probe(f"http://127.0.0.1:{port}/cert.html", 1440, 700)
    finally:
        httpd.shutdown()

    assert result["found"], "the rail has no logout button"
    assert result["top"] >= 0 and result["bottom"] <= result["viewport"], (
        f"logout button left the viewport: {result}"
    )
    assert result["navScrollHeight"] is not None and result["navClientHeight"] is not None
    assert result["navScrollHeight"] > result["navClientHeight"], (
        f"the rail's nav list is not actually scrolling -- the criterion "
        f"would pass vacuously on a viewport it merely fit into: {result}"
    )
