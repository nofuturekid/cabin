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

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

import ca_fixtures
import probes
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import certs as certs_service
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
    """Spec 0025 AC-1, re-pointed by spec 0030 FR-7.

    The requirement is unchanged and is the whole of what 0025 AC-1
    measures: the five transfer pages have five rail entries and the rail
    has sixteen. What moves is the label of the fourth group and which of
    the five entries sit in it -- and they move *together*, because either
    half alone names a group for what it is not (`Export` whose first two
    entries are `Import a CA` and `Import a cross certificate`). The
    membership assertion is AC-7 clause 1's and lives in
    `test_the_rail_group_moved_and_the_badge_is_absent_at_zero`; what is
    kept here is the count and the departed path.
    """
    _setup_superadmin(client)
    html = client.get("/").text

    assert "Export" in _nav_group_labels(html), (
        f"the rail's fourth group is not labelled `Export`: {_nav_group_labels(html)}. "
        f"Spec 0030 FR-19 renames it and FR-7 moves the two imports out of it"
    )
    assert "Transfer" not in _nav_group_labels(html)
    hrefs = _nav_hrefs(html)
    assert len(hrefs) == 16, hrefs
    assert "/ca/import" not in hrefs


# === spec 0030 AC-7: the rail's fourth group, and a badge absent at zero ====

#: FR-7: the count stays sixteen, every href stays and no link's label
#: changes -- only which group two of them sit in. Both are asserted, so a
#: build that moved the membership by dropping an entry fails.
RAIL_GROUPS = ["Overview", "Certificate authority", "Certificates", "Export", "Access"]

RAIL_LINKS = [
    ("/", "Dashboard"),
    ("/ca", "Hierarchies"),
    ("/ca/new", "Create"),
    ("/transfer/ca-import", "Import a CA"),
    ("/transfer/cross-import", "Import a cross certificate"),
    ("/certs", "Inventory"),
    ("/certs/new", "Issue"),
    ("/certs/sign", "Sign a CSR"),
    ("/transfer/trust-bundle", "Trust bundle"),
    ("/transfer/ca-key", "CA key"),
    ("/transfer/inventory", "Inventory export"),
    ("/acme/admin", "ACME"),
    ("/tokens", "API tokens"),
    ("/users", "Users"),
    ("/audit", "Audit log"),
    ("/settings", "Settings"),
]

_NAV_ITEM_RE = re.compile(
    r'<span class="nav-group">([^<]+)</span>|<a href="([^"]*)"[^>]*>(.*?)</a>', re.S
)


def _nav_items(html: str) -> list[tuple[str, str, str]]:
    """The rail's contents in document order as ``(kind, href, label)``.

    Groups and links in one sequence, because AC-7's claim is about
    *position*: the two imports have to land between the second heading and
    the third, and a test that only counted hrefs could not tell a moved
    entry from an unmoved one.
    """
    items: list[tuple[str, str, str]] = []
    for group, href, label in _NAV_ITEM_RE.findall(_nav_html(html)):
        if group:
            items.append(("group", "", group.strip()))
        else:
            # The count badge lives inside the Inventory link (FR-7) and is
            # not part of that link's label; it has its own criterion below.
            without_badge = re.sub(r'<span class="nav-count">.*?</span>', "", label, flags=re.S)
            items.append(("link", href, re.sub(r"<[^>]*>", "", without_badge).strip()))
    return items


def _group_of(items: list[tuple[str, str, str]], href: str) -> str:
    current = ""
    for kind, item_href, label in items:
        if kind == "group":
            current = label
        elif item_href == href:
            return current
    raise AssertionError(f"the rail carries no link to {href}")


def test_the_rail_group_moved_and_the_badge_is_absent_at_zero(
    client: TestClient, cfg: Config
) -> None:
    """AC-7, both halves.

    _Supersedes spec 0025 AC-1's `Transfer` rail group._ The operator was
    asked whether the design's grouping should override 0025's own decision
    -- 0025 put the two imports and the three exports in one group of five --
    and chose the design: `Export` holds the trust bundle, the CA key and
    the inventory export, and the two imports join `Certificate authority`.

    The badge's half is here rather than in a test of its own because the
    two failures are opposite: a build that renames the label without moving
    the membership fails clause 1, and a build that renders the badge
    unconditionally fails clause 2 only at zero.
    """
    _setup_superadmin(client)
    items = _nav_items(client.get("/").text)

    assert [label for kind, _href, label in items if kind == "group"] == RAIL_GROUPS, (
        f"the rail's group headings are {[label for kind, _h, label in items if kind == 'group']}"
    )
    assert [(href, label) for kind, href, label in items if kind == "link"] == RAIL_LINKS, (
        f"the rail's sixteen entries are not the sixteen they are today, in the "
        f"design's order. FR-7 moves two of them between groups and changes no "
        f"href and no label: "
        f"{[(h, label) for kind, h, label in items if kind == 'link']}"
    )
    for href in ("/transfer/ca-import", "/transfer/cross-import"):
        assert _group_of(items, href) == "Certificate authority", (
            f"{href} is still under {_group_of(items, href)!r}. The design puts "
            f"Import CA and Import Cross Certificate under the authorities group"
        )
    for href in ("/transfer/trust-bundle", "/transfer/ca-key", "/transfer/inventory"):
        assert _group_of(items, href) == "Export", (
            f"{href} is under {_group_of(items, href)!r}, not `Export`"
        )

    # --- the count badge, at one and at zero
    db = _db(cfg)
    try:
        issuer = ca_fixtures.sole_active_issuer(db, "badge")
        ca_fixtures.insert_cert(db, issuer_id=issuer, cn="soon.lan", expires_in=timedelta(days=5))
        ca_fixtures.insert_cert(db, issuer_id=issuer, cn="fine.lan", expires_in=timedelta(days=300))
        expected = certs_service.status_counts(db, datetime.now(UTC))["expiring"]
    finally:
        db.close()
    assert expected == 1, f"the fixture produced {expected} expiring certificates, not one"

    badges = _nav_count_badges(client.get("/").text)
    assert len(badges) == 1, (
        f"the rail carries {len(badges)} `.nav-count` badge(s) with one certificate "
        f"expiring; FR-7 puts exactly one, on the Inventory entry"
    )
    href, text = badges[0]
    assert href == "/certs", f"the badge sits on {href!r}, not on the Inventory entry"
    assert text == str(expected), (
        f"the badge reads {text!r} and `status_counts(db, now)['expiring']` is "
        f"{expected} -- the badge and the dashboard's tile must not show two "
        f"different numbers"
    )


def test_the_badge_is_absent_rather_than_zero(client: TestClient, cfg: Config) -> None:
    """AC-7 clause 2's other half, on its own instance.

    A second instance rather than a second request: "at zero the element is
    absent" cannot be measured on a database that has already been given an
    expiring certificate, and revoking one back out would leave a `revoked`
    row whose absence from the count is a different fact.
    """
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        issuer = ca_fixtures.sole_active_issuer(db, "quiet")
        ca_fixtures.insert_cert(db, issuer_id=issuer, cn="fine.lan", expires_in=timedelta(days=300))
        assert certs_service.status_counts(db, datetime.now(UTC))["expiring"] == 0
    finally:
        db.close()

    badges = _nav_count_badges(client.get("/").text)
    assert badges == [], (
        f"the rail renders a count badge with nothing expiring: {badges}. The "
        f"design draws it 'only when > 0' and a badge reading zero is a decoration "
        f"that says nothing"
    )


def _nav_count_badges(html: str) -> list[tuple[str, str]]:
    """``(the href of the entry it sits in, its text)`` for every
    `.nav-count` in the rail -- scoped to the entry, so "the badge is on
    Inventory" is measured rather than "a badge is somewhere"."""
    found = []
    for href, inner in re.findall(r'<a href="([^"]*)"[^>]*>(.*?)</a>', _nav_html(html), re.S):
        for badge in re.findall(r'<span class="nav-count">(.*?)</span>', inner, re.S):
            found.append((href, re.sub(r"<[^>]*>", "", badge).strip()))
    return found


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
    var main = document.querySelector('#main');
    if (main) main.scrollTop = main.scrollHeight;
    setTimeout(function () {
      var button = document.querySelector('.rail-foot button');
      var nav = document.querySelector('.rail nav');
      var r = button ? button.getBoundingClientRect() : null;
      var out = document.createElement('div');
      out.id = 'probe-result';
      out.textContent = JSON.stringify({
        found: !!button,
        mainFound: !!main,
        scrolled: main ? Math.round(main.scrollTop) : null,
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
    page = client.get(cert_path)
    assert page.status_code == 200
    # Tie the test's own name to real evidence: this must be the sixteen-
    # entry rail, not today's twelve, which already scrolls at this height
    # and would let this test pass without spec 0025 in place at all.
    assert len(_nav_hrefs(page.text)) == 16
    probes.stage(root, STATIC, {"cert": page.text}, RAIL_PROBE)

    httpd, port = probes.serve(root)
    try:
        result = probes.run(f"http://127.0.0.1:{port}/cert.html", 1440, 700)
    finally:
        httpd.shutdown()

    assert result["mainFound"], f"the page has no #main to scroll (spec 0027 FR-23): {result}"
    assert result["found"], "the rail has no logout button"
    assert isinstance(result["scrolled"], int) and result["scrolled"] > 400, (
        f"main was not long enough to test -- the criterion is about a page "
        f"taller than the viewport: {result}"
    )
    assert result["top"] >= 0 and result["bottom"] <= result["viewport"], (
        f"logout button left the viewport: {result}"
    )
    assert result["navScrollHeight"] is not None and result["navClientHeight"] is not None
    assert result["navScrollHeight"] > result["navClientHeight"], (
        f"the rail's nav list is not actually scrolling -- the criterion "
        f"would pass vacuously on a viewport it merely fit into: {result}"
    )
