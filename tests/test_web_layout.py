"""Web-layer tests for spec 0015: the page chrome and its layout primitives.

Two kinds of test live here. The cheap ones read the templates and the
stylesheet and assert their structure (FR-1..FR-8, AC-4..AC-6). The expensive
ones render every page in headless Chrome and measure whether anything is
drawn outside its container (AC-1..AC-3) — the defect this spec exists for is
geometric, and only a browser can see it.
"""

import json
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory

TEMPLATES = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
STATIC = Path(__file__).resolve().parents[1] / "src/cabin/web/static"
CSS = STATIC / "cabin.css"

#: Templates rendered inside the rail. login/setup are the two without one,
#: and `ca_macros.html` (spec 0026 FR-13) is not a page at all: it is a macro
#: library, extends nothing, defines no content block and is never rendered
#: on its own. AC-18 asserts exactly that below, so the exemption cannot
#: later be widened to silence a real page that forgot its `nav_current`.
NOT_PAGES = {"layout.html", "login.html", "setup.html", "ca_macros.html"}
CONTENT_TEMPLATES = sorted(p.name for p in TEMPLATES.glob("*.html") if p.name not in NOT_PAGES)


# --------------------------------------------------------------------------
# structure: templates
# --------------------------------------------------------------------------


def test_layout_has_rail_and_main() -> None:
    layout = (TEMPLATES / "layout.html").read_text()
    assert '<aside class="rail">' in layout
    assert "<main>" in layout
    # The rail only exists for a signed-in user; login/setup render without it.
    assert '<body class="{% if user %}with-rail{% endif %}">' in layout


def test_every_content_template_sets_nav_current() -> None:
    """FR-2: the rail can only mark the current page if the page names itself."""
    missing = [
        name
        for name in CONTENT_TEMPLATES
        if not re.search(r"{%\s*set nav_current\s*=", (TEMPLATES / name).read_text())
    ]
    assert missing == []

    # spec 0026 AC-18: the one exemption this test grants is a macro library,
    # and it is checked rather than trusted -- a real page smuggled into
    # NOT_PAGES to silence a failure is the only way this exemption can do
    # harm. `ca_macros.html` must be no page...
    macros_path = TEMPLATES / "ca_macros.html"
    assert macros_path.exists(), "ca_macros.html is missing (spec 0026 FR-13)"
    macros = macros_path.read_text()
    assert "{% extends" not in macros
    assert "{% block content %}" not in macros

    # ...and everything this test does check must be one: a template that
    # extends nothing cannot be marked by the rail whatever it sets.
    not_extending = [
        name
        for name in CONTENT_TEMPLATES
        if '{% extends "layout.html" %}' not in (TEMPLATES / name).read_text()
    ]
    assert not_extending == []


def test_every_table_is_wrapped_in_scroller() -> None:
    """FR-4: a table is the one thing wide enough to push the page sideways."""
    offenders = []
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text()
        for match in re.finditer(r"<table", text):
            before = text[: match.start()]
            # The nearest preceding div must be the scroller, and it must not
            # have been closed again in between.
            opened = before.rfind('<div class="scroller">')
            if opened == -1 or "</div>" in before[opened:]:
                offenders.append(path.name)
    assert offenders == []


def test_no_template_uses_card_or_badge_classes() -> None:
    """FR-3/FR-5: the three competing widths and the old badges are gone."""
    offenders = {}
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text()
        hits = re.findall(r'class="[^"]*\b(card(?!-narrow)\b|card-wide|badge[\w-]*)', text)
        if hits:
            offenders[path.name] = hits
    assert offenders == {}


def test_login_and_setup_use_narrow() -> None:
    for name in ("login.html", "setup.html"):
        assert 'class="card-narrow"' in (TEMPLATES / name).read_text()


# --------------------------------------------------------------------------
# structure: stylesheet
# --------------------------------------------------------------------------


def test_css_has_no_external_urls() -> None:
    """FR-7: cabin runs on an isolated network; nothing may be fetched off-host."""
    assert re.findall(r"url\(\s*['\"]?https?://", CSS.read_text()) == []


def test_css_defines_dark_counterpart_for_every_token() -> None:
    """FR-8: a token defined only in one scheme is unreadable in the other."""
    text = CSS.read_text()
    root = re.search(r":root\s*{(.*?)}", text, re.S)
    dark = re.search(r"prefers-color-scheme:\s*dark\s*\)\s*{\s*:root\s*{(.*?)}", text, re.S)
    assert root and dark
    colours = {
        name
        for name, value in re.findall(r"(--[\w-]+):\s*([^;]+);", root.group(1))
        if value.strip().startswith("#")
    }
    dark_tokens = set(re.findall(r"(--[\w-]+):", dark.group(1)))
    assert colours - dark_tokens == set()


def test_fonts_are_vendored_with_their_licences() -> None:
    fonts = STATIC / "fonts"
    for name in ("PublicSans.woff2", "IBMPlexMono.woff2"):
        assert (fonts / name).read_bytes()[:4] == b"wOF2"
    assert (fonts / "LICENSE-PublicSans.txt").exists()
    assert (fonts / "LICENSE-IBMPlexMono.txt").exists()


# --------------------------------------------------------------------------
# rendered pages
# --------------------------------------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _csrf(client: TestClient, cfg: Config) -> str:
    db: Session = create_session_factory(cfg.db_url)()
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _root_id(cfg: Config) -> int:
    """``_populate``'s own hierarchy's root id -- what ``/ca/{id}`` (spec
    0023's per-hierarchy detail page) is addressed by.

    Ordered by id and takes the first rather than ``.one()``: with
    ``second_issuer=True`` (``test_no_horizontal_overflow``), ``_populate``
    adds a second root as a cross-sign candidate, and the earliest one --
    created first, lowest id -- is always the hierarchy the rest of
    ``_populate`` (the issued certificate, the token, the EAB key) builds
    on.
    """
    db: Session = create_session_factory(cfg.db_url)()
    try:
        row = db.scalars(
            select(CACertificate).where(CACertificate.kind == "root").order_by(CACertificate.id)
        ).first()
        assert row is not None, "no root row exists"
        return row.id
    finally:
        db.close()


def _first_intermediate_id(cfg: Config) -> int:
    """The intermediate under ``_root_id``'s hierarchy -- what spec 0026's
    `/ca/{root_id}/issuer/{issuer_id}` is addressed by. Lowest id, for the
    reason ``_root_id`` gives."""
    db: Session = create_session_factory(cfg.db_url)()
    try:
        row = db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "intermediate")
            .order_by(CACertificate.id)
        ).first()
        assert row is not None, "no intermediate row exists"
        return row.id
    finally:
        db.close()


def _cross_id(cfg: Config) -> int:
    """The cross certificate ``_populate(second_issuer=True)`` creates for
    ``_root_id``'s root -- spec 0026's `/ca/{root_id}/cross/{cross_id}`."""
    db: Session = create_session_factory(cfg.db_url)()
    try:
        row = db.scalars(
            select(CACertificate).where(CACertificate.kind == "cross").order_by(CACertificate.id)
        ).first()
        assert row is not None, "no cross row exists"
        return row.id
    finally:
        db.close()


def _populate(client: TestClient, cfg: Config, *, second_issuer: bool = False) -> str:
    """A CA, a certificate with a long name and several SANs, a token and an
    EAB key — the data that made the old layout break.

    ``second_issuer`` (default off, so every other caller in this file is
    unaffected): adds a second root, eligible to cross-sign the first, and
    an intermediate under it. Added only after the certificate above is
    issued, because issuing with no ``issuer_id`` resolves to "the sole
    active issuer" and turns ambiguous the moment a second one exists (spec
    0017). Two active issuers is what ``certs_new.html``/``certs_sign.html``
    need before their own issuer ``<select>`` renders at all (FR-14), and a
    second root with ``path_length=2`` is what makes ``ca_detail.html``
    offer one to cross-sign the first (spec 0021 FR-13) -- the two
    ``<select>``s ``test_no_horizontal_overflow`` would otherwise never
    render at all.

    Both new names are freshly made up rather than reusing the intermediate
    name above, and deliberately close to ``_MAX_NAME_BYTES`` (64):
    measured directly (headless Chrome, 390px), that 56-byte name alone
    does not overflow either of these two selects' own ``.field`` -- its
    rendered width lands just *under* the grid cell here, where it only
    clears it in ``transfer_ca_key.html`` because that page appends
    ``" (kind)"`` to every option. A shorter name would make this test pass
    for the wrong reason (spec 0015 AC-1/AC-2 says "no overflow", not "no
    overflow of names this short"); these two are picked long enough that
    the select itself, not a suffix some other page happens to add, is what
    crosses the line.
    """
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    assert (
        client.post(
            "/ca/create",
            data={
                "name": "Acme Corporation Internal Issuing Authority",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    db: Session = create_session_factory(cfg.db_url)()
    try:
        root_row = db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "root")
            .order_by(CACertificate.id.desc())
        ).first()
        assert root_row is not None, "no root row exists"
        root_id = root_row.id
    finally:
        db.close()
    assert (
        client.post(
            f"/ca/{root_id}/intermediate",
            data={
                # Distinct from the root's own name: create_intermediate_under
                # refuses an intermediate whose subject collides with its
                # parent root's (spec 0024 FR-13).
                "name": "Acme Corporation Internal Issuing Authority Intermediate",
                "key_type": "ecdsa-p256",
                "years": 10,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    client.post(
        "/settings",
        data={
            "base_url": "https://cabin.internal.example.com:8443",
            "csrf_token": _csrf(client, cfg),
        },
    )
    issued = client.post(
        "/certs/issue",
        data={
            "subject_cn": "kubernetes-ingress-controller.platform.internal.example.com",
            "sans": "\n".join(
                [
                    "kubernetes-ingress-controller.platform.internal.example.com",
                    "grafana.observability.internal.example.com",
                    "alertmanager.observability.internal.example.com",
                    "10.42.13.201",
                    "ops-team@internal.example.com",
                ]
            ),
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert issued.status_code == 303
    client.post(
        "/tokens",
        data={
            "label": "terraform-provider-automation",
            "role": "admin",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.post(
        "/acme/admin/eab-keys",
        data={
            "label": "traefik.edge.internal.example.com",
            "csrf_token": _csrf(client, cfg),
        },
    )
    if second_issuer:
        assert (
            client.post(
                "/ca/create",
                data={
                    "name": "Beta Worldwide Corporation Internal Issuing Authority Root CA",
                    "key_type": "ecdsa-p256",
                    "root_years": 20,
                    "path_length": 2,
                    "csrf_token": _csrf(client, cfg),
                },
            ).status_code
            == 303
        )
        db: Session = create_session_factory(cfg.db_url)()
        try:
            second_root = db.scalars(
                select(CACertificate)
                .where(CACertificate.kind == "root")
                .order_by(CACertificate.id.desc())
            ).first()
            assert second_root is not None, "second root was not created"
            second_root_id = second_root.id
        finally:
            db.close()
        assert (
            client.post(
                f"/ca/{second_root_id}/intermediate",
                data={
                    "name": "Beta Worldwide Corporation Internal Issuing Sub-Authority CA",
                    "key_type": "ecdsa-p256",
                    "years": 10,
                    "csrf_token": _csrf(client, cfg),
                },
            ).status_code
            == 303
        )
        # spec 0026: the five-column `Cross certificates` table is the widest
        # new thing on a hierarchy page, and its row's own page is one of the
        # two pages the overflow probe gains -- neither exists unless a cross
        # certificate does. The second root's `path_length=2` is what lets it
        # sign the first.
        assert (
            client.post(
                f"/ca/{_root_id(cfg)}/cross-sign",
                data={
                    "signing_root_id": second_root_id,
                    "years": 5,
                    "csrf_token": _csrf(client, cfg),
                },
            ).status_code
            == 303
        )
    return issued.headers["location"]


def test_nav_current_marked_once_per_page(client: TestClient, cfg: Config) -> None:
    """AC-5: exactly one entry is marked, and it is the page being viewed."""
    cert_path = _populate(client, cfg)
    expected = {
        "/": "Dashboard",
        "/ca": "Hierarchies",
        "/ca/new": "Create",
        "/transfer/ca-import": "Import a CA",
        "/transfer/cross-import": "Import a cross certificate",
        "/transfer/trust-bundle": "Trust bundle",
        "/transfer/ca-key": "CA key",
        "/transfer/inventory": "Inventory export",
        "/certs": "Inventory",
        cert_path: "Inventory",
        "/certs/new": "Issue",
        "/certs/sign": "Sign a CSR",
        "/acme/admin": "ACME",
        "/tokens": "API tokens",
        "/users": "Users",
        "/audit": "Audit log",
        "/settings": "Settings",
    }
    for path, label in expected.items():
        html = client.get(path).text
        marked = re.findall(r'<a href="[^"]*" aria-current="page">([^<]+)</a>', html)
        assert marked == [label], f"{path}: {marked}"


def test_nav_entries_still_role_gated(client: TestClient, cfg: Config) -> None:
    """FR-1: the rail regroups the entries, it does not re-authorise them."""
    _populate(client, cfg)
    client.post(
        "/users",
        data={
            "username": "vera",
            "password": "correcthorse1x",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.post(
        "/users",
        data={
            "username": "adam",
            "password": "correcthorse1x",
            "role": "admin",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.post("/logout", data={"csrf_token": _csrf(client, cfg)})
    client.post("/login", data={"username": "vera", "password": "correcthorse1x"})

    rail = client.get("/certs").text
    assert 'href="/certs"' in rail and 'href="/audit"' in rail
    for hidden in (
        'href="/certs/new"',
        'href="/certs/sign"',
        'href="/tokens"',
        'href="/settings"',
        'href="/acme/admin"',
        # spec 0023: the two new create/import entries are as admin-only as
        # the forms they now point at.
        'href="/ca/new"',
        'href="/transfer/ca-import"',
        # spec 0025: the CA key export is superadmin-only.
        'href="/transfer/ca-key"',
    ):
        assert hidden not in rail

    client.post("/logout", data={"csrf_token": _csrf(client, cfg)})
    client.post("/login", data={"username": "adam", "password": "correcthorse1x"})

    admin_rail = client.get("/certs").text
    assert 'href="/ca/new"' in admin_rail
    assert 'href="/transfer/ca-import"' in admin_rail
    # spec 0025 FR-6: the CA key export is the one entry an admin -- not just
    # a viewer -- must not see either, the first such case in this file.
    assert 'href="/transfer/ca-key"' not in admin_rail


def test_signing_is_its_own_page(client: TestClient, cfg: Config) -> None:
    """AC-8/FR-10: the CSR form is a page of its own, admin-only, and its
    errors stay on it instead of bouncing to the issue page."""
    _populate(client, cfg)

    page = client.get("/certs/sign")
    assert page.status_code == 200
    assert 'name="csr_pem"' in page.text
    # The two pages are separate: neither carries the other's form.
    assert 'name="subject_cn"' not in page.text
    assert 'name="csr_pem"' not in client.get("/certs/new").text

    rejected = client.post(
        "/certs/sign",
        data={
            "csr_pem": "not a csr",
            "profile": "server",
            "days": 30,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert rejected.status_code == 400
    assert 'name="csr_pem"' in rejected.text, "the error left the CSR page"
    assert 'name="subject_cn"' not in rejected.text

    client.post(
        "/users",
        data={
            "username": "val",
            "password": "correcthorse1x",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.post("/logout", data={"csrf_token": _csrf(client, cfg)})
    client.post("/login", data={"username": "val", "password": "correcthorse1x"})
    assert client.get("/certs/sign").status_code == 403


def test_fonts_served_with_woff2_content_type(client: TestClient, cfg: Config) -> None:
    for name in ("PublicSans", "IBMPlexMono"):
        resp = client.get(f"/static/fonts/{name}.woff2")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "font/woff2"


# --------------------------------------------------------------------------
# geometry (AC-1..AC-3)
# --------------------------------------------------------------------------

CHROME = "/opt/google/chrome/chrome"

#: Injected into a rendered page; reports every element drawn past the viewport
#: or past its own container. Elements inside a scroll container are skipped —
#: clipping there is the point of .scroller.
PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function scrollable(el) {
      for (var p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        var ox = getComputedStyle(p).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden') return true;
      }
      return false;
    }
    function container(el) {
      for (var p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
        if (getComputedStyle(p).display !== 'inline' && p.getBoundingClientRect().width > 0) {
          return p;
        }
      }
      return null;
    }
    var vw = document.documentElement.clientWidth, bad = [];
    document.querySelectorAll('body *').forEach(function (el) {
      var r = el.getBoundingClientRect();
      if ((r.width === 0 && r.height === 0) || scrollable(el)) return;
      var c = container(el);
      var label = el.tagName.toLowerCase() + '.' + (el.className || '').toString().slice(0, 30);
      if (r.right > vw + 1) bad.push(label + ' past viewport by ' + Math.round(r.right - vw));
      else if (c) {
        var over = Math.round(r.right - c.getBoundingClientRect().right);
        if (over > 1) bad.push(label + ' out of container by ' + over);
      }
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify(bad);
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


def _serve(root: Path) -> tuple[ThreadingHTTPServer, int]:
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _overflow(url: str, width: int, height: int) -> list[str]:
    dom = subprocess.run(
        [
            CHROME,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--window-size={width},{height}",
            "--virtual-time-budget=4000",
            "--dump-dom",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=90,
    ).stdout
    found = re.search(r'<div id="probe-result">(.*?)</div>', dom, re.S)
    assert found is not None, "probe did not run — Chrome rendered nothing"
    return json.loads(found.group(1).replace("&quot;", '"').replace("&amp;", "&"))


#: Injected into a long page; scrolls to the bottom and reports whether the
#: rail's logout button is still inside the viewport.
STICKY_PROBE = """
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
        scrolled: Math.round(window.scrollY),
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


def _probe(url: str, width: int, height: int) -> dict:
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
    assert found is not None, "probe did not run — Chrome rendered nothing"
    return json.loads(found.group(1).replace("&quot;", '"').replace("&amp;", "&"))


@pytest.mark.skipif(not Path(CHROME).exists(), reason="headless Chrome not installed")
def test_rail_stays_in_view_on_a_long_page(client: TestClient, cfg: Config, tmp_path: Path) -> None:
    """The rail is the only way out of a page, so it may not scroll away.

    A certificate detail page carries two PEM blocks and is several viewports
    tall; scrolled to its end, the logout button — the last thing in the rail,
    and therefore the first to disappear — has to still be on screen.

    ``_populate`` sets up and stays logged in as the superadmin, so this is
    already the sixteen-entry rail (spec 0025 AC-13). The logout button
    staying on screen is not enough on its own — a viewport the rail merely
    fits into would pass that without the rail's own internal scroll
    (``cabin.css:143-152``) ever engaging — so this also asserts the
    ``<nav>`` itself is actually taller than its own box.
    """
    cert_path = _populate(client, cfg)
    root = tmp_path / "sticky"
    root.mkdir()
    shutil.copytree(STATIC, root / "static")
    page = client.get(cert_path)
    assert page.status_code == 200
    (root / "cert.html").write_text(page.text.replace("</body>", STICKY_PROBE + "</body>"))

    httpd, port = _serve(root)
    try:
        result = _probe(f"http://127.0.0.1:{port}/cert.html", 1440, 700)
    finally:
        httpd.shutdown()

    assert result["found"], "the rail has no logout button"
    assert result["scrolled"] > 400, f"page was not long enough to test: {result}"
    assert result["top"] >= 0 and result["bottom"] <= result["viewport"], (
        f"logout button left the viewport after scrolling: {result}"
    )
    assert result["navScrollHeight"] is not None and result["navClientHeight"] is not None
    assert result["navScrollHeight"] > result["navClientHeight"], (
        f"the rail's nav list is not actually scrolling -- the criterion "
        f"would pass vacuously on a viewport it merely fit into: {result}"
    )


@pytest.mark.skipif(not Path(CHROME).exists(), reason="headless Chrome not installed")
@pytest.mark.parametrize("width,height", [(1440, 1150), (390, 900)])
def test_no_horizontal_overflow(tmp_path: Path, width: int, height: int) -> None:
    """AC-1/AC-2: with real data, nothing is drawn outside its container at
    either a desktop or a phone width.

    This test is the reason spec 0015 exists: before it, /certs drew its last
    three columns 275px outside the card and off the screen.

    ``.field select`` in cabin.css exists because a native ``<select>`` won't
    shrink below its longest option, and a CA name is the thing long enough
    to force that. Five pages carry such a select. Four of them only render
    it in a state ``_populate`` alone doesn't reach -- more than one active
    issuer (``certs_new.html``/``certs_sign.html``), TLS on
    (``settings.html``), or a second root eligible to cross-sign the first
    (``ca_detail.html``) -- so this test builds its own TLS-enabled
    ``Config`` and calls ``_populate(..., second_issuer=True)`` rather than
    using the file's shared ``cfg``/``client`` fixtures, which stay
    single-issuer, TLS-off for every other test here.
    """
    data_dir = tmp_path / "data"
    cfg = Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        cert_path = _populate(client, cfg, second_issuer=True)
        root = tmp_path / "pages"
        root.mkdir()
        shutil.copytree(STATIC, root / "static")

        pages = {
            "dashboard": "/",
            "ca": "/ca",
            "ca_new": "/ca/new",
            "ca_detail": f"/ca/{_root_id(cfg)}",
            "ca_issuer": f"/ca/{_root_id(cfg)}/issuer/{_first_intermediate_id(cfg)}",
            "ca_cross": f"/ca/{_root_id(cfg)}/cross/{_cross_id(cfg)}",
            "transfer_ca_import": "/transfer/ca-import",
            "transfer_cross_import": "/transfer/cross-import",
            "transfer_trust_bundle": "/transfer/trust-bundle",
            "transfer_ca_key": "/transfer/ca-key",
            "transfer_inventory": "/transfer/inventory",
            "certs": "/certs",
            "certs_new": "/certs/new",
            "certs_sign": "/certs/sign",
            "cert_detail": cert_path,
            "users": "/users",
            "audit": "/audit",
            "settings": "/settings",
            "acme": "/acme/admin",
            "tokens": "/tokens",
        }
        for name, path in pages.items():
            resp = client.get(path)
            assert resp.status_code == 200, f"{path} -> {resp.status_code}"
            (root / f"{name}.html").write_text(resp.text.replace("</body>", PROBE + "</body>"))

    httpd, port = _serve(root)
    try:
        offenders = {
            name: bad
            for name in pages
            if (bad := _overflow(f"http://127.0.0.1:{port}/{name}.html", width, height))
        }
    finally:
        httpd.shutdown()
    assert offenders == {}
