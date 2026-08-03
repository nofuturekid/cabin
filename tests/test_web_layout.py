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
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory

TEMPLATES = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
STATIC = Path(__file__).resolve().parents[1] / "src/cabin/web/static"
CSS = STATIC / "cabin.css"

#: Templates rendered inside the rail. login/setup are the two without one.
CONTENT_TEMPLATES = sorted(
    p.name
    for p in TEMPLATES.glob("*.html")
    if p.name not in {"layout.html", "login.html", "setup.html"}
)


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


def _populate(client: TestClient, cfg: Config) -> str:
    """A CA, a certificate with a long name and several SANs, a token and an
    EAB key — the data that made the old layout break."""
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
                "intermediate_years": 10,
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
    return issued.headers["location"]


def test_nav_current_marked_once_per_page(client: TestClient, cfg: Config) -> None:
    """AC-5: exactly one entry is marked, and it is the page being viewed."""
    cert_path = _populate(client, cfg)
    expected = {
        "/": "Dashboard",
        "/ca": "Certificate authority",
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
    ):
        assert hidden not in rail


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
      var r = button ? button.getBoundingClientRect() : null;
      var out = document.createElement('div');
      out.id = 'probe-result';
      out.textContent = JSON.stringify({
        found: !!button,
        scrolled: Math.round(window.scrollY),
        top: r ? Math.round(r.top) : null,
        bottom: r ? Math.round(r.bottom) : null,
        viewport: document.documentElement.clientHeight
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


@pytest.mark.skipif(not Path(CHROME).exists(), reason="headless Chrome not installed")
@pytest.mark.parametrize("width,height", [(1440, 1150), (390, 900)])
def test_no_horizontal_overflow(
    client: TestClient, cfg: Config, tmp_path: Path, width: int, height: int
) -> None:
    """AC-1/AC-2: with real data, nothing is drawn outside its container at
    either a desktop or a phone width.

    This test is the reason spec 0015 exists: before it, /certs drew its last
    three columns 275px outside the card and off the screen.
    """
    cert_path = _populate(client, cfg)
    root = tmp_path / "pages"
    root.mkdir()
    shutil.copytree(STATIC, root / "static")

    pages = {
        "dashboard": "/",
        "ca": "/ca",
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
