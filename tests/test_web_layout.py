"""Web-layer tests for spec 0015: the page chrome and its layout primitives.

Two kinds of test live here. The cheap ones read the templates and the
stylesheet and assert their structure (FR-1..FR-8, AC-4..AC-6). The expensive
ones render every page in headless Chrome and measure whether anything is
drawn outside its container (AC-1..AC-3) — the defect this spec exists for is
geometric, and only a browser can see it.
"""

import re
from collections.abc import Iterator
from pathlib import Path

import probes
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
    # The rail only exists for a signed-in user; login/setup render without it.
    assert '<body class="{% if user %}with-rail{% endif %}">' in layout

    # spec 0027 FR-6: the rail and the content move inside one shell, and
    # `<main>` gains the id `_HEIGHT_PROBE` measures (FR-23). Both names are
    # scoped by tests and by the stylesheet, so they are asserted here rather
    # than left to a rendered page to imply.
    assert '<div class="shell">' in layout
    assert '<main id="main">' in layout


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


_TOKEN_RE = re.compile(r"(--[\w-]+)\s*:\s*([^;{}]+);?")

_LIGHT_MEDIA = "@media (prefers-color-scheme: light)"


def _brace_block(text: str, start: int) -> str:
    """The balanced ``{...}`` body that begins at or after ``start``."""
    open_brace = text.index("{", start)
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : i]
    raise AssertionError("unbalanced braces in cabin.css")


def _default_root(text: str) -> str:
    at = text.find(":root")
    assert at != -1, "cabin.css declares no :root block"
    light = text.find(_LIGHT_MEDIA)
    assert light == -1 or at < light, "the default :root must precede the light override (FR-8)"
    return _brace_block(text, at)


def _light_root(text: str) -> str:
    at = text.find(_LIGHT_MEDIA)
    assert at != -1, f"cabin.css has no {_LIGHT_MEDIA} block (spec 0027 FR-8)"
    media = _brace_block(text, at)
    inner = media.find(":root")
    assert inner != -1, "the light media block contains no :root rule (FR-8)"
    return _brace_block(media, inner)


def _tokens(block: str) -> dict[str, str]:
    return {name: " ".join(value.split()).lower() for name, value in _TOKEN_RE.findall(block)}


def _is_colour(value: str) -> bool:
    """FR-13.1: a colour is not only a hex literal.

    The design's two dividers are ``rgba(233,233,237,.08)`` and
    ``rgba(233,233,237,.07)`` -- the border between every section and every
    list row on every page. The old filter was ``startswith("#")``, so both
    would have dropped out of the set being checked entirely.
    """
    return value.startswith(("#", "rgb(", "rgba(", "hsl(", "hsla(", "color(", "lab(", "oklch("))


def _scheme_defects(text: str) -> list[str]:
    """Every way the two schemes can fail to be each other's counterpart."""
    defaults = _tokens(_default_root(text))
    overrides = _tokens(_light_root(text))
    coloured = {name: value for name, value in defaults.items() if _is_colour(value)}
    defects = [
        f"{name} has no light counterpart" for name in sorted(set(coloured) - set(overrides))
    ]
    defects += [
        f"{name} is overridden but has no default"
        for name in sorted(set(overrides) - set(defaults))
    ]
    defects += [
        f"{name}'s light override repeats its default ({value})"
        for name, value in sorted(overrides.items())
        if defaults.get(name) == value
    ]
    return defects


def test_css_defines_dark_counterpart_for_every_token() -> None:
    """Spec 0015 FR-8, re-pointed by spec 0027 FR-8/FR-13.

    The requirement has not changed: a token defined in only one scheme is
    unreadable in the other. Only the block it reads has moved -- the dark
    values are now the defaults and the override block is
    ``prefers-color-scheme: light``.

    Three strengthenings (FR-13). It accepts ``rgba()`` and not only ``#``;
    it runs in both directions, because an override for a token that has no
    default is dead CSS and is what a half-finished rename leaves behind; and
    it rejects an override that merely repeats its default. The last clause
    is the one that matters most: copying the dark value into the light block
    satisfies "a counterpart exists" while being exactly the defect this test
    was written for -- the light scheme would then paint dark-scheme greys on
    a white ground. The old test passed against that build.
    """
    text = CSS.read_text()
    assert _scheme_defects(text) == []

    # AC-9's counter-check: the third clause has to be able to bite. Replace
    # one light override with its own default and the test must go red -- a
    # clause that cannot fail is not a clause.
    overrides = _tokens(_light_root(text))
    defaults = _tokens(_default_root(text))
    victim = next(name for name in overrides if name in defaults)
    light = _light_root(text)
    doctored = text.replace(
        light, re.sub(rf"{victim}\s*:\s*[^;]+;", f"{victim}: {defaults[victim]};", light, count=1)
    )
    assert doctored != text, "the counter-check did not change the stylesheet"
    assert _scheme_defects(doctored) != [], (
        "a light override replaced by its own default was not rejected -- "
        "the clause that catches a copied-across value does not bite"
    )


def test_light_block_holds_nothing_but_token_overrides() -> None:
    """FR-8/AC-9: the shape FR-14's scheme-forcing depends on.

    ``probes.light_stylesheet`` makes the light scheme unconditional by
    deleting the media wrapper. That is only faithful if the block holds one
    ``:root`` rule and nothing else; anything else in it would be promoted to
    unconditional too, and the light contrast run would be measuring a page
    the browser never draws.
    """
    text = CSS.read_text()
    at = text.find(_LIGHT_MEDIA)
    assert at != -1, f"cabin.css has no {_LIGHT_MEDIA} block (spec 0027 FR-8)"
    assert text.find(_LIGHT_MEDIA, at + 1) == -1, "more than one light media block"

    media = _brace_block(text, at)
    inner = media.find(":root")
    assert inner != -1, "the light media block contains no :root rule"
    root = _brace_block(media, inner)
    remainder = media.replace(f"{{{root}}}", "", 1).replace(":root", "", 1)
    assert remainder.strip() == "", (
        f"the light media block holds more than one :root rule: {remainder.strip()!r}"
    )

    declarations = [part.strip() for part in root.split(";") if part.strip()]
    strays = [part for part in declarations if not part.startswith("--")]
    assert strays == [], f"the light :root declares more than custom properties: {strays}"


def test_fonts_are_vendored_with_their_licences() -> None:
    """Spec 0015 FR-7's requirement, re-pointed by spec 0027 FR-17/AC-20.

    The requirement is unchanged: both faces live in the repository with
    their SIL OFL 1.1 licence text beside them and nothing is fetched from a
    CDN. Only the filenames move -- Public Sans retires and Inter takes its
    place. AC-20 adds what the old test did not carry at all: the retired
    face and its licence are gone and nothing references them, so Inter
    cannot simply be added on top of 27 KB of dead weight.
    """
    fonts = STATIC / "fonts"
    for name in ("Inter.woff2", "IBMPlexMono.woff2"):
        assert (fonts / name).read_bytes()[:4] == b"wOF2", f"{name} is not a woff2 file"
    for licence in ("LICENSE-Inter.txt", "LICENSE-IBMPlexMono.txt"):
        assert (fonts / licence).read_text().strip() != "", f"{licence} is missing or empty"

    assert not (fonts / "PublicSans.woff2").exists(), "the retired face is still in the repository"
    assert not (fonts / "LICENSE-PublicSans.txt").exists()

    text = CSS.read_text()
    assert re.findall(r"url\(\s*['\"]?https?://", text) == []
    referenced = set(re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", text))
    assert {name for name in referenced if "fonts/" in name} == {
        "/static/fonts/Inter.woff2",
        "/static/fonts/IBMPlexMono.woff2",
    }, referenced

    repo = Path(__file__).resolve().parents[1]
    still = [
        path.relative_to(repo).as_posix()
        for path in (repo / "src").rglob("*")
        if path.is_file() and "PublicSans" in path.read_bytes().decode("utf-8", "ignore")
    ]
    assert still == [], f"PublicSans is still referenced by {still}"

    # FR-17's deliberate divergence from brief section 2: cabin's monospace
    # carries fingerprints and PEM bodies, which a bare system stack renders
    # at a different advance width on every platform.
    mono = _tokens(_default_root(text))["--mono"]
    assert mono.startswith('"ibm plex mono"'), mono
    assert "ui-monospace" in mono, mono


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
    """Spec 0015 FR-7: cabin serves the faces itself, with the right type.

    Re-pointed by spec 0027 FR-17 -- two filenames change, the assertion
    shape does not. AC-20's other half: the retired face is not served
    either, so "Inter was added" cannot be mistaken for "Public Sans went".
    """
    for name in ("Inter", "IBMPlexMono"):
        resp = client.get(f"/static/fonts/{name}.woff2")
        assert resp.status_code == 200, f"{name}.woff2 -> {resp.status_code}"
        assert resp.headers["content-type"] == "font/woff2"
        assert resp.content[:4] == b"wOF2"
    assert client.get("/static/fonts/PublicSans.woff2").status_code == 404


# --------------------------------------------------------------------------
# geometry (AC-1..AC-3, and spec 0027 AC-3/AC-13)
# --------------------------------------------------------------------------

#: Injected into a long page; scrolls `#main` to its end and reports whether
#: the rail's logout button is still inside the viewport.
#:
#: spec 0027 FR-23: the window can no longer scroll -- the shell is
#: `height:100vh; overflow:hidden` -- so `window.scrollTo(...)` leaves
#: `scrollY` at 0 and the old assertion `scrolled > 400` would go red without
#: the requirement having changed at all. The scroll target becomes `#main`.
#: The nav guard below is kept verbatim: it is the half that makes the
#: criterion non-vacuous, and the shell does not make it redundant, because
#: the rail's footer is still pushed out of a 100vh column and clipped by
#: `overflow:hidden` if `nav` does not scroll on its own.
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


def page_paths(cfg: Config, cert_path: str) -> dict[str, str]:
    """The nineteen screens the overflow probe covers.

    Lifted out of ``test_no_horizontal_overflow`` so that spec 0027's
    contrast, focus and stylesheet-agreement checks run over the same list
    rather than over a second one that drifts away from it (FR-20).
    """
    return {
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


def render_pages(client: TestClient, paths: dict[str, str]) -> dict[str, str]:
    """Fetch every page, asserting each one is actually a page.

    A route that moves and starts 404ing or 405ing would otherwise drop out
    of every probe below while contributing nothing and failing nothing.
    """
    rendered = {}
    for name, path in paths.items():
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        rendered[name] = resp.text
    return rendered


@pytest.mark.skipif(not Path(probes.CHROME).exists(), reason="headless Chrome not installed")
def test_rail_stays_in_view_on_a_long_page(client: TestClient, cfg: Config, tmp_path: Path) -> None:
    """The rail is the only way out of a page, so it may not scroll away.

    A certificate detail page carries two PEM blocks and is several viewports
    tall; scrolled to its end, the logout button — the last thing in the rail,
    and therefore the first to disappear — has to still be on screen.

    ``_populate`` sets up and stays logged in as the superadmin, so this is
    already the sixteen-entry rail (spec 0025 AC-13). The logout button
    staying on screen is not enough on its own — a viewport the rail merely
    fits into would pass that without the rail's own internal scroll ever
    engaging — so this also asserts the ``<nav>`` itself is actually taller
    than its own box.

    spec 0027 FR-23 re-points the scroll from the window to ``#main`` and
    keeps the nav guard verbatim. The requirement is spec 0015 FR-1's and is
    unchanged; only the element that scrolls has moved.
    """
    cert_path = _populate(client, cfg)
    root = tmp_path / "sticky"
    root.mkdir()
    page = client.get(cert_path)
    assert page.status_code == 200
    probes.stage(root, STATIC, {"cert": page.text}, RAIL_PROBE)

    httpd, port = probes.serve(root)
    try:
        result = probes.run(f"http://127.0.0.1:{port}/cert.html", 1440, 700)
    finally:
        httpd.shutdown()

    assert result["mainFound"], f"the page has no #main to scroll (spec 0027 FR-23): {result}"
    assert result["found"], "the rail has no logout button"
    assert result["scrolled"] > 400, f"main was not long enough to test: {result}"
    assert result["top"] >= 0 and result["bottom"] <= result["viewport"], (
        f"logout button left the viewport after scrolling: {result}"
    )
    assert result["navScrollHeight"] is not None and result["navClientHeight"] is not None
    assert result["navScrollHeight"] > result["navClientHeight"], (
        f"the rail's nav list is not actually scrolling -- the criterion "
        f"would pass vacuously on a viewport it merely fit into: {result}"
    )


@pytest.mark.skipif(not Path(probes.CHROME).exists(), reason="headless Chrome not installed")
@pytest.mark.parametrize("scheme", ["dark", "light"])
@pytest.mark.parametrize("width,height", [(1440, 1150), (390, 900)])
def test_no_horizontal_overflow(tmp_path: Path, width: int, height: int, scheme: str) -> None:
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

    spec 0027 AC-3: the probe is the repaired one from ``tests/probes.py``,
    it is run in both schemes, and every page must report having examined at
    least twenty elements (FR-4). What that floor guards against is a walker
    that excuses the page, not a page that is small: once the shell lands the
    pre-repair walker leaves exactly one element examined, because every
    element has an ``overflow:hidden`` ancestor and the shell is the only one
    it cannot excuse. Twenty is twenty times that and two-thirds of the
    thinnest real page (``/ca``, 30 examined at 390).
    """
    data_dir = tmp_path / "data"
    cfg = Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        cert_path = _populate(client, cfg, second_issuer=True)
        pages = page_paths(cfg, cert_path)
        rendered = render_pages(client, pages)

    root = tmp_path / f"pages-{scheme}"
    root.mkdir()
    probes.stage(root, STATIC, rendered, probes.OVERFLOW_PROBE, scheme)

    httpd, port = probes.serve(root)
    try:
        results = {
            name: probes.overflow(f"http://127.0.0.1:{port}/{name}.html", width, height)
            for name in pages
        }
    finally:
        httpd.shutdown()

    offenders = {name: found["bad"] for name, found in results.items() if found["bad"]}
    assert offenders == {}
    thin = {name: found for name, found in results.items() if int(str(found["examined"])) < 20}
    assert thin == {}, (
        f"the probe examined almost nothing on {sorted(thin)} -- a green run that "
        f"measured no page is the failure spec 0027 FR-4 exists to catch: {thin}"
    )
