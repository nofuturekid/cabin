"""Web-layer tests for spec 0026 (hierarchy tables and row pages):
`/ca/{root_id}` becomes a root section, an `Issuers` table, a
`Cross certificates` table and then the two forms (FR-1..FR-4), and every
per-row detail moves onto `/ca/{root_id}/issuer/{id}` and
`/ca/{root_id}/cross/{id}` (FR-5..FR-9), which is also where the renew and
retire controls, their refusals and their redirects now live
(FR-10/FR-11).

This branch is red by design: neither new route exists, `ca_issuer.html`
and `ca_macros.html` do not exist, `ca_detail.html` still renders one
`.section` per intermediate and per cross row above nothing, `_child_view`
and `_page_of` and `_load_pair` do not exist, and both POST redirects
still go to `/ca/{root_of_row}`.

Scoping follows `test_web_ca_pages.py`'s `_row(...)`/`_form_block(...)`:
the element that actually wraps a marker, found by parsing tag nesting --
never a fixed-character window and never a bare substring search over the
whole page. `_row`'s `class_name` is optional here (and in the four other
copies of the helper) so a `<tr>` can be scoped by a marker inside it:
table rows deliberately carry no class, and giving them one would put a
selector in the stylesheet that AC-15's both-directions test would then
require to be used and styled.

Every helper below is duplicated rather than imported, as this project's
other web test files already do (there is no conftest.py, and each file
owns its own client/session/CSRF and HTML-scoping plumbing).
"""

import json
import re
import shutil
import subprocess
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from html import unescape
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import probes
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.testclient import TestClient
from jinja2 import FileSystemLoader
from sqlalchemy.orm import Session

# Spec 0027 FR-2's rule, one level up: the stylesheet parser has one
# definition too. A second copy here would be a second thing to repair the
# next time a selector form appears that it cannot read.
from test_web_design_shell import css_rules, declarations

from cabin import web as cabin_web
from cabin.acme import http as acme_http
from cabin.app import create_app
from cabin.ca import certs as ca_certs
from cabin.ca import crl as crl_service
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.web import ca_ui

REPO = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO / "src/cabin/web/static"
TEMPLATES_DIR = REPO / "src/cabin/web/templates"
CSS_PATH = STATIC_DIR / "cabin.css"
CHROME = "/opt/google/chrome/chrome"

#: The commit spec 0028 starts from. AC-16 renders each of the five pages
#: twice -- once through the templates as they stand and once through the
#: templates as they stood here -- against one database, so that every text
#: node that differs differs because of markup and not because of data.
BASELINE = "051b006"

#: FR-1's five templates.
FIVE_TEMPLATES = (
    "ca_list.html",
    "ca_detail.html",
    "ca_issuer.html",
    "ca_macros.html",
    "cert_detail.html",
)

#: FR-10's table, as a set: every class this spec defines, and its first
#: user's template. `.panel`/`.panel-danger` were reserved by spec 0027 and
#: are rendered here; the other twelve are new.
DEFINED_CLASSES = (
    "rows",
    "cols-hierarchies",
    "cols-issuers",
    "cols-crosses",
    "facts",
    "facts-indent",
    "rowlink",
    "row-root",
    "row-child",
    "state-active",
    "state-retired",
    "tree",
    "panel",
    "panel-danger",
)

#: The two table headings, matched as heading *text* rather than as a bare
#: word: `>Issuers<` cannot land inside a help sentence or an attribute the
#: way `Issuers` could.
ISSUERS_HEADING = ">Issuers<"
CROSS_HEADING = ">Cross certificates<"

#: The constrained intermediate's permitted entry. Deliberately not
#: `example.com`: that string is the `Add intermediate` textarea's own
#: placeholder, so AC-2's "the constraint entry is not on the root page"
#: would be unfailable with it.
PERMITTED = "constrained.alpha.example"


# --- fixtures and low-level plumbing, duplicated from test_web_ca_pages.py --


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


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _create_viewer(client: TestClient, cfg: Config, username: str = "vera") -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str) -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _status_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).status
    finally:
        db.close()


def _cert_of(cfg: Config, ca_id: int) -> x509.Certificate:
    db = _db(cfg)
    try:
        return x509.load_pem_x509_certificate(ca_service.get_ca(db, ca_id).cert_pem.encode("ascii"))
    finally:
        db.close()


def _fingerprint(cfg: Config, ca_id: int) -> str:
    """The same format `ca_x509.describe_certificate` renders -- SHA-256,
    colon-hex -- computed here from the certificate itself rather than
    imported, so this is a check against the certificate, not against the
    code under test."""
    digest = _cert_of(cfg, ca_id).fingerprint(hashes.SHA256())
    return ":".join(f"{b:02x}" for b in digest)


def _subject_of(cfg: Config, ca_id: int) -> str:
    return _cert_of(cfg, ca_id).subject.rfc4514_string()


def _expiry_of(cfg: Config, ca_id: int) -> str:
    """`not_valid_after` as the template renders it (`str(datetime)`)."""
    return str(_cert_of(cfg, ca_id).not_valid_after_utc)


def _published_urls(cfg: Config, issuer_id: int) -> tuple[str, str, str]:
    """The CRL, AIA and ACME directory URLs for one issuer, read through the
    same helpers the certificates themselves are built with."""
    db = _db(cfg)
    try:
        crl_url = crl_service.distribution_url(db, issuer_id)
        aia_url = crl_service.ca_issuers_url(db, issuer_id)
        acme_url = acme_http.directory_url(db, issuer_id)
    finally:
        db.close()
    assert crl_url is not None and aia_url is not None and acme_url is not None
    return crl_url, aia_url, acme_url


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@dataclass(frozen=True)
class Fixture:
    """The spec's own fixture: alpha (`path_length=2`, one intermediate
    carrying name constraints), beta (default `path_length`, one
    intermediate), one cross certificate for beta's root signed by alpha's
    root, a base URL so CRL/AIA URLs exist, and ACME enabled so the
    directory URL does too."""

    alpha_root: int
    alpha_int: int
    beta_root: int
    beta_int: int
    cross: int
    alpha_root_name: str
    alpha_int_name: str
    beta_root_name: str
    beta_int_name: str


def _seed(cfg: Config) -> Fixture:
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        set_setting(db, BASE_URL, "http://ca.example.org")
        set_setting(db, ACME_ENABLED, TRUE)
        alpha = ca_service.create_hierarchy(
            db,
            secrets,
            "alpha root",
            "alpha issuer",
            path_length=2,
            constraints=leaf_mod.NameConstraintSpec(permitted_dns=(PERMITTED,)),
        )
        beta = ca_service.create_hierarchy(db, secrets, "beta root", "beta issuer")
        cross = ca_service.cross_sign_root(db, secrets, beta.root.id, alpha.root.id)
        return Fixture(
            alpha_root=alpha.root.id,
            alpha_int=alpha.intermediate.id,
            beta_root=beta.root.id,
            beta_int=beta.intermediate.id,
            cross=cross.id,
            alpha_root_name=alpha.root.name,
            alpha_int_name=alpha.intermediate.name,
            beta_root_name=beta.root.name,
            beta_int_name=beta.intermediate.name,
        )
    finally:
        db.close()


def _import_foreign_cross(client: TestClient, cfg: Config, subject_root: int, name: str) -> int:
    """A cross certificate for `subject_root` signed by a root this
    instance holds no key for, brought in through the real
    `POST /ca/cross-import` door. Returns the cross row's id; the signing
    root is inserted by that import as a keyless `kind="root"` row with no
    intermediate of its own (`service.import_cross`)."""
    subject_cert = _cert_of(cfg, subject_root)
    foreign_cert, foreign_key = ca_x509.create_root(name, "ecdsa-p256", path_length=2)
    cross = ca_x509.cross_sign(subject_cert, foreign_cert, foreign_key)
    resp = client.post(
        "/ca/cross-import",
        data={
            "cross_pem": _pem(cross),
            "issuer_pem": _pem(foreign_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db, kind="cross")
        return max(row.id for row in rows)
    finally:
        db.close()


def _keyless_root_of(cfg: Config, cross_id: int) -> int:
    db = _db(cfg)
    try:
        row = ca_service.get_ca(db, cross_id)
        assert row.parent_id is not None
        signer = ca_service.get_ca(db, row.parent_id)
        assert signer.key_sealed is None
        return signer.id
    finally:
        db.close()


def _set_cross_validity(
    cfg: Config, cross_id: int, *, not_before: datetime, not_after: datetime
) -> None:
    """Rewrite the cross certificate with a genuinely different validity
    window, signed for real by its own signing root -- not a mocked clock.
    Duplicated from `test_cross_chains.py`, which builds AC-16's expired
    cross the same way."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        cross = ca_service.get_ca(db, cross_id)
        assert cross.parent_id is not None
        assert cross.cross_of_id is not None
        signer = ca_service.get_ca(db, cross.parent_id)
        subject = ca_service.get_ca(db, cross.cross_of_id)
        signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
        signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
        subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
        ski = subject_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        basic_constraints = subject_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = subject_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        rebuilt = (
            x509.CertificateBuilder()
            .subject_name(subject_cert.subject)
            .issuer_name(signer_cert.subject)
            .public_key(subject_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(basic_constraints, critical=True)
            .add_extension(key_usage, critical=True)
            .add_extension(ski, critical=False)
            .add_extension(
                ca_x509.authority_key_identifier(signer_cert, signer_key), critical=False
            )
            .sign(signer_key, algorithm=ca_x509.signing_algorithm(signer_key))
        )
        cross.cert_pem = _pem(rebuilt)
        db.commit()
    finally:
        db.close()


# --- HTML scoping helpers: parsed structure, never a fixed-character
# window and never a bare "x in html" over the whole page. ------------------

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


def _row(html: str, marker: str, *, class_name: str | None = None, tag: str | None = "div") -> str:
    """The full outer HTML of the innermost element matching `tag` and
    `class_name` that contains `marker`'s first occurrence -- scoped by
    parsing the actual tag nesting. `tag=None` matches any tag name;
    `class_name=None` matches any class, which is what lets a `<tr>` be
    scoped by a marker inside it (table rows carry no class of their own).
    """
    if marker not in html:
        raise AssertionError(f"marker {marker!r} is not on the page at all")
    marker_idx = html.index(marker)
    stack: list[tuple[str, str, int]] = []  # (tag name, attrs text, start offset)
    for m in _TAG_RE.finditer(html):
        closing, name, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if name in _VOID_TAGS or attrs.rstrip().endswith("/"):
            continue  # void or self-closing: no nesting depth to track
        if not closing:
            stack.append((name, attrs, m.start()))
            continue
        if not stack or stack[-1][0] != name:
            continue  # not well-formed at this point; nothing to close
        open_name, open_attrs, open_start = stack.pop()
        if open_start <= marker_idx < m.end():
            classes = _CLASS_RE.search(open_attrs)
            matches_tag = tag is None or open_name == tag
            matches_class = class_name is None or (
                classes is not None and class_name in classes.group(1).split()
            )
            if matches_tag and matches_class:
                return html[open_start : m.end()]
    raise AssertionError(f"no <{tag or '*'} class={class_name!r}> element wraps {marker!r}")


def _count_tag(html: str, tag: str) -> int:
    return len(re.findall(rf"<{tag}\b", html, re.IGNORECASE))


_DANGER_BUTTON_RE = re.compile(r'<button\b[^>]*\bclass="?danger"?(?=[\s>])')


def _count_danger_buttons(html: str) -> int:
    return len(_DANGER_BUTTON_RE.findall(html))


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


class _FormBlock(HTMLParser):
    """The state of the `<form>` whose `action` equals `action`: its input
    values by name."""

    def __init__(self, action: str) -> None:
        super().__init__()
        self._action = action
        self.found_form = False
        self.input_values: dict[str, str | None] = {}
        self._in_form_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "form" and attrs_dict.get("action") == self._action:
            self.found_form = True
            self._in_form_depth = 1
            return
        if self._in_form_depth > 0:
            if tag == "form":
                self._in_form_depth += 1
            elif tag == "input":
                name = attrs_dict.get("name")
                if name is not None:
                    self.input_values[name] = attrs_dict.get("value")

    def handle_endtag(self, tag: str) -> None:
        if self._in_form_depth > 0 and tag == "form":
            self._in_form_depth -= 1


def _form_block(html: str, action: str) -> _FormBlock:
    parser = _FormBlock(action)
    parser.feed(html)
    return parser


class _ElementById(HTMLParser):
    """The first element carrying `id=target_id`: whether it exists, the
    `href`s of any `<a>` nested inside it, and its own text."""

    def __init__(self, target_id: str) -> None:
        super().__init__()
        self._target_id = target_id
        self.found = False
        self.anchor_hrefs: list[str] = []
        self.text = ""
        self._tag: str | None = None
        self._depth = 0
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if not self._inside and attrs_dict.get("id") == self._target_id:
            self.found = True
            self._inside = True
            self._tag = tag
            self._depth = 1
            return
        if self._inside:
            if tag == self._tag:
                self._depth += 1
            if tag == "a":
                href = attrs_dict.get("href")
                if href is not None:
                    self.anchor_hrefs.append(href)

    def handle_data(self, data: str) -> None:
        if self._inside:
            self.text += data

    def handle_endtag(self, tag: str) -> None:
        if self._inside and tag == self._tag:
            self._depth -= 1
            if self._depth == 0:
                self._inside = False


def _element(html: str, target_id: str) -> _ElementById:
    parser = _ElementById(target_id)
    parser.feed(html)
    return parser


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = ""

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, self._text.strip()))
            self._href = None


def _anchors(html: str) -> list[tuple[str, str]]:
    parser = _Anchors()
    parser.feed(html)
    return parser.anchors


def _hrefs(html: str) -> list[str]:
    return [href for href, _text in _anchors(html)]


class _Headings(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.headings: list[str] = []
        self._level: str | None = None
        self._text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"h1", "h2", "h3"}:
            self._level = tag
            self._text = ""

    def handle_data(self, data: str) -> None:
        if self._level is not None:
            self._text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == self._level:
            self.headings.append(unescape(self._text).strip())
            self._level = None


def _headings(html: str) -> list[str]:
    parser = _Headings()
    parser.feed(html)
    return parser.headings


def _tbody_rows(section_html: str) -> list[str]:
    """Every `<tr>` inside the section's `<tbody>`, as outer HTML."""
    body = re.search(r"<tbody\b[^>]*>(.*?)</tbody>", section_html, re.S)
    assert body is not None, "the section carries no <tbody> -- no table was rendered"
    return re.findall(r"<tr\b[^>]*>.*?</tr>", body.group(1), re.S)


def _cells(row_html: str) -> list[str]:
    return re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, re.S)


def _column_index(section_html: str, header: str) -> int:
    """The position of the `<th>` whose text is `header`, so a cell is
    addressed by the column it is actually under -- a dropped column fails
    here by name rather than shifting every later assertion silently."""
    headers = _column_headers(section_html)
    assert header in headers, f"no {header!r} column: {headers}"
    return headers.index(header)


def _text_of(fragment: str) -> str:
    return unescape(re.sub(r"<[^>]+>", " ", fragment)).strip()


# --- spec 0028 helpers -----------------------------------------------------


def _column_headers(section_html: str) -> list[str]:
    """The `<th>` texts of the section's table head, in document order."""
    head = re.search(r"<thead\b[^>]*>(.*?)</thead>", section_html, re.S)
    assert head is not None, "the section's table has no <thead>"
    return [
        unescape(re.sub(r"<[^>]+>", "", cell)).strip()
        for cell in re.findall(r"<th\b[^>]*>(.*?)</th>", head.group(1), re.S)
    ]


def _table(html: str, class_name: str) -> str:
    """The first `<table>` whose class list carries `class_name`, outer HTML.

    A table cannot nest inside a table on any of these pages, so the
    non-greedy match to the first `</table>` is exact rather than lucky.
    """
    found = re.search(
        rf'<table\b[^>]*class="[^"]*\b{class_name}\b[^"]*"[^>]*>.*?</table>', html, re.S
    )
    assert found is not None, f'no <table class="...{class_name}..."> on the page'
    return found.group(0)


def _tables_with_class(html: str, class_name: str) -> list[str]:
    return re.findall(
        rf'<table\b[^>]*class="[^"]*\b{class_name}\b[^"]*"[^>]*>.*?</table>', html, re.S
    )


def _fact_rows(table_html: str) -> list[tuple[str, str]]:
    """A definition grid as `(label, value markup)` pairs, one per `<tr>`."""
    pairs = []
    for row in re.findall(r"<tr\b[^>]*>(.*?)</tr>", table_html, re.S):
        label = re.search(r"<th\b[^>]*>(.*?)</th>", row, re.S)
        value = re.search(r"<td\b[^>]*>(.*?)</td>", row, re.S)
        if label is not None and value is not None:
            pairs.append((_text_of(label.group(1)), value.group(1)))
    return pairs


def _classes_of(fragment: str, tag: str) -> list[str]:
    """The class tokens on the first `<tag>` in `fragment`."""
    found = re.search(rf'<{tag}\b[^>]*class="([^"]*)"', fragment)
    return found.group(1).split() if found is not None else []


def _split_tracks(value: str) -> list[str]:
    """One `grid-template-columns` value as its tracks.

    Paren-aware, because `minmax(0, 2fr)` carries a comma and a space inside
    itself; splitting on whitespace alone would report six tracks where the
    design has three.
    """
    tracks: list[str] = []
    depth = 0
    current = ""
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char.isspace() and depth == 0:
            if current:
                tracks.append(current)
            current = ""
            continue
        current += char
    if current:
        tracks.append(current)
    return tracks


def _column_templates(css_text: str) -> dict[str, list[str]]:
    """Every `.cols-*` class's declared tracks, read off the stylesheet.

    FR-9 makes the `minmax(0, …)` form load-bearing rather than decorative,
    so it is read from the file as well as from the computed style: the two
    say different things, and only the file says which form was written.
    """
    templates: dict[str, list[str]] = {}
    for selector, body in css_rules(css_text):
        names = re.findall(r"\.(cols-[\w-]+)", selector)
        if not names:
            continue
        for name, value in declarations(body):
            if name == "grid-template-columns":
                for cols_class in names:
                    templates[cols_class] = _split_tracks(value)
    return templates


def _chrome(
    tmp_path: Path,
    name: str,
    pages: dict[str, str],
    probe: str,
    *,
    width: int = 1440,
    height: int = 1150,
    scheme: str = "dark",
) -> dict[str, object]:
    """Every page in `pages` under `probe`, in headless Chrome, at one size.

    Delegates to `tests/probes.py` for the staging, the server and the
    result-reading (spec 0027 FR-2): this file already carries one
    pre-0027 copy of that plumbing in `_run_probe`, and a second one written
    for this spec would be the third.
    """
    root = tmp_path / f"p28-{name}-{scheme}-{width}"
    root.mkdir(parents=True, exist_ok=True)
    probes.stage(root, STATIC_DIR, pages, probe, scheme)
    httpd, port = probes.serve(root)
    try:
        return {
            page: probes.run(f"http://127.0.0.1:{port}/{page}.html", width, height)
            for page in pages
        }
    finally:
        httpd.shutdown()


#: AC-1 clause 2: whether each table fits the `.scroller` box it is in, and
#: which cells are forbidden from wrapping.
#:
#: The page-level overflow probe cannot answer either question: it excuses
#: everything inside a `.scroller`, which is right -- a scroller exists so a
#: wide table scrolls instead of breaking the page (spec 0015 FR-4) -- and
#: which is exactly why it reports a clean page for a table that does not
#: fit. `scrollWidth > clientWidth` on the scroller is the table failing to
#: fit; `white-space: nowrap` on a body cell is the usual reason (FR-9).
_FIT_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var out = [];
    document.querySelectorAll('.scroller').forEach(function (box, i) {
      var table = box.querySelector('table');
      var heads = [], nowrap = [];
      box.querySelectorAll('thead th').forEach(function (th) {
        heads.push(th.textContent.trim());
      });
      box.querySelectorAll('tbody td').forEach(function (td) {
        var ws = getComputedStyle(td).whiteSpace;
        if (ws === 'nowrap' || ws === 'pre') {
          nowrap.push(td.tagName.toLowerCase() + '.' + (td.className || '')
            + ' "' + td.textContent.trim().slice(0, 30) + '" is ' + ws);
        }
      });
      var widest = null, worst = 0;
      box.querySelectorAll('td, th').forEach(function (cell) {
        var over = cell.scrollWidth - Math.round(cell.getBoundingClientRect().width);
        if (over > worst) {
          worst = over;
          widest = cell.tagName.toLowerCase() + '.' + (cell.className || '')
            + ' "' + cell.textContent.trim().slice(0, 30) + '" needs ' + cell.scrollWidth
            + 'px in ' + Math.round(cell.getBoundingClientRect().width) + 'px';
        }
      });
      out.push({
        i: i, headers: heads, nowrapCells: nowrap,
        classes: table ? (table.className || '').toString() : '',
        clientWidth: box.clientWidth, scrollWidth: box.scrollWidth,
        over: box.scrollWidth - box.clientWidth, worstCell: widest
      });
    });
    var div = document.createElement('div');
    div.id = 'probe-result';
    div.textContent = JSON.stringify(out);
    document.body.appendChild(div);
  }, 300);
});
</script>
"""

#: AC-2: the stretched link's overlay against the row it is supposed to
#: cover. `getComputedStyle(el, '::after')` resolves `width`/`height` to used
#: pixel values in Chrome, so the overlay is measured rather than inferred
#: from the rule that draws it.
_STRETCH_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var out = [];
    document.querySelectorAll('table.rows tbody tr').forEach(function (tr, i) {
      var link = tr.querySelector('a.rowlink');
      var box = tr.getBoundingClientRect();
      if (!link) {
        out.push({i: i, rowlink: false, cells: tr.children.length});
        return;
      }
      var after = getComputedStyle(link, '::after');
      out.push({
        i: i, rowlink: true,
        trPosition: getComputedStyle(tr).position,
        afterContent: after.content,
        afterPosition: after.position,
        afterWidth: parseFloat(after.width),
        afterHeight: parseFloat(after.height),
        rowWidth: box.width,
        rowHeight: box.height,
        links: tr.querySelectorAll('a').length
      });
    });
    var div = document.createElement('div');
    div.id = 'probe-result';
    div.textContent = JSON.stringify(out);
    document.body.appendChild(div);
  }, 300);
});
</script>
"""

#: AC-3: focus the second row's link and read what changed. The anchor's own
#: ring is read from the same properties spec 0027's `FOCUS_PROBE` reads, so
#: "the row is marked" and "the anchor still has its ring" are one
#: measurement and cannot be satisfied one at a time.
_FOCUS_ROW_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var rows = document.querySelectorAll('table.rows tbody tr');
    var out = {rows: rows.length, focusable: 0, groupClass: null};
    var groups = {};
    for (var i = 0; i < rows.length; i++) {
      if (!rows[i].querySelector('a.rowlink')) continue;
      out.focusable++;
      var key = (rows[i].className || '').toString();
      if (!groups[key]) groups[key] = [];
      groups[key].push(rows[i]);
    }
    var target = null, other = null;
    Object.keys(groups).forEach(function (key) {
      if (other === null && groups[key].length >= 2) {
        out.groupClass = key;
        target = groups[key][0];
        other = groups[key][1];
      }
    });
    if (other === null) {
      var early = document.createElement('div');
      early.id = 'probe-result';
      early.textContent = JSON.stringify(out);
      document.body.appendChild(early);
      return;
    }
    var link = other.querySelector('a.rowlink');
    out.beforeFocus = getComputedStyle(other).backgroundColor;
    link.focus();
    out.focused = document.activeElement === link;
    var cs = getComputedStyle(link);
    out.outlineStyle = cs.outlineStyle;
    out.outlineWidth = parseFloat(cs.outlineWidth);
    out.outlineColor = cs.outlineColor;
    out.afterFocus = getComputedStyle(other).backgroundColor;
    out.siblingBackground = getComputedStyle(target).backgroundColor;
    out.boxShadow = getComputedStyle(other).boxShadow;
    var div = document.createElement('div');
    div.id = 'probe-result';
    div.textContent = JSON.stringify(out);
    document.body.appendChild(div);
  }, 300);
});
</script>
"""

#: AC-9/AC-7: what the browser resolved each row's column template to, and
#: what the table it belongs to is called.
_TRACKS_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var out = [];
    document.querySelectorAll('table').forEach(function (table) {
      var tr = table.querySelector('tbody tr');
      if (!tr) return;
      var style = getComputedStyle(tr);
      out.push({
        classes: (table.className || '').toString(),
        display: style.display,
        tracks: style.gridTemplateColumns,
        cells: tr.children.length,
        cellPaddingTop: getComputedStyle(tr.children[0]).paddingTop,
        cellPaddingLeft: getComputedStyle(tr.children[0]).paddingLeft,
        rowPaddingTop: style.paddingTop,
        rowPaddingLeft: style.paddingLeft
      });
    });
    var div = document.createElement('div');
    div.id = 'probe-result';
    div.textContent = JSON.stringify(out);
    document.body.appendChild(div);
  }, 300);
});
</script>
"""

#: AC-15: every row, and everything in one, that the browser is drawing at
#: less than full opacity. The contrast probe cannot see this -- `opacity`
#: composites the subtree *after* `getComputedStyle` has reported its
#: `color`, which is exactly why FR-14 declines to ship it -- so it is
#: measured directly.
#:
#: Scoped to the list tables rather than to `body *` on purpose: spec 0027's
#: entry animation (`main > div { animation: cabinIn }`) begins at
#: `opacity: 0`, and headless Chrome reports the wrapper at its first frame
#: however long the probe waits. A page-wide reading would therefore report
#: one offender on every page forever, which is a probe nobody can keep
#: green and everybody learns to ignore.
_OPACITY_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var bad = [], seen = 0;
    document.querySelectorAll('table.rows tr, table.rows tr *').forEach(function (el) {
      seen++;
      var value = parseFloat(getComputedStyle(el).opacity);
      if (value < 1) {
        bad.push(el.tagName.toLowerCase() + '.' + (el.className || '').toString().slice(0, 24)
          + ' is drawn at opacity ' + value);
      }
    });
    var div = document.createElement('div');
    div.id = 'probe-result';
    div.textContent = JSON.stringify({bad: bad, examined: seen});
    document.body.appendChild(div);
  }, 300);
});
</script>
"""


# --- headless-Chrome plumbing, duplicated from test_ca_names_and_actions.py -


def _serve(root: Path) -> tuple[ThreadingHTTPServer, int]:
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _dump_dom(url: str, width: int, height: int) -> str:
    return subprocess.run(
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


def _probe_result(dom: str) -> list[str]:
    found = re.search(r'<div id="probe-result">(.*?)</div>', dom, re.S)
    assert found is not None, "probe did not run -- Chrome rendered nothing"
    result: list[str] = json.loads(found.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    return result


def _run_probe(
    pages: dict[str, str], probe: str, tmp_path: Path, name: str
) -> dict[str, list[str]]:
    """Run `probe` over several pages in one Chrome-serving directory, with
    the real stylesheet in place (the probes measure rendered structure, and
    an unstyled page is not the page under test)."""
    root = tmp_path / f"probe-{name}"
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(STATIC_DIR, root / "static", dirs_exist_ok=True)
    for page_name, html in pages.items():
        (root / f"{page_name}.html").write_text(html.replace("</body>", probe + "</body>"))
    httpd, port = _serve(root)
    try:
        return {
            page_name: _probe_result(
                _dump_dom(f"http://127.0.0.1:{port}/{page_name}.html", 1440, 1150)
            )
            for page_name in pages
        }
    finally:
        httpd.shutdown()


#: AC-14: every `.section` element's first child has visible text.
_SECTION_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var bad = [];
    document.querySelectorAll('.section').forEach(function (el, i) {
      var first = el.children[0];
      if (!first || !first.textContent.trim()) {
        bad.push('section ' + i + ' has no non-empty first child');
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

#: AC-13: the rendered height of the scrolling content, as one number.
#:
#: spec 0027 FR-23 re-points this from `document.body` to `#main`. With the
#: shell at `height:100vh` the body's scrollHeight is the viewport height on
#: every page, so `(h4 - h1) / 3 < 80` would compute `0 < 80` and pass while
#: measuring nothing at all. `<main>` is the element that scrolls now, so it
#: is the element whose height an intermediate can grow.
_HEIGHT_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var main = document.querySelector('#main');
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify([main ? main.scrollHeight : null]);
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


# === AC-1: the tables sit above both forms, and the anchor exists ==========


def test_tables_sit_above_both_forms(client: TestClient, cfg: Config) -> None:
    """The operator's actual complaint: the issuers were below two tall
    forms. Every block is parsed out first and their document positions are
    compared -- never `html.index("Issuers")` against `html.index("Add
    intermediate")`, which would also be satisfied by two words in one
    paragraph."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    html = client.get(f"/ca/{fix.beta_root}").text

    root_block = _row(html, f'href="/ca/{fix.beta_root}.pem"', class_name="section", tag=None)
    issuers_block = _row(html, ISSUERS_HEADING, class_name="section", tag=None)
    cross_block = _row(html, CROSS_HEADING, class_name="section", tag=None)
    add_block = _row(
        html, f'action="/ca/{fix.beta_root}/intermediate"', class_name="section", tag=None
    )
    sign_block = _row(
        html, f'action="/ca/{fix.beta_root}/cross-sign"', class_name="section", tag=None
    )

    blocks = [root_block, issuers_block, cross_block, add_block, sign_block]
    positions = [html.index(block) for block in blocks]
    assert len(set(positions)) == 5, "the five blocks are not five distinct elements"
    assert positions == sorted(positions), (
        "root, Issuers, Cross certificates, Add intermediate, Cross-sign are out of order"
    )

    # FR-1: the id sits on the `.section` itself, which is what the empty
    # state's `#add-intermediate` link scrolls to.
    assert 'id="add-intermediate"' in add_block.split(">", 1)[0]


# === AC-2: an intermediate is a row, and only a row =======================


def test_an_intermediate_is_a_row_and_only_a_row(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    crl_url, aia_url, acme_url = _published_urls(cfg, fix.alpha_int)

    html = client.get(f"/ca/{fix.alpha_root}").text

    issuers = _row(html, ISSUERS_HEADING, class_name="section", tag=None)
    rows = _tbody_rows(issuers)
    assert len(rows) == 1, f"expected one issuer row, got {len(rows)}"
    cells = _cells(rows[0])
    name_cell = cells[_column_index(issuers, "Name")]
    assert _anchors(name_cell) == [
        (f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}", fix.alpha_int_name)
    ]
    assert "active" in _text_of(cells[_column_index(issuers, "Status")])
    assert _expiry_of(cfg, fix.alpha_int) in _text_of(cells[_column_index(issuers, "Expires")])

    # ...and nothing else about that intermediate is anywhere on this page:
    # "moved" must not quietly become "duplicated".
    assert _fingerprint(cfg, fix.alpha_int) not in html
    assert _subject_of(cfg, fix.alpha_int) not in html
    assert f'href="/ca/{fix.alpha_int}.pem"' not in html
    assert f"/ca/{fix.alpha_int}/chain.pem" not in html
    assert crl_url not in html
    assert aia_url not in html
    assert acme_url not in html
    assert PERMITTED not in html
    assert f"/ca/{fix.alpha_int}/renew" not in _form_actions(html)
    assert f"/ca/{fix.alpha_int}/retire" not in _form_actions(html)


# === AC-3: the cross table tells two rows apart, and is omitted when empty =


def test_cross_table_names_the_signer_and_is_omitted_when_empty(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    db = _db(cfg)
    try:
        # A third root, wide enough to carry the extra hop, so beta's root
        # carries TWO cross certificates -- which is the only state in which
        # the name column alone can be shown to be unreadable (both rows
        # carry beta's root's own name, spec 0021 FR-1).
        gamma = ca_service.create_root(db, _secrets(cfg), "gamma root", path_length=2)
        second = ca_service.cross_sign_root(db, _secrets(cfg), fix.beta_root, gamma.id)
        gamma_name, second_id = gamma.name, second.id
    finally:
        db.close()

    html = client.get(f"/ca/{fix.beta_root}").text
    cross_section = _row(html, CROSS_HEADING, class_name="section", tag=None)
    rows = _tbody_rows(cross_section)
    assert len(rows) == 2, f"expected two cross rows, got {len(rows)}"

    name_col = _column_index(cross_section, "Name")
    signer_col = _column_index(cross_section, "Signed by")
    by_href = {}
    for row_html in rows:
        cells = _cells(row_html)
        anchors = _anchors(cells[name_col])
        assert len(anchors) == 1, f"the name cell is not the link: {cells[name_col]!r}"
        href, text = anchors[0]
        by_href[href] = (text, _text_of(cells[signer_col]))

    first = f"/ca/{fix.beta_root}/cross/{fix.cross}"
    other = f"/ca/{fix.beta_root}/cross/{second_id}"
    assert set(by_href) == {first, other}
    # both rows show the same name -- which is exactly why the signer column
    # is the one thing that tells them apart
    assert by_href[first][0] == by_href[other][0] == fix.beta_root_name
    assert by_href[first][1] == fix.alpha_root_name
    assert by_href[other][1] == gamma_name

    # alpha's root has no cross certificate of its own (it is the *signer*
    # of one, which is a different hierarchy's row), so its page carries no
    # heading at all rather than an empty table under one.
    alpha_html = client.get(f"/ca/{fix.alpha_root}").text
    assert "Cross certificates" not in _headings(alpha_html)


# === AC-4: the empty state, three variants, one test ======================


def test_empty_state_for_admin_viewer_and_keyless_root(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_viewer(client, cfg)
    db = _db(cfg)
    try:
        solo = ca_service.create_root(db, _secrets(cfg), "solo root", path_length=2)
        solo_id = solo.id
    finally:
        db.close()

    admin_html = client.get(f"/ca/{solo_id}").text
    admin_note = _element(admin_html, "ca-no-intermediates")
    assert admin_note.found is True
    # Spec 0029 FR-13 re-points this, unchanged in substance and tightened:
    # the empty state's link must now *open* the form it points at, not
    # scroll to a closed one. Exactly one href, still ending in the fragment
    # the section's id provides, and now carrying the query that opens it.
    assert len(admin_note.anchor_hrefs) == 1, admin_note.anchor_hrefs
    assert admin_note.anchor_hrefs[0].endswith("#add-intermediate"), admin_note.anchor_hrefs
    assert "add=intermediate" in admin_note.anchor_hrefs[0], (
        f"the empty state's link points at {admin_note.anchor_hrefs[0]!r}, which "
        f"scrolls to a closed panel; FR-13 gives it the query that opens one"
    )
    # ...and that anchor exists further down the same page, in both states.
    for suffix in ("", "?add=intermediate"):
        page = client.get(f"/ca/{solo_id}{suffix}")
        assert page.status_code == 200, f"{suffix} -> {page.status_code}"
        target = _element(page.text, "add-intermediate")
        assert target.found is True, f"#add-intermediate is not rendered at {suffix!r}"
        assert page.text.index('id="ca-no-intermediates"') < page.text.index(
            'id="add-intermediate"'
        ), f"the empty state sits below the section it points at, at {suffix!r}"

    _login(client, "vera", "whatever12345")
    viewer_resp = client.get(f"/ca/{solo_id}")
    assert viewer_resp.status_code == 200
    viewer_note = _element(viewer_resp.text, "ca-no-intermediates")
    assert viewer_note.found is True
    assert viewer_note.anchor_hrefs == []
    assert _form_actions(viewer_resp.text) == ["/logout"]

    _login(client, "alice", "correcthorse1")
    cross_id = _import_foreign_cross(client, cfg, solo_id, "foreign root")
    keyless_root = _keyless_root_of(cfg, cross_id)
    keyless_resp = client.get(f"/ca/{keyless_root}")
    assert keyless_resp.status_code == 200, keyless_resp.text
    keyless_note = _element(keyless_resp.text, "ca-no-intermediates")
    assert keyless_note.found is True
    assert "#add-intermediate" not in keyless_note.anchor_hrefs
    # a different sentence, asserted as inequality rather than by matching a
    # phrase: what matters is that the three variants are not one sentence
    assert keyless_note.text.strip() != admin_note.text.strip()

    resp = client.post(
        f"/ca/{solo_id}/intermediate",
        data={
            "name": "solo issuer",
            "key_type": "ecdsa-p256",
            "years": 10,
            "permitted_names": "",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    after = client.get(f"/ca/{solo_id}").text
    assert _element(after, "ca-no-intermediates").found is False
    assert len(_tbody_rows(_row(after, ISSUERS_HEADING, class_name="section", tag=None))) == 1


# === AC-5: the row's page carries everything the root page lost ===========


def test_issuer_page_carries_the_full_inventory(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    crl_url, aia_url, acme_url = _published_urls(cfg, fix.alpha_int)

    resp = client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}")
    assert resp.status_code == 200, resp.text
    html = resp.text

    assert _subject_of(cfg, fix.alpha_int) in html
    assert _fingerprint(cfg, fix.alpha_int) in html

    hrefs = _hrefs(html)
    assert f"/ca/{fix.alpha_int}.pem" in hrefs
    assert f"/ca/{fix.alpha_int}/chain.pem" in hrefs
    assert crl_url in hrefs
    assert aia_url in hrefs
    assert acme_url in hrefs
    assert f"/ca/{fix.alpha_root}" in hrefs  # the back link

    # the permitted entry inside the constraints block, not merely somewhere
    constraints = _row(html, PERMITTED, class_name="constraints", tag=None)
    assert PERMITTED in constraints

    actions = _form_actions(html)
    assert f"/ca/{fix.alpha_int}/renew" in actions
    retire = _form_block(html, f"/ca/{fix.alpha_int}/retire")
    assert retire.found_form is True
    assert "confirm" in retire.input_values


def test_cross_page_carries_its_signer_and_renew_follows_the_signing_key(
    client: TestClient, cfg: Config
) -> None:
    """`parent_has_key` on a cross page comes from `row.parent_id` -- the
    root that signed it -- not from the root whose page it hangs under. The
    two halves disagree in opposite directions, which is the only way to
    catch a mistake that is invisible in the markup: a renew button that can
    only ever 500."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    resp = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}")
    assert resp.status_code == 200, resp.text
    html = resp.text

    assert _subject_of(cfg, fix.cross) in html
    assert _fingerprint(cfg, fix.cross) in html
    assert f"/ca/{fix.cross}.pem" in _hrefs(html)
    assert fix.alpha_root_name in html  # the signing root, named
    assert "it is not revocation" in html
    # alpha's root holds its key, so renewing this cross certificate is
    # something cabin can actually do
    assert f"/ca/{fix.cross}/renew" in _form_actions(html)

    # ...and the mirror image: a cross certificate whose signing root this
    # instance holds no key for offers no renew, while still being readable.
    imported = _import_foreign_cross(client, cfg, fix.beta_root, "foreign root")
    imported_resp = client.get(f"/ca/{fix.beta_root}/cross/{imported}")
    assert imported_resp.status_code == 200, imported_resp.text
    assert _fingerprint(cfg, imported) in imported_resp.text
    assert f"/ca/{imported}/renew" not in _form_actions(imported_resp.text)


# === AC-6: every refusal of FR-7, asserted on its own =====================


def test_issuer_and_cross_pages_refuse_every_mismatched_pair(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)

    refused = {
        "unknown root id": f"/ca/999999/issuer/{fix.alpha_int}",
        "root_id names an intermediate": f"/ca/{fix.alpha_int}/issuer/{fix.alpha_int}",
        "unknown row id": f"/ca/{fix.alpha_root}/issuer/999999",
        "a root id in the issuer slot": f"/ca/{fix.alpha_root}/issuer/{fix.alpha_root}",
        "a cross id in the issuer slot": f"/ca/{fix.alpha_root}/issuer/{fix.cross}",
        "a root id in the cross slot": f"/ca/{fix.beta_root}/cross/{fix.beta_root}",
        "an intermediate id in the cross slot": f"/ca/{fix.alpha_root}/cross/{fix.alpha_int}",
        "an intermediate under another root": f"/ca/{fix.alpha_root}/issuer/{fix.beta_int}",
    }
    for reason, path in refused.items():
        resp = client.get(path)
        # 404, and specifically not a redirect to the correct hierarchy
        # (FR-9) and not a 403 or a 422
        assert resp.status_code == 404, f"{reason}: {path} -> {resp.status_code}"

    # ...and a build that refuses everything fails right here
    assert client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}").status_code == 200


# === AC-7: a cross row belongs to its subject root, both directions =======


def test_cross_page_belongs_to_its_subject_root_not_its_signer(
    client: TestClient, cfg: Config
) -> None:
    """FR-8: on a cross row `parent_id` is the signing root and
    `cross_of_id` is the subject root. A guard written against `parent_id`
    swaps these two halves -- and the third assertion, which compares the
    href the table actually renders against the URL that answered 200, says
    so in one line."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    under_subject = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}")
    assert under_subject.status_code == 200, under_subject.text
    assert fix.alpha_root_name in under_subject.text

    under_signer = client.get(f"/ca/{fix.alpha_root}/cross/{fix.cross}")
    assert under_signer.status_code == 404, (
        "the signing root's URL for this cross row must not be served -- no table links to it"
    )

    beta_html = client.get(f"/ca/{fix.beta_root}").text
    cross_section = _row(beta_html, CROSS_HEADING, class_name="section", tag=None)
    rows = _tbody_rows(cross_section)
    assert len(rows) == 1
    name_col = _column_index(cross_section, "Name")
    linked = _anchors(_cells(rows[0])[name_col])[0][0]
    assert linked == f"/ca/{fix.beta_root}/cross/{fix.cross}"


# === AC-8: nothing shadows anything, and a non-numeric id is a 404 ========


def test_non_numeric_ids_answer_404_not_422(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)

    # without `:int` on both parameters these answer 422 from conversion
    # instead of 404 from routing (spec 0023 FR-9, one path deeper)
    assert client.get(f"/ca/{fix.alpha_root}/issuer/not-a-number").status_code == 404
    assert client.get("/ca/not-a-number/issuer/1").status_code == 404

    assert client.get(f"/ca/{fix.alpha_root}").status_code == 200
    pem = client.get(f"/ca/{fix.alpha_root}.pem")
    assert pem.status_code == 200
    assert pem.headers["content-type"].startswith("application/x-pem-file")
    assert client.get(f"/ca/{fix.alpha_root}.cer").status_code == 200
    assert client.get(f"/ca/{fix.alpha_int}/chain.pem").status_code == 200
    assert client.get("/ca/new").status_code == 200


# === AC-9: the unticked retire is refused on the page owning the form =====


def test_unticked_retire_returns_400_on_the_page_that_owns_the_form(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    retire_action = f"/ca/{fix.alpha_int}/retire"

    unticked = client.post(retire_action, data={"csrf_token": _csrf(client, cfg)})
    assert unticked.status_code == 400
    html = unticked.text
    assert retire_action in _form_actions(html), (
        "the form the operator just failed to submit is gone"
    )
    assert f"/ca/{fix.alpha_root}" in _hrefs(html)  # the issuer page's back link
    # what tells the issuer page apart from the root page in this response:
    # the root page's own Add intermediate form is not on it
    assert f"/ca/{fix.alpha_root}/intermediate" not in _form_actions(html)
    assert _status_of(cfg, fix.alpha_int) == "active"

    ticked = client.post(retire_action, data={"confirm": "on", "csrf_token": _csrf(client, cfg)})
    assert ticked.status_code == 303
    assert _status_of(cfg, fix.alpha_int) == "retired"


# === AC-10: every redirect lands on the row that was acted on =============


def test_renew_and_retire_redirect_to_the_rows_own_page(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)

    expected = {
        f"/ca/{fix.alpha_root}/renew": f"/ca/{fix.alpha_root}",
        f"/ca/{fix.alpha_int}/renew": f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}",
    }
    for action, location in expected.items():
        resp = client.post(action, data={"years": 5, "csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 303, resp.text
        assert resp.headers["location"] == location
        # a well-formed path that no route serves fails here
        assert client.get(location).status_code == 200, location

    retire = client.post(
        f"/ca/{fix.cross}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire.status_code == 303, retire.text
    cross_page = f"/ca/{fix.beta_root}/cross/{fix.cross}"
    assert retire.headers["location"] == cross_page
    assert client.get(cross_page).status_code == 200
    assert _status_of(cfg, fix.cross) == "retired"


# === AC-11: a viewer reads both new pages and sees no control =============


def test_viewer_reads_both_new_pages_and_sees_no_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    _create_viewer(client, cfg)
    crl_url, _aia_url, _acme_url = _published_urls(cfg, fix.alpha_int)

    admin_issuer = client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}")
    assert admin_issuer.status_code == 200
    admin_actions = _form_actions(admin_issuer.text)
    assert f"/ca/{fix.alpha_int}/renew" in admin_actions
    assert f"/ca/{fix.alpha_int}/retire" in admin_actions

    _login(client, "vera", "whatever12345")

    issuer_page = client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}")
    assert issuer_page.status_code == 200
    assert _fingerprint(cfg, fix.alpha_int) in issuer_page.text
    assert crl_url in _hrefs(issuer_page.text)
    assert _form_actions(issuer_page.text) == ["/logout"]

    cross_page = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}")
    assert cross_page.status_code == 200
    assert _fingerprint(cfg, fix.cross) in cross_page.text
    assert _form_actions(cross_page.text) == ["/logout"]


# === AC-12: the root page does the work its output needs, and no more =====


def test_root_page_makes_no_per_intermediate_lookups(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured at the call rather than on the page: a `_child_view` written
    as a thinner `_row_view` that still computes the URLs and drops them at
    the template renders identical markup."""
    _setup_superadmin(client)
    fix = _seed(cfg)
    db = _db(cfg)
    try:
        ca_service.create_intermediate_under(db, _secrets(cfg), fix.beta_root, "beta issuer two")
    finally:
        db.close()

    calls: dict[str, int] = {}

    def spy(module: object, name: str) -> None:
        original = getattr(module, name)

        def wrapper(*args: object, **kwargs: object) -> object:
            calls[name] = calls.get(name, 0) + 1
            return original(*args, **kwargs)

        monkeypatch.setattr(module, name, wrapper)

    spy(crl_service, "distribution_url")
    spy(crl_service, "ca_issuers_url")
    spy(acme_http, "directory_url")
    spy(leaf_mod, "constraints_of")

    assert client.get(f"/ca/{fix.beta_root}").status_code == 200
    assert calls.get("distribution_url", 0) == 0
    assert calls.get("ca_issuers_url", 0) == 0
    assert calls.get("directory_url", 0) == 0
    assert calls.get("constraints_of", 0) == 1  # the root's own block, and nothing else

    calls.clear()
    assert client.get(f"/ca/{fix.beta_root}/issuer/{fix.beta_int}").status_code == 200
    assert calls.get("distribution_url", 0) == 1
    assert calls.get("ca_issuers_url", 0) == 1
    assert calls.get("directory_url", 0) == 1


# === AC-16: an expired cross certificate says so in both places ===========


def test_expired_cross_is_marked_in_the_table_and_explained_on_its_page(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    now = datetime.now(UTC)
    _set_cross_validity(
        cfg, fix.cross, not_before=now - timedelta(days=400), not_after=now - timedelta(days=1)
    )

    html = client.get(f"/ca/{fix.beta_root}").text
    cross_section = _row(html, CROSS_HEADING, class_name="section", tag=None)
    row_html = _row(cross_section, f'href="/ca/{fix.beta_root}/cross/{fix.cross}"', tag="tr")
    serving = _text_of(_cells(row_html)[_column_index(cross_section, "Serving")])
    assert "not served" in serving

    page = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}")
    assert page.status_code == 200
    # the full clause, which is what tells an operator no action is needed.
    # Spec 0028 FR-7 moves it out of the identity table and into the `.panel`
    # banner; the requirement is unchanged and so is what it compares, but a
    # bare `in page.text` would also pass on a build that renders the banner
    # and leaves the rows where they were, which is the one thing AC-8 exists
    # to rule out. It is scoped to the banner instead.
    banner = _row(page.text, "outside its validity window", class_name="panel", tag=None)
    assert str(_cert_of(cfg, fix.cross).not_valid_before_utc) in banner
    assert "no action needed to fall back to the short chain" in banner


# === AC-13: per-intermediate growth is bounded ============================


def test_per_intermediate_growth_stays_bounded(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-15: the requirement is a relation, not a pixel bound -- an
    intermediate must cost a table row rather than a section. The last two
    assertions are what stop a table that renders nothing from satisfying
    the growth bound perfectly."""
    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    _setup_superadmin(client)
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        set_setting(db, BASE_URL, "http://ca.example.org")
        hierarchy = ca_service.create_hierarchy(db, secrets, "growth root", "growth issuer 1")
        root_id = hierarchy.root.id
    finally:
        db.close()

    one_html = client.get(f"/ca/{root_id}").text

    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        for n in (2, 3, 4):
            ca_service.create_intermediate_under(db, secrets, root_id, f"growth issuer {n}")
    finally:
        db.close()

    four_html = client.get(f"/ca/{root_id}").text

    results = _run_probe({"one": one_html, "four": four_html}, _HEIGHT_PROBE, tmp_path, "ca_growth")
    assert results["one"][0] is not None and results["four"][0] is not None, (
        f"the height probe found no #main to measure (spec 0027 FR-23): {results}"
    )
    h1 = int(results["one"][0])
    h4 = int(results["four"][0])

    links = [href for href in _hrefs(four_html) if f"/ca/{root_id}/issuer/" in href]
    assert len(links) == 4, f"the four-intermediate table rendered {len(links)} row links"
    assert h4 > h1, "four intermediates did not make the page any taller at all"
    assert (h4 - h1) / 3 < 80, f"each further intermediate costs {(h4 - h1) / 3:.0f}px"


# === AC-14: the section and danger probes cover all three pages ===========


def test_section_and_danger_probes_cover_all_three_pages(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """After the split the root page has exactly one danger button, so a
    probe still pointed only at it would cover none of the moved ones. Each
    page carries its own "at least one danger button here" assertion, so it
    cannot pass by having nothing to check.

    spec 0027: the section probe's page list grows from the three CA pages to
    every page that carries a `.section`, because `.section`'s geometry
    changes under it -- it becomes the design's `250px minmax(0,1fr)` row
    with a `border-top`, and an empty left column is invisible in a
    screenshot and obvious to this probe. Each page asserts it actually has a
    section, so a page that stops rendering one fails rather than quietly
    contributing nothing.
    """
    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    _setup_superadmin(client)
    fix = _seed(cfg)

    danger_pages = {
        "root": client.get(f"/ca/{fix.beta_root}").text,
        "issuer": client.get(f"/ca/{fix.beta_root}/issuer/{fix.beta_int}").text,
        "cross": client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}").text,
    }
    for name, html in danger_pages.items():
        assert _count_danger_buttons(html) >= 1, f"{name} page has no danger button to check"
        assert _count_tag(html, "details") == 0, f"{name} page reintroduced <details>"
        assert _count_tag(html, "summary") == 0, f"{name} page reintroduced <summary>"

    issued = client.post(
        "/certs/issue",
        data={
            "subject_cn": f"leaf.{PERMITTED}",
            "issuer_id": fix.alpha_int,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert issued.status_code == 303, issued.text

    section_paths = {
        "dashboard": "/",
        "ca_new": "/ca/new",
        "ca_detail": f"/ca/{fix.beta_root}",
        "ca_issuer": f"/ca/{fix.beta_root}/issuer/{fix.beta_int}",
        "ca_cross": f"/ca/{fix.beta_root}/cross/{fix.cross}",
        "cert_detail": issued.headers["location"],
        "certs_new": "/certs/new",
        "certs_sign": "/certs/sign",
        "transfer_ca_import": "/transfer/ca-import",
        "transfer_cross_import": "/transfer/cross-import",
        "transfer_ca_key": "/transfer/ca-key",
        "acme": "/acme/admin",
        "tokens": "/tokens",
        "users": "/users",
        "settings": "/settings",
    }
    section_pages = {}
    for name, path in section_paths.items():
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert 'class="section' in resp.text, f"{name} carries no .section to probe"
        section_pages[name] = resp.text

    sections = _run_probe(section_pages, _SECTION_PROBE, tmp_path, "ca_sections")
    assert sections == {name: [] for name in section_pages}, sections

    danger = _run_probe(danger_pages, probes.DANGER_PROBE, tmp_path, "ca_danger")
    assert danger == {name: [] for name in danger_pages}, danger


# === bugfix: a retired row's page offers no renew form =====================
#
# `_row_view` computes `can_renew` from `signing_key_available` alone, never
# from `row.status` -- unlike `can_retire`, which requires `status ==
# "active"`. A retired row still renders a working Renew form even though
# `renew_in_place` neither reads nor writes `status`, so the certificate it
# produces is one the row will never serve. `can_renew` must also require an
# active row.
#
# Each test below retires one row through the real POST (so the fixture
# reaches "retired" the way an operator would put it there, not by poking
# the column directly) and checks both directions: the retired row's own
# page loses the form, and a sibling row that is still active keeps it --
# otherwise a fix that removed the form unconditionally would also pass.


def test_retired_intermediate_page_offers_no_renew_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)

    retire_resp = client.post(
        f"/ca/{fix.alpha_int}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire_resp.status_code == 303, retire_resp.text
    assert _status_of(cfg, fix.alpha_int) == "retired"

    retired_html = client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}").text
    assert f"/ca/{fix.alpha_int}/renew" not in _form_actions(retired_html), (
        "a retired intermediate still offers a renew form"
    )

    # beta's intermediate was never touched -- an active row keeps the form
    active_html = client.get(f"/ca/{fix.beta_root}/issuer/{fix.beta_int}").text
    assert f"/ca/{fix.beta_int}/renew" in _form_actions(active_html)


def test_retired_root_page_offers_no_renew_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)

    # alpha's root cascades to alpha's intermediate on retire
    # (`retire_targets`), but beta's hierarchy stays active, so this is not
    # refused as "no active issuer would remain" (`ca/service.py:854`).
    retire_resp = client.post(
        f"/ca/{fix.alpha_root}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire_resp.status_code == 303, retire_resp.text
    assert _status_of(cfg, fix.alpha_root) == "retired"

    retired_html = client.get(f"/ca/{fix.alpha_root}").text
    assert f"/ca/{fix.alpha_root}/renew" not in _form_actions(retired_html), (
        "a retired root still offers a renew form"
    )

    active_html = client.get(f"/ca/{fix.beta_root}").text
    assert f"/ca/{fix.beta_root}/renew" in _form_actions(active_html)


def test_retired_cross_page_offers_no_renew_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    fix = _seed(cfg)
    db = _db(cfg)
    try:
        # a second cross certificate for beta's root, signed by a different
        # root with a stored key, so the active-row counter-check has a
        # cross row of its own rather than leaning on `fix.cross`.
        gamma = ca_service.create_root(db, _secrets(cfg), "gamma root", path_length=2)
        second_cross_id = ca_service.cross_sign_root(db, _secrets(cfg), fix.beta_root, gamma.id).id
    finally:
        db.close()

    retire_resp = client.post(
        f"/ca/{fix.cross}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire_resp.status_code == 303, retire_resp.text
    assert _status_of(cfg, fix.cross) == "retired"

    retired_html = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}").text
    assert f"/ca/{fix.cross}/renew" not in _form_actions(retired_html), (
        "a retired cross certificate still offers a renew form"
    )

    active_html = client.get(f"/ca/{fix.beta_root}/cross/{second_cross_id}").text
    assert f"/ca/{second_cross_id}/renew" in _form_actions(active_html)


def test_post_renew_on_a_retired_row_is_refused_server_side(
    client: TestClient, cfg: Config
) -> None:
    """Hiding the form is not the whole fix: `renew_in_place` neither reads
    nor writes `status`, so the route that answers `POST /ca/{id}/renew`
    would still carry out a renewal an operator can no longer reach a form
    for -- the exact shape of defect a hidden-but-still-live control is
    (`_refuse_retire_of_tls_issuer` exists for the same reason on the retire
    side). Asserted on effect, not on a status code alone: the stored
    certificate must be byte-for-byte the one from before the POST, and the
    row must still read "retired" afterward.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)

    retire_resp = client.post(
        f"/ca/{fix.alpha_int}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire_resp.status_code == 303, retire_resp.text
    fingerprint_before = _fingerprint(cfg, fix.alpha_int)

    renew_resp = client.post(
        f"/ca/{fix.alpha_int}/renew", data={"years": 5, "csrf_token": _csrf(client, cfg)}
    )
    assert renew_resp.status_code == 400, renew_resp.text
    assert _status_of(cfg, fix.alpha_int) == "retired"
    assert _fingerprint(cfg, fix.alpha_int) == fingerprint_before, (
        "the certificate was reissued even though the row is retired"
    )


# ==========================================================================
# spec 0028: the detail and list pages take the design's arrangement
# ==========================================================================


def _issue_leaf(client: TestClient, cfg: Config, fix: Fixture) -> tuple[str, list[str]]:
    """One certificate under alpha's constrained issuer, and **the SAN values
    its page renders**.

    Not the names as posted. `certificates.sans_json` stores a SAN in its
    prefixed form -- `ca/certs.py`'s `sans` property is documented as "the
    stored SAN strings (`DNS:nas.lan`, ...)" -- and both `cert_detail.html`'s
    old comma-joined cell and FR-6's new one-element-per-name cell render
    exactly those values, unchanged. A fixture that handed back the posted
    names would have the test compare the page against a string that was
    never on it; that is what the first draft of this helper did, and it
    failed AC-7 and AC-16 in two different-looking ways for one reason.

    The values are read back from the model rather than rebuilt by gluing a
    `DNS:` prefix on, because FR-6's requirement is "the values are the same
    values", not "the values are prefixed" -- if the model's own form ever
    changes, this follows it and the criterion still means what it says. The
    correspondence with what was actually asked for is asserted here instead,
    so the fixture cannot drift into proving nothing.

    Every name is under `PERMITTED`, because alpha's intermediate carries a
    name constraint and an issuance outside it is refused at the door.
    """
    requested = [
        f"leaf.{PERMITTED}",
        f"alt-one.{PERMITTED}",
        f"alt-two.{PERMITTED}",
    ]
    issued = client.post(
        "/certs/issue",
        data={
            "subject_cn": requested[0],
            "sans": "\n".join(requested),
            "issuer_id": fix.alpha_int,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert issued.status_code == 303, issued.text
    location = issued.headers["location"]

    db = _db(cfg)
    try:
        row = ca_certs.get_certificate(db, int(location.rsplit("/", 1)[1]))
        assert row is not None, f"no certificate row behind {location}"
        stored = row.sans
    finally:
        db.close()

    assert [value.split(":", 1)[-1] for value in stored] == requested, (
        f"the stored SANs are not the names that were asked for: {stored}"
    )
    return location, stored


# === AC-1: the Kind column exists and costs no width ======================


def test_issuers_table_has_a_kind_column_and_still_fits_at_390(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-2 and FR-9, measured by two instruments that can each fail.

    Spec 0026 FR-2 refused a fourth column because it "would cost a fourth
    column at 390 pixels". What overturns that is not the grid -- a track
    that shrinks under an unbreakable word does not make the word narrower
    -- but FR-9: the widest unbreakable word on this table was a timestamp
    cabin itself made unbreakable with `class="nowrap"`, and it comes off.

    **Clause 1, the page.** The overflow probe at 390. It owns exactly one
    question -- does anything get drawn outside the page -- and it answers
    it well. It cannot answer anything about the table, because it excuses
    everything inside a `.scroller`, which is what a scroller is for. It
    reports a clean page for the three-column table shipping today, for a
    four-column plain `<table>`, and for a four-column grid whose timestamp
    still cannot wrap. All three were measured.

    **Clause 2, each table.** Every `.rows` table's own `.scroller`:
    `scrollWidth <= clientWidth`, i.e. the table fits without scrolling, and
    no body cell computes `white-space: nowrap`. Measured at 390 on the
    long-name fixture, this is what the builds come out at (issuers / cross):
    today `0 / 76`, grid with `nowrap` kept `74 / 89`, grid with wrapping
    `0 / 0`. The cross table's 76 is a defect spec 0026 shipped and nothing
    caught, because the only instrument pointed at it was clause 1.

    The two clauses are counter-checked against each other below, on a table
    that is made to overflow on purpose: clause 2 must report it and clause 1
    must not. That is the difference between them, stated as an experiment
    rather than as a paragraph.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    html = client.get(f"/ca/{fix.alpha_root}").text

    issuers = _row(html, ISSUERS_HEADING, class_name="section", tag=None)
    assert _column_headers(issuers) == ["Name", "Kind", "Status", "Expires"]

    rows = _tbody_rows(issuers)
    assert len(rows) == 1, f"expected one issuer row, got {len(rows)}"
    cells = _cells(rows[0])
    assert len(cells) == 4, f"the row has {len(cells)} cells, not four: {cells}"
    kind_cell = cells[_column_index(issuers, "Kind")]
    tagged = [
        _text_of(body)
        for classes, body in re.findall(r'<span class="([^"]*)"[^>]*>(.*?)</span>', kind_cell, re.S)
        if "tag" in classes.split()
    ]
    assert tagged == ["intermediate"], f"the Kind cell carries no kind tag: {kind_cell!r}"

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    # Clause 1: the page, on both pages that carry a widened table.
    pages = {"ca": client.get("/ca").text, "ca_detail": client.get(f"/ca/{fix.beta_root}").text}
    for name, found in _chrome(
        tmp_path, "kind-page", pages, probes.OVERFLOW_PROBE, width=390, height=900
    ).items():
        assert isinstance(found, dict)
        assert found["bad"] == [], f"{name} draws outside the page at 390: {found['bad']}"
        assert int(str(found["examined"])) >= 20, (
            f"{name}: the overflow probe examined {found['examined']} elements: {found}"
        )

    # Clause 2: each table, in its own box. All three `.rows` tables -- the
    # four-column Issuers, the five-column Cross certificates and `/ca`'s
    # five-column grouped list.
    def rows_tables(staged: dict[str, str], name: str) -> dict[str, dict[str, object]]:
        measured = _chrome(tmp_path, name, staged, _FIT_PROBE, width=390, height=900)
        found = {}
        for page, boxes in measured.items():
            assert isinstance(boxes, list)
            for box in boxes:
                classes = str(box["classes"]).split()
                if "rows" in classes:
                    cols = next((c for c in classes if c.startswith("cols-")), f"{page}-unnamed")
                    found[cols] = box
        return found

    tables = rows_tables(pages, "kind-fit")
    assert set(tables) == {"cols-hierarchies", "cols-issuers", "cols-crosses"}, (
        f"expected the three .rows tables in their own scrollers, measured {sorted(tables)}"
    )
    for cols_class, box in sorted(tables.items()):
        assert int(str(box["over"])) <= 1, (
            f".{cols_class} does not fit its scroller at 390: it needs "
            f"{box['scrollWidth']}px of the {box['clientWidth']}px it has, so the table "
            f"scrolls sideways on a phone. The page-level probe reports this as clean, "
            f"which is why it is measured here. Widest cell: {box['worstCell']}"
        )
        assert box["nowrapCells"] == [], (
            f".{cols_class} has body cells that cannot wrap, which is what made the "
            f"fourth column unaffordable (FR-9): {box['nowrapCells']}"
        )

    # The counter-check, and the demonstration that the two clauses are not
    # the same measurement: 4000px planted *inside* the scroller is exactly
    # where clause 1 stops looking.
    widened = issuers.replace(
        '<div class="scroller">', '<div class="scroller"><div style="width:4000px">x</div>', 1
    )
    assert widened != issuers, "the planted div was not inserted"
    broken = {"ca_detail": html.replace(issuers, widened, 1)}

    planted = rows_tables(broken, "kind-fit-planted")["cols-issuers"]
    assert int(str(planted["over"])) > 1, (
        f"a 4000px div inside the Issuers scroller was not reported as overflow -- "
        f"clause 2 cannot fail and measures nothing: {planted}"
    )
    blind = _chrome(
        tmp_path, "kind-page-planted", broken, probes.OVERFLOW_PROBE, width=390, height=900
    )["ca_detail"]
    assert isinstance(blind, dict)
    assert blind["bad"] == [], (
        f"the page probe reported a 4000px element inside a .scroller. That is the "
        f"one thing it is supposed to excuse (spec 0015 FR-4), and if it no longer "
        f"does, clause 1 and clause 2 are the same measurement and one of them "
        f"should go: {blind['bad']}"
    )


# === AC-2: the whole row is the target, the name cell is still the link ====


def test_the_row_is_the_click_target_and_the_name_is_still_the_link(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-3. Spec 0026 AC-2's assertion is re-run unmodified -- the row's
    first cell contains an `<a>` whose `href` is the row's page and whose
    text is the row's name -- plus the class, plus the geometry.

    The geometry is the half no markup assertion can reach: an overlay drawn
    against the page instead of against the row (`position: relative`
    missing on the `<tr>`) covers the whole table, and the last row wins
    every click while every string on the page stays exactly where it was.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    html = client.get(f"/ca/{fix.alpha_root}").text

    issuers = _row(html, ISSUERS_HEADING, class_name="section", tag=None)
    row_html = _tbody_rows(issuers)[0]
    name_cell = _cells(row_html)[_column_index(issuers, "Name")]
    assert _anchors(name_cell) == [
        (f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}", fix.alpha_int_name)
    ]
    assert "rowlink" in _classes_of(name_cell, "a"), (
        f"the name cell's link does not carry .rowlink: {name_cell!r}"
    )

    pages = {
        "ca": client.get("/ca").text,
        "alpha": html,
        "beta": client.get(f"/ca/{fix.beta_root}").text,
    }
    crowded = {}
    for page_name, page in pages.items():
        for table in _tables_with_class(page, "rows"):
            for tr in re.findall(r"<tr\b[^>]*>.*?</tr>", table, re.S):
                links = len(re.findall(r"<a\b", tr))
                if links > 1:
                    crowded.setdefault(page_name, []).append(_text_of(tr))
    assert crowded == {}, (
        f"a stretched row's overlay covers every other link in the row, so a row "
        f"may hold exactly one: {crowded}"
    )

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    measured = _chrome(tmp_path, "stretch", {"ca_detail": html}, _STRETCH_PROBE)["ca_detail"]
    assert isinstance(measured, list)
    assert measured, "no <tbody> row of a .rows table was rendered at all"
    assert [entry for entry in measured if not entry["rowlink"]] == [], (
        f"a row of a clickable table has no .rowlink in it: {measured}"
    )
    for entry in measured:
        assert entry["trPosition"] == "relative", (
            f"the <tr> is not a positioned box, so the overlay is drawn against the "
            f"page and covers the whole table: {entry}"
        )
        assert entry["afterPosition"] == "absolute", entry
        assert entry["afterWidth"] is not None and entry["afterHeight"] is not None, (
            f".rowlink has no ::after box at all -- there is no overlay: {entry}"
        )
        assert abs(entry["afterWidth"] - entry["rowWidth"]) <= 1, (
            f"the overlay is {entry['afterWidth']}px wide and the row is "
            f"{entry['rowWidth']}px: {entry}"
        )
        assert abs(entry["afterHeight"] - entry["rowHeight"]) <= 1, (
            f"the overlay is {entry['afterHeight']}px tall and the row is "
            f"{entry['rowHeight']}px: {entry}"
        )


# === AC-3: focus is visible on the row, not only on the name ==============


def test_focus_paints_on_the_row_and_on_the_link(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-3's third clause: the treatment is *additive*.

    Spec 0027 FR-15 gives every focusable element a 2px accent ring, which on
    a stretched link paints around the name text and not around the row the
    click opens. The obvious fix -- suppress the anchor's outline and draw
    one on the row -- is forbidden: no rule anywhere may set `outline: none`
    or `outline: 0`. So both are asserted in one test, and the two halves
    fail in opposite directions.

    The row is compared against **another row of the same class**: a child
    row focused and compared with a `.row-root` sibling would differ whatever
    the focus rule does, because the root row carries a fill of its own.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    del fix
    page = client.get("/ca").text

    css = CSS_PATH.read_text()
    suppressed = [
        (selector, name, value)
        for selector, body in css_rules(css)
        for name, value in declarations(body)
        if name == "outline" and value.strip() in {"none", "0"}
    ]
    assert suppressed == [], (
        f"spec 0027 FR-15 forbids a suppressed outline anywhere, and a stretched "
        f"row is exactly where one is tempting: {suppressed}"
    )

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    found = _chrome(tmp_path, "focusrow", {"ca": page}, _FOCUS_ROW_PROBE)["ca"]
    assert isinstance(found, dict)
    assert found.get("groupClass") is not None, (
        f"the grouped list has no two rows of the same class carrying a .rowlink, so "
        f"there is nothing to compare a focused row against: {found}"
    )
    assert found["focused"], f"the .rowlink could not take focus: {found}"
    assert found["outlineStyle"] != "none", (
        f"the anchor's own ring is gone; spec 0027 AC-11's probe reads exactly this "
        f"property, and FR-3 requires the row treatment to be added to it, not to "
        f"replace it: {found}"
    )
    assert float(found["outlineWidth"]) >= 2, found
    assert found["afterFocus"] != found["beforeFocus"], (
        f"focusing the row's link changed nothing about the row: it is drawn "
        f"{found['afterFocus']} either way, so an operator working from the keyboard "
        f"cannot see which row they are on: {found}"
    )
    assert found["afterFocus"] != found["siblingBackground"], (
        f"the focused row is drawn the same as an unfocused row of the same class "
        f"({found['groupClass']}): {found}"
    )


# === AC-4: renew and retire are last, and the tables are still above ======


def test_renew_and_retire_is_its_own_section_and_comes_last(
    client: TestClient, cfg: Config
) -> None:
    """FR-4 supersedes spec 0026 FR-1 clause 2. Spec 0026 AC-1's five-block
    order is the first five of these six and is unchanged, which is what
    stops "the forms moved" from becoming "the forms moved back above the
    tables" -- the defect spec 0026 exists to fix."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    html = client.get(f"/ca/{fix.beta_root}").text

    blocks = [
        _row(html, f'href="/ca/{fix.beta_root}.pem"', class_name="section", tag=None),
        _row(html, ISSUERS_HEADING, class_name="section", tag=None),
        _row(html, CROSS_HEADING, class_name="section", tag=None),
        _row(html, f'action="/ca/{fix.beta_root}/intermediate"', class_name="section", tag=None),
        _row(html, f'action="/ca/{fix.beta_root}/cross-sign"', class_name="section", tag=None),
        _row(html, f'action="/ca/{fix.beta_root}/retire"', class_name="section", tag=None),
    ]
    positions = [html.index(block) for block in blocks]
    assert len(set(positions)) == 6, (
        "the six blocks are not six distinct elements -- the retire form is still "
        "inside one of the sections above it"
    )
    assert positions == sorted(positions), (
        "root, Issuers, Cross certificates, Add intermediate, Cross-sign, "
        "Renew and retire are out of order"
    )

    root_block, retire_block = blocks[0], blocks[-1]
    assert "<form" not in root_block, (
        "the root's identity section still carries a form: FR-4 moves the renew and "
        "retire forms out of it, so that the page's one danger control is not read "
        "beside the root's subject and fingerprint"
    )
    assert _headings(retire_block) == ["Renew and retire"], _headings(retire_block)

    last_section = max(m.start() for m in re.finditer(r'<div class="section[^"]*"', html))
    assert last_section == html.index(retire_block), (
        "Renew and retire is not the last section on the page (the design's 5.8 "
        "gives it the fifth and last slot)"
    )

    # ...and it is still gated the way the forms it holds were: a viewer sees
    # no section at all rather than an empty heading.
    _create_viewer(client, cfg)
    _login(client, "vera", "whatever12345")
    viewer_html = client.get(f"/ca/{fix.beta_root}").text
    assert "Renew and retire" not in _headings(viewer_html), (
        "a viewer is shown the Renew and retire section with nothing in it"
    )
    assert _form_actions(viewer_html) == ["/logout"]


# === AC-7: the definition grid keeps every field and its box ==============


def test_the_fact_grid_keeps_every_field_and_its_scroller(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-6 restyles spec 0026 FR-6's identity table; it does not replace it.

    Every field is named separately, so a restyle that drops one fails by
    name. The `.scroller` is a deliberate divergence from the design (FR-6):
    dropping it to match the brief would mean editing
    `test_every_table_is_wrapped_in_scroller` in the same change that
    introduces four new tables.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    cert_path, sans = _issue_leaf(client, cfg, fix)

    issuer_html = client.get(f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}").text
    facts = _fact_rows(_table(issuer_html, "facts"))
    labels = Counter(label for label, _value in facts)
    assert labels == Counter(
        ["Kind", "Status", "Valid from", "Valid until", "Subject", "Fingerprint"]
    ), sorted(labels.items())
    values = dict(facts)
    assert "intermediate" in _text_of(values["Kind"])
    assert "active" in _text_of(values["Status"])
    assert _expiry_of(cfg, fix.alpha_int) in _text_of(values["Valid until"])
    assert _subject_of(cfg, fix.alpha_int) in _text_of(values["Subject"])
    assert _fingerprint(cfg, fix.alpha_int) in _text_of(values["Fingerprint"])

    box = _row(issuer_html, _fingerprint(cfg, fix.alpha_int), class_name="scroller", tag="div")
    assert "<table" in box, "the definition grid is no longer inside its .scroller (FR-6)"

    cert_html = client.get(cert_path).text
    cert_facts = _table(cert_html, "facts")
    cert_values = dict(_fact_rows(cert_facts))
    assert {"Serial", "Profile", "SANs", "Valid from", "Valid until"} <= set(cert_values)
    sans_cell = cert_values["SANs"]
    per_element = [
        _text_of(body) for _tag, body in re.findall(r"<(\w+)\b[^>]*>(.*?)</\1>", sans_cell, re.S)
    ]
    assert sorted(per_element) == sorted(sans), (
        f"the design's 5.4 renders one element per SAN; this cell renders "
        f"{per_element!r} for {sans!r}"
    )

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    for name, page in (("ca_issuer", issuer_html), ("cert_detail", cert_html)):
        measured = _chrome(tmp_path, f"facts-{name}", {name: page}, _TRACKS_PROBE)[name]
        assert isinstance(measured, list)
        grids = [entry for entry in measured if "facts" in entry["classes"].split()]
        assert len(grids) == 1, f"{name}: expected one .facts table, got {len(grids)}"
        tracks = _split_tracks(grids[0]["tracks"])
        assert len(tracks) == 2, (
            f"{name}: the definition grid's row resolves to {len(tracks)} tracks, not the "
            f"design's `auto minmax(0,1fr)`: {grids[0]}"
        )


# === AC-8: the banner carries the signer, and the grid carries neither ====


def test_the_cross_banner_carries_what_the_grid_lost(client: TestClient, cfg: Config) -> None:
    """FR-7 moves two facts; both halves are asserted here, because a build
    that renders the banner and leaves the rows in place would pass every
    other criterion in this spec."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    page = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}").text
    banner = _row(page, "in place of", class_name="panel", tag=None)
    assert fix.alpha_root_name in _text_of(banner), (
        f"the banner does not name the signing root: {_text_of(banner)!r}"
    )
    tags = [
        _text_of(body)
        for classes, body in re.findall(r'<span class="([^"]*)"[^>]*>(.*?)</span>', banner, re.S)
        if "tag" in classes.split()
    ]
    assert tags, f"the banner carries no serving tag: {banner!r}"

    labels = set(dict(_fact_rows(_table(page, "facts"))))
    assert "Signed by" not in labels and "Serving" not in labels, (
        f"the two facts were copied into the banner and left in the grid, which is "
        f"what turns 'moved' into 'duplicated': {sorted(labels)}"
    )

    now = datetime.now(UTC)
    _set_cross_validity(
        cfg, fix.cross, not_before=now - timedelta(days=400), not_after=now - timedelta(days=1)
    )
    expired = client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}").text
    expired_banner = _row(expired, "outside its validity window", class_name="panel", tag=None)
    assert str(_cert_of(cfg, fix.cross).not_valid_before_utc) in expired_banner
    assert "no action needed to fall back to the short chain" in _text_of(expired_banner), (
        "the full clause -- the half that tells an operator nothing needs doing -- is "
        "not in the banner"
    )

    detail = client.get(f"/ca/{fix.beta_root}").text
    cross_section = _row(detail, CROSS_HEADING, class_name="section", tag=None)
    row_html = _row(cross_section, f'href="/ca/{fix.beta_root}/cross/{fix.cross}"', tag="tr")
    serving = _text_of(_cells(row_html)[_column_index(cross_section, "Serving")])
    assert "not served" in serving, (
        "the short tag stayed on the hierarchy page (spec 0026 FR-3); only the full "
        "clause moved into the banner"
    )


# === AC-9: the column templates are the design's =========================


#: The brief's own ratios, per screen (sections 5.7 and 5.8).
BRIEF_TRACKS = {
    "cols-hierarchies": (2.0, 0.8, 1.0, 0.9, 1.1),
    "cols-issuers": (2.0, 1.2, 0.8, 1.1),
    "cols-crosses": (1.7, 1.3, 0.8, 0.9, 1.0),
}


def test_the_column_templates_are_the_designs(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-9's templates, read twice: off the file and off the browser.

    They say different things. The computed style says what the columns came
    out as at this width; only the file says which *form* was written.

    What this does **not** claim is that a bare `Nfr` breaks 390. An earlier
    draft of AC-9 did, and it was measured false: a bare `Nfr` fits at 390 on
    cabin's content, in both the wrapping and the non-wrapping build, and
    AC-1's probe could not have failed for that reason in any case. The
    `minmax(0, …)` form is required because it is the design's own (brief
    section 6.14) and because it bounds every track to the container for
    content this fixture does not contain. Whether a table actually fits is
    AC-1 clause 2's measurement, whatever the tracks are written as.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)

    declared = _column_templates(CSS_PATH.read_text())
    assert set(declared) == set(BRIEF_TRACKS), (
        f"the stylesheet declares column templates for {sorted(declared)}; FR-9 names "
        f"{sorted(BRIEF_TRACKS)}"
    )
    for name, tracks in sorted(declared.items()):
        expected = BRIEF_TRACKS[name]
        assert len(tracks) == len(expected), f".{name} has {len(tracks)} tracks: {tracks}"
        bare = [track for track in tracks if not re.fullmatch(r"minmax\(\s*0(px)?\s*,.*\)", track)]
        assert bare == [], (
            f".{name} has tracks that are not `minmax(0, …)`: {bare}. The form is the "
            f"design's own and it bounds every track to the container whatever the "
            f"cell holds; a bare `Nfr` is `minmax(auto, Nfr)`, whose minimum is the "
            f"content's, and it happens to fit this fixture's content only"
        )
        ratios = [float(re.search(r"([\d.]+)fr", track).group(1)) for track in tracks]  # type: ignore[union-attr]
        assert ratios == list(expected), f".{name} declares {ratios}, the brief has {expected}"

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    pages = {
        "ca": client.get("/ca").text,
        "ca_detail": client.get(f"/ca/{fix.beta_root}").text,
    }
    measured = _chrome(tmp_path, "tracks", pages, _TRACKS_PROBE)
    seen: dict[str, list[float]] = {}
    for page_name, entries in measured.items():
        assert isinstance(entries, list)
        for entry in entries:
            classes = entry["classes"].split()
            for cols_class in BRIEF_TRACKS:
                if cols_class not in classes:
                    continue
                assert entry["display"] == "grid", (
                    f"{page_name}: a .{cols_class} row is `display: {entry['display']}`, so "
                    f"the column template is not applied at all: {entry}"
                )
                widths = [float(track.rstrip("px")) for track in _split_tracks(entry["tracks"])]
                seen[cols_class] = widths
    missing = sorted(set(BRIEF_TRACKS) - set(seen))
    assert missing == [], f"no row of these tables was rendered at all: {missing}"

    for cols_class, widths in sorted(seen.items()):
        expected = BRIEF_TRACKS[cols_class]
        assert len(widths) == len(expected), (
            f".{cols_class} resolved to {len(widths)} tracks, not {len(expected)}: {widths}"
        )
        total, share = sum(widths), sum(expected)
        drift = {
            index: (round(widths[index] / total, 4), round(expected[index] / share, 4))
            for index in range(len(widths))
            if abs(widths[index] / total - expected[index] / share)
            > 0.02 * (expected[index] / share)
        }
        assert drift == {}, (
            f".{cols_class} column {sorted(drift)} is not in the brief's ratio "
            f"(measured, brief): {drift}"
        )


# === AC-10: every table is still a table, and still wrapped ===============


def test_the_tables_are_still_tables(client: TestClient, cfg: Config) -> None:
    """FR-8/AC-10. `test_every_table_is_wrapped_in_scroller` (spec 0015 FR-4)
    is satisfied vacuously by a page with no `<table>` left to wrap, so what
    it cannot see is asserted here: the elements are still the table
    elements, and the design's `<div>` stack -- the brief's own explicit "do
    not" in section 6.2 -- was not reproduced literally."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    with_tables = set()
    for name in FIVE_TEMPLATES:
        text = (TEMPLATES_DIR / name).read_text()
        for role in ('role="table"', 'role="row"', 'role="cell"', 'role="columnheader"'):
            assert role not in text, f"{name} reproduces the design's <div> stack: {role}"
        if "<table" in text:
            with_tables.add(name)
            for element in ("<tbody", "<td"):
                assert element in text, f"{name} has a <table> but no {element}"
    assert with_tables == {
        "ca_list.html",
        "ca_detail.html",
        "ca_issuer.html",
        "cert_detail.html",
    }, with_tables

    declared = _column_templates(CSS_PATH.read_text())
    pages = {
        "ca": client.get("/ca").text,
        "ca_detail": client.get(f"/ca/{fix.beta_root}").text,
    }
    checked = 0
    for page_name, page in pages.items():
        for table in _tables_with_class(page, "rows"):
            classes = _classes_of(table, "table")
            cols = [name for name in classes if name.startswith("cols-")]
            assert len(cols) == 1, f"{page_name}: a .rows table has {cols} column templates"
            assert cols[0] in declared, f"{page_name}: .{cols[0]} has no rule in cabin.css"
            headers = _column_headers(table)
            assert len(headers) == len(declared[cols[0]]), (
                f"{page_name}: .{cols[0]} declares {len(declared[cols[0]])} tracks and its "
                f"<thead> has {len(headers)} columns: {headers}"
            )
            checked += 1
    assert checked == 3, f"expected the three .rows tables, measured {checked}"


# === AC-15: nothing is dimmed with opacity ================================


def _dimming_rules(css_text: str) -> list[tuple[str, str]]:
    """Every rule of this spec's own that declares `opacity`."""
    return [
        (selector, value)
        for selector, body in css_rules(css_text)
        for name, value in declarations(body)
        if name == "opacity"
        and any(re.search(rf"\.{re.escape(known)}\b", selector) for known in DEFINED_CLASSES)
    ]


def test_no_row_is_dimmed_with_opacity(client: TestClient, cfg: Config, tmp_path: Path) -> None:
    """FR-14, and the reason it is a requirement rather than a preference.

    The design gives non-active rows `opacity: .65`. `opacity` composites the
    whole subtree *after* `getComputedStyle` has reported its `color`, so the
    contrast probe spec 0027 built would report 4.5:1 for text that renders
    at roughly 3:1 -- a property that quietly defeats the check.

    Which means the contrast run below cannot catch it, and saying so is the
    point: what catches it is the stylesheet parse (with its counter-check)
    and the rendered `opacity` reading, which looks at the property the
    contrast probe is blind to.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    css = CSS_PATH.read_text()

    defined = {
        name
        for selector, _body in css_rules(css)
        for name in re.findall(r"\.([a-zA-Z][\w-]*)", selector)
    }
    undefined = [name for name in DEFINED_CLASSES if name not in defined]
    assert undefined == [], (
        f"these classes have no rule in cabin.css, so 'none of this spec's rules "
        f"declares opacity' would be true of a stylesheet that declares nothing at "
        f"all: {undefined}"
    )
    assert _dimming_rules(css) == [], (
        f"a dimmed row passes the contrast probe while being a third less legible "
        f"than the probe believes: {_dimming_rules(css)}"
    )

    doctored = css + "\n.row-child { opacity: .65; }\n"
    assert _dimming_rules(doctored) != [], (
        "the design's own `opacity: .65`, appended to the stylesheet, was not "
        "reported -- the clause above cannot fail"
    )

    retire = client.post(
        f"/ca/{fix.beta_int}/retire", data={"confirm": "on", "csrf_token": _csrf(client, cfg)}
    )
    assert retire.status_code == 303, retire.text
    assert _status_of(cfg, fix.beta_int) == "retired"

    detail = client.get(f"/ca/{fix.beta_root}").text
    issuers = _row(detail, ISSUERS_HEADING, class_name="section", tag=None)
    retired_row = _row(
        issuers, f'href="/ca/{fix.beta_root}/issuer/{fix.beta_int}"', class_name=None, tag="tr"
    )
    status_cell = _cells(retired_row)[_column_index(issuers, "Status")]
    tagged = [
        (classes.split(), _text_of(body))
        for classes, body in re.findall(
            r'<span class="([^"]*)"[^>]*>(.*?)</span>', status_cell, re.S
        )
    ]
    assert [text for classes, text in tagged if "tag-bad" in classes] == ["retired"], (
        f"a retired row is marked the way every other retired thing in cabin is "
        f"marked -- a `tag-bad` tag reading `retired`: {status_cell!r}"
    )

    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    pages = {"ca": client.get("/ca").text, "ca_detail": detail}
    dimmed = _chrome(tmp_path, "opacity", pages, _OPACITY_PROBE)
    for name, found in dimmed.items():
        assert isinstance(found, dict)
        assert found["bad"] == [], (
            f"{name}: a row is composited at less than full opacity, which the "
            f"contrast probe reads straight through: {found['bad']}"
        )
        assert int(str(found["examined"])) >= 10, (
            f"{name}: the probe found {found['examined']} elements in the list tables, "
            f"so it is measuring nothing: {found}"
        )

    contrast = _chrome(tmp_path, "opacity-contrast", pages, probes.CONTRAST_PROBE)
    for name, found in contrast.items():
        assert isinstance(found, dict)
        assert found["bad"] == [], f"{name}: {found['bad']}"


# === AC-16: not one sentence changed ======================================


class _TextNodes(HTMLParser):
    """Every visible text node of a page, whitespace-collapsed."""

    def __init__(self) -> None:
        super().__init__()
        self.texts: list[str] = []
        self._muted = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._muted += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._muted:
            self._muted -= 1

    def handle_data(self, data: str) -> None:
        if self._muted:
            return
        text = " ".join(data.split())
        if text:
            self.texts.append(text)


def _text_nodes(html: str) -> Counter[str]:
    parser = _TextNodes()
    parser.feed(html)
    return Counter(parser.texts)


def _baseline_templates(tmp_path: Path, ref: str = BASELINE) -> Path:
    """The templates as they stood at `ref`, in a directory of their own.

    `ref` is a parameter rather than a read of `BASELINE` because spec 0029
    needs the same instrument against its own base commit
    (`test_web_form_previews.test_no_sentence_changed_on_the_form_pages`),
    and a second copy of it would be a second thing to repair.
    """
    out = tmp_path / f"templates-before-{ref}"
    out.mkdir(parents=True, exist_ok=True)
    listed = subprocess.run(
        ["git", "-C", str(REPO), "ls-tree", "-r", "--name-only", ref, str(TEMPLATES_DIR)],
        capture_output=True,
        text=True,
    )
    assert listed.returncode == 0, listed.stderr
    names = [line for line in listed.stdout.split() if line.endswith(".html")]
    assert len(names) > 10, f"{ref} has {len(names)} templates: {names}"
    for name in names:
        blob = subprocess.run(
            ["git", "-C", str(REPO), "show", f"{ref}:{name}"], capture_output=True
        )
        assert blob.returncode == 0, blob.stderr
        (out / Path(name).name).write_bytes(blob.stdout)
    return out


@contextmanager
def _rendering_from(directory: Path) -> Iterator[None]:
    """Render through another set of templates, against the same database.

    One environment, one instance, one set of rows: every difference between
    the two renderings is a difference of markup, which is the only thing
    FR-15 is about. Rendering a second instance would compare two different
    fingerprints and two different expiry dates and prove nothing.
    """
    env = cabin_web.templates.env
    original = env.loader
    env.loader = FileSystemLoader(str(directory))
    env.cache.clear()
    try:
        yield
    finally:
        env.loader = original
        env.cache.clear()


def test_no_sentence_changed_on_the_five_pages(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-15/AC-16: nothing is lost, and every addition is named.

    An equality would be the stronger claim and it is not available: FR-2
    adds a `Kind` heading and a kind cell, FR-5 a row per intermediate, FR-4
    a section heading and its help line, FR-6 splits the comma-joined SANs,
    and FR-7 takes two labels off the cross page -- four of the five are this
    spec's own requirements. So the comparison is exact in the direction that
    carries FR-15 (nothing the page said before is gone) and named in the
    other (every new string is listed, per page, from the fixture's own
    data). A heading "improved" while the markup around it is rewritten fails
    both halves at once: the old wording disappears and the new wording is in
    nobody's list.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    cert_path, sans = _issue_leaf(client, cfg, fix)

    paths = {
        "ca": "/ca",
        "ca_detail": f"/ca/{fix.beta_root}",
        "ca_issuer": f"/ca/{fix.alpha_root}/issuer/{fix.alpha_int}",
        "ca_cross": f"/ca/{fix.beta_root}/cross/{fix.cross}",
        "cert_detail": cert_path,
    }

    def render() -> dict[str, str]:
        pages = {}
        for name, path in paths.items():
            resp = client.get(path)
            assert resp.status_code == 200, f"{path} -> {resp.status_code}"
            pages[name] = resp.text
        return pages

    after = render()
    with _rendering_from(_baseline_templates(tmp_path)):
        before = render()

    assert any(before[name] != after[name] for name in paths), (
        f"the five pages render byte-identically through the templates of "
        f"{BASELINE} and through today's -- either this spec has not been "
        f"implemented, or the template loader was not actually swapped and this "
        f"test is comparing every page with itself"
    )

    glyphs = {"├", "└"}  # the tree glyphs, named rather than matched
    kind_words = {"root", "intermediate", "cross"}
    statuses = {"active", "retired"}
    row_data = {
        fix.alpha_int_name,
        fix.beta_int_name,
        _expiry_of(cfg, fix.alpha_int),
        _expiry_of(cfg, fix.beta_int),
    }
    additions = {
        # FR-5: one row per intermediate under its own root.
        "ca": glyphs | kind_words | statuses | row_data,
        # FR-2's Kind column, and FR-4's section heading and help line, which
        # are lifted verbatim from `ca_issuer.html` rather than written.
        "ca_detail": {
            "Kind",
            "intermediate",
            "Renew and retire",
            "The two things that can be done to this certificate from here.",
        },
        "ca_issuer": set(),
        "ca_cross": set(),
        # FR-6: one element per SAN instead of one comma-joined string.
        "cert_detail": set(sans),
    }
    removals = {
        "ca": set(),
        "ca_detail": set(),
        "ca_issuer": set(),
        # FR-7: the two labels the banner takes over. The sentences beside
        # them move unchanged and must not show up here.
        "ca_cross": {"Signed by", "Serving"},
        "cert_detail": {", ".join(sans)},
    }

    for name in paths:
        old, new = _text_nodes(before[name]), _text_nodes(after[name])
        assert sum(old.values()) >= 20, f"{name}: the baseline page has {sum(old.values())} texts"
        lost = old - new
        assert set(lost) <= removals[name], (
            f"{name}: text that was on this page before this spec is gone from it. "
            f"FR-15 takes no exception: {sorted(set(lost) - removals[name])}"
        )
        gained = new - old
        assert set(gained) <= additions[name], (
            f"{name}: text this spec did not name appears on the page. Every "
            f"addition is argued in an FR or it is a wording change: "
            f"{sorted(set(gained) - additions[name])}"
        )


# === AC-18: the view builders return exactly what the contract says =======


def test_child_view_and_overview_return_exactly_their_keys(client: TestClient, cfg: Config) -> None:
    """The Interface Contract enumerates every key, including the ones inside
    the dictionaries, because spec 0024's contract once said "gains one flag
    … no other key changes" and that sentence produced a defect that survived
    a green suite. Set equality, so an extra key fails as loudly as a missing
    one -- spec 0026's contract said `_child_view` returns *exactly five*."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    six = {"id", "name", "kind", "status", "not_valid_after", "href"}
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        by_id = {row.id: row for row in rows}

        child = ca_ui._child_view(by_id[fix.alpha_int])
        assert set(child) == six, sorted(child)
        assert child["kind"] == by_id[fix.alpha_int].kind == "intermediate"

        cross = ca_ui._child_view(by_id[fix.cross])
        assert set(cross) == six, sorted(cross)
        assert cross["kind"] == by_id[fix.cross].kind == "cross"

        overview = ca_ui._overview(db, rows)
        assert len(overview) == 2, overview
        for entry in overview:
            assert set(entry) == {
                "id",
                "name",
                "status",
                "not_valid_after",
                "intermediate_count",
                "cross_count",
                "issuers",
            }, sorted(entry)
            issuers = entry["issuers"]
            assert isinstance(issuers, list)
            assert len(issuers) == entry["intermediate_count"], (
                f"the count column and the child rows are two statements about the "
                f"same hierarchy and they disagree: {entry}"
            )
            for issuer in issuers:
                assert set(issuer) == six, sorted(issuer)
                assert by_id[issuer["id"]].parent_id == entry["id"], (
                    f"an issuer of another root is listed under this one: {issuer}"
                )
                assert issuer["href"] == f"/ca/{entry['id']}/issuer/{issuer['id']}"

        group = ca_ui._group(db, rows, by_id[fix.beta_root])
        assert [set(row) for row in group["intermediates"]] == [six]
        assert [set(row) for row in group["cross_certificates"]] == [six | {"signed_by", "served"}]
    finally:
        db.close()


# === spec 0029 AC-12: the disclosure is URL state, in both directions =====


class _AnchorAttrs(HTMLParser):
    """Every `<a>` in a fragment as its full attribute dictionary.

    `_anchors` above gives href and text, which is what spec 0026's
    assertions needed. Spec 0029 AC-12 has to read `hx-get`, `hx-select` and
    `hx-target` off the same element, and an anchor whose href is right and
    whose `hx-target` points somewhere else is exactly the build the
    criterion exists to catch.
    """

    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.anchors.append(dict(attrs))


def _anchor_attrs(fragment: str) -> list[dict[str, str | None]]:
    parser = _AnchorAttrs()
    parser.feed(fragment)
    return parser.anchors


def _section_with_id(html: str, element_id: str) -> str:
    """The outer HTML of the `.section` carrying `element_id`, scoped by
    parsing tag nesting rather than by a character window."""
    return _row(html, f'id="{element_id}"', class_name="section", tag=None)


def _control_names(form_html: str) -> set[str]:
    """Every named form control in a fragment -- inputs, selects and
    textareas alike, which `_form_block` above does not cover because spec
    0023 only ever needed the inputs' values."""
    names = set()
    for match in re.finditer(r"<(input|select|textarea)\b([^>]*)>", form_html, re.I):
        found = re.search(r'name="([^"]*)"', match.group(2))
        if found is not None:
            names.add(found.group(1))
    return names


def test_the_disclosure_is_url_state(client: TestClient, cfg: Config, tmp_path: Path) -> None:
    """Spec 0029 AC-12: both directions, and the error re-render.

    The three defects this is written against are named in the criterion. A
    `<button>` or a `#`-only anchor has no URL and does nothing without
    JavaScript. An id that moves with the state breaks the empty state's link
    and the swap target at once. An error re-render landing on the closed
    page is the defect spec 0023 AC-3 was written for and that spec 0024
    retired along with the `<details>` it could not open.

    "Every field it carries today" is read off the page as it renders at
    `BASELINE`, where the form is unconditionally open, rather than typed out
    here: a list of field names in a test is a second original, and this one
    would stop tracking the form the day the form gained a field.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    action = f"/ca/{fix.alpha_root}/intermediate"

    with _rendering_from(_baseline_templates(tmp_path)):
        baseline = client.get(f"/ca/{fix.alpha_root}")
        assert baseline.status_code == 200
    expected_fields = _control_names(_row(baseline.text, f'action="{action}"', tag="form"))
    assert "name" in expected_fields and "csrf_token" in expected_fields, expected_fields

    # --- closed ------------------------------------------------------------
    closed = client.get(f"/ca/{fix.alpha_root}")
    assert closed.status_code == 200
    section = _section_with_id(closed.text, "add-intermediate")
    assert "Add intermediate" in _headings(section), (
        f"the closed section lost its <h2>; FR-13 keeps the heading visible without "
        f"opening anything: {_headings(section)}"
    )
    assert _count_tag(section, "form") == 0, "the closed section still renders its form"

    anchors = _anchor_attrs(section)
    assert len(anchors) == 1, f"the closed section carries {len(anchors)} anchors: {anchors}"
    trigger = anchors[0]
    expected_href = f"/ca/{fix.alpha_root}?add=intermediate#add-intermediate"
    assert trigger.get("href") == expected_href, (
        f"the trigger's href is {trigger.get('href')!r}, not {expected_href!r} -- a "
        f"`#`-only anchor has nothing to follow without JavaScript"
    )
    assert trigger.get("hx-get") == expected_href.split("#")[0] or trigger.get("hx-get") == (
        expected_href
    ), f"the trigger's hx-get is {trigger.get('hx-get')!r}"
    assert trigger.get("hx-select") == "#add-intermediate", trigger
    assert trigger.get("hx-target") == "#add-intermediate", trigger
    assert trigger.get("hx-swap") == "outerHTML", trigger
    assert trigger.get("hx-push-url") == "true", trigger

    # --- open --------------------------------------------------------------
    opened = client.get(f"/ca/{fix.alpha_root}?add=intermediate")
    assert opened.status_code == 200
    open_section = _section_with_id(opened.text, "add-intermediate")
    assert action in _form_actions(open_section), (
        f"?add=intermediate does not open the form: {_form_actions(open_section)}"
    )
    assert (
        _control_names(_row(open_section, f'action="{action}"', tag="form")) == expected_fields
    ), "the opened form is not the form that stood here at BASELINE"
    cross_section = _row(
        opened.text, ">Cross-sign with another root<", class_name="section", tag=None
    )
    assert _count_tag(cross_section, "form") == 0, (
        "?add=intermediate opened the cross-sign form as well; the parameter names one panel"
    )

    # --- an unrecognised value is a typo, not an error ----------------------
    banana = client.get(f"/ca/{fix.alpha_root}?add=banana")
    assert banana.status_code == 200, banana.status_code
    assert _count_tag(_section_with_id(banana.text, "add-intermediate"), "form") == 0
    assert (
        _count_tag(
            _row(banana.text, ">Cross-sign with another root<", class_name="section", tag=None),
            "form",
        )
        == 0
    )

    # --- the error re-render lands on the open panel (spec 0023 AC-3) -------
    rejected = client.post(
        action,
        data={
            "name": "   ",
            "key_type": "ed25519",
            "years": 7,
            "permitted_names": "",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert rejected.status_code == 400, rejected.status_code
    error_section = _section_with_id(rejected.text, "add-intermediate")
    assert action in _form_actions(error_section), (
        "the 400 re-render came back with the panel closed, so the operator's own "
        "input is behind a link they have to find again -- the defect spec 0023 "
        "AC-3 was written for"
    )
    form_html = _row(error_section, f'action="{action}"', tag="form")
    assert 'value="7"' in form_html, f"the submitted years are gone: {form_html}"
    assert re.search(r'<option value="ed25519"[^>]*\bselected\b', form_html), (
        f"the submitted key_type is not selected again: {form_html}"
    )

    # --- and no browser-held open state, in any of the four renders --------
    for html in (closed.text, opened.text, banana.text, rejected.text):
        assert _count_tag(html, "details") == 0, "a <details> is back (0026 FR-16's first half)"
        assert _count_tag(html, "summary") == 0
