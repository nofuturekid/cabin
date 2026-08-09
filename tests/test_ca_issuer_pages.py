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
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from html import unescape
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.acme import http as acme_http
from cabin.app import create_app
from cabin.ca import crl as crl_service
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory

STATIC_DIR = Path(__file__).resolve().parents[1] / "src/cabin/web/static"
CHROME = "/opt/google/chrome/chrome"

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
    head = re.search(r"<thead\b[^>]*>(.*?)</thead>", section_html, re.S)
    assert head is not None, "the section's table has no <thead>"
    headers = [
        unescape(re.sub(r"<[^>]+>", "", cell)).strip()
        for cell in re.findall(r"<th\b[^>]*>(.*?)</th>", head.group(1), re.S)
    ]
    assert header in headers, f"no {header!r} column: {headers}"
    return headers.index(header)


def _text_of(fragment: str) -> str:
    return unescape(re.sub(r"<[^>]+>", " ", fragment)).strip()


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

#: AC-14: every button.danger has a confirm checkbox inside its own <form>.
_DANGER_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var bad = [];
    document.querySelectorAll('button.danger').forEach(function (btn, i) {
      var form = btn.closest('form');
      var ok = form && form.querySelector('input[name="confirm"]');
      if (!ok) bad.push('danger button ' + i + ' has no confirm checkbox in its form');
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify(bad);
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: AC-13: the rendered height of the whole document, as one number.
_HEIGHT_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify([document.body.scrollHeight]);
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
    assert "#add-intermediate" in admin_note.anchor_hrefs
    # ...and that anchor exists further down the same page
    target = _element(admin_html, "add-intermediate")
    assert target.found is True
    assert admin_html.index('id="ca-no-intermediates"') < admin_html.index('id="add-intermediate"')

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
    # the full clause, which is what tells an operator no action is needed
    assert "outside its validity window" in page.text
    assert str(_cert_of(cfg, fix.cross).not_valid_before_utc) in page.text
    assert "no action needed to fall back to the short chain" in page.text


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
    cannot pass by having nothing to check."""
    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    _setup_superadmin(client)
    fix = _seed(cfg)

    pages = {
        "root": client.get(f"/ca/{fix.beta_root}").text,
        "issuer": client.get(f"/ca/{fix.beta_root}/issuer/{fix.beta_int}").text,
        "cross": client.get(f"/ca/{fix.beta_root}/cross/{fix.cross}").text,
    }
    for name, html in pages.items():
        assert _count_danger_buttons(html) >= 1, f"{name} page has no danger button to check"
        assert _count_tag(html, "details") == 0, f"{name} page reintroduced <details>"
        assert _count_tag(html, "summary") == 0, f"{name} page reintroduced <summary>"

    sections = _run_probe(pages, _SECTION_PROBE, tmp_path, "ca_sections")
    assert sections == {name: [] for name in pages}, sections

    danger = _run_probe(pages, _DANGER_PROBE, tmp_path, "ca_danger")
    assert danger == {name: [] for name in pages}, danger
