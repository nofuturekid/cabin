"""Web-layer tests for spec 0024 (CA names, separate creation, action
layout): a name is stored and signed exactly as typed (FR-1/FR-2), a
64-**byte** limit rather than a 64-character one (FR-2), `POST /ca/create`
writes a root and nothing else (FR-3), the grant and cabin's own TLS hook
move to the intermediate route (FR-5), "no CA" and "a CA with no issuer"
stop being the same sentence at every site that says it (FR-7), every
action on the detail page is a headed `.section` with no `<details>`
(FR-8), and retire gets a confirmation checkbox enforced server-side (FR-9).

This branch is red by design: `ca/service.py` still interpolates
`f"{name} Root CA"`/`f"{name} Intermediate CA"`, `POST /ca/create` still
writes two rows, there is no `_name_error`, the grant and TLS hook still
sit on `/ca/create`, the four "no CA" sites still share one sentence, and
`ca_detail.html` still uses `<details>` with an unconfirmed retire button.

Scoping follows `test_web_ca_pages.py`'s `_row(...)`/`_form_block(...)`:
the actual element that wraps a marker, found by parsing tag nesting,
never a fixed-character window and never a bare substring search over the
whole page. Every helper below is duplicated rather than imported, as this
project's other web test files already do (there is no conftest.py and
each file owns its own client/session/csrf/HTML-scoping plumbing).
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
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin import audit
from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.audit import AuditAction
from cabin.ca import service as ca_service
from cabin.ca.service import CACertificate, CANotConfiguredError, resolve_issuer
from cabin.config import Config
from cabin.issuer_grants import Principal, PrincipalKind, UserIssuer, resolve_granted_issuer
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import TLS_ISSUER_ID, get_setting
from cabin.store import create_session_factory, run_migrations
from cabin.tls import TlsManager, cert_path
from cabin.users import Role, User

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
STATIC_DIR = Path(__file__).resolve().parents[1] / "src/cabin/web/static"
CSS_PATH = STATIC_DIR / "cabin.css"
CHROME = "/opt/google/chrome/chrome"


# --- fixtures and low-level plumbing, duplicated from test_web_ca_pages.py ---


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


def make_tls_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)


@pytest.fixture
def tls_cfg(tmp_path: Path) -> Config:
    return make_tls_config(tmp_path)


@pytest.fixture
def tls_client(tls_cfg: Config) -> Iterator[TestClient]:
    manager = TlsManager(tls_cfg.data_dir)
    with TestClient(create_app(tls_cfg, manager), follow_redirects=False) as c:
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


def _create_admin(client: TestClient, cfg: Config, username: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": "admin",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str) -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _row_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return len(ca_service.list_cas(db))
    finally:
        db.close()


def _status_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).status
    finally:
        db.close()


def _last_root_id(cfg: Config) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "root")
            .order_by(CACertificate.id.desc())
        ).first()
        assert row is not None, "no root row exists"
        return row.id
    finally:
        db.close()


def _cn_of(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    assert attrs, "certificate has no CN"
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


# --- the two-step create flow this spec introduces (FR-3) -------------------


def _create_root(
    client: TestClient,
    cfg: Config,
    *,
    name: str,
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    path_length: int = 1,
) -> Response:
    return client.post(
        "/ca/create",
        data={
            "name": name,
            "key_type": key_type,
            "root_years": root_years,
            "path_length": path_length,
            "csrf_token": _csrf(client, cfg),
        },
    )


def _create_intermediate(
    client: TestClient,
    cfg: Config,
    root_id: int,
    *,
    name: str,
    key_type: str = "ecdsa-p256",
    years: int = 10,
    permitted_names: str = "",
    excluded_names: str = "",
) -> Response:
    return client.post(
        f"/ca/{root_id}/intermediate",
        data={
            "name": name,
            "key_type": key_type,
            "years": years,
            "permitted_names": permitted_names,
            "excluded_names": excluded_names,
            "csrf_token": _csrf(client, cfg),
        },
    )


# --- HTML scoping helpers: parsed structure, duplicated from
# test_web_ca_pages.py, never a fixed-character window and never a bare
# "x in html" search. -------------------------------------------------------

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
    actual tag nesting. `tag=None` matches any tag name."""
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
    values by name and its textarea text by name."""

    def __init__(self, action: str) -> None:
        super().__init__()
        self._action = action
        self.found_form = False
        self.input_values: dict[str, str | None] = {}
        self.textarea_values: dict[str, str] = {}
        self._in_form_depth = 0
        self._current_textarea: str | None = None

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
            elif tag == "textarea":
                self._current_textarea = attrs_dict.get("name")

    def handle_data(self, data: str) -> None:
        if self._current_textarea is not None:
            self.textarea_values[self._current_textarea] = (
                self.textarea_values.get(self._current_textarea, "") + data
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "textarea":
            self._current_textarea = None
        if self._in_form_depth > 0 and tag == "form":
            self._in_form_depth -= 1


def _form_block(html: str, action: str) -> _FormBlock:
    parser = _FormBlock(action)
    parser.feed(html)
    return parser


class _SelectedOption(HTMLParser):
    """The `value` of the `<option selected>` inside the `<select name=...>`
    matching `name` -- what a re-filled `<select>` carries back (AC-4)."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self._inside = False
        self.selected_value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "select" and attrs_dict.get("name") == self._name:
            self._inside = True
        elif tag == "option" and self._inside and "selected" in attrs_dict:
            self.selected_value = attrs_dict.get("value")

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._inside = False


def _selected(html: str, name: str) -> str | None:
    parser = _SelectedOption(name)
    parser.feed(html)
    return parser.selected_value


class _ElementById(HTMLParser):
    """The first element carrying `id=target_id`: whether it exists, and
    the `href`s of any `<a>` nested inside it."""

    def __init__(self, target_id: str) -> None:
        super().__init__()
        self._target_id = target_id
        self.found = False
        self.anchor_hrefs: list[str] = []
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

    def handle_endtag(self, tag: str) -> None:
        if self._inside and tag == self._tag:
            self._depth -= 1
            if self._depth == 0:
                self._inside = False


def _element(html: str, target_id: str) -> _ElementById:
    parser = _ElementById(target_id)
    parser.feed(html)
    return parser


_ERROR_RE = re.compile(r'<div class="error">(.*?)</div>', re.S)


def _error_box(html: str) -> tuple[str, list[str]] | None:
    """The text and the `href`s of the page's `.error` box, or `None` when
    there is none -- used both to read an error's own message (AC-2..AC-4)
    and to tell two different error states apart (AC-7/AC-8)."""
    match = _ERROR_RE.search(html)
    if match is None:
        return None
    inner = match.group(1)
    hrefs = re.findall(r'href="([^"]*)"', inner)
    text = re.sub(r"<[^>]+>", "", inner)
    return text, hrefs


def _error_text(html: str) -> str:
    box = _error_box(html)
    assert box is not None, "no .error box found"
    return box[0]


_FIELD_NAME_RE = re.compile(r'<(?:input|select|textarea)\b[^>]*\bname="([^"]*)"')


def _field_names(html: str) -> set[str]:
    return set(_FIELD_NAME_RE.findall(html))


# --- headless-Chrome plumbing, duplicated from test_web_layout.py ----------


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


def _run_probe(html: str, probe: str, tmp_path: Path, name: str) -> list[str]:
    root = tmp_path / f"probe-{name}"
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{name}.html").write_text(html.replace("</body>", probe + "</body>"))
    httpd, port = _serve(root)
    try:
        dom = _dump_dom(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150)
    finally:
        httpd.shutdown()
    return _probe_result(dom)


#: AC-9's second half: every `.section` element's first child has visible text.
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

#: AC-11: every button.danger has a confirm checkbox inside its own <form>.
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

#: AC-17: 0015's overflow probe, duplicated so this file can re-run it over
#: the CA pages whose grid-row count FR-8's section split multiplies.
_OVERFLOW_PROBE = """
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


def _overflow(url: str, width: int, height: int) -> list[str]:
    return _probe_result(_dump_dom(url, width, height))


# === FR-1/AC-1: a name is stored and signed exactly as it was typed ========


def test_created_name_is_stored_and_signed_verbatim(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    resp = _create_root(client, cfg, name="Acme Root CA")
    assert resp.status_code == 303
    assert _row_count(cfg) == 1

    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate)).one()
        assert row.kind == "root"
        assert row.name == "Acme Root CA"
        cert_pem = row.cert_pem
    finally:
        db.close()
    assert _cn_of(cert_pem) == "Acme Root CA"


def test_intermediate_name_is_stored_and_signed_verbatim(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    resp = _create_intermediate(client, cfg, root_id, name="Acme Issuing CA")
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        rows = list(db.scalars(select(CACertificate)))
        names_and_pems = [(row.kind, row.name, row.cert_pem) for row in rows]
    finally:
        db.close()

    assert len(names_and_pems) == 2
    # 0017's naming rule holds on every row -- no name disagrees with its
    # own certificate's CN.
    for _kind, name, cert_pem in names_and_pems:
        assert name == _cn_of(cert_pem)
    intermediate_name = next(name for kind, name, _pem in names_and_pems if kind == "intermediate")
    assert intermediate_name == "Acme Issuing CA"


# === FR-2/AC-2: the name check refuses, and the message is cabin's =========


def test_create_refuses_empty_blank_and_oversized_names(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    for bad_name in ("", "   ", "a" * 65):
        resp = _create_root(client, cfg, name=bad_name)
        assert resp.status_code == 400, repr(bad_name)
        assert _row_count(cfg) == 0
        assert "/ca/create" in _form_actions(resp.text)
        assert "Attribute's length" not in _error_text(resp.text)

    ok = _create_root(client, cfg, name="a" * 64)
    assert ok.status_code == 303
    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate)).one()
        name, cert_pem = row.name, row.cert_pem
    finally:
        db.close()
    assert name == "a" * 64
    assert _cn_of(cert_pem) == "a" * 64


def test_name_limit_counts_bytes_not_characters(client: TestClient, cfg: Config) -> None:
    """The check is a byte limit, not a character limit: `NameAttribute`
    measures the UTF-8 encoding, so 33 umlauts (66 bytes) are refused while
    32 (64 bytes) are accepted -- an ASCII-only test cannot tell a byte
    check from a character check."""
    _setup_superadmin(client)

    too_long = "ä" * 33  # 66 UTF-8 bytes
    assert len(too_long.encode("utf-8")) == 66
    refused = _create_root(client, cfg, name=too_long)
    assert refused.status_code == 400
    assert _row_count(cfg) == 0
    assert "/ca/create" in _form_actions(refused.text)
    assert "Attribute's length" not in _error_text(refused.text)

    fits = "ä" * 32  # exactly 64 UTF-8 bytes
    assert len(fits.encode("utf-8")) == 64
    accepted = _create_root(client, cfg, name=fits)
    assert accepted.status_code == 303
    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate)).one()
        name, cert_pem = row.name, row.cert_pem
    finally:
        db.close()
    assert name == fits
    assert _cn_of(cert_pem) == fits


def test_create_strips_surrounding_whitespace(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    resp = _create_root(client, cfg, name="  Acme  ")
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate)).one()
        name, cert_pem = row.name, row.cert_pem
    finally:
        db.close()
    assert name == "Acme"
    assert _cn_of(cert_pem) == "Acme"


def test_intermediate_name_error_renders_the_detail_page(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)
    before = _row_count(cfg)

    resp = _create_intermediate(client, cfg, root_id, name="   ", key_type="ecdsa-p384", years=7)
    assert resp.status_code == 400
    action = f"/ca/{root_id}/intermediate"
    assert action in _form_actions(resp.text)
    block = _form_block(resp.text, action)
    assert block.found_form is True
    assert block.input_values.get("years") == "7"
    assert _selected(resp.text, "key_type") == "ecdsa-p384"
    assert "Attribute's length" not in _error_text(resp.text)
    assert _row_count(cfg) == before

    good = _create_intermediate(client, cfg, root_id, name="Acme Issuing CA")
    assert good.status_code == 303
    assert good.headers["location"] == f"/ca/{root_id}"
    assert _row_count(cfg) == before + 1


# === FR-3/AC-5: a create makes a root, only the second step makes an issuer


def test_create_writes_only_a_root(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    resp = _create_root(client, cfg, name="Acme Root CA")
    assert resp.status_code == 303
    assert _row_count(cfg) == 1

    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate)).one()
        assert row.kind == "root"
        assert ca_service.active_issuers(db) == []
        root_id = row.id
    finally:
        db.close()

    detail = client.get(f"/ca/{root_id}")
    assert detail.status_code == 200
    assert f"/ca/{root_id}/intermediate" in _form_actions(detail.text)


def test_intermediate_step_produces_the_first_issuer(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    resp = _create_intermediate(client, cfg, root_id, name="Acme Issuing CA")
    assert resp.status_code == 303
    assert _row_count(cfg) == 2

    db = _db(cfg)
    try:
        assert len(ca_service.active_issuers(db)) == 1
    finally:
        db.close()

    # The issue form now recognises this issuer: no "no CA"/"no issuer"
    # error, so the second step is genuinely reachable from the page --
    # not merely a row nobody can use (goes red if create alone already
    # writes both rows, or if this route can't be reached).
    issue_page = client.get("/certs/new").text
    assert _error_box(issue_page) is None


# === FR-3/AC-6: /ca/new no longer asks about the intermediate ==============


def test_ca_new_has_no_intermediate_fields(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    new_page = client.get("/ca/new").text
    field_names = _field_names(new_page)
    assert {"name", "key_type", "root_years", "path_length"} <= field_names
    assert "intermediate_years" not in field_names
    assert "permitted_names" not in field_names
    assert "excluded_names" not in field_names

    detail = client.get(f"/ca/{root_id}").text
    block = _form_block(detail, f"/ca/{root_id}/intermediate")
    assert block.found_form is True
    assert "permitted_names" in block.textarea_values
    assert "excluded_names" in block.textarea_values


# === FR-7: "no CA" and "a CA with no issuer" are not the same sentence =====


def test_issue_form_distinguishes_no_ca_from_no_issuer(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    no_ca_box = _error_box(client.get("/certs/new").text)
    assert no_ca_box is not None
    no_ca_text, no_ca_hrefs = no_ca_box
    assert "/ca/new" in no_ca_hrefs

    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    no_issuer_box = _error_box(client.get("/certs/new").text)
    assert no_issuer_box is not None
    no_issuer_text, no_issuer_hrefs = no_issuer_box
    assert f"/ca/{root_id}" in no_issuer_hrefs
    assert "/ca/new" not in no_issuer_hrefs
    assert no_issuer_text != no_ca_text


def test_dashboard_distinguishes_no_ca_from_no_issuer(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    root_only = client.get("/").text
    root_only_error = _error_box(root_only)
    assert root_only_error is None or "CA: not set up" not in root_only_error[0]
    no_issuer = _element(root_only, "ca-no-issuer")
    assert no_issuer.found is True
    assert f"/ca/{root_id}" in no_issuer.anchor_hrefs
    revocation_before = _row(root_only, "Revocation", class_name="section", tag="div")
    assert _count_tag(revocation_before, "table") == 0

    assert _create_intermediate(client, cfg, root_id, name="Acme Issuing CA").status_code == 303

    full = client.get("/").text
    assert _element(full, "ca-no-issuer").found is False
    revocation_after = _row(full, "Revocation", class_name="section", tag="div")
    assert _count_tag(revocation_after, "table") == 1


def test_no_ca_and_no_issuer_are_distinct_at_every_call_site(
    client: TestClient, cfg: Config
) -> None:
    """FR-7 names four sites that today share one sentence: `certs_ui`'s
    issue form, `ca_service.resolve_issuer`, `issuer_grants
    .resolve_granted_issuer` (a duplicated string, and the path the API,
    MCP and ACME finalize actually take), and the dashboard. The other two
    tests in this file cover the dashboard and the issue form; this one
    enumerates the remaining two explicitly, plus the HTTP boundary the
    API actually answers through, rather than trusting that fixing one
    fixes the rest.
    """
    _setup_superadmin(client)
    principal = Principal(kind=PrincipalKind.user, id=999, role=Role.admin)

    db = _db(cfg)
    try:
        with pytest.raises(CANotConfiguredError) as no_ca_service:
            resolve_issuer(db, None)
        with pytest.raises(CANotConfiguredError) as no_ca_grant:
            resolve_granted_issuer(db, principal, None)
    finally:
        db.close()
    no_ca_service_message = str(no_ca_service.value)
    no_ca_grant_message = str(no_ca_grant.value)
    # one module-level message: resolve_issuer and resolve_granted_issuer
    # must agree on a no-row instance, or the two can drift again.
    assert no_ca_service_message == no_ca_grant_message

    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303

    db = _db(cfg)
    try:
        with pytest.raises(CANotConfiguredError) as root_only_service:
            resolve_issuer(db, None)
        with pytest.raises(CANotConfiguredError) as root_only_grant:
            resolve_granted_issuer(db, principal, None)
        secret, _token = create_token(db, "probe-token", Role.admin)
    finally:
        db.close()
    root_only_service_message = str(root_only_service.value)
    root_only_grant_message = str(root_only_grant.value)

    # a root with no active intermediate must say so -- not the no-row
    # sentence -- and both service-layer call sites must still agree.
    assert root_only_service_message != no_ca_service_message
    assert root_only_service_message == root_only_grant_message

    # the HTTP boundary the API (and, by the same code path, MCP and ACME
    # finalize) actually answers through carries the same message, not a
    # second hardcoded copy of the old one.
    api_resp = client.post(
        "/api/v1/certificates",
        json={"subject_cn": "example.lan"},
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert api_resp.status_code == 409
    assert api_resp.json()["detail"] == root_only_service_message
    assert api_resp.json()["detail"] != no_ca_service_message


# === FR-8/AC-9: no <details>, and no empty left column ======================


def test_detail_page_has_no_details_and_no_empty_column(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_a = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_a, name="Acme Issuing CA").status_code == 303
    # A second root with path_length=2 -- the one that can cross-sign root_a
    # -- so root_a's own page offers the cross-sign section (test_web_ca_pages
    # .py's own fixture uses the same asymmetry).
    assert _create_root(client, cfg, name="Beta Root CA", path_length=2).status_code == 303
    root_b = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_b, name="Beta Issuing CA").status_code == 303

    db = _db(cfg)
    try:
        intermediate_a = db.scalars(
            select(CACertificate).where(
                CACertificate.kind == "intermediate", CACertificate.parent_id == root_a
            )
        ).one()
        intermediate_a_id = intermediate_a.id
    finally:
        db.close()

    html = client.get(f"/ca/{root_a}").text
    assert _count_tag(html, "details") == 0
    assert _count_tag(html, "summary") == 0

    intermediate_action = f"/ca/{root_a}/intermediate"
    intermediate_block = _row(html, intermediate_action, class_name="section", tag=None)
    assert "<h2" in intermediate_block

    cross_action = f"/ca/{root_a}/cross-sign"
    cross_block = _row(html, cross_action, class_name="section", tag=None)
    assert "<h2" in cross_block

    chain_marker = f"/ca/{intermediate_a_id}/chain.pem"
    chain_block = _row(html, chain_marker, class_name="section", tag=None)
    assert "<h2" in chain_block

    # Each is its OWN section, not one giant wrapper carrying every action --
    # under today's single `.section` for the whole hierarchy, all three of
    # the above are literally the same string, and an "h2 appears somewhere
    # before the marker" check would pass on that shared wrapper by
    # accident. Distinctness is what actually proves the split happened.
    assert intermediate_block != cross_block
    assert intermediate_block != chain_block
    assert cross_block != chain_block

    if Path(CHROME).exists():
        bad = _run_probe(html, _SECTION_PROBE, tmp_path, "ca_detail_sections")
        assert bad == [], bad


# === FR-9/AC-10: retire is confirmed, and enforced server-side =============


def test_retire_requires_the_confirmation_box(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_id, name="Acme Issuing CA").status_code == 303
    # 0017 FR-4 refuses to retire the last active issuer instance-wide, so a
    # second, unrelated hierarchy has to exist before Acme's root can be
    # retired below.
    assert _create_root(client, cfg, name="Spare Root CA").status_code == 303
    spare_root_id = _last_root_id(cfg)
    assert (
        _create_intermediate(client, cfg, spare_root_id, name="Spare Issuing CA").status_code == 303
    )

    detail = client.get(f"/ca/{root_id}").text
    retire_action = f"/ca/{root_id}/retire"
    renew_action = f"/ca/{root_id}/renew"
    # two SEPARATE <form> elements, not one form with formaction buttons --
    # _form_actions only sees a form's own action, never a button's.
    assert retire_action in _form_actions(detail)
    assert renew_action in _form_actions(detail)

    retire_block = _form_block(detail, retire_action)
    assert retire_block.found_form is True
    assert "confirm" in retire_block.input_values
    assert "years" not in retire_block.input_values

    unticked = client.post(retire_action, data={"csrf_token": _csrf(client, cfg)})
    assert unticked.status_code == 400
    assert retire_action in _form_actions(unticked.text)
    assert _status_of(cfg, root_id) == "active"

    ticked = client.post(retire_action, data={"confirm": "on", "csrf_token": _csrf(client, cfg)})
    assert ticked.status_code == 303
    assert _status_of(cfg, root_id) == "retired"


def test_every_danger_button_has_a_confirmation(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    if not Path(CHROME).exists():
        pytest.skip("headless Chrome not installed")

    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA", path_length=2).status_code == 303
    root_a = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_a, name="Acme Issuing CA").status_code == 303
    assert _create_root(client, cfg, name="Beta Root CA").status_code == 303
    root_b = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_b, name="Beta Issuing CA").status_code == 303
    cross_resp = client.post(
        f"/ca/{root_b}/cross-sign",
        data={"signing_root_id": root_a, "years": 5, "csrf_token": _csrf(client, cfg)},
    )
    assert cross_resp.status_code == 303

    # root_b's own page now shows its root, its intermediate and the cross
    # row signed by root_a -- three danger buttons, proving the treatment
    # repeats rather than being applied to the first row alone (AC-11).
    html = client.get(f"/ca/{root_b}").text
    assert _count_danger_buttons(html) >= 1  # sanity: the fixture built what it claims to

    bad = _run_probe(html, _DANGER_PROBE, tmp_path, "ca_detail_danger")
    assert bad == [], bad


# === FR-10/AC-12: the stylesheet loses what nothing uses, both directions ===


def test_stylesheet_and_templates_agree_in_both_directions(client: TestClient, cfg: Config) -> None:
    css_text = CSS_PATH.read_text()
    assert "details" not in css_text
    assert ".inline-form" not in css_text
    assert ".ca-row" not in css_text

    for path in TEMPLATES_DIR.glob("*.html"):
        text = path.read_text()
        assert "<details" not in text, f"{path.name} still uses <details>"
        assert "ca-row" not in text, f"{path.name} still uses .ca-row"
        assert "inline-form" not in text, f"{path.name} still uses .inline-form"

    # 0023 AC-11's forward direction, re-run over the pages this spec
    # touches: every class used in the rendered markup has a rule.
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA", path_length=2).status_code == 303
    root_a = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_a, name="Acme Issuing CA").status_code == 303
    assert _create_root(client, cfg, name="Beta Root CA").status_code == 303
    root_b = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_b, name="Beta Issuing CA").status_code == 303
    cross_resp = client.post(
        f"/ca/{root_b}/cross-sign",
        data={"signing_root_id": root_a, "years": 5, "csrf_token": _csrf(client, cfg)},
    )
    assert cross_resp.status_code == 303

    pages = [
        client.get("/ca").text,
        client.get("/ca/new").text,
        client.get("/ca/import").text,
        client.get(f"/ca/{root_a}").text,
        client.get(f"/ca/{root_b}").text,
    ]

    defined = set(re.findall(r"\.([a-zA-Z][\w-]*)", css_text))
    used: set[str] = set()
    for html in pages:
        for classes in _CLASS_RE.findall(html):
            used.update(classes.split())
    missing = used - defined
    assert missing == set(), missing


# === FR-5/AC-13: the TLS swap happens when an issuer appears, not before ===


def test_tls_swaps_when_the_intermediate_appears(tls_client: TestClient, tls_cfg: Config) -> None:
    _setup_superadmin(tls_client)

    root_resp = _create_root(tls_client, tls_cfg, name="Acme Root CA")
    assert root_resp.status_code == 303
    root_id = _last_root_id(tls_cfg)

    served_after_root = x509.load_pem_x509_certificate(cert_path(tls_cfg.data_dir).read_bytes())
    assert served_after_root.issuer == served_after_root.subject
    db = _db(tls_cfg)
    try:
        assert not get_setting(db, TLS_ISSUER_ID)
    finally:
        db.close()

    intermediate_resp = _create_intermediate(tls_client, tls_cfg, root_id, name="Acme Issuing CA")
    assert intermediate_resp.status_code == 303

    db = _db(tls_cfg)
    try:
        intermediate_row = db.scalars(
            select(CACertificate).where(CACertificate.kind == "intermediate")
        ).one()
        intermediate_cert = x509.load_pem_x509_certificate(
            intermediate_row.cert_pem.encode("utf-8")
        )
        tls_issuer_id = get_setting(db, TLS_ISSUER_ID)
    finally:
        db.close()

    served_after_intermediate = x509.load_pem_x509_certificate(
        cert_path(tls_cfg.data_dir).read_bytes()
    )
    assert served_after_intermediate.issuer == intermediate_cert.subject
    assert served_after_intermediate.issuer != served_after_intermediate.subject
    assert tls_issuer_id == str(intermediate_row.id)


# === FR-5/AC-14: the grant and the audit event follow the row that exists ==


def test_grant_and_audit_follow_the_intermediate(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_admin(client, cfg, "bob")
    _login(client, "bob", "whatever12345")

    assert _create_root(client, cfg, name="Acme Root CA").status_code == 303
    root_id = _last_root_id(cfg)

    db = _db(cfg)
    try:
        bob = db.scalars(select(User).where(User.username == "bob")).one()
        bob_id = bob.id
        assert list(db.scalars(select(UserIssuer))) == []
        events, _total = audit.list_events(db, action=AuditAction.ca_created)
        assert len(events) == 1
        create_target_id = events[0].target_id
        create_detail = events[0].detail
    finally:
        db.close()
    assert create_target_id == str(root_id)
    assert create_detail is not None
    assert "granted_to" not in create_detail

    intermediate_resp = _create_intermediate(client, cfg, root_id, name="Acme Issuing CA")
    assert intermediate_resp.status_code == 303

    db = _db(cfg)
    try:
        intermediate_row = db.scalars(
            select(CACertificate).where(CACertificate.kind == "intermediate")
        ).one()
        intermediate_id = intermediate_row.id
        grants = list(db.scalars(select(UserIssuer)))
        assert len(grants) == 1
        assert grants[0].user_id == bob_id
        assert grants[0].ca_certificate_id == intermediate_id
        events, _total = audit.list_events(db, action=AuditAction.ca_created)
        assert len(events) == 2
        newest = events[0]
        newest_target_id = newest.target_id
        newest_detail = newest.detail
    finally:
        db.close()
    assert newest_target_id == str(intermediate_id)
    assert newest_detail is not None
    assert newest_detail.get("granted_to") == bob_id

    # the effect, not just a row: bob can actually issue now.
    issue_resp = client.post(
        "/certs/issue",
        data={"subject_cn": "example.lan", "csrf_token": _csrf(client, cfg)},
    )
    assert issue_resp.status_code == 303


# === FR-11/AC-15: the fixtures follow production's naming rule =============


def test_fixtures_name_rows_the_way_production_does(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """FR-11/AC-15: the direct-fixture half runs against its own, isolated
    database -- sharing ``cfg``'s with the HTTP half below would leave two
    active issuers behind (Fixture CA's and Http CA's) and break that
    half's own "exactly one active issuer" assertion, which is about
    ``create_ca_via_http`` and has nothing to do with what this half checks.

    The rule under test is not "root and intermediate share one label" --
    production refuses exactly that (FR-13: an intermediate may not carry
    its parent root's own subject). It is that ``name`` is never decorated
    and always agrees with the row's own certificate, and that root and
    intermediate get two distinguishable names derived from the single
    argument a caller passes, the same way ``create_ca_via_http`` derives
    the intermediate's name from ``name`` below.
    """
    fixture_cfg = make_config(tmp_path / "fixture-check")
    fixture_cfg.data_dir.mkdir(parents=True)
    run_migrations(fixture_cfg.db_url)
    db = _db(fixture_cfg)
    secrets = _secrets(fixture_cfg)
    try:
        hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Fixture CA")
        assert hierarchy.root.name == "Fixture CA"
        assert hierarchy.intermediate.name == "Fixture CA Intermediate"
        assert hierarchy.root.name != hierarchy.intermediate.name
        for row in (hierarchy.root, hierarchy.intermediate):
            assert row.name == _cn_of(row.cert_pem)
    finally:
        db.close()

    _setup_superadmin(client)
    ca_fixtures.create_ca_via_http(client, cfg, name="Http CA")

    db = _db(cfg)
    try:
        rows = list(db.scalars(select(CACertificate)))
        assert len(rows) == 2, (
            "create_ca_via_http must post the intermediate as a second request (FR-11)"
        )
        root_row = next(r for r in rows if r.kind == "root")
        assert root_row.name == "Http CA"
        for row in rows:
            assert row.name == _cn_of(row.cert_pem)
        assert len(ca_service.active_issuers(db)) == 1
    finally:
        db.close()


# === AC-17 (0015, re-run): no page scrolls sideways =========================


@pytest.mark.skipif(not Path(CHROME).exists(), reason="headless Chrome not installed")
@pytest.mark.parametrize("width,height", [(1440, 1150), (390, 900)])
def test_no_horizontal_overflow(
    client: TestClient, cfg: Config, tmp_path: Path, width: int, height: int
) -> None:
    """0015 AC-1/AC-2 re-run over the CA pages: FR-8's section split
    multiplies the number of grid rows on the detail page, which is
    exactly the change that has broken this before."""
    _setup_superadmin(client)
    assert _create_root(client, cfg, name="Acme Root CA", path_length=2).status_code == 303
    root_a = _last_root_id(cfg)
    assert (
        _create_intermediate(
            client,
            cfg,
            root_a,
            name="Acme Issuing CA",
            permitted_names="example.com",
            excluded_names="internal.example.com",
        ).status_code
        == 303
    )
    assert _create_root(client, cfg, name="Beta Root CA").status_code == 303
    root_b = _last_root_id(cfg)
    assert _create_intermediate(client, cfg, root_b, name="Beta Issuing CA").status_code == 303
    cross_resp = client.post(
        f"/ca/{root_b}/cross-sign",
        data={"signing_root_id": root_a, "years": 5, "csrf_token": _csrf(client, cfg)},
    )
    assert cross_resp.status_code == 303

    root = tmp_path / "pages"
    root.mkdir()
    shutil.copytree(STATIC_DIR, root / "static")
    pages = {
        "ca": "/ca",
        "ca_new": "/ca/new",
        "ca_detail_a": f"/ca/{root_a}",
        "ca_detail_b": f"/ca/{root_b}",
        "transfer_ca_import": "/transfer/ca-import",
        "transfer_cross_import": "/transfer/cross-import",
        "transfer_trust_bundle": "/transfer/trust-bundle",
        "transfer_ca_key": "/transfer/ca-key",
        "transfer_inventory": "/transfer/inventory",
    }
    for name, path in pages.items():
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        (root / f"{name}.html").write_text(
            resp.text.replace("</body>", _OVERFLOW_PROBE + "</body>")
        )

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
