"""Web-layer tests for spec 0023 (CA pages): the four pages `/ca` is split
into -- `GET /ca` (list), `GET /ca/{ca_id}` (one hierarchy), `GET /ca/new`
(create) and `GET /ca/import` (import) -- their routing, and what each one
shows and withholds.

Everything else about the POST routes (paths, methods, fields, guards,
CSRF, audit events) is unchanged by this spec and stays covered by
`test_web_ca.py`, `test_web_name_constraints.py` and `test_web_dashboard.py`.
This file covers only what moved: which page a GET or a refused POST
lands on, which hierarchy a detail page shows, which forms a page carries,
and the route shapes that must not shadow each other (FR-9).

Scoping follows `test_web_ca.py:168`'s `_row(...)`: the actual element
that wraps a marker, found by parsing tag nesting, never a fixed-character
window and never a bare substring search over the whole page.

This branch is red by design: `/ca/{ca_id}`, `/ca/new` and `/ca/import`
don't exist yet, `ca_detail.html`/`ca_new.html`/`ca_import.html` don't
exist, and `POST /ca/{root_id}/intermediate` still raises a bare
`HTTPException` instead of re-rendering a page.
"""

import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import BASE_URL, set_setting
from cabin.store import create_session_factory

# --- fixtures and low-level plumbing, duplicated from test_web_ca.py rather
# than imported: this project has no conftest.py, and each web test file
# owns its own client/session/csrf helpers. ------------------------------


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


def _row_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return len(ca_service.list_cas(db))
    finally:
        db.close()


def _cert_pem_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).cert_pem
    finally:
        db.close()


def _fingerprint(cert_pem: str) -> str:
    """Same format `ca_x509.describe_certificate` puts on the page: SHA-256,
    colon-hex -- computed independently here rather than imported, so this
    is a check against the certificate, not against the code under test."""
    digest = x509.load_pem_x509_certificate(cert_pem.encode("ascii")).fingerprint(hashes.SHA256())
    return ":".join(f"{b:02x}" for b in digest)


def _seed_two_hierarchies(cfg: Config) -> tuple[int, int, int, int]:
    """The spec's own fixture: alpha (`path_length=2`, one intermediate)
    and beta (default `path_length`, one intermediate), both active --
    built directly through `ca_service`, since what is under test is the
    web layer's routing and rendering, not hierarchy creation itself.
    `path_length=2` on alpha alone is what makes AC-7 measurable: alpha can
    cross-sign beta, beta cannot cross-sign alpha.

    Returns (alpha_root_id, alpha_intermediate_id, beta_root_id,
    beta_intermediate_id).
    """
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        alpha = ca_service.create_hierarchy(db, secrets, "alpha", path_length=2)
        beta = ca_service.create_hierarchy(db, secrets, "beta")
        return alpha.root.id, alpha.intermediate.id, beta.root.id, beta.intermediate.id
    finally:
        db.close()


# --- HTML scoping helpers: parsed structure, never a fixed-character
# window and never a bare "x in html" (test_web_ca.py:168, AC-* preamble). --

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
    actual tag nesting, following `test_web_ca.py:168`. `tag=None` matches
    any tag name, for a class (like `.note`) not pinned to one element.
    """
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
            if matches_tag and classes is not None and class_name in classes.group(1).split():
                return html[open_start : m.end()]
    raise AssertionError(f"no <{tag or '*'} class={class_name!r}> element wraps {marker!r}")


def _count_tag(html: str, tag: str) -> int:
    return len(re.findall(rf"<{tag}\b", html, re.IGNORECASE))


class _FormActions(HTMLParser):
    """The `action` attribute of every `<form>` on the page, in document
    order -- so "the page has exactly one form" is a count over actual
    `<form>` elements, never a substring search (AC-1/AC-6)."""

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
    values by name, its textarea text by name, and whether the nearest
    `<details>` ancestor (if any) carries the boolean `open` attribute --
    the collapsed disclosure a re-filled form can hide inside (FR-8).
    """

    def __init__(self, action: str) -> None:
        super().__init__()
        self._action = action
        self.found_form = False
        self.input_values: dict[str, str | None] = {}
        self.textarea_values: dict[str, str] = {}
        self.details_open: bool | None = None
        self._details_stack: list[bool] = []
        self._in_form_depth = 0
        self._current_textarea: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "details":
            self._details_stack.append("open" in attrs_dict)
        if tag == "form" and attrs_dict.get("action") == self._action:
            self.found_form = True
            self._in_form_depth = 1
            if self._details_stack:
                self.details_open = self._details_stack[-1]
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
        if tag == "details" and self._details_stack:
            self._details_stack.pop()


def _form_block(html: str, action: str) -> _FormBlock:
    parser = _FormBlock(action)
    parser.feed(html)
    return parser


class _SelectOptions(HTMLParser):
    """Whether a `<select name=...>` is present, and the `value` of every
    `<option>` inside it -- for AC-7's cross-sign candidate select."""

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


class _ElementById(HTMLParser):
    """The first element carrying `id=target_id`: whether it exists, and
    the `href`s of any `<a>` nested inside it -- so "the empty state links
    to /ca/new" is read off the DOM, not guessed at with a substring."""

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


def _marked_labels(html: str) -> list[str]:
    """Every rail entry marked `aria-current="page"`, by its label text --
    used here only as a proxy for "which page rendered", the way AC-4 uses
    it (not for asserting the rail's own group structure, which is
    test_web_layout.py's job)."""
    return re.findall(r'<a href="[^"]*" aria-current="page">([^<]+)</a>', html)


# === AC-1: /ca is a list, no forms, no per-hierarchy detail ================


def test_ca_list_has_no_forms_and_links_each_hierarchy(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, beta_root, beta_int = _seed_two_hierarchies(cfg)

    html = client.get("/ca").text

    # exactly one form on the page: the rail's own logout form
    assert _form_actions(html) == ["/logout"]
    # no <details> at all -- those live on the detail page now
    assert _count_tag(html, "details") == 0

    assert f'href="/ca/{alpha_root}"' in html
    assert f'href="/ca/{beta_root}"' in html

    assert "alpha Intermediate CA" not in html
    assert "beta Intermediate CA" not in html
    alpha_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_root))
    beta_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_root))
    assert alpha_fingerprint not in html
    assert beta_fingerprint not in html
    _ = alpha_int, beta_int  # not shown on the list; ids only used above


# === AC-9: no hierarchy at all is not a dead end, and is admin/viewer aware


def test_ca_list_empty_state_links_for_admin_and_not_for_viewer(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_viewer(client, cfg)

    admin_html = client.get("/ca").text
    assert admin_html  # still logged in as admin at this point
    admin_empty = _element(admin_html, "ca-empty")
    assert admin_empty.found is True
    assert "/ca/new" in admin_empty.anchor_hrefs
    assert "/ca/import" in admin_empty.anchor_hrefs

    _login(client, "vera", "whatever12345")
    viewer_resp = client.get("/ca")
    assert viewer_resp.status_code == 200
    viewer_empty = _element(viewer_resp.text, "ca-empty")
    assert viewer_empty.found is True
    assert "/ca/new" not in viewer_empty.anchor_hrefs
    assert "/ca/import" not in viewer_empty.anchor_hrefs


# === AC-2: the detail page is one hierarchy, named by its root =============


def test_ca_detail_shows_only_its_own_hierarchy(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, beta_root, _beta_int = _seed_two_hierarchies(cfg)
    alpha_root_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_root))
    beta_root_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_root))

    alpha_page = client.get(f"/ca/{alpha_root}")
    assert alpha_page.status_code == 200
    assert "alpha Intermediate CA" in alpha_page.text
    assert alpha_root_fingerprint in alpha_page.text
    assert "beta Intermediate CA" not in alpha_page.text

    beta_page = client.get(f"/ca/{beta_root}")
    assert beta_page.status_code == 200
    assert "beta Intermediate CA" in beta_page.text
    assert beta_root_fingerprint in beta_page.text
    assert "alpha Intermediate CA" not in beta_page.text


def test_ca_detail_404_for_a_non_root_id(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)
    _ = alpha_root

    # named by an intermediate id -- FR-3: a hierarchy is named by its root
    assert client.get(f"/ca/{alpha_int}").status_code == 404
    # an id no row has at all
    assert client.get("/ca/999999").status_code == 404


# === AC-3/FR-8: a refused intermediate keeps what was typed, visibly =======


def test_intermediate_error_refills_the_form_and_opens_the_details(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)

    resp = client.post(
        f"/ca/{alpha_root}/intermediate",
        data={
            "name": "edge",
            "key_type": "ecdsa-p384",
            "years": 7,
            "permitted_names": "not a name constraint!!",
            "excluded_names": "shadow.example.com",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 400
    html = resp.text

    action = f"/ca/{alpha_root}/intermediate"
    block = _form_block(html, action)
    assert block.found_form is True, "the refused form is gone -- not re-rendered at all"
    assert block.input_values.get("name") == "edge"
    assert block.input_values.get("years") == "7"
    assert block.textarea_values.get("permitted_names") == "not a name constraint!!"
    assert block.textarea_values.get("excluded_names") == "shadow.example.com"
    assert block.details_open is True, (
        "the <details> wrapping the refilled form must carry `open`, or the "
        "operator is looking at an error about fields that appear to be gone"
    )

    error_block = _row(html, "not a valid name-constraint entry", class_name="error", tag=None)
    assert "not a valid name-constraint entry" in error_block


def test_intermediate_error_writes_no_row(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)
    before = _row_count(cfg)

    bad = client.post(
        f"/ca/{alpha_root}/intermediate",
        data={
            "name": "edge",
            "key_type": "ecdsa-p256",
            "years": 7,
            "permitted_names": "not a name constraint!!",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert bad.status_code == 400
    assert _row_count(cfg) == before

    good = client.post(
        f"/ca/{alpha_root}/intermediate",
        data={
            "name": "edge",
            "key_type": "ecdsa-p256",
            "years": 7,
            "permitted_names": "edge.example.com",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert good.status_code == 303
    assert good.headers["location"] == f"/ca/{alpha_root}"
    assert _row_count(cfg) == before + 1


# === AC-4: an error lands on the page that owns the form ====================


def test_form_errors_render_the_page_that_owns_the_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, beta_root, _beta_int = _seed_two_hierarchies(cfg)
    before = _row_count(cfg)

    create_resp = client.post(
        "/ca/create",
        data={
            "name": "toowide",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "path_length": 9,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert create_resp.status_code == 400
    assert _marked_labels(create_resp.text) == ["Create"]
    assert "/ca/create" in _form_actions(create_resp.text)

    import_resp = client.post(
        "/ca/import",
        data={
            "cert_pem": "not a pem",
            "key_pem": "not a pem",
            "chain_pem": "not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert import_resp.status_code == 400
    assert _marked_labels(import_resp.text) == ["Import"]
    assert "/ca/import" in _form_actions(import_resp.text)

    cross_import_resp = client.post(
        "/ca/cross-import",
        data={
            "cross_pem": "not a pem",
            "issuer_pem": "not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert cross_import_resp.status_code == 400
    assert _marked_labels(cross_import_resp.text) == ["Import"]
    assert "/ca/cross-import" in _form_actions(cross_import_resp.text)

    cross_sign_resp = client.post(
        f"/ca/{beta_root}/cross-sign",
        data={
            "signing_root_id": alpha_root,
            "years": 0,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert cross_sign_resp.status_code == 400
    assert _marked_labels(cross_sign_resp.text) == ["Hierarchies"]
    assert f"/ca/{beta_root}/cross-sign" in _form_actions(cross_sign_resp.text)

    assert _row_count(cfg) == before  # none of the four wrote a row


# === AC-6: a viewer reads the detail page and sees no form; an admin does ===


def test_viewer_reads_the_detail_page_and_sees_no_form(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)
    db = _db(cfg)
    try:
        # crl.distribution_url forces the scheme to http regardless of what
        # is configured here (spec 0017 FR-12) -- the expected URL below
        # matches that, not the scheme this sets.
        set_setting(db, BASE_URL, "http://ca.example.org")
        db.commit()
    finally:
        db.close()
    _create_viewer(client, cfg)

    admin_page = client.get(f"/ca/{alpha_root}")
    assert admin_page.status_code == 200
    admin_actions = _form_actions(admin_page.text)
    assert f"/ca/{alpha_root}/intermediate" in admin_actions
    assert f"/ca/{alpha_root}/renew" in admin_actions

    _login(client, "vera", "whatever12345")
    viewer_page = client.get(f"/ca/{alpha_root}")
    assert viewer_page.status_code == 200
    assert "alpha Intermediate CA" in viewer_page.text
    expected_crl_url = f"http://ca.example.org/crl/{alpha_int}"
    assert f'href="{expected_crl_url}"' in viewer_page.text  # readable, not gated
    assert _form_actions(viewer_page.text) == ["/logout"]


def test_viewer_rail_has_no_ca_new_or_ca_import(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_viewer(client, cfg)
    _login(client, "vera", "whatever12345")

    assert client.get("/ca/new").status_code == 403
    assert client.get("/ca/import").status_code == 403

    rail = client.get("/ca").text
    assert 'href="/ca"' in rail
    assert 'href="/ca/new"' not in rail
    assert 'href="/ca/import"' not in rail


# === AC-7: cross-sign candidates come from every row, not from the group ===


def test_cross_sign_candidates_come_from_every_row(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, beta_root, _beta_int = _seed_two_hierarchies(cfg)

    beta_page = client.get(f"/ca/{beta_root}").text
    beta_select = _select(beta_page, "signing_root_id")
    assert beta_select.found is True
    assert str(alpha_root) in beta_select.option_values

    alpha_page = client.get(f"/ca/{alpha_root}").text
    alpha_select = _select(alpha_page, "signing_root_id")
    assert alpha_select.found is False
    # the explanatory note is on the page, scoped to the .note primitive --
    # not just present anywhere in the html.
    _row(alpha_page, "path_length", class_name="note", tag=None)


# === AC-8: nothing shadows anything (FR-9) ==================================


def test_ca_routes_are_not_shadowed_by_the_detail_route(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)

    assert client.get("/ca/new").status_code == 200
    assert client.get("/ca/import").status_code == 200

    pem_resp = client.get(f"/ca/{alpha_root}.pem")
    assert pem_resp.status_code == 200
    assert pem_resp.headers["content-type"].startswith("application/x-pem-file")

    assert client.get(f"/ca/{alpha_root}.cer").status_code == 200
    assert client.get(f"/ca/{alpha_int}/chain.pem").status_code == 200

    # a non-numeric id must be a 404 from routing, never a 422 from the
    # detail route's int conversion (the 0017 /crl/7.pem bug, again)
    not_found = client.get("/ca/does-not-exist")
    assert not_found.status_code == 404

    # GET and POST /ca/import share a path and must reach their own handler
    bad_import = client.post(
        "/ca/import",
        data={
            "cert_pem": "not a pem",
            "key_pem": "not a pem",
            "chain_pem": "not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert bad_import.status_code == 400  # reached ca_import's own handler


# === AC-9: the create/import forms are not duplicated elsewhere =============


def test_new_and_import_pages_own_their_forms_and_link_each_other(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    alpha_root, _alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)

    new_page = client.get("/ca/new").text
    assert "/ca/create" in _form_actions(new_page)
    assert "/ca/import" not in _form_actions(new_page)
    assert 'href="/ca/import"' in new_page

    import_page = client.get("/ca/import").text
    assert "/ca/import" in _form_actions(import_page)
    assert "/ca/cross-import" in _form_actions(import_page)
    assert "/ca/create" not in _form_actions(import_page)
    assert 'href="/ca/new"' in import_page

    # neither the list nor a detail page carries either form
    list_page = client.get("/ca").text
    assert "/ca/create" not in _form_actions(list_page)
    assert "/ca/import" not in _form_actions(list_page)
    detail_page = client.get(f"/ca/{alpha_root}").text
    assert "/ca/create" not in _form_actions(detail_page)
    assert "/ca/import" not in _form_actions(detail_page)

    templates_dir = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
    assert not (templates_dir / "ca_setup.html").exists()
