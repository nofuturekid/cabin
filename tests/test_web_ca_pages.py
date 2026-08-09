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
        alpha = ca_service.create_hierarchy(
            db, secrets, "alpha", "alpha intermediate", path_length=2
        )
        beta = ca_service.create_hierarchy(db, secrets, "beta", "beta intermediate")
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


def _row(html: str, marker: str, *, class_name: str | None = None, tag: str | None = "div") -> str:
    """The full outer HTML of the innermost element carrying `class_name`
    that contains `marker`'s first occurrence -- scoped by parsing the
    actual tag nesting, following `test_web_ca.py:168`. `tag=None` matches
    any tag name, for a class (like `.note`) not pinned to one element.
    """
    # A marker that is not on the page at all is a distinct failure from
    # "no element of that class wraps it"; `html.index` alone would report
    # it as a bare ValueError from inside this helper.
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
            # spec 0026: `class_name=None` scopes a `<tr>` by a marker inside
            # it -- the two hierarchy tables' rows deliberately carry no class.
            matches_class = class_name is None or (
                classes is not None and class_name in classes.group(1).split()
            )
            if matches_tag and matches_class:
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
    values by name and its textarea text by name (FR-8's re-fill on a
    refused submission). Spec 0024 moved every create/add form out of a
    collapsible `<details>` wrapper into its own open `.section`
    (FR-10), so this no longer tracks disclosure state -- there is none
    left to track.
    """

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

    # Intermediates never surface on the list page: the overview only ever
    # carries a count. Checking for "alpha Intermediate CA" would be dead --
    # spec 0024 FR-1 dropped that composed suffix, so `_seed_two_hierarchies`
    # names the row "alpha intermediate" and that string never existed on
    # this page under any implementation. Check the real, still-moving
    # value instead: the intermediate's own name and fingerprint.
    assert "alpha intermediate" not in html
    assert "beta intermediate" not in html
    alpha_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_root))
    beta_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_root))
    alpha_int_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_int))
    beta_int_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_int))
    assert alpha_fingerprint not in html
    assert beta_fingerprint not in html
    assert alpha_int_fingerprint not in html
    assert beta_int_fingerprint not in html


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
    assert "/transfer/ca-import" in admin_empty.anchor_hrefs

    _login(client, "vera", "whatever12345")
    viewer_resp = client.get("/ca")
    assert viewer_resp.status_code == 200
    viewer_empty = _element(viewer_resp.text, "ca-empty")
    assert viewer_empty.found is True
    assert "/ca/new" not in viewer_empty.anchor_hrefs
    assert "/transfer/ca-import" not in viewer_empty.anchor_hrefs


# === AC-2: the detail page is one hierarchy, named by its root =============


def test_ca_detail_shows_only_its_own_hierarchy(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, beta_root, beta_int = _seed_two_hierarchies(cfg)
    alpha_root_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_root))
    beta_root_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_root))
    alpha_int_fingerprint = _fingerprint(_cert_pem_of(cfg, alpha_int))
    beta_int_fingerprint = _fingerprint(_cert_pem_of(cfg, beta_int))

    alpha_page = client.get(f"/ca/{alpha_root}")
    assert alpha_page.status_code == 200
    assert "alpha" in alpha_page.text
    assert alpha_root_fingerprint in alpha_page.text
    # spec 0024 FR-1: alpha and beta's rows are no longer distinguished by a
    # " Intermediate CA" suffix (both hierarchies are literally named just
    # "alpha"/"beta" now), so cross-hierarchy isolation is checked against
    # beta's own unambiguous values rather than a marker string that no
    # longer exists. The root fingerprint alone is not a sufficient check:
    # `_group` takes its root row straight from its own `root` argument, so
    # a bug that drops the `parent_id == root.id` filter on `_group`'s
    # intermediate list would leak beta's INTERMEDIATE onto alpha's page
    # while beta's root fingerprint stayed correctly absent.
    #
    # spec 0026: the field that moves when that filter breaks is no longer
    # the intermediate's fingerprint -- no fingerprint but the root's own is
    # on this page any more (FR-2) -- but the row's LINK, which names both
    # the hierarchy and the row. The fingerprint half of this test moves to
    # the two issuer pages below, keeping the requirement it was written for.
    assert beta_root_fingerprint not in alpha_page.text
    assert f'href="/ca/{alpha_root}/issuer/{alpha_int}"' in alpha_page.text
    assert f"/issuer/{beta_int}" not in alpha_page.text

    beta_page = client.get(f"/ca/{beta_root}")
    assert beta_page.status_code == 200
    assert "beta" in beta_page.text
    assert beta_root_fingerprint in beta_page.text
    assert alpha_root_fingerprint not in beta_page.text
    assert f'href="/ca/{beta_root}/issuer/{beta_int}"' in beta_page.text
    assert f"/issuer/{alpha_int}" not in beta_page.text

    # ...and each intermediate's own page carries its own fingerprint and
    # not the other hierarchy's.
    alpha_issuer = client.get(f"/ca/{alpha_root}/issuer/{alpha_int}")
    assert alpha_issuer.status_code == 200
    assert alpha_int_fingerprint in alpha_issuer.text
    assert beta_int_fingerprint not in alpha_issuer.text

    beta_issuer = client.get(f"/ca/{beta_root}/issuer/{beta_int}")
    assert beta_issuer.status_code == 200
    assert beta_int_fingerprint in beta_issuer.text
    assert alpha_int_fingerprint not in beta_issuer.text


def test_ca_detail_404_for_a_non_root_id(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    alpha_root, alpha_int, _beta_root, _beta_int = _seed_two_hierarchies(cfg)
    _ = alpha_root

    # named by an intermediate id -- FR-3: a hierarchy is named by its root
    assert client.get(f"/ca/{alpha_int}").status_code == 404
    # an id no row has at all
    assert client.get("/ca/999999").status_code == 404


# === FR-8: a refused intermediate keeps what was typed, visibly ============


def test_intermediate_error_refills_the_form(client: TestClient, cfg: Config) -> None:
    """The defect FR-8 guards against: a refused submission must not lose
    what the operator typed. Spec 0024 moved this form out of a collapsible
    `<details>` into its own open `.section` (FR-10), so there is no longer
    a wrapper to assert `open` on -- only the re-fill itself, which is what
    this test was written for."""
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
    # A leading "\n" is HTML boilerplate right after <textarea> (the
    # template writes the Jinja expression on its own line so browsers,
    # which swallow exactly one leading newline there, never show a blank
    # first row); html.parser does not swallow it, so strip it here too.
    assert block.textarea_values.get("permitted_names", "").strip() == "not a name constraint!!"
    assert block.textarea_values.get("excluded_names", "").strip() == "shadow.example.com"

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
    assert _marked_labels(import_resp.text) == ["Import a CA"]
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
    assert _marked_labels(cross_import_resp.text) == ["Import a cross certificate"]
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
    assert "alpha" in viewer_page.text
    assert _form_actions(viewer_page.text) == ["/logout"]

    # spec 0026: "a viewer can read the hierarchy in full" was measured on
    # the CRL URL, which is no longer on the root page (FR-2) -- it moved,
    # with everything else about an intermediate, onto that intermediate's
    # own page. Both halves follow it there: the URL is readable, and that
    # page carries no form either.
    expected_crl_url = f"http://ca.example.org/crl/{alpha_int}"
    viewer_issuer = client.get(f"/ca/{alpha_root}/issuer/{alpha_int}")
    assert viewer_issuer.status_code == 200
    assert f'href="{expected_crl_url}"' in viewer_issuer.text  # readable, not gated
    assert _form_actions(viewer_issuer.text) == ["/logout"]


def test_viewer_rail_has_no_ca_new_or_ca_import(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_viewer(client, cfg)
    _login(client, "vera", "whatever12345")

    assert client.get("/ca/new").status_code == 403
    assert client.get("/transfer/ca-import").status_code == 403

    rail = client.get("/ca").text
    assert 'href="/ca"' in rail
    assert 'href="/ca/new"' not in rail
    assert 'href="/transfer/ca-import"' not in rail


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
    # FR-2: GET /ca/import is gone -- POST /ca/import still lives at this
    # exact path. The right answer is 405 (no GET handler), never a 422 from
    # the detail route's int conversion swallowing the literal path, which
    # is exactly the shape the 0017 /crl/7.pem bug had.
    assert client.get("/ca/import").status_code == 405

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
    assert 'href="/transfer/ca-import"' in new_page

    # FR-2 split the one import page in two -- each owns exactly its own
    # form now, not both.
    import_page = client.get("/transfer/ca-import").text
    assert "/ca/import" in _form_actions(import_page)
    assert "/ca/cross-import" not in _form_actions(import_page)
    assert "/ca/create" not in _form_actions(import_page)
    assert 'href="/ca/new"' in import_page

    cross_import_page = client.get("/transfer/cross-import").text
    assert "/ca/cross-import" in _form_actions(cross_import_page)
    assert "/ca/import" not in _form_actions(cross_import_page)
    assert "/ca/create" not in _form_actions(cross_import_page)

    # neither the list nor a detail page carries any of the three forms
    list_page = client.get("/ca").text
    assert "/ca/create" not in _form_actions(list_page)
    assert "/ca/import" not in _form_actions(list_page)
    assert "/ca/cross-import" not in _form_actions(list_page)
    detail_page = client.get(f"/ca/{alpha_root}").text
    assert "/ca/create" not in _form_actions(detail_page)
    assert "/ca/import" not in _form_actions(detail_page)
    assert "/ca/cross-import" not in _form_actions(detail_page)

    templates_dir = Path(__file__).resolve().parents[1] / "src/cabin/web/templates"
    assert not (templates_dir / "ca_setup.html").exists()
