"""Web-layer tests for spec 0004 FR-5/FR-6 (AC-1, AC-4, AC-5) and spec 0017
FR-14 (AC-11, AC-12, AC-13): the /ca page as a list of hierarchies, per-row
actions, and role/CSRF guards on all of them.

Route contract this file exercises (spec 0017 FR-10/FR-14, no route names
are fixed by the spec text itself, so they are fixed here instead):
  - POST /ca/create                     unchanged: a further hierarchy, not
                                         "the" hierarchy (FR-2 deletes
                                         CAExistsError).
  - POST /ca/import                     unchanged.
  - POST /ca/{root_id}/intermediate     create a further intermediate under
                                         an existing root (FR-3 rotation).
  - POST /ca/{ca_id}/renew              renew a row in place (FR-5).
  - POST /ca/{ca_id}/retire             retire a row (FR-4).
  - GET  /ca/{ca_id}.pem                one certificate, authenticated
                                         (replaces /ca/root.pem).
  - GET  /ca/{issuer_id}/chain.pem      issuer + ancestors, root last,
                                         authenticated (replaces
                                         /ca/chain.pem).
"""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.acme import http as acme_http
from cabin.app import create_app
from cabin.ca import crl as crl_service
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca.service import signing_credentials
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import TLS_ISSUER_ID, set_setting
from cabin.store import create_session_factory


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


def _create_user_as_superadmin(client: TestClient, cfg: Config, username: str, role: str) -> None:
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


def _last_root_id(cfg: Config) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(
            select(ca_service.CACertificate)
            .where(ca_service.CACertificate.kind == "root")
            .order_by(ca_service.CACertificate.id.desc())
        ).first()
        assert row is not None, "no root row exists"
        return row.id
    finally:
        db.close()


def _create_ca(client: TestClient, cfg: Config, name: str = "cabin") -> None:
    """``POST /ca/create`` then ``POST /ca/{root_id}/intermediate`` -- the
    two steps spec 0024 FR-3 split a single create into (FR-11).

    Root and intermediate are given distinct literal names (``name`` with
    " Root CA"/" Intermediate CA" appended by *this test file*, not by
    production) so this file's many ``_by_name(cfg, "... Root CA")``-style
    lookups keep finding exactly one row each.
    """
    resp = client.post(
        "/ca/create",
        data={
            "name": f"{name} Root CA",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    root_id = _last_root_id(cfg)
    resp = client.post(
        f"/ca/{root_id}/intermediate",
        data={
            "name": f"{name} Intermediate CA",
            "key_type": "ecdsa-p256",
            "years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def _pem_key_str(key: object, *, password: bytes | None = None) -> str:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


def _pem_cert_str(cert: object) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]


def _rows(cfg: Config) -> list[ca_service.CACertificate]:
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        for row in rows:
            _ = row.id, row.kind, row.name, row.status, row.parent_id  # detach-safe read
        db.expunge_all()
        return rows
    finally:
        db.close()


def _by_name(cfg: Config, name: str) -> ca_service.CACertificate:
    matches = [row for row in _rows(cfg) if row.name == name]
    assert len(matches) == 1, f"expected exactly one row named {name!r}, got {len(matches)}"
    return matches[0]


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


def _row(html: str, marker: str, *, class_name: str | None = None, tag: str = "div") -> str:
    """The full outer HTML of the innermost ``<tag class="class_name">``
    element that contains ``marker``'s first occurrence -- scoped by parsing
    the actual tag nesting, not by slicing a fixed number of characters
    after the marker. A row's markup can grow or shrink for any reason (a
    class added, a hint reworded) without ever moving what a test measures,
    and there is no fixed budget for the next change to silently exceed.

    ``class_name`` is optional (spec 0026): a ``<tr>`` in one of the two new
    hierarchy tables carries no class of its own -- giving it one would put a
    selector in the stylesheet that the both-directions test would then
    require to be used and styled -- so a table row is scoped by its tag plus
    a marker inside it instead.
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
            matches_class = class_name is None or (
                classes is not None and class_name in classes.group(1).split()
            )
            if open_name == tag and matches_class:
                return html[open_start : m.end()]
    raise AssertionError(f"no <{tag} class={class_name!r}> element wraps {marker!r}")


# --- FR-2/FR-14: a further hierarchy is ordinary operation, not an error ----


def test_ca_wizard_ui_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    # dashboard hints at /ca before any CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" in resp.text

    # spec 0023: /ca no longer carries the create/import forms itself. What
    # its empty state has to promise instead (FR-10) is that an operator
    # with no CA is pointed somewhere they can make one -- the two pages
    # that now own those forms.
    resp = client.get("/ca")
    assert resp.status_code == 200
    empty_state = _row(resp.text, "No hierarchy exists yet.", class_name="note", tag="p")
    assert '<a href="/ca/new">' in empty_state
    assert '<a href="/transfer/ca-import">' in empty_state

    _create_ca(client, cfg, "cabin")

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "cabin Root CA" in resp.text
    # the empty state's promise is gone once a hierarchy actually exists
    assert 'id="ca-empty"' not in resp.text

    # the intermediate itself lives on the hierarchy's own detail page now.
    # (Spec 0028 FR-5 makes `/ca` a grouped list, so the parenthetical this
    # comment used to carry -- "which shows only root rows and counts" -- is
    # no longer true; the requirement this test protects is unchanged and no
    # assertion in it moves. What `/ca` groups is
    # `test_ca_list_groups_issuers_under_their_own_root`'s subject.)
    detail = client.get(f"/ca/{_by_name(cfg, 'cabin Root CA').id}")
    assert detail.status_code == 200
    assert "cabin Intermediate CA" in detail.text

    # the dashboard hint is gone once a CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" not in resp.text

    # FR-2: CAExistsError is deleted -- a second hierarchy is ordinary
    # operation, not a 409. Both coexist afterward, at the DB and on the page.
    _create_ca(client, cfg, "again")

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "cabin Root CA" in resp.text
    assert "again Root CA" in resp.text

    roots = [row for row in _rows(cfg) if row.kind == "root"]
    assert len(roots) == 2
    assert {row.name for row in roots} == {"cabin Root CA", "again Root CA"}


# --- AC-12: /ca groups every row under its root, with its status -----------


def test_ca_page_lists_hierarchies(client: TestClient, cfg: Config) -> None:
    """AC-12, carried over for spec 0023 (FR-2/FR-3): /ca lists every root,
    and each root's own detail page carries the rest of its own hierarchy --
    and, now that each hierarchy has its own page, none of any other
    hierarchy at all. That is the strict form the old "grouped under its
    own root, not interleaved with the next one" check takes once grouping
    means "on this page" rather than "in this order on a shared one".
    """
    _setup_superadmin(client)
    _create_ca(client, cfg, "alpha")
    _create_ca(client, cfg, "beta")

    overview = client.get("/ca")
    assert overview.status_code == 200
    for name in ("alpha Root CA", "beta Root CA"):
        assert name in overview.text, name

    alpha_root = _by_name(cfg, "alpha Root CA")
    beta_root = _by_name(cfg, "beta Root CA")

    alpha_html = client.get(f"/ca/{alpha_root.id}").text
    assert "alpha Root CA" in alpha_html
    assert "alpha Intermediate CA" in alpha_html
    assert "beta Root CA" not in alpha_html
    assert "beta Intermediate CA" not in alpha_html

    beta_html = client.get(f"/ca/{beta_root.id}").text
    assert "beta Root CA" in beta_html
    assert "beta Intermediate CA" in beta_html
    assert "alpha Root CA" not in beta_html
    assert "alpha Intermediate CA" not in beta_html

    # retire beta's intermediate directly (bypassing the HTTP action, since
    # this test is about what the page *shows*, not the action itself) and
    # confirm the status is attached to the right row, not sprayed globally.
    db = _db(cfg)
    try:
        beta_intermediate = next(
            r
            for r in ca_service.list_cas(db, kind="intermediate")
            if r.name == "beta Intermediate CA"
        )
        beta_intermediate.status = "retired"
        db.commit()
    finally:
        db.close()

    # spec 0026: an intermediate is a row in its hierarchy's Issuers table,
    # not a `.section` of its own. The requirement is unchanged -- a status
    # belongs to the row it is rendered on rather than being sprayed across
    # the page -- so the block scoped is now that intermediate's `<tr>`,
    # found by the link in its name cell (rows carry no class).
    beta_intermediate_id = _by_name(cfg, "beta Intermediate CA").id
    alpha_intermediate_id = _by_name(cfg, "alpha Intermediate CA").id
    beta_window = _row(
        client.get(f"/ca/{beta_root.id}").text,
        f'href="/ca/{beta_root.id}/issuer/{beta_intermediate_id}"',
        tag="tr",
    )
    alpha_window = _row(
        client.get(f"/ca/{alpha_root.id}").text,
        f'href="/ca/{alpha_root.id}/issuer/{alpha_intermediate_id}"',
        tag="tr",
    )
    assert "retired" in beta_window.lower()
    assert "retired" not in alpha_window.lower()


# --- spec 0028 FR-5/FR-17: /ca is the grouped list -------------------------


def _grouped_rows(html: str) -> list[tuple[list[str], str]]:
    """Every `<tr>` in the page's `<tbody>`, as `(class tokens, outer HTML)`.

    Document order is the whole point: a build that renders every issuer in
    one block at the bottom of the table puts the same names and the same
    links on the page and is caught by nothing else.
    """
    body = re.search(r"<tbody\b[^>]*>(.*?)</tbody>", html, re.S)
    assert body is not None, "the page carries no <tbody> -- no table was rendered"
    rows = re.findall(r"<tr\b[^>]*>.*?</tr>", body.group(1), re.S)
    return [(_row_classes(row), row) for row in rows]


def _row_classes(row_html: str) -> list[str]:
    found = re.search(r'<tr\b[^>]*class="([^"]*)"', row_html)
    return found.group(1).split() if found is not None else []


def test_ca_list_groups_issuers_under_their_own_root(client: TestClient, cfg: Config) -> None:
    """FR-5 supersedes spec 0026's Out of Scope clause "No change to /ca's
    list."

    `/ca` today answers "which hierarchies exist" and makes the operator open
    a root to find out what can actually sign. Every issuance, every ACME
    directory and every grant is named by an *issuer*, so the list names
    both.

    The children are checked by **position**, not by presence: every name and
    every link would still be somewhere on the page if they were all rendered
    under the wrong root, or in one block at the bottom.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg, "alpha")
    _create_ca(client, cfg, "beta")
    # a root with no issuer at all: FR-5 gives it a row in place of the
    # children rather than nothing, and its count column still reads 0.
    assert (
        client.post(
            "/ca/create",
            data={
                "name": "solo Root CA",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )

    resp = client.get("/ca")
    assert resp.status_code == 200
    rows = _grouped_rows(resp.text)

    expected: list[tuple[int, list[int]]] = []
    for row in _rows(cfg):
        if row.kind == "root":
            expected.append((row.id, []))
    for row in _rows(cfg):
        if row.kind == "intermediate":
            parent = next(group for group in expected if group[0] == row.parent_id)
            parent[1].append(row.id)
    assert [len(children) for _root, children in expected] == [1, 1, 0], expected

    assert any("row-root" in classes for classes, _html in rows), (
        f"no row on /ca carries .row-root, so the list is not grouped at all "
        f"(FR-5): {[classes for classes, _html in rows]}"
    )

    grouped: list[tuple[int, list[int]]] = []
    empty_states: dict[int, str] = {}
    for classes, row_html in rows:
        hrefs = re.findall(r'href="([^"]*)"', row_html)
        if "row-root" in classes:
            root_href = next(h for h in hrefs if re.fullmatch(r"/ca/\d+", h))
            grouped.append((int(root_href.rsplit("/", 1)[1]), []))
        elif "row-child" in classes:
            assert grouped, "a child row was rendered before any root row"
            issuer_href = next(h for h in hrefs if "/issuer/" in h)
            root_id, issuer_id = (int(part) for part in re.findall(r"\d+", issuer_href))
            assert root_id == grouped[-1][0], (
                f"{issuer_href} is rendered under the root {grouped[-1][0]}, which is "
                f"not the root it belongs to"
            )
            grouped[-1][1].append(issuer_id)
            assert client.get(issuer_href).status_code == 200, issuer_href
        else:
            assert grouped, f"a row belongs to no group: {row_html!r}"
            empty_states[grouped[-1][0]] = row_html

    assert grouped == expected, (
        f"the grouped list is not the hierarchy: rendered {grouped}, the database has {expected}"
    )

    solo_id = expected[-1][0]
    assert set(empty_states) == {solo_id}, sorted(empty_states)
    assert "This hierarchy has no issuer yet, so nothing can be signed under it." in re.sub(
        r"\s+", " ", empty_states[solo_id]
    ), empty_states[solo_id]

    headers = re.findall(r"<th\b[^>]*>(.*?)</th>", resp.text, re.S)
    headers = [re.sub(r"<[^>]+>", "", head).strip() for head in headers]
    assert headers == ["Name", "Status", "Expires", "Intermediates", "Cross certificates"], headers
    counts_column = headers.index("Intermediates")
    status_column = headers.index("Status")
    for (root_id, children), (classes, row_html) in zip(
        grouped, [row for row in rows if "row-root" in row[0]], strict=True
    ):
        assert "row-root" in classes
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, re.S)
        assert len(cells) == len(headers), f"root {root_id} has {len(cells)} cells: {cells}"
        assert re.sub(r"<[^>]+>", "", cells[counts_column]).strip() == str(len(children)), (
            f"root {root_id} counts {cells[counts_column]!r} intermediates and has "
            f"{len(children)} rows under it"
        )

    # FR-5: a child row carries its own status, and `/ca` is where an
    # operator looks to see what is active. Asserted by effect -- one issuer
    # is retired through the real door and the page is read again -- and in
    # both directions, because a build that marks every row retired and a
    # build that marks none would each satisfy one half alone.
    alpha_issuer = _by_name(cfg, "alpha Intermediate CA")
    retire = client.post(
        f"/ca/{alpha_issuer.id}/retire",
        data={"confirm": "on", "csrf_token": _csrf(client, cfg)},
    )
    assert retire.status_code == 303, retire.text

    after = client.get("/ca")
    assert after.status_code == 200
    marked: dict[int, str] = {}
    for classes, row_html in _grouped_rows(after.text):
        if "row-child" not in classes:
            continue
        issuer_href = next(h for h in re.findall(r'href="([^"]*)"', row_html) if "/issuer/" in h)
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, re.S)
        assert len(cells) == len(headers), (
            f"a child row has {len(cells)} cells and the table has {len(headers)} "
            f"columns, so its Status column is not where the heading says it is: "
            f"{row_html!r}"
        )
        marked[int(issuer_href.rsplit("/", 1)[1])] = cells[status_column]

    assert set(marked) == {issuer for _root, issuers in expected for issuer in issuers}
    retired_cell = marked.pop(alpha_issuer.id)
    tags = re.findall(r'<span class="([^"]*)"[^>]*>(.*?)</span>', retired_cell, re.S)
    assert [text.strip() for classes, text in tags if "tag-bad" in classes.split()] == [
        "retired"
    ], (
        f"the retired issuer's row on /ca does not say so: {retired_cell!r}. A retired "
        f"issuer that looks live on this page is how someone signs against the wrong "
        f"hierarchy, or believes they cannot sign at all (FR-5)"
    )
    for issuer_id, cell in sorted(marked.items()):
        assert "retired" not in re.sub(r"<[^>]+>", " ", cell).lower(), (
            f"issuer {issuer_id} is active and its row on /ca reads {cell!r} -- the "
            f"status is being sprayed across the list rather than read off the row"
        )
        assert "active" in re.sub(r"<[^>]+>", " ", cell).lower(), (
            f"issuer {issuer_id} shows no status at all: {cell!r}"
        )


def test_ca_list_makes_no_per_issuer_lookups(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-17: spec 0026 FR-12's work bound follows the component to `/ca`.

    Measured at the call, because the markup is identical either way: the
    obvious way to get a name, a status and an expiry for an intermediate is
    `_row_view`, which makes three URL lookups and a constraints parse per row
    that nothing on this page displays.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg, "alpha")
    _create_ca(client, cfg, "beta")
    assert (
        client.post(
            f"/ca/{_by_name(cfg, 'alpha Root CA').id}/intermediate",
            data={
                "name": "alpha Second Intermediate CA",
                "key_type": "ecdsa-p256",
                "years": 10,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )

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

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert calls == {}, f"/ca did work its output does not need: {calls}"

    # ...and a build that renders no children at all cannot pass by doing no
    # work: the three issuers are on the page. Without this clause the
    # assertion above is satisfied perfectly by the list as it stands today.
    issuer_links = re.findall(r'href="/ca/\d+/issuer/\d+"', resp.text)
    assert len(issuer_links) == 3, (
        f"/ca links to {len(issuer_links)} issuers, not the three this instance has: {issuer_links}"
    )


# --- AC-12: create-intermediate/renew/retire need admin role + CSRF --------


def test_ca_actions_require_admin_and_csrf(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")

    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    admin_csrf = _csrf(client, cfg)

    routes = (
        (f"/ca/{root.id}/intermediate", {"name": "second", "key_type": "ecdsa-p256", "years": 5}),
        (f"/ca/{root.id}/renew", {"years": 25}),
        (f"/ca/{intermediate.id}/retire", {}),
    )

    # admin, missing CSRF -> 403, nothing about the CSRF guard depends on
    # whether the action would otherwise have succeeded
    for path, data in routes:
        resp = client.post(path, data=data)
        assert resp.status_code == 403, path

    # admin, wrong CSRF -> 403
    for path, data in routes:
        resp = client.post(path, data={**data, "csrf_token": "not-the-token"})
        assert resp.status_code == 403, path

    # viewer, correct-for-admin CSRF is not even the viewer's own -> log in
    # as viewer and use its own (valid) session/csrf, still 403 on role
    client.cookies.clear()
    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    viewer_csrf = _csrf(client, cfg)
    for path, data in routes:
        resp = client.post(path, data={**data, "csrf_token": viewer_csrf})
        assert resp.status_code == 403, path

    # sanity: admin_csrf was a real token (used nowhere above on purpose,
    # since every case above must fail before reaching the domain layer)
    assert admin_csrf


# --- AC-13: unavailable actions are not offered, not a 500 button ----------


def test_ca_page_hides_unavailable_actions_for_imported_root(
    client: TestClient, cfg: Config
) -> None:
    """An imported root has no stored private key (key_sealed is NULL by
    design), so it cannot sign a further intermediate and cannot renew
    itself. The page must not offer those actions for it -- the negative
    alone proves nothing, so a generated root's row must still offer both."""
    _setup_superadmin(client)

    # a generated hierarchy: both actions must be offered for its root
    _create_ca(client, cfg, "generated")
    generated_root = _by_name(cfg, "generated Root CA")

    # an imported hierarchy: the imported ROOT (the chain_pem parent) never
    # gets a key_sealed value (ca/service.py's import_hierarchy stores it as
    # None) -- that is the row whose actions must disappear.
    root_cert, root_key = create_root("Imported Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Imported Intermediate CA", "ecdsa-p256"
    )
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key),
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    imported_root = _by_name(cfg, "Imported Root CA")
    assert imported_root.key_sealed is None  # the premise this test measures

    generated_html = client.get(f"/ca/{generated_root.id}").text
    imported_html = client.get(f"/ca/{imported_root.id}").text
    # the root's name also appears in <title> and <h1>, outside the section
    # -- its own <h2> (spec 0023's per-hierarchy page) is what is actually
    # scoped to the section this test measures.
    generated_window = _row(generated_html, "<h2>generated Root CA</h2>", class_name="section")
    # spec 0024 FR-8: "Add intermediate" is its own headed section now, a
    # sibling of the root's rather than nested inside it -- scoped to that
    # section on its own, not to the root's.
    # spec 0029 FR-13 re-points this one window. The requirement is unchanged
    # -- a root cabin holds a key for offers the intermediate form, an
    # imported one does not -- but the form now stands at `?add=intermediate`,
    # so the positive half is read there. The negative half below stays on the
    # plain page and is *stronger* for it: `can_create_intermediate` is false
    # for an imported root, so its whole section is omitted in both states,
    # and the heading's absence is what proves it rather than the form's.
    generated_open = client.get(f"/ca/{generated_root.id}?add=intermediate").text
    generated_create_window = _row(generated_open, "Add intermediate", class_name="section")
    # spec 0028 FR-4: the root's renew and retire forms are their own headed
    # section, last on the page, rather than the tail of the root's identity
    # block. The requirement here has not moved -- an imported root offers no
    # renew -- so the scoping follows the form rather than becoming a
    # page-wide search, which would pass on a build that offered the form
    # somewhere else entirely.
    generated_renew_window = _row(generated_html, "<h2>Renew and retire</h2>", class_name="section")
    imported_renew_window = _row(imported_html, "<h2>Renew and retire</h2>", class_name="section")

    create_intermediate_url = f"/ca/{generated_root.id}/intermediate"
    renew_url = f"/ca/{generated_root.id}/renew"
    assert create_intermediate_url in generated_create_window
    assert renew_url in generated_renew_window
    assert renew_url not in generated_window, (
        "the renew form is still inside the root's identity section (spec 0028 FR-4)"
    )

    blocked_create_url = f"/ca/{imported_root.id}/intermediate"
    blocked_renew_url = f"/ca/{imported_root.id}/renew"
    # can_create_intermediate is False, so the whole section -- heading
    # included -- is omitted rather than merely emptied.
    assert "Add intermediate" not in imported_html
    assert blocked_create_url not in imported_html
    # ...and asking for it by URL does not conjure it either (spec 0029
    # FR-13): `open_form` comes from the query string now, so "the section is
    # omitted" has to hold at the URL that opens it as well.
    imported_open = client.get(f"/ca/{imported_root.id}?add=intermediate").text
    assert "Add intermediate" not in imported_open
    assert blocked_create_url not in imported_open
    assert blocked_renew_url not in imported_renew_window
    # ...and nowhere else on the page either: the section moved, so an
    # absence scoped to one block no longer says much on its own.
    assert blocked_renew_url not in imported_html
    # The section itself is there and does carry the imported root's other
    # control, so this is an absence inside a block that exists rather than
    # the absence of the block.
    assert f"/ca/{imported_root.id}/retire" in imported_renew_window


# --- AC-11: root path_length is bounded, and the default is unchanged ------


def test_root_path_length_bounds_rejected(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    for bad in (0, 5):
        resp = client.post(
            "/ca/create",
            data={
                "name": "cabin",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "path_length": bad,
                "csrf_token": csrf,
            },
        )
        assert resp.status_code == 400, bad
    assert _rows(cfg) == []  # no row written by either rejected attempt

    # omitted entirely -> default stays 1
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    root = _by_name(cfg, "cabin")
    cert = x509.load_pem_x509_certificate(root.cert_pem.encode("ascii"))
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.path_length == 1


# --- AC-5 (spec 0004)/FR-10: PEM downloads ----------------------------------


def test_ca_downloads_pem(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")

    resp = client.get(f"/ca/{root.id}.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=cabin Root CA"

    resp = client.get(f"/ca/{intermediate.id}/chain.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    # nearest issuer first, root last (FR-2 chain_for)
    assert len(chain_certs) == 2
    assert chain_certs[0].subject.rfc4514_string() == "CN=cabin Intermediate CA"
    assert chain_certs[1].subject.rfc4514_string() == "CN=cabin Root CA"


def test_ca_downloads_404_for_unknown_id(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert client.get("/ca/999999.pem").status_code == 404
    assert client.get("/ca/999999/chain.pem").status_code == 404


# --- AC-5: viewer read-only ----------------------------------------------------


def test_viewer_readonly_on_ca(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")
    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    client.cookies.clear()

    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    viewer_csrf = _csrf(client, cfg)

    # viewer can GET everything under /ca
    assert client.get("/ca").status_code == 200
    assert client.get(f"/ca/{root.id}.pem").status_code == 200
    assert client.get(f"/ca/{intermediate.id}/chain.pem").status_code == 200

    # but mutating POSTs are 403
    resp = client.post(
        "/ca/create",
        data={
            "name": "x",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": "irrelevant",
            "key_pem": "irrelevant",
            "chain_pem": "irrelevant",
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403


# --- AC-3/FR-3 (spec 0004): import happy path (encrypted key, root key absent) --


def test_ca_import_happy_path_web_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Import Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Import Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"import-passphrase"),
            "key_passphrase": "import-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/ca"

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "Import Root CA" in resp.text

    root = _by_name(cfg, "Import Root CA")
    intermediate = _by_name(cfg, "Import Intermediate CA")

    # the intermediate itself lives on the hierarchy's own detail page now,
    # not on the /ca overview (which shows only root rows and counts).
    detail = client.get(f"/ca/{root.id}")
    assert detail.status_code == 200
    assert "Import Root CA" in detail.text
    assert "Import Intermediate CA" in detail.text

    assert root.key_sealed is None  # FR-3: root key absent on import
    assert intermediate.key_sealed is not None

    db = _db(cfg)
    try:
        secrets = SecretStore.open(cfg.data_dir, None)
        cert, key = signing_credentials(db, secrets, intermediate.id)
        message = b"web-import-roundtrip"
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
        cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))  # no exception
    finally:
        db.close()


# --- AC-5 (spec 0004): import must not leak a chain_pem bundle/preamble ----


def test_ca_import_root_pem_is_clean_despite_bundle_and_preamble(
    client: TestClient, cfg: Config
) -> None:
    """chain_pem may arrive as an openssl-style dump (subject=/issuer= text
    before the PEM block) or as a multi-cert bundle; either way, the root
    download must serve exactly one clean certificate and the chain exactly
    two."""
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Junky Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Junky Intermediate CA", "ecdsa-p256"
    )
    unrelated_cert, _unrelated_key = create_root("Unrelated CA", "ecdsa-p256")
    junky_chain_pem = (
        "subject=CN=Junky Root CA\nissuer=CN=Junky Root CA\n"
        + _pem_cert_str(root_cert)
        + _pem_cert_str(unrelated_cert)
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key),
            "chain_pem": junky_chain_pem,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303

    root = _by_name(cfg, "Junky Root CA")
    intermediate = _by_name(cfg, "Junky Intermediate CA")

    resp = client.get(f"/ca/{root.id}.pem")
    assert resp.status_code == 200
    assert resp.content.decode("ascii").strip().startswith("-----BEGIN CERTIFICATE-----")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=Junky Root CA"

    resp = client.get(f"/ca/{intermediate.id}/chain.pem")
    assert resp.status_code == 200
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(chain_certs) == 2


# --- FR-6/FR-14: year-range and key-type validation re-render the wizard ---


def test_ca_create_invalid_years_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 100,  # out of range: max is 50
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "root_years" in resp.text
    assert "Create a new CA" in resp.text  # re-rendered wizard, not a JSON error body

    assert _rows(cfg) == []


def test_ca_create_invalid_key_type_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "dsa-1024",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "key_type" in resp.text

    assert _rows(cfg) == []


# --- FR-2/AC-3 (spec 0004): import failure path re-renders the wizard ------


def test_ca_import_wrong_passphrase_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Wrong Passphrase Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Wrong Passphrase Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"correct-passphrase"),
            "key_passphrase": "wrong-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "decrypt" in resp.text.lower()


# --- spec 0022 FR-17: retiring cabin's own bound TLS issuer is refused -----
#
# FR-17: "Retiring the bound issuer is refused while TLS is on. ... The
# check must cover the cascade: retiring a root also retires its
# intermediates, so it tests the whole set that would be stood down, not
# just the named row. ... With TLS off there is no refusal at all."
#
# Not implemented yet on this branch: verified by hand that with TLS on,
# two active issuers and one bound via ``tls_issuer_id``, POST
# ``/ca/{bound}/retire`` returns 303 and the row is retired. These four
# tests are expected to be RED until the guard lands in
# ``web/ca_ui.py``'s retire route.


def make_tls_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)


@pytest.fixture
def tls_cfg(tmp_path: Path) -> Config:
    return make_tls_config(tmp_path)


@pytest.fixture
def tls_client(tls_cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(tls_cfg), follow_redirects=False) as c:
        yield c


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _bind_tls_issuer(cfg: Config, ca_id: int) -> None:
    db = _db(cfg)
    try:
        set_setting(db, TLS_ISSUER_ID, str(ca_id))
        db.commit()
    finally:
        db.close()


def _two_hierarchies(cfg: Config) -> tuple[int, int, int, int]:
    """Two independent, active hierarchies (ids only: root_a,
    intermediate_a, root_b, intermediate_b), created directly through
    ``ca_service`` rather than the HTTP wizard -- what matters here is the
    retire route, not the create flow. Two hierarchies rather than one so
    that retiring either issuer always leaves an active one elsewhere: the
    pre-existing "would leave no active issuer" invariant
    (``ca/service.retire``) never fires on its own, and every retire in the
    tests below can only be blocked -- or not -- by FR-17's bound-issuer
    check, nothing else.
    """
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        alpha = ca_service.create_hierarchy(db, secrets, "alpha", "alpha intermediate")
        beta = ca_service.create_hierarchy(db, secrets, "beta", "beta intermediate")
        return alpha.root.id, alpha.intermediate.id, beta.root.id, beta.intermediate.id
    finally:
        db.close()


def _status_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).status
    finally:
        db.close()


def test_retire_bound_tls_issuer_is_refused(tls_client: TestClient, tls_cfg: Config) -> None:
    """Retiring the issuer bound to cabin's own TLS certificate, directly by
    its own id, must be refused while TLS is on."""
    _setup_superadmin(tls_client)
    _root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(
        f"/ca/{intermediate_a}/retire", data={"confirm": "on", "csrf_token": csrf}
    )

    assert resp.status_code == 400, resp.text
    assert _status_of(tls_cfg, intermediate_a) == "active"


def test_retire_root_of_bound_tls_issuer_is_refused_via_cascade(
    tls_client: TestClient, tls_cfg: Config
) -> None:
    """The bound issuer is alpha's INTERMEDIATE; this retires alpha's ROOT,
    whose cascade (``ca_service.retire_targets``) would stand the bound
    intermediate down too. The id named in the URL is never itself the
    bound row, so a guard that only compares the URL's ``ca_id`` against
    the binding -- instead of the whole cascade -- would let this through.
    Refused, and neither row changes status.
    """
    _setup_superadmin(tls_client)
    root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(f"/ca/{root_a}/retire", data={"confirm": "on", "csrf_token": csrf})

    assert resp.status_code == 400, resp.text
    assert _status_of(tls_cfg, root_a) == "active"
    assert _status_of(tls_cfg, intermediate_a) == "active"


def test_retire_bound_tls_issuer_succeeds_when_tls_is_off(client: TestClient, cfg: Config) -> None:
    """The identical binding, the identical retirement -- but TLS is off, so
    the binding is inert and must not obstruct an installation that does
    not use cabin's own TLS (FR-17: "With TLS off there is no refusal at
    all"). Without this counter-check, a guard that simply refuses every
    retirement regardless of ``config.tls`` would pass the two tests above.
    """
    _setup_superadmin(client)
    _root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(cfg)
    _bind_tls_issuer(cfg, intermediate_a)
    csrf = _csrf(client, cfg)

    resp = client.post(f"/ca/{intermediate_a}/retire", data={"confirm": "on", "csrf_token": csrf})

    assert resp.status_code == 303, resp.text
    assert _status_of(cfg, intermediate_a) == "retired"


def test_retire_non_bound_issuer_succeeds_while_tls_is_on(
    tls_client: TestClient, tls_cfg: Config
) -> None:
    """TLS is on and an issuer IS bound, but this retires the OTHER active
    issuer -- not the bound one and not its root. FR-17's refusal must not
    spill over onto issuers the binding has nothing to do with."""
    _setup_superadmin(tls_client)
    _root_a, intermediate_a, _root_b, intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(
        f"/ca/{intermediate_b}/retire", data={"confirm": "on", "csrf_token": csrf}
    )

    assert resp.status_code == 303, resp.text
    assert _status_of(tls_cfg, intermediate_b) == "retired"
    assert _status_of(tls_cfg, intermediate_a) == "active"
