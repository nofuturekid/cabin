"""Spec 0030: the flash message, the "Not permitted" page and the boundary
between the interface and the three other front doors.

Four things in this file are worth knowing before reading it.

**The flash is popped on render, so the assertion that matters is the second
one.** An implementation that sets the column to ``None`` on the in-memory
row and never commits passes every in-process check that reads the object it
just wrote. AC-1 therefore renders the page twice and reads the column back
out of the database in between, and it is clause 5 -- the *second* render
showing nothing -- that catches the missing commit.

**The JSON half of AC-5 is measured against an application built without the
handler**, not against literals repeated here. ``create_app`` is called
twice on two identical fixtures and the second app's ``HTTPException``
handler is removed; every JSON door is then requested against both and
compared byte for byte. A test that only asserted "``/api/v1`` still answers
JSON" would pass against a handler that renders HTML for a 404, or for a
status the API happens not to use in the request the test chose.

**The census is taken from the router objects, never from the path.**
``/acme/admin`` is a UI page whose path begins ``/acme``, so a prefix test
answers cabin's own ACME settings page as ``application/problem+json`` and
passes any criterion keyed on prefixes. FR-6 decides by which router owns
the matched route and AC-5 asserts the set the handler would answer HTML for
equals the set those ten routers contribute. Both of AC-5's recorded
mechanical traps are handled here: ``app.routes`` holds one
``_IncludedRouter`` wrapper per ``include_router`` call rather than the
routes themselves, so the census walks them; and the MCP door is a ``POST``,
because ``GET /mcp`` is a 405 answered while routing, before any handler
runs, and a comparison made on it is green against every implementation.

**"At this spec's base commit" is read out of git, not out of a second
running application.** AC-15's and AC-18's wording asks for the same page
rendered through the base commit's templates. That cannot be done in this
process for the dashboard -- FR-8 removes ``ca_certs`` from its context and
``StrictUndefined`` makes the old template a hard error against the new one
-- so what is compared is the *text the templates carry*, extracted from
``git show`` at :data:`BASE_COMMIT` and from the working tree, which is what
FR-19 is actually about ("every sentence, label, heading, help line and hint
that exists on the thirteen templates today is byte-identical afterwards").
"""

import json
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import dom
import probes
import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.acme.eab import AcmeEabKey
from cabin.acme.errors import AcmeError
from cabin.api_tokens import ApiToken
from cabin.api_tokens import create_token as create_api_token
from cabin.app import create_app
from cabin.audit import AuditEvent
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import Certificate
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.sessions import create_session as create_user_session
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.users import Role, User

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "src/cabin/web/templates"
STATIC = REPO / "src/cabin/web/static"
CSS = STATIC / "cabin.css"

#: The commit spec 0030 is written against -- `docs(spec): 0030 -- the
#: remaining pages, the flash and the 403 page`. Every "unchanged from
#: today" comparison in this file resolves its baseline out of git at this
#: revision rather than out of a literal repeated in a test, so a reworded
#: heading fails instead of being copied into both sides of the assertion.
BASE_COMMIT = "964a208"

#: FR-19's new copy, verbatim. The two bodies are what AC-6 tells apart.
NOT_PERMITTED_TITLE = "Not permitted"
BACK_TO_INVENTORY = "Back to the inventory"
ROLE_REFUSAL = "Your role does not allow this page. Ask a superadmin if you need it."
CSRF_REFUSAL = (
    "This form was submitted with a token this session does not recognise. "
    "Open the page again and retry."
)

#: FR-6's ten interface routers, by the name `cabin.app` imports them under.
#: Named rather than derived, because "which routers are the interface" is
#: the decision the requirement makes; what is derived is the set of
#: endpoints they carry.
INTERFACE_ROUTERS = (
    ("ui_router", "cabin.web.ui", "router"),
    ("ca_router", "cabin.web.ca_ui", "router"),
    ("transfer_router", "cabin.web.transfer_ui", "router"),
    ("transfer_ca_router", "cabin.web.transfer_ui", "ca_router"),
    ("certs_router", "cabin.web.certs_ui", "router"),
    ("certs_download_router", "cabin.web.certs_download_ui", "router"),
    ("settings_router", "cabin.web.settings_ui", "router"),
    ("acme_ui_router", "cabin.web.acme_ui", "router"),
    ("tokens_router", "cabin.web.tokens_ui", "router"),
    ("audit_router", "cabin.web.audit_ui", "router"),
)


# --------------------------------------------------------------------------
# fixtures and plumbing
# --------------------------------------------------------------------------


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
    return create_session_factory(cfg.db_url)()


def _setup_superadmin(
    client: TestClient, username: str = "alice", password: str = "correcthorse1"
) -> None:
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303, resp.text


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> int:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    db = _db(cfg)
    try:
        return int(db.scalars(select(User).where(User.username == username)).one().id)
    finally:
        db.close()


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303, resp.text


def _session_columns(cfg: Config) -> set[str]:
    db = _db(cfg)
    try:
        return {column["name"] for column in sa.inspect(db.get_bind()).get_columns("sessions")}
    finally:
        db.close()


def _flash_of(client: TestClient, cfg: Config) -> str | None:
    """This client's own session row's ``flash``, read straight out of the
    database rather than off an ORM object this process may still be holding
    dirty -- which is the whole point of AC-1 clause 4."""
    assert "flash" in _session_columns(cfg), (
        "the `sessions` table has no `flash` column: FR-2 adds one nullable "
        "`sa.Text` column and migration 0011_session_flash.py"
    )
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None, "this client holds no live session"
        token_hash = row.token_hash
        db.expire_all()
        value = db.execute(
            sa.text("SELECT flash FROM sessions WHERE token_hash = :h"), {"h": token_hash}
        ).scalar_one()
        return None if value is None else str(value)
    finally:
        db.close()


def _drain_flash(client: TestClient) -> None:
    """Render one page so that whatever the fixture's own mutations left
    pending is popped.

    `_seed` posts eighteen-style mutations of its own, so a message is
    waiting the moment it returns. Any assertion about "no panel here" or
    "this POST set that message" has to start from a clean column, or it is
    reading the fixture's leftovers.
    """
    assert client.get("/certs").status_code == 200


def _events(cfg: Config) -> list[AuditEvent]:
    db = _db(cfg)
    try:
        return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    finally:
        db.close()


def _flash_elements(html: str) -> list[dom.Node]:
    return dom.parse(html).find_all(cls="flash")


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: Any) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _csr_pem(common_name: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --------------------------------------------------------------------------
# the spec's own fixture
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Fixture:
    alpha_root: int
    alpha_issuers: tuple[int, int]
    beta_root: int
    beta_issuer: int
    cross: int
    viewer: int
    admin: int
    token: int
    eab_key: str
    expiring_cert: int
    valid_cert: int


def _last_root_id(cfg: Config) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "root")
            .order_by(CACertificate.id.desc())
        ).first()
        assert row is not None
        return int(row.id)
    finally:
        db.close()


def _enable_services(client: TestClient, cfg: Config) -> None:
    """A base URL, ACME on and MCP on -- the state in which the two doors
    AC-5 compares answer their own refusals rather than the 404 they answer
    while switched off. Written through the one form that owns all three,
    which is also FR-13's point.
    """
    resp = client.post(
        "/settings",
        data={
            "base_url": "https://cabin.example.test",
            "acme_enabled": "on",
            "mcp_enabled": "on",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def _seed(client: TestClient, cfg: Config) -> Fixture:
    """The Acceptance Criteria's fixture: hierarchy alpha (a root with two
    intermediates), hierarchy beta (one intermediate), a cross certificate
    for beta's root signed by alpha's root, a superadmin, an admin, a
    viewer, one API token, one certificate expiring inside 30 days and one
    outside it, and a base URL set.
    """
    _setup_superadmin(client)
    viewer = _create_user(client, cfg, "vera", "viewer")
    admin = _create_user(client, cfg, "adam", "admin")

    _enable_services(client, cfg)

    assert (
        client.post(
            "/ca/create",
            data={
                "name": "alpha Root CA",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "path_length": 2,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    alpha_root = _last_root_id(cfg)
    alpha_issuers = []
    for label in ("alpha Issuing CA", "alpha Second Issuing CA"):
        assert (
            client.post(
                f"/ca/{alpha_root}/intermediate",
                data={
                    "name": label,
                    "key_type": "ecdsa-p256",
                    "years": 10,
                    "csrf_token": _csrf(client, cfg),
                },
            ).status_code
            == 303
        )
        alpha_issuers.append(_ca_id(cfg, label))

    assert (
        client.post(
            "/ca/create",
            data={
                "name": "beta Root CA",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    beta_root = _last_root_id(cfg)
    assert (
        client.post(
            f"/ca/{beta_root}/intermediate",
            data={
                "name": "beta Issuing CA",
                "key_type": "ecdsa-p256",
                "years": 10,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    beta_issuer = _ca_id(cfg, "beta Issuing CA")
    assert (
        client.post(
            f"/ca/{beta_root}/cross-sign",
            data={
                "signing_root_id": alpha_root,
                "years": 5,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    db = _db(cfg)
    try:
        cross = int(db.scalars(select(CACertificate).where(CACertificate.kind == "cross")).one().id)
    finally:
        db.close()

    expiring = _issue(client, cfg, "soon.example.test", alpha_issuers[0], days=20)
    valid = _issue(client, cfg, "later.example.test", alpha_issuers[0], days=300)

    created = client.post(
        "/tokens",
        data={"label": "ci", "role": "admin", "csrf_token": _csrf(client, cfg)},
    )
    assert created.status_code == 200, created.text
    token = _last_id(cfg, ApiToken)

    eab = client.post(
        "/acme/admin/eab-keys",
        data={
            "label": "edge",
            "issuer_id": alpha_issuers[0],
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert eab.status_code == 200, eab.text
    db = _db(cfg)
    try:
        eab_key = str(db.scalars(select(AcmeEabKey)).first().id)  # type: ignore[union-attr]
    finally:
        db.close()

    return Fixture(
        alpha_root=alpha_root,
        alpha_issuers=(alpha_issuers[0], alpha_issuers[1]),
        beta_root=beta_root,
        beta_issuer=beta_issuer,
        cross=cross,
        viewer=viewer,
        admin=admin,
        token=token,
        eab_key=eab_key,
        expiring_cert=expiring,
        valid_cert=valid,
    )


def _last_id(cfg: Config, model: Any) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(select(model).order_by(model.id.desc())).first()
        assert row is not None, f"no {model.__name__} row exists"
        return int(row.id)
    finally:
        db.close()


def _ca_id(cfg: Config, name: str) -> int:
    db = _db(cfg)
    try:
        return int(db.scalars(select(CACertificate).where(CACertificate.name == name)).one().id)
    finally:
        db.close()


def _issue(client: TestClient, cfg: Config, cn: str, issuer_id: int, days: int) -> int:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": cn,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": days,
            "issuer_id": issuer_id,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[-1])


# ==========================================================================
# AC-1: the flash is written once, shown once, and gone
# ==========================================================================


def test_the_flash_is_written_once_and_popped_once(client: TestClient, cfg: Config) -> None:
    """AC-1, five clauses in one test.

    The two halves that can each pass on their own are here together: a
    build that writes and never renders fails clause 3, one that renders and
    never clears fails clauses 4 and 5, one that never writes fails clause
    2. And clause 4 alone is not enough, because ``pop_flash`` setting the
    attribute to ``None`` without committing satisfies it on the object this
    process is holding -- clause 5 is the one that reaches the database
    again through a second request.

    The message is compared against the audit event's own ``summary``, never
    against a literal: FR-3 derives the panel's sentence from the log so that
    there is one sentence per action in this project, and comparing both to a
    string written here would pass a build that wrote its own.
    """
    _setup_superadmin(client)
    viewer = _create_user(client, cfg, "vera", "viewer")
    before = len(_events(cfg))

    changed = client.post(
        f"/users/{viewer}/role",
        data={"role": "admin", "csrf_token": _csrf(client, cfg)},
    )
    assert changed.status_code == 303, changed.text

    events = _events(cfg)
    assert len(events) == before + 1, "the role change did not record exactly one audit event"
    summary = events[-1].summary

    stored = _flash_of(client, cfg)
    assert stored is not None, (
        "the session's `flash` column is NULL after a 303 that recorded one "
        "audit event (FR-3): nothing was written"
    )
    assert stored == summary, (
        f"the flash says {stored!r} and the audit log says {summary!r}. FR-3 binds "
        f"the f-string to a local and passes it to both, so the panel cannot drift "
        f"from the log"
    )

    first = client.get("/users")
    assert first.status_code == 200
    panels = _flash_elements(first.text)
    assert len(panels) == 1, f"expected exactly one .flash element, found {len(panels)}"
    panel = panels[0]
    assert summary in panel.text(), f"the panel does not carry the summary: {panel.text()!r}"

    shell = panel.closest(cls="shell")
    assert shell is not None, "the .flash panel is not inside .shell (FR-4)"
    assert panel.parent is not None and "shell" in panel.parent.classes, (
        "the .flash panel is not a direct child of .shell, so it is not a sibling "
        "of <aside class='rail'> and <main id='main'> the way FR-4 places it"
    )
    mains = [child for child in shell.children if child.tag == "main"]
    assert [main.get("id") for main in mains] == ["main"], (
        f"the shell holds {len(mains)} <main> element(s); the panel's sibling is <main id='main'>"
    )

    assert _flash_of(client, cfg) is None, (
        "the `flash` column is still set after the page that showed it was "
        "rendered -- pop_flash reads and clears in one call (FR-2)"
    )

    second = client.get("/users")
    assert second.status_code == 200
    assert _flash_elements(second.text) == [], (
        "the flash is shown a second time. This is the clause an implementation "
        "that clears the in-memory attribute without committing fails, and the "
        "only one that can see it"
    )


# ==========================================================================
# AC-2: a no-op says nothing, and a real change says something
# ==========================================================================


def test_a_no_op_mutation_leaves_no_flash(client: TestClient, cfg: Config) -> None:
    """AC-2, both halves against one API token.

    ``revoke_token`` on an already-revoked token redirects without recording
    an event (``tokens_ui.py:240``). A build that sets the flash at the top
    of the handler, or before the work rather than after the event, announces
    a revocation that did not happen -- and nothing else in the suite would
    see it, because the response is a 303 either way.
    """
    _setup_superadmin(client)
    created = client.post(
        "/tokens", data={"label": "ci", "role": "admin", "csrf_token": _csrf(client, cfg)}
    )
    assert created.status_code == 200, created.text
    token_id = _last_id(cfg, ApiToken)

    before = len(_events(cfg))
    first = client.post(f"/tokens/{token_id}/revoke", data={"csrf_token": _csrf(client, cfg)})
    assert first.status_code == 303
    events = _events(cfg)
    assert len(events) == before + 1, "revoking a live token recorded no event"
    assert _flash_of(client, cfg) == events[-1].summary

    page = client.get("/tokens")
    assert page.status_code == 200
    panels = _flash_elements(page.text)
    assert len(panels) == 1 and events[-1].summary in panels[0].text(), (
        f"the revocation was not announced: {[node.text() for node in panels]}"
    )

    again = client.post(f"/tokens/{token_id}/revoke", data={"csrf_token": _csrf(client, cfg)})
    assert again.status_code == 303
    assert len(_events(cfg)) == len(events), (
        "revoking an already-revoked token recorded an event; the no-op guard moved"
    )
    assert _flash_of(client, cfg) is None, (
        "a request that changed nothing left a message behind -- a panel saying "
        "something happened when nothing did is worse than no panel (FR-3)"
    )
    assert _flash_elements(client.get("/tokens").text) == []


# ==========================================================================
# AC-3: the flash is not in the URL, and no mutation runs through htmx
# ==========================================================================


def test_the_flash_is_not_a_query_parameter(client: TestClient, cfg: Config) -> None:
    """AC-3, three clauses.

    Clause 3 pins spec 0029's four previews to the four files that carry
    them, which is AC-3's corrected wording: the criterion first read "the
    count of ``hx-post`` attributes is zero" and no build could satisfy it,
    because FR-20 leaves those four in place. Pinned rather than counted --
    a count alone passes on a build that moved one.
    """
    fix = _seed(client, cfg)
    _drain_flash(client)

    # 1. a link cannot make cabin say anything
    forged = client.get("/users?flash=deleted+user+%27root%27")
    assert forged.status_code == 200
    assert _flash_elements(forged.text) == [], (
        "a `?flash=` query parameter rendered a panel. The one thing a message "
        "from the server is worth is that the server said it"
    )

    # 2. every one of FR-3's eighteen POSTs redirects where it does today, and
    #    every one of them says what it did -- in the column, never in the URL.
    posted = _exercise_the_eighteen(client, cfg, fix)
    for done in posted:
        assert "flash" not in parse_qs(urlparse(done.location).query), (
            f"{done.label} smuggled the flash into its redirect target: "
            f"{done.location!r}. That is the query-parameter design with a column "
            f"beside it, and it inherits every property the column was chosen to avoid"
        )
    not_one_event = {done.label: done.recorded for done in posted if len(done.recorded) != 1}
    assert not_one_event == {}, (
        f"FR-3's rule is 'a UI POST that answers 303 and records exactly one audit "
        f"event sets the flash to that event's own summary'. These eighteen are the "
        f"routes it names, and these did not record exactly one:\n"
        f"{json.dumps(not_one_event, indent=2)}"
    )
    silent = {
        done.label: (done.flash, done.recorded[0])
        for done in posted
        if done.flash != done.recorded[0]
    }
    assert silent == {}, (
        f"these routes did not set the flash to their own audit summary "
        f"(flash, summary):\n{json.dumps(silent, indent=2)}"
    )

    # 3. the htmx attribute census
    hx_post: dict[str, int] = {}
    hx_get = 0
    for path in sorted(TEMPLATES.glob("*.html")):
        text = path.read_text()
        posts = len(re.findall(r'\shx-post\s*=\s*"', text))
        if posts:
            hx_post[path.name] = posts
        hx_get += len(re.findall(r'\shx-get\s*=\s*"', text))
    assert hx_post == {
        "ca_new.html": 1,
        "certs_new.html": 1,
        "certs_sign.html": 1,
        "transfer_ca_import.html": 1,
    }, (
        f"the `hx-post` attributes in the templates are no longer exactly spec "
        f"0029's four previews. FR-20 clause 2: this spec adds none, and every "
        f"mutation it touches is a real form submit: {hx_post}"
    )
    assert hx_get > 0, (
        "no template carries an hx-get at all, so clause 3 would pass by having nothing to count"
    )


@dataclass(frozen=True)
class Posted:
    """What one of FR-3's eighteen POSTs left behind."""

    label: str
    location: str
    recorded: list[str]
    flash: str | None


def _exercise_the_eighteen(client: TestClient, cfg: Config, fix: Fixture) -> list[Posted]:
    """FR-3's eighteen routes, each posted once, each with the target it
    redirects to today written beside it.

    Driven imperatively rather than from a table because half of them depend
    on a row an earlier one created (the cross-sign needs the root
    ``POST /ca/create`` makes, the delete has to come after the role change
    on the same user), and a table that pretended otherwise would either
    reorder them or need a second mechanism to thread the ids through.
    """
    seen: list[Posted] = []

    def post(label: str, url: str, payload: dict[str, object], expected: str | None) -> str:
        before = _events(cfg)
        resp = client.post(url, data={**payload, "csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 303, f"{label} -> {resp.status_code}: {resp.text[:400]}"
        location = resp.headers["location"]
        if expected is not None:
            assert location == expected, (
                f"{label} redirects to {location!r}; today it redirects to "
                f"{expected!r}, and FR-1 changes no redirect target"
            )
        after = _events(cfg)
        seen.append(
            Posted(
                label=label,
                location=location,
                recorded=[event.summary for event in after[len(before) :]],
                flash=_flash_of(client, cfg),
            )
        )
        return location

    # --- ui.py
    post(
        "POST /users",
        "/users",
        {"username": "carol", "password": "whatever12345", "role": "viewer"},
        "/users",
    )
    post("POST /users/{id}/role", f"/users/{fix.viewer}/role", {"role": "admin"}, "/users")
    post(
        "POST /users/{id}/password",
        f"/users/{fix.viewer}/password",
        {"password": "anotherpassword1"},
        "/users",
    )
    post(
        "POST /users/{id}/issuers",
        f"/users/{fix.admin}/issuers",
        {"issuer_id": fix.alpha_issuers[1]},
        "/users",
    )
    post("POST /users/{id}/delete", f"/users/{fix.viewer}/delete", {}, "/users")

    # --- ca_ui.py. `gamma` is created with room to cross-sign, because the
    # pair (beta root, alpha root) already has an active cross certificate
    # from the fixture and cabin refuses a second one for the same pair.
    post(
        "POST /ca/create",
        "/ca/create",
        {"name": "gamma Root CA", "key_type": "ecdsa-p256", "root_years": 20, "path_length": 2},
        "/ca",
    )
    gamma_root = _last_root_id(cfg)
    post(
        "POST /ca/{root}/intermediate",
        f"/ca/{gamma_root}/intermediate",
        {"name": "gamma Issuing CA", "key_type": "ecdsa-p256", "years": 5},
        f"/ca/{gamma_root}",
    )
    post(
        "POST /ca/{id}/cross-sign",
        f"/ca/{fix.beta_root}/cross-sign",
        {"signing_root_id": gamma_root, "years": 5},
        f"/ca/{fix.beta_root}",
    )
    post(
        "POST /ca/{id}/renew",
        f"/ca/{fix.alpha_issuers[1]}/renew",
        {"years": 5},
        f"/ca/{fix.alpha_root}/issuer/{fix.alpha_issuers[1]}",
    )
    post(
        "POST /ca/{id}/retire",
        f"/ca/{fix.alpha_issuers[1]}/retire",
        {"confirm": "on"},
        f"/ca/{fix.alpha_root}/issuer/{fix.alpha_issuers[1]}",
    )

    # --- certs_ui.py
    issued = post(
        "POST /certs/issue",
        "/certs/issue",
        {
            "subject_cn": "flash.example.test",
            "sans": "flash.example.test",
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": 90,
            "issuer_id": fix.alpha_issuers[0],
        },
        None,
    )
    signed = post(
        "POST /certs/sign",
        "/certs/sign",
        {
            "csr_pem": _csr_pem("signed.example.test"),
            "profile": "server",
            "days": 90,
            "issuer_id": fix.alpha_issuers[0],
        },
        None,
    )
    for label, location in (("POST /certs/issue", issued), ("POST /certs/sign", signed)):
        assert re.fullmatch(r"/certs/\d+", location), (
            f"{label} redirects to {location!r}, not to the new certificate's own page"
        )
    post(
        "POST /certs/{id}/revoke",
        f"/certs/{fix.valid_cert}/revoke",
        {"reason": "superseded", "confirm": "on"},
        f"/certs/{fix.valid_cert}",
    )

    # --- tokens_ui.py
    post(
        "POST /tokens/{id}/issuers",
        f"/tokens/{fix.token}/issuers",
        {"issuer_id": fix.alpha_issuers[0]},
        "/tokens",
    )
    post("POST /tokens/{id}/revoke", f"/tokens/{fix.token}/revoke", {}, "/tokens")

    # --- transfer_ui.py
    imported_root, imported_root_key = ca_x509.create_root("Imported Root CA", "ecdsa-p256")
    imported_issuer, imported_issuer_key = ca_x509.create_intermediate(
        imported_root, imported_root_key, "Imported Issuing CA", "ecdsa-p256"
    )
    post(
        "POST /ca/import",
        "/ca/import",
        {
            "cert_pem": _pem(imported_issuer),
            "key_pem": _key_pem(imported_issuer_key),
            "chain_pem": _pem(imported_root),
        },
        "/ca",
    )
    signer_cert, signer_key = ca_x509.create_root("Cross Signer Root CA", "ecdsa-p256", 20, 2)
    db = _db(cfg)
    try:
        row = db.get(CACertificate, fix.alpha_root)
        assert row is not None
        alpha_root_cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    finally:
        db.close()
    post(
        "POST /ca/cross-import",
        "/ca/cross-import",
        {
            "cross_pem": _pem(ca_x509.cross_sign(alpha_root_cert, signer_cert, signer_key, 5)),
            "issuer_pem": _pem(signer_cert),
        },
        "/ca",
    )

    # --- acme_ui.py
    post(
        "POST /acme/admin/eab-keys/{id}/revoke",
        f"/acme/admin/eab-keys/{fix.eab_key}/revoke",
        {},
        "/acme/admin",
    )

    assert len(seen) == 18, f"FR-3 names eighteen routes; this exercised {len(seen)}"
    return seen


# ==========================================================================
# AC-4: the panel animates, and stops animating when asked to
# ==========================================================================


def _rules(text: str) -> list[tuple[str, str]]:
    """Every rule as ``(selector, body)``, at-rules flattened -- the same
    parse ``test_web_design_shell.css_rules`` makes, kept local so that this
    file does not import a spec-0027 helper for a spec-0030 assertion."""
    rules: list[tuple[str, str]] = []

    def walk(chunk: str) -> None:
        depth = 0
        start = 0
        selector = ""
        body_start = 0
        for index, char in enumerate(chunk):
            if char == "{":
                if depth == 0:
                    selector = chunk[start:index].strip()
                    body_start = index + 1
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    body = chunk[body_start:index]
                    if selector.startswith("@") and not selector.startswith("@keyframes"):
                        walk(body)
                    else:
                        rules.append((selector, body))
                    start = index + 1

    walk(re.sub(r"/\*.*?\*/", "", text, flags=re.S))
    return rules


def _brace_block(text: str, start: int) -> str:
    open_brace = text.index("{", start)
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : index]
    raise AssertionError("unbalanced braces in cabin.css")


REDUCED_MOTION = "@media (prefers-reduced-motion: reduce)"


def _animation_selectors(chunk: str) -> dict[str, str]:
    """``selector -> animation value`` for every rule in ``chunk`` that
    declares one. Selectors are split on commas so that a grouped rule
    contributes each of its subjects, which is what makes AC-4 clause 3 a
    set comparison rather than a string comparison."""
    found: dict[str, str] = {}
    for selector, body in _rules(chunk):
        for name, value in re.findall(r"([-\w]+)\s*:\s*([^;{}]+)", body):
            if name.strip() != "animation":
                continue
            for part in selector.split(","):
                found[" ".join(part.split())] = " ".join(value.split())
    return found


def test_the_flash_animation_is_declared_and_reducible() -> None:
    """AC-4's stylesheet half. The rendered half is
    ``test_web_design_shell.test_the_flash_panel_animates_in_the_browser``.

    Clause 3 is a set comparison on purpose. The reduced-motion block is
    extended today by copying the selector already in it; a fourth animated
    element added later without being covered has to fail this rather than
    pass unnoticed, and only "every animated selector appears inside the
    block" can say that.
    """
    text = CSS.read_text()

    flash_rules = {
        selector: value
        for selector, value in _animation_selectors(text).items()
        if ".flash" in selector
    }
    assert flash_rules, "no rule selecting .flash declares an `animation` (FR-4)"
    entry = next(iter(flash_rules.values()))
    assert "cabinToast" in entry and "cabinToastOut" in entry, (
        f".flash's animation names {entry!r}; FR-4 declares both the entry "
        f"(`cabinToast`) and the hide (`cabinToastOut`)"
    )
    assert "3.2s" in entry, (
        f".flash's animation carries no 3.2s delay: {entry!r}. The prototype's "
        f"timer is a setTimeout; the only way to spend 3.2 seconds without "
        f"JavaScript is a delayed animation"
    )
    hide = entry.split(",")[-1]
    assert "cabinToastOut" in hide and "forwards" in hide, (
        f"the hide half of .flash's animation is {hide!r}; without `forwards` the "
        f"panel reappears at the end of the animation"
    )

    keyframes = re.findall(r"@keyframes\s+([\w-]+)", text)
    assert sorted(keyframes) == sorted(["cabinIn", "cabinToast", "cabinToastOut"]), (
        f"cabin.css declares the keyframes {sorted(keyframes)}; FR-4 ships exactly "
        f"three -- the brief's two plus `cabinToastOut`, recorded as a divergence"
    )

    at = text.find(REDUCED_MOTION)
    assert at != -1, f"cabin.css has no {REDUCED_MOTION} block"
    assert text.find(REDUCED_MOTION, at + 1) == -1, "more than one reduced-motion block"
    inside_text = _brace_block(text, at)
    outside_text = text[:at] + text[at + len(inside_text) :]

    outside = set(_animation_selectors(outside_text))
    inside = _animation_selectors(inside_text)
    uncovered = sorted(outside - set(inside))
    assert uncovered == [], (
        f"these selectors animate and are not covered by {REDUCED_MOTION}: "
        f"{uncovered}. The block is extended by covering the new selector, never "
        f"by copying the one already in it"
    )
    still_moving = {
        selector: value for selector, value in inside.items() if value.strip() != "none"
    }
    assert still_moving == {}, (
        f"inside the reduced-motion block these still animate: {still_moving}"
    )


# ==========================================================================
# AC-5: HTML for the interface, unchanged bytes for the other three doors
# ==========================================================================


def _interface_endpoints() -> set[object]:
    import importlib

    endpoints: set[object] = set()
    for _name, module_path, attribute in INTERFACE_ROUTERS:
        router = getattr(importlib.import_module(module_path), attribute)
        for route in router.routes:
            endpoint = getattr(route, "endpoint", None)
            if endpoint is not None:
                endpoints.add(endpoint)
    return endpoints


def _refusal_page(html: str) -> dom.Node:
    tree = dom.parse(html)
    assert tree.find_all(tag="html"), "the refusal is not an HTML document"
    assert tree.find_all(tag="aside", cls="rail"), (
        "the refusal has no rail: an operator refused one page is still logged in "
        "and every other page is one click away (FR-5)"
    )
    mains = [node for node in tree.find_all(tag="main") if node.get("id") == "main"]
    assert len(mains) == 1, "the refusal is not rendered inside <main id='main'>"
    headings = tree.find_all(tag="h1")
    assert len(headings) == 1 and headings[0].text() == NOT_PERMITTED_TITLE, (
        f"the refusal's <h1> elements are {[node.text() for node in headings]}"
    )
    links = [node for node in tree.find_all(tag="a") if node.get("href") == "/certs"]
    assert len(links) == 1, (
        f"the refusal carries {len(links)} link(s) to /certs; FR-5 gives it exactly "
        f"one, and /certs is the one page every refusable role can still open"
    )
    marked = [node for node in tree.walk() if node.get("aria-current") == "page"]
    assert marked == [], (
        f"a rail entry is marked current on the refusal page: {marked}. The page is "
        f"not one of the rail's destinations and marking the one the reader was "
        f"refused would be a lie about where they are"
    )
    return tree


def test_the_refusal_is_html_for_the_ui_and_json_for_the_doors(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-5, both directions plus the census.

    The three HTML URLs are chosen because each fails a different wrong
    implementation: ``/tokens`` is the case any build gets right,
    ``/acme/admin`` is the one a path test on ``/acme`` gets wrong, and the
    POST is the one a build keyed on the method gets wrong.

    The three JSON doors are compared against a second application built from
    the same code with the handler removed, so "unchanged" is measured rather
    than restated. The removal is asserted to have actually removed something
    -- without that, a build registering no handler at all would compare two
    identical applications and pass.
    """
    fix = _seed(client, cfg)

    _login(client, "vera")
    refused = client.get("/tokens")
    assert refused.status_code == 403, f"/tokens for a viewer -> {refused.status_code}"
    assert refused.headers["content-type"].startswith("text/html"), (
        f"a viewer's /tokens answers {refused.headers['content-type']!r}"
    )
    _refusal_page(refused.text)

    acme = client.get("/acme/admin")
    assert acme.status_code == 403
    assert acme.headers["content-type"].startswith("text/html"), (
        "/acme/admin answers JSON to a refused viewer. It is a UI page whose path "
        "begins /acme, which is why FR-6 decides by router and never by prefix"
    )
    _refusal_page(acme.text)

    posted = client.post(f"/users/{fix.admin}/delete", data={"csrf_token": _csrf(client, cfg)})
    assert posted.status_code == 403
    assert posted.headers["content-type"].startswith("text/html"), (
        "a refused POST answers JSON; the rule is about the route, not the method"
    )
    _refusal_page(posted.text)

    # --- the other three doors, against an application without the handler.
    # Two applications, seeded identically, one of them with the handler
    # removed after `create_app` built it: "unchanged bytes" is then a
    # comparison rather than a literal repeated here, and a status or a
    # content type this test did not think to name still cannot move.
    other = make_config(tmp_path / "baseline")
    baseline_app = create_app(other)
    removed = baseline_app.exception_handlers.pop(HTTPException, None)
    assert removed is not None, (
        "the application registers no handler for HTTPException, so this "
        "comparison would compare two identical applications and prove nothing "
        "(FR-6)"
    )
    assert AcmeError in baseline_app.exception_handlers, (
        "AcmeError's own handler is gone; FR-6 leaves it alone"
    )

    with TestClient(baseline_app, follow_redirects=False) as baseline:
        _setup_superadmin(baseline)
        _enable_services(baseline, other)
        baseline_token = _mint_token(other)
        live_token = _mint_token(cfg)

        # One refused request per door. The ACME one comes back through
        # `AcmeError`'s own handler as `application/problem+json`, and the MCP
        # one is a POST with the streamable-HTTP `Accept` because `GET /mcp`
        # is a 405 that never reaches an exception handler at all -- a
        # comparison made on it would be green against any implementation.
        for label, method, path, headers in (
            ("api", "POST", "/api/v1/certificates", {"Authorization": "Bearer {token}"}),
            ("acme", "POST", "/acme/new-account", {}),
            ("mcp", "POST", "/mcp", {"Accept": "application/json, text/event-stream"}),
        ):
            live = _door(client, method, path, headers, live_token)
            base = _door(baseline, method, path, headers, baseline_token)
            assert (live.status_code, live.headers.get("content-type")) == (
                base.status_code,
                base.headers.get("content-type"),
            ), (
                f"the {label} door answers {live.status_code} "
                f"{live.headers.get('content-type')!r} with this spec's handler and "
                f"{base.status_code} {base.headers.get('content-type')!r} without it"
            )
            assert live.content == base.content, (
                f"the {label} door's body changed:\n  with:    {live.text[:300]}\n"
                f"  without: {base.text[:300]}"
            )
            assert not live.headers.get("content-type", "").startswith("text/html"), (
                f"the {label} door answers HTML. An API client receiving an HTML "
                f"error page is a worse regression than the JSON body this spec "
                f"exists to replace"
            )
            assert live.status_code >= 400, (
                f"the {label} door answered {live.status_code}: this request was "
                f"supposed to be refused, so neither side measured a refusal"
            )
            assert live.status_code != 405, (
                f"the {label} door answered 405, which starlette produces before any "
                f"exception handler runs -- this request measures routing, not the "
                f"boundary FR-6 draws"
            )

    # --- the census, taken from the router objects and never from the path
    from cabin.app import _html_403_endpoints

    declared = set(_html_403_endpoints())
    expected = _interface_endpoints()
    assert declared == expected, (
        f"the set the 403 handler answers HTML for is not the set the ten interface "
        f"routers carry.\n  missing: {sorted(str(item) for item in expected - declared)}"
        f"\n  extra: {sorted(str(item) for item in declared - expected)}"
    )
    assert declared, "the set is empty, so every refusal would keep answering JSON"

    app_routes = [
        route
        for route in _flatten(client.app.routes)  # type: ignore[attr-defined]
        if getattr(route, "endpoint", None) is not None
    ]
    html_routes = {route.path for route in app_routes if route.endpoint in declared}
    assert html_routes, "no route in the application is covered by the set"
    assert len(html_routes) < len({route.path for route in app_routes}), (
        "every route in the application would answer HTML for a 403, which is the "
        "regression FR-6 exists to prevent"
    )
    for path in ("/api/v1/certificates", "/acme/new-account", "/healthz"):
        assert path not in html_routes, f"{path} is inside the interface set"


def _mint_token(cfg: Config) -> str:
    """A viewer bearer token, minted through `cabin.api_tokens` rather than
    through `POST /tokens`: the page that shows a secret is one FR-14
    rewrites, and a test that scraped it would break on the redesign it is
    not measuring."""
    db = _db(cfg)
    try:
        secret, _row = create_api_token(db, "probe-viewer", Role.viewer)
        return secret
    finally:
        db.close()


def _door(client: TestClient, method: str, path: str, headers: dict[str, str], token: str) -> Any:
    sent = {name: value.format(token=token) for name, value in headers.items()}
    if method == "GET":
        return client.get(path, headers=sent)
    return client.post(path, headers=sent, json={})


# ==========================================================================
# AC-6: the two bodies are told apart, and the status never moves
# ==========================================================================


def test_the_refusal_names_its_cause(client: TestClient, cfg: Config) -> None:
    """AC-6: one body for each of cabin's two actual causes.

    A single body for both would tell the reader of a stale form to ask a
    superadmin for a role they already have, and the fix that works -- reload
    the page -- is the one they are not offered.
    """
    _seed(client, cfg)

    _login(client, "vera")
    before = len(_events(cfg))
    role_refused = client.get("/tokens")
    assert role_refused.status_code == 403
    assert role_refused.headers["content-type"].startswith("text/html"), (
        f"a refused /tokens answers {role_refused.headers['content-type']!r}, so "
        f"there is no page to read a cause off (FR-5/FR-6)"
    )
    body = dom.parse(role_refused.text).find(tag="main").text()
    assert ROLE_REFUSAL in body, f"the role refusal does not carry its own sentence: {body!r}"
    assert CSRF_REFUSAL not in body, "the role refusal carries the CSRF sentence"
    assert len(_events(cfg)) == before, "a refusal recorded an audit event"

    _login(client, "adam")
    before = len(_events(cfg))
    csrf_refused = client.post(
        "/settings", data={"base_url": "https://elsewhere.example.test", "csrf_token": "wrong"}
    )
    assert csrf_refused.status_code == 403, (
        f"a wrong csrf_token answered {csrf_refused.status_code}, not 403 -- FR-6 "
        f"changes the body and the content type of a 403 and nothing else"
    )
    assert csrf_refused.headers["content-type"].startswith("text/html"), (
        f"a refused CSRF answers {csrf_refused.headers['content-type']!r}"
    )
    body = dom.parse(csrf_refused.text).find(tag="main").text()
    assert CSRF_REFUSAL in body, f"the CSRF refusal does not carry its own sentence: {body!r}"
    assert ROLE_REFUSAL not in body, "the CSRF refusal carries the role sentence"
    assert len(_events(cfg)) == before, "a refusal recorded an audit event"


# ==========================================================================
# AC-15: the CA-key page groups, and the trust bundle stays unclickable
# ==========================================================================


def _git_show(path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{BASE_COMMIT}:{path}"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"cannot read {path} at {BASE_COMMIT}: {result.stderr.strip()}. Every "
        f"'unchanged from today' comparison in this file resolves its baseline "
        f"out of git rather than out of a literal"
    )
    return result.stdout


def _rows_of(table: dom.Node) -> list[dom.Node]:
    bodies = table.find_all(tag="tbody")
    assert len(bodies) == 1, f"the table has {len(bodies)} <tbody> elements"
    return [node for node in bodies[0].children if node.tag == "tr"]


def _grouping_defects(rows: list[dom.Node]) -> list[str]:
    """AC-8 clause 2's shape, applied wherever the grouped list is reused.

    Every row is `row-root` or `row-child`, a child follows a root, and no
    child opens the list -- which is what "each root's intermediates follow
    their own root immediately in document order" comes to once the roots
    themselves are in the order the service returns.
    """
    defects = []
    seen_root = False
    for index, row in enumerate(rows):
        classes = row.classes
        kinds = {"row-root", "row-child"} & classes
        if len(kinds) != 1:
            defects.append(f"row {index} carries {sorted(classes)}, not exactly one row kind")
            continue
        if "row-root" in kinds:
            seen_root = True
        elif not seen_root:
            defects.append(f"row {index} is a row-child before any row-root")
    return defects


def test_the_ca_key_page_groups_and_the_bundle_does_not_click(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-15, three clauses.

    Clause 1's "the multiset the page renders at this spec's base commit" is
    read off the base commit's own template: the three key-state sentences
    are literals in ``transfer_ca_key.html`` and FR-15 keeps the strings it
    has, so the comparison is between the strings that template carried and
    the strings the page renders now.
    """
    fix = _seed(client, cfg)

    page = client.get("/transfer/ca-key")
    assert page.status_code == 200, page.text
    tree = dom.parse(page.text)
    tables = [node for node in tree.find_all(tag="table") if "cols-ca-keys" in node.classes]
    assert len(tables) == 1, (
        f"/transfer/ca-key carries {len(tables)} table(s) with `cols-ca-keys` (FR-15/FR-17)"
    )
    rows = _rows_of(tables[0])
    assert _grouping_defects(rows) == [], _grouping_defects(rows)
    assert sum(1 for row in rows if "row-child" in row.classes) >= 3, (
        "the CA-key page's list is not grouped: this fixture has three "
        "intermediates and none of them is a row-child"
    )

    base_template = _git_show("src/cabin/web/templates/transfer_ca_key.html")
    states = re.findall(
        r"\{%\s*if row\.exportable\s*%\}(.*?)\{%\s*endif\s*%\}", base_template, re.S
    )
    assert states, "the base commit's transfer_ca_key.html has no `exportable` branch"
    expected_states = {" ".join(part.split()) for part in re.split(r"\{%\s*else\s*%\}", states[0])}
    rendered_states = {row.children[-1].text() for row in rows}
    assert rendered_states <= expected_states, (
        f"the Key cell renders {sorted(rendered_states - expected_states)}, which the "
        f"page did not say at {BASE_COMMIT}. FR-15 keeps the strings it has"
    )
    assert rendered_states, "no Key cell was rendered at all"

    bundle = client.get("/transfer/trust-bundle")
    assert bundle.status_code == 200
    bundle_tree = dom.parse(bundle.text)
    assert bundle_tree.find_all(cls="rowlink") == [], (
        "a trust-bundle row is a `.rowlink`; FR-15 keeps those rows unclickable, "
        "which is also what keeps spec 0028 FR-8's hover off them"
    )
    bundle_tables = [
        node for node in bundle_tree.find_all(tag="table") if "cols-trust-bundle" in node.classes
    ]
    assert len(bundle_tables) == 1, "/transfer/trust-bundle carries no `cols-trust-bundle` table"
    for row in _rows_of(bundle_tables[0]):
        anchors = row.find_all(tag="a")
        assert len(anchors) == 1, (
            f"a trust-bundle row carries {len(anchors)} links; the per-hierarchy "
            f"download stays the only anchor in its row"
        )
        assert anchors[0].text() == "Download this hierarchy", anchors[0].text()

    if not Path(probes.CHROME).exists():
        pytest.skip("headless Chrome not installed")

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    measured = _hover(tmp_path, {"bundle": bundle.text, "dashboard": dashboard.text})
    assert measured["bundle"]["rows"] > 0 and measured["dashboard"]["rows"] > 0, (
        f"one of the two pages rendered no list rows at all, so neither half of this "
        f"clause measured anything: {measured}"
    )
    assert measured["dashboard"]["selector"] is not None, (
        f"no rule in cabin.css gives a list row a background on :hover, so 'the hover "
        f"is scoped' is a claim about nothing: {measured['dashboard']}"
    )
    assert measured["bundle"]["wouldHover"] == 0, (
        f"the row-hover rule applies to {measured['bundle']['wouldHover']} of the "
        f"trust bundle's {measured['bundle']['rows']} rows through "
        f"{measured['bundle']['selector']!r}. spec 0028 FR-8 scopes it to "
        f"`tr:has(.rowlink)` and FR-15 leaves those rows unclickable"
    )
    assert measured["dashboard"]["wouldHover"] > 0, (
        f"the row-hover rule applies to none of the dashboard's authorities rows: "
        f"{measured['dashboard']}. A build that highlights everything and a build "
        f"that highlights nothing must each fail"
    )
    assert measured["dashboard"]["background"] != measured["dashboard"]["current"], (
        f"the hover background and the row's own background resolve to the same "
        f"colour, so the hover is invisible: {measured['dashboard']}"
    )
    assert fix.alpha_root  # the fixture is the spec's, not an arbitrary one


#: The hover half of AC-15 clause 3, and the one probe here that measures a
#: selector rather than a pointer. Headless Chrome cannot be told to hover
#: from the outside -- there is no pointer and `--dump-dom` runs no input --
#: so what is read instead is which rows the stylesheet's own row-hover rule
#: would apply to, and what background it would give them. That is the whole
#: of spec 0028 FR-8's claim ("the hover is scoped to rows that go
#: somewhere") and it fails in both directions: a rule widened to `tr:hover`
#: matches the trust bundle's rows, and a rule that lost its background, or a
#: dashboard list built without `.rowlink`, matches nothing on `/`.
#:
#: Result: ``{"rows": N, "wouldHover": N, "selector": str|null,
#: "background": str|null, "current": str|null}``.
_HOVER_PROBE = r"""
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var selector = null, declared = null;
    for (var s = 0; s < document.styleSheets.length; s++) {
      var rules;
      try { rules = document.styleSheets[s].cssRules; } catch (e) { continue; }
      for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        if (!rule.selectorText) continue;
        if (rule.selectorText.indexOf(':hover') === -1) continue;
        if (!/(^|[\s,>])tr/.test(rule.selectorText)) continue;
        if (!rule.style || !rule.style.backgroundColor) continue;
        selector = rule.selectorText;
        declared = rule.style.backgroundColor;
      }
    }
    var rows = 0, wouldHover = 0, current = null;
    var probe = selector === null ? null : selector.replace(/:hover/g, '');
    document.querySelectorAll('table.rows tbody tr').forEach(function (tr) {
      rows++;
      if (current === null) current = getComputedStyle(tr).backgroundColor;
      if (probe === null) return;
      try { if (tr.matches(probe)) wouldHover++; } catch (e) { /* not our selector */ }
    });
    var resolved = null;
    if (declared !== null) {
      var swatch = document.createElement('div');
      swatch.style.backgroundColor = declared;
      document.body.appendChild(swatch);
      resolved = getComputedStyle(swatch).backgroundColor;
    }
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({
      rows: rows, wouldHover: wouldHover, selector: selector,
      background: resolved, current: current
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


def _hover(tmp_path: Path, pages: dict[str, str]) -> dict[str, Any]:
    root = tmp_path / "hover"
    root.mkdir(parents=True, exist_ok=True)
    probes.stage(root, STATIC, pages, _HOVER_PROBE)
    httpd, port = probes.serve(root)
    try:
        return {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150) for name in pages
        }
    finally:
        httpd.shutdown()


# ==========================================================================
# AC-18: not one existing sentence changed
# ==========================================================================

#: FR-1's thirteen templates plus the one it adds. `layout.html` is here
#: because it is rendered inside every one of the others.
TOUCHED_TEMPLATES = (
    "layout.html",
    "dashboard.html",
    "certs_list.html",
    "users.html",
    "tokens.html",
    "acme.html",
    "audit.html",
    "settings.html",
    "transfer_trust_bundle.html",
    "transfer_ca_key.html",
    "transfer_inventory.html",
    "login.html",
    "setup.html",
)

#: FR-19's tables: the one string that changes, and the six new ones.
#:
#: `stale` is deliberately **not** here. FR-19's table listed it as new
#: copy on the dashboard's CRL cards and it is not new -- `dashboard.html`
#: already renders `<span class="tag tag-bad">stale</span>` -- so it is one
#: of the strings this spec relocates without editing, and leaving it in
#: the allow-list would license adding it somewhere it never was.
RENAMED = {"Transfer": "Export"}
NEW_COPY = (
    NOT_PERMITTED_TITLE,
    BACK_TO_INVENTORY,
    ROLE_REFUSAL,
    CSRF_REFUSAL,
    "Edit",
    "Cancel",
)


def _sentences(template_text: str) -> list[str]:
    """The text a reader sees, as this template carries it.

    Jinja tags and expressions are removed first, then HTML tags, then
    comments; what remains is split on the tag boundaries so that a heading
    and the paragraph under it are two entries rather than one. Whitespace
    is collapsed because the formatter reflows attributes and indentation.
    """
    text = re.sub(r"<!--.*?-->", " ", template_text, flags=re.S)
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text, flags=re.S)
    text = re.sub(r"\{#.*?#\}", " ", text, flags=re.S)
    text = re.sub(r"\{\{.*?\}\}", "\x00", text, flags=re.S)
    text = re.sub(r"\{%.*?%\}", "\x00", text, flags=re.S)
    text = re.sub(r"<[^>]*>", "\x00", text, flags=re.S)
    out = []
    for chunk in text.split("\x00"):
        collapsed = " ".join(chunk.split())
        if collapsed:
            out.append(collapsed)
    return out


def test_no_sentence_changed_on_the_remaining_pages() -> None:
    """AC-18/FR-19, measured on the templates rather than on rendered pages.

    The criterion is measured on the templates, which is FR-19's own
    sentence: "every sentence, label, heading, help line and hint that
    exists on the thirteen templates today is byte-identical afterwards."
    AC-18 first asked for each page rendered through the base commit's
    templates "on one instance with one database", and that instrument
    cannot be built -- FR-8 removes `ca_certs` from the dashboard's context
    and `StrictUndefined` (web/__init__.py) makes the old template against
    the new context a hard error rather than a comparison.

    What is compared is the strings each template carries at
    :data:`BASE_COMMIT` against the strings it carries now. It sees a
    reworded heading, a dropped help line and a silently added sentence,
    and it does not depend on a fixture reaching every branch.
    """
    lost: dict[str, list[str]] = {}
    gained: dict[str, list[str]] = {}
    for name in TOUCHED_TEMPLATES:
        before = _sentences(_git_show(f"src/cabin/web/templates/{name}"))
        after = _sentences((TEMPLATES / name).read_text())
        missing = [line for line in before if line not in after]
        added = [line for line in after if line not in before]
        if missing:
            lost[name] = missing
        if added:
            gained[name] = added

    permitted_loss = {"layout.html": ["Transfer"]}
    assert lost == permitted_loss, (
        f"a sentence that exists today is gone. FR-19 permits exactly one removal on "
        f"exactly one page -- `Transfer` from the rail, which `Export` replaces -- "
        f"and several hundred assertions depend on the rest:\n{json.dumps(lost, indent=2)}"
    )

    allowed = {*RENAMED.values(), *NEW_COPY}
    unnamed = {
        name: [line for line in lines if line not in allowed] for name, lines in gained.items()
    }
    unnamed = {name: lines for name, lines in unnamed.items() if lines}
    assert unnamed == {}, (
        f"new copy that FR-19's table does not name. Every addition is enumerated "
        f"there so that 'new copy' cannot later mean 'an edit to something that was "
        f"already there':\n{json.dumps(unnamed, indent=2)}"
    )

    new_page = TEMPLATES / "not_permitted.html"
    assert new_page.exists(), "src/cabin/web/templates/not_permitted.html does not exist (FR-5)"
    written = _sentences(new_page.read_text())
    assert set(written) <= allowed, (
        f"the refusal page carries copy FR-19 does not name: {sorted(set(written) - allowed)}"
    )
    for required in (NOT_PERMITTED_TITLE, BACK_TO_INVENTORY, ROLE_REFUSAL, CSRF_REFUSAL):
        assert required in written, f"not_permitted.html does not carry {required!r}"


# ==========================================================================
# AC-19: nothing scrolls sideways, and the flash is inside the viewport
# ==========================================================================

#: Where the flash panel actually is, at whatever width the page is drawn.
#: Reported as raw geometry plus whether a panel was found at all, for the
#: reason every other probe in `tests/probes.py` reports what it examined: a
#: page with no `.flash` would answer "inside the viewport" to a boolean.
FLASH_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var panels = [];
    document.querySelectorAll('.flash').forEach(function (el) {
      var r = el.getBoundingClientRect();
      panels.push({
        left: Math.round(r.left),
        right: Math.round(r.right),
        width: Math.round(r.width),
        animation: getComputedStyle(el).animationName,
        fill: getComputedStyle(el).animationFillMode
      });
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({
      panels: panels,
      viewport: document.documentElement.clientWidth
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


@pytest.mark.skipif(not Path(probes.CHROME).exists(), reason="headless Chrome not installed")
@pytest.mark.parametrize("width,height", [(1440, 1150), (390, 900)])
def test_the_remaining_pages_do_not_scroll_sideways(
    client: TestClient, cfg: Config, tmp_path: Path, width: int, height: int
) -> None:
    """AC-19's flash clause.

    The overflow, contrast and focus runs over the full page list are
    `test_web_layout.test_no_horizontal_overflow` and
    `test_web_design_shell`'s two probes, which this spec extends with
    `/login`, `/setup` and a refused render rather than repeating here. What
    is measured here is the one piece of geometry this spec adds: the panel
    the design puts at `left: 250px`, on a 390px viewport.
    """
    _seed(client, cfg)
    # A real message, staged the way an operator produces one: a mutation
    # that redirects, and then the page it redirects to.
    revoked = client.post(
        f"/certs/{_any_cert(cfg)}/revoke",
        data={"reason": "superseded", "confirm": "on", "csrf_token": _csrf(client, cfg)},
    )
    assert revoked.status_code == 303
    page = client.get("/certs")
    assert page.status_code == 200
    assert _flash_elements(page.text), (
        "no flash was staged, so this run would measure a panel that is not there"
    )

    root = tmp_path / f"flash-{width}"
    root.mkdir()
    probes.stage(root, STATIC, {"certs": page.text}, FLASH_PROBE)
    httpd, port = probes.serve(root)
    try:
        found = probes.run(f"http://127.0.0.1:{port}/certs.html", width, height)
    finally:
        httpd.shutdown()

    assert len(found["panels"]) == 1, f"the browser drew {len(found['panels'])} panels: {found}"
    panel = found["panels"][0]
    assert panel["left"] >= 0, f"the panel starts left of the viewport: {panel}"
    assert panel["right"] <= found["viewport"], (
        f"the panel ends {panel['right'] - found['viewport']}px past the right edge "
        f"of a {found['viewport']}px viewport: {panel}. The design's `left: 250px` "
        f"unqualified puts a 520px panel 250px into a 390px screen"
    )
    if width == 1440:
        assert panel["left"] == 250, (
            f"at 1440 the panel's left edge is {panel['left']}, not the design's 250"
        )
        assert "cabinToast" in panel["animation"] and "cabinToastOut" in panel["animation"], (
            f"the computed animation-name is {panel['animation']!r}"
        )
        assert "forwards" in panel["fill"], f"animation-fill-mode is {panel['fill']!r}"


def _any_cert(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return int(db.scalars(select(Certificate).order_by(Certificate.id)).first().id)  # type: ignore[union-attr]
    finally:
        db.close()


# ==========================================================================
# AC-20: everything that was not this spec's subject still behaves the same
# ==========================================================================

#: The route inventory recorded at :data:`BASE_COMMIT`. Regenerated only by
#: a deliberate act: `no route is added and no route is removed` is the
#: Interface Contract's own first sentence, so a diff here is a decision.
ROUTE_BASELINE = Path(__file__).resolve().parent / "data" / "0030_routes.json"


def _flatten(routes: Any) -> list[Any]:
    """Every real route the application will match.

    FastAPI 0.141 does not splice an included router's routes into
    ``app.routes``; it appends one ``_IncludedRouter`` per ``include_router``
    call and matches through it. AC-5's "over every route in ``app.routes``"
    therefore has to walk that wrapper, or the census is taken over the five
    routes FastAPI itself adds and nothing else.
    """
    out: list[Any] = []
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            out.extend(_flatten(inner.routes))
        else:
            out.append(route)
    return out


def _route_inventory(app: Any) -> list[list[str]]:
    """``[path, methods, endpoint]`` for every route the application carries.

    The endpoint's qualified name is recorded beside the path because two of
    ACME's routes are the same gate object under different paths, and a
    census keyed on the callable alone would collapse them into one.
    """
    found = set()
    for route in _flatten(app.routes):
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        name = "{}.{}".format(
            getattr(endpoint, "__module__", type(endpoint).__module__),
            getattr(endpoint, "__qualname__", type(endpoint).__qualname__),
        )
        methods = ",".join(sorted(getattr(route, "methods", None) or ["MOUNT"]))
        found.add((str(getattr(route, "path", "")), methods, name))
    return sorted([path, methods, name] for path, methods, name in found)


def test_the_unchanged_routes_are_unchanged(client: TestClient, cfg: Config) -> None:
    """AC-20, asserted as behaviour and against a recorded baseline.

    The criterion first asked for a CRL byte-identical to the base commit's,
    which no build can satisfy: a CRL is signed, by a key this fixture
    generates, and carries `thisUpdate`/`nextUpdate` from the clock, so two
    runs of the *same* commit differ. What is deterministic -- and what the
    corrected criterion compares -- is the route inventory and the
    `/api/v1` operation set, recorded at the base commit in
    `tests/data/0030_routes.json`. That is the Interface Contract's own
    first sentence: no route is added and none is removed.
    """
    fix = _seed(client, cfg)

    recorded = json.loads(ROUTE_BASELINE.read_text())
    assert _route_inventory(client.app) == recorded["routes"], (  # type: ignore[attr-defined]
        "the set of routes moved. The Interface Contract's first sentence is that "
        "no route is added and none is removed"
    )

    schema = client.get("/api/v1/openapi.json")
    assert schema.status_code == 200
    operations = sorted(
        f"{method.upper()} {path}"
        for path, item in schema.json()["paths"].items()
        for method in item
    )
    assert operations == recorded["api_operations"], "the /api/v1 surface moved"

    # guards, both directions, on the routes this spec touches the handlers of
    client.cookies.clear()
    for path in ("/", "/users", "/certs", "/audit", "/tokens", "/settings"):
        anonymous = client.get(path)
        assert anonymous.status_code == 303 and anonymous.headers["location"] == "/login", (
            f"anonymous {path} -> {anonymous.status_code}"
        )

    _login(client, "vera")
    for path in ("/tokens", "/settings", "/certs/new", "/acme/admin", "/transfer/ca-key"):
        assert client.get(path).status_code == 403, f"a viewer was let into {path}"
    for path in ("/", "/certs", "/users", "/audit", "/transfer/trust-bundle"):
        assert client.get(path).status_code == 200, f"a viewer was refused {path}"

    _login(client, "alice", "correcthorse1")
    missing_csrf = client.post(f"/users/{fix.admin}/role", data={"role": "viewer"})
    assert missing_csrf.status_code == 403, "a POST with no csrf_token was accepted"

    # Every screen this spec touches, plus the three that have never been
    # walked, parses as HTML and answers what it answers today. The refused
    # render is the clause that is red before FR-6 lands: today it is a JSON
    # body in a browser window.
    _login(client, "vera")
    refused = client.get("/tokens")
    assert refused.status_code == 403
    assert refused.headers["content-type"].startswith("text/html"), (
        f"a refused render answers {refused.headers['content-type']!r}; AC-20's "
        f"second bullet asks every one of the twenty-two screens to parse as HTML"
    )
    assert dom.parse(refused.text).find_all(tag="html"), "the refusal is not a document"

    _login(client, "alice", "correcthorse1")
    for path in ("/login", "/certs", "/users", "/audit", "/", "/tokens", "/settings"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert dom.parse(resp.text).find_all(tag="html"), f"{path} does not parse as HTML"

    # A session written before the migration ran: `create_session` never names
    # `flash`, so the row it inserts is exactly the row an upgraded database
    # already holds. A `NOT NULL` column with no server default turns this
    # insert into an IntegrityError and every existing session into a dead one.
    db = _db(cfg)
    try:
        alice = db.scalars(select(User).where(User.username == "alice")).one()
        token, _row = create_user_session(db, alice)
    finally:
        db.close()
    client.cookies.clear()
    client.cookies.set("cabin_session", token)
    for path in ("/", "/users", "/certs", "/audit", "/tokens", "/settings", "/acme/admin"):
        resp = client.get(path)
        assert resp.status_code == 200, (
            f"{path} -> {resp.status_code} for a session written the way one written "
            f"before migration 0011 was"
        )
        assert _flash_elements(resp.text) == [], f"{path} rendered a flash out of a NULL column"
