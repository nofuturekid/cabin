"""Spec 0012 FR-5/FR-7, AC-6/AC-7: the ACME admin page -- its toggles, its
EAB keys and their one-time secret -- and the ACME origin of an issued
certificate in the normal inventory."""

import base64
import re
from collections.abc import Iterator
from pathlib import Path

import dom
import grant_fixtures
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.acme.eab import AcmeEabKey
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.ca.certs import CertSource
from cabin.ca.leaf import Profile
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import (
    ACME_ENABLED,
    ACME_REQUIRE_EAB,
    BASE_URL,
    DNS_RESOLVERS,
    MCP_ENABLED,
    get_flag,
    get_setting,
    set_setting,
)
from cabin.store import create_session_factory
from cabin.users import Role, create_user

ACME_PAGE = "/acme/admin"
#: What the one-time secret looks like on screen: base64url, no padding.
_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{40,}")


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup(client: TestClient, cfg: Config) -> str:
    """First-run superadmin plus a base URL, which ACME needs before it can
    hand out any URL at all, and a hierarchy (spec 0019 FR-13: the /acme
    page lists one directory row per intermediate, so there has to be one to
    list)."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, "https://ca.example.org")
        ca_service.create_hierarchy(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin", "cabin Intermediate"
        )
    finally:
        db.close()
    return _csrf(client, cfg)


def _issuer_id(cfg: Config) -> int:
    """The intermediate ``_setup`` created -- spec 0019 gives every ACME
    surface a per-issuer shape, so a test that means "the one hierarchy"
    still has to name it."""
    db = _db(cfg)
    try:
        return ca_service.active_issuers(db)[0].id
    finally:
        db.close()


def _keys(cfg: Config) -> list[AcmeEabKey]:
    db = _db(cfg)
    try:
        return list(db.scalars(select(AcmeEabKey).order_by(AcmeEabKey.created_at)).all())
    finally:
        db.close()


def _actions(cfg: Config) -> list[str]:
    db = _db(cfg)
    try:
        return [event.action for event in db.scalars(select(AuditEvent).order_by(AuditEvent.id))]
    finally:
        db.close()


def test_acme_ui_key_lifecycle(client: TestClient, cfg: Config) -> None:
    """FR-5/AC-6: create a key, see its secret exactly once, then revoke it."""
    csrf = _setup(client, cfg)
    issuer_id = _issuer_id(cfg)

    page = client.get(ACME_PAGE)
    assert page.status_code == 200, page.text
    # spec 0019 FR-13: the page lists one directory URL per intermediate,
    # not a single instance-wide one.
    assert f"https://ca.example.org/acme/ca/{issuer_id}/directory" in page.text
    # FR-5: the onboarding snippets an operator copies
    assert "certbot" in page.text
    assert "acme.sh" in page.text
    assert "--eab-kid" in page.text

    # the toggles live here (FR-5)
    toggled = client.post(
        ACME_PAGE,
        data={"acme_enabled": "on", "acme_require_eab": "on", "csrf_token": csrf},
    )
    assert toggled.status_code == 303, toggled.text
    db = _db(cfg)
    try:
        assert get_flag(db, ACME_ENABLED) is True
        assert get_flag(db, ACME_REQUIRE_EAB) is True
    finally:
        db.close()

    # spec 0019 FR-8: minting a key is now a granted operation. alice is a
    # superadmin, whose grant is implicit (0018 FR-3) and would let this
    # POST through no matter what FR-8 checked -- so the rest of this test
    # switches to a plain admin explicitly granted this issuer, which is
    # what makes the request below prove the grant, not the role that
    # happened to set up the instance.
    db = _db(cfg)
    try:
        operator = create_user(db, "operator", "whatever12345", Role.admin)
        grant_fixtures.grant_user(db, operator, issuer_id)
    finally:
        db.close()
    client.cookies.clear()
    logged_in = client.post("/login", data={"username": "operator", "password": "whatever12345"})
    assert logged_in.status_code == 303, logged_in.text
    csrf = _csrf(client, cfg)

    created = client.post(
        f"{ACME_PAGE}/eab-keys",
        data={"label": "nas.lan", "issuer_id": str(issuer_id), "csrf_token": csrf},
    )
    assert created.status_code == 200, created.text
    rows = _keys(cfg)
    assert len(rows) == 1
    key_id = rows[0].id
    assert rows[0].label == "nas.lan"
    assert rows[0].ca_certificate_id == issuer_id
    assert key_id in created.text

    # the secret is on this page, exactly once, and never stored in the clear
    secrets_shown = [
        match for match in _SECRET_RE.findall(created.text) if match not in (key_id, csrf)
    ]
    assert secrets_shown, created.text
    secret = secrets_shown[0]
    assert base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    assert secret not in rows[0].hmac_sealed
    # ...and it is gone from every later render of the page
    assert secret not in client.get(ACME_PAGE).text

    revoked = client.post(f"{ACME_PAGE}/eab-keys/{key_id}/revoke", data={"csrf_token": csrf})
    assert revoked.status_code == 303, revoked.text
    assert _keys(cfg)[0].revoked_at is not None

    assert AuditAction.acme_eab_key_created in _actions(cfg)
    assert AuditAction.acme_eab_key_revoked in _actions(cfg)


# === spec 0030 AC-13: the toggles are checkboxes, and one Save writes
# every flag the form carries ==============================================


def _toggle(tree: dom.Node, element_id: str) -> dom.Node:
    """The one element carrying ``id``, out of a tree the caller already has.

    It takes the parsed tree rather than the page's text on purpose:
    ``dom.parse`` builds a fresh tree on every call and memoises nothing, so a
    node taken from a second parse is never the same object as a node taken
    from the first, and ``control.closest(tag="form") is form`` can then only
    ever be false. The containment claim AC-13 clause 1 makes is about one
    document, so it is measured on one tree.
    """
    found = [node for node in tree.walk() if node.get("id") == element_id]
    assert len(found) == 1, f"the page carries {len(found)} elements with id={element_id!r}"
    return found[0]


def test_one_save_still_writes_both_flags(client: TestClient, cfg: Config) -> None:
    """AC-13, the case the design's own recommendation would have broken.

    Brief section 9.7 offers two shapes for a toggle switch and recommends
    the one whose submit button *is* the track. On this page that shape is
    not merely worse, it is broken: `POST /acme/admin` reads `acme_enabled`
    and `acme_require_eab` out of one submission and an absent checkbox
    means off, so a per-toggle button would post the whole form and turning
    EAB on would turn ACME off.

    Clause 2's second POST is the measurement. It is the behaviour spec 0019
    already has, and it is what a per-toggle submit button silently breaks --
    nothing else in the suite posts one of these two flags without the other.
    """
    _setup(client, cfg)

    page = client.get(ACME_PAGE)
    assert page.status_code == 200
    tree = dom.parse(page.text)
    forms = [node for node in tree.find_all(tag="form") if node.get("action") == ACME_PAGE]
    assert len(forms) == 1, (
        f"the ACME page has {len(forms)} forms posting to {ACME_PAGE}; both flags "
        f"live in one submission, which is the whole of FR-13's argument"
    )
    form = forms[0]
    submits = [node for node in form.find_all(tag="button") if (node.get("type") or "") == "submit"]
    assert len(submits) == 1, (
        f"the settings form carries {len(submits)} submit buttons. A per-toggle "
        f"button posts this form in full, so pressing one clears the other flag"
    )

    for element_id in ("acme_enabled", "acme_require_eab"):
        control = _toggle(tree, element_id)
        assert control.tag == "input" and control.get("type") == "checkbox", (
            f"#{element_id} is a <{control.tag} type={control.get('type')!r}>. FR-13 "
            f"keeps the real control -- its id, its name, its value and its position "
            f"in the form it is already in -- and draws it as the design's track"
        )
        assert "toggle" in control.classes, (
            f"#{element_id} does not carry `toggle`: {sorted(control.classes)}"
        )
        assert control.get("name") == element_id
        assert control.get("value") == "on"
        assert control.closest(tag="form") is form, (
            f"#{element_id} is not inside the one form that posts to {ACME_PAGE}"
        )

    # both on
    both = client.post(
        ACME_PAGE,
        data={"acme_enabled": "on", "acme_require_eab": "on", "csrf_token": _csrf(client, cfg)},
    )
    assert both.status_code == 303, both.text
    db = _db(cfg)
    try:
        assert get_flag(db, ACME_ENABLED) is True
        assert get_flag(db, ACME_REQUIRE_EAB) is True
    finally:
        db.close()

    # only one of them: the other goes off, which is spec 0019's own behaviour
    one = client.post(ACME_PAGE, data={"acme_enabled": "on", "csrf_token": _csrf(client, cfg)})
    assert one.status_code == 303, one.text
    db = _db(cfg)
    try:
        assert get_flag(db, ACME_ENABLED) is True
        assert get_flag(db, ACME_REQUIRE_EAB) is False, (
            "a submission without `acme_require_eab` left it on. An absent checkbox "
            "means off (acme_ui.py:214-218), and that is why a per-toggle submit "
            "button on this page would turn ACME off when EAB was turned on"
        )
    finally:
        db.close()


def test_one_save_still_writes_every_settings_flag(client: TestClient, cfg: Config) -> None:
    """AC-13 clause 3: the same shape on `/settings`, where seven fields
    share one wrapping `<form>` (`settings.html:14`).

    The extra half here is the one that has nothing to do with toggles: a
    POST that changes only `mcp_enabled` must leave `base_url` and
    `dns_resolvers` exactly as they were. A per-toggle button would post the
    whole form with those two fields absent and clear them both.
    """
    _setup(client, cfg)

    page = client.get("/settings")
    assert page.status_code == 200
    tree = dom.parse(page.text)
    forms = [node for node in tree.find_all(tag="form") if node.get("action") == "/settings"]
    assert len(forms) == 1, f"/settings has {len(forms)} forms posting to itself"
    submits = [
        node for node in forms[0].find_all(tag="button") if (node.get("type") or "") == "submit"
    ]
    assert len(submits) == 1, (
        f"/settings carries {len(submits)} submit buttons; seven fields share one form"
    )
    for element_id in ("acme_enabled", "mcp_enabled"):
        control = _toggle(tree, element_id)
        assert control.tag == "input" and control.get("type") == "checkbox", control.attrs
        assert "toggle" in control.classes, (
            f"#{element_id} on /settings does not carry `toggle`: {sorted(control.classes)}"
        )
        assert control.closest(tag="form") is forms[0]

    db = _db(cfg)
    try:
        before_base_url = get_setting(db, BASE_URL)
        before_resolvers = get_setting(db, DNS_RESOLVERS)
    finally:
        db.close()
    assert before_base_url, "the fixture set no base URL, so this clause measures nothing"

    saved = client.post(
        "/settings",
        data={
            "base_url": before_base_url,
            "dns_resolvers": before_resolvers or "",
            "mcp_enabled": "on",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert saved.status_code == 303, saved.text
    db = _db(cfg)
    try:
        assert get_flag(db, MCP_ENABLED) is True
        assert get_setting(db, BASE_URL) == before_base_url, (
            "the base URL changed when only a toggle was saved"
        )
        assert get_setting(db, DNS_RESOLVERS) == before_resolvers
    finally:
        db.close()


def test_acme_page_is_admin_only_and_in_the_nav(client: TestClient, cfg: Config) -> None:
    """FR-5: a viewer is neither offered the page nor allowed onto it."""
    csrf = _setup(client, cfg)
    assert 'href="/acme/admin"' in client.get("/").text

    created = client.post(
        "/users",
        data={
            "username": "bob",
            "password": "correcthorse1",
            "role": "viewer",
            "csrf_token": csrf,
        },
    )
    assert created.status_code == 303, created.text
    client.post("/logout", data={"csrf_token": csrf})
    assert (
        client.post("/login", data={"username": "bob", "password": "correcthorse1"}).status_code
        == 303
    )

    assert client.get(ACME_PAGE).status_code == 403
    assert 'href="/acme/admin"' not in client.get("/").text
    assert client.post(f"{ACME_PAGE}/eab-keys", data={"label": "x"}).status_code == 403


def test_acme_page_refuses_to_enable_without_a_base_url(client: TestClient, cfg: Config) -> None:
    """The same guard /settings has: ACME hands out absolute URLs, so it
    cannot be switched on before cabin knows its own address."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    csrf = _csrf(client, cfg)

    refused = client.post(ACME_PAGE, data={"acme_enabled": "on", "csrf_token": csrf})

    assert refused.status_code == 400, refused.text
    assert "base URL" in refused.text
    db = _db(cfg)
    try:
        assert get_flag(db, ACME_ENABLED) is False
    finally:
        db.close()


def test_settings_cross_links_to_the_acme_page(client: TestClient, cfg: Config) -> None:
    """FR-5: /settings keeps the master switch it has always had and points
    at the page that owns the rest of ACME."""
    _setup(client, cfg)

    assert 'href="/acme/admin"' in client.get("/settings").text


def test_inventory_shows_acme_source(client: TestClient, cfg: Config) -> None:
    """FR-7/AC-7: an ACME-issued certificate is a normal inventory row that
    says where it came from -- and is revocable from the UI like any other."""
    csrf = _setup(client, cfg)
    db = _db(cfg)
    try:
        secrets = SecretStore.open(cfg.data_dir, cfg.master_passphrase)
        hierarchy = ca_service.create_hierarchy(
            db, secrets, "cabin test", "cabin test Intermediate"
        )
        principal = grant_fixtures.granted_admin(db, hierarchy.intermediate.id)
        # spec 0017 FR-7: issue_and_store/sign_csr_and_store now return an
        # Issued(row, capped_from) wrapper rather than a bare row.
        issued = certs_service.issue_and_store(
            db,
            secrets,
            principal=principal,
            profile=Profile.server,
            subject_cn="nas.lan",
            sans=["nas.lan"],
            source=CertSource.acme,
        )
        other = certs_service.issue_and_store(
            db,
            secrets,
            principal=principal,
            profile=Profile.server,
            subject_cn="ui.lan",
            sans=["ui.lan"],
        )
        cert_id, other_id = issued.row.id, other.row.id
        issuer_id = hierarchy.intermediate.id
    finally:
        db.close()

    listing = client.get("/certs")
    assert listing.status_code == 200, listing.text
    assert "acme" in listing.text
    assert listing.text.count("tag-source-acme") == 1
    assert listing.text.count("tag-source-ui") == 1

    revoked = client.post(
        f"/certs/{cert_id}/revoke",
        data={"reason": "superseded", "confirm": "on", "csrf_token": csrf},
    )
    assert revoked.status_code == 303, revoked.text
    db = _db(cfg)
    try:
        assert certs_service.get_certificate(db, cert_id).revoked_at is not None  # type: ignore[union-attr]
        assert certs_service.get_certificate(db, other_id).source == CertSource.ui  # type: ignore[union-attr]
    finally:
        db.close()
    # spec 0017 FR-10: /crl is gone with no alias; the per-issuer route
    # (/crl/{issuer_id}) is what replaces it.
    assert client.get("/crl").status_code == 404
    crl = client.get(f"/crl/{issuer_id}")
    assert crl.status_code == 200


# === spec 0030 AC-14 clause 4: the EAB secret, the same four clauses ======


def test_the_eab_secret_is_stored_nowhere(client: TestClient, cfg: Config) -> None:
    """AC-14 clause 4. `POST /acme/admin/eab-keys` is the second of FR-3's
    two named exclusions that render rather than redirect, and it is
    excluded for the same reason: a flash would put a live credential in a
    database column in clear text and show it again on the next page load.
    """
    _setup(client, cfg)
    created = client.post(
        f"{ACME_PAGE}/eab-keys",
        data={"label": "edge", "issuer_id": _issuer_id(cfg), "csrf_token": _csrf(client, cfg)},
    )
    assert created.status_code == 200, (
        f"POST /acme/admin/eab-keys answered {created.status_code}; it renders the "
        f"page with the secret shown exactly once and must keep doing so"
    )
    assert created.headers["cache-control"] == "no-store"

    tree = dom.parse(created.text)
    copyable = tree.find_all(cls="copyable")
    assert copyable, (
        "the EAB page carries no `.copyable` element. FR-14 names three users for "
        "it: the API-token secret, the EAB secret and the ACME directory URL"
    )
    secrets = [node.text() for node in copyable if _SECRET_RE.fullmatch(node.text())]
    assert secrets, (
        f"the one-time EAB secret is not inside a `.copyable`: "
        f"{[node.text()[:24] for node in copyable]}"
    )
    secret = secrets[0]

    db = _db(cfg)
    try:
        columns = {column["name"] for column in sa.inspect(db.get_bind()).get_columns("sessions")}
        assert "flash" in columns, (
            "`sessions` has no `flash` column, so the clause below reads nothing. "
            "FR-2 adds it; a build without it cannot be measured for what it puts "
            "there and must fail rather than skip"
        )
        stored = [
            str(value)
            for (value,) in db.execute(sa.text("SELECT flash FROM sessions")).all()
            if value is not None
        ]
        assert not any(secret in value for value in stored), (
            "the EAB secret is sitting in a `sessions.flash` column in clear text"
        )
        #: The column is `detail_json` (`audit.py:190`); `AuditEvent.detail` is
        #: the decoded property beside it and is not a column raw SQL can name.
        events = db.execute(sa.text("SELECT summary, detail_json FROM audit_events")).all()
    finally:
        db.close()
    for summary, detail in events:
        assert secret not in (summary or ""), summary
        assert secret not in (detail or ""), "the EAB secret leaked into an event's detail"

    again = client.get(ACME_PAGE)
    assert again.status_code == 200
    assert secret not in again.text, "the ACME page showed the EAB secret a second time"
