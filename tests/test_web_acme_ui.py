"""Spec 0012 FR-5/FR-7, AC-6/AC-7: the ACME admin page -- its toggles, its
EAB keys and their one-time secret -- and the ACME origin of an issued
certificate in the normal inventory."""

import base64
import re
from collections.abc import Iterator
from pathlib import Path

import grant_fixtures
import pytest
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
    get_flag,
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
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin"
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
        hierarchy = ca_service.create_hierarchy(db, secrets, "cabin test")
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
