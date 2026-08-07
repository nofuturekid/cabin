"""Spec 0012 FR-5/FR-7, AC-6/AC-7: the ACME admin page -- its toggles, its
EAB keys and their one-time secret -- and the ACME origin of an issued
certificate in the normal inventory."""

import base64
import re
from collections.abc import Iterator
from pathlib import Path

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
    hand out any URL at all."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, "https://ca.example.org")
    finally:
        db.close()
    return _csrf(client, cfg)


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

    page = client.get(ACME_PAGE)
    assert page.status_code == 200, page.text
    assert "https://ca.example.org/acme/directory" in page.text
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

    created = client.post(f"{ACME_PAGE}/eab-keys", data={"label": "nas.lan", "csrf_token": csrf})
    assert created.status_code == 200, created.text
    rows = _keys(cfg)
    assert len(rows) == 1
    key_id = rows[0].id
    assert rows[0].label == "nas.lan"
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
        # spec 0017 FR-7: issue_and_store/sign_csr_and_store now return an
        # Issued(row, capped_from) wrapper rather than a bare row.
        issued = certs_service.issue_and_store(
            db,
            secrets,
            profile=Profile.server,
            subject_cn="nas.lan",
            sans=["nas.lan"],
            source=CertSource.acme,
        )
        other = certs_service.issue_and_store(
            db, secrets, profile=Profile.server, subject_cn="ui.lan", sans=["ui.lan"]
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
