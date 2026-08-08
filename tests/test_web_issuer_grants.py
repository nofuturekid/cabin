"""Tests for managing issuer grants through the interface (spec 0018
FR-11): the superadmin-only ``POST /users/{id}/issuers`` and
``POST /tokens/{id}/issuers`` routes, and ``POST /tokens`` gaining the same
optional ``issuer_id`` field at creation.

Every test that grants or revokes through these routes proves the effect,
not the form: it drives a real issuance (through the UI for a user, through
REST for a token) before and after the change and checks what was actually
allowed, per the task brief's own warning that an implementation which
filters a select box but forgets to enforce the post would pass a
presence-only test. Where a rendered page is checked at all (the audit
filter's options), that mirrors the one precedent already in this codebase
for exactly that kind of assertion (test_web_audit.py's
test_ca_lifecycle_events_recorded).

Three active issuers, not one, wherever the scenario allows it: the
interesting case for FR-4's narrowed default rule is one granted issuer
among several active ones, not the trivial single-CA case.
"""

import re
from collections.abc import Iterator
from pathlib import Path

import ca_fixtures
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin import api_tokens
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca.certs import Certificate, get_certificate
from cabin.config import Config
from cabin.issuer_grants import TokenIssuer, UserIssuer
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.users import User

_SECRET_RE = re.compile(r"cabin_[A-Za-z0-9_-]{43}")
SUPERADMIN_PASSWORD = "correcthorse1"


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


def _secrets_for(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> None:
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


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _user_id(cfg: Config, username: str) -> int:
    db = _db(cfg)
    try:
        row = db.scalar(select(User).where(User.username == username))
        assert row is not None
        return row.id
    finally:
        db.close()


def _three_active_issuers(cfg: Config) -> tuple[int, int, int]:
    """Three real, independently-signing hierarchies -- real keys, because
    several of these tests actually issue through them, not merely resolve
    an id."""
    db = _db(cfg)
    secrets = _secrets_for(cfg)
    try:
        a = ca_fixtures.make_hierarchy(db, secrets, "alpha").intermediate.id
        b = ca_fixtures.make_hierarchy(db, secrets, "beta").intermediate.id
        c = ca_fixtures.make_hierarchy(db, secrets, "gamma").intermediate.id
        return a, b, c
    finally:
        db.close()


def _set_user_issuers(
    client: TestClient, cfg: Config, user_id: int, issuer_ids: list[int]
) -> Response:
    data: dict[str, object] = {"csrf_token": _csrf(client, cfg)}
    if issuer_ids:
        data["issuer_id"] = issuer_ids
    return client.post(f"/users/{user_id}/issuers", data=data)


def _set_token_issuers(
    client: TestClient, cfg: Config, token_id: int, issuer_ids: list[int]
) -> Response:
    data: dict[str, object] = {"csrf_token": _csrf(client, cfg)}
    if issuer_ids:
        data["issuer_id"] = issuer_ids
    return client.post(f"/tokens/{token_id}/issuers", data=data)


def _issue(client: TestClient, cfg: Config, *, issuer_id: int | None, cn: str) -> Response:
    data: dict[str, object] = {
        "subject_cn": cn,
        "sans": cn,
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": "90",
        "csrf_token": _csrf(client, cfg),
    }
    if issuer_id is not None:
        data["issuer_id"] = issuer_id
    return client.post("/certs/issue", data=data)


def _rest_issue(client: TestClient, secret: str, *, issuer_id: int | None, cn: str) -> Response:
    body: dict[str, object] = {
        "subject_cn": cn,
        "sans": [cn],
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": 90,
    }
    if issuer_id is not None:
        body["issuer_id"] = issuer_id
    return client.post(
        "/api/v1/certificates", json=body, headers={"Authorization": f"Bearer {secret}"}
    )


def _cert_count(cfg: Config) -> int:
    db = _db(cfg)
    try:
        return db.query(Certificate).count()
    finally:
        db.close()


def _cert_issuer_id(cfg: Config, cert_id: int) -> int:
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        return row.issuer_id
    finally:
        db.close()


def _token_id(cfg: Config, label: str) -> int:
    db = _db(cfg)
    try:
        row = next(r for r in api_tokens.list_tokens(db) if r.label == label)
        return row.id
    finally:
        db.close()


def _create_admin_token(
    client: TestClient, cfg: Config, label: str, issuer_ids: list[int] | None = None
) -> tuple[str, int]:
    data: dict[str, object] = {
        "label": label,
        "role": "admin",
        "expires_at": "",
        "csrf_token": _csrf(client, cfg),
    }
    if issuer_ids:
        data["issuer_id"] = issuer_ids
    resp = client.post("/tokens", data=data)
    assert resp.status_code == 200, resp.text
    match = _SECRET_RE.search(resp.text)
    assert match is not None
    return match.group(0), _token_id(cfg, label)


# --- granting/revoking through /users/{id}/issuers: proved by real issuance -


def test_grant_through_users_page_lets_the_holder_issue_from_it(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    a, _b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")

    _login(client, "adam")
    refused = _issue(client, cfg, issuer_id=a, cn="before-grant.example.lan")
    assert refused.status_code == 403
    assert _cert_count(cfg) == 0

    _login(client, "alice", SUPERADMIN_PASSWORD)
    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303

    _login(client, "adam")
    # The interesting case (FR-4's third row): one granted issuer among
    # three active ones resolves without being named.
    issued = _issue(client, cfg, issuer_id=None, cn="after-grant.example.lan")
    assert issued.status_code == 303, issued.text
    cert_id = int(issued.headers["location"].rsplit("/", 1)[1])
    assert _cert_issuer_id(cfg, cert_id) == a


def test_revoke_through_users_page_removes_the_ability_to_issue(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    a, _b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")
    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303

    _login(client, "adam")
    assert _issue(client, cfg, issuer_id=None, cn="still-granted.example.lan").status_code == 303
    count_before = _cert_count(cfg)

    _login(client, "alice", SUPERADMIN_PASSWORD)
    # An empty post is how a grant is taken away entirely (FR-11).
    assert _set_user_issuers(client, cfg, adam_id, []).status_code == 303

    _login(client, "adam")
    refused = _issue(client, cfg, issuer_id=a, cn="after-revoke.example.lan")
    assert refused.status_code == 403
    assert _cert_count(cfg) == count_before


def test_users_page_grant_replaces_rather_than_accumulates(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    a, b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")
    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303
    assert _set_user_issuers(client, cfg, adam_id, [b]).status_code == 303

    _login(client, "adam")
    refused = _issue(client, cfg, issuer_id=a, cn="old-grant.example.lan")
    assert refused.status_code == 403
    ok = _issue(client, cfg, issuer_id=None, cn="new-grant.example.lan")
    assert ok.status_code == 303, ok.text
    cert_id = int(ok.headers["location"].rsplit("/", 1)[1])
    assert _cert_issuer_id(cfg, cert_id) == b


def test_pre_granting_a_viewer_grants_nothing_until_promoted(
    client: TestClient, cfg: Config
) -> None:
    """FR-11: a viewer row shows the grant control with a note that it
    grants nothing until the role changes -- because the grant survives a
    role change (FR-10), so pre-granting someone about to be promoted is
    legitimate. This proves the effect of both rules together: the refusal
    while a viewer is the role gate, not a missing grant, and no second
    POST to /users/{id}/issuers is needed after the promotion."""
    _setup_superadmin(client)
    _create_user(client, cfg, "vera", "viewer")
    a, _b, _c = _three_active_issuers(cfg)
    vera_id = _user_id(cfg, "vera")

    assert _set_user_issuers(client, cfg, vera_id, [a]).status_code == 303

    _login(client, "vera")
    refused = _issue(client, cfg, issuer_id=a, cn="viewer.example.lan")
    assert refused.status_code == 403
    assert _cert_count(cfg) == 0

    _login(client, "alice", SUPERADMIN_PASSWORD)
    promoted = client.post(
        f"/users/{vera_id}/role", data={"role": "admin", "csrf_token": _csrf(client, cfg)}
    )
    assert promoted.status_code == 303

    _login(client, "vera")
    ok = _issue(client, cfg, issuer_id=None, cn="promoted.example.lan")
    assert ok.status_code == 303, ok.text
    cert_id = int(ok.headers["location"].rsplit("/", 1)[1])
    assert _cert_issuer_id(cfg, cert_id) == a


# --- granting/revoking through /tokens/{id}/issuers: proved over REST ------


def test_grant_through_tokens_page_lets_the_token_issue_over_rest(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    a, _b, _c = _three_active_issuers(cfg)
    secret, token_id = _create_admin_token(client, cfg, "script")

    refused = _rest_issue(client, secret, issuer_id=a, cn="before.example.lan")
    assert refused.status_code == 403
    assert _cert_count(cfg) == 0

    assert _set_token_issuers(client, cfg, token_id, [a]).status_code == 303

    ok = _rest_issue(client, secret, issuer_id=None, cn="after.example.lan")
    assert ok.status_code == 201, ok.text
    assert _cert_issuer_id(cfg, ok.json()["id"]) == a


def test_revoke_through_tokens_page_removes_rest_access(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    a, _b, _c = _three_active_issuers(cfg)
    secret, token_id = _create_admin_token(client, cfg, "script", issuer_ids=[a])

    assert (
        _rest_issue(client, secret, issuer_id=None, cn="while-granted.example.lan").status_code
        == 201
    )
    count_before = _cert_count(cfg)

    assert _set_token_issuers(client, cfg, token_id, []).status_code == 303

    refused = _rest_issue(client, secret, issuer_id=a, cn="after-revoke.example.lan")
    assert refused.status_code == 403
    assert _cert_count(cfg) == count_before


def test_token_created_with_issuers_field_can_issue_immediately(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    a, _b, _c = _three_active_issuers(cfg)
    secret, _token_id = _create_admin_token(client, cfg, "born-granted", issuer_ids=[a])

    ok = _rest_issue(client, secret, issuer_id=None, cn="born-granted.example.lan")
    assert ok.status_code == 201, ok.text
    assert _cert_issuer_id(cfg, ok.json()["id"]) == a


# --- AC-13: superadmin + CSRF only, exactly as user/token management already are


def test_issuer_grant_routes_require_superadmin(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    _create_user(client, cfg, "vera", "viewer")
    a, _b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")
    _secret, token_id = _create_admin_token(client, cfg, "script")

    for username in ("adam", "vera"):
        _login(client, username)
        assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 403
        assert _set_token_issuers(client, cfg, token_id, [a]).status_code == 403

    db = _db(cfg)
    try:
        assert db.scalar(select(sa.func.count()).select_from(UserIssuer)) == 0
        assert db.scalar(select(sa.func.count()).select_from(TokenIssuer)) == 0
    finally:
        db.close()


def test_issuer_grant_routes_require_csrf(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    a, _b, _c = _three_active_issuers(cfg)
    _create_user(client, cfg, "adam", "admin")
    adam_id = _user_id(cfg, "adam")
    _secret, token_id = _create_admin_token(client, cfg, "script")

    assert client.post(f"/users/{adam_id}/issuers", data={"issuer_id": a}).status_code == 403
    assert client.post(f"/tokens/{token_id}/issuers", data={"issuer_id": a}).status_code == 403

    db = _db(cfg)
    try:
        assert db.scalar(select(sa.func.count()).select_from(UserIssuer)) == 0
        assert db.scalar(select(sa.func.count()).select_from(TokenIssuer)) == 0
    finally:
        db.close()


def test_issuer_grant_routes_404_for_unknown_id(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert _set_user_issuers(client, cfg, 999_999, []).status_code == 404
    assert _set_token_issuers(client, cfg, 999_999, []).status_code == 404


def test_grant_on_a_root_via_users_page_is_refused(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    adam_id = _user_id(cfg, "adam")

    db = _db(cfg)
    secrets = _secrets_for(cfg)
    try:
        root_id = ca_fixtures.make_hierarchy(db, secrets, "root-test").root.id
    finally:
        db.close()

    resp = _set_user_issuers(client, cfg, adam_id, [root_id])
    assert resp.status_code == 400

    db = _db(cfg)
    try:
        assert (
            db.scalar(
                select(sa.func.count()).select_from(UserIssuer).where(UserIssuer.user_id == adam_id)
            )
            == 0
        )
        assert db.scalar(select(sa.func.count()).select_from(TokenIssuer)) == 0
    finally:
        db.close()


# --- AC-14: audit ------------------------------------------------------------


def test_grant_change_is_audited_with_added_and_removed(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    a, b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")

    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303
    assert _set_user_issuers(client, cfg, adam_id, [b]).status_code == 303

    db = _db(cfg)
    try:
        events = list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.action == AuditAction.user_issuers_changed.value)
                .order_by(AuditEvent.id)
            )
        )
        assert len(events) == 2
        assert events[0].target_type == "user"
        assert events[0].target_id == str(adam_id)
        assert events[0].detail == {"added": [a], "removed": [], "issuers": [a]}
        assert events[1].detail == {"added": [b], "removed": [a], "issuers": [b]}
    finally:
        db.close()


def test_token_grant_change_is_audited_as_token_issuers_changed(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    a, _b, _c = _three_active_issuers(cfg)
    _secret, token_id = _create_admin_token(client, cfg, "script")

    assert _set_token_issuers(client, cfg, token_id, [a]).status_code == 303

    db = _db(cfg)
    try:
        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == AuditAction.token_issuers_changed.value)
        )
        assert event is not None
        assert event.target_type == "api_token"
        assert event.target_id == str(token_id)
        assert event.detail == {"added": [a], "removed": [], "issuers": [a]}
    finally:
        db.close()


def test_reposting_the_identical_grant_set_records_no_new_event(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    a, _b, _c = _three_active_issuers(cfg)
    adam_id = _user_id(cfg, "adam")

    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303
    assert _set_user_issuers(client, cfg, adam_id, [a]).status_code == 303

    db = _db(cfg)
    try:
        count = db.scalar(
            select(sa.func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == AuditAction.user_issuers_changed.value)
        )
        assert count == 1
    finally:
        db.close()


def test_grant_actions_are_selectable_in_the_audit_filter(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    options = client.get("/audit").text
    assert '<option value="user_issuers_changed"' in options
    assert '<option value="token_issuers_changed"' in options
