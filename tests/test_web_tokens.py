"""UI tests for spec 0008 FR-6: the superadmin-only /tokens page with its
one-time secret, and role-aware navigation (AC-8)."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from cabin.api_tokens import list_tokens
from cabin.app import create_app
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory

_SECRET_RE = re.compile(r"cabin_[A-Za-z0-9_-]{43}")


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


# --- FR-6/AC-8: the tokens page ------------------------------------------------


def test_ui_tokens_superadmin_only(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    _create_user(client, cfg, "vera", "viewer")

    page = client.get("/tokens")
    assert page.status_code == 200
    assert "API tokens" in page.text

    created = client.post(
        "/tokens",
        data={
            "label": "ansible",
            "role": "admin",
            "expires_at": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert created.status_code == 200
    match = _SECRET_RE.search(created.text)
    assert match is not None
    secret = match.group(0)
    # AC-1: shown exactly once, and said so.
    assert "only time" in created.text or "shown once" in created.text

    listed = client.get("/tokens")
    assert listed.status_code == 200
    assert "ansible" in listed.text
    assert secret not in listed.text

    # The secret handed out on that page is a working API credential (AC-1).
    cookies = dict(client.cookies)
    client.cookies.clear()
    resp = client.get("/api/v1/certificates", headers={"Authorization": f"Bearer {secret}"})
    assert resp.status_code == 200
    client.cookies.update(cookies)

    token_id = int(re.search(r"/tokens/(\d+)/revoke", listed.text).group(1))  # type: ignore[union-attr]
    revoked = client.post(f"/tokens/{token_id}/revoke", data={"csrf_token": _csrf(client, cfg)})
    assert revoked.status_code == 303
    assert "revoked" in client.get("/tokens").text

    client.cookies.clear()
    assert (
        client.get(
            "/api/v1/certificates", headers={"Authorization": f"Bearer {secret}"}
        ).status_code
        == 401
    )

    # AC-8: admins and viewers have no business here at all.
    for username in ("adam", "vera"):
        _login(client, username)
        assert client.get("/tokens").status_code == 403
        assert (
            client.post(
                "/tokens",
                data={
                    "label": "sneaky",
                    "role": "superadmin",
                    "csrf_token": _csrf(client, cfg),
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/tokens/{token_id}/revoke", data={"csrf_token": _csrf(client, cfg)}
            ).status_code
            == 403
        )

    client.cookies.clear()
    anonymous = client.get("/tokens")
    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/login"


def _create(client: TestClient, cfg: Config, **overrides: str) -> Response:
    data = {
        "label": "token",
        "role": "admin",
        "expires_at": "",
        "csrf_token": _csrf(client, cfg),
    }
    data.update(overrides)
    return client.post("/tokens", data=data)


def test_ui_tokens_expiry_and_role_parsing(client: TestClient, cfg: Config) -> None:
    """FR-6: the expiry field and the role are parsed in the route, so every
    shape they can arrive in needs an answer -- including 9999-12-31, which
    is exactly what a browser's native date picker offers as its maximum and
    which "the end of that day" cannot be expressed for."""
    _setup_superadmin(client)
    today = datetime.now(UTC).date()

    ok = _create(
        client,
        cfg,
        label="thirty-days",
        expires_at=(today + timedelta(days=30)).isoformat(),
    )
    assert ok.status_code == 200

    # A token picked for "today" is usable through the end of today.
    today_token = _create(client, cfg, label="today", expires_at=today.isoformat())
    assert today_token.status_code == 200

    for label, field, value in (
        ("past", "expires_at", (today - timedelta(days=1)).isoformat()),
        ("overflow", "expires_at", "9999-12-31"),
        ("german", "expires_at", "31.12.2026"),
        ("empty-ish", "expires_at", "2026-13-01"),
        ("bad-role", "role", "root"),
    ):
        resp = _create(client, cfg, label=label, **{field: value})
        assert resp.status_code == 400, (label, value)
        assert resp.headers["content-type"].startswith("text/html")
        assert _SECRET_RE.search(resp.text) is None

    db = _db(cfg)
    try:
        rows = list_tokens(db)
        # Only the two accepted requests created anything.
        assert [row.label for row in rows] == ["thirty-days", "today"]
        # Valid through the end of the chosen day, stored as naive UTC.
        assert rows[0].expires_at == datetime.combine(
            today + timedelta(days=31), datetime.min.time()
        )
        assert rows[1].expires_at == datetime.combine(
            today + timedelta(days=1), datetime.min.time()
        )
    finally:
        db.close()


def test_ui_tokens_rejects_empty_label(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    resp = client.post(
        "/tokens",
        data={"label": "  ", "role": "admin", "csrf_token": _csrf(client, cfg)},
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert _SECRET_RE.search(resp.text) is None


# --- FR-6/AC-8: navigation only offers what the role can use -------------------


def test_nav_hides_unusable_entries(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    _create_user(client, cfg, "vera", "viewer")

    superadmin_nav = client.get("/").text
    for link in ('href="/certs/new"', 'href="/settings"', 'href="/tokens"'):
        assert link in superadmin_nav

    _login(client, "adam")
    admin_nav = client.get("/").text
    assert 'href="/certs/new"' in admin_nav
    assert 'href="/settings"' in admin_nav
    assert 'href="/tokens"' not in admin_nav

    _login(client, "vera")
    viewer_nav = client.get("/").text
    assert 'href="/certs/new"' not in viewer_nav
    assert 'href="/settings"' not in viewer_nav
    assert 'href="/tokens"' not in viewer_nav
    # What a viewer *can* use is still offered.
    for link in ('href="/certs"', 'href="/ca"', 'href="/users"'):
        assert link in viewer_nav

    # Hiding is cosmetic: the server still refuses, it does not merely omit.
    assert client.get("/certs/new").status_code == 403
    assert client.get("/settings").status_code == 403
    assert client.get("/tokens").status_code == 403
