"""Web-layer tests for spec 0003: setup, login/logout, CSRF, roles, sessions."""

import re
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.config import Config
from cabin.sessions import _utcnow, get_session
from cabin.store import create_session_factory
from cabin.users import count_users, list_users


def make_config(tmp_path: Path, *, cookie_secure: bool = False) -> Config:
    data_dir = tmp_path / "data"
    return Config(
        port=8080,
        data_dir=data_dir,
        db_url=f"sqlite:///{data_dir}/cabin.db",
        cookie_secure=cookie_secure,
    )


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
    assert resp.headers["location"] == "/"
    assert "cabin_session" in resp.cookies  # client jar already picked this up


def _csrf_token_for(cfg: Config, raw_token: str) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, raw_token)
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


# --- AC-1 / FR-5: first-run setup -------------------------------------------


def test_setup_flow_first_run(client: TestClient, cfg: Config) -> None:
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup"

    resp = client.get("/setup")
    assert resp.status_code == 200
    assert "Create the superadmin account" in resp.text

    resp = client.post("/setup", data={"username": "alice", "password": "correcthorse1"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert "cabin_session" in resp.cookies

    resp = client.get("/")
    assert resp.status_code == 200
    assert "alice" in resp.text

    db = _db(cfg)
    try:
        assert count_users(db) == 1
    finally:
        db.close()


def test_setup_404_after_users_exist(client: TestClient) -> None:
    _setup_superadmin(client)

    assert client.get("/setup").status_code == 404
    assert (
        client.post("/setup", data={"username": "bob", "password": "whatever12345"}).status_code
        == 404
    )


# --- AC-2: login ------------------------------------------------------------


def test_login_wrong_password(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    client.cookies.clear()

    resp = client.post("/login", data={"username": "alice", "password": "wrongpassword"})
    assert resp.status_code == 401
    assert "cabin_session" not in resp.cookies
    assert "invalid" in resp.text.lower()


def test_login_sets_cookie_flags(client: TestClient) -> None:
    _setup_superadmin(client)
    client.cookies.clear()

    resp = client.post("/login", data={"username": "alice", "password": "correcthorse1"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    set_cookie = resp.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "secure" not in set_cookie.lower()

    resp = client.get("/")
    assert resp.status_code == 200
    assert "alice" in resp.text


def test_login_sets_secure_cookie_when_configured(tmp_path: Path) -> None:
    cfg = make_config(tmp_path, cookie_secure=True)
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        _setup_superadmin(client)
        client.cookies.clear()
        resp = client.post("/login", data={"username": "alice", "password": "correcthorse1"})
        assert "secure" in resp.headers["set-cookie"].lower()


# --- AC-3: logout -------------------------------------------------------------


def test_logout_invalidates_session(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    token = client.cookies["cabin_session"]
    csrf = _csrf_token_for(cfg, token)

    resp = client.post("/logout", data={"csrf_token": csrf})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    # the session row itself is gone, not just "looks logged out"
    db = _db(cfg)
    try:
        assert get_session(db, token) is None
    finally:
        db.close()

    # old cookie no longer authenticates
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --- AC-4: CSRF ---------------------------------------------------------------


def test_csrf_missing_or_wrong_403(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    resp = client.post(
        "/users",
        data={"username": "mallory", "password": "whatever12345", "role": "viewer"},
    )
    assert resp.status_code == 403

    resp = client.post(
        "/users",
        data={
            "username": "mallory",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": "wrong-token",
        },
    )
    assert resp.status_code == 403

    db = _db(cfg)
    try:
        assert {u.username for u in list_users(db)} == {"alice"}
    finally:
        db.close()


def test_csrf_non_ascii_token_is_403_not_500(client: TestClient) -> None:
    """hmac.compare_digest on two str raises TypeError for non-ascii input;
    a forged/garbage csrf_token must be a clean 403, never a 500."""
    _setup_superadmin(client)

    resp = client.post(
        "/users",
        data={
            "username": "mallory",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": "töken",
        },
    )
    assert resp.status_code == 403


# --- AC-5: role guards ---------------------------------------------------------


def _create_user_as_superadmin(client: TestClient, cfg: Config, username: str, role: str) -> None:
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303


def test_role_viewer_cannot_mutate(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    client.cookies.clear()

    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/users",
        data={
            "username": "mallory",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 403

    db = _db(cfg)
    try:
        assert "mallory" not in {u.username for u in list_users(db)}
    finally:
        db.close()


def test_role_admin_cannot_manage_users(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "adam", "admin")
    client.cookies.clear()

    resp = client.post("/login", data={"username": "adam", "password": "whatever12345"})
    assert resp.status_code == 303
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/users",
        data={
            "username": "mallory",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 403


def test_role_superadmin_can_manage_users(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "carol", "viewer")

    db = _db(cfg)
    try:
        assert "carol" in {u.username for u in list_users(db)}
    finally:
        db.close()


@pytest.mark.parametrize("role", ["admin", "viewer"])
@pytest.mark.parametrize(
    ("path_suffix", "form_data"),
    [
        ("", {"username": "mallory", "password": "whatever12345", "role": "viewer"}),
        ("/{id}/role", {"role": "viewer"}),
        ("/{id}/password", {"password": "whatever12345"}),
        ("/{id}/delete", {}),
    ],
    ids=["create", "role", "password", "delete"],
)
def test_role_cannot_manage_users_via_any_route(
    client: TestClient,
    cfg: Config,
    role: str,
    path_suffix: str,
    form_data: dict[str, str],
) -> None:
    """AC-5, every user-management POST route: neither admin nor viewer may
    mutate users, whichever of create/role/password/delete they try."""
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "target", "viewer")
    _create_user_as_superadmin(client, cfg, f"actor_{role}", role)

    db = _db(cfg)
    try:
        target_id = next(u.id for u in list_users(db) if u.username == "target")
    finally:
        db.close()

    resp = client.post("/login", data={"username": f"actor_{role}", "password": "whatever12345"})
    assert resp.status_code == 303
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    path = "/users" + path_suffix.format(id=target_id)
    resp = client.post(path, data={**form_data, "csrf_token": csrf})
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_role_can_view_users_list(client: TestClient, cfg: Config, role: str) -> None:
    """AC-5/FR-6: viewer=read-only pages -- both non-superadmin roles can
    still see the users list, only mutating it is forbidden."""
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, f"actor_{role}", role)

    resp = client.post("/login", data={"username": f"actor_{role}", "password": "whatever12345"})
    assert resp.status_code == 303

    resp = client.get("/users")
    assert resp.status_code == 200


# --- AC-6: last superadmin protection -----------------------------------------


def test_last_superadmin_protected(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    db = _db(cfg)
    try:
        alice_id = next(u.id for u in list_users(db) if u.username == "alice")
    finally:
        db.close()

    resp = client.post(f"/users/{alice_id}/role", data={"role": "admin", "csrf_token": csrf})
    assert resp.status_code == 400

    resp = client.post(f"/users/{alice_id}/delete", data={"csrf_token": csrf})
    assert resp.status_code == 400

    db = _db(cfg)
    try:
        alice = next(u for u in list_users(db) if u.username == "alice")
        assert alice.role == "superadmin"
    finally:
        db.close()


# --- AC-7: expired sessions ----------------------------------------------------


def test_expired_session_unauthenticated(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    token = client.cookies["cabin_session"]

    db = _db(cfg)
    try:
        row = get_session(db, token)
        assert row is not None
        row.expires_at = _utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --- AC-8: weak passwords -------------------------------------------------------


def test_weak_password_rejected_on_setup(client: TestClient, cfg: Config) -> None:
    resp = client.post("/setup", data={"username": "alice", "password": "short1"})
    assert resp.status_code == 400

    db = _db(cfg)
    try:
        assert count_users(db) == 0
    finally:
        db.close()


def test_weak_password_rejected_on_user_create(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    resp = client.post(
        "/users",
        data={
            "username": "bob",
            "password": "short1",
            "role": "viewer",
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400

    db = _db(cfg)
    try:
        assert "bob" not in {u.username for u in list_users(db)}
    finally:
        db.close()


def test_weak_password_rejected_on_password_reset(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf_token_for(cfg, client.cookies["cabin_session"])

    db = _db(cfg)
    try:
        alice_id = next(u.id for u in list_users(db) if u.username == "alice")
        old_hash = next(u for u in list_users(db) if u.username == "alice").password_hash
    finally:
        db.close()

    resp = client.post(
        f"/users/{alice_id}/password", data={"password": "short1", "csrf_token": csrf}
    )
    assert resp.status_code == 400

    db = _db(cfg)
    try:
        alice = next(u for u in list_users(db) if u.username == "alice")
        assert alice.password_hash == old_hash
    finally:
        db.close()


# --- BUG 1: dashboard's logout form must carry a real csrf_token --------------


def test_dashboard_logout_form_csrf_token_works(client: TestClient, cfg: Config) -> None:
    """AC-3: logging out from the dashboard (not /users) must actually work.

    Scrapes the csrf_token out of the rendered HTML -- the same way a real
    browser would submit the form -- rather than reading it out of the DB,
    so this catches the template/context wiring bug, not just the backend.
    """
    _setup_superadmin(client)
    token = client.cookies["cabin_session"]

    resp = client.get("/")
    assert resp.status_code == 200
    match = re.search(r'name="csrf_token"\s+value="([^"]*)"', resp.text)
    assert match is not None, "no csrf_token hidden input found on the dashboard page"
    scraped_csrf = match.group(1)
    assert scraped_csrf, "csrf_token hidden input rendered empty"

    resp = client.post("/logout", data={"csrf_token": scraped_csrf})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    db = _db(cfg)
    try:
        assert get_session(db, token) is None
    finally:
        db.close()


# --- BUG 2: sliding session must re-issue the cookie to the browser ----------


def test_sliding_session_reissues_cookie_when_near_expiry(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    token = client.cookies["cabin_session"]

    db = _db(cfg)
    try:
        row = get_session(db, token)
        assert row is not None
        row.expires_at = _utcnow() + timedelta(hours=1)  # < 23h remaining -> should refresh
        db.commit()
    finally:
        db.close()

    resp = client.get("/")
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie")
    assert set_cookie is not None
    assert "cabin_session=" in set_cookie
    assert "max-age=86400" in set_cookie.lower()


def test_fresh_session_does_not_reissue_cookie(client: TestClient) -> None:
    _setup_superadmin(client)
    # session was just created by setup: ~24h remaining, well above the 23h
    # refresh threshold, so no Set-Cookie should be re-issued on next use.
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("set-cookie") is None


def test_logout_of_near_expiry_session_still_deletes_cookie(
    client: TestClient, cfg: Config
) -> None:
    """The sliding-refresh middleware must not clobber /logout's own
    cookie deletion when the session it just deleted also happened to be
    due for a refresh."""
    _setup_superadmin(client)
    token = client.cookies["cabin_session"]
    csrf = _csrf_token_for(cfg, token)

    db = _db(cfg)
    try:
        row = get_session(db, token)
        assert row is not None
        row.expires_at = _utcnow() + timedelta(hours=1)  # due for a refresh
        db.commit()
    finally:
        db.close()

    resp = client.post("/logout", data={"csrf_token": csrf})
    assert resp.status_code == 303
    set_cookie = resp.headers["set-cookie"]
    assert "max-age=86400" not in set_cookie.lower()

    db = _db(cfg)
    try:
        assert get_session(db, token) is None
    finally:
        db.close()


# --- quality review: password reset invalidates the target's sessions --------


def test_password_reset_invalidates_target_users_session(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "bob", "viewer")
    admin_token = client.cookies["cabin_session"]
    admin_csrf = _csrf_token_for(cfg, admin_token)

    resp = client.post("/login", data={"username": "bob", "password": "whatever12345"})
    assert resp.status_code == 303
    bob_token = client.cookies["cabin_session"]

    # bob's session works before the reset
    resp = client.get("/", headers={"Cookie": f"cabin_session={bob_token}"})
    assert resp.status_code == 200

    db = _db(cfg)
    try:
        bob_id = next(u.id for u in list_users(db) if u.username == "bob")
    finally:
        db.close()

    resp = client.post(
        f"/users/{bob_id}/password",
        data={"password": "brandnewlongpassword", "csrf_token": admin_csrf},
        headers={"Cookie": f"cabin_session={admin_token}"},
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/users"  # not /login: the admin request itself succeeded

    # bob's old cookie no longer authenticates
    resp = client.get("/", headers={"Cookie": f"cabin_session={bob_token}"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    db = _db(cfg)
    try:
        assert get_session(db, bob_token) is None
    finally:
        db.close()


# --- quality review: deleting a user invalidates/removes their sessions ------


def test_delete_user_removes_their_session_and_unauthenticates(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "bob", "viewer")
    admin_token = client.cookies["cabin_session"]
    admin_csrf = _csrf_token_for(cfg, admin_token)

    resp = client.post("/login", data={"username": "bob", "password": "whatever12345"})
    assert resp.status_code == 303
    bob_token = client.cookies["cabin_session"]

    db = _db(cfg)
    try:
        bob_id = next(u.id for u in list_users(db) if u.username == "bob")
    finally:
        db.close()

    resp = client.post(
        f"/users/{bob_id}/delete",
        data={"csrf_token": admin_csrf},
        headers={"Cookie": f"cabin_session={admin_token}"},
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/users"  # not /login: the admin request itself succeeded

    db = _db(cfg)
    try:
        assert get_session(db, bob_token) is None
    finally:
        db.close()

    resp = client.get("/", headers={"Cookie": f"cabin_session={bob_token}"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --- quality review: first-run setup race is never a 500 ---------------------


def test_setup_concurrent_posts_never_500_and_create_one_user(
    client: TestClient, cfg: Config
) -> None:
    """Two near-simultaneous POST /setup (same username) must never 500:
    the module-level lock serializes check+create, so the loser sees the
    already-covered post-setup 404 (or, in a genuine DB-level race, a
    friendly re-render) -- and exactly one superadmin is ever created."""
    from concurrent.futures import ThreadPoolExecutor

    def _post() -> int:
        resp = client.post("/setup", data={"username": "alice", "password": "correcthorse1"})
        return resp.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _post(), range(2)))

    assert all(code < 500 for code in results), results

    db = _db(cfg)
    try:
        assert count_users(db) == 1
    finally:
        db.close()


# --- quality review: re-login replaces the old session, doesn't add to it ----


def test_relogin_leaves_only_one_session_row(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    first_token = client.cookies["cabin_session"]

    resp = client.post("/login", data={"username": "alice", "password": "correcthorse1"})
    assert resp.status_code == 303
    second_token = client.cookies["cabin_session"]
    assert second_token != first_token

    db = _db(cfg)
    try:
        assert get_session(db, first_token) is None
        assert get_session(db, second_token) is not None
    finally:
        db.close()


def test_login_does_not_invalidate_a_different_users_session(
    client: TestClient, cfg: Config
) -> None:
    """A cookie merely *presented* alongside someone else's login (e.g. a
    shared browser) is not the logging-in user's to invalidate."""
    _setup_superadmin(client)
    _create_user_as_superadmin(client, cfg, "bob", "viewer")
    admin_token = client.cookies["cabin_session"]

    # bob logs in on the same client/browser, admin's cookie still in the jar
    resp = client.post("/login", data={"username": "bob", "password": "whatever12345"})
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        assert get_session(db, admin_token) is not None
    finally:
        db.close()
