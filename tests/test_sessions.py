"""Tests for cabin.sessions: DB-backed sessions, sliding expiry, CSRF tokens."""

import hashlib
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from cabin.sessions import (
    SESSION_LIFETIME,
    UserSession,
    _utcnow,
    create_session,
    delete_session,
    delete_sessions_for_user,
    get_session,
    purge_expired,
    touch_session,
)
from cabin.store import create_session_factory, run_migrations
from cabin.users import Role, create_user


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()


def test_create_session_stores_only_token_hash(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    token, row = create_session(db, user)
    assert len(token) > 20
    assert row.token_hash == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert row.user_id == user.id
    assert row.csrf_token
    assert row.csrf_token != token


def test_get_session_returns_row_for_valid_token(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    token, row = create_session(db, user)
    fetched = get_session(db, token)
    assert fetched is not None
    assert fetched.token_hash == row.token_hash


def test_get_session_unknown_token_returns_none(db: Session) -> None:
    assert get_session(db, "not-a-real-token") is None


def test_get_session_expired_returns_none(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    token, row = create_session(db, user)
    row.expires_at = _utcnow() - timedelta(seconds=1)
    db.commit()
    assert get_session(db, token) is None


def test_touch_session_extends_when_close_to_expiry(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    _token, row = create_session(db, user)
    row.expires_at = _utcnow() + timedelta(hours=1)
    db.commit()
    extended = touch_session(db, row)
    assert extended is True
    remaining = row.expires_at - _utcnow()
    assert remaining > timedelta(hours=23)


def test_touch_session_does_not_extend_when_fresh(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    _token, row = create_session(db, user)
    original_expiry = row.expires_at
    extended = touch_session(db, row)
    assert extended is False
    assert row.expires_at == original_expiry


def test_delete_session_removes_row(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    token, _row = create_session(db, user)
    delete_session(db, token)
    assert get_session(db, token) is None


def test_purge_expired_removes_only_expired(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    _fresh_token, fresh_row = create_session(db, user)
    _expired_token, expired_row = create_session(db, user)
    expired_row.expires_at = _utcnow() - timedelta(seconds=1)
    db.commit()

    purge_expired(db)

    assert db.get(UserSession, fresh_row.token_hash) is not None
    assert db.get(UserSession, expired_row.token_hash) is None


def test_session_lifetime_is_24h() -> None:
    assert timedelta(hours=24) == SESSION_LIFETIME


def test_delete_sessions_for_user_removes_all_their_rows_only(db: Session) -> None:
    alice = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    bob = create_user(db, "bob", "anotherlongpassword", Role.viewer)
    alice_token_1, _ = create_session(db, alice)
    alice_token_2, _ = create_session(db, alice)
    bob_token, _ = create_session(db, bob)

    delete_sessions_for_user(db, alice.id)

    assert get_session(db, alice_token_1) is None
    assert get_session(db, alice_token_2) is None
    assert get_session(db, bob_token) is not None


def test_get_session_with_non_ascii_token_returns_none_not_raises(db: Session) -> None:
    """A garbage/non-ASCII cookie value must be treated as 'no session', not
    crash sha256's ascii encoding (500)."""
    assert get_session(db, "töken-not-ascii") is None
