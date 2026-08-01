"""Domain-layer tests for spec 0008 FR-2: token creation, storage as a
sha256 digest, verification and the last-used throttle (AC-1, AC-2, AC-7)."""

import hashlib
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from cabin.api_tokens import (
    TOKEN_PREFIX,
    create_token,
    list_tokens,
    revoke_token,
    verify_token,
)
from cabin.store import create_session_factory, run_migrations
from cabin.users import Role


@pytest.fixture
def db_file(tmp_path: Path) -> Path:
    return tmp_path / "cabin.db"


@pytest.fixture
def db(db_file: Path) -> Iterator[Session]:
    url = f"sqlite:///{db_file}"
    run_migrations(url)
    session = create_session_factory(url)()
    try:
        yield session
    finally:
        session.close()


def _dump(db_file: Path) -> str:
    """Everything the database physically holds, as one string -- the only
    honest way to assert that a secret is *not* in there anywhere."""
    con = sqlite3.connect(db_file)
    try:
        return "\n".join(con.iterdump())
    finally:
        con.close()


def test_create_token_returns_secret_once(db: Session, db_file: Path) -> None:
    """AC-1: the plaintext comes back from the create call and from nowhere
    else -- not from the row, not from the database file."""
    secret, row = create_token(db, "ansible", Role.admin)

    assert secret.startswith(TOKEN_PREFIX)
    # 32 random bytes, urlsafe-base64, unpadded (FR-2).
    assert len(secret) == len(TOKEN_PREFIX) + 43
    assert row.label == "ansible"
    assert row.role == Role.admin.value
    assert row.revoked_at is None
    assert row.last_used_at is None

    second, _ = create_token(db, "ansible", Role.admin)
    assert second != secret

    assert secret not in _dump(db_file)
    assert [t.label for t in list_tokens(db)] == ["ansible", "ansible"]


def test_token_hash_stored_not_secret(db: Session) -> None:
    """FR-2: sha256 hex of the secret, nothing reversible."""
    secret, row = create_token(db, "scripts", Role.viewer)

    assert row.token_hash == hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert secret not in row.token_hash


def test_verify_token_rejects_wrong_expired_revoked(db: Session) -> None:
    """AC-1/AC-2: only a live, unexpired, unrevoked secret authenticates."""
    now = datetime.now(UTC)
    secret, row = create_token(db, "good", Role.admin)

    verified = verify_token(db, secret, now)
    assert verified is not None
    assert verified.id == row.id

    assert verify_token(db, secret + "x", now) is None
    assert verify_token(db, "cabin_" + "A" * 43, now) is None
    assert verify_token(db, "", now) is None
    # Not even a well-formed bearer value: must be a clean miss, not a crash.
    assert verify_token(db, "ünicode", now) is None

    expiring, _ = create_token(db, "short", Role.admin, expires_at=now + timedelta(hours=1))
    assert verify_token(db, expiring, now) is not None
    assert verify_token(db, expiring, now + timedelta(hours=2)) is None

    doomed, doomed_row = create_token(db, "doomed", Role.admin)
    assert verify_token(db, doomed, now) is not None
    revoke_token(db, doomed_row.id, now)
    assert verify_token(db, doomed, now) is None


def test_last_used_throttled(db: Session) -> None:
    """AC-7: last_used_at follows usage, but at most one write per minute --
    a busy script must not turn every call into a database write."""
    now = datetime.now(UTC)
    secret, row = create_token(db, "busy", Role.viewer)

    verify_token(db, secret, now)
    db.refresh(row)
    first = row.last_used_at
    assert first is not None

    verify_token(db, secret, now + timedelta(seconds=30))
    db.refresh(row)
    assert row.last_used_at == first

    verify_token(db, secret, now + timedelta(seconds=61))
    db.refresh(row)
    assert row.last_used_at is not None
    assert row.last_used_at > first
