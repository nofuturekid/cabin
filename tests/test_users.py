"""Tests for cabin.users: argon2id password hashing, roles, and CRUD."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from cabin.store import create_session_factory, run_migrations
from cabin.users import (
    InvalidCredentialsError,
    LastSuperadminError,
    Role,
    UserExistsError,
    WeakPasswordError,
    count_users,
    create_user,
    delete_user,
    get_user,
    list_users,
    reset_password,
    update_role,
    verify_credentials,
)


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


def test_create_user_hashes_password_argon2id(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    assert user.id is not None
    assert user.username == "alice"
    assert user.role == Role.superadmin.value
    assert user.password_hash.startswith("$argon2id$")
    assert user.password_hash != "correcthorsebattery"


def test_create_user_duplicate_username_rejected(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    with pytest.raises(UserExistsError):
        create_user(db, "alice", "anotherlongpassword", Role.viewer)


def test_create_user_weak_password_rejected(db: Session) -> None:
    with pytest.raises(WeakPasswordError):
        create_user(db, "bob", "short1", Role.viewer)
    assert list_users(db) == []


def test_verify_credentials_ok(db: Session) -> None:
    created = create_user(db, "alice", "correcthorsebattery", Role.admin)
    user = verify_credentials(db, "alice", "correcthorsebattery")
    assert user.id == created.id


def test_verify_credentials_wrong_password(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.admin)
    with pytest.raises(InvalidCredentialsError):
        verify_credentials(db, "alice", "wrongpassword")


def test_verify_credentials_unknown_username(db: Session) -> None:
    with pytest.raises(InvalidCredentialsError):
        verify_credentials(db, "nobody", "whatever12345")


def test_list_users_returns_all(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    create_user(db, "bob", "anotherlongpassword", Role.viewer)
    usernames = {u.username for u in list_users(db)}
    assert usernames == {"alice", "bob"}


def test_count_users(db: Session) -> None:
    assert count_users(db) == 0
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    assert count_users(db) == 1


def test_update_role_changes_role(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    bob = create_user(db, "bob", "anotherlongpassword", Role.viewer)
    updated = update_role(db, bob.id, Role.admin)
    assert updated.role == Role.admin.value


def test_reset_password_updates_hash(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    old_hash = user.password_hash
    updated = reset_password(db, user.id, "brandnewlongpassword")
    assert updated.password_hash != old_hash
    verify_credentials(db, "alice", "brandnewlongpassword")


def test_reset_password_weak_rejected(db: Session) -> None:
    user = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    with pytest.raises(WeakPasswordError):
        reset_password(db, user.id, "short")


def test_delete_user_removes_row(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    bob = create_user(db, "bob", "anotherlongpassword", Role.viewer)
    delete_user(db, bob.id)
    assert {u.username for u in list_users(db)} == {"alice"}


def test_last_superadmin_cannot_be_deleted(db: Session) -> None:
    alice = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    with pytest.raises(LastSuperadminError):
        delete_user(db, alice.id)
    assert get_user(db, alice.id).username == "alice"


def test_last_superadmin_cannot_be_demoted(db: Session) -> None:
    alice = create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    with pytest.raises(LastSuperadminError):
        update_role(db, alice.id, Role.admin)
    assert get_user(db, alice.id).role == Role.superadmin.value


def test_second_superadmin_can_be_demoted_and_deleted(db: Session) -> None:
    create_user(db, "alice", "correcthorsebattery", Role.superadmin)
    bob = create_user(db, "bob", "anotherlongpassword", Role.superadmin)
    update_role(db, bob.id, Role.viewer)
    assert get_user(db, bob.id).role == Role.viewer.value
