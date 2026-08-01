"""User accounts: argon2id password hashing, roles, and CRUD.

Passwords are hashed with argon2id (argon2-cffi defaults) and never stored
or logged in plaintext. All domain failures raise sentinel exceptions rather
than generic ones so callers (the web layer) can map them to the right
HTTP response.
"""

import contextlib
import enum
from datetime import UTC, datetime

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.store import Base

MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher()
# Verified against on an unknown username, so a login attempt costs the same
# argon2id hash regardless of whether the username exists (no timing oracle
# for username enumeration).
_DUMMY_HASH = _hasher.hash("not-a-real-password-timing-decoy-only")


class Role(enum.StrEnum):
    superadmin = "superadmin"
    admin = "admin"
    viewer = "viewer"


class UserExistsError(Exception):
    """A user with that username already exists."""


class InvalidCredentialsError(Exception):
    """Username/password did not match any user."""


class WeakPasswordError(Exception):
    """Password is shorter than MIN_PASSWORD_LENGTH."""


class LastSuperadminError(Exception):
    """Refused: this would delete or demote the last remaining superadmin."""


class UserNotFoundError(Exception):
    """No user with that id."""


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(sa.String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )


def _check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def _count_superadmins(db: Session, *, exclude_id: int | None = None) -> int:
    stmt = select(sa.func.count()).select_from(User).where(User.role == Role.superadmin.value)
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return db.scalar(stmt) or 0


def create_user(db: Session, username: str, password: str, role: Role) -> User:
    """Create a new user, hashing the password with argon2id.

    Raises WeakPasswordError if the password is too short, UserExistsError
    if the username is already taken.
    """
    _check_password_strength(password)
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise UserExistsError(f"username already exists: {username!r}")
    user = User(username=username, password_hash=_hasher.hash(password), role=role.value)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def verify_credentials(db: Session, username: str, password: str) -> User:
    """Return the matching user, or raise InvalidCredentialsError."""
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        # Hash against a dummy so an unknown username takes the same argon2id
        # cost as a real one -- otherwise response time leaks which
        # usernames exist.
        with contextlib.suppress(VerifyMismatchError):
            _hasher.verify(_DUMMY_HASH, password)
        raise InvalidCredentialsError("invalid username or password")
    try:
        _hasher.verify(user.password_hash, password)
    except VerifyMismatchError as exc:
        raise InvalidCredentialsError("invalid username or password") from exc
    return user


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


def get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise UserNotFoundError(f"no such user: {user_id}")
    return user


def count_users(db: Session) -> int:
    return db.scalar(select(sa.func.count()).select_from(User)) or 0


def update_role(db: Session, user_id: int, role: Role) -> User:
    """Change a user's role, refusing to demote the last superadmin."""
    user = get_user(db, user_id)
    if (
        user.role == Role.superadmin.value
        and role != Role.superadmin
        and _count_superadmins(db, exclude_id=user.id) == 0
    ):
        raise LastSuperadminError("cannot demote the last superadmin")
    user.role = role.value
    db.commit()
    db.refresh(user)
    return user


def reset_password(db: Session, user_id: int, new_password: str) -> User:
    _check_password_strength(new_password)
    user = get_user(db, user_id)
    user.password_hash = _hasher.hash(new_password)
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, user_id: int) -> None:
    """Delete a user, refusing to delete the last superadmin."""
    user = get_user(db, user_id)
    if user.role == Role.superadmin.value and _count_superadmins(db, exclude_id=user.id) == 0:
        raise LastSuperadminError("cannot delete the last superadmin")
    db.delete(user)
    db.commit()
