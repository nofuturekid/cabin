"""DB-backed sessions: token issuance/lookup/touch/delete, and CSRF tokens.

The raw session token only ever lives in the cookie; the database stores
sha256(token) so a DB dump does not hand out live sessions. Expiry is a
24h sliding window: :func:`touch_session` extends it back to 24h once less
than 23h remain, which caps the refresh rate at roughly once per hour
without needing a separate "last refreshed" column.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.store import Base
from cabin.users import User

SESSION_LIFETIME = timedelta(hours=24)
_REFRESH_WINDOW = timedelta(hours=23)
_TOKEN_BYTES = 32


class UserSession(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)


def _utcnow() -> datetime:
    """Naive UTC 'now', matching how SQLite round-trips DateTime columns."""
    return datetime.now(UTC).replace(tzinfo=None)


def _hash_token(token: str) -> str:
    # utf-8, not ascii: an attacker- or client-supplied cookie value isn't
    # guaranteed to be ASCII, and encode("ascii") raising would surface as a
    # 500 instead of "not a valid session".
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User) -> tuple[str, UserSession]:
    """Create a new session for ``user``. Returns (raw token, row)."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    now = _utcnow()
    row = UserSession(
        token_hash=_hash_token(token),
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(_TOKEN_BYTES),
        created_at=now,
        expires_at=now + SESSION_LIFETIME,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return token, row


def get_session(db: Session, token: str) -> UserSession | None:
    """Look up a non-expired session by its raw cookie token."""
    row = db.get(UserSession, _hash_token(token))
    if row is None or row.expires_at < _utcnow():
        return None
    return row


def touch_session(db: Session, row: UserSession) -> bool:
    """Sliding expiry: extend to now+24h once less than 23h remain.

    Returns True if the row was actually extended, so callers can re-issue
    the Set-Cookie header to the browser (the DB expiry alone is invisible
    to the client, which otherwise drops the cookie after the original
    24h from login regardless of activity).
    """
    now = _utcnow()
    if row.expires_at - now < _REFRESH_WINDOW:
        row.expires_at = now + SESSION_LIFETIME
        db.commit()
        return True
    return False


def delete_session(db: Session, token: str) -> None:
    db.execute(sa.delete(UserSession).where(UserSession.token_hash == _hash_token(token)))
    db.commit()


def delete_sessions_for_user(db: Session, user_id: int) -> None:
    """Invalidate every session belonging to ``user_id``.

    Used after a password reset (the old sessions were authenticated with
    a password that no longer applies) and before/around user deletion (so
    no session row is left pointing at a user that no longer exists).
    """
    db.execute(sa.delete(UserSession).where(UserSession.user_id == user_id))
    db.commit()


def purge_expired(db: Session) -> None:
    """Opportunistically drop expired session rows (called on login)."""
    db.execute(sa.delete(UserSession).where(UserSession.expires_at < _utcnow()))
    db.commit()
