"""API tokens (spec 0008 FR-2): long-lived bearer credentials for scripts,
each carrying one of the same roles a user account has.

Only ``sha256(secret)`` reaches the database. That is deliberately a fast
hash, unlike :mod:`cabin.users`' argon2id: a token secret is 32 bytes of
`secrets.token_urlsafe` output, so there is no low-entropy input to brute
force and a slow KDF would only tax every API call. The plaintext exists
exactly once, in the response to the call that created it.

Times are stored as naive UTC, the same shape :mod:`cabin.sessions` uses,
so SQLite round-trips them unchanged.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.store import Base
from cabin.users import Role

#: Prefix every secret carries so a leaked string is recognizable as a cabin
#: API token at a glance -- by a human and by a secret scanner.
TOKEN_PREFIX = "cabin_"
#: 32 random bytes -> 43 urlsafe-base64 characters (FR-2).
_TOKEN_BYTES = 32
#: FR-2: ``last_used_at`` answers "is this token still in use", not "what did
#: it do" (that is spec 0009's audit log), so a busy script costs at most one
#: row update per minute rather than one per request.
LAST_USED_THROTTLE = timedelta(seconds=60)
#: Enough to name a script or a host; the column is sized to match.
MAX_LABEL_LENGTH = 100


class TokenError(Exception):
    """A token could not be created as asked; the message names the reason
    and is safe to show in the UI."""


class ApiToken(Base):
    """One API credential. ``token_hash`` is the only trace of the secret."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(sa.String(MAX_LABEL_LENGTH), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime, nullable=True)


def _naive_utc(moment: datetime) -> datetime:
    """UTC without a tzinfo -- the shape every DateTime column here stores.

    Callers hand us whatever their clock produced; an aware instant is
    converted, a naive one is taken to be UTC already.
    """
    return moment.astimezone(UTC).replace(tzinfo=None) if moment.tzinfo else moment


def _now(now: datetime | None) -> datetime:
    return _naive_utc(now) if now is not None else datetime.now(UTC).replace(tzinfo=None)


def _hash_secret(secret: str) -> str:
    # utf-8, not ascii: the value comes straight off an Authorization header
    # and is not guaranteed to be ASCII -- encode() raising there would be a
    # 500 instead of "not a valid token".
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def create_token(
    db: Session,
    label: str,
    role: Role,
    expires_at: datetime | None = None,
) -> tuple[str, ApiToken]:
    """Mint a token. Returns ``(plaintext secret, row)`` -- the secret is not
    recoverable afterwards, from here or from the database (AC-1).

    Raises TokenError for an empty or over-long label.
    """
    clean = label.strip()
    if not clean:
        raise TokenError("the token label must not be empty")
    if len(clean) > MAX_LABEL_LENGTH:
        raise TokenError(f"the token label must be at most {MAX_LABEL_LENGTH} characters")
    secret = TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
    row = ApiToken(
        label=clean,
        token_hash=_hash_secret(secret),
        role=role.value,
        created_at=_now(None),
        expires_at=_naive_utc(expires_at) if expires_at is not None else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return secret, row


def verify_token(db: Session, secret: str, now: datetime | None = None) -> ApiToken | None:
    """The token behind ``secret``, or None if there is no live one (FR-2).

    Revoked and expired tokens are misses, not errors: the caller has no
    business learning which of the three it was.

    A hit touches ``last_used_at``, but no more often than
    :data:`LAST_USED_THROTTLE` (AC-7). The lookup is a plain equality on a
    256-bit digest -- there is nothing to time-attack, because a near-miss
    tells an attacker nothing about a secret they would have to guess whole.
    """
    if not secret:
        return None
    moment = _now(now)
    row = db.scalar(select(ApiToken).where(ApiToken.token_hash == _hash_secret(secret)))
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at is not None and row.expires_at <= moment:
        return None
    if row.last_used_at is None or moment - row.last_used_at >= LAST_USED_THROTTLE:
        row.last_used_at = moment
        db.commit()
    return row


def get_token(db: Session, token_id: int) -> ApiToken | None:
    """One token by id, or None. Lets a caller see what state a token is in
    *before* acting on it -- which is how :func:`revoke_token`'s idempotence
    stays compatible with recording a revocation exactly once."""
    return db.get(ApiToken, token_id)


def list_tokens(db: Session) -> list[ApiToken]:
    """Every token ever created, in creation order -- revoked and expired
    ones included, because "this one is dead" is what the page is for."""
    return list(db.scalars(select(ApiToken).order_by(ApiToken.id)))


def revoke_token(db: Session, token_id: int, now: datetime | None = None) -> ApiToken | None:
    """Kill a token immediately, or return None if there is no such token.

    Idempotent: re-revoking leaves the original date in place, so the record
    of when it stopped working does not move.
    """
    row = db.get(ApiToken, token_id)
    if row is None:
        return None
    if row.revoked_at is None:
        row.revoked_at = _now(now)
        db.commit()
    return row


def token_status(row: ApiToken, now: datetime | None = None) -> str:
    """Where a token stands, for display. Uses exactly the checks
    :func:`verify_token` authenticates with, so the page cannot claim a token
    is usable that the API would reject."""
    moment = _now(now)
    if row.revoked_at is not None:
        return "revoked"
    if row.expires_at is not None and row.expires_at <= moment:
        return "expired"
    return "active"
