"""ORM models for the five ACME tables created by migration 0008.

Storage shapes only -- the rules that keep them consistent live in
:mod:`cabin.acme.service`. Every id is an opaque random string that appears
verbatim in a URL (FR-2), and every timestamp is the ISO-8601 UTC text the
rest of cabin stores time in.
"""

import hashlib
from enum import StrEnum

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from cabin.store import Base


class AccountStatus(StrEnum):
    """RFC 8555 7.1.6. Mirrors the table's CHECK constraint."""

    valid = "valid"
    deactivated = "deactivated"
    revoked = "revoked"


class OrderStatus(StrEnum):
    """RFC 8555 7.1.6. Only ``pending`` is reachable in spec 0010."""

    pending = "pending"
    ready = "ready"
    processing = "processing"
    valid = "valid"
    invalid = "invalid"


class AuthorizationStatus(StrEnum):
    pending = "pending"
    valid = "valid"
    invalid = "invalid"
    expired = "expired"


class ChallengeStatus(StrEnum):
    pending = "pending"
    processing = "processing"
    valid = "valid"
    invalid = "invalid"


def kid_hash(account_id: str) -> str:
    """What ``acme_accounts.kid_hash`` stores: the SHA-256 of the account's
    id, i.e. of the last segment of its URL.

    A request's ``kid`` header is text an attacker chooses, and this is the
    one place it turns into a lookup. Hashing first means the raw value never
    reaches a query and every input costs the same to look up.
    """
    return hashlib.sha256(account_id.encode("utf-8")).hexdigest()


class AcmeAccount(Base):
    """One ACME account, identified by its key rather than by its URL: two
    new-account requests signed with the same key are the same account, which
    is why ``jwk_thumbprint`` is the unique column that matters."""

    __tablename__ = "acme_accounts"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    kid_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    jwk_json: Mapped[str] = mapped_column(sa.Text, nullable=False)
    jwk_thumbprint: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    contacts_json: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    tos_agreed_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)


class AcmeNonce(Base):
    """An unused anti-replay nonce. Rows are deleted as they are spent, so
    the table holds only what has been handed out and not yet come back."""

    __tablename__ = "acme_nonces"

    nonce: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    issued_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)


class AcmeOrder(Base):
    __tablename__ = "acme_orders"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        sa.String(64), sa.ForeignKey("acme_accounts.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    identifiers_json: Mapped[str] = mapped_column(sa.Text, nullable=False)
    not_before: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    not_after: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    expires_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    certificate_id: Mapped[int | None] = mapped_column(
        sa.Integer, sa.ForeignKey("certificates.id"), nullable=True
    )
    error_json: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)


class AcmeAuthorization(Base):
    __tablename__ = "acme_authorizations"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    order_id: Mapped[str] = mapped_column(
        sa.String(64), sa.ForeignKey("acme_orders.id"), nullable=False
    )
    identifier_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    identifier_value: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    expires_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    wildcard: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)


class AcmeChallenge(Base):
    __tablename__ = "acme_challenges"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    authz_id: Mapped[str] = mapped_column(
        sa.String(64), sa.ForeignKey("acme_authorizations.id"), nullable=False
    )
    type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    token: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    validated_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    error_json: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
