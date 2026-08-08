"""Issuer grants: which users and API tokens may issue and revoke through
which CA intermediate (spec 0018).

This commit holds only the two join tables' ORM models -- the schema half
of spec 0018 Phase 0, matching migration ``0010``. The principal type and
the grant policy (``Principal``, ``granted_issuers``, ``may_use_issuer``,
``resolve_granted_issuer``, ``set_issuers`` and the rest of the Interface
Contract) land in a follow-up commit; nothing in the tree calls or is
called by them yet, and no behaviour changes here.
"""

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from cabin.store import Base


class UserIssuer(Base):
    """One user's grant to sign and revoke through one CA intermediate.

    No surrogate id and no ``granted_at``/``granted_by`` column: the
    composite primary key over both columns is what makes granting
    idempotent at the database -- re-granting the same pair is an
    IntegrityError, not a second row -- and who changed a grant and when is
    what the audit log is for (spec 0018 FR-12), not a second thing this
    table would have to keep true.
    """

    __tablename__ = "user_issuers"

    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), primary_key=True)
    ca_certificate_id: Mapped[int] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), primary_key=True
    )


class TokenIssuer(Base):
    """One API token's grant to sign and revoke through one CA intermediate.

    A separate table from :class:`UserIssuer` rather than one table with a
    polymorphic owner column: API tokens have no owning user
    (``api_tokens.py``, spec 0008 -- deliberate, so a token cannot inherit a
    user's grants), so a token's grants cannot be expressed as a user's. See
    :class:`UserIssuer` for why there is no surrogate id.
    """

    __tablename__ = "token_issuers"

    api_token_id: Mapped[int] = mapped_column(sa.ForeignKey("api_tokens.id"), primary_key=True)
    ca_certificate_id: Mapped[int] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), primary_key=True
    )
