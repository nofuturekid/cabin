"""acme accounts, nonces, orders, authorizations and challenges

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

# Every id in this schema is an opaque random string that appears verbatim in
# a URL an ACME client stores and comes back to (spec 0010 FR-2). Sequential
# integers would leak how many accounts and orders exist and would make one
# client's resources guessable from another's -- a resource URL is the only
# thing tying an order to the account that placed it.
_ID = sa.String(length=64)
# tz-aware ISO-8601 UTC text, the same shape audit_events.occurred_at and
# certificates.not_after use: fixed-layout UTC strings sort lexicographically
# in chronological order on SQLite and PostgreSQL alike.
_TIMESTAMP = sa.String(length=40)


def upgrade() -> None:
    op.create_table(
        "acme_accounts",
        sa.Column("id", _ID, primary_key=True),
        # The sha256 of the id, i.e. of the last segment of the account URL.
        # A request's "kid" header is attacker-controlled text; hashing it
        # before it is used to look anything up means the raw value never
        # reaches a query, and a lookup costs the same for every input.
        sa.Column("kid_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("jwk_json", sa.Text(), nullable=False),
        # RFC 7638 SHA-256 thumbprint, base64url. This -- not the id -- is
        # what identifies an account: new-account is idempotent on the key.
        sa.Column("jwk_thumbprint", sa.String(length=64), nullable=False, unique=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("contacts_json", sa.Text(), nullable=True),
        sa.Column("tos_agreed_at", _TIMESTAMP, nullable=True),
        sa.Column("created_at", _TIMESTAMP, nullable=False),
        sa.CheckConstraint(
            "status IN ('valid', 'deactivated', 'revoked')",
            name="ck_acme_accounts_status",
        ),
    )

    op.create_table(
        "acme_nonces",
        # The nonce is the key: consuming one is a single DELETE, so two
        # concurrent requests cannot both win it.
        sa.Column("nonce", sa.String(length=64), primary_key=True),
        sa.Column("issued_at", _TIMESTAMP, nullable=False),
    )
    # The only query besides the primary key is "everything older than X".
    op.create_index("ix_acme_nonces_issued_at", "acme_nonces", ["issued_at"])

    op.create_table(
        "acme_orders",
        sa.Column("id", _ID, primary_key=True),
        sa.Column("account_id", _ID, sa.ForeignKey("acme_accounts.id"), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("identifiers_json", sa.Text(), nullable=False),
        sa.Column("not_before", _TIMESTAMP, nullable=True),
        sa.Column("not_after", _TIMESTAMP, nullable=True),
        sa.Column("expires_at", _TIMESTAMP, nullable=False),
        # Filled by spec 0012's finalize; NULL for every order until then.
        sa.Column(
            "certificate_id",
            sa.Integer(),
            sa.ForeignKey("certificates.id"),
            nullable=True,
        ),
        sa.Column("error_json", sa.Text(), nullable=True),
        sa.Column("created_at", _TIMESTAMP, nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'ready', 'processing', 'valid', 'invalid')",
            name="ck_acme_orders_status",
        ),
    )
    op.create_index("ix_acme_orders_account_id", "acme_orders", ["account_id"])

    op.create_table(
        "acme_authorizations",
        sa.Column("id", _ID, primary_key=True),
        sa.Column("order_id", _ID, sa.ForeignKey("acme_orders.id"), nullable=False),
        sa.Column("identifier_type", sa.String(length=16), nullable=False),
        sa.Column("identifier_value", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("expires_at", _TIMESTAMP, nullable=False),
        # RFC 8555 7.1.4: the identifier keeps the base name, and this flag
        # says the authorization also covers "*." in front of it.
        sa.Column("wildcard", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.CheckConstraint(
            "identifier_type IN ('dns', 'ip')",
            name="ck_acme_authorizations_identifier_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'valid', 'invalid', 'expired')",
            name="ck_acme_authorizations_status",
        ),
    )
    op.create_index("ix_acme_authorizations_order_id", "acme_authorizations", ["order_id"])

    op.create_table(
        "acme_challenges",
        sa.Column("id", _ID, primary_key=True),
        sa.Column("authz_id", _ID, sa.ForeignKey("acme_authorizations.id"), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("token", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("validated_at", _TIMESTAMP, nullable=True),
        sa.Column("error_json", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'valid', 'invalid')",
            name="ck_acme_challenges_status",
        ),
    )
    op.create_index("ix_acme_challenges_authz_id", "acme_challenges", ["authz_id"])


def downgrade() -> None:
    op.drop_index("ix_acme_challenges_authz_id", table_name="acme_challenges")
    op.drop_table("acme_challenges")
    op.drop_index("ix_acme_authorizations_order_id", table_name="acme_authorizations")
    op.drop_table("acme_authorizations")
    op.drop_index("ix_acme_orders_account_id", table_name="acme_orders")
    op.drop_table("acme_orders")
    op.drop_index("ix_acme_nonces_issued_at", table_name="acme_nonces")
    op.drop_table("acme_nonces")
    op.drop_table("acme_accounts")
