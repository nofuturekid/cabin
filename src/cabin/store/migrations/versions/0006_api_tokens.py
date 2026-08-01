"""api tokens

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("label", sa.String(length=100), nullable=False),
        # sha256 hex of the secret -- 64 characters, and unique so the same
        # secret can never be registered twice.
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        # All three are naive UTC, like sessions.expires_at. NULL means
        # "never used" / "no expiry" / "not revoked" respectively.
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        # Same guard as users.role: a token's role decides what it may do,
        # so an unknown value must not be storable in the first place.
        sa.CheckConstraint("role IN ('superadmin', 'admin', 'viewer')", name="ck_api_tokens_role"),
    )


def downgrade() -> None:
    op.drop_table("api_tokens")
