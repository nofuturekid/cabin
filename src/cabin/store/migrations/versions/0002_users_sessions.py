"""users and sessions

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-01

Edited in place (not superseded) to add sessions.user_id ON DELETE CASCADE:
this project is pre-release with no real data in any deployed DB, so there
is nothing to migrate and no reason to carry the fixed version as dead
history. The app also explicitly deletes a user's sessions in the same
request that deletes/resets them (belt-and-suspenders for SQLite, where
FK enforcement is opt-in); CASCADE is the correctness guarantee for
backends -- Postgres -- that enforce FKs by default.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("role IN ('superadmin', 'admin', 'viewer')", name="ck_users_role"),
    )
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sessions")
    op.drop_table("users")
