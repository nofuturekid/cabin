"""revocation and CRL state

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # tz-aware ISO-8601 UTC, in the same shape as not_before/not_after so the
    # inventory's status filter stays one string comparison (spec 0006).
    op.add_column("certificates", sa.Column("revoked_at", sa.String(length=40), nullable=True))
    op.add_column(
        "certificates",
        sa.Column("revocation_reason", sa.String(length=32), nullable=True),
    )
    op.create_table(
        "crl_state",
        # The current CRL is a single document, not a history: the CHECK
        # pins the table to exactly one row (id = 1) so no code path can
        # accidentally leave two "current" CRLs behind.
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("crl_number", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("crl_der", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_crl_state_single_row"),
    )


def downgrade() -> None:
    op.drop_table("crl_state")
    op.drop_column("certificates", "revocation_reason")
    op.drop_column("certificates", "revoked_at")
