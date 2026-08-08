"""revocation and CRL state

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-01

Edited in place for spec 0017 FR-1: crl_state stops being a singleton. The
CHECK id = 1 backstop is gone along with the id column itself -- the primary
key is now issuer_id (FK ca_certificates.id), so each issuer's CRL is its
own row, and "exactly one CRL per issuer" is what the primary key enforces.
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
        sa.Column(
            "issuer_id",
            sa.Integer(),
            sa.ForeignKey("ca_certificates.id"),
            primary_key=True,
            autoincrement=False,
        ),
        sa.Column("crl_number", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("crl_der", sa.LargeBinary(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("crl_state")
    op.drop_column("certificates", "revocation_reason")
    op.drop_column("certificates", "revoked_at")
