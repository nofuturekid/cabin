"""ca certificates

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-01

Edited in place (not superseded) to add a UniqueConstraint on kind: same
rationale as migration 0002's in-place edit -- this project is pre-release
with no real data in any deployed DB. The unique constraint is the DB-level
backstop for "at most one active hierarchy" (FR-3): the application-level
check-then-insert in cabin.ca.service already guards this, but a real
constraint closes the race a bare check-then-insert can't.
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ca_certificates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("key_sealed", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("kind IN ('root', 'intermediate')", name="ck_ca_certificates_kind"),
        sa.UniqueConstraint("kind", name="uq_ca_certificates_kind"),
    )


def downgrade() -> None:
    op.drop_table("ca_certificates")
