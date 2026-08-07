"""ca certificates

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-01

Edited in place (not superseded) for spec 0017 FR-1: this project is
pre-release with no real data in any deployed database, and migrations
0003-0005 are rewritten rather than superseded -- there is no upgrade path
from a 0.1.x database, only an empty /data.

The UniqueConstraint on kind is gone: a hierarchy is no longer a singleton,
so several roots and intermediates now coexist. Three columns carry that:
name (the operator-facing label, not unique on purpose -- a rotation
deliberately produces a second row with the same label), parent_id
(self-referential, NULL for a self-signed root), and status (active/retired,
so a rotated-out issuer keeps serving its chain and CRL without being
offered for new issuance).
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
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column(
            "parent_id",
            sa.Integer(),
            sa.ForeignKey("ca_certificates.id"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("key_sealed", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("kind IN ('root', 'intermediate')", name="ck_ca_certificates_kind"),
        sa.CheckConstraint("status IN ('active', 'retired')", name="ck_ca_certificates_status"),
    )


def downgrade() -> None:
    op.drop_table("ca_certificates")
