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

Edited in place again for spec 0021 FR-1 (cross-signing): kind's CHECK
gains 'cross', and a new nullable cross_of_id column (self-referential FK)
names the self-signed row a cross row duplicates -- parent_id already names
the root that signed it. Edited rather than added as revision 0011 for the
same reason 0019 FR-1 gave for 0008/0009: nothing in this release cycle has
shipped, and spec 0020 AC-9 asserts the migration chain still ends at 0010.
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
        sa.Column(
            "cross_of_id",
            sa.Integer(),
            sa.ForeignKey("ca_certificates.id"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("key_sealed", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('root', 'intermediate', 'cross')", name="ck_ca_certificates_kind"
        ),
        sa.CheckConstraint("status IN ('active', 'retired')", name="ck_ca_certificates_status"),
    )


def downgrade() -> None:
    op.drop_table("ca_certificates")
