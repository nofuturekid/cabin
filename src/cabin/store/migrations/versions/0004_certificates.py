"""issued certificates

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "certificates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("serial_hex", sa.String(length=64), nullable=False),
        sa.Column("subject_cn", sa.String(length=64), nullable=False),
        # JSON array of canonical SAN strings ("DNS:nas.lan", "IP:10.0.0.5").
        sa.Column("sans_json", sa.Text(), nullable=False),
        sa.Column("profile", sa.String(length=16), nullable=False),
        # tz-aware ISO-8601, exactly as read back off the certificate.
        sa.Column("not_before", sa.String(length=40), nullable=False),
        sa.Column("not_after", sa.String(length=40), nullable=False),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        # sealed PKCS#8 PEM for server-generated keys, NULL for CSR signing.
        sa.Column("key_sealed", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("profile IN ('server', 'client')", name="ck_certificates_profile"),
        sa.UniqueConstraint("serial_hex", name="uq_certificates_serial_hex"),
    )


def downgrade() -> None:
    op.drop_table("certificates")
