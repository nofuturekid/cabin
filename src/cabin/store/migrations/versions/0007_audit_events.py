"""audit events

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        # tz-aware ISO-8601 UTC, the same shape certificates.not_after uses:
        # fixed-layout UTC strings sort lexicographically in chronological
        # order, so "newest first" is one index scan on SQLite and PostgreSQL
        # alike -- neither of which would agree on a naive DateTime here.
        sa.Column("occurred_at", sa.String(length=40), nullable=False),
        sa.Column("actor_kind", sa.String(length=16), nullable=False),
        # NULL for an actor that has no row to point at: a failed login (which
        # proved nothing about who was typing) and anything cabin did itself.
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor_label", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        # Text, not an integer: today's targets are integer ids, but an ACME
        # account or order (specs 0010-0012) is identified by a string, and
        # the log must not need a migration to record one.
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("detail_json", sa.Text(), nullable=True),
        # 45 characters holds an IPv4-mapped IPv6 address in full.
        sa.Column("ip", sa.String(length=45), nullable=True),
        # Same guard as users.role: an actor kind nothing can interpret must
        # not be storable in the first place.
        sa.CheckConstraint(
            "actor_kind IN ('user', 'token', 'system', 'acme')",
            name="ck_audit_events_actor_kind",
        ),
    )
    # The log is read newest-first and, when someone is investigating, one
    # action at a time -- those are the only two access patterns FR-6 has.
    op.create_index(
        "ix_audit_events_occurred_at",
        "audit_events",
        [sa.text("occurred_at DESC")],
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
