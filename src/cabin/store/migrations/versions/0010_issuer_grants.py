"""issuer grants: which users and API tokens may issue and revoke through
which CA intermediate

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-08

Two tables, appended -- unlike 0017's in-place rewrites, nothing here is
superseded. Each primary key spans both columns and nothing else is
stored: re-granting the same pair is an IntegrityError, not a second row,
so no counting logic anywhere has to be right about duplicates, and who
changed a grant and when is what the audit log is for (spec 0018 FR-12),
not a second thing this table would have to keep true.

Neither foreign key carries ``ondelete``, unlike ``sessions.user_id
ON DELETE CASCADE`` in 0002. That looks like an omission and is not one:
``store/__init__.py``'s ``_enforce_sqlite_foreign_keys`` puts SQLite's FK
enforcement on for every pooled connection, so a CASCADE here would make
the database silently drop a user's or token's grants the moment the user
or token is deleted. Spec 0018 FR-10 requires the *application* --
``users.delete_user`` -- to do that cleanup itself, in the same
transaction, and AC-12 exists specifically to catch an implementation that
forgot to write it. A CASCADE would satisfy AC-12 without FR-10's cleanup
ever running, which defeats the one criterion FR-10 exists for. Tokens are
revoked, never deleted, so ``token_issuers`` has no equivalent hole and no
equivalent reason to reconsider this.
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_issuers",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "ca_certificate_id",
            sa.Integer(),
            sa.ForeignKey("ca_certificates.id"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("user_id", "ca_certificate_id"),
    )
    op.create_table(
        "token_issuers",
        sa.Column("api_token_id", sa.Integer(), sa.ForeignKey("api_tokens.id"), nullable=False),
        sa.Column(
            "ca_certificate_id",
            sa.Integer(),
            sa.ForeignKey("ca_certificates.id"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("api_token_id", "ca_certificate_id"),
    )


def downgrade() -> None:
    op.drop_table("token_issuers")
    op.drop_table("user_issuers")
