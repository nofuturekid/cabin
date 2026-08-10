"""session flash: one message written by a mutation and popped by the next
render

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-10

One nullable column, and the only schema change in the whole redesign (spec
0030 FR-2). It is ``sa.Text`` rather than a bounded ``String`` because the
longest message this spec can produce is ``imported CA {subject}`` and a
subject is operator-supplied: a length cap would mean inventing a truncation
rule and an ellipsis nobody asked for.

Nullable, and deliberately without a server default. Every session row that
exists when this runs has no message pending, and ``NULL`` is what "nothing
pending" means everywhere else in this column's life -- a ``NOT NULL``
column would either fail the upgrade or leave every logged-in operator
holding a row the model cannot load.
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("flash", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("sessions", "flash")
