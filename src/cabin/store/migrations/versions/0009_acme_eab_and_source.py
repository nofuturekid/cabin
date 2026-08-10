"""acme external account binding keys, and where a certificate came from

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

# Same shapes as migration 0008: opaque URL-safe ids and fixed-layout UTC
# ISO-8601 text, so timestamps sort lexicographically on SQLite and
# PostgreSQL alike.
_ID = sa.String(length=64)
_TIMESTAMP = sa.String(length=40)

#: Where an issued certificate came from (spec 0012 FR-7): "ui", "api" or
#: "acme". Text rather than an integer so the column reads on its own in a
#: database dump. No CHECK constraint, unlike the tables created from
#: scratch in 0008: SQLite cannot add one to an existing table without
#: rebuilding it, and the value is written from a single enum in
#: :mod:`cabin.ca.certs` rather than from anywhere a typo could reach.
_DEFAULT_SOURCE = "ui"


def upgrade() -> None:
    op.create_table(
        "acme_eab_keys",
        # The key identifier is the primary key: it is what a client puts in
        # the inner JWS's "kid" header, so it is looked up by exactly this
        # value and by nothing else.
        sa.Column("id", _ID, primary_key=True),
        # AES-GCM sealed by the secrets layer (spec 0002). Never the raw MAC
        # key: anyone who could read this column could register accounts, and
        # a database backup is not a place to keep a live credential.
        sa.Column("hmac_sealed", sa.Text(), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("created_at", _TIMESTAMP, nullable=False),
        # RFC 8555 7.3.4 does not require single use, but an operator handing
        # out one credential per host means one account per credential. These
        # three columns are what make that enforceable rather than a promise.
        sa.Column(
            "bound_account_id",
            _ID,
            sa.ForeignKey("acme_accounts.id"),
            nullable=True,
        ),
        sa.Column("bound_at", _TIMESTAMP, nullable=True),
        sa.Column("revoked_at", _TIMESTAMP, nullable=True),
        # Spec 0019 FR-1/FR-7: which issuer this key authorizes registration
        # against. Named for the column it references rather than
        # "issuer_id", matching 0018's join tables (user_issuers,
        # token_issuers) -- a key names a CA row, and only FR-8 decides
        # whether that row is a usable issuer. NOT NULL, no server default
        # and no ondelete, for the same reasons as acme_accounts.issuer_id
        # in migration 0008.
        sa.Column(
            "ca_certificate_id", sa.Integer(), sa.ForeignKey("ca_certificates.id"), nullable=False
        ),
    )
    # One account per key, enforced by the database rather than by the code
    # that races for it: two simultaneous registrations must not both bind.
    op.create_index(
        "ux_acme_eab_keys_bound_account_id",
        "acme_eab_keys",
        ["bound_account_id"],
        unique=True,
    )

    # FR-7: existing rows predate ACME entirely, so the server default is
    # also the right answer for every one of them.
    op.add_column(
        "certificates",
        sa.Column(
            "source",
            sa.String(length=16),
            nullable=False,
            server_default=_DEFAULT_SOURCE,
        ),
    )
    # Explicit even though the server default already filled them in: a
    # backfill that is written down cannot be lost to a future change of the
    # default above.
    op.execute(
        sa.text("UPDATE certificates SET source = :value WHERE source IS NULL").bindparams(
            value=_DEFAULT_SOURCE
        )
    )


def downgrade() -> None:
    op.drop_column("certificates", "source")
    op.drop_index("ux_acme_eab_keys_bound_account_id", table_name="acme_eab_keys")
    op.drop_table("acme_eab_keys")
