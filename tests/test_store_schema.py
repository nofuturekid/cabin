"""Schema-level tests for spec 0017 FR-1/AC-16: migrations 0003-0005 are
rewritten in place, not superseded, so there is nothing to test at the
Alembic-revision level -- only the shape of the database they produce.

Written first, red against the pre-0017 schema (a UniqueConstraint on
``ca_certificates.kind``, a ``CHECK id = 1`` on ``crl_state``, a nullable
``certificates.issuer_id``), green after.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import cabin.store as cabin_store
from cabin.ca.certs import Certificate
from cabin.store import create_session_factory, run_migrations


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()


def test_schema_has_no_singleton_constraints(db: Session) -> None:
    """AC-16: a fresh database has no unique constraint on
    ``ca_certificates.kind`` (several hierarchies now coexist), no
    ``CHECK id = 1`` on ``crl_state`` (one CRL per issuer, not one per
    instance -- and the ``id`` column it pinned is gone entirely), and a
    NOT NULL ``certificates.issuer_id``.
    """
    inspector = inspect(db.get_bind())

    ca_uniques = inspector.get_unique_constraints("ca_certificates")
    assert not any("kind" in uc["column_names"] for uc in ca_uniques), ca_uniques

    crl_columns = {col["name"] for col in inspector.get_columns("crl_state")}
    assert "id" not in crl_columns, crl_columns
    crl_pk = inspector.get_pk_constraint("crl_state")
    assert crl_pk["constrained_columns"] == ["issuer_id"], crl_pk
    crl_checks = inspector.get_check_constraints("crl_state")
    assert not any("id" in check["sqltext"] for check in crl_checks), crl_checks

    cert_columns = {col["name"]: col for col in inspector.get_columns("certificates")}
    assert cert_columns["issuer_id"]["nullable"] is False, cert_columns["issuer_id"]


def test_certificate_without_issuer_is_rejected_by_the_database(db: Session) -> None:
    """AC-16's second half: bypass the ORM entirely, so the assertion is
    about the schema and not about ``cabin.ca.certs.Certificate`` happening
    to always set ``issuer_id`` -- a NOT NULL column enforces this even
    against a raw INSERT.
    """
    with pytest.raises(IntegrityError):
        db.execute(
            sa.text(
                "INSERT INTO certificates "
                "(serial_hex, subject_cn, sans_json, profile, not_before, not_after, "
                "cert_pem, created_at) "
                "VALUES "
                "('ab12', 'orphan.lan', '[]', 'server', '2026-01-01T00:00:00+00:00', "
                "'2027-01-01T00:00:00+00:00', 'stub', '2026-01-01T00:00:00')"
            )
        )
        db.commit()


def test_orm_session_rejects_a_certificate_with_no_such_issuer(db: Session) -> None:
    """SQLite ignores every ``FOREIGN KEY`` in the schema unless
    ``PRAGMA foreign_keys=ON`` is set on the connection actually in use, and
    that pragma is not on by default. This goes red if
    ``create_session_factory``'s ``connect`` listener (``cabin/store/
    __init__.py``) is ever removed: the row below is well-formed and would
    silently insert. Uses the ORM session the application actually issues
    certificates through -- a raw ``sqlite3`` connection would prove nothing
    about *this* pragma state, since it is set per connection.
    """
    db.add(
        Certificate(
            issuer_id=99999,  # no ca_certificates row has this id
            serial_hex="ab12",
            subject_cn="orphan.lan",
            sans_json="[]",
            profile="server",
            not_before="2026-01-01T00:00:00+00:00",
            not_after="2027-01-01T00:00:00+00:00",
            cert_pem="stub",
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()


def test_foreign_keys_enforced_on_a_second_pooled_connection(tmp_path: Path) -> None:
    """The pragma is set per connection, not per database, so a listener
    wired to only the pool's first ``connect`` event would leave every later
    connection unenforced. Keeping ``first`` open across an execute forces
    SQLAlchemy's ``QueuePool`` to hand ``second`` a genuinely new DBAPI
    connection rather than reuse the first one -- exactly the connection a
    once-only listener would miss.
    """
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)

    first = factory()
    try:
        first.execute(sa.text("SELECT 1"))  # checks out the pool's first connection

        second = factory()
        try:
            second.add(
                Certificate(
                    issuer_id=99999,
                    serial_hex="cd34",
                    subject_cn="orphan2.lan",
                    sans_json="[]",
                    profile="server",
                    not_before="2026-01-01T00:00:00+00:00",
                    not_after="2027-01-01T00:00:00+00:00",
                    cert_pem="stub",
                )
            )
            with pytest.raises(IntegrityError):
                second.commit()
        finally:
            second.close()
    finally:
        first.close()


# === spec 0030 FR-2/AC-20: the one schema change in the whole redesign =====


def _migrations_dir() -> Path:
    return Path(cabin_store.__file__).resolve().parent / "migrations"


def _alembic(db_url: str) -> AlembicConfig:
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_migrations_dir()))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_migration_0011_adds_a_nullable_flash_column(tmp_path: Path) -> None:
    """FR-2: one nullable `sa.Text` column, and its `down_revision`.

    The nullability is the assertion AC-20's last clause turns on. A
    `NOT NULL` column with no server default upgrades a populated database
    into a state where every existing session row is invalid and every
    logged-in operator is thrown out -- and a test that only checked the
    column exists would pass against exactly that build.
    """
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)

    script = ScriptDirectory.from_config(_alembic(db_url))
    try:
        revision = script.get_revision("0011")
    except CommandError as exc:
        raise AssertionError(
            "there is no migration 0011: FR-2 adds "
            "src/cabin/store/migrations/versions/0011_session_flash.py with "
            f'revision = "0011" and down_revision = "0010" ({exc})'
        ) from exc
    assert revision is not None, "there is no migration 0011"
    assert revision.down_revision == "0010", (
        f"0011's down_revision is {revision.down_revision!r}; FR-2 chains it onto 0010"
    )

    factory = create_session_factory(db_url)
    session = factory()
    try:
        columns = {col["name"]: col for col in inspect(session.get_bind()).get_columns("sessions")}
        assert "flash" in columns, "migration 0011 did not add `sessions.flash`"
        assert columns["flash"]["nullable"] is True, (
            "`sessions.flash` is NOT NULL. Every session row that existed before this "
            "migration has no value for it, so an upgrade would either fail or leave "
            "every logged-in operator with a dead session (AC-20)"
        )
        assert str(columns["flash"]["type"]).upper() in {"TEXT", "VARCHAR"}, (
            f"`sessions.flash` is {columns['flash']['type']}; FR-2 chooses `sa.Text` "
            f"over a bounded String because the longest message is "
            f"`imported CA {{subject}}` and a subject is operator-supplied"
        )
        for name in ("token_hash", "user_id", "csrf_token", "created_at", "expires_at"):
            assert name in columns, f"migration 0011 lost `sessions.{name}`"
            assert columns[name]["nullable"] is False, (
                f"`sessions.{name}` became nullable; the Interface Contract leaves the "
                f"five existing columns unchanged in type, nullability and meaning"
            )
    finally:
        session.close()


def test_migration_0011_upgrades_a_populated_database(tmp_path: Path) -> None:
    """AC-20's last clause, and the only shape that can catch a `NOT NULL`
    migration: the session row is written **before** the upgrade.

    Written through raw SQL naming only the pre-0011 columns, because that is
    exactly the row an existing database already holds -- inserting through
    the ORM after the model gained the attribute would supply a value for it
    and the criterion would measure nothing.
    """
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    cfg = _alembic(db_url)
    command.downgrade(cfg, "0010")

    factory = create_session_factory(db_url)
    session = factory()
    try:
        columns = {col["name"] for col in inspect(session.get_bind()).get_columns("sessions")}
        assert "flash" not in columns, (
            "downgrading to 0010 left `sessions.flash` behind; FR-2 drops it in `downgrade`"
        )
        session.execute(
            sa.text(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES ('alice', 'x', 'superadmin', '2026-01-01T00:00:00')"
            )
        )
        session.execute(
            sa.text(
                "INSERT INTO sessions "
                "(token_hash, user_id, csrf_token, created_at, expires_at) "
                "VALUES ('deadbeef', 1, 'csrf', '2026-01-01T00:00:00', '2099-01-01T00:00:00')"
            )
        )
        session.commit()
    finally:
        session.close()

    command.upgrade(cfg, "0011")

    session = factory()
    try:
        value = session.execute(
            sa.text("SELECT flash FROM sessions WHERE token_hash = 'deadbeef'")
        ).scalar_one()
        assert value is None, (
            f"the row written before the upgrade came out with flash={value!r}; a "
            f"pre-existing session has no message pending and must show none"
        )
    finally:
        session.close()
