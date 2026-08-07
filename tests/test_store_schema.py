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
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

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
