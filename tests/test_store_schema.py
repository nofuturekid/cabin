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
