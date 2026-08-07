"""Shared test scaffolding for CA hierarchies and certificate rows (spec
0017 Phase 0).

Every helper here builds ``ca_certificates`` / ``certificates`` rows
directly against the ORM rather than through :mod:`cabin.ca.service` /
:mod:`cabin.ca.certs`. That is deliberate, not a shortcut: those modules'
function bodies are mid-rewrite for multi-CA and are not a stable base for
test scaffolding during this phase (see the spec 0017 work split, Phase 0).
Tests that exercise ``create_hierarchy``, ``issue_and_store`` and friends
*as the thing under test* must keep calling them directly -- routing them
through here would stop those tests from testing anything.

This module exists so a schema change is a one-file fix instead of a sweep
across every test file: before this, ~190 call sites across 19 files each
built their own ``ca_certificates`` / ``certificates`` rows by hand.

Two names carry a trap warning (spec 0017 work split R4): if a stub issuer
is inserted as an extra *active* intermediate in a test that also builds a
real hierarchy, that test now has two active issuers, and every unqualified
issuance in it starts raising ``IssuerRequiredError`` -- far from where the
stub was added. :func:`sole_active_issuer` and :func:`extra_active_issuer`
are kept as distinct, explicitly named functions so that misuse is visible
at the call site instead of failing silently three files away.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.ca import x509 as ca_x509
from cabin.ca.certs import Certificate
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory

#: A syntactically-plausible but unparsed placeholder, for rows that are
#: never fed to anything that parses cert_pem (inventory/pagination/status
#: fixtures read only the surrounding columns).
_STUB_PEM = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass(frozen=True)
class CAHierarchy:
    """Mirrors :class:`cabin.ca.service.CAHierarchy` (root + intermediate),
    kept as a separate type here so this module has no import-time
    dependency on which shape ``cabin.ca.service`` settles on."""

    root: CACertificate
    intermediate: CACertificate


def make_hierarchy(
    db: Session,
    secrets: SecretStore,
    name: str = "cabin",
    *,
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    intermediate_years: int = 10,
) -> CAHierarchy:
    """A fresh, active root + intermediate, stored directly.

    Replaces the 26 direct ``create_hierarchy``/``import_hierarchy`` calls
    that existed purely as scaffolding (a signing CA to issue/revoke
    against) rather than as the thing being tested. A test that asserts on
    ``create_hierarchy``'s own behaviour must keep calling it directly.
    """
    root_cert, root_key = ca_x509.create_root(f"{name} Root CA", key_type, years=root_years)
    intermediate_cert, intermediate_key = ca_x509.create_intermediate(
        root_cert,
        root_key,
        f"{name} Intermediate CA",
        key_type,
        years=intermediate_years,
    )
    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=_cert_pem(root_cert),
        key_sealed=secrets.seal(_key_pem(root_key)),
    )
    db.add(root_row)
    db.flush()  # assigns root_row.id, needed for the intermediate's parent_id
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status="active",
        cert_pem=_cert_pem(intermediate_cert),
        key_sealed=secrets.seal(_key_pem(intermediate_key)),
    )
    db.add(intermediate_row)
    db.commit()
    return CAHierarchy(root=root_row, intermediate=intermediate_row)


def _csrf_token(client: TestClient, cfg: Config) -> str:
    db = create_session_factory(cfg.db_url)()
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def create_ca_via_http(
    client: TestClient,
    cfg: Config,
    *,
    name: str = "cabin",
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    intermediate_years: int = 10,
) -> None:
    """``POST /ca/create`` with a fresh CSRF token, asserting success.

    Replacement for the 20 near-identical ``_create_ca`` helper bodies
    across the web/API test files. Needs a real session cookie (from
    ``client``) already established by first-run setup, exactly like the
    helpers it replaces.
    """
    resp = client.post(
        "/ca/create",
        data={
            "name": name,
            "key_type": key_type,
            "root_years": root_years,
            "intermediate_years": intermediate_years,
            "csrf_token": _csrf_token(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def sole_active_issuer(db: Session, name: str = "stub") -> int:
    """Guarantee exactly one active intermediate exists and return its id.

    For the tests that build ``certificates`` rows to satisfy the
    ``issuer_id`` foreign key but never sign anything -- inventory
    arithmetic, pagination, status counts. Idempotent within one database: a
    second call in the same test returns the existing row rather than
    inserting a competing "sole" issuer, so a helper that calls this once
    per row it inserts still ends up with exactly one active issuer.

    Use this ONLY in a test that builds no other hierarchy. If the point of
    the test is a second active issuer, use :func:`extra_active_issuer`
    instead -- naming the difference is what keeps a stray stub from
    silently tripping the "exactly one active issuer" default-issuer rule
    (spec 0017 FR-6) in a test that also calls :func:`make_hierarchy`.
    """
    existing = db.scalar(
        select(CACertificate.id).where(
            CACertificate.kind == "intermediate", CACertificate.status == "active"
        )
    )
    if existing is not None:
        return existing
    cert, _key = ca_x509.create_root(f"{name} CA", "ecdsa-p256")
    row = CACertificate(
        kind="intermediate",
        name=f"{name} CA",
        status="active",
        cert_pem=_cert_pem(cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row.id


def extra_active_issuer(db: Session, name: str = "stub-extra") -> int:
    """Insert a SECOND active intermediate and return its id.

    Deliberately never used by the mechanical Phase-0 sweep -- this name
    exists so a test that means to exercise more than one active issuer
    says so at the call site, instead of reusing :func:`sole_active_issuer`
    and getting a second active issuer as an accident nobody reading the
    test would notice.
    """
    cert, _key = ca_x509.create_root(f"{name} CA", "ecdsa-p256")
    row = CACertificate(
        kind="intermediate",
        name=f"{name} CA",
        status="active",
        cert_pem=_cert_pem(cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row.id


def retired_issuer(db: Session, name: str = "stub-retired") -> int:
    """Insert a RETIRED intermediate and return its id.

    Also never used by the mechanical sweep -- for tests that need an
    issuer specifically not offered for new issuance (FR-4).
    """
    cert, _key = ca_x509.create_root(f"{name} CA", "ecdsa-p256")
    row = CACertificate(
        kind="intermediate",
        name=f"{name} CA",
        status="retired",
        cert_pem=_cert_pem(cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row.id


def insert_cert(
    db: Session,
    *,
    issuer_id: int,
    cn: str = "host.lan",
    sans: Sequence[str] | None = None,
    serial: str | None = None,
    expires_in: timedelta = timedelta(days=365),
    created_at: datetime | None = None,
    with_key: bool = True,
    revoked_at: datetime | None = None,
    profile: str = "server",
) -> Certificate:
    """A certificate row without going through issuance -- the shared body
    behind the ``_insert``/``_bulk_insert``/``_issue`` helpers that used to
    be duplicated per test file. The inventory/dashboard/pagination queries
    this feeds only read columns, so there is nothing to gain from a real
    certificate here; ``issuer_id`` is required (keyword-only, no default)
    so a caller cannot forget it the way the old NOT-NULL-free schema let it.
    ``expires_in`` takes a timedelta rather than a whole number of days: one
    caller needs the exact-second AC-9 boundary (30 days + 30 seconds).
    """
    # X.509 validity is second-granular, and so is every not_after a real
    # issuance stores; the inventory's status filter compares these as
    # fixed-layout strings (certs.py's _iso), so a microsecond component
    # here would sort differently than the truncated boundary it is
    # compared against and silently misclassify a row at an exact cutoff.
    now = datetime.now(UTC).replace(microsecond=0)
    row = Certificate(
        issuer_id=issuer_id,
        serial_hex=(serial if serial is not None else f"{db.query(Certificate).count() + 1:016x}"),
        subject_cn=cn,
        sans_json=json.dumps(list(sans) if sans is not None else [f"DNS:{cn}"]),
        profile=profile,
        not_before=now.isoformat(),
        not_after=(now + expires_in).isoformat(),
        cert_pem=_STUB_PEM,
        key_sealed="sealed" if with_key else None,
        created_at=(created_at or now).replace(tzinfo=None),
        revoked_at=revoked_at.isoformat() if revoked_at else None,
        revocation_reason="superseded" if revoked_at else None,
    )
    db.add(row)
    db.commit()
    return row
