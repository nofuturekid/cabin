"""Tests for spec 0007: the pure CRL builder (:mod:`cabin.ca.revocation`,
FR-2/FR-3) and the revocation/CRL persistence on top of it
(:mod:`cabin.ca.crl`, FR-4), covering AC-1..AC-3."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import ca_fixtures
import grant_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from cabin.ca.certs import issue_and_store
from cabin.ca.crl import (
    CRL_MAX_AGE,
    CRLState,
    RevocationError,
    current_crl,
    regenerate_crl,
    revoke_certificate,
)
from cabin.ca.leaf import Profile
from cabin.ca.revocation import (
    CRL_VALIDITY,
    REASON_FLAGS,
    RevocationReason,
    RevokedEntry,
    build_crl,
)
from cabin.ca.service import CANotConfiguredError, signing_credentials
from cabin.ca.x509 import create_root
from cabin.issuer_grants import Principal
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations

_NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


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


@pytest.fixture
def secrets(tmp_path: Path) -> SecretStore:
    return SecretStore.open(tmp_path, None)


def _issue(db: Session, secrets: SecretStore, principal: Principal, cn: str = "nas.lan") -> int:
    issued = issue_and_store(
        db,
        secrets,
        principal=principal,
        profile=Profile.server,
        subject_cn=cn,
        sans=[f"DNS:{cn}"],
        days=90,
    )
    return issued.row.id


def _parse(state: CRLState) -> x509.CertificateRevocationList:
    """Always read the STORED DER back, never the in-memory object: what the
    endpoints serve is the bytes in the database."""
    return x509.load_der_x509_crl(state.crl_der)


# --- FR-3: the pure builder ---------------------------------------------------


@pytest.mark.parametrize("key_type", ["ecdsa-p256", "ed25519"])
def test_build_crl_extensions_and_signature(key_type: str) -> None:
    """AC-2: the CRL parses from DER, is issued by (and verifies against) the
    signing CA, and carries CRLNumber + AKI. Ed25519 is included because its
    signature algorithm is ``None``, not a hash."""
    issuer_cert, issuer_key = create_root("Builder Root CA", key_type)
    entry = RevokedEntry(
        serial_number=0x1234ABCD,
        revoked_at=_NOW,
        reason=RevocationReason.key_compromise,
    )

    crl = build_crl(
        issuer_cert,
        issuer_key,
        [entry],
        crl_number=7,
        this_update=_NOW,
        next_update=_NOW + CRL_VALIDITY,
    )

    parsed = x509.load_der_x509_crl(crl.public_bytes(serialization.Encoding.DER))
    assert parsed.issuer == issuer_cert.subject
    assert parsed.is_signature_valid(issuer_cert.public_key())
    assert parsed.last_update_utc == _NOW
    assert parsed.next_update_utc == _NOW + CRL_VALIDITY

    assert parsed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 7
    aki = parsed.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    # The AKI is copied from the issuer's SKI byte for byte -- an imported CA
    # may not use an RFC 5280 "method 1" SKI, and OpenSSL matches on bytes.
    assert aki.key_identifier == ski.digest

    revoked = parsed.get_revoked_certificate_by_serial_number(0x1234ABCD)
    assert revoked is not None
    assert revoked.revocation_date_utc == _NOW


def test_build_crl_reason_codes() -> None:
    """FR-2/FR-3: every reason maps to its ReasonFlags counterpart, and
    "unspecified" carries no CRLReason extension at all -- it is what a
    reason-less entry already means."""
    issuer_cert, issuer_key = create_root("Reasons Root CA", "ecdsa-p256")
    reasons = list(RevocationReason)
    entries = [
        RevokedEntry(serial_number=index + 1, revoked_at=_NOW, reason=reason)
        for index, reason in enumerate(reasons)
    ]

    crl = build_crl(
        issuer_cert,
        issuer_key,
        entries,
        crl_number=1,
        this_update=_NOW,
        next_update=_NOW + CRL_VALIDITY,
    )

    assert set(REASON_FLAGS) == set(RevocationReason)
    assert REASON_FLAGS[RevocationReason.key_compromise] is x509.ReasonFlags.key_compromise
    for index, reason in enumerate(reasons):
        revoked = crl.get_revoked_certificate_by_serial_number(index + 1)
        assert revoked is not None
        if reason is RevocationReason.unspecified:
            with pytest.raises(x509.ExtensionNotFound):
                revoked.extensions.get_extension_for_class(x509.CRLReason)
        else:
            code = revoked.extensions.get_extension_for_class(x509.CRLReason).value
            assert code.reason is REASON_FLAGS[reason]


def test_build_crl_empty_list() -> None:
    """FR-4: nothing revoked is still a statement -- and a valid, signed
    (empty) CRL is how it is made."""
    issuer_cert, issuer_key = create_root("Empty Root CA", "ecdsa-p256")

    crl = build_crl(
        issuer_cert,
        issuer_key,
        [],
        crl_number=1,
        this_update=_NOW,
        next_update=_NOW + CRL_VALIDITY,
    )

    parsed = x509.load_der_x509_crl(crl.public_bytes(serialization.Encoding.DER))
    assert len(parsed) == 0
    assert parsed.is_signature_valid(issuer_cert.public_key())
    assert parsed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1


# --- FR-4: revocation and CRL storage ------------------------------------------


def test_revoke_sets_fields_and_updates_crl(db: Session, secrets: SecretStore) -> None:
    """AC-1/AC-2: the row is marked, and the stored CRL -- signed by the
    intermediate, in its name -- carries that serial with its reason."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Revoke")
    principal = grant_fixtures.granted_admin(db, hierarchy.intermediate.id)
    cert_id = _issue(db, secrets, principal)

    row = revoke_certificate(
        db, secrets, cert_id, RevocationReason.key_compromise, principal=principal, now=_NOW
    )

    assert row.revoked_at is not None
    assert datetime.fromisoformat(row.revoked_at) == _NOW
    assert row.revocation_reason == "key_compromise"

    state = db.get(CRLState, hierarchy.intermediate.id)
    assert state is not None
    crl = _parse(state)
    intermediate_cert, _key = signing_credentials(db, secrets, hierarchy.intermediate.id)
    assert crl.issuer == intermediate_cert.subject
    assert crl.is_signature_valid(intermediate_cert.public_key())
    revoked = crl.get_revoked_certificate_by_serial_number(int(row.serial_hex, 16))
    assert revoked is not None
    assert revoked.revocation_date_utc == _NOW
    reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value
    assert reason.reason is x509.ReasonFlags.key_compromise


def test_revoke_is_idempotent(db: Session, secrets: SecretStore) -> None:
    """AC-1: revoking twice is success, not an error, and must not rewrite
    the revocation date (a relying party's answer would change)."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Revoke")
    principal = grant_fixtures.granted_admin(db, hierarchy.intermediate.id)
    cert_id = _issue(db, secrets, principal)

    first = revoke_certificate(
        db, secrets, cert_id, RevocationReason.superseded, principal=principal, now=_NOW
    )
    first_state = db.get(CRLState, hierarchy.intermediate.id)
    assert first_state is not None
    first_number = first_state.crl_number

    later = _NOW + timedelta(days=1)
    second = revoke_certificate(
        db, secrets, cert_id, RevocationReason.key_compromise, principal=principal, now=later
    )

    assert second.id == first.id
    assert second.revoked_at == first.revoked_at
    assert second.revocation_reason == "superseded"
    state = db.get(CRLState, hierarchy.intermediate.id)
    assert state is not None
    # nothing changed, so nothing was republished: no new CRL number either
    assert state.crl_number == first_number
    crl = _parse(state)
    assert len(crl) == 1


def test_revoke_unknown_certificate_errors(db: Session, secrets: SecretStore) -> None:
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Revoke")
    principal = grant_fixtures.granted_admin(db)

    with pytest.raises(RevocationError):
        revoke_certificate(
            db, secrets, 4242, RevocationReason.unspecified, principal=principal, now=_NOW
        )

    # a failed revocation must not leave a CRL behind either
    assert db.get(CRLState, hierarchy.intermediate.id) is None


def test_revoke_with_a_keyless_issuer_leaves_the_row_alone(
    db: Session, secrets: SecretStore
) -> None:
    """FR-4's "one transaction": if the CRL cannot be published, the mark must
    come off again -- a row recorded as revoked that no CRL mentions is a
    revocation nobody can see.

    Redesigned for spec 0017: ``certificates.issuer_id`` is NOT NULL now, so
    an orphan row with no CA at all cannot exist (see test_store_schema.py).
    The equivalent premise is an issuer that exists but has no usable
    private key -- exactly what :func:`ca_fixtures.sole_active_issuer`
    builds, and exactly the situation FR-3 names for an imported root.
    """
    issuer_id = ca_fixtures.sole_active_issuer(db)
    principal = grant_fixtures.granted_admin(db, issuer_id)
    row = ca_fixtures.insert_cert(db, issuer_id=issuer_id, cn="keyless.lan")

    with pytest.raises(CANotConfiguredError):
        revoke_certificate(
            db, secrets, row.id, RevocationReason.superseded, principal=principal, now=_NOW
        )

    db.refresh(row)
    assert row.revoked_at is None
    assert row.revocation_reason is None
    assert db.get(CRLState, issuer_id) is None


def test_crl_number_monotonic(db: Session, secrets: SecretStore) -> None:
    """AC-3: relying parties reject a CRL whose number went backwards, so the
    counter only ever climbs -- including across revocations."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Numbers")
    issuer_id = hierarchy.intermediate.id
    principal = grant_fixtures.granted_admin(db, issuer_id)

    numbers = [regenerate_crl(db, secrets, issuer_id, now=_NOW).crl_number for _ in range(3)]
    cert_id = _issue(db, secrets, principal)
    revoke_certificate(
        db, secrets, cert_id, RevocationReason.unspecified, principal=principal, now=_NOW
    )
    state = db.get(CRLState, issuer_id)
    assert state is not None
    numbers.append(state.crl_number)

    assert numbers == sorted(set(numbers))
    assert numbers[0] >= 1
    assert (
        _parse(state).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        == (numbers[-1])
    )
    # exactly one row for THIS issuer: the CRL is a single current document
    # per issuer, not a history.
    assert db.query(CRLState).filter(CRLState.issuer_id == issuer_id).count() == 1


def test_crl_next_update_window(db: Session, secrets: SecretStore) -> None:
    """FR-4: nextUpdate is thisUpdate + 7 days, and a CRL past it is replaced
    on access rather than served stale (AC-4's self-healing half)."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Window")
    issuer_id = hierarchy.intermediate.id
    assert CRL_VALIDITY.days == 7

    state = regenerate_crl(db, secrets, issuer_id, now=_NOW)
    # the row is the session's one CRLState object, so remember the value,
    # not the object, before anything regenerates it
    published = state.crl_number
    crl = _parse(state)
    assert crl.last_update_utc == _NOW
    assert crl.next_update_utc == _NOW + CRL_VALIDITY
    assert len(crl) == 0

    # inside the window the stored CRL is served as-is: no needless resigning
    fresh = current_crl(db, secrets, issuer_id, now=_NOW + timedelta(days=1))
    assert fresh.crl_number == published

    refreshed = current_crl(db, secrets, issuer_id, now=_NOW + CRL_VALIDITY + timedelta(seconds=1))
    assert refreshed.crl_number > published
    assert _parse(refreshed).next_update_utc > _NOW + CRL_VALIDITY


def test_crl_refreshed_before_it_expires(db: Session, secrets: SecretStore) -> None:
    """FR-5: the CRL is served with a one-hour cache header, so it must be
    replaced a full cache lifetime BEFORE nextUpdate -- otherwise a client
    that caches a CRL 30 minutes before it expires is left holding an expired
    one for the other half hour."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Margin")
    issuer_id = hierarchy.intermediate.id
    assert CRL_MAX_AGE.total_seconds() == 3600
    published = regenerate_crl(db, secrets, issuer_id, now=_NOW).crl_number

    # more than one cache lifetime left: no reason to resign yet
    comfortable = current_crl(db, secrets, issuer_id, now=_NOW + CRL_VALIDITY - timedelta(hours=2))
    assert comfortable.crl_number == published

    # 30 minutes to go, still technically valid -- but not for a whole hour
    due = _NOW + CRL_VALIDITY - timedelta(minutes=30)
    refreshed = current_crl(db, secrets, issuer_id, now=due)

    assert refreshed.crl_number > published
    # and the replacement is good for a fresh full window from that moment
    assert _parse(refreshed).next_update_utc == due + CRL_VALIDITY


def test_crl_lazy_regeneration_is_per_issuer(db: Session, secrets: SecretStore) -> None:
    """FR-9/AC-10: a stale stored CRL for one issuer is regenerated on access
    without touching another issuer's ``crl_number`` -- the lazy refresh is
    scoped per issuer, not instance-wide."""
    h1 = ca_fixtures.make_hierarchy(db, secrets, "One")
    h2 = ca_fixtures.make_hierarchy(db, secrets, "Two")
    i1, i2 = h1.intermediate.id, h2.intermediate.id

    published1 = regenerate_crl(db, secrets, i1, now=_NOW).crl_number
    published2 = regenerate_crl(db, secrets, i2, now=_NOW).crl_number

    # Only I1's CRL is stale; accessing it must not touch I2's number.
    stale_access = _NOW + CRL_VALIDITY + timedelta(seconds=1)
    refreshed1 = current_crl(db, secrets, i1, now=stale_access)
    assert refreshed1.crl_number > published1

    untouched2 = db.get(CRLState, i2)
    assert untouched2 is not None
    assert untouched2.crl_number == published2
