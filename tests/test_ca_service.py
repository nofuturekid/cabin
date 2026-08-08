"""Tests for cabin.ca.service: DB storage of CA hierarchies with sealed
private keys, on top of real certificates from cabin.ca.x509 (spec 0004
FR-3/FR-4; spec 0017 FR-2/FR-3/FR-4/FR-5/FR-6 for multiple hierarchies).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from sqlalchemy import select
from sqlalchemy.orm import Session

import cabin.ca.service as ca_service
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    RetireError,
    UnknownIssuerError,
    active_issuers,
    chain_for,
    create_hierarchy,
    create_intermediate_under,
    get_ca,
    import_hierarchy,
    list_cas,
    renew_in_place,
    resolve_issuer,
    retire,
    signing_credentials,
)
from cabin.ca.x509 import create_intermediate, create_root
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations


def test_ca_exists_error_is_deleted() -> None:
    """FR-2: CAExistsError and both check-then-insert guards are removed, not
    merely unused -- a second hierarchy is ordinary operation now."""
    assert not hasattr(ca_service, "CAExistsError")


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


def _pem_cert_bytes(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key_str(key: object, *, password: bytes | None = None) -> str:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


def _imported_root(db: Session, name: str = "Imported") -> CACertificate:
    """A root row with no stored key, exactly what an import leaves behind
    (FR-2/FR-3: ``import_hierarchy`` never receives the root's key)."""
    cert, _key = create_root(f"{name} Root CA", "ecdsa-p256")
    row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row


def _imported_root_with_intermediate(
    db: Session, secrets: SecretStore, name: str = "Imported"
) -> tuple[CACertificate, CACertificate]:
    """An intermediate that DOES have its key, whose parent root does not --
    the case FR-5 names explicitly: renewal needs the parent's key, and an
    imported root has none."""
    root_cert, root_key = create_root(f"{name} Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, f"{name} Intermediate CA", "ecdsa-p256"
    )
    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=_pem_cert_bytes(root_cert).decode("ascii"),
        key_sealed=None,
    )
    db.add(root_row)
    db.flush()
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status="active",
        cert_pem=_pem_cert_bytes(intermediate_cert).decode("ascii"),
        key_sealed=secrets.seal(
            intermediate_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
    )
    db.add(intermediate_row)
    db.commit()
    return root_row, intermediate_row


# --- AC-1/AC-2: wizard create -> two sealed rows -----------------------------


def test_keys_sealed_in_db(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin")

    rows = {row.kind: row for row in db.scalars(select(CACertificate))}
    assert set(rows) == {"root", "intermediate"}
    for row in rows.values():
        assert row.key_sealed is not None
        # sealed tokens are base64url, not PEM -- never plaintext key material
        assert "BEGIN" not in row.key_sealed
        assert "PRIVATE KEY" not in row.key_sealed


# --- AC-2: unseal back to a working private key ------------------------------


def test_signing_credentials_roundtrip(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    cert, key = signing_credentials(db, secrets, hierarchy.intermediate.id)

    assert isinstance(key, ec.EllipticCurvePrivateKey)
    message = b"roundtrip-check"
    signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))  # no exception


def test_signing_credentials_roundtrip_ed25519(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin", key_type="ed25519")

    cert, key = signing_credentials(db, secrets, hierarchy.intermediate.id)

    assert isinstance(key, ed25519.Ed25519PrivateKey)
    message = b"ed25519-roundtrip-check"
    signature = key.sign(message)
    cert.public_key().verify(signature, message)  # no exception -> success


def test_signing_credentials_unknown_issuer_raises(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(UnknownIssuerError):
        signing_credentials(db, secrets, 999_999)


# --- FR-2: several hierarchies coexist, CAExistsError is gone ----------------


def test_second_hierarchy_can_be_created(db: Session, secrets: SecretStore) -> None:
    """The opposite of the pre-0017 test: a second hierarchy is ordinary
    operation now, not a conflict."""
    first = create_hierarchy(db, secrets, "cabin-one")
    second = create_hierarchy(db, secrets, "cabin-two")

    assert first.root.id != second.root.id
    assert first.intermediate.id != second.intermediate.id
    rows = list(db.scalars(select(CACertificate)))
    assert len(rows) == 4


def test_import_hierarchy_can_add_a_further_hierarchy(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin-one")

    root_cert, root_key = create_root("Other Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Other Intermediate CA", "ecdsa-p256"
    )
    imported = import_hierarchy(
        db,
        secrets,
        _pem_cert_bytes(intermediate_cert).decode("ascii"),
        _pem_key_str(intermediate_key),
        None,
        _pem_cert_bytes(root_cert).decode("ascii"),
    )

    assert imported.root.key_sealed is None  # never supplied for an import
    assert imported.intermediate.key_sealed is not None
    rows = list(db.scalars(select(CACertificate)))
    assert len(rows) == 4
    # Naming rule: import_hierarchy takes no name -- the row's name is read
    # off the imported certificate's own subject, not a cabin-local label.
    assert imported.root.name == "Other Root CA"
    assert imported.intermediate.name == "Other Intermediate CA"


# --- AC-5: import stores the PARSED parent, not the raw submitted chain_pem -


def test_import_stores_only_direct_parent_from_multi_cert_chain(
    db: Session, secrets: SecretStore
) -> None:
    """A chain_pem bundle containing more than one certificate must not leak
    the extra cert(s) into the stored root row -- only the direct parent
    (the first certificate in the bundle, which is what load_import's chain
    check verifies against) is kept."""
    root_cert, root_key = create_root("Chain Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Chain Intermediate CA", "ecdsa-p256"
    )
    unrelated_cert, _unrelated_key = create_root("Unrelated CA", "ecdsa-p256")

    chain_pem = _pem_cert_bytes(root_cert).decode("ascii") + _pem_cert_bytes(unrelated_cert).decode(
        "ascii"
    )

    hierarchy = import_hierarchy(
        db,
        secrets,
        _pem_cert_bytes(intermediate_cert).decode("ascii"),
        _pem_key_str(intermediate_key),
        None,
        chain_pem,
    )

    stored_certs = x509.load_pem_x509_certificates(hierarchy.root.cert_pem.encode("ascii"))
    assert len(stored_certs) == 1
    assert stored_certs[0].subject.rfc4514_string() == "CN=Chain Root CA"
    # Naming rule: the row's name is read off the certificate's subject.
    assert hierarchy.root.name == "Chain Root CA"


# --- FR-4: signing_credentials with no CA configured -------------------------


def test_signing_credentials_raises_when_no_ca(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(UnknownIssuerError):
        signing_credentials(db, secrets, 1)


# --- FR-2: list_cas / chain_for / active_issuers / get_ca(issuer_id) --------


def test_list_cas_orders_by_id(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    h2 = create_hierarchy(db, secrets, "cabin-two")

    rows = list_cas(db)

    assert [row.id for row in rows] == sorted(row.id for row in rows)
    assert {row.id for row in rows} == {
        h1.root.id,
        h1.intermediate.id,
        h2.root.id,
        h2.intermediate.id,
    }


def test_list_cas_filters_by_status_and_kind(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")
    # FR-4: the last active intermediate cannot be retired, so the
    # replacement must exist before the old one is retired (the rotation
    # order the spec's own user story describes).
    create_intermediate_under(db, secrets, hierarchy.root.id, "cabin second", years=5)
    retire(db, hierarchy.intermediate.id)

    assert {row.id for row in list_cas(db, kind="root")} == {hierarchy.root.id}
    assert {row.id for row in list_cas(db, status="retired")} == {hierarchy.intermediate.id}
    assert hierarchy.intermediate.id not in {row.id for row in list_cas(db, status="active")}


def test_chain_for_walks_parent_id_nearest_first_root_last(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    chain = chain_for(db, hierarchy.intermediate.id)

    assert [row.id for row in chain] == [hierarchy.intermediate.id, hierarchy.root.id]


def test_chain_for_root_has_no_ancestors(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    chain = chain_for(db, hierarchy.root.id)

    assert [row.id for row in chain] == [hierarchy.root.id]


def test_chain_for_unknown_id_raises(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(UnknownIssuerError):
        chain_for(db, 999_999)


def test_active_issuers_excludes_retired_and_roots(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    h2 = create_hierarchy(db, secrets, "cabin-two")
    retire(db, h2.intermediate.id)

    ids = {row.id for row in active_issuers(db)}

    assert ids == {h1.intermediate.id}
    assert h1.root.id not in ids
    assert h2.intermediate.id not in ids


def test_get_ca_unknown_id_raises(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(UnknownIssuerError):
        get_ca(db, 999_999)


def test_get_ca_returns_row_regardless_of_status(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")
    # FR-4: the last active intermediate cannot be retired, so create the
    # replacement first (the rotation order the spec's own user story
    # describes).
    create_intermediate_under(db, secrets, hierarchy.root.id, "cabin second", years=5)
    retire(db, hierarchy.intermediate.id)

    row = get_ca(db, hierarchy.intermediate.id)

    assert row.id == hierarchy.intermediate.id
    assert row.status == "retired"


# --- FR-3: create_intermediate_under -----------------------------------------


def test_create_intermediate_under_root_signs_with_parent_key(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin", root_years=20)

    second = create_intermediate_under(db, secrets, hierarchy.root.id, "cabin second", years=8)

    assert second.parent_id == hierarchy.root.id
    assert second.status == "active"
    assert second.kind == "intermediate"
    assert second.key_sealed is not None

    root_cert = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))
    second_cert = x509.load_pem_x509_certificate(second.cert_pem.encode("ascii"))
    second_cert.verify_directly_issued_by(root_cert)  # raises on failure


def test_create_intermediate_under_rejects_non_root(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    with pytest.raises(ValueError, match="root"):
        create_intermediate_under(db, secrets, hierarchy.intermediate.id, "nope")

    assert list_cas(db, kind="intermediate") == [
        row for row in list_cas(db) if row.kind == "intermediate"
    ]
    assert len(list_cas(db, kind="intermediate")) == 1  # no extra row written


def test_create_intermediate_under_clamps_validity_to_root(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin", root_years=1)
    root_cert = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))

    second = create_intermediate_under(db, secrets, hierarchy.root.id, "clamped", years=10)

    second_cert = x509.load_pem_x509_certificate(second.cert_pem.encode("ascii"))
    assert second_cert.not_valid_after_utc <= root_cert.not_valid_after_utc


def test_create_intermediate_under_imported_root_raises(db: Session, secrets: SecretStore) -> None:
    """AC-13: an imported root has no key cabin can sign with (FR-3)."""
    root = _imported_root(db)
    before = len(list_cas(db))

    with pytest.raises(CANotConfiguredError, match="key"):
        create_intermediate_under(db, secrets, root.id, "under imported root")

    assert len(list_cas(db)) == before


# --- FR-4: retire -------------------------------------------------------------


def test_retire_sets_status_and_is_idempotent(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    create_hierarchy(db, secrets, "cabin-two")  # keeps an active issuer elsewhere

    retire(db, h1.intermediate.id)
    assert get_ca(db, h1.intermediate.id).status == "retired"

    retire(db, h1.intermediate.id)  # no-op, not an error
    assert get_ca(db, h1.intermediate.id).status == "retired"


def test_retire_last_active_intermediate_refused(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    with pytest.raises(RetireError):
        retire(db, hierarchy.intermediate.id)

    assert get_ca(db, hierarchy.intermediate.id).status == "active"


def test_retire_root_cascades_to_intermediates(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    create_hierarchy(db, secrets, "cabin-two")  # elsewhere active issuer
    second_under_root1 = create_intermediate_under(db, secrets, h1.root.id, "second")

    retire(db, h1.root.id)

    assert get_ca(db, h1.root.id).status == "retired"
    assert get_ca(db, h1.intermediate.id).status == "retired"
    assert get_ca(db, second_under_root1.id).status == "retired"


def test_retire_root_refused_when_it_would_leave_no_active_issuer(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    with pytest.raises(RetireError):
        retire(db, hierarchy.root.id)

    assert get_ca(db, hierarchy.root.id).status == "active"
    assert get_ca(db, hierarchy.intermediate.id).status == "active"


def test_retire_root_allowed_when_another_hierarchy_stays_active(
    db: Session, secrets: SecretStore
) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    h2 = create_hierarchy(db, secrets, "cabin-two")

    retire(db, h1.root.id)  # h2's intermediate is still active

    assert get_ca(db, h1.root.id).status == "retired"
    assert get_ca(db, h1.intermediate.id).status == "retired"
    assert get_ca(db, h2.intermediate.id).status == "active"


# --- FR-5: renew_in_place -----------------------------------------------------


def test_renew_in_place_same_key_name_id_longer_validity(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin", root_years=1)
    before_cert = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))
    before_ski = before_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest

    renewed = renew_in_place(db, secrets, hierarchy.root.id, years=30)

    assert renewed.id == hierarchy.root.id
    after_cert = x509.load_pem_x509_certificate(renewed.cert_pem.encode("ascii"))
    assert after_cert.subject == before_cert.subject
    after_ski = after_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    assert after_ski == before_ski  # same key -> same SKI, the whole point
    assert after_cert.serial_number != before_cert.serial_number
    assert after_cert.not_valid_after_utc > before_cert.not_valid_after_utc

    # SKI equality is carried over unconditionally by renew_certificate and
    # so would still hold even if the row had been re-signed with a fresh
    # key -- it does not prove the key is unchanged. Check the actual public
    # key bytes, and that the renewed root's self-signature verifies against
    # that same key: a root resigned with a different private key still has
    # subject == issuer (still "looks" self-issued) but fails this check.
    def _spki(cert: x509.Certificate) -> bytes:
        return cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    assert _spki(after_cert) == _spki(before_cert)
    after_cert.verify_directly_issued_by(after_cert)

    stored = get_ca(db, hierarchy.root.id)
    assert stored.cert_pem == renewed.cert_pem


def test_renew_in_place_imported_root_raises(db: Session, secrets: SecretStore) -> None:
    root = _imported_root(db)

    with pytest.raises(CANotConfiguredError, match="key"):
        renew_in_place(db, secrets, root.id, years=10)


def test_renew_in_place_intermediate_under_imported_root_raises(
    db: Session, secrets: SecretStore
) -> None:
    """The intermediate has its own key, but renewal signs with the PARENT's
    key -- and an imported root has none (FR-5)."""
    _root, intermediate = _imported_root_with_intermediate(db, secrets)

    with pytest.raises(CANotConfiguredError, match="key"):
        renew_in_place(db, secrets, intermediate.id, years=5)


# --- FR-6: resolve_issuer -----------------------------------------------------


def test_resolve_issuer_explicit_id(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    h2 = create_hierarchy(db, secrets, "cabin-two")

    resolved = resolve_issuer(db, h2.intermediate.id)

    assert resolved.id == h2.intermediate.id
    assert resolved.id != h1.intermediate.id


def test_resolve_issuer_unknown_id_raises(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin")

    with pytest.raises(UnknownIssuerError):
        resolve_issuer(db, 999_999)


def test_resolve_issuer_retired_id_raises(db: Session, secrets: SecretStore) -> None:
    h1 = create_hierarchy(db, secrets, "cabin-one")
    create_hierarchy(db, secrets, "cabin-two")
    retire(db, h1.intermediate.id)

    with pytest.raises(IssuerRetiredError):
        resolve_issuer(db, h1.intermediate.id)


def test_resolve_issuer_defaults_when_one_active(db: Session, secrets: SecretStore) -> None:
    hierarchy = create_hierarchy(db, secrets, "cabin")

    resolved = resolve_issuer(db, None)

    assert resolved.id == hierarchy.intermediate.id


def test_resolve_issuer_requires_id_when_several_active(db: Session, secrets: SecretStore) -> None:
    create_hierarchy(db, secrets, "cabin-one")
    create_hierarchy(db, secrets, "cabin-two")

    with pytest.raises(IssuerRequiredError):
        resolve_issuer(db, None)


def test_resolve_issuer_no_active_at_all_raises(db: Session, secrets: SecretStore) -> None:
    with pytest.raises(CANotConfiguredError):
        resolve_issuer(db, None)
