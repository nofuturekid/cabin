"""Tests for cabin.issuer_grants (spec 0018): the two grant lookups
themselves, and what issuing, revoking, creating a hierarchy and deleting a
user do with them.

``granted_issuers`` and ``may_use_issuer`` are deliberately different
lookups (FR-3): the first feeds issuing and the issuer selector and is
blind to a *retired* issuer, the second feeds revocation and is blind to
*status* instead -- a certificate signed by a since-retired issuer must
stay revocable by whoever was allowed to issue it (spec 0017). The spec's
own warning is that swapping one for the other in FR-6 passes every
criterion except the retired-issuer revocation case, so that case gets a
test of its own here rather than being folded into a general "revocation
works" check: see test_revocation_through_a_retired_granted_issuer_succeeds
and test_omitted_issuer_id_never_falls_back_to_a_retired_grant.

Two fixture styles live here side by side:

* ``db``/``secrets`` for direct calls into cabin.issuer_grants,
  cabin.ca.certs and cabin.ca.crl -- no HTTP, no app. Most of this file.
* ``cfg``/``client`` for FR-8 (whoever creates a hierarchy is granted it):
  that rule is written into the /ca/* route handlers themselves, not into
  any function ``ca.service`` exposes, so proving it needs a real request.

Nothing here drives the six issuance/revocation entry points as a sweep --
that cross-cutting assertion (AC-1/AC-3/AC-6) belongs to
test_issuer_permissions.py. This file is about the policy functions and
what a single representative caller (``ca.certs``/``ca.crl`` called
directly) does with their answer.
"""

from collections.abc import Iterator
from pathlib import Path

import ca_fixtures
import grant_fixtures
import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from cryptography import x509
from fastapi.testclient import TestClient
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import cabin.store as store_module
from cabin.api_tokens import ApiToken, create_token
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import service as ca_service
from cabin.ca.certs import issue_and_store
from cabin.ca.crl import CRLState, revoke_certificate
from cabin.ca.leaf import Profile
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import (
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    UnknownIssuerError,
)
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.issuer_grants import (
    ACME_PRINCIPAL,
    SYSTEM_PRINCIPAL,
    Change,
    IssuerForbiddenError,
    NoGrantedIssuerError,
    PrincipalKind,
    UserIssuer,
    grant,
    granted_issuers,
    issuers_of,
    may_use_issuer,
    resolve_granted_issuer,
    set_issuers,
    token_principal,
    user_principal,
)
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory, run_migrations
from cabin.users import Role, User, create_user, delete_user, get_user

# --- direct-call fixtures (no HTTP) -----------------------------------------


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


def _user(db: Session, username: str, role: Role) -> User:
    return create_user(db, username, "whatever12345", role)


def _token(db: Session, label: str, role: Role) -> ApiToken:
    _secret, row = create_token(db, label, role)
    return row


# --- HTTP fixtures, for FR-8 only -------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets_for(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _user_by_name(db: Session, username: str) -> User:
    row = db.scalar(select(User).where(User.username == username))
    assert row is not None
    return row


def _pem_cert(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _pem_key(key: object) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _migrations_dir() -> Path:
    return Path(store_module.__file__).resolve().parent / "migrations"


# --- Principal: unrestricted is superadmin-only, for users and tokens alike --
# (spec 0018 user story: "my access to every issuer is implicit ... so
# demoting myself later does not take my own CA away" -- and the mirror
# image, that a viewer never gets that implicit access no matter what a
# grant row says.)


@pytest.mark.parametrize("role", [Role.superadmin, Role.admin, Role.viewer])
def test_user_principal_unrestricted_true_only_for_superadmin(db: Session, role: Role) -> None:
    user = _user(db, "u", role)
    principal = user_principal(user)
    assert principal.kind == PrincipalKind.user
    assert principal.id == user.id
    assert principal.role == role
    assert principal.unrestricted == (role == Role.superadmin)


@pytest.mark.parametrize("role", [Role.superadmin, Role.admin, Role.viewer])
def test_token_principal_unrestricted_true_only_for_superadmin(db: Session, role: Role) -> None:
    token = _token(db, "t", role)
    principal = token_principal(token)
    assert principal.kind == PrincipalKind.token
    assert principal.id == token.id
    assert principal.role == role
    assert principal.unrestricted == (role == Role.superadmin)


def test_acme_and_system_principals_are_unrestricted_and_idless() -> None:
    assert ACME_PRINCIPAL.unrestricted
    assert ACME_PRINCIPAL.id is None
    assert ACME_PRINCIPAL.role is None
    assert ACME_PRINCIPAL.kind == PrincipalKind.acme

    assert SYSTEM_PRINCIPAL.unrestricted
    assert SYSTEM_PRINCIPAL.id is None
    assert SYSTEM_PRINCIPAL.role is None
    assert SYSTEM_PRINCIPAL.kind == PrincipalKind.system


# --- granted_issuers / may_use_issuer: the two lookups ----------------------


def test_granted_issuers_for_an_unrestricted_principal_is_every_active_issuer(
    db: Session,
) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    ca_fixtures.retired_issuer(db, "retired")
    superadmin = _user(db, "root", Role.superadmin)
    assert {row.id for row in granted_issuers(db, user_principal(superadmin))} == {a, b}


def test_granted_issuers_for_a_restricted_principal_is_the_intersection(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    ca_fixtures.extra_active_issuer(db, "c")  # active, but never granted
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    grant_fixtures.grant_user(db, admin, b)
    assert {row.id for row in granted_issuers(db, user_principal(admin))} == {a, b}


def test_granted_issuers_excludes_a_retired_issuer_even_when_granted(db: Session) -> None:
    ca_fixtures.sole_active_issuer(db, "kept-active")
    retired = ca_fixtures.retired_issuer(db, "gone")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, retired)
    assert granted_issuers(db, user_principal(admin)) == []


def test_may_use_issuer_is_status_blind_for_a_grant(db: Session) -> None:
    """FR-6's reason to exist: a retired issuer's grant must still answer
    True here, or nobody could revoke what it signed."""
    retired = ca_fixtures.retired_issuer(db, "gone")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, retired)
    assert may_use_issuer(db, user_principal(admin), retired) is True


def test_may_use_issuer_is_false_without_a_grant_even_when_active(db: Session) -> None:
    active = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    assert may_use_issuer(db, user_principal(admin), active) is False


def test_may_use_issuer_is_true_for_every_unrestricted_principal(db: Session) -> None:
    active = ca_fixtures.sole_active_issuer(db, "a")
    superadmin_user = _user(db, "root", Role.superadmin)
    superadmin_token = _token(db, "root-token", Role.superadmin)
    for principal in (
        user_principal(superadmin_user),
        token_principal(superadmin_token),
        ACME_PRINCIPAL,
        SYSTEM_PRINCIPAL,
    ):
        assert may_use_issuer(db, principal, active) is True


def test_token_grants_are_read_from_the_token_table_not_the_user_table(db: Session) -> None:
    """The two join tables are structurally identical (FR-1); this is the
    test that would catch a lookup built against the wrong one."""
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    admin_user = _user(db, "adam", Role.admin)
    admin_token = _token(db, "script", Role.admin)
    grant_fixtures.grant_user(db, admin_user, a)
    grant_fixtures.grant_token(db, admin_token, b)

    assert {row.id for row in granted_issuers(db, user_principal(admin_user))} == {a}
    assert {row.id for row in granted_issuers(db, token_principal(admin_token))} == {b}
    assert may_use_issuer(db, user_principal(admin_user), b) is False
    assert may_use_issuer(db, token_principal(admin_token), a) is False


# --- the substitution trap: issuing and revoking must use different lookups -


def test_revocation_through_a_retired_granted_issuer_succeeds(
    db: Session, secrets: SecretStore
) -> None:
    """The spec's own mutation warning: swap may_use_issuer for
    granted_issuers in revoke_certificate and every other criterion in this
    file still passes, because issuing is unaffected and revocation only
    breaks once the issuer is retired. This is the one test standing
    between that mutation and a green suite.

    Parsed with the cryptography library, not byte-compared -- the same
    proof-of-content standard test_ca_multi.py's
    test_retired_issuer_still_serves_chain_and_crl already sets for exactly
    this scenario pre-0018.
    """
    ca_fixtures.make_hierarchy(db, secrets, "kept-active")  # so retire() is allowed to proceed
    doomed = ca_fixtures.make_hierarchy(db, secrets, "doomed")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, doomed.intermediate.id)

    issued = issue_and_store(
        db,
        secrets,
        principal=user_principal(admin),
        profile=Profile.server,
        subject_cn="doomed.example.lan",
        sans=["DNS:doomed.example.lan"],
        issuer_id=doomed.intermediate.id,
    )
    ca_service.retire(db, doomed.intermediate.id)

    revoked = revoke_certificate(
        db,
        secrets,
        issued.row.id,
        RevocationReason.key_compromise,
        principal=user_principal(admin),
    )
    assert revoked.revoked_at is not None

    state = db.get(CRLState, doomed.intermediate.id)
    assert state is not None
    crl = x509.load_der_x509_crl(state.crl_der)
    assert crl.get_revoked_certificate_by_serial_number(int(issued.row.serial_hex, 16)) is not None


def test_omitted_issuer_id_never_falls_back_to_a_retired_grant(db: Session) -> None:
    ca_fixtures.sole_active_issuer(db, "kept-active")  # granted to nobody
    retired = ca_fixtures.retired_issuer(db, "gone")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, retired)
    with pytest.raises(NoGrantedIssuerError):
        resolve_granted_issuer(db, user_principal(admin), None)


def test_named_retired_issuer_raises_issuer_retired_not_forbidden(db: Session) -> None:
    """AC-5(a): retirement is the operative fact, so the message has to say
    so even though the issuer is also not (usefully) granted any more."""
    ca_fixtures.sole_active_issuer(db, "kept-active")
    retired = ca_fixtures.retired_issuer(db, "gone")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, retired)
    with pytest.raises(IssuerRetiredError):
        resolve_granted_issuer(db, user_principal(admin), retired)


def test_revocation_is_refused_without_the_issuing_grant(db: Session, secrets: SecretStore) -> None:
    granted = ca_fixtures.make_hierarchy(db, secrets, "granted")
    other = ca_fixtures.make_hierarchy(db, secrets, "other")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, granted.intermediate.id)
    superadmin = _user(db, "root", Role.superadmin)

    # A decoy revocation on "other" gives this test a CRL state to prove
    # untouched, rather than merely absent.
    decoy = issue_and_store(
        db,
        secrets,
        principal=user_principal(superadmin),
        profile=Profile.server,
        subject_cn="decoy.example.lan",
        sans=["DNS:decoy.example.lan"],
        issuer_id=other.intermediate.id,
    )
    revoke_certificate(
        db,
        secrets,
        decoy.row.id,
        RevocationReason.unspecified,
        principal=user_principal(superadmin),
    )
    before = db.get(CRLState, other.intermediate.id)
    assert before is not None
    before_number, before_der = before.crl_number, before.crl_der

    target = issue_and_store(
        db,
        secrets,
        principal=user_principal(superadmin),
        profile=Profile.server,
        subject_cn="target.example.lan",
        sans=["DNS:target.example.lan"],
        issuer_id=other.intermediate.id,
    )

    with pytest.raises(IssuerForbiddenError):
        revoke_certificate(
            db,
            secrets,
            target.row.id,
            RevocationReason.unspecified,
            principal=user_principal(admin),
        )

    db.refresh(target.row)
    assert target.row.revoked_at is None
    after = db.get(CRLState, other.intermediate.id)
    assert after is not None
    assert after.crl_number == before_number
    assert after.crl_der == before_der


def test_superadmin_issues_and_revokes_with_no_grant_rows_at_all(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "cabin")
    superadmin = _user(db, "root", Role.superadmin)

    issued = issue_and_store(
        db,
        secrets,
        principal=user_principal(superadmin),
        profile=Profile.server,
        subject_cn="x.example.lan",
        sans=["DNS:x.example.lan"],
        issuer_id=hierarchy.intermediate.id,
    )
    revoked = revoke_certificate(
        db,
        secrets,
        issued.row.id,
        RevocationReason.unspecified,
        principal=user_principal(superadmin),
    )
    assert revoked.revoked_at is not None


# --- FR-4: "exactly one active issuer" narrows to "exactly one granted" -----


def test_single_granted_issuer_among_several_active_is_the_default(db: Session) -> None:
    """The interesting case, not the easy one: three active issuers, one
    granted -- must resolve to it, not be told the choice is ambiguous."""
    a = ca_fixtures.sole_active_issuer(db, "a")
    ca_fixtures.extra_active_issuer(db, "b")
    ca_fixtures.extra_active_issuer(db, "c")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    resolved = resolve_granted_issuer(db, user_principal(admin), None)
    assert resolved.id == a


def test_a_second_grant_makes_the_choice_required(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    ca_fixtures.extra_active_issuer(db, "c")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    grant_fixtures.grant_user(db, admin, b)
    with pytest.raises(IssuerRequiredError):
        resolve_granted_issuer(db, user_principal(admin), None)


def test_superadmin_must_choose_among_several_active_issuers(db: Session) -> None:
    """Same instance, same three active issuers as the admin case above --
    but a superadmin's granted set is all three, so the rule (one rule,
    applied to a different set) lands on IssuerRequiredError instead."""
    ca_fixtures.sole_active_issuer(db, "a")
    ca_fixtures.extra_active_issuer(db, "b")
    ca_fixtures.extra_active_issuer(db, "c")
    superadmin = _user(db, "root", Role.superadmin)
    with pytest.raises(IssuerRequiredError):
        resolve_granted_issuer(db, user_principal(superadmin), None)


def test_single_active_issuer_granted_still_resolves_with_no_issuer_named(db: Session) -> None:
    """0017's single-CA ergonomics survive: one active issuer, granted,
    omitted issuer_id still works."""
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    resolved = resolve_granted_issuer(db, user_principal(admin), None)
    assert resolved.id == a


def test_no_granted_issuer_but_some_active_raises_no_granted_issuer_error(db: Session) -> None:
    ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    with pytest.raises(NoGrantedIssuerError):
        resolve_granted_issuer(db, user_principal(admin), None)


def test_no_active_issuer_anywhere_raises_ca_not_configured(db: Session) -> None:
    admin = _user(db, "adam", Role.admin)
    with pytest.raises(CANotConfiguredError):
        resolve_granted_issuer(db, user_principal(admin), None)


def test_named_issuer_not_granted_raises_issuer_forbidden(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    with pytest.raises(IssuerForbiddenError):
        resolve_granted_issuer(db, user_principal(admin), b)


def test_named_unknown_issuer_raises_unknown_issuer_error(db: Session) -> None:
    admin = _user(db, "adam", Role.admin)
    with pytest.raises(UnknownIssuerError):
        resolve_granted_issuer(db, user_principal(admin), 999_999)


# --- FR-10: grant lifecycle (roots refused, retired allowed, exempt refused) -


def test_set_issuers_rejects_a_root(db: Session, secrets: SecretStore) -> None:
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "root-test")
    admin = _user(db, "adam", Role.admin)
    with pytest.raises(ValueError, match="intermediate"):
        set_issuers(db, user_principal(admin), [hierarchy.root.id])
    assert issuers_of(db, user_principal(admin)) == []


def test_set_issuers_accepts_a_retired_intermediate(db: Session) -> None:
    """Retiring an issuer does not touch its grants (FR-10); pre-granting a
    currently-retired one (e.g. ahead of an un-retire) must not be refused
    the way a root is."""
    retired = ca_fixtures.retired_issuer(db, "gone")
    admin = _user(db, "adam", Role.admin)
    change = set_issuers(db, user_principal(admin), [retired])
    assert change.issuers == [retired]


def test_set_issuers_rejects_acme_and_system_targets(db: Session) -> None:
    active = ca_fixtures.sole_active_issuer(db, "a")
    for principal in (ACME_PRINCIPAL, SYSTEM_PRINCIPAL):
        with pytest.raises(ValueError):
            set_issuers(db, principal, [active])
        with pytest.raises(ValueError):
            grant(db, principal, active)


def test_set_issuers_reports_added_and_removed(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    c = ca_fixtures.extra_active_issuer(db, "c")
    admin = _user(db, "adam", Role.admin)

    first = set_issuers(db, user_principal(admin), [a, b])
    assert sorted(first.added) == [a, b]
    assert first.removed == []
    assert sorted(first.issuers) == [a, b]
    assert first.changed is True

    second = set_issuers(db, user_principal(admin), [b, c])
    assert second.added == [c]
    assert second.removed == [a]
    assert sorted(second.issuers) == [b, c]
    assert second.changed is True


def test_reposting_the_identical_set_reports_no_change(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    set_issuers(db, user_principal(admin), [a])
    repeat = set_issuers(db, user_principal(admin), [a])
    assert repeat == Change(added=[], removed=[], issuers=[a])
    assert repeat.changed is False


def test_grant_reports_whether_a_row_was_actually_written(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    assert grant(db, user_principal(admin), a) is True
    assert grant(db, user_principal(admin), a) is False  # already granted: idempotent, no 2nd row
    assert issuers_of(db, user_principal(admin)) == [a]


def test_issuers_of_reflects_the_current_set(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    b = ca_fixtures.extra_active_issuer(db, "b")
    token = _token(db, "script", Role.admin)
    set_issuers(db, token_principal(token), [a, b])
    assert sorted(issuers_of(db, token_principal(token))) == sorted([a, b])
    set_issuers(db, token_principal(token), [])
    assert issuers_of(db, token_principal(token)) == []


# --- FR-10 / AC-12: deleting a user deletes its grants, loudly if forgotten -


def test_deleted_user_leaves_no_grants(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)
    admin_id = admin.id

    delete_user(db, admin_id)

    remaining = db.scalars(select(UserIssuer).where(UserIssuer.user_id == admin_id)).all()
    assert remaining == []


def test_delete_user_with_a_grant_does_not_raise(db: Session) -> None:
    """The trap: cabin enforces SQLite foreign keys (store/__init__.py) and
    neither join table declares ``ondelete`` (migration 0010), so a
    forgotten cleanup here does not leave a silent orphan row -- it raises
    IntegrityError and makes a granted user permanently undeletable. That is
    the loud bug FR-10's application-level cleanup exists to prevent."""
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    grant_fixtures.grant_user(db, admin, a)

    delete_user(db, admin.id)  # must not raise IntegrityError

    assert db.get(User, admin.id) is None


def test_migration_0010_declares_no_ondelete_on_either_foreign_key(db: Session) -> None:
    """AC-12 part 2: asserted against the schema cabin actually migrates to,
    not the migration's source text. Without this, part 1 above would pass
    even if the application cleanup were missing entirely, because a
    CASCADE would have done the job instead -- the criterion would then be
    measuring SQLite, not FR-10."""
    inspector = sa_inspect(db.get_bind())
    for table, column in (("user_issuers", "user_id"), ("token_issuers", "api_token_id")):
        fks = inspector.get_foreign_keys(table)
        matching = [fk for fk in fks if column in fk["constrained_columns"]]
        assert len(matching) == 1, (table, column, fks)
        assert matching[0]["options"].get("ondelete") is None, (table, column, matching[0])


# --- AC-17: schema -----------------------------------------------------------


def test_schema_join_tables_have_composite_primary_keys(db: Session) -> None:
    inspector = sa_inspect(db.get_bind())
    for table, columns in (
        ("user_issuers", {"user_id", "ca_certificate_id"}),
        ("token_issuers", {"api_token_id", "ca_certificate_id"}),
    ):
        pk = inspector.get_pk_constraint(table)
        assert set(pk["constrained_columns"]) == columns
        for col in inspector.get_columns(table):
            if col["name"] in columns:
                assert col["nullable"] is False


def test_duplicate_grant_pair_fails_at_the_database(db: Session) -> None:
    a = ca_fixtures.sole_active_issuer(db, "a")
    admin = _user(db, "adam", Role.admin)
    db.add(UserIssuer(user_id=admin.id, ca_certificate_id=a))
    db.commit()
    db.add(UserIssuer(user_id=admin.id, ca_certificate_id=a))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_migration_0010_down_revision_is_0009() -> None:
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_migrations_dir()))
    script = ScriptDirectory.from_config(cfg)
    revision = script.get_revision("0010")
    assert revision is not None
    assert revision.down_revision == "0009"


def test_migration_0010_downgrade_drops_both_tables(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_migrations_dir()))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.downgrade(cfg, "0009")

    factory = create_session_factory(db_url)
    session = factory()
    try:
        inspector = sa_inspect(session.get_bind())
        assert "user_issuers" not in inspector.get_table_names()
        assert "token_issuers" not in inspector.get_table_names()
    finally:
        session.close()


# --- FR-8: whoever creates a hierarchy is granted it, immediately ----------


def test_ca_create_grants_the_creator_and_not_the_root(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    _create_user(client, cfg, "beth", "admin")

    _login(client, "adam")
    resp = client.post(
        "/ca/create",
        data={
            "name": "lab",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "path_length": 1,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        root = next(r for r in rows if r.name == "lab Root CA")
        intermediate = next(r for r in rows if r.name == "lab Intermediate CA")
        adam_row = _user_by_name(db, "adam")
        beth_row = _user_by_name(db, "beth")

        # The grant lands on the new INTERMEDIATE only -- the root gets none.
        assert issuers_of(db, user_principal(adam_row)) == [intermediate.id]
        assert root.id not in issuers_of(db, user_principal(adam_row))
        assert issuers_of(db, user_principal(beth_row)) == []

        # The creator issues with no issuer named at all -- and beth, facing
        # the exact same single ACTIVE issuer, cannot: proving the default
        # rule counts GRANTED issuers, not merely active ones.
        issued = issue_and_store(
            db,
            _secrets_for(cfg),
            principal=user_principal(adam_row),
            profile=Profile.server,
            subject_cn="lab.example.lan",
            sans=["DNS:lab.example.lan"],
        )
        assert issued.row.issuer_id == intermediate.id

        with pytest.raises(NoGrantedIssuerError):
            resolve_granted_issuer(db, user_principal(beth_row), None)

        event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == AuditAction.ca_created.value,
                AuditEvent.target_id == str(intermediate.id),
            )
        )
        assert event is not None
        assert event.detail is not None
        assert event.detail["granted_to"] == adam_row.id
    finally:
        db.close()


def test_ca_import_grants_the_creator(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")
    _login(client, "adam")

    root_cert, root_key = create_root("Imported Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Imported Intermediate CA", "ecdsa-p256"
    )
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert(intermediate_cert),
            "key_pem": _pem_key(intermediate_key),
            "chain_pem": _pem_cert(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        intermediate = next(r for r in rows if r.name == "Imported Intermediate CA")
        adam_row = _user_by_name(db, "adam")
        assert issuers_of(db, user_principal(adam_row)) == [intermediate.id]

        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == AuditAction.ca_imported.value)
        )
        assert event is not None
        assert event.detail is not None
        assert event.detail["granted_to"] == adam_row.id
    finally:
        db.close()


def test_ca_intermediate_grants_the_creator(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "adam", "admin")

    assert (
        client.post(
            "/ca/create",
            data={
                "name": "root-only",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "path_length": 1,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    db = _db(cfg)
    try:
        root_id = next(r.id for r in ca_service.list_cas(db) if r.name == "root-only Root CA")
    finally:
        db.close()

    _login(client, "adam")
    resp = client.post(
        f"/ca/{root_id}/intermediate",
        data={
            "name": "second",
            "key_type": "ecdsa-p256",
            "years": 5,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    db = _db(cfg)
    try:
        second = next(r for r in ca_service.list_cas(db) if r.name == "second Intermediate CA")
        adam_row = _user_by_name(db, "adam")
        assert issuers_of(db, user_principal(adam_row)) == [second.id]

        event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == AuditAction.ca_created.value,
                AuditEvent.target_id == str(second.id),
            )
        )
        assert event is not None
        assert event.detail is not None
        assert event.detail["granted_to"] == adam_row.id
    finally:
        db.close()


def test_superadmin_creator_keeps_its_hierarchy_after_demotion(
    client: TestClient, cfg: Config
) -> None:
    """The row is written even for a superadmin, where it is redundant at
    the time -- so that demoting them later does not take their own CA away
    (FR-8). A second superadmin has to exist first, or demoting alice would
    be refused as the last-superadmin guard, not proved by this test."""
    _setup_superadmin(client)  # alice
    _create_user(client, cfg, "beth", "superadmin")
    _create_user(client, cfg, "carol", "admin")  # never touches CA creation

    assert (
        client.post(
            "/ca/create",
            data={
                "name": "solo",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "path_length": 1,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )

    db = _db(cfg)
    try:
        intermediate_id = next(
            r.id for r in ca_service.list_cas(db) if r.name == "solo Intermediate CA"
        )
        alice_id = _user_by_name(db, "alice").id
    finally:
        db.close()

    demoted = client.post(
        f"/users/{alice_id}/role", data={"role": "admin", "csrf_token": _csrf(client, cfg)}
    )
    assert demoted.status_code == 303

    db = _db(cfg)
    try:
        alice_row = get_user(db, alice_id)
        assert alice_row.role == Role.admin.value  # the premise: no longer unrestricted

        issued = issue_and_store(
            db,
            _secrets_for(cfg),
            principal=user_principal(alice_row),
            profile=Profile.server,
            subject_cn="solo.example.lan",
            sans=["DNS:solo.example.lan"],
        )
        assert issued.row.issuer_id == intermediate_id

        carol_row = _user_by_name(db, "carol")
        with pytest.raises(NoGrantedIssuerError):
            resolve_granted_issuer(db, user_principal(carol_row), None)
    finally:
        db.close()
