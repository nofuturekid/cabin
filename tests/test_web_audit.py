"""Wiring, UI and API tests for the audit log (spec 0009 FR-4..FR-7,
AC-1..AC-7): every state change writes exactly one event, no event carries a
secret, and /audit and /api/v1/audit show them back.
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin import audit
from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import service as ca_service
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.users import Role

SUPERADMIN_PASSWORD = "correcthorse1"
USER_PASSWORD = "whatever12345"
#: The shape of a token secret, for finding the one the page shows once.
_SECRET_RE = re.compile(r"cabin_[A-Za-z0-9_-]{43}")


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


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    resp = client.post("/setup", data={"username": "alice", "password": SUPERADMIN_PASSWORD})
    assert resp.status_code == 303


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": USER_PASSWORD,
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = USER_PASSWORD) -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _create_ca(client: TestClient, cfg: Config, name: str = "cabin") -> None:
    resp = client.post(
        "/ca/create",
        data={
            "name": name,
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _issue(client: TestClient, cfg: Config, cn: str = "nas.lan") -> int:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": cn,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _csr_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _events(cfg: Config, action: str | None = None) -> list[AuditEvent]:
    """Every event written so far, oldest first -- detached, so a test can
    keep reading them after the session is gone."""
    db = _db(cfg)
    try:
        rows = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        for row in rows:
            _ = row.detail, row.summary, row.ip, row.actor_label, row.target_id
        db.expunge_all()
    finally:
        db.close()
    return [row for row in rows if action is None or row.action == action]


def _one(cfg: Config, action: AuditAction) -> AuditEvent:
    rows = _events(cfg, action)
    assert len(rows) == 1, f"expected exactly one {action} event, got {len(rows)}"
    return rows[0]


def _api_token(cfg: Config, role: Role = Role.admin) -> str:
    db = _db(cfg)
    try:
        secret, _ = create_token(db, f"{role.value}-token", role)
        return secret
    finally:
        db.close()


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


# --- FR-4/AC-1/AC-2: authentication -------------------------------------------


def test_login_success_and_failure_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    client.cookies.clear()

    assert (
        client.post("/login", data={"username": "alice", "password": "wrongpassword"}).status_code
        == 401
    )
    assert (
        client.post("/login", data={"username": "ghost", "password": "wrongpassword"}).status_code
        == 401
    )
    _login(client, "alice", SUPERADMIN_PASSWORD)

    failed = _events(cfg, AuditAction.login_failed)
    assert len(failed) == 2
    for event, attempted in zip(failed, ("alice", "ghost"), strict=True):
        # AC-2: the attempted username is in the summary, and no user id is
        # claimed -- a failed login has not proven who was at the keyboard.
        assert attempted in event.summary
        assert event.actor_label == attempted
        assert event.actor_id is None
        assert event.actor_kind == "user"
        assert event.ip == "testclient"
        # Never the password, not even the wrong one.
        assert "wrongpassword" not in (event.summary + (event.detail_json or ""))

    # The first-run setup logs the new superadmin in, so that is a login too.
    logins = _events(cfg, AuditAction.login_success)
    assert len(logins) == 2
    assert logins[-1].actor_label == "alice"
    assert logins[-1].actor_id is not None


def test_logout_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    resp = client.post("/logout", data={"csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303

    event = _one(cfg, AuditAction.logout)
    assert event.actor_kind == "user"
    assert event.actor_label == "alice"
    assert "alice" in event.summary


# --- FR-4/AC-1: user management -----------------------------------------------


def test_user_management_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_user(client, cfg, "bob", "viewer")
    creations = _events(cfg, AuditAction.user_created)
    # First-run setup created a user too, with cabin itself as the actor --
    # the log must not start one account late.
    assert [event.actor_kind for event in creations] == ["system", "user"]
    bob_id = creations[-1].target_id
    assert bob_id is not None

    for path, data in (
        (f"/users/{bob_id}/role", {"role": "admin"}),
        # Setting the role a user already has changes nothing, so it is not
        # an event either.
        (f"/users/{bob_id}/role", {"role": "admin"}),
        (f"/users/{bob_id}/password", {"password": "brandnewpassword"}),
        (f"/users/{bob_id}/delete", {}),
    ):
        resp = client.post(path, data={**data, "csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 303

    created = _events(cfg, AuditAction.user_created)[-1]
    assert created.actor_label == "alice"
    assert created.target_type == "user"
    assert created.detail == {"username": "bob", "role": "viewer"}
    assert "bob" in created.summary

    changed = _one(cfg, AuditAction.user_role_changed)
    assert changed.detail == {
        "username": "bob",
        "old_role": "viewer",
        "new_role": "admin",
    }

    reset = _one(cfg, AuditAction.user_password_reset)
    assert reset.detail == {"username": "bob"}
    # FR-3: the new password is nowhere near the log.
    assert "brandnewpassword" not in (reset.summary + (reset.detail_json or ""))

    deleted = _one(cfg, AuditAction.user_deleted)
    assert deleted.target_id == bob_id
    assert deleted.detail == {"username": "bob", "role": "admin"}


# --- FR-4/AC-1: CA and settings -----------------------------------------------


def test_ca_create_import_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, name="Acme")

    created = _one(cfg, AuditAction.ca_created)
    assert created.actor_label == "alice"
    # spec 0017 FR-15: target_type="ca" is replaced by "ca_certificate" --
    # one table, one target type, shared with cert issuance's "certificate".
    assert created.target_type == "ca_certificate"
    assert created.detail is not None
    assert created.detail["name"] == "Acme"
    assert created.detail["key_type"] == "ecdsa-p256"
    assert "Acme" in created.summary


def test_ca_import_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    root_cert, root_key = create_root("Import Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Import Intermediate CA", "ecdsa-p256"
    )
    key_pem = intermediate_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert(intermediate_cert),
            "key_pem": key_pem,
            "chain_pem": _pem_cert(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    imported = _one(cfg, AuditAction.ca_imported)
    assert "Import Intermediate CA" in imported.summary
    assert imported.target_type == "ca_certificate"
    assert imported.detail is not None
    # FR-3: the imported private key must not survive anywhere in the log.
    blob = imported.summary + (imported.detail_json or "")
    assert "PRIVATE KEY" not in blob


def test_ca_created_and_imported_use_the_ca_certificate_target_type(
    client: TestClient, cfg: Config
) -> None:
    """FR-15 replaces target_type="ca" with "ca_certificate" at both
    web/ca_ui.py:135 (create) and :187 (import) -- checked together, and
    checked that the old label is gone entirely rather than merely unused by
    these two particular events."""
    _setup_superadmin(client)
    _create_ca(client, cfg, name="created-target")

    root_cert, root_key = create_root("Import Target Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Import Target Intermediate CA", "ecdsa-p256"
    )
    key_pem = intermediate_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert(intermediate_cert),
            "key_pem": key_pem,
            "chain_pem": _pem_cert(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    created = _one(cfg, AuditAction.ca_created)
    imported = _one(cfg, AuditAction.ca_imported)
    assert created.target_type == "ca_certificate"
    assert imported.target_type == "ca_certificate"
    assert all(event.target_type != "ca" for event in _events(cfg))


def test_audit_ca_renewed_and_retired(client: TestClient, cfg: Config) -> None:
    """AC-14: ca_renewed/ca_retired carry target_type="ca_certificate" and
    the row id, and are selectable in the audit filter -- which is generated
    from AuditAction, so this is an assertion on the rendered options."""
    _setup_superadmin(client)
    _create_ca(client, cfg, name="rotate")
    # a second active issuer, so retiring "rotate"'s intermediate does not
    # trip AC-5's "the last active intermediate cannot be retired" refusal
    _create_ca(client, cfg, name="spare")

    dbsession = _db(cfg)
    try:
        rows = ca_service.list_cas(dbsession)
        root = next(r for r in rows if r.name == "rotate Root CA")
        intermediate = next(r for r in rows if r.name == "rotate Intermediate CA")
        root_id, intermediate_id = root.id, intermediate.id
    finally:
        dbsession.close()

    renewed = client.post(
        f"/ca/{root_id}/renew",
        data={"years": "25", "csrf_token": _csrf(client, cfg)},
    )
    assert renewed.status_code == 303

    retired = client.post(
        f"/ca/{intermediate_id}/retire",
        data={"csrf_token": _csrf(client, cfg)},
    )
    assert retired.status_code == 303

    renewed_event = _one(cfg, AuditAction.ca_renewed)
    assert renewed_event.target_type == "ca_certificate"
    assert renewed_event.target_id == str(root_id)

    retired_event = _one(cfg, AuditAction.ca_retired)
    assert retired_event.target_type == "ca_certificate"
    assert retired_event.target_id == str(intermediate_id)

    options = client.get("/audit").text
    assert '<option value="ca_renewed"' in options
    assert '<option value="ca_retired"' in options


def test_settings_change_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    # The private-target checkbox is on by default (spec 0011 FR-9), so the
    # form has to submit it to change nothing but the base URL -- an
    # unticked checkbox is not "leave as it was", here or anywhere else.
    unchanged = {
        "allow_private_validation_targets": "on",
        "csrf_token": _csrf(client, cfg),
    }
    resp = client.post(
        "/settings",
        data={"base_url": "https://ca.example.org", **unchanged},
    )
    assert resp.status_code == 303

    # AC-3: the key plus what it was and what it became.
    event = _one(cfg, AuditAction.settings_changed)
    assert event.target_type == "setting"
    assert event.target_id == "base_url"
    assert event.detail == {
        "key": "base_url",
        "old": None,
        "new": "https://ca.example.org",
    }
    assert "base_url" in event.summary

    # Saving the same values again changes nothing, so it records nothing.
    resp = client.post(
        "/settings",
        data={
            "base_url": "https://ca.example.org",
            "allow_private_validation_targets": "on",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    assert len(_events(cfg, AuditAction.settings_changed)) == 1

    # Ticking trust_proxy is a second, separately recorded setting change.
    resp = client.post(
        "/settings",
        data={
            "base_url": "https://ca.example.org",
            "trust_proxy": "on",
            "allow_private_validation_targets": "on",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    changes = _events(cfg, AuditAction.settings_changed)
    assert [event.target_id for event in changes] == ["base_url", "trust_proxy"]
    assert changes[-1].detail == {"key": "trust_proxy", "old": "false", "new": "true"}
    assert "checked" in client.get("/settings").text


# --- FR-4/AC-1/AC-3: issuance, signing, revocation ----------------------------


def test_cert_issued_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg, "nas.lan")

    event = _one(cfg, AuditAction.cert_issued)
    assert event.actor_kind == "user"
    assert event.actor_label == "alice"
    assert event.target_type == "certificate"
    assert event.target_id == str(cert_id)
    assert "nas.lan" in event.summary
    assert event.detail is not None
    # AC-3: serial, profile and key type -- and nothing that could unlock it.
    assert event.detail["profile"] == "server"
    assert event.detail["key_type"] == "ecdsa-p256"
    assert event.detail["serial_hex"]
    assert "PRIVATE KEY" not in (event.detail_json or "")


def test_cert_signed_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    csr = _csr_pem("signed.lan")
    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": csr,
            "profile": "server",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    event = _one(cfg, AuditAction.cert_signed)
    assert event.target_type == "certificate"
    assert "signed.lan" in event.summary
    assert event.detail is not None
    assert event.detail["serial_hex"]
    # FR-3: the CSR itself is not evidence worth keeping, and it is bulky.
    assert "CERTIFICATE REQUEST" not in (event.detail_json or "")
    assert csr[:60] not in (event.detail_json or "")


def test_cert_revoked_recorded_ui_and_api(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    ui_cert = _issue(client, cfg, "ui.lan")
    api_cert = _issue(client, cfg, "api.lan")

    resp = client.post(
        f"/certs/{ui_cert}/revoke",
        data={
            "reason": "key_compromise",
            "confirm": "yes",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    # Revoking again is idempotent -- and must not write a second event.
    resp = client.post(
        f"/certs/{ui_cert}/revoke",
        data={
            "reason": "key_compromise",
            "confirm": "yes",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303

    secret = _api_token(cfg)
    client.cookies.clear()
    for _ in range(2):
        resp = client.post(
            f"/api/v1/certificates/{api_cert}/revoke",
            json={"reason": "superseded"},
            headers=_auth(secret),
        )
        assert resp.status_code == 200

    revocations = _events(cfg, AuditAction.cert_revoked)
    assert len(revocations) == 2
    ui_event, api_event = revocations
    assert (ui_event.actor_kind, ui_event.actor_label) == ("user", "alice")
    assert ui_event.target_id == str(ui_cert)
    assert ui_event.detail is not None
    assert ui_event.detail["reason"] == "key_compromise"
    # FR-4: an API caller is a token, not a user.
    assert (api_event.actor_kind, api_event.actor_label) == ("token", "admin-token")
    assert api_event.actor_id is not None
    assert api_event.target_id == str(api_cert)
    assert api_event.detail is not None
    assert api_event.detail["reason"] == "superseded"


def test_api_issue_and_sign_recorded_as_token_actor(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    secret = _api_token(cfg)
    client.cookies.clear()

    resp = client.post(
        "/api/v1/certificates",
        json={"subject_cn": "robot.lan", "sans": ["robot.lan"]},
        headers=_auth(secret),
    )
    assert resp.status_code == 201
    resp = client.post(
        "/api/v1/certificates/sign",
        json={"csr_pem": _csr_pem("robot-csr.lan")},
        headers=_auth(secret),
    )
    assert resp.status_code == 201

    issued = _one(cfg, AuditAction.cert_issued)
    assert (issued.actor_kind, issued.actor_label) == ("token", "admin-token")
    assert "robot.lan" in issued.summary
    signed = _one(cfg, AuditAction.cert_signed)
    assert (signed.actor_kind, signed.actor_label) == ("token", "admin-token")
    assert "robot-csr.lan" in signed.summary


# --- FR-4/AC-1: API tokens -----------------------------------------------------


def test_token_create_revoke_recorded(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    resp = client.post(
        "/tokens",
        data={
            "label": "ansible",
            "role": "admin",
            "expires_at": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 200

    created = _one(cfg, AuditAction.token_created)
    assert created.actor_label == "alice"
    assert created.target_type == "api_token"
    assert created.detail == {"label": "ansible", "role": "admin", "expires_at": None}
    assert "ansible" in created.summary

    token_id = created.target_id
    assert token_id is not None
    for _ in range(2):
        resp = client.post(f"/tokens/{token_id}/revoke", data={"csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 303
    # Revoking a token twice is idempotent: the second post changes nothing,
    # so it records nothing.
    revoked = _one(cfg, AuditAction.token_revoked)
    assert revoked.target_id == token_id
    assert revoked.detail == {"label": "ansible", "role": "admin"}

    # An unknown token id is silently nothing -- and writes nothing.
    resp = client.post("/tokens/9999/revoke", data={"csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303
    assert len(_events(cfg, AuditAction.token_revoked)) == 1


# --- FR-4: failures are not state changes --------------------------------------


def test_failed_operations_are_not_recorded(client: TestClient, cfg: Config) -> None:
    """Only successful state changes are events -- except login_failed, which
    is the whole point of watching logins."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    before = len(_events(cfg))

    csrf = _csrf(client, cfg)
    # Rejected by validation, by CSRF, and by a state conflict respectively.
    assert (
        client.post("/certs/issue", data={"subject_cn": " ", "csrf_token": csrf}).status_code == 400
    )
    assert (
        client.post("/settings", data={"base_url": "ftp://x", "csrf_token": csrf}).status_code
        == 400
    )
    assert (
        client.post(
            "/users",
            data={
                "username": "eve",
                "password": "short",
                "role": "admin",
                "csrf_token": csrf,
            },
        ).status_code
        == 400
    )
    assert (
        client.post("/tokens", data={"label": " ", "role": "admin", "csrf_token": csrf}).status_code
        == 400
    )
    assert (
        client.post("/certs/issue", data={"subject_cn": "x.lan", "csrf_token": "wrong"}).status_code
        == 403
    )
    # spec 0017 FR-2: CAExistsError is gone -- a second /ca/create now
    # succeeds (and is covered by its own recorded-event test), so it is no
    # longer an example of a failure here. A CA action against an id that
    # does not exist still is one.
    assert client.post("/ca/999999/retire", data={"csrf_token": csrf}).status_code == 404

    assert len(_events(cfg)) == before


# --- AC-3: nothing secret ever reaches a detail blob ---------------------------


def test_no_secrets_in_details(client: TestClient, cfg: Config) -> None:
    """A scan of *every* event a full round of operations produced."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_user(client, cfg, "bob", "admin")
    client.post(
        "/settings",
        data={"base_url": "https://ca.example.org", "csrf_token": _csrf(client, cfg)},
    )
    created = client.post(
        "/tokens",
        data={"label": "scanner", "role": "admin", "csrf_token": _csrf(client, cfg)},
    )
    assert created.status_code == 200
    match = _SECRET_RE.search(created.text)
    assert match is not None
    secret = match.group(0)
    cert_id = _issue(client, cfg, "scan.lan")
    csr = _csr_pem("scan-csr.lan")
    client.post(
        "/certs/sign",
        data={
            "csr_pem": csr,
            "profile": "server",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.post(
        f"/certs/{cert_id}/revoke",
        data={
            "reason": "unspecified",
            "confirm": "yes",
            "csrf_token": _csrf(client, cfg),
        },
    )
    client.cookies.clear()
    client.post("/login", data={"username": "bob", "password": "wrongpassword"})

    rows = _events(cfg)
    assert len(rows) > 8
    blob = "\n".join(f"{row.summary}\n{row.detail_json or ''}" for row in rows)
    for forbidden in (
        "PRIVATE KEY",
        "CERTIFICATE REQUEST",
        "BEGIN CERTIFICATE",
        SUPERADMIN_PASSWORD,
        USER_PASSWORD,
        "wrongpassword",
        secret,
        csr[:60],
    ):
        assert forbidden not in blob, forbidden


# --- FR-6/AC-4/AC-5: the /audit page ------------------------------------------


def _seed(cfg: Config, count: int, *, start: datetime | None = None) -> None:
    db = _db(cfg)
    # Anchored at "now" so the seeded events are unambiguously newer than
    # whatever the fixtures wrote before them.
    moment = start or datetime.now(UTC)
    try:
        for index in range(count):
            audit.record(
                db,
                audit.SYSTEM_ACTOR,
                AuditAction.settings_changed,
                summary=f"seeded event {index:03d}",
                now=moment + timedelta(minutes=index),
            )
    finally:
        db.close()


def test_audit_list_filters(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _issue(client, cfg, "filter.lan")
    _create_user(client, cfg, "bob", "viewer")

    # Every action name is also in the filter dropdown, so a row is
    # identified by the markup only a row has.
    issued, created = "<code>cert_issued</code>", "<code>user_created</code>"

    page = client.get("/audit")
    assert page.status_code == 200
    # Newest first: the user creation happened after the issuance.
    assert page.text.index(created) < page.text.index(issued)

    only_issued = client.get("/audit", params={"action": "cert_issued"}).text
    assert "filter.lan" in only_issued
    assert created not in only_issued

    by_kind = client.get("/audit", params={"actor_kind": "system"}).text
    assert issued not in by_kind

    by_q = client.get("/audit", params={"q": "filter.lan"}).text
    assert "filter.lan" in by_q
    assert created not in by_q

    combined = client.get(
        "/audit", params={"q": "alice", "action": "cert_issued", "actor_kind": "user"}
    ).text
    assert "filter.lan" in combined
    assert created not in combined

    # An unknown filter value is a typo, not an error (like the inventory).
    unknown = client.get("/audit", params={"action": "nonsense", "actor_kind": "nonsense"})
    assert unknown.status_code == 200
    assert issued in unknown.text


def test_audit_pagination(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    seeded = audit.PER_PAGE + 3
    _seed(cfg, seeded)

    def label(index: int) -> str:
        return f"seeded event {index:03d}"

    first = client.get("/audit")
    assert first.status_code == 200
    # Newest first, so the last one seeded heads page 1 and the ones that no
    # longer fit have fallen onto page 2.
    assert label(seeded - 1) in first.text
    assert label(seeded - audit.PER_PAGE - 1) not in first.text
    assert 'href="/audit?' in first.text

    second = client.get("/audit", params={"page": 2})
    assert second.status_code == 200
    assert label(seeded - audit.PER_PAGE - 1) in second.text
    assert "page 2 of" in second.text

    # Out of range is an empty page, never an error (AC-4) -- and the page
    # does not claim to be showing a page that does not exist.
    for page in (0, -3, 99, 10**9):
        resp = client.get("/audit", params={"page": page})
        assert resp.status_code == 200
        assert f"page {page} of" not in resp.text


def test_audit_cert_link(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg, "linked.lan")

    page = client.get("/audit")
    assert f'href="/certs/{cert_id}"' in page.text
    assert client.get(f"/certs/{cert_id}").status_code == 200

    # AC-5: an event whose target is gone still renders, and the link is a
    # plain 404 rather than a broken page.
    db = _db(cfg)
    try:
        audit.record(
            db,
            audit.SYSTEM_ACTOR,
            AuditAction.cert_revoked,
            summary="revoked a certificate that no longer exists",
            target_type="certificate",
            target_id=999_999,
        )
    finally:
        db.close()
    page = client.get("/audit")
    assert page.status_code == 200
    assert 'href="/certs/999999"' in page.text
    assert client.get("/certs/999999").status_code == 404


def test_audit_open_to_every_authenticated_role(client: TestClient, cfg: Config) -> None:
    """FR-6: entries are metadata, not secrets, so every logged-in user may
    read them -- and the nav says so."""
    _setup_superadmin(client)
    _create_user(client, cfg, "vera", "viewer")

    assert 'href="/audit"' in client.get("/").text
    _login(client, "vera")
    assert 'href="/audit"' in client.get("/").text
    assert client.get("/audit").status_code == 200

    client.cookies.clear()
    anonymous = client.get("/audit")
    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/login"


# --- FR-5/AC-6: the client IP ---------------------------------------------------


def test_forwarded_for_respects_trust_proxy(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    forwarded = {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}

    client.cookies.clear()
    assert (
        client.post(
            "/login",
            data={"username": "alice", "password": "wrongpassword"},
            headers=forwarded,
        ).status_code
        == 401
    )
    # Off by default: a header anyone can set is not evidence of anything.
    assert _events(cfg, AuditAction.login_failed)[-1].ip == "testclient"

    _login(client, "alice", SUPERADMIN_PASSWORD)
    resp = client.post(
        "/settings",
        data={"base_url": "", "trust_proxy": "on", "csrf_token": _csrf(client, cfg)},
    )
    assert resp.status_code == 303

    client.cookies.clear()
    assert (
        client.post(
            "/login",
            data={"username": "alice", "password": "wrongpassword"},
            headers=forwarded,
        ).status_code
        == 401
    )
    # On: the first entry, which is the client the nearest proxy saw.
    assert _events(cfg, AuditAction.login_failed)[-1].ip == "203.0.113.9"


# --- FR-7/AC-7: GET /api/v1/audit ----------------------------------------------


def test_api_audit_list(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _issue(client, cfg, "api-audit.lan")
    viewer_secret = _api_token(cfg, Role.viewer)
    client.cookies.clear()

    resp = client.get("/api/v1/audit", headers=_auth(viewer_secret))
    assert resp.status_code == 200
    body = resp.json()
    assert body["page"] == 1
    assert body["per_page"] == audit.PER_PAGE
    assert body["total"] == len(_events(cfg))
    assert body["pages"] == 1
    # Newest first, same order as the UI.
    assert body["items"][0]["action"] == "cert_issued"
    first = body["items"][0]
    assert first["actor_kind"] == "user"
    assert first["actor_label"] == "alice"
    assert first["target_type"] == "certificate"
    assert first["detail"]["profile"] == "server"
    assert datetime.fromisoformat(first["occurred_at"]).tzinfo is not None

    filtered = client.get(
        "/api/v1/audit",
        params={"action": "cert_issued", "actor_kind": "user", "q": "api-audit.lan"},
        headers=_auth(viewer_secret),
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1

    # Unknown filter values are a 422 here (a script must be told), and an
    # out-of-range page is an empty list rather than an error.
    assert (
        client.get(
            "/api/v1/audit", params={"action": "nonsense"}, headers=_auth(viewer_secret)
        ).status_code
        == 422
    )
    empty = client.get("/api/v1/audit", params={"page": 5}, headers=_auth(viewer_secret))
    assert empty.status_code == 200
    assert empty.json()["items"] == []


def test_api_audit_requires_token(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    # A browser session is not an API credential: the cookie jar is still
    # full, and the answer is still 401.
    assert client.get("/api/v1/audit").status_code == 401
    assert client.get("/api/v1/audit", headers=_auth("cabin_nonsense")).status_code == 401
