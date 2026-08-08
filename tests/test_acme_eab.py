"""Spec 0012 FR-4, AC-6: external account binding -- the operator hands out
a key id and an HMAC key, and only a client that holds both may register."""

import base64
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from acme_client import Acme, external_account_binding, rsa_key
from acme_orders import BASE, assert_problem, db_session
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import func, select

from cabin.acme import eab
from cabin.acme.api_account import _spend_binding
from cabin.acme.eab import AcmeEabKey
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.models import AcmeAccount
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.settings import ACME_ENABLED, ACME_REQUIRE_EAB, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        db = create_session_factory(cfg.db_url)()
        try:
            set_setting(db, BASE_URL, BASE)
            set_setting(db, ACME_ENABLED, TRUE)
            set_setting(db, ACME_REQUIRE_EAB, TRUE)
        finally:
            db.close()
        yield c


@pytest.fixture
def issuer_id(client: TestClient, cfg: Config) -> int:
    db = create_session_factory(cfg.db_url)()
    try:
        hierarchy = ca_service.create_hierarchy(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin test"
        )
        return hierarchy.intermediate.id
    finally:
        db.close()


@pytest.fixture
def acme(client: TestClient, issuer_id: int) -> Acme:
    return Acme(client, issuer_id=issuer_id)


def new_eab_key(cfg: Config, issuer_id: int, label: str = "nas.lan") -> tuple[str, bytes]:
    """One operator-issued credential: its key id and the HMAC key bytes the
    client is given (base64url on screen, raw here)."""
    db = db_session(cfg)
    try:
        row, secret = eab.create_key(
            db,
            SecretStore.open(cfg.data_dir, cfg.master_passphrase),
            label=label,
            ca_certificate_id=issuer_id,
        )
        return row.id, base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    finally:
        db.close()


def register(
    acme: Acme, key_id: str, mac_key: bytes, *, account: Any = None, **overrides: Any
) -> tuple[Any, Response]:
    account = account or rsa_key()
    fields: dict[str, Any] = {
        "kid": key_id,
        "mac_key": mac_key,
        "url": acme.url(acme.new_account_path),
        "jwk": account.jwk,
        **overrides,
    }
    binding = external_account_binding(**fields)
    payload = {"termsOfServiceAgreed": True, "externalAccountBinding": binding}
    return account, acme.post(acme.new_account_path, account, payload)


def eab_row(cfg: Config, key_id: str) -> AcmeEabKey:
    db = db_session(cfg)
    try:
        row = db.get(AcmeEabKey, key_id)
        assert row is not None
        return row
    finally:
        db.close()


def account_count(cfg: Config) -> int:
    db = db_session(cfg)
    try:
        return db.scalar(select(func.count()).select_from(AcmeAccount)) or 0
    finally:
        db.close()


def test_eab_required_rejects_plain_registration(acme: Acme, cfg: Config) -> None:
    """AC-6: with the requirement on, a registration without a binding is
    refused with the problem type that tells the client what is missing --
    and the directory says so up front, so a client need not guess."""
    assert acme.directory()["meta"]["externalAccountRequired"] is True

    refused = acme.post(acme.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})

    assert_problem(refused, "externalAccountRequired", 403)
    assert account_count(cfg) == 0


def test_eab_valid_binds_key(acme: Acme, cfg: Config) -> None:
    """AC-6: a correct binding registers the account and marks the key used."""
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)

    account, registered = register(acme, key_id, mac_key)

    assert registered.status_code == 201, registered.text
    account_id = registered.headers["location"].rsplit("/", 1)[1]
    row = eab_row(cfg, key_id)
    assert row.bound_account_id == account_id
    assert row.bound_at is not None
    # ...and the account keeps working without presenting the binding again
    again = acme.post(acme.new_account_path, account, {"termsOfServiceAgreed": True})
    assert again.status_code == 200, again.text

    # ...and re-registering is not a second account, so not a second event
    db = db_session(cfg)
    try:
        actions = [
            event.action for event in db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
        ]
    finally:
        db.close()
    assert actions == [AuditAction.acme_account_created]


def test_eab_key_single_use(acme: Acme, cfg: Config) -> None:
    """AC-6: a key that has bound an account cannot bind a second one -- the
    operator handed out one credential, not a reusable one."""
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)
    _, first = register(acme, key_id, mac_key)
    assert first.status_code == 201, first.text
    bound_to = eab_row(cfg, key_id).bound_account_id

    _, second = register(acme, key_id, mac_key)

    assert_problem(second, "unauthorized", 403)
    assert eab_row(cfg, key_id).bound_account_id == bound_to
    # the second registration left nothing behind
    assert account_count(cfg) == 1


def test_a_second_key_for_one_account_is_refused_rather_than_crashing(
    acme: Acme, cfg: Config
) -> None:
    """ "One key, one account" has a second half the route never handled: the
    unique index on ``bound_account_id``. Two registrations that share an
    account key but present *different* EAB keys both end up at the one
    account, and the later UPDATE hits that index -- which must become the
    refusal this code already intends, not a 500 the client cannot read.

    Driven at the binding itself: over HTTP a re-registration is answered
    from the existing account long before the binding is looked at, so the
    losing half of the race cannot be timed from outside.
    """
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)
    _, registered = register(acme, key_id, mac_key)
    assert registered.status_code == 201, registered.text

    db = db_session(cfg)
    try:
        account = db.scalars(select(AcmeAccount)).one()
        account_id = account.id
        second, _secret = eab.create_key(
            db,
            SecretStore.open(cfg.data_dir, cfg.master_passphrase),
            label="second",
            ca_certificate_id=account.issuer_id,
        )
        second_id = second.id
        with pytest.raises(AcmeError) as refused:
            _spend_binding(db, second, account, created=False)
    finally:
        db.close()

    assert refused.value.kind is ErrorType.unauthorized
    # the account keeps the key it was registered with, and nothing else
    assert eab_row(cfg, key_id).bound_account_id == account_id
    assert eab_row(cfg, second_id).bound_account_id is None
    assert account_count(cfg) == 1


def test_eab_revoked_key_rejected(acme: Acme, cfg: Config) -> None:
    """AC-6: revoking a key in the UI takes it out of service immediately."""
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)
    db = db_session(cfg)
    try:
        eab.revoke_key(db, eab.get_key(db, key_id))
    finally:
        db.close()

    _, refused = register(acme, key_id, mac_key)

    assert_problem(refused, "unauthorized", 403)
    assert account_count(cfg) == 0


def test_eab_tampered_signature_rejected(acme: Acme, cfg: Config) -> None:
    """AC-6: every part of the binding is checked -- the MAC, the key id, the
    URL it was made for, the algorithm, and that it really carries *this*
    account's key."""
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)

    _, wrong_mac = register(acme, key_id, b"not the hmac key at all")
    assert_problem(wrong_mac, "unauthorized", 403)

    _, unknown_kid = register(acme, "no-such-key-id", mac_key)
    assert_problem(unknown_kid, "unauthorized", 403)

    _, wrong_url = register(acme, key_id, mac_key, url=f"{BASE}/acme/new-order")
    assert_problem(wrong_url, "malformed", 400)

    _, wrong_alg = register(acme, key_id, mac_key, alg="HS512")
    assert_problem(wrong_alg, "badSignatureAlgorithm", 400)

    # a binding that carries somebody else's key is not a binding for this one
    _, wrong_jwk = register(acme, key_id, mac_key, jwk=rsa_key().jwk)
    assert_problem(wrong_jwk, "unauthorized", 403)

    # a flipped signature byte
    account = rsa_key()
    binding = external_account_binding(
        kid=key_id, mac_key=mac_key, url=acme.url(acme.new_account_path), jwk=account.jwk
    )
    # Flipped in the decoded MAC, not in its base64url: the last character of
    # a 43-character encoding carries padding bits, so changing *it* can
    # decode to the very same 32 bytes.
    mac = bytearray(base64.urlsafe_b64decode(binding["signature"] + "="))
    mac[0] ^= 0x01
    binding["signature"] = base64.urlsafe_b64encode(bytes(mac)).rstrip(b"=").decode("ascii")
    flipped = acme.post(
        acme.new_account_path,
        account,
        {"termsOfServiceAgreed": True, "externalAccountBinding": binding},
    )
    assert_problem(flipped, "unauthorized", 403)

    assert account_count(cfg) == 0
    assert eab_row(cfg, key_id).bound_account_id is None


def test_eab_outer_jws_still_refuses_hmac(acme: Acme, cfg: Config) -> None:
    """The binding is the *only* place an HMAC is accepted: the outer JWS
    allowlist must not have been widened to let one in."""
    key_id, mac_key = new_eab_key(cfg, acme.issuer_id)
    account = rsa_key()
    binding = external_account_binding(
        kid=key_id, mac_key=mac_key, url=acme.url(acme.new_account_path), jwk=account.jwk
    )
    refused = acme.post(
        acme.new_account_path,
        account,
        {"termsOfServiceAgreed": True, "externalAccountBinding": binding},
        alg="HS256",
    )
    assert_problem(refused, "badSignatureAlgorithm", 400)


def test_eab_is_optional_until_it_is_required(acme: Acme, cfg: Config) -> None:
    """FR-4: the requirement is a setting. With it off, registration works
    as before -- and the directory says so."""
    db = db_session(cfg)
    try:
        set_setting(db, ACME_REQUIRE_EAB, "false")
    finally:
        db.close()

    assert acme.directory()["meta"]["externalAccountRequired"] is False
    plain = acme.post(acme.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert plain.status_code == 201, plain.text

    # ...but a binding that *is* presented is still verified
    key_id, _ = new_eab_key(cfg, acme.issuer_id)
    _, refused = register(acme, key_id, b"wrong key")
    assert_problem(refused, "unauthorized", 403)
