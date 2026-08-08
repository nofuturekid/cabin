"""Spec 0010: the ACME HTTP surface -- directory, nonces, accounts, orders,
authorizations and challenges (FR-4..FR-7, AC-1, AC-3..AC-6, AC-8)."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import ca_fixtures
import pytest
from acme_client import Acme, ec_key, flattened, rsa_key
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cabin.acme.models import AcmeAccount, AcmeAuthorization, AcmeNonce, AcmeOrder
from cabin.acme.service import AUTHZ_LIFETIME, ORDER_LIFETIME
from cabin.app import create_app
from cabin.audit import AuditEvent
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, FALSE, TRUE, get_flag, set_setting
from cabin.store import create_session_factory

ERROR_PREFIX = "urn:ietf:params:acme:error:"
#: Cabin's configured public address in these tests -- the same host
#: TestClient posts to, so published and requested URLs match.
BASE = "http://testserver"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def raw_client(cfg: Config) -> Iterator[TestClient]:
    """The app with ACME still switched off (FR-5's default)."""
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


@pytest.fixture
def client(raw_client: TestClient, cfg: Config) -> TestClient:
    # FR-5: ACME stays off until it knows the address clients were handed.
    _setting(cfg, BASE_URL, BASE)
    _setting(cfg, ACME_ENABLED, TRUE)
    return raw_client


@pytest.fixture
def issuer_id(client: TestClient, cfg: Config) -> int:
    """A real, active intermediate -- spec 0019 FR-4/FR-5 resolve the
    per-issuer directory and new-account paths against an existing row, so
    ``acme`` needs one to build a working URL at all. Tests that used to
    call ``create_ca`` for order placement no longer have to: this fixture
    already made the one hierarchy they need, and calling ``create_ca``
    again would leave the instance with two active issuers, which is a
    different (and, for most of these tests, irrelevant) scenario."""
    return create_ca(cfg)


@pytest.fixture
def acme(client: TestClient, issuer_id: int) -> Acme:
    return Acme(client, issuer_id=issuer_id)


def db_session(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _setting(cfg: Config, key: str, value: str) -> None:
    db = db_session(cfg)
    try:
        set_setting(db, key, value)
    finally:
        db.close()


def create_ca(cfg: Config) -> int:
    """A fresh hierarchy; returns the intermediate's id."""
    db = db_session(cfg)
    try:
        hierarchy = ca_service.create_hierarchy(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin test"
        )
        return hierarchy.intermediate.id
    finally:
        db.close()


def _setup_admin(client: TestClient, cfg: Config) -> str:
    """First-run setup, returning the session's CSRF token."""
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    db = db_session(cfg)
    try:
        session = get_session(db, client.cookies["cabin_session"])
        assert session is not None
        return session.csrf_token
    finally:
        db.close()


def problem(resp: Response) -> dict[str, Any]:
    body: dict[str, Any] = resp.json()
    return body


def assert_problem(resp: Response, kind: str, status: int) -> None:
    __tracebackhide__ = True
    assert resp.status_code == status, resp.text
    assert problem(resp)["type"] == f"{ERROR_PREFIX}{kind}", resp.text


def register(acme: Acme, key: Any = None, **payload: Any) -> tuple[Any, str]:
    """A fresh account; returns (key, kid)."""
    key = key or rsa_key()
    body: dict[str, Any] = {"termsOfServiceAgreed": True, **payload}
    resp = acme.post(acme.new_account_path, key, body)
    assert resp.status_code == 201, resp.text
    return key, resp.headers["location"]


def place_order(acme: Acme, key: Any, kid: str, *values: str) -> Response:
    identifiers = [{"type": "dns", "value": value} for value in values]
    return acme.post("/acme/new-order", key, {"identifiers": identifiers}, kid=kid)


def path_of(url: str) -> str:
    return url.removeprefix("http://testserver")


def read(acme: Acme, key: Any, kid: str, url: str) -> Response:
    """POST-as-GET: an empty payload, not an empty object."""
    return acme.post(path_of(url), key, None, kid=kid)


# --- FR-4, AC-1: directory and nonces ------------------------------------------------


def test_directory_fields(client: TestClient, issuer_id: int) -> None:
    resp = client.get(f"/acme/ca/{issuer_id}/directory")

    assert resp.status_code == 200
    body = resp.json()
    assert body["newNonce"] == "http://testserver/acme/new-nonce"
    assert body["newAccount"] == f"http://testserver/acme/ca/{issuer_id}/new-account"
    assert body["newOrder"] == "http://testserver/acme/new-order"
    assert body["revokeCert"] == "http://testserver/acme/revoke-cert"
    assert body["keyChange"] == "http://testserver/acme/key-change"
    assert body["meta"]["externalAccountRequired"] is False
    assert "caaIdentities" not in body["meta"]
    # the directory is a GET nobody follows with a POST of the same nonce, so
    # it does not mint one -- see the nonce-economy test below
    assert "replay-nonce" not in resp.headers
    # FR-11: a per-issuer path carries an index link to its own directory.
    assert resp.headers["link"] == f'<http://testserver/acme/ca/{issuer_id}/directory>;rel="index"'


def test_directory_prefers_the_configured_base_url(
    client: TestClient, issuer_id: int, cfg: Config
) -> None:
    """FR-4/FR-5: behind a reverse proxy the request's own host is whatever
    the proxy passed on -- the configured base URL is what clients were told
    to use, and every URL cabin hands out has to agree with it."""
    _setting(cfg, BASE_URL, "https://ca.example.org")

    body = client.get(f"/acme/ca/{issuer_id}/directory").json()

    assert body["newAccount"] == f"https://ca.example.org/acme/ca/{issuer_id}/new-account"
    assert body["meta"]["website"] == "https://ca.example.org"


def test_new_nonce_headers(client: TestClient) -> None:
    """FR-4/AC-1: HEAD answers 200, GET answers 204, both with a nonce that
    no cache may keep."""
    head = client.head("/acme/new-nonce")
    assert head.status_code == 200
    assert head.headers["replay-nonce"]
    assert head.headers["cache-control"] == "no-store"
    # FR-11: new-nonce carries no issuer, so it carries no index link either.
    assert "link" not in head.headers

    get = client.get("/acme/new-nonce")
    assert get.status_code == 204
    assert get.headers["replay-nonce"] != head.headers["replay-nonce"]
    assert get.content == b""


# --- FR-4, AC-3: accounts ------------------------------------------------------------


def test_new_account_creates_and_is_idempotent(acme: Acme, cfg: Config) -> None:
    key = rsa_key()

    created = acme.post(
        acme.new_account_path,
        key,
        {"termsOfServiceAgreed": True, "contact": ["mailto:ops@example.org"]},
    )

    assert created.status_code == 201, created.text
    kid = created.headers["location"]
    assert kid.startswith("http://testserver/acme/account/")
    body = created.json()
    assert body["status"] == "valid"
    assert body["contact"] == ["mailto:ops@example.org"]
    assert body["orders"] == f"{kid}/orders"

    # AC-3: the same key again is the same account, answered with 200
    again = acme.post(acme.new_account_path, key, {"termsOfServiceAgreed": True})
    assert again.status_code == 200, again.text
    assert again.headers["location"] == kid

    # a different key is a different account
    other = acme.post(acme.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert other.status_code == 201
    assert other.headers["location"] != kid

    db = db_session(cfg)
    try:
        rows = db.scalars(select(AcmeAccount)).all()
        assert len(rows) == 2
        assert rows[0].tos_agreed_at is not None
        # the stored key is the public JWK only -- no private parameter of a
        # key a client mistakenly sent may ever land in the database
        assert set(json.loads(rows[0].jwk_json)) == {"kty", "n", "e"}
        # ...and the thumbprint is what identifies the account, not the URL
        # it happens to live at
        assert len({row.jwk_thumbprint for row in rows}) == 2
    finally:
        db.close()


def test_only_return_existing(acme: Acme) -> None:
    """AC-3: onlyReturnExisting never creates -- an unknown key is
    accountDoesNotExist 400."""
    unknown = acme.post(acme.new_account_path, rsa_key(), {"onlyReturnExisting": True})
    assert_problem(unknown, "accountDoesNotExist", 400)

    key, kid = register(acme)
    found = acme.post(acme.new_account_path, key, {"onlyReturnExisting": True})
    assert found.status_code == 200
    assert found.headers["location"] == kid


def test_account_update_contacts_and_deactivate(acme: Acme, cfg: Config) -> None:
    key, kid = register(acme, contact=["mailto:first@example.org"])

    updated = acme.post(path_of(kid), key, {"contact": ["mailto:second@example.org"]}, kid=kid)
    assert updated.status_code == 200, updated.text
    assert updated.json()["contact"] == ["mailto:second@example.org"]
    assert read(acme, key, kid, kid).json()["contact"] == ["mailto:second@example.org"]

    # a contact that is not a URL is refused rather than stored as garbage
    bad = acme.post(path_of(kid), key, {"contact": ["ops@example.org"]}, kid=kid)
    assert bad.status_code == 400
    assert read(acme, key, kid, kid).json()["contact"] == ["mailto:second@example.org"]

    deactivated = acme.post(path_of(kid), key, {"status": "deactivated"}, kid=kid)
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["status"] == "deactivated"

    # AC-3/RFC 8555 7.3.6: a deactivated account can do nothing further
    assert_problem(read(acme, key, kid, kid), "unauthorized", 403)
    assert_problem(place_order(acme, key, kid, "nas.lan"), "unauthorized", 403)
    assert_problem(
        acme.post(acme.new_account_path, key, {"onlyReturnExisting": True}),
        "unauthorized",
        403,
    )


def test_key_change(acme: Acme) -> None:
    """FR-4: implemented rather than stubbed -- the inner JWS proves the new
    key wants this account, the outer one proves the account wants the new
    key."""
    from acme_client import flattened

    key, kid = register(acme)
    new_key = ec_key("ES256")
    url = acme.url("/acme/key-change")

    def inner(signer: Any, jwk: dict[str, Any], payload: dict[str, Any]) -> dict[str, str]:
        return flattened(signer, {"alg": signer.alg, "url": url, "jwk": jwk}, payload)

    # the inner JWS announces the new key but is signed by the old one: it
    # proves nothing about who holds the key being rolled to
    wrong_signer = inner(key, new_key.jwk, {"account": kid, "oldKey": key.jwk})
    assert acme.post("/acme/key-change", key, wrong_signer, kid=kid).status_code == 400

    # ...and the roll has to quote the key it is replacing
    wrong_old = inner(new_key, new_key.jwk, {"account": kid, "oldKey": ec_key("ES256").jwk})
    assert acme.post("/acme/key-change", key, wrong_old, kid=kid).status_code == 400

    # RFC 8555 7.3.5 step 9: no two accounts may share a key -- which also
    # rules out rolling to the key this account already has
    to_itself = inner(key, key.jwk, {"account": kid, "oldKey": key.jwk})
    conflict = acme.post("/acme/key-change", key, to_itself, kid=kid)
    assert conflict.status_code == 409, conflict.text
    assert conflict.headers["location"] == kid

    ok = acme.post(
        "/acme/key-change",
        key,
        inner(new_key, new_key.jwk, {"account": kid, "oldKey": key.jwk}),
        kid=kid,
    )
    assert ok.status_code == 200, ok.text

    # the old key no longer speaks for the account, the new one does
    assert read(acme, key, kid, kid).status_code in (400, 403)
    assert read(acme, new_key, kid, kid).json()["status"] == "valid"
    # ...and the new key now finds the same account
    same = acme.post(acme.new_account_path, new_key, {"onlyReturnExisting": True})
    assert same.status_code == 200
    assert same.headers["location"] == kid


# --- FR-4/FR-7, AC-4, AC-8: orders, authorizations, challenges ------------------------


def test_new_order_creates_authz_and_challenges(acme: Acme, cfg: Config) -> None:
    key, kid = register(acme)

    resp = place_order(acme, key, kid, "nas.lan")

    assert resp.status_code == 201, resp.text
    order = resp.json()
    assert resp.headers["location"].startswith("http://testserver/acme/order/")
    assert order["status"] == "pending"
    assert order["identifiers"] == [{"type": "dns", "value": "nas.lan"}]
    assert order["finalize"] == f"{resp.headers['location']}/finalize"
    expires = datetime.fromisoformat(order["expires"])
    assert datetime.now(UTC) < expires <= datetime.now(UTC) + ORDER_LIFETIME

    assert len(order["authorizations"]) == 1
    authz = read(acme, key, kid, order["authorizations"][0]).json()
    assert authz["status"] == "pending"
    assert authz["identifier"] == {"type": "dns", "value": "nas.lan"}
    assert "wildcard" not in authz
    assert (
        datetime.now(UTC)
        < datetime.fromisoformat(authz["expires"])
        <= (datetime.now(UTC) + AUTHZ_LIFETIME)
    )

    # AC-4: three challenge types, three distinct tokens, three distinct URLs
    types = {challenge["type"] for challenge in authz["challenges"]}
    assert types == {"http-01", "dns-01", "tls-alpn-01"}
    tokens = {challenge["token"] for challenge in authz["challenges"]}
    assert len(tokens) == 3
    assert all(len(token) >= 22 for token in tokens)
    assert len({challenge["url"] for challenge in authz["challenges"]}) == 3
    assert all(challenge["status"] == "pending" for challenge in authz["challenges"])


def test_new_order_accepts_ip_and_multiple_identifiers(acme: Acme, cfg: Config) -> None:
    key, kid = register(acme)

    resp = acme.post(
        "/acme/new-order",
        key,
        {
            "identifiers": [
                {"type": "dns", "value": "nas.lan"},
                {"type": "ip", "value": "192.0.2.10"},
                {"type": "dns", "value": "nas.lan"},
            ]
        },
        kid=kid,
    )

    assert resp.status_code == 201, resp.text
    order = resp.json()
    # a repeated identifier is one authorization, not two
    assert order["identifiers"] == [
        {"type": "dns", "value": "nas.lan"},
        {"type": "ip", "value": "192.0.2.10"},
    ]
    assert len(order["authorizations"]) == 2


def test_wildcard_order_dns01_only(acme: Acme, cfg: Config) -> None:
    """AC-4: RFC 8555 8.4 -- only dns-01 can prove control of a wildcard, and
    the authorization names the base domain with wildcard: true."""
    key, kid = register(acme)

    resp = place_order(acme, key, kid, "*.nas.lan")

    assert resp.status_code == 201, resp.text
    order = resp.json()
    assert order["identifiers"] == [{"type": "dns", "value": "*.nas.lan"}]
    authz = read(acme, key, kid, order["authorizations"][0]).json()
    assert authz["wildcard"] is True
    assert authz["identifier"] == {"type": "dns", "value": "nas.lan"}
    assert [challenge["type"] for challenge in authz["challenges"]] == ["dns-01"]


def test_identifier_policy_rejections(acme: Acme, cfg: Config) -> None:
    """AC-8/FR-7: the SAN policy from spec 0005 decides what a DNS identifier
    may be -- and every rejection is an ACME problem, never a 500."""
    key, kid = register(acme)

    for value in (
        "http://x",
        "nas.lan/../",
        "nas.lan/",
        "",
        " ",
        "nas .lan",
        "-nas.lan",
        "nas..lan",
        "*.*.nas.lan",
        "nas.*.lan",
        "*",
        "xn--" + "a" * 300,
        "nas.lan:8443",
        "ünicode.lan",
        "192.0.2.1",  # an IP has to be announced as one
    ):
        resp = place_order(acme, key, kid, value)
        assert resp.status_code == 400, f"{value!r} -> {resp.status_code} {resp.text}"
        assert problem(resp)["type"] == f"{ERROR_PREFIX}rejectedIdentifier", value

    for identifier in (
        {"type": "email", "value": "ops@example.org"},
        {"type": "dns-account-01", "value": "nas.lan"},
        {"type": "", "value": "nas.lan"},
    ):
        resp = acme.post("/acme/new-order", key, {"identifiers": [identifier]}, kid=kid)
        assert_problem(resp, "unsupportedIdentifier", 400)

    ip_resp = acme.post(
        "/acme/new-order",
        key,
        {"identifiers": [{"type": "ip", "value": "not-an-ip"}]},
        kid=kid,
    )
    assert_problem(ip_resp, "rejectedIdentifier", 400)
    # a wildcard IP is meaningless
    wild_ip = acme.post(
        "/acme/new-order",
        key,
        {"identifiers": [{"type": "ip", "value": "*.192.0.2.1"}]},
        kid=kid,
    )
    assert_problem(wild_ip, "rejectedIdentifier", 400)

    for payload in (
        {},
        {"identifiers": []},
        {"identifiers": "nas.lan"},
        {"identifiers": [{"value": "nas.lan"}]},
        {"identifiers": ["nas.lan"]},
        {"identifiers": [{"type": "dns", "value": 7}]},
        {"identifiers": [{"type": "dns", "value": "nas.lan"}], "notAfter": "whenever"},
        {
            "identifiers": [{"type": "dns", "value": "nas.lan"}],
            "notBefore": "2026-08-01",
        },
        # parses fine, then lands past datetime.max on the way to UTC
        {
            "identifiers": [{"type": "dns", "value": "nas.lan"}],
            "notAfter": "9999-12-31T23:59:59-14:00",
        },
        {
            "identifiers": [{"type": "dns", "value": "nas.lan"}],
            "notBefore": "0001-01-01T00:00:00+14:00",
        },
        {"identifiers": [{"type": "dns", "value": "nas.lan"} for _ in range(200)]},
    ):
        resp = acme.post("/acme/new-order", key, payload, kid=kid)
        assert resp.status_code == 400, f"{payload} -> {resp.status_code} {resp.text}"
        assert str(problem(resp)["type"]).startswith(ERROR_PREFIX)


def test_new_order_without_a_ca_says_so(client: TestClient, cfg: Config) -> None:
    """FR-5: a new registration at a retired issuer's directory is refused
    outright, so a client learns this issuer cannot sign anything before it
    ever reaches new-order. The pre-0019 version of this test registered
    against a directory with no CA behind it at all -- impossible now that
    FR-4/FR-5 resolve the directory and new-account paths against a real
    row, so a retired one is the nearest surviving shape of "cannot issue"."""
    db = db_session(cfg)
    try:
        retired_id = ca_fixtures.retired_issuer(db)
    finally:
        db.close()
    acme = Acme(client, issuer_id=retired_id)

    resp = acme.post(acme.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})

    assert_problem(resp, "unauthorized", 403)


def test_orders_belong_to_one_account(acme: Acme, cfg: Config) -> None:
    """A resource URL is not a capability: another account may not read it."""
    key, kid = register(acme)
    order = place_order(acme, key, kid, "nas.lan").json()
    order_url = place_order(acme, key, kid, "other.lan").headers["location"]

    intruder, intruder_kid = register(acme)

    for url in (order_url, order["authorizations"][0]):
        assert_problem(read(acme, intruder, intruder_kid, url), "unauthorized", 403)
    authz = read(acme, key, kid, order["authorizations"][0]).json()
    challenge_url = authz["challenges"][0]["url"]
    assert_problem(read(acme, intruder, intruder_kid, challenge_url), "unauthorized", 403)


# --- AC-5: POST-as-GET --------------------------------------------------------------


def test_post_as_get_all_resources(acme: Acme, cfg: Config) -> None:
    key, kid = register(acme)
    created = place_order(acme, key, kid, "nas.lan")
    order_url = created.headers["location"]
    authz_url = created.json()["authorizations"][0]
    challenge_url = read(acme, key, kid, authz_url).json()["challenges"][0]["url"]

    for url in (kid, order_url, authz_url, challenge_url, f"{kid}/orders"):
        resp = read(acme, key, kid, url)
        assert resp.status_code == 200, f"{url} -> {resp.text}"
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.headers["replay-nonce"]

    assert read(acme, key, kid, f"{kid}/orders").json()["orders"] == [order_url]

    # An empty JSON *object* is a different thing from an empty payload: on a
    # challenge it is spec 0011's trigger, which starts a validation. That
    # difference is tested in test_acme_challenges_api.py, where there is a
    # server for the validator to talk to.

    unknown = acme.post("/acme/order/nope", key, None, kid=kid)
    assert unknown.status_code == 404
    assert str(problem(unknown)["type"]).startswith(ERROR_PREFIX)


def test_get_method_not_allowed(client: TestClient, issuer_id: int) -> None:
    """AC-5: these resources are read with POST-as-GET; a plain GET is 405,
    not a leak and not a 404."""
    for path in (
        f"/acme/ca/{issuer_id}/new-account",
        "/acme/new-order",
        "/acme/key-change",
        "/acme/revoke-cert",
        "/acme/account/whatever",
        "/acme/account/whatever/orders",
        "/acme/order/whatever",
        "/acme/order/whatever/finalize",
        "/acme/authz/whatever",
        "/acme/chal/whatever",
    ):
        resp = client.get(path)
        assert resp.status_code == 405, f"{path} -> {resp.status_code}"
        # RFC 7231 6.5.5: a 405 has to say what would have worked
        assert resp.headers["allow"] == "POST", path
        # ...and it does not mint a nonce: nothing here is going to use one
        assert "replay-nonce" not in resp.headers, path


def test_requires_the_jose_content_type(acme: Acme) -> None:
    """RFC 8555 6.2: an ACME POST carries a JWS, so it must announce one --
    anything else is 415. Not pedantry: a request cabin will read as a signed
    document must not be one a browser form or a fetch() with default headers
    could have produced, or a cross-origin page could speak ACME on a
    visitor's behalf.
    """
    key = rsa_key()

    def body() -> dict[str, str]:
        return flattened(
            key,
            {
                "alg": key.alg,
                "nonce": acme.nonce(),
                "url": acme.url(acme.new_account_path),
                "jwk": key.jwk,
            },
            {"termsOfServiceAgreed": True},
        )

    for content_type in (
        "text/plain",
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "",
        None,
    ):
        resp = acme.post_body(acme.new_account_path, body(), content_type=content_type)
        assert resp.status_code == 415, f"{content_type!r} -> {resp.status_code}"
        assert str(problem(resp)["type"]).startswith(ERROR_PREFIX)
        # a client that gets this far still needs a nonce to try again
        assert resp.headers["replay-nonce"]

    # parameters are part of the media type's syntax, not of its identity
    for content_type in (
        "application/jose+json",
        "application/jose+json; charset=utf-8",
    ):
        resp = acme.post_body(acme.new_account_path, body(), content_type=content_type)
        assert resp.status_code in (200, 201), f"{content_type!r} -> {resp.text}"


def test_nonces_are_only_issued_where_the_protocol_needs_them(
    acme: Acme, client: TestClient, cfg: Config
) -> None:
    """A nonce is a stored row with a 24h life, so minting one per response
    would let an unauthenticated GET loop grow the table without bound.

    RFC 8555 needs one on the nonce endpoint and on the answer to every POST
    (that is what the next POST spends). Nothing else, including the
    directory, has a client waiting to use one.
    """

    def stored() -> int:
        db = db_session(cfg)
        try:
            return db.scalar(select(func.count()).select_from(AcmeNonce)) or 0
        finally:
            db.close()

    before = stored()
    for _ in range(25):
        resp = client.get(acme.directory_path)
        assert resp.status_code == 200
        assert "replay-nonce" not in resp.headers
    assert client.get("/acme/nothing-here").status_code == 404
    assert client.get("/acme/new-order").status_code == 405
    assert stored() == before

    # the nonce endpoint does, obviously
    head = client.head("/acme/new-nonce")
    assert head.headers["replay-nonce"]
    assert stored() == before + 1

    # ...and so does every POST response, success or failure
    key, kid = register(acme)
    for resp in (
        acme.post(path_of(kid), key, None, kid=kid),
        acme.post(path_of(kid), key, None, kid=kid, nonce="AAAAAAAAAAAAAAAAAAAAAA"),
        acme.post("/acme/revoke-cert", key, {}, kid=kid),
        acme.post("/acme/does-not-exist", key, None, kid=kid),
    ):
        assert resp.headers["replay-nonce"], resp.status_code


def test_dns_identifiers_are_case_folded(acme: Acme, cfg: Config) -> None:
    """DNS names are case-insensitive, so NAS.LAN and nas.lan are one name --
    one authorization, one challenge set, one thing to prove."""
    key, kid = register(acme)

    resp = acme.post(
        "/acme/new-order",
        key,
        {
            "identifiers": [
                {"type": "dns", "value": "NAS.LAN"},
                {"type": "dns", "value": "nas.lan"},
                {"type": "dns", "value": "*.NAS.lan"},
            ]
        },
        kid=kid,
    )

    assert resp.status_code == 201, resp.text
    order = resp.json()
    assert order["identifiers"] == [
        {"type": "dns", "value": "nas.lan"},
        {"type": "dns", "value": "*.nas.lan"},
    ]
    assert len(order["authorizations"]) == 2
    authz = read(acme, key, kid, order["authorizations"][0]).json()
    assert authz["identifier"]["value"] == "nas.lan"


def test_expired_orders_and_authorizations_say_so(acme: Acme, cfg: Config) -> None:
    """``expires`` is a promise, not a decoration: past it, the order is
    invalid and the authorization expired, whatever the stored row says. Spec
    0011 refuses to validate a challenge on that basis, so the rule has to be
    one shared function rather than two readings of the same column."""
    key, kid = register(acme)
    created = place_order(acme, key, kid, "nas.lan")
    order_url = created.headers["location"]
    authz_url = created.json()["authorizations"][0]

    past = (datetime.now(UTC) - timedelta(minutes=1)).replace(microsecond=0).isoformat()
    db = db_session(cfg)
    try:
        order = db.get(AcmeOrder, order_url.rsplit("/", 1)[1])
        authz = db.get(AcmeAuthorization, authz_url.rsplit("/", 1)[1])
        assert order is not None and authz is not None
        order.expires_at = past
        authz.expires_at = past
        db.commit()
    finally:
        db.close()

    assert read(acme, key, kid, order_url).json()["status"] == "invalid"
    assert read(acme, key, kid, authz_url).json()["status"] == "expired"


# --- FR-5, AC-6: the enablement gate --------------------------------------------------


def test_acme_disabled_returns_404(raw_client: TestClient, cfg: Config) -> None:
    """AC-6: off means invisible -- 404 everywhere, never 403, and never a
    nonce that would suggest there is something here."""
    # No hierarchy exists yet, so "1" names nothing real -- the gate has to
    # 404 these before FR-4 ever gets to ask whether the id resolves.
    paths = (
        "/acme/ca/1/directory",
        "/acme/new-nonce",
        "/acme/ca/1/new-account",
        "/acme/new-order",
        "/acme/key-change",
        "/acme/revoke-cert",
        "/acme/account/whatever",
        "/acme/account/whatever/orders",
        "/acme/order/whatever",
        "/acme/order/whatever/finalize",
        "/acme/authz/whatever",
        "/acme/chal/whatever",
        "/acme/",
        # bare, with no trailing slash: this must not 307 to "/acme/" and
        # thereby admit that something lives here
        "/acme",
        "/acme/anything-else",
    )
    for path in paths:
        for method in ("get", "post", "head", "put"):
            resp = getattr(raw_client, method)(path)
            assert resp.status_code == 404, f"{method} {path} -> {resp.status_code}"
            assert "replay-nonce" not in resp.headers, f"{method} {path}"

    # ...and switching it on lights the same paths up
    _setting(cfg, BASE_URL, BASE)
    _setting(cfg, ACME_ENABLED, TRUE)
    issuer_id = create_ca(cfg)
    assert raw_client.get(f"/acme/ca/{issuer_id}/directory").status_code == 200

    # ...and switching it off again puts them out
    _setting(cfg, ACME_ENABLED, FALSE)
    assert raw_client.get(f"/acme/ca/{issuer_id}/directory").status_code == 404


def test_acme_needs_a_base_url_to_answer(raw_client: TestClient, cfg: Config) -> None:
    """Without a configured base URL, cabin would have to take the address it
    publishes from the request's own Host header -- which an attacker sets.
    Every URL in the directory, and the RFC 8555 6.4 binding between a
    signature and the URL it covers, would then be attacker-asserted. So the
    gate treats "no base URL" exactly like "switched off": 404.
    """
    _setting(cfg, ACME_ENABLED, TRUE)
    issuer_id = create_ca(cfg)

    for path in (
        f"/acme/ca/{issuer_id}/directory",
        "/acme/new-nonce",
        f"/acme/ca/{issuer_id}/new-account",
    ):
        assert raw_client.get(path).status_code == 404, path

    _setting(cfg, BASE_URL, BASE)
    assert raw_client.get(f"/acme/ca/{issuer_id}/directory").status_code == 200

    # ...and a Host header cannot talk cabin into publishing someone else
    body = raw_client.get(
        f"/acme/ca/{issuer_id}/directory", headers={"Host": "evil.example"}
    ).json()
    assert body["newAccount"] == f"{BASE}/acme/ca/{issuer_id}/new-account"


def test_settings_refuses_to_enable_acme_without_a_base_url(
    raw_client: TestClient, cfg: Config
) -> None:
    """The gate above is the backstop; an operator who ticks the box must be
    told why nothing happened, rather than left with a setting that reads as
    on and a server that 404s."""
    csrf = _setup_admin(raw_client, cfg)

    resp = raw_client.post(
        "/settings",
        data={"base_url": "", "acme_enabled": "on", "csrf_token": csrf},
    )

    assert resp.status_code == 400, resp.text
    assert "base URL" in resp.text
    db = db_session(cfg)
    try:
        assert get_flag(db, ACME_ENABLED) is False
    finally:
        db.close()
    # No base URL, so the gate 404s whatever the id -- no hierarchy needed.
    assert raw_client.get("/acme/ca/1/directory").status_code == 404


# --- FR-6: audit ---------------------------------------------------------------------


def test_audit_records_acme_events(acme: Acme, cfg: Config) -> None:
    key, kid = register(acme)
    order = place_order(acme, key, kid, "nas.lan")
    assert order.status_code == 201, order.text
    assert acme.post(path_of(kid), key, {"status": "deactivated"}, kid=kid).status_code == 200

    db = db_session(cfg)
    try:
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.actor_kind == "acme").order_by(AuditEvent.id)
        ).all()
    finally:
        db.close()

    assert [event.action for event in events] == [
        "acme_account_created",
        "acme_order_created",
        "acme_account_deactivated",
    ]
    account_id = kid.rsplit("/", 1)[1]
    assert events[0].target_id == account_id
    assert events[1].target_type == "acme_order"
    assert events[1].detail == {"identifiers": ["dns:nas.lan"]}
    # FR-6: the label names the key, not the URL -- a deleted account is still
    # readable in the log
    assert all(event.actor_label.startswith("acme:") for event in events)
    assert all(event.actor_id is None for event in events)
    assert len({event.actor_label for event in events}) == 1


# --- FR-5: the operator's side --------------------------------------------------------


def test_settings_page_toggles_acme_and_shows_the_directory_url(
    raw_client: TestClient, cfg: Config
) -> None:
    """FR-13: /settings only toggles ACME now -- there is no single directory
    URL to print once every issuer has its own, so that line moved to /ca
    (one row per intermediate) and /acme (AC-14)."""
    csrf = _setup_admin(raw_client, cfg)

    page = raw_client.get("/settings")
    assert "acme_enabled" in page.text
    assert raw_client.get("/acme/ca/1/directory").status_code == 404

    resp = raw_client.post(
        "/settings",
        data={
            "base_url": "https://ca.example.org",
            "acme_enabled": "on",
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303, resp.text

    issuer_id = create_ca(cfg)
    assert raw_client.get(f"/acme/ca/{issuer_id}/directory").status_code == 200
    assert "/acme/ca/" not in raw_client.get("/settings").text
    assert f"https://ca.example.org/acme/ca/{issuer_id}/directory" in raw_client.get("/ca").text
