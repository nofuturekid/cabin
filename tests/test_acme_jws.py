"""Spec 0010: nonces (FR-3, AC-1) and JWS request verification (FR-3, AC-2).

Every check here goes through the real HTTP surface, because AC-2 is about
what a client is told -- an ACME problem type *and* an HTTP status -- not
just about a function returning False.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from acme_client import Acme, b64, b64json, ec_key, ed25519_key, flattened, rsa_key
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from cabin.acme import nonces
from cabin.acme.models import AcmeNonce
from cabin.app import create_app
from cabin.config import Config
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory

ERROR_PREFIX = "urn:ietf:params:acme:error:"
#: What the tests configure as cabin's public address, so that the URLs it
#: publishes and the ones TestClient posts to are the same strings.
BASE = "http://testserver"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        enable_acme(cfg)
        yield c


@pytest.fixture
def acme(client: TestClient) -> Acme:
    return Acme(client)


def db_session(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def enable_acme(cfg: Config) -> None:
    db = db_session(cfg)
    try:
        # FR-5: ACME needs to know the address clients were handed, so the
        # gate keeps it off until a base URL is configured. Setting it to the
        # test host means every URL below is the one cabin publishes.
        set_setting(db, BASE_URL, BASE)
        set_setting(db, ACME_ENABLED, TRUE)
    finally:
        db.close()


def problem(resp: Response) -> dict[str, Any]:
    body: dict[str, Any] = resp.json()
    return body


def assert_problem(resp: Response, kind: str, status: int) -> None:
    __tracebackhide__ = True
    assert resp.status_code == status, resp.text
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = problem(resp)
    assert body["type"] == f"{ERROR_PREFIX}{kind}", body
    # FR-4: even an error hands back a usable nonce, or the client is stuck.
    assert resp.headers["replay-nonce"]
    assert 'rel="index"' in resp.headers["link"]


# --- FR-3, AC-1: nonces ------------------------------------------------------------


def test_nonce_single_use(acme: Acme) -> None:
    """AC-1: a nonce is accepted exactly once; the replay is badNonce 400 --
    and carries a fresh nonce so the client can retry rather than loop."""
    key = rsa_key()
    nonce = acme.nonce()

    first = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True}, nonce=nonce)
    assert first.status_code == 201, first.text

    second = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True}, nonce=nonce)

    assert_problem(second, "badNonce", 400)
    assert second.headers["replay-nonce"] != nonce
    # ...and the fresh one works
    retry = acme.post(
        "/acme/new-account",
        key,
        {"termsOfServiceAgreed": True},
        nonce=second.headers["replay-nonce"],
    )
    assert retry.status_code == 200, retry.text


def test_nonce_helpers_are_single_use_and_expire(cfg: Config, client: TestClient) -> None:
    """The unit-level truth behind AC-1, including the 24h cut-off that no
    HTTP test can wait for."""
    db = db_session(cfg)
    try:
        issued = nonces.issue(db)
        assert nonces.consume(db, issued) is True
        assert nonces.consume(db, issued) is False
        assert nonces.consume(db, "never-issued") is False
        assert nonces.consume(db, "") is False

        stale = nonces.issue(db)
        row = db.get(AcmeNonce, stale)
        assert row is not None
        row.issued_at = (datetime.now(UTC) - nonces.NONCE_LIFETIME - timedelta(days=1)).isoformat()
        db.commit()
        assert nonces.consume(db, stale) is False

        # ...and the expired row does not accumulate for ever
        assert nonces.purge(db) >= 1
        assert db.get(AcmeNonce, stale) is None
    finally:
        db.close()


def test_jws_rejects_stale_nonce(acme: Acme, cfg: Config) -> None:
    """AC-2: an unknown, missing or expired nonce is badNonce, never a 500."""
    key = rsa_key()

    unknown = acme.post("/acme/new-account", key, {}, nonce="AAAAAAAAAAAAAAAAAAAAAA")
    assert_problem(unknown, "badNonce", 400)

    missing = acme.post("/acme/new-account", key, {}, drop=("nonce",))
    assert_problem(missing, "badNonce", 400)

    expired = acme.nonce()
    db = db_session(cfg)
    try:
        row = db.get(AcmeNonce, expired)
        assert row is not None
        row.issued_at = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        db.commit()
    finally:
        db.close()
    assert_problem(acme.post("/acme/new-account", key, {}, nonce=expired), "badNonce", 400)


def test_nonce_is_not_burned_by_a_bad_signature(acme: Acme) -> None:
    """A forged request must not consume the nonce it quotes: otherwise
    anyone who can see a nonce can invalidate an honest client's request."""
    key = rsa_key()
    nonce = acme.nonce()
    body = flattened(
        key,
        {
            "alg": "RS256",
            "nonce": nonce,
            "url": acme.url("/acme/new-account"),
            "jwk": key.jwk,
        },
        {"termsOfServiceAgreed": True},
    )
    body["signature"] = b64(b"\x00" * 256)
    assert_problem(acme.post_body("/acme/new-account", body), "malformed", 400)

    good = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True}, nonce=nonce)
    assert good.status_code == 201, good.text


# --- FR-3, AC-2: JWS verification ---------------------------------------------------


def test_jws_rejects_base64url_with_a_trailing_newline(acme: Acme) -> None:
    """The base64url check has to be a full match.

    Python's ``$`` also matches just before a final newline, so a pattern
    anchored with it accepts "aGkA\\n" -- and ``urlsafe_b64decode`` then
    silently drops the newline. The bytes that verified would not be the
    bytes that were sent, which is the whole property a JWS exists to
    provide.
    """
    key = rsa_key()

    def signed(protected_suffix: str = "", payload_suffix: str = "") -> dict[str, str]:
        protected = (
            b64json(
                {
                    "alg": "RS256",
                    "nonce": acme.nonce(),
                    "url": acme.url("/acme/new-account"),
                    "jwk": key.jwk,
                }
            )
            + protected_suffix
        )
        payload = b64json({"termsOfServiceAgreed": True}) + payload_suffix
        signing_input = f"{protected}.{payload}".encode("ascii")
        return {
            "protected": protected,
            "payload": payload,
            "signature": b64(key.sign(signing_input)),
        }

    for kwargs in (
        {"protected_suffix": "\n"},
        {"payload_suffix": "\n"},
        {"protected_suffix": "\n", "payload_suffix": "\n"},
        {"payload_suffix": "\r\n"},
        {"payload_suffix": "\n\n"},
    ):
        resp = acme.post_body("/acme/new-account", signed(**kwargs))
        assert_problem(resp, "malformed", 400)

    # ...and a signature with one too
    body = signed()
    body["signature"] += "\n"
    assert_problem(acme.post_body("/acme/new-account", body), "malformed", 400)


def test_jws_rejects_bad_signature(acme: Acme) -> None:
    key = rsa_key()
    other = rsa_key()

    # signed by a key that is not the one in the header
    body = flattened(
        other,
        {
            "alg": "RS256",
            "nonce": acme.nonce(),
            "url": acme.url("/acme/new-account"),
            "jwk": key.jwk,
        },
        {"termsOfServiceAgreed": True},
    )
    assert_problem(acme.post_body("/acme/new-account", body), "malformed", 400)

    # a payload swapped after signing
    tampered = flattened(
        key,
        {
            "alg": "RS256",
            "nonce": acme.nonce(),
            "url": acme.url("/acme/new-account"),
            "jwk": key.jwk,
        },
        {"termsOfServiceAgreed": True},
    )
    tampered["payload"] = b64json({"contact": ["mailto:someone-else@example.org"]})
    assert_problem(acme.post_body("/acme/new-account", tampered), "malformed", 400)


def test_jws_rejects_none_and_hs256(acme: Acme) -> None:
    """AC-2: the algorithm allowlist is checked against the header before any
    verification happens -- ``none`` and the symmetric families never get to
    influence which key is used."""
    key = rsa_key()

    unsigned = flattened(
        key,
        {
            "alg": "none",
            "nonce": acme.nonce(),
            "url": acme.url("/acme/new-account"),
            "jwk": key.jwk,
        },
        {"termsOfServiceAgreed": True},
    )
    unsigned["signature"] = ""
    assert_problem(acme.post_body("/acme/new-account", unsigned), "badSignatureAlgorithm", 400)

    for alg in ("HS256", "HS384", "HS512", "RS1", "ES512", "PS256", "rs256", ""):
        resp = acme.post("/acme/new-account", key, {}, alg=alg)
        assert_problem(resp, "badSignatureAlgorithm", 400)
        # RFC 8555 6.2: say which algorithms would have worked
        assert "RS256" in problem(resp)["algorithms"]

    # an HS256 JWS whose "key" is the shared secret must not authenticate
    # anything either, however it is dressed up
    forged = {
        "protected": b64json(
            {
                "alg": "HS256",
                "nonce": acme.nonce(),
                "url": acme.url("/acme/new-account"),
                "jwk": {"kty": "oct", "k": b64(b"secret")},
            }
        ),
        "payload": b64json({}),
        "signature": b64(b"whatever"),
    }
    assert_problem(acme.post_body("/acme/new-account", forged), "badSignatureAlgorithm", 400)


def test_jws_rejects_jwk_and_kid_together(acme: Acme) -> None:
    """AC-2: RFC 8555 6.2 -- exactly one of jwk/kid, never both and never
    neither."""
    key = rsa_key()
    created = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True})
    assert created.status_code == 201, created.text
    kid = created.headers["location"]

    both = acme.post("/acme/new-order", key, {}, kid=kid, protected={"jwk": key.jwk})
    assert_problem(both, "malformed", 400)

    neither = acme.post("/acme/new-order", key, {}, drop=("jwk",))
    assert_problem(neither, "malformed", 400)


def test_jws_rejects_wrong_url(acme: Acme) -> None:
    """AC-2: RFC 8555 6.4 -- a signature over someone else's URL is not a
    signature over this request."""
    key = rsa_key()

    for wrong in (
        "http://testserver/acme/new-order",
        "https://testserver/acme/new-account",
        "http://evil.example/acme/new-account",
        "http://testserver/acme/new-account/",
        "",
    ):
        assert_problem(acme.post("/acme/new-account", key, {}, url=wrong), "unauthorized", 403)

    assert_problem(acme.post("/acme/new-account", key, {}, drop=("url",)), "unauthorized", 403)


def test_jws_accepts_every_allowed_algorithm(acme: Acme) -> None:
    """The allowlist is a list, not a single algorithm: a client with an EC
    or Ed25519 account key has to work too."""
    for key in (rsa_key(), ec_key("ES256"), ec_key("ES384"), ed25519_key()):
        resp = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True})
        assert resp.status_code == 201, f"{key.alg}: {resp.text}"


def test_jws_rejects_unusable_keys(acme: Acme) -> None:
    """A key that cannot carry the announced algorithm is badPublicKey, not a
    traceback: wrong curve, too-small RSA, a private key sent by mistake."""
    p384 = ec_key("ES384")
    mismatched = flattened(
        p384,
        {
            "alg": "ES256",
            "nonce": acme.nonce(),
            "url": acme.url("/acme/new-account"),
            "jwk": p384.jwk,
        },
        {},
    )
    assert_problem(acme.post_body("/acme/new-account", mismatched), "badPublicKey", 400)

    small = rsa_key(bits=1024)
    assert_problem(acme.post("/acme/new-account", small, {}), "badPublicKey", 400)

    key = rsa_key()
    with_private = dict(key.jwk)
    with_private["d"] = b64(b"\x01" * 32)
    resp = acme.post("/acme/new-account", key, {}, protected={"jwk": with_private})
    assert_problem(resp, "badPublicKey", 400)


def test_jws_rejects_malformed_bodies_without_a_500(acme: Acme) -> None:
    """Hostile input is the normal case for a public endpoint: nothing below
    may reach a traceback."""
    key = rsa_key()
    bodies: list[bytes | dict[str, Any]] = [
        b"",
        b"not json at all",
        b"[]",
        b'"string"',
        b"null",
        {},
        {"protected": "", "payload": "", "signature": ""},
        {"protected": "!!!!", "payload": "", "signature": "AAAA"},
        {"protected": b64json([1, 2, 3]), "payload": "", "signature": "AAAA"},
        {"protected": b64(b"{not json}"), "payload": "", "signature": "AAAA"},
        {"protected": b64json({"alg": "RS256"}), "payload": "", "signature": "AAAA"},
        {"protected": b64json({"alg": 7}), "payload": "", "signature": "AAAA"},
        {"payload": "", "signature": "AAAA"},
        {"protected": b64json({"alg": "RS256", "nonce": "x", "url": "y", "jwk": key.jwk})},
        {
            "protected": b64json(
                {
                    "alg": "RS256",
                    "nonce": "x",
                    "url": "y",
                    "jwk": key.jwk,
                    "crit": ["exp"],
                }
            ),
            "payload": "",
            "signature": "AAAA",
        },
        # general (non-flattened) serialization is not what RFC 8555 asks for
        {"payload": "", "signatures": [{"protected": "", "signature": ""}]},
        # an unprotected header is a way to smuggle in a second opinion
        {
            "protected": b64json({"alg": "RS256", "nonce": "x", "url": "y", "jwk": key.jwk}),
            "header": {"alg": "none"},
            "payload": "",
            "signature": "AAAA",
        },
    ]
    for body in bodies:
        resp = acme.post_body("/acme/new-account", body)
        assert resp.status_code < 500, f"{body!r} -> {resp.status_code} {resp.text}"
        assert resp.headers["replay-nonce"], body
        assert str(problem(resp)["type"]).startswith(ERROR_PREFIX)

    # a payload that is valid base64url but not a JSON object
    for bad_payload in (b64(b"[]"), b64(b"7"), b64(b"{"), "!!!"):
        protected = b64json(
            {
                "alg": "RS256",
                "nonce": acme.nonce(),
                "url": acme.url("/acme/new-account"),
                "jwk": key.jwk,
            }
        )
        signing_input = f"{protected}.{bad_payload}".encode("ascii")
        resp = acme.post_body(
            "/acme/new-account",
            {
                "protected": protected,
                "payload": bad_payload,
                "signature": b64(key.sign(signing_input)),
            },
        )
        assert_problem(resp, "malformed", 400)


def test_jws_rejects_an_unknown_or_foreign_kid(acme: Acme) -> None:
    key = rsa_key()
    created = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True})
    kid = created.headers["location"]

    for bad_kid in (
        "http://testserver/acme/account/does-not-exist",
        "http://evil.example/acme/account/whatever",
        "http://testserver/acme/account/",
        "not-a-url",
        f"{kid}/orders",
    ):
        resp = acme.post("/acme/new-order", key, {}, kid=bad_kid)
        assert resp.status_code in (400, 403), f"{bad_kid} -> {resp.text}"
        assert problem(resp)["type"] in (
            f"{ERROR_PREFIX}accountDoesNotExist",
            f"{ERROR_PREFIX}unauthorized",
        )


def test_new_account_must_use_jwk_and_others_must_use_kid(acme: Acme) -> None:
    """RFC 8555 6.2: new-account is the one request that carries its key; a
    request that already has an account must name it."""
    key = rsa_key()
    created = acme.post("/acme/new-account", key, {"termsOfServiceAgreed": True})
    kid = created.headers["location"]

    assert_problem(acme.post("/acme/new-account", key, {}, kid=kid), "malformed", 400)
    assert_problem(acme.post("/acme/new-order", key, {}), "malformed", 400)


def test_jws_body_size_is_bounded(acme: Acme) -> None:
    """A public POST endpoint must not be a way to make the server parse an
    arbitrarily large JSON document."""
    resp = acme.post_body("/acme/new-account", b"{" + b"a" * (300 * 1024) + b"}")
    assert resp.status_code < 500, resp.status_code
    assert str(problem(resp)["type"]).startswith(ERROR_PREFIX)


def test_deeply_nested_json_is_refused_not_crashed(acme: Acme) -> None:
    """Deeply nested JSON is the cheap way to exhaust a parser: a few
    kilobytes of ``[[[[…`` makes CPython's json module raise RecursionError,
    which is not a ValueError and would otherwise escape as a 500."""
    depth = 40_000
    nested = ("[" * depth + "]" * depth).encode("ascii")
    assert len(nested) < 128 * 1024  # inside the body cap, so it is really parsed

    body = acme.post_body("/acme/new-account", nested)
    assert body.status_code == 400, body.status_code
    assert str(problem(body)["type"]).startswith(ERROR_PREFIX)

    # ...and the same trick inside the payload of an otherwise valid JWS
    key = rsa_key()
    protected = b64json(
        {
            "alg": "RS256",
            "nonce": acme.nonce(),
            "url": acme.url("/acme/new-account"),
            "jwk": key.jwk,
        }
    )
    payload = b64(nested)
    signing_input = f"{protected}.{payload}".encode("ascii")
    inner = acme.post_body(
        "/acme/new-account",
        {
            "protected": protected,
            "payload": payload,
            "signature": b64(key.sign(signing_input)),
        },
    )
    assert_problem(inner, "malformed", 400)
