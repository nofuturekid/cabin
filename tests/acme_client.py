"""A deliberately hand-rolled ACME client for the spec-0010 tests.

Not a fixture module and not collected by pytest -- it is imported by
``test_acme_jws.py`` and ``test_acme_api.py``.

Everything here is built straight from RFC 7515/7517/7518 rather than with
``josepy``, on purpose: the server verifies with josepy, so a test that
signed with josepy too would only prove the two halves of one library agree
with each other. It also has to produce JWS bodies no real client would --
``alg: none``, HS256, both ``jwk`` and ``kid`` -- which a well-behaved
library will not build.
"""

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from fastapi.testclient import TestClient
from httpx2 import Response

JOSE_CONTENT_TYPE = "application/jose+json"


def b64(data: bytes) -> str:
    """base64url without padding, the only encoding JOSE uses."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64json(obj: Any) -> str:
    return b64(json.dumps(obj).encode("utf-8"))


def _uint(value: int, length: int) -> str:
    return b64(value.to_bytes(length, "big"))


#: RFC 7638 3.2: the members that take part in a thumbprint, per key type.
#: Everything else in a JWK is left out, and the order is lexicographic.
_THUMBPRINT_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}


@dataclass(frozen=True)
class AcmeKey:
    """A signing key plus the JWK and ``alg`` that go with it."""

    alg: str
    private: Any
    jwk: dict[str, Any]

    def thumbprint(self) -> str:
        """The RFC 7638 thumbprint of this key -- the second half of every
        key authorization (spec 0011 FR-1).

        Computed here from the RFC rather than asked of the server, so that a
        test comparing the two is comparing two readings of the specification
        and not one value with itself.
        """
        members = _THUMBPRINT_MEMBERS[self.jwk["kty"]]
        canonical = json.dumps(
            {name: self.jwk[name] for name in members},
            sort_keys=True,
            separators=(",", ":"),
        )
        return b64(hashlib.sha256(canonical.encode("utf-8")).digest())

    def sign(self, signing_input: bytes) -> bytes:
        if self.alg == "RS256":
            return bytes(self.private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
        if self.alg in ("ES256", "ES384"):
            hash_alg = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
            size = 32 if self.alg == "ES256" else 48
            der = self.private.sign(signing_input, ec.ECDSA(hash_alg))
            r, s = utils.decode_dss_signature(der)
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        if self.alg == "EdDSA":
            return bytes(self.private.sign(signing_input))
        raise AssertionError(f"no signer for {self.alg}")


def rsa_key(bits: int = 2048) -> AcmeKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = private.public_key().public_numbers()
    byte_length = (numbers.n.bit_length() + 7) // 8
    return AcmeKey(
        alg="RS256",
        private=private,
        jwk={
            "kty": "RSA",
            "n": _uint(numbers.n, byte_length),
            "e": _uint(numbers.e, 3),
        },
    )


def ec_key(alg: str = "ES256") -> AcmeKey:
    curve, size, crv = (
        (ec.SECP256R1(), 32, "P-256") if alg == "ES256" else (ec.SECP384R1(), 48, "P-384")
    )
    private = ec.generate_private_key(curve)
    numbers = private.public_key().public_numbers()
    return AcmeKey(
        alg=alg,
        private=private,
        jwk={
            "kty": "EC",
            "crv": crv,
            "x": _uint(numbers.x, size),
            "y": _uint(numbers.y, size),
        },
    )


def ed25519_key() -> AcmeKey:
    private = ed25519.Ed25519PrivateKey.generate()
    return AcmeKey(
        alg="EdDSA",
        private=private,
        jwk={
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(private.public_key().public_bytes_raw()),
        },
    )


def flattened(key: AcmeKey, protected: dict[str, Any], payload: Any) -> dict[str, str]:
    """Sign ``protected``/``payload`` into an RFC 7515 flattened JWS.

    ``payload=None`` produces the empty payload of a POST-as-GET request --
    which is not the same thing as ``payload={}``.
    """
    protected_b64 = b64json(protected)
    payload_b64 = "" if payload is None else b64json(payload)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64(key.sign(signing_input)),
    }


class Acme:
    """The client under the tests: fetches nonces, signs, posts."""

    def __init__(self, client: TestClient, base: str = "http://testserver") -> None:
        self.client = client
        self.base = base

    def url(self, path: str) -> str:
        return f"{self.base}{path}"

    def directory(self) -> dict[str, Any]:
        resp = self.client.get("/acme/directory")
        assert resp.status_code == 200, resp.text
        body: dict[str, Any] = resp.json()
        return body

    def nonce(self) -> str:
        resp = self.client.head("/acme/new-nonce")
        assert resp.status_code == 200, resp.text
        return resp.headers["replay-nonce"]

    def post_body(
        self, path: str, body: Any, content_type: str | None = JOSE_CONTENT_TYPE
    ) -> Response:
        """POST a body verbatim. ``content_type=None`` omits the header
        entirely, which is a case RFC 8555 6.2 has an opinion about."""
        headers = {"Content-Type": content_type} if content_type is not None else {}
        return self.client.post(
            path,
            content=json.dumps(body) if not isinstance(body, str | bytes) else body,
            headers=headers,
        )

    def post(
        self,
        path: str,
        key: AcmeKey,
        payload: Any = None,
        *,
        kid: str | None = None,
        nonce: str | None = None,
        url: str | None = None,
        alg: str | None = None,
        protected: dict[str, Any] | None = None,
        drop: tuple[str, ...] = (),
    ) -> Response:
        """Sign and POST. The keyword arguments exist so a test can build a
        request that is wrong in exactly one way."""
        header: dict[str, Any] = {
            # `is not None`, not `or`: alg="" is a case a test wants to send.
            "alg": key.alg if alg is None else alg,
            "nonce": self.nonce() if nonce is None else nonce,
            "url": self.url(path) if url is None else url,
        }
        if kid is None:
            header["jwk"] = key.jwk
        else:
            header["kid"] = kid
        header.update(protected or {})
        for name in drop:
            header.pop(name, None)
        return self.post_body(path, flattened(key, header, payload))


def external_account_binding(
    *,
    kid: str,
    mac_key: bytes,
    url: str,
    jwk: dict[str, Any],
    alg: str = "HS256",
) -> dict[str, str]:
    """The inner JWS of RFC 8555 7.3.4, built straight from the RFC.

    HMAC rather than a signature, the account's public JWK as the payload,
    and no nonce -- it is a binding, not a request.
    """
    protected_b64 = b64json({"alg": alg, "kid": kid, "url": url})
    payload_b64 = b64json(jwk)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64(hmac.new(mac_key, signing_input, hashlib.sha256).digest()),
    }


def account_url(resp: Response) -> str:
    location = resp.headers["location"]
    assert location.startswith("http"), location
    return location
