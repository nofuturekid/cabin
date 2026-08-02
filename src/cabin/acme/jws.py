"""JWS-authenticated ACME requests (spec 0010 FR-3, AC-2).

Every ACME request except the directory and the nonce endpoint is a POST
whose body is a JWS in RFC 7515's *flattened JSON serialization*; the
signature is the only authentication there is. This module turns such a body
into a :class:`VerifiedRequest` or raises an :class:`AcmeError` -- there is
no third outcome, and in particular no path that returns a payload without
having checked a signature.

Two rules drive the order of the checks below.

**The header never chooses the verifier.** ``alg`` is matched against
:data:`ALLOWED_ALGORITHMS` first, and the verifier is then looked up in a
table cabin owns. ``none`` and the HMAC families are not in that table, so
the classic JWS confusion attacks -- "verify this with alg none", "treat the
RSA public key as an HMAC secret" -- cannot get as far as choosing code to
run. Nor can a key of the wrong shape: an RSA key may only carry RS256, a
P-256 key only ES256, and so on.

**A forged request must not cost an honest client its nonce.** The nonce is
consumed last, after the signature has verified, so anyone who can observe a
nonce cannot spend it on someone else's behalf.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from josepy import errors as jose_errors
from josepy import jwa as jose_jwa
from josepy import jwk as jose_jwk
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.acme import nonces
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.models import AccountStatus, AcmeAccount, kid_hash

#: The signature algorithms cabin accepts (FR-3). RS256 because every ACME
#: client can produce it, ES256/ES384 because modern ones prefer them, EdDSA
#: because it is the cheapest of the three to verify. Deliberately absent:
#: ``none`` (no signature at all), the HS* family (a shared secret, which an
#: account key is not), and RS1/PS*/ES512, which nothing in this ecosystem
#: needs.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256", "ES384", "EdDSA")

#: The one MAC algorithm cabin accepts, and only for the external account
#: binding of RFC 8555 7.3.4 (spec 0012 FR-4). It is deliberately NOT in
#: :data:`ALLOWED_ALGORITHMS`: the outer JWS is signed with an account key,
#: which is a key pair, and an HMAC there would mean cabin verifying a
#: request against a secret it also knows -- the classic confusion attack.
#: Two constants, two code paths, and :func:`verify_external_binding` is the
#: only caller of this one.
EAB_ALGORITHM = "HS256"

#: RSA below this is not a key, it is a formality.
MIN_RSA_BITS = 2048

#: A JWS large enough to be worth parsing is already far larger than any
#: real one -- the biggest legitimate body here is a key rollover carrying
#: two RSA-4096 keys, which is a few kilobytes.
MAX_BODY_BYTES = 128 * 1024

#: How much of an attacker-supplied value an error message repeats back.
_MAX_ECHO = 80

#: The table the verifier is looked up in. Nothing in a request header ever
#: selects an entry that is not here.
_JWA = {"RS256": jose_jwa.RS256, "ES256": jose_jwa.ES256, "ES384": jose_jwa.ES384}
#: RFC 7518 3.4: each ECDSA algorithm names exactly one curve. josepy sizes
#: the signature from the key's curve, so without this a P-384 key would
#: happily answer for ES256.
_EC_CURVE_FOR_ALG = {"ES256": ("P-256", "secp256r1"), "ES384": ("P-384", "secp384r1")}
#: Parameters that only ever appear in a *private* JWK. A client sending one
#: has leaked its account key; refusing is both safer and more useful than
#: quietly using the public half.
_PRIVATE_JWK_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

#: Used with :meth:`re.Pattern.fullmatch`, and deliberately without anchors.
#: ``$`` would be wrong here: in Python it also matches just before a final
#: newline, so ``^[A-Za-z0-9_-]*$`` accepts "aGkA\n" -- which
#: ``urlsafe_b64decode`` then silently drops, leaving the bytes that verified
#: different from the bytes that arrived.
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


class KeyMode(StrEnum):
    """Which key a particular request must be signed with (RFC 8555 6.2).

    ``jwk`` is new-account, the one request whose signer has no account yet
    and so carries its public key inline; ``kid`` is everything afterwards,
    which names the account URL instead. Requiring one *or* the other per
    route -- rather than accepting whichever turns up -- is what stops a
    request from being replayed into an endpoint that trusts the other form.
    """

    jwk = "jwk"
    kid = "kid"


@dataclass(frozen=True)
class AccountKey:
    """A public key that has been checked against the algorithm it claims.

    ``jwk`` is the canonical public JWK (what gets stored), ``thumbprint``
    its RFC 7638 SHA-256 digest (what identifies the account).
    """

    jwk: dict[str, Any]
    thumbprint: str
    alg: str
    key: ed25519.Ed25519PublicKey | jose_jwk.JWKRSA | jose_jwk.JWKEC

    def verify(self, signing_input: bytes, signature: bytes) -> bool:
        if isinstance(self.key, ed25519.Ed25519PublicKey):
            try:
                self.key.verify(signature, signing_input)
            except InvalidSignature:
                return False
            return True
        return bool(_JWA[self.alg].verify(self.key.key, signing_input, signature))

    def public_der(self) -> bytes:
        """This key as a DER SubjectPublicKeyInfo -- the encoding a
        certificate carries its public key in.

        Spec 0012 FR-3 needs to answer "is the key that signed this request
        the key in that certificate?", and comparing the two SPKIs is the
        only form of that question which does not depend on how either side
        happened to be serialized.
        """
        raw = self.key if isinstance(self.key, ed25519.Ed25519PublicKey) else self.key.key
        encoded: bytes = raw.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return encoded


@dataclass(frozen=True)
class VerifiedRequest:
    """A request whose signature checked out.

    ``payload`` is None for a POST-as-GET (an empty payload, RFC 8555 6.3) --
    which is a different thing from ``{}``, an empty JSON object, and the two
    must stay distinguishable: for a challenge the latter is what triggers
    validation in spec 0011.
    """

    protected: dict[str, Any]
    payload: dict[str, Any] | None
    key: AccountKey
    account: AcmeAccount | None


def _echo(value: object) -> str:
    text = repr(value)
    return text if len(text) <= _MAX_ECHO else f"{text[:_MAX_ECHO]}..."


def b64encode(data: bytes) -> str:
    """base64url without padding -- the only encoding JOSE uses."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(value: object, what: str) -> bytes:
    """Strict base64url: no padding, no standard-alphabet characters, no
    whitespace. Anything else is malformed rather than silently repaired,
    because "repaired" would mean verifying a signature over bytes the
    client did not sign."""
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None:
        raise AcmeError(ErrorType.malformed, f"{what} is not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise AcmeError(ErrorType.malformed, f"{what} is not base64url") from exc


def _loads(raw: bytes, what: str) -> Any:
    """``json.loads`` with the two failures a public endpoint actually sees.

    ``RecursionError`` is the interesting one: a few kilobytes of ``[[[[…``
    is enough to exhaust the interpreter's stack inside the parser, and an
    uncaught one would be a 500 handed out for free.
    """
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AcmeError(ErrorType.malformed, f"{what} is not JSON") from exc
    except RecursionError as exc:
        raise AcmeError(ErrorType.malformed, f"{what} is nested too deeply") from exc


def _json_object(raw: bytes, what: str) -> dict[str, Any]:
    decoded = _loads(raw, what)
    if not isinstance(decoded, dict):
        raise AcmeError(ErrorType.malformed, f"{what} is not a JSON object")
    return decoded


# --- key handling ------------------------------------------------------------------


def _okp_key(raw: dict[str, Any], alg: str) -> AccountKey:
    """Ed25519 (RFC 8037). Hand-rolled because josepy has no OKP support --
    which is also why the thumbprint is computed here instead of by
    :meth:`josepy.JWK.thumbprint`."""
    if raw.get("crv") != "Ed25519":
        raise AcmeError(ErrorType.bad_public_key, "EdDSA requires an Ed25519 key")
    material = b64decode(raw.get("x"), 'the JWK\'s "x" parameter')
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(material)
    except ValueError as exc:
        raise AcmeError(ErrorType.bad_public_key, f"not a usable Ed25519 key: {exc}") from exc
    # RFC 7638 2 / RFC 8037 2: the required members, lexicographically
    # ordered, no whitespace -- then SHA-256.
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": b64encode(public.public_bytes_raw())}
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return AccountKey(jwk=jwk, thumbprint=b64encode(digest), alg=alg, key=public)


def _josepy_key(raw: dict[str, Any], alg: str) -> AccountKey:
    """RSA and EC, parsed and thumbprinted by josepy (RFC 7638)."""
    try:
        parsed = jose_jwk.JWK.from_json(dict(raw))
    except (jose_errors.DeserializationError, KeyError, ValueError, TypeError) as exc:
        raise AcmeError(ErrorType.bad_public_key, f"the JWK could not be read: {exc}") from exc
    if not isinstance(parsed, jose_jwk.JWKRSA | jose_jwk.JWKEC):
        # ``kty: oct`` parses into a symmetric JWK. The algorithm allowlist
        # already rules out anything that could use one, but a key type this
        # module cannot reason about must not reach a verifier regardless.
        raise AcmeError(ErrorType.bad_public_key, "unsupported JWK key type")
    if isinstance(parsed, jose_jwk.JWKRSA):
        bits = int(parsed.key.key_size)
        if bits < MIN_RSA_BITS:
            raise AcmeError(
                ErrorType.bad_public_key,
                f"an RSA account key must be at least {MIN_RSA_BITS} bits, not {bits}",
            )
    else:
        announced, expected = _EC_CURVE_FOR_ALG[alg]
        if str(parsed.key.curve.name) != expected:
            raise AcmeError(ErrorType.bad_public_key, f"{alg} requires a {announced} key")
    return AccountKey(
        jwk=dict(parsed.to_json()),
        thumbprint=b64encode(parsed.thumbprint()),
        alg=alg,
        key=parsed,
    )


def load_account_key(raw: object, alg: str) -> AccountKey:
    """Read a JWK and check it can actually carry ``alg`` (RFC 7518)."""
    if not isinstance(raw, dict):
        raise AcmeError(ErrorType.malformed, "the JWS jwk header is not a JSON object")
    if _PRIVATE_JWK_PARAMETERS & set(raw):
        raise AcmeError(
            ErrorType.bad_public_key,
            "the JWK must contain only public key parameters",
        )
    kty = raw.get("kty")
    if alg == "EdDSA" and kty == "OKP":
        return _okp_key(raw, alg)
    if alg == "RS256" and kty == "RSA":
        return _josepy_key(raw, alg)
    if alg in _EC_CURVE_FOR_ALG and kty == "EC":
        return _josepy_key(raw, alg)
    raise AcmeError(ErrorType.bad_public_key, f"a {_echo(kty)} key cannot carry {alg} signatures")


# --- parsing -----------------------------------------------------------------------


@dataclass(frozen=True)
class _Jws:
    protected_b64: str
    payload_b64: str
    signature: bytes
    protected: dict[str, Any]

    @property
    def signing_input(self) -> bytes:
        # RFC 7515 5.2: the signature covers exactly these bytes, taken from
        # the wire rather than re-encoded -- re-serializing the header would
        # verify a document the client never sent.
        return f"{self.protected_b64}.{self.payload_b64}".encode("ascii")


def _parse_document(document: object) -> _Jws:
    if not isinstance(document, dict):
        raise AcmeError(ErrorType.malformed, "the request body is not a JSON object")
    if "signatures" in document:
        raise AcmeError(
            ErrorType.malformed,
            "RFC 8555 6.2 requires the flattened JSON serialization, with one signature",
        )
    if "header" in document:
        # An unprotected header is a second, unsigned opinion about the same
        # request; RFC 8555 6.2 has no use for one.
        raise AcmeError(ErrorType.malformed, "the JWS must not carry an unprotected header")
    members: dict[str, str] = {}
    for name in ("protected", "payload", "signature"):
        value = document.get(name)
        if not isinstance(value, str):
            raise AcmeError(ErrorType.malformed, f'the JWS has no string "{name}" member')
        members[name] = value
    protected = _json_object(
        b64decode(members["protected"], "the JWS protected header"),
        "the JWS protected header",
    )
    if "crit" in protected:
        # RFC 8555 6.2: cabin understands no extensions, so it must not
        # accept a header that insists one was understood.
        raise AcmeError(ErrorType.malformed, 'the JWS "crit" header is not supported')
    return _Jws(
        protected_b64=members["protected"],
        payload_b64=members["payload"],
        signature=b64decode(members["signature"], "the JWS signature"),
        protected=protected,
    )


def _parse(body: bytes) -> _Jws:
    if len(body) > MAX_BODY_BYTES:
        raise AcmeError(ErrorType.malformed, "the request body is too large")
    return _parse_document(_loads(body, "the request body"))


def _algorithm(protected: dict[str, Any]) -> str:
    alg = protected.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
        raise AcmeError(
            ErrorType.bad_signature_algorithm,
            f"unsupported JWS algorithm: {_echo(alg)}",
            extra={"algorithms": list(ALLOWED_ALGORITHMS)},
        )
    return alg


def _payload(payload_b64: str) -> dict[str, Any] | None:
    if payload_b64 == "":
        return None
    raw = b64decode(payload_b64, "the JWS payload")
    if raw == b"":
        return None
    return _json_object(raw, "the JWS payload")


def _account_for_kid(db: Session, kid: object, account_url_prefix: str) -> AcmeAccount:
    """Resolve a ``kid`` header to the account it names.

    The kid must be *this* server's URL for the account, not merely end in
    something that looks like an id: accepting a foreign origin would let a
    request signed for another CA be replayed here.
    """
    if not isinstance(kid, str) or not kid.startswith(account_url_prefix):
        raise AcmeError(
            ErrorType.unauthorized,
            "the JWS kid header is not an account URL of this server",
        )
    account_id = kid[len(account_url_prefix) :]
    if not account_id or "/" in account_id:
        raise AcmeError(ErrorType.unauthorized, "the JWS kid header is not an account URL")
    account = db.scalar(select(AcmeAccount).where(AcmeAccount.kid_hash == kid_hash(account_id)))
    if account is None:
        raise AcmeError(ErrorType.account_does_not_exist, "no account with that key identifier")
    if account.status != AccountStatus.valid:
        raise AcmeError(ErrorType.unauthorized, f"this account is {account.status}")
    return account


def verify_request(
    db: Session,
    body: bytes,
    *,
    url: str,
    mode: KeyMode,
    account_url_prefix: str,
) -> VerifiedRequest:
    """Authenticate one ACME request, or raise :class:`AcmeError`.

    ``url`` is the canonical URL cabin publishes for this route -- not
    ``request.url`` -- so that a deployment behind a reverse proxy compares
    the client's ``url`` header against the address it was actually given
    (RFC 8555 6.4).
    """
    jws = _parse(body)
    alg = _algorithm(jws.protected)

    has_jwk, has_kid = "jwk" in jws.protected, "kid" in jws.protected
    if has_jwk == has_kid:
        raise AcmeError(
            ErrorType.malformed,
            "the JWS must carry exactly one of the jwk and kid headers",
        )
    if mode is KeyMode.jwk and not has_jwk:
        raise AcmeError(ErrorType.malformed, "this request must carry its key in a jwk header")
    if mode is KeyMode.kid and not has_kid:
        raise AcmeError(ErrorType.malformed, "this request must name its account in a kid header")

    if jws.protected.get("url") != url:
        raise AcmeError(
            ErrorType.unauthorized,
            "the JWS url header does not match the requested URL",
        )
    nonce = jws.protected.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise AcmeError(ErrorType.bad_nonce, "the JWS carries no anti-replay nonce")

    account: AcmeAccount | None = None
    if has_kid:
        account = _account_for_kid(db, jws.protected["kid"], account_url_prefix)
        key = load_account_key(json.loads(account.jwk_json), alg)
    else:
        key = load_account_key(jws.protected["jwk"], alg)

    if not key.verify(jws.signing_input, jws.signature):
        raise AcmeError(ErrorType.malformed, "the JWS signature does not verify")
    # Last, so a forged request cannot spend a nonce an honest client holds.
    if not nonces.consume(db, nonce):
        raise AcmeError(ErrorType.bad_nonce, "this nonce is unknown, already used, or expired")

    return VerifiedRequest(
        protected=jws.protected,
        payload=_payload(jws.payload_b64),
        key=key,
        account=account,
    )


def key_mode(body: bytes) -> KeyMode:
    """Which of the two forms a request arrived in, read from the header
    alone and before anything is verified.

    Exactly one route needs this: RFC 8555 7.6 lets a revocation be signed
    either by the account that ordered the certificate or by the
    certificate's own key, and the route has to know which claim is being
    made before it can check it. Everywhere else the mode is a property of
    the route, not of the request, and stays that way -- this function does
    not decide anything, it only reports what the client said, and
    :func:`verify_request` is still what enforces it.
    """
    protected = _parse(body).protected
    has_jwk, has_kid = "jwk" in protected, "kid" in protected
    if has_jwk == has_kid:
        raise AcmeError(
            ErrorType.malformed,
            "the JWS must carry exactly one of the jwk and kid headers",
        )
    return KeyMode.kid if has_kid else KeyMode.jwk


@dataclass(frozen=True)
class ExternalBinding:
    """A parsed ``externalAccountBinding``, before its MAC has been checked.

    Split from the check itself because the two happen at different times:
    the ``kid`` is what tells cabin *which* key to unseal, and it can only
    look that up once it has read the header.
    """

    kid: str
    signing_input: bytes
    signature: bytes
    payload_b64: str


def parse_external_binding(document: object, *, url: str) -> ExternalBinding:
    """Read the inner JWS of an external account binding (RFC 8555 7.3.4)
    and check everything about it that does not need the secret.

    This is the one place in cabin where a JWS is verified with a shared
    secret, and it is written out here rather than folded into
    :func:`verify_request` on purpose. The two are different security
    arguments: an account key proves "I am this account", the MAC proves "an
    operator gave me this credential", and the binding exists precisely
    because those are not the same claim. Sharing the algorithm table would
    mean one of them could be presented where the other was expected.

    Checked here: ``alg`` is exactly :data:`EAB_ALGORITHM` -- not "one of
    the HMAC family", since HS384/HS512 with a key sized for HS256 buys
    nothing -- there is a ``kid`` and no inline ``jwk``, and the ``url`` is
    the new-account URL cabin published, so that a binding made for another
    CA (or another endpoint) cannot be replayed here.
    """
    jws = _parse_document(document)
    alg = jws.protected.get("alg")
    if alg != EAB_ALGORITHM:
        raise AcmeError(
            ErrorType.bad_signature_algorithm,
            f"an external account binding must be signed with {EAB_ALGORITHM}, not {_echo(alg)}",
            extra={"algorithms": [EAB_ALGORITHM]},
        )
    kid = jws.protected.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AcmeError(
            ErrorType.malformed,
            "the external account binding names no key identifier in its kid header",
        )
    if "jwk" in jws.protected:
        raise AcmeError(
            ErrorType.malformed,
            "the external account binding must name its key by kid, not carry one inline",
        )
    if jws.protected.get("url") != url:
        raise AcmeError(
            ErrorType.malformed,
            "the external account binding was not made for this server's new-account URL",
        )
    return ExternalBinding(
        kid=kid,
        signing_input=jws.signing_input,
        signature=jws.signature,
        payload_b64=jws.payload_b64,
    )


def verify_external_binding(
    binding: ExternalBinding, *, mac_key: bytes, account_jwk: dict[str, Any]
) -> None:
    """The half of RFC 8555 7.3.4 that needs the operator's secret: the MAC,
    and that the binding really carries the key being registered.

    Raises ``unauthorized`` for either failure -- a client that presents a
    binding it cannot prove is not entitled to register, and telling it
    which of the two checks failed would help nobody but an attacker.
    """
    expected = hmac.new(mac_key, binding.signing_input, hashlib.sha256).digest()
    # Constant time: a MAC comparison that returns early leaks, byte by
    # byte, what the right answer would have been.
    if not hmac.compare_digest(expected, binding.signature):
        raise AcmeError(ErrorType.unauthorized, "the external account binding does not verify")

    payload = _payload(binding.payload_b64)
    if payload is None:
        raise AcmeError(ErrorType.malformed, "the external account binding carries no key")
    # Compared member by member against the canonical account JWK rather than
    # as whole documents: a client may add "kid"/"alg"/"use" to the key it
    # signs, and refusing those would fail registrations that are perfectly
    # correct. Every member that identifies the key must still be present
    # and equal, so this cannot pass for a different key.
    if any(payload.get(name) != value for name, value in account_jwk.items()):
        raise AcmeError(
            ErrorType.unauthorized,
            "the external account binding is not for the key this request is signed with",
        )


def verify_embedded(document: object, *, url: str) -> tuple[AccountKey, dict[str, Any]]:
    """Verify a JWS that arrived as the *payload* of another one -- the inner
    JWS of a key rollover (RFC 8555 7.3.5).

    It proves possession of the new account key, so it carries ``jwk`` and
    not ``kid``, and it must not carry a nonce of its own: it is not a
    request, and a nonce here would be a second thing to replay.
    """
    jws = _parse_document(document)
    alg = _algorithm(jws.protected)
    if "jwk" not in jws.protected or "kid" in jws.protected:
        raise AcmeError(ErrorType.malformed, "the inner JWS must carry a jwk header, not a kid")
    if "nonce" in jws.protected:
        raise AcmeError(ErrorType.malformed, "the inner JWS must not carry a nonce")
    if jws.protected.get("url") != url:
        raise AcmeError(
            ErrorType.malformed, "the inner JWS url header does not match the outer one"
        )
    key = load_account_key(jws.protected["jwk"], alg)
    if not key.verify(jws.signing_input, jws.signature):
        raise AcmeError(ErrorType.malformed, "the inner JWS signature does not verify")
    payload = _payload(jws.payload_b64)
    if payload is None:
        raise AcmeError(ErrorType.malformed, "the inner JWS has no payload")
    return key, payload
