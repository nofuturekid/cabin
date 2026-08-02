"""The key authorization (spec 0011 FR-1, RFC 8555 8.1).

One string ties a challenge token to the account key that asked for it, and
all three validation methods are built on it: http-01 serves it verbatim,
dns-01 publishes its SHA-256 digest, tls-alpn-01 puts the same digest in a
certificate extension. Deriving it in one place is what makes "the same
proof, three transports" true rather than merely intended.

Why it is built this way: the token alone would be a bearer secret anyone
who saw it could satisfy, and the thumbprint alone would be the same for
every challenge. Concatenated, a proof is worth nothing to another account
and nothing for another challenge.
"""

import base64
import hashlib


def _b64(data: bytes) -> str:
    """base64url without padding -- JOSE's encoding, and the one RFC 8555
    uses for both halves of this string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def key_authorization(token: str, thumbprint: str) -> str:
    """RFC 8555 8.1: ``token || '.' || base64url(Thumbprint(accountKey))``.

    ``thumbprint`` is the account's stored RFC 7638 thumbprint, which is
    already the base64url SHA-256 of the canonical JWK (see
    :mod:`cabin.acme.jws`) -- so this is a concatenation and not a second
    round of hashing.
    """
    return f"{token}.{thumbprint}"


def digest(authorization: str) -> bytes:
    """SHA-256 of the key authorization: what tls-alpn-01 compares against
    the certificate extension (RFC 8737 3)."""
    return hashlib.sha256(authorization.encode("utf-8")).digest()


def dns_value(authorization: str) -> str:
    """What the TXT record must contain (RFC 8555 8.4): the base64url of
    that same digest."""
    return _b64(digest(authorization))
