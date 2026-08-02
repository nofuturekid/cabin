"""Reading a finalization CSR and checking it against the order it belongs
to (spec 0012 FR-1, RFC 8555 7.4).

Pure: no database, no HTTP, no issuance. What it enforces is one sentence
from the RFC -- "the CSR MUST indicate the exact same set of requested
identifiers as the initial newOrder request" -- and the whole point of
putting it here is that "exact same set" is decided in one place, with one
notion of what makes two names equal.

Three of those notions are not obvious and are the reason this is a module
and not four lines in the route:

* **DNS names compare case-insensitively.** ``NAS.LAN`` and ``nas.lan`` are
  the same name, and an order already stores identifiers folded to lower
  case (:mod:`cabin.acme.service`), so the CSR is folded the same way.
* **IP addresses compare as addresses.** ``192.168.001.010``,
  ``192.168.1.10`` and ``::ffff:c0a8:010a`` are text a client might send;
  :mod:`ipaddress` is what decides whether two of them are one host.
* **A wildcard is just a name here.** ``*.example.com`` in the order matches
  ``*.example.com`` in the CSR and nothing else -- in particular it does not
  match ``www.example.com``, because the client asked for the wildcard and
  the wildcard is what it must prove and receive.

Every rejection is a ``badCSR`` that names the offending value. "Your CSR
does not match" is not something a client can act on; "your CSR also asks
for evil.lan" is.
"""

import ipaddress
from collections.abc import Iterable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from cabin.acme import jws
from cabin.acme.errors import AcmeError, ErrorType

#: How much of an attacker-supplied name an error message repeats back.
_MAX_ECHO = 100
#: Cap on the CSR itself. A DER CSR with a hundred SANs and an RSA-4096 key
#: is a few kilobytes; anything past this is not a certificate request.
MAX_CSR_BYTES = 64 * 1024

#: The curves cabin will certify -- the same two :mod:`cabin.acme.jws`
#: accepts for an account key. A client that could not have registered with
#: a key has no business being issued a certificate on one.
CURVES = ("secp256r1", "secp384r1")


def _bad(detail: str) -> AcmeError:
    return AcmeError(ErrorType.bad_csr, detail[:400])


def _echo(value: str) -> str:
    return value if len(value) <= _MAX_ECHO else f"{value[:_MAX_ECHO]}..."


def _check_public_key(csr: x509.CertificateSigningRequest) -> None:
    """The key strength floor, which is the account key's floor.

    :data:`cabin.acme.jws.MIN_RSA_BITS` guards the key a client *signs*
    with; this guards the one it asks cabin to *certify* -- the one relying
    parties will trust for a year. Leaving the second unguarded made the
    policy exactly backwards: a 1024-bit RSA account key was refused, and
    the same key in a CSR came back signed by cabin's CA.
    """
    key = csr.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < jws.MIN_RSA_BITS:
            raise _bad(f"an RSA key must be at least {jws.MIN_RSA_BITS} bits, not {key.key_size}")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in CURVES:
            raise _bad(
                f"cabin does not issue certificates on the {key.curve.name} curve: "
                "use P-256 or P-384"
            )
    elif not isinstance(key, ed25519.Ed25519PublicKey):
        raise _bad("cabin issues certificates for RSA, P-256, P-384 and Ed25519 keys only")


def load(der: bytes) -> x509.CertificateSigningRequest:
    """Parse a finalization CSR, check it signed itself, and check its key.

    The signature proves the requester holds the private key of the key it
    is asking cabin to certify -- without it, a client could have cabin
    certify a public key belonging to someone else entirely.
    """
    if len(der) > MAX_CSR_BYTES:
        raise _bad("the CSR is too large")
    try:
        csr = x509.load_der_x509_csr(der)
    except ValueError as exc:
        raise _bad(f"the CSR is not a valid DER PKCS#10 request: {exc}") from exc
    try:
        valid = csr.is_signature_valid
    except (ValueError, TypeError) as exc:
        # An unsupported signature algorithm raises rather than answering
        # False, and a request cabin cannot check is one it must not honour.
        raise _bad(f"the CSR's signature could not be checked: {exc}") from exc
    if not valid:
        raise _bad("the CSR's signature does not verify against its own public key")
    _check_public_key(csr)
    return csr


def _normalize(kind: str, value: str) -> str:
    """One comparable token per name. The type is part of it, so a DNS name
    and an IP address that happen to read alike can never match."""
    if kind == "ip":
        try:
            return f"ip:{ipaddress.ip_address(value)}"
        except ValueError:
            return f"ip:{value.lower()}"
    return f"dns:{value.lower()}"


def identifier_tokens(identifiers: Iterable[dict[str, str]]) -> dict[str, str]:
    """The order's identifiers as ``token -> value as the client wrote it``.

    The value is kept so a rejection can quote what was ordered rather than
    the normalized form, which the client never sent.
    """
    return {_normalize(entry["type"], entry["value"]): entry["value"] for entry in identifiers}


def _san_tokens(csr: x509.CertificateSigningRequest) -> dict[str, str]:
    try:
        extensions = csr.extensions
    except ValueError as exc:
        raise _bad(f"the CSR's extensions could not be read: {exc}") from exc
    try:
        san = extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return {}
    tokens: dict[str, str] = {}
    for name in san:
        if isinstance(name, x509.DNSName):
            tokens[_normalize("dns", name.value)] = name.value
        elif isinstance(name, x509.IPAddress):
            tokens[_normalize("ip", str(name.value))] = str(name.value)
        else:
            # An order can only ever have asked for a DNS name or an IP
            # (RFC 8555 9.7.7, RFC 8738), so any other GeneralName is a name
            # nobody authorized -- dropping it silently would put it in the
            # certificate, since the SAN list is rebuilt from the order.
            raise _bad(f"the CSR carries a subjectAltName cabin does not issue: {name!r}"[:400])
    return tokens


def _common_name(csr: x509.CertificateSigningRequest) -> str | None:
    attributes = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attributes:
        return None
    value = attributes[0].value
    if not isinstance(value, str):
        raise _bad("the CSR's subject common name is not a text value")
    return value


def check_identifiers(
    csr: x509.CertificateSigningRequest, identifiers: Sequence[dict[str, str]]
) -> None:
    """RFC 8555 7.4: the CSR's names must be exactly the order's names.

    Raises ``badCSR`` naming the first name that is wrong -- extra, missing,
    or a common name nobody authorized.
    """
    ordered = identifier_tokens(identifiers)
    requested = _san_tokens(csr)

    extra = sorted(requested.keys() - ordered.keys())
    if extra:
        raise _bad(
            "the CSR asks for names this order did not authorize: "
            + ", ".join(_echo(requested[token]) for token in extra)
        )
    missing = sorted(ordered.keys() - requested.keys())
    if missing:
        raise _bad(
            "the CSR is missing names this order asked for: "
            + ", ".join(_echo(ordered[token]) for token in missing)
        )

    common_name = _common_name(csr)
    if common_name is None:
        return
    # RFC 8555 7.4 allows the CN to carry one of the identifiers; it does not
    # allow it to introduce a new one. A CN is still a name a relying party
    # may look at, so an unauthorized one is refused rather than dropped.
    tokens = (_normalize("dns", common_name), _normalize("ip", common_name))
    if not any(token in ordered for token in tokens):
        raise _bad(
            "the CSR's subject common name is not one of the order's identifiers: "
            f"{_echo(common_name)}"
        )
