"""tls-alpn-01 (spec 0011 FR-6, RFC 8737).

Open a TLS connection to port 443 of the identifier, insist on the
``acme-tls/1`` protocol, and look at the certificate the server presents:
it must name the identifier and carry a *critical* ``id-pe-acmeIdentifier``
extension whose payload is the SHA-256 of the key authorization.

The chain is deliberately not verified. That is not a shortcut: the
certificate here is a signed message, not a credential -- it is self-signed
by definition (the client is asking for its first certificate) and its only
job is to carry a digest that only the account key holder could compute.
What *is* checked, in order:

* the negotiated protocol is exactly ``acme-tls/1`` -- without it this is
  just some TLS server, and RFC 8737 3 requires a server that understands
  the challenge to select it;
* the certificate names the identifier (RFC 8737 3), so a certificate
  captured from another host cannot be replayed;
* the extension is present and **critical**, so a server that does not
  understand it cannot present it by accident;
* the digest matches, compared in constant time.
"""

import hmac
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.validation import keyauth, targets
from cabin.acme.validation.targets import Attempt, Deadline

#: RFC 8737 3: the protocol, the port and the extension.
ACME_TLS_1 = "acme-tls/1"
PORT = 443
ACME_IDENTIFIER_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")
#: The extension's value is a DER OCTET STRING around a SHA-256 digest:
#: tag 0x04, length 0x20, then the 32 bytes. ``cryptography`` hands an
#: unknown extension over as raw DER, so the header is compared too --
#: sloppily accepting a bare digest would accept a different encoding of
#: the same claim.
_OCTET_STRING_HEADER = bytes([0x04, hashes.SHA256.digest_size])


def validate(attempt: Attempt) -> None:
    """Prove control of ``attempt`` over TLS-ALPN, or raise :class:`AcmeError`."""
    certificate = _presented_certificate(attempt, attempt.deadline())
    _assert_names(certificate, attempt)
    _assert_digest(certificate, attempt)


def _presented_certificate(attempt: Attempt, deadline: Deadline) -> x509.Certificate:
    # Module attribute, not a from-import: this is the seam the tests replace.
    endpoint = targets.resolve(attempt.identifier_value, PORT, attempt.allow_private)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # See the module docstring: the certificate is the message, not the
    # credential, and the client cannot have a trusted one yet.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols([ACME_TLS_1])
    try:
        with socket.create_connection(
            (endpoint.address, endpoint.port), timeout=deadline.check(endpoint.host)
        ) as raw:
            # The handshake runs on the socket's own timeout, so it gets what
            # is left after the connect rather than a second full budget: a
            # peer that accepts and then says nothing must not hold a
            # threadpool worker for longer than the attempt is allowed.
            raw.settimeout(deadline.check(endpoint.host, ErrorType.tls))
            with context.wrap_socket(raw, server_hostname=endpoint.sni) as tls:
                if tls.selected_alpn_protocol() != ACME_TLS_1:
                    raise AcmeError(
                        ErrorType.tls,
                        f"the server at {endpoint.netloc} did not negotiate "
                        f"the {ACME_TLS_1} protocol",
                    )
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        raise AcmeError(
            ErrorType.tls,
            f"the TLS handshake with {endpoint.netloc} failed: {type(exc).__name__}",
        ) from exc
    except TimeoutError as exc:
        raise AcmeError(
            ErrorType.connection,
            f"connecting to {endpoint.netloc} timed out after {deadline.budget:g} seconds",
        ) from exc
    except OSError as exc:
        raise AcmeError(
            ErrorType.connection,
            f"could not connect to {endpoint.netloc}: {type(exc).__name__}",
        ) from exc
    if not der:  # pragma: no cover - a completed handshake always has one
        raise AcmeError(ErrorType.tls, f"{endpoint.netloc} presented no certificate")
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:  # pragma: no cover - the stack parsed it already
        raise AcmeError(ErrorType.tls, "the presented certificate could not be read") from exc


def _assert_names(certificate: x509.Certificate, attempt: Attempt) -> None:
    """RFC 8737 3: the certificate must name the identifier being validated,
    and only through its SubjectAlternativeName -- a common name is not a
    name any more (RFC 6125 6.4.4)."""
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        names: list[str] = []
    else:
        names = [name.lower() for name in san.get_values_for_type(x509.DNSName)]
        names += [str(address) for address in san.get_values_for_type(x509.IPAddress)]
    wanted = attempt.identifier_value
    if attempt.identifier_type == "ip":
        wanted = str(ipaddress.ip_address(wanted))
    if wanted.lower() not in names:
        raise AcmeError(
            ErrorType.incorrect_response,
            f"the presented certificate does not name {wanted}",
        )


def _assert_digest(certificate: x509.Certificate, attempt: Attempt) -> None:
    try:
        extension = certificate.extensions.get_extension_for_oid(ACME_IDENTIFIER_OID)
    except x509.ExtensionNotFound as exc:
        raise AcmeError(
            ErrorType.incorrect_response,
            "the presented certificate carries no acmeIdentifier extension",
        ) from exc
    if not extension.critical:
        raise AcmeError(
            ErrorType.incorrect_response,
            "the acmeIdentifier extension of the presented certificate is not critical",
        )
    value = extension.value
    presented = value.value if isinstance(value, x509.UnrecognizedExtension) else b""
    expected = _OCTET_STRING_HEADER + keyauth.digest(attempt.key_authorization)
    if not hmac.compare_digest(presented, expected):
        raise AcmeError(
            ErrorType.incorrect_response,
            "the acmeIdentifier extension of the presented certificate does not match the "
            "key authorization",
        )
