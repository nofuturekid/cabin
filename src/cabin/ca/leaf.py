"""Pure X.509 leaf issuance: profiles, SAN policy, server-side key
generation and CSR signing (spec 0005 FR-1..FR-4).

No FastAPI or database imports here -- this module only deals with
pyca/cryptography objects and PEM bytes. Storage of the results (and
sealing of server-generated keys) lives in :mod:`cabin.ca.certs`.
"""

import ipaddress
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cabin.ca.x509 import (
    KEY_TYPES,
    authority_key_identifier,
    generate_key,
    signing_algorithm,
)

#: NotBefore is backdated so a certificate issued "now" isn't rejected by a
#: relying party whose clock is slightly behind ours (FR-1).
_BACKDATE = timedelta(minutes=5)

MIN_DAYS = 1
MAX_DAYS = 3650
DEFAULT_DAYS = 365
#: Upper bound on SAN entries per certificate -- a sanity cap, not a
#: standards limit, so one request can't mint a multi-megabyte certificate.
MAX_SANS = 100

_MAX_CN_LENGTH = 64
_MAX_HOSTNAME_LENGTH = 253

#: Pragmatic hostname check: dot-separated labels of letters/digits/hyphens
#: (no leading/trailing hyphen, at most 63 characters each -- RFC 1035),
#: optionally a ``*.`` wildcard on the leftmost label only. ASCII only: an
#: internationalized name has to be given as its A-label (punycode), which
#: is what ends up in a certificate anyway.
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_HOSTNAME_RE = re.compile(rf"^(?:\*\.)?{_LABEL}(?:\.{_LABEL})*$")

_SAN_PREFIXES = ("dns", "ip", "email")


class Profile(StrEnum):
    """Leaf profile: which EKU/KU a certificate is issued for (FR-1)."""

    server = "server"
    client = "client"


class IssueError(Exception):
    """Issuance input failed validation (bad CN/SAN/days/CSR); the message
    names the specific reason and is safe to show in the UI."""


_PROFILE_EKU = {
    Profile.server: ExtendedKeyUsageOID.SERVER_AUTH,
    Profile.client: ExtendedKeyUsageOID.CLIENT_AUTH,
}


def parse_profile(value: str) -> Profile:
    """Form value -> :class:`Profile`, raising IssueError for anything else."""
    try:
        return Profile(value)
    except ValueError as exc:
        raise IssueError(f"unknown profile: {value!r}") from exc


def _is_hostname(value: str) -> bool:
    return len(value) <= _MAX_HOSTNAME_LENGTH and _HOSTNAME_RE.match(value) is not None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_san(entry: str) -> str:
    """One SAN input line -> canonical ``DNS:``/``IP:``/``EMAIL:`` form.

    The ``dns:``/``ip:``/``email:`` prefix is optional: a bare entry is an
    IP if it parses as one, an email if it contains ``@``, else a hostname
    (FR-6). Already-canonical entries pass through unchanged.
    """
    raw = entry.strip()
    prefix, separator, rest = raw.partition(":")
    # Only treat the part before ':' as a prefix if it is one of ours --
    # otherwise "fe80::1" would be read as a prefix "fe80".
    if separator and prefix.strip().lower() in _SAN_PREFIXES:
        kind, value = prefix.strip().lower(), rest.strip()
    elif _is_ip(raw):
        kind, value = "ip", raw
    elif "@" in raw:
        kind, value = "email", raw
    else:
        kind, value = "dns", raw

    if not value:
        raise IssueError(f"empty SAN entry: {entry!r}")
    if kind == "ip" and not _is_ip(value):
        raise IssueError(f"not a valid IP address: {value!r}")
    if kind == "dns" and not _is_hostname(value):
        raise IssueError(f"not a valid hostname: {value!r}")
    if kind == "email" and ("@" not in value or any(c.isspace() for c in value)):
        raise IssueError(f"not a valid email address: {value!r}")
    return f"{kind.upper()}:{value}"


def parse_san_lines(text: str) -> list[str]:
    """One SAN per line (blank lines ignored) -> canonical SAN strings,
    de-duplicated with the input order preserved."""
    entries = [_normalize_san(line) for line in text.splitlines() if line.strip()]
    return list(dict.fromkeys(entries))


def _general_name(san: str) -> x509.GeneralName:
    kind, _, value = san.partition(":")
    if kind == "DNS":
        return x509.DNSName(value)
    if kind == "IP":
        return x509.IPAddress(ipaddress.ip_address(value))
    if kind == "EMAIL":
        return x509.RFC822Name(value)
    raise IssueError(f"unsupported SAN entry: {san!r}")


def san_strings(names: Iterable[x509.GeneralName]) -> list[str]:
    """GeneralNames -> canonical SAN strings, keeping only DNS/IP/email
    (FR-3): any other type (URI, otherName, ...) is dropped rather than
    carried over. Also used to read back what a finished certificate
    actually carries."""
    entries: list[str] = []
    for name in names:
        if isinstance(name, x509.DNSName):
            entries.append(f"DNS:{name.value}")
        elif isinstance(name, x509.IPAddress):
            entries.append(f"IP:{name.value}")
        elif isinstance(name, x509.RFC822Name):
            entries.append(f"EMAIL:{name.value}")
    return list(dict.fromkeys(entries))


def _csr_sans(csr: x509.CertificateSigningRequest) -> list[str]:
    """The CSR's DNS/IP/email SANs, run through exactly the same policy as
    form input (FR-3).

    A CSR is not a way around validation: an empty or malformed DNS name, a
    non-leftmost wildcard, an address-less RFC822 name or an IPAddress
    holding a whole *network* all fail loud here rather than being copied
    verbatim into an issued certificate (or, for a network, escaping as a
    bare ValueError later on).
    """
    try:
        extensions = csr.extensions
    except ValueError as exc:
        raise IssueError(f"could not parse the CSR's extensions: {exc}") from exc
    try:
        san = extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [_normalize_san(entry) for entry in san_strings(san)]


def _san_from_cn(subject_cn: str) -> str | None:
    """FR-3's last rung: the CN as an IP-SAN if it parses as an IP, else as
    a DNS-SAN if it is a valid hostname. IP first -- an IP literal also
    matches the hostname pattern."""
    if _is_ip(subject_cn):
        return f"IP:{subject_cn}"
    if _is_hostname(subject_cn):
        return f"DNS:{subject_cn}"
    return None


def _resolve_sans(explicit: Sequence[str], csr_sans: Sequence[str], subject_cn: str) -> list[str]:
    """FR-3's ladder: explicit SANs win, then the CSR's, then the CN.

    The winning rung is de-duplicated here, so "nas.lan" and "dns:nas.lan"
    in one request produce a single SAN entry -- otherwise the certificate
    would carry a name twice while the stored SAN list (which de-duplicates)
    disagrees with it.
    """
    chosen = list(explicit) or list(csr_sans)
    if not chosen:
        fallback = _san_from_cn(subject_cn)
        if fallback is None:
            raise IssueError("no usable SAN: give at least one SAN, or use a hostname or IP as CN")
        chosen = [fallback]
    resolved = list(dict.fromkeys(chosen))
    if len(resolved) > MAX_SANS:
        raise IssueError(f"too many SANs: at most {MAX_SANS} are allowed")
    return resolved


def _validate_cn(subject_cn: str) -> str:
    cn = subject_cn.strip()
    if not cn:
        raise IssueError("subject CN must not be empty")
    if len(cn) > _MAX_CN_LENGTH:
        raise IssueError(f"subject CN must be at most {_MAX_CN_LENGTH} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in cn):
        raise IssueError("subject CN must not contain control characters")
    return cn


def _validate_days(days: int) -> None:
    if not MIN_DAYS <= days <= MAX_DAYS:
        raise IssueError(f"days must be between {MIN_DAYS} and {MAX_DAYS}")


def _key_usage(profile: Profile, public_key: CertificatePublicKeyTypes) -> x509.KeyUsage:
    """FR-1: digitalSignature for every leaf; an RSA server leaf may also be
    used for RSA key transport, so it gets keyEncipherment as well."""
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=profile is Profile.server and isinstance(public_key, rsa.RSAPublicKey),
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _crl_distribution_points(crl_url: str) -> x509.CRLDistributionPoints:
    """Spec 0007 FR-6: one distribution point, one URI, no reason/CRLIssuer
    partitioning -- cabin serves a single full CRL."""
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _build_leaf(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    public_key: CertificatePublicKeyTypes,
    subject_cn: str,
    sans: Sequence[str],
    profile: Profile,
    days: int,
    crl_url: str | None = None,
) -> x509.Certificate:
    """The single place a leaf certificate is assembled: both flows build
    the same extension set from scratch, which is what keeps CSR extensions
    from leaking into an issued certificate (FR-1/FR-2).

    ``crl_url`` adds a CRL distribution point (spec 0007 FR-6); without one
    the extension is left out entirely rather than pointing somewhere that
    does not answer."""
    now = datetime.now(UTC)
    # FR-4: a leaf must never outlive the CA that signed it.
    not_after = min(now + timedelta(days=days), issuer_cert.not_valid_after_utc)
    if not_after <= now:
        raise IssueError("the signing CA certificate has expired")

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(profile, public_key), critical=True)
        .add_extension(x509.ExtendedKeyUsage([_PROFILE_EKU[profile]]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier(issuer_cert, issuer_key), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([_general_name(san) for san in sans]),
            critical=False,
        )
    )
    if crl_url:
        builder = builder.add_extension(_crl_distribution_points(crl_url), critical=False)
    return builder.sign(issuer_key, algorithm=signing_algorithm(issuer_key))


def issue_certificate(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    profile: Profile,
    subject_cn: str,
    sans: Sequence[str],
    days: int = DEFAULT_DAYS,
    key_type: str = "ecdsa-p256",
    crl_url: str | None = None,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """Generate a key server-side and issue a leaf for it (FR-2).

    Returns ``(certificate, private_key)``; the caller is responsible for
    sealing the key before it touches any storage.
    """
    cn = _validate_cn(subject_cn)
    _validate_days(days)
    if key_type not in KEY_TYPES:
        raise IssueError(f"unsupported key type: {key_type!r}")
    resolved = _resolve_sans([_normalize_san(san) for san in sans], [], cn)
    key = generate_key(key_type)
    cert = _build_leaf(
        issuer_cert, issuer_key, key.public_key(), cn, resolved, profile, days, crl_url
    )
    return cert, key


def sign_csr(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    csr_pem: bytes,
    profile: Profile,
    days: int = DEFAULT_DAYS,
    sans_override: Sequence[str] | None = None,
    crl_url: str | None = None,
) -> x509.Certificate:
    """Sign a pasted CSR (FR-2).

    The CSR contributes exactly three things: its public key, its subject
    CN, and -- unless ``sans_override`` is given -- its SAN entries. Every
    other extension it carries is ignored, so a CSR cannot talk cabin into
    issuing a CA certificate.
    """
    _validate_days(days)
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise IssueError(f"not a valid CSR PEM: {exc}") from exc
    if not csr.is_signature_valid:
        raise IssueError("the CSR's signature is not valid")

    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names:
        raise IssueError("the CSR has no subject common name")
    raw_cn = common_names[0].value
    if not isinstance(raw_cn, str):
        raise IssueError("the CSR's subject common name is not a text value")
    cn = _validate_cn(raw_cn)

    explicit = [_normalize_san(san) for san in sans_override] if sans_override else []
    resolved = _resolve_sans(explicit, _csr_sans(csr), cn)
    return _build_leaf(
        issuer_cert, issuer_key, csr.public_key(), cn, resolved, profile, days, crl_url
    )
