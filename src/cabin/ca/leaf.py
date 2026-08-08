"""Pure X.509 leaf issuance: profiles, SAN policy, server-side key
generation and CSR signing (spec 0005 FR-1..FR-4).

No FastAPI or database imports here -- this module only deals with
pyca/cryptography objects and PEM bytes. Storage of the results (and
sealing of server-generated keys) lives in :mod:`cabin.ca.certs`.
"""

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from cabin.ca.x509 import (
    KEY_TYPES,
    authority_key_identifier,
    generate_key,
    signing_algorithm,
)


def public_http_origin(base_url: str) -> str:
    """The public HTTP origin a CDP/AIA URL is built on top of (spec 0017
    FR-12): scheme forced to ``http``, an explicit ``:443`` dropped,
    everything else -- host, any other port, path -- left exactly as
    configured.

    A relying party validating a cabin certificate would otherwise need to
    fetch its CRL over TLS, which needs a certificate that has already been
    validated. Forcing the scheme here, in the one place both
    ``crl.distribution_url`` and ``crl.ca_issuers_url`` call, is what keeps
    that from happening -- rather than each of them reimplementing it and
    the two answers drifting apart.
    """
    parts = urlsplit(base_url)
    netloc = parts.netloc
    if netloc.endswith(":443"):
        netloc = netloc[: -len(":443")]
    return urlunsplit(("http", netloc, parts.path, "", ""))


def _authority_information_access(ca_issuers_url: str) -> x509.AuthorityInformationAccess:
    """FR-11: one non-critical AIA extension with exactly one ``caIssuers``
    access description, built the same way :func:`_crl_distribution_points`
    (below) builds the CDP."""
    return x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(ca_issuers_url),
            )
        ]
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

#: Public because the API's request models mirror the same limit (spec 0008
#: FR-5) and must not be allowed to drift from the one enforced here.
MAX_CN_LENGTH = 64
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


class NameConstraintError(IssueError):
    """A name is outside the issuer's name constraints, or a constraint
    entry is not one cabin can express (spec 0020 FR-8). A subclass of
    ``IssueError`` so every existing door already refuses it with no
    change and no possibility of one being forgotten; distinguished only
    so ACME's finalize can answer ``rejectedIdentifier`` instead of
    ``serverInternal``."""


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


def _resolve_sans(
    explicit: Sequence[str], csr_sans: Sequence[str], subject_cn: str | None
) -> list[str]:
    """FR-3's ladder: explicit SANs win, then the CSR's, then the CN.

    The winning rung is de-duplicated here, so "nas.lan" and "dns:nas.lan"
    in one request produce a single SAN entry -- otherwise the certificate
    would carry a name twice while the stored SAN list (which de-duplicates)
    disagrees with it.
    """
    chosen = list(explicit) or list(csr_sans)
    if not chosen:
        fallback = None if subject_cn is None else _san_from_cn(subject_cn)
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
    if len(cn) > MAX_CN_LENGTH:
        raise IssueError(f"subject CN must be at most {MAX_CN_LENGTH} characters")
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


# --- Spec 0020: name constraints ------------------------------------------------
#
# The constraint type, its parser, the extension builder, the reader and the
# matcher all live here rather than in ``cabin.ca.x509``: this module already
# imports ``x509.py``, and the reverse would be a cycle -- and
# ``NameConstraintError`` must subclass ``IssueError`` (above) for FR-8 to
# hold. ``ca/x509.py`` only ever receives the finished
# ``x509.NameConstraints`` object this module builds.


@dataclass(frozen=True)
class NameConstraintSpec:
    """Operator intent for one intermediate's ``NameConstraints`` extension,
    already validated and normalised (FR-3): DNS suffixes lower-cased with
    any leading dot stripped, IP entries as networks with no host bits set.

    Frozen and tuple-valued so a spec cannot be mutated between the moment
    it is parsed and the moment it is signed into a certificate.
    """

    permitted_dns: tuple[str, ...] = ()
    permitted_ip: tuple[IPv4Network | IPv6Network, ...] = ()
    excluded_dns: tuple[str, ...] = ()
    excluded_ip: tuple[IPv4Network | IPv6Network, ...] = ()

    def is_empty(self) -> bool:
        return not (
            self.permitted_dns or self.permitted_ip or self.excluded_dns or self.excluded_ip
        )


#: FR-3's sanity cap, one per side -- the same kind of bound MAX_SANS is, so
#: one form post cannot mint a multi-megabyte CA certificate.
MAX_NAME_CONSTRAINTS = 50


def _parse_ip_entry(entry: str) -> IPv4Network | IPv6Network | None:
    """``entry`` as a name-constraint iPAddress subtree, or ``None`` when it
    is not an IP entry at all (the caller then tries it as a hostname).

    A bare address becomes its own ``/32``/``/128`` -- a name-constraint
    ``iPAddress`` general name is a network, never a bare address, and a
    bare address would encode to half the required DER length. An address
    with host bits set (``10.1.2.3/8``) is refused rather than silently
    widened by ``strict=False``, which would turn what the operator typed
    into a constraint an order of magnitude wider.
    """
    try:
        address = ipaddress.ip_address(entry)
    except ValueError:
        address = None
    if address is not None:
        bits = 32 if address.version == 4 else 128
        return ipaddress.ip_network(f"{entry}/{bits}")
    if "/" not in entry:
        return None
    try:
        return ipaddress.ip_network(entry, strict=True)
    except ValueError as exc:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return None  # not an IP network either -- try it as a hostname
        raise NameConstraintError(
            f"{entry!r} has host bits set -- this would be silently widened to a "
            "wider network than what was typed; use the network address instead"
        ) from exc


def _parse_entry(entry: str) -> str | IPv4Network | IPv6Network:
    """One non-blank operator line -> a dNSName suffix or an iPAddress
    network (FR-3). Raises :class:`NameConstraintError`, naming ``entry``,
    for anything that would mean something other than what the operator
    read into it: a wildcard, an empty name, or text that is neither a
    hostname nor an IP entry.
    """
    if entry.startswith("*."):
        raise NameConstraintError(
            f"{entry!r} is a wildcard, which is not a name-constraint entry -- a "
            "subtree already means 'this name and everything below it'"
        )
    network = _parse_ip_entry(entry)
    if network is not None:
        return network
    # The leading-dot spelling is common in OpenSSL configuration and means
    # the same subtree as the bare hostname -- not a hostname with an empty
    # first label.
    dns_value = entry[1:] if entry.startswith(".") else entry
    if not dns_value or not _is_hostname(dns_value):
        raise NameConstraintError(f"not a valid name-constraint entry: {entry!r}")
    return dns_value.lower()


def _parse_side(text: str) -> tuple[tuple[str, ...], tuple[IPv4Network | IPv6Network, ...]]:
    dns: list[str] = []
    ips: list[IPv4Network | IPv6Network] = []
    for line in text.splitlines():
        entry = line.strip()
        if not entry:
            continue
        parsed = _parse_entry(entry)
        if isinstance(parsed, str):
            dns.append(parsed)
        else:
            ips.append(parsed)
    total = len(dns) + len(ips)
    if total > MAX_NAME_CONSTRAINTS:
        raise NameConstraintError(
            f"at most {MAX_NAME_CONSTRAINTS} name-constraint entries are allowed on "
            f"one side; found {total}"
        )
    return tuple(dns), tuple(ips)


def parse_name_constraints(permitted: str, excluded: str) -> NameConstraintSpec:
    """The two form fields -- one entry per line, blank lines ignored -- ->
    a validated :class:`NameConstraintSpec` (FR-3). The only place operator
    text becomes a constraint; raises :class:`NameConstraintError` naming
    the offending line.
    """
    permitted_dns, permitted_ip = _parse_side(permitted)
    excluded_dns, excluded_ip = _parse_side(excluded)
    return NameConstraintSpec(
        permitted_dns=permitted_dns,
        permitted_ip=permitted_ip,
        excluded_dns=excluded_dns,
        excluded_ip=excluded_ip,
    )


def name_constraints_extension(spec: NameConstraintSpec) -> x509.NameConstraints | None:
    """``spec`` -> a critical ``NameConstraints`` extension value, or
    ``None`` for an empty spec (FR-2).

    ``None``, not an extension with two empty subtree lists:
    ``cryptography`` raises for an empty list on either side, and RFC 5280
    4.2.1.10 forbids an extension with both sides absent -- so "no
    constraints" has to mean no extension at all, never an empty one. A
    side with no entries of its own becomes ``None``, not ``[]``, for the
    same reason.
    """
    if spec.is_empty():
        return None
    permitted: list[x509.GeneralName] = [
        *(x509.DNSName(name) for name in spec.permitted_dns),
        *(x509.IPAddress(network) for network in spec.permitted_ip),
    ]
    excluded: list[x509.GeneralName] = [
        *(x509.DNSName(name) for name in spec.excluded_dns),
        *(x509.IPAddress(network) for network in spec.excluded_ip),
    ]
    return x509.NameConstraints(
        permitted_subtrees=permitted or None,
        excluded_subtrees=excluded or None,
    )


def constraints_of(cert: x509.Certificate) -> NameConstraintSpec:
    """The dNSName/iPAddress subtrees ``cert`` carries, read back from its
    own ``NameConstraints`` extension -- the one reader, used by
    :func:`check_name_constraints`, by ``x509.py:renew_certificate``'s
    carry-over check and by ``/ca``'s row view, so none of the three can
    describe an issuer differently from the others.

    Returns an empty spec for a certificate with no such extension. Only
    the forms this spec implements are returned; a subtree of a form it
    does not (``rfc822Name``, ``directoryName``, ...) is invisible here and
    handled separately by :func:`check_name_constraints` (FR-5 rule 8).
    """
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return NameConstraintSpec()
    permitted = nc.permitted_subtrees or []
    excluded = nc.excluded_subtrees or []
    return NameConstraintSpec(
        permitted_dns=tuple(gn.value.lower() for gn in permitted if isinstance(gn, x509.DNSName)),
        permitted_ip=tuple(
            gn.value
            for gn in permitted
            if isinstance(gn, x509.IPAddress) and isinstance(gn.value, IPv4Network | IPv6Network)
        ),
        excluded_dns=tuple(gn.value.lower() for gn in excluded if isinstance(gn, x509.DNSName)),
        excluded_ip=tuple(
            gn.value
            for gn in excluded
            if isinstance(gn, x509.IPAddress) and isinstance(gn.value, IPv4Network | IPv6Network)
        ),
    )


def _dns_within(name: str, constraint: str) -> bool:
    """FR-5 rule 4: label-boundary match, both sides already lower-cased by
    the caller. ``name.endswith(constraint)`` is the classic mistake this
    avoids -- it would let ``badexample.com`` through under ``example.com``.
    """
    return name == constraint or name.endswith(f".{constraint}")


def _check_dns(
    name: str,
    permitted: Sequence[x509.GeneralName],
    excluded: Sequence[x509.GeneralName],
) -> None:
    lname = name.lower()
    permitted_dns = [gn.value for gn in permitted if isinstance(gn, x509.DNSName)]
    excluded_dns = [gn.value for gn in excluded if isinstance(gn, x509.DNSName)]

    excluded_hit = next((c for c in excluded_dns if _dns_within(lname, c.lower())), None)
    if excluded_hit is not None:
        raise NameConstraintError(
            f"{name} is excluded by this CA's name constraints (excluded DNS: {excluded_hit})"
        )
    if permitted_dns and not any(_dns_within(lname, c.lower()) for c in permitted_dns):
        allowed = ", ".join(permitted_dns)
        raise NameConstraintError(
            f"{name} is not permitted by this CA's name constraints (permitted DNS: {allowed})"
        )


def _check_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    permitted: Sequence[x509.GeneralName],
    excluded: Sequence[x509.GeneralName],
) -> None:
    """FR-5 rule 6: containment in a real network, never an address-string
    prefix comparison -- and the iPAddress form covers both families, so an
    IPv6 address is never inside an IPv4 network (or the reverse)."""
    permitted_ip = [
        gn.value
        for gn in permitted
        if isinstance(gn, x509.IPAddress) and isinstance(gn.value, IPv4Network | IPv6Network)
    ]
    excluded_ip = [
        gn.value
        for gn in excluded
        if isinstance(gn, x509.IPAddress) and isinstance(gn.value, IPv4Network | IPv6Network)
    ]

    excluded_hit = next((net for net in excluded_ip if address in net), None)
    if excluded_hit is not None:
        raise NameConstraintError(
            f"{address} is excluded by this CA's name constraints (excluded IP: {excluded_hit})"
        )
    if permitted_ip and not any(address in net for net in permitted_ip):
        allowed = ", ".join(str(net) for net in permitted_ip)
        raise NameConstraintError(
            f"{address} is not permitted by this CA's name constraints (permitted IP: {allowed})"
        )


def _check_unevaluable(
    san: str,
    value: str,
    gn_type: type[x509.GeneralName],
    label: str,
    permitted: Sequence[x509.GeneralName],
    excluded: Sequence[x509.GeneralName],
) -> None:
    """FR-5 rule 8: a name form cabin cannot evaluate is refused, not
    ignored. An imported intermediate may legitimately carry a subtree of a
    form this spec does not implement (``rfc822Name``, ``directoryName``,
    ``uniformResourceIdentifier``, ``otherName``); a leaf carrying a SAN of
    that same form is refused rather than treated as unconstrained, because
    cabin has no implementation to judge it against -- refusing is the
    conservative direction, and the alternative is issuing a certificate
    whose acceptance cabin has no opinion about.
    """
    if any(isinstance(gn, gn_type) for gn in (*permitted, *excluded)):
        raise NameConstraintError(
            f"{san} cannot be evaluated against this CA's name constraints: cabin "
            f"does not implement {label} subtrees (value: {value})"
        )


def check_name_constraints(
    issuer_cert: x509.Certificate, subject_cn: str | None, sans: Sequence[str]
) -> None:
    """FR-4/FR-5: refuse a leaf that falls outside ``issuer_cert``'s own
    ``NameConstraints`` extension. Called from :func:`_build_leaf`, after
    the validity clamp and before ``builder.sign(...)`` -- the one place
    both :func:`issue_certificate` and :func:`sign_csr` converge, so every
    front door gets this check with nothing to forget.

    Takes no database, no settings and no issuer id: a pure function of a
    certificate and the names being asked for, so most of FR-5 is measured
    directly against it rather than behind an HTTP client.

    An issuer certificate with no ``NameConstraints`` extension permits
    everything, and this returns immediately -- the cost on the
    unconstrained path is one ``get_extension_for_class`` call.
    """
    try:
        nc = issuer_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return

    permitted = nc.permitted_subtrees or []
    excluded = nc.excluded_subtrees or []

    # FR-5 rule 7: the CN is checked as a dNSName only when the SAN list
    # carries no DNS entry at all -- exactly what OpenSSL's
    # NAME_CONSTRAINTS_check_CN does, which is the validator cabin's own
    # check must agree with (FR-7).
    has_dns_san = any(san.startswith("DNS:") for san in sans)
    names = list(sans)
    if not has_dns_san and subject_cn is not None and _is_hostname(subject_cn):
        names.append(f"DNS:{subject_cn}")

    for name in names:
        kind, _, entry_value = name.partition(":")
        if kind == "DNS":
            _check_dns(entry_value, permitted, excluded)
        elif kind == "IP":
            _check_ip(ipaddress.ip_address(entry_value), permitted, excluded)
        elif kind == "EMAIL":
            _check_unevaluable(
                name, entry_value, x509.RFC822Name, "rfc822Name", permitted, excluded
            )


def _build_leaf(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    public_key: CertificatePublicKeyTypes,
    subject_cn: str | None,
    sans: Sequence[str],
    profile: Profile,
    days: int,
    crl_url: str | None = None,
    ca_issuers_url: str | None = None,
) -> tuple[x509.Certificate, datetime | None]:
    """The single place a leaf certificate is assembled: both flows build
    the same extension set from scratch, which is what keeps CSR extensions
    from leaking into an issued certificate (FR-1/FR-2).

    ``crl_url`` adds a CRL distribution point (spec 0007 FR-6); ``ca_issuers_url``
    adds an AIA ``caIssuers`` access description the same way (spec 0017
    FR-11). Without one, the corresponding extension is left out entirely
    rather than pointing somewhere that does not answer.

    ``subject_cn=None`` builds an empty subject, for a name too long to be a
    common name (see :func:`sign_csr`). RFC 5280 4.2.1.6 then requires the
    subjectAltName to be critical -- with no subject it is the only name the
    certificate has, so a relying party that skipped it would be trusting a
    certificate that says nothing about who it is for.

    Returns ``(certificate, capped_from)`` -- spec 0017 FR-7. ``capped_from``
    is the ``not_after`` that was asked for but not granted because the
    issuer's own expiry was sooner, and ``None`` when the full request was
    met. This is the only place that holds both the requested ``days`` and
    the ``now`` the clamp is measured against, so it is also the only place
    that can answer "was this clamped" -- callers must not re-derive it from
    ``cert.not_valid_after_utc == issuer_cert.not_valid_after_utc``, which
    would silently go wrong the moment the issuer itself is renewed to a
    later expiry (spec 0017 FR-5).
    """
    now = datetime.now(UTC)
    requested_not_after = now + timedelta(days=days)
    # FR-4: a leaf must never outlive the CA that signed it.
    not_after = min(requested_not_after, issuer_cert.not_valid_after_utc)
    if not_after <= now:
        raise IssueError("the signing CA certificate has expired")
    capped_from = requested_not_after if requested_not_after > not_after else None

    # Spec 0020 FR-4: beside the SAN validation this function already does,
    # and before anything is signed. Takes no parameter of its own --
    # ``issuer_cert`` and ``sans`` are already in scope -- so there is
    # nothing a caller can forget to pass and no door that can add itself
    # later without this check coming with it.
    check_name_constraints(issuer_cert, subject_cn, sans)

    subject = [] if subject_cn is None else [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject))
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
            critical=subject_cn is None,
        )
    )
    if crl_url:
        builder = builder.add_extension(_crl_distribution_points(crl_url), critical=False)
    if ca_issuers_url:
        builder = builder.add_extension(
            _authority_information_access(ca_issuers_url), critical=False
        )
    cert = builder.sign(issuer_key, algorithm=signing_algorithm(issuer_key))
    return cert, capped_from


def issue_certificate(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    profile: Profile,
    subject_cn: str,
    sans: Sequence[str],
    days: int = DEFAULT_DAYS,
    key_type: str = "ecdsa-p256",
    crl_url: str | None = None,
    ca_issuers_url: str | None = None,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes, datetime | None]:
    """Generate a key server-side and issue a leaf for it (FR-2).

    Returns ``(certificate, private_key, capped_from)`` -- see
    :func:`_build_leaf` for ``capped_from`` (spec 0017 FR-7). The caller is
    responsible for sealing the key before it touches any storage.
    """
    cn = _validate_cn(subject_cn)
    _validate_days(days)
    if key_type not in KEY_TYPES:
        raise IssueError(f"unsupported key type: {key_type!r}")
    resolved = _resolve_sans([_normalize_san(san) for san in sans], [], cn)
    key = generate_key(key_type)
    cert, capped_from = _build_leaf(
        issuer_cert,
        issuer_key,
        key.public_key(),
        cn,
        resolved,
        profile,
        days,
        crl_url,
        ca_issuers_url,
    )
    return cert, key, capped_from


def self_signed_server_certificate(
    subject_cn: str,
    sans: Sequence[str],
    key_type: str = "ecdsa-p256",
    days: int = 90,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """Spec 0022 FR-4: stage 1's certificate, generated before any CA
    exists so cabin has something to serve at first start.

    Reuses this module's SAN normalisation and validation and the
    ``server`` profile's KeyUsage/EKU, so a stage-1 certificate looks, to
    everything but its issuer, like an ordinary server leaf --
    ``BasicConstraints(ca=False)``, the same digitalSignature KeyUsage and
    serverAuth EKU :func:`issue_certificate` gives the ``server`` profile,
    and the same ``_BACKDATE``. It carries no CRL distribution point and no
    AIA: there is no CRL that would cover a certificate with no issuer to
    revoke it. Not stored in the ``certificates`` table -- that is the
    caller's decision (FR-4), not this pure function's.
    """
    cn = _validate_cn(subject_cn)
    resolved = _resolve_sans([_normalize_san(san) for san in sans], [], cn)
    key = generate_key(key_type)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(Profile.server, key.public_key()), critical=True)
        .add_extension(x509.ExtendedKeyUsage([_PROFILE_EKU[Profile.server]]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([_general_name(san) for san in resolved]),
            critical=False,
        )
        .sign(key, algorithm=signing_algorithm(key))
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
    ca_issuers_url: str | None = None,
    subject_cn_fallback: str | None = None,
    allow_empty_subject: bool = False,
) -> tuple[x509.Certificate, datetime | None]:
    """Sign a pasted CSR (FR-2).

    The CSR contributes exactly three things: its public key, its subject
    CN, and -- unless ``sans_override`` is given -- its SAN entries. Every
    other extension it carries is ignored, so a CSR cannot talk cabin into
    issuing a CA certificate.

    ``subject_cn_fallback`` names the subject when the CSR has none. A
    subject-less CSR is not a broken one: RFC 8555 7.4 lets an ACME client
    put its names in the SAN extension alone, and the certbot library does
    exactly that. Only a caller that already knows which names it authorized
    may supply it -- for the pasted-CSR forms of spec 0005 there is nothing
    to fall back to, so they keep refusing (and this stays None).

    ``allow_empty_subject`` is the same caller saying "and if you have no
    fallback either, issue it anyway". It only makes sense together with
    ``sans_override``: the names then live entirely in the SAN, which is
    what a relying party checks -- and it is the only way to certify a name
    longer than a common name's 64 characters, which ACME can order and a
    subject cannot hold.

    Returns ``(certificate, capped_from)`` -- see :func:`_build_leaf` for
    ``capped_from`` (spec 0017 FR-7).
    """
    _validate_days(days)
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise IssueError(f"not a valid CSR PEM: {exc}") from exc
    if not csr.is_signature_valid:
        raise IssueError("the CSR's signature is not valid")

    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    raw_cn: object = common_names[0].value if common_names else subject_cn_fallback
    cn: str | None = None
    if raw_cn is None:
        if not allow_empty_subject:
            raise IssueError("the CSR has no subject common name")
    elif not isinstance(raw_cn, str):
        raise IssueError("the CSR's subject common name is not a text value")
    else:
        cn = _validate_cn(raw_cn)

    explicit = [_normalize_san(san) for san in sans_override] if sans_override else []
    resolved = _resolve_sans(explicit, _csr_sans(csr), cn)
    return _build_leaf(
        issuer_cert,
        issuer_key,
        csr.public_key(),
        cn,
        resolved,
        profile,
        days,
        crl_url,
        ca_issuers_url,
    )
