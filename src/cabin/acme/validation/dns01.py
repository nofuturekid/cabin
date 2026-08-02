"""dns-01 (spec 0011 FR-5, RFC 8555 8.4).

Look up TXT records at ``_acme-challenge.<identifier>`` and accept if any of
them is the base64url SHA-256 of the key authorization.

*Any* of them, not the only one: a name whose wildcard and whose base
certificate are being renewed at the same time legitimately has two records
under that label, and rejecting the second one would make simultaneous
orders a race.

Not applicable to IP identifiers -- an address has no zone to hold a record
(RFC 8738 4). Spec 0010 already declines to offer the challenge for one; the
check below is the backstop for a challenge id that arrives anyway.

Failures are told apart on purpose: "the name does not exist", "it exists
with no TXT record", "the resolver did not answer" and "a record is there
but says something else" have four different fixes, and an operator reading
the challenge's error field should not have to guess which one happened.
"""

import hmac

import dns.exception
import dns.rdatatype
import dns.resolver

from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.validation import keyauth
from cabin.acme.validation.targets import Attempt, Deadline

#: RFC 8555 8.4: the label the record lives under.
LABEL = "_acme-challenge"


def lookup_txt(name: str, resolvers: tuple[str, ...], timeout: float) -> list[str]:
    """Every TXT record at ``name``, asked for within ``timeout`` seconds.

    The seam the tests replace -- it is the only function in this package
    that sends a DNS query. ``resolvers`` overrides the system configuration
    (FR-5); empty means "whatever this host resolves with", which on a
    machine that already knows the internal zone is the right answer.
    ``timeout`` is what is left of the attempt's budget (FR-3): dnspython's
    own default lifetime would let a resolver that never answers outlive it.

    A TXT record is a sequence of character-strings; RFC 1035 says a reader
    concatenates them, which matters because a base64url digest is 43 bytes
    and safely under the 255-byte split, but a zone file can still break it
    up.
    """
    resolver = dns.resolver.Resolver()
    if resolvers:
        resolver.nameservers = list(resolvers)
    answer = resolver.resolve(name, dns.rdatatype.TXT, lifetime=timeout)
    return [
        b"".join(record.strings).decode("utf-8", errors="replace") for record in answer.rrset or []
    ]


def validate(attempt: Attempt) -> None:
    """Prove control of ``attempt`` through DNS, or raise :class:`AcmeError`."""
    if attempt.identifier_type != "dns":
        raise AcmeError(
            ErrorType.malformed,
            f"dns-01 cannot prove control of a {attempt.identifier_type} identifier",
        )
    # The authorization already carries the base name for a wildcard order
    # (spec 0010 stores ``base_value``), so there is no "*." to strip here --
    # which is why a wildcard and its base name share one TXT record, as
    # RFC 8555 8.4 describes.
    name = f"{LABEL}.{attempt.identifier_value}"
    records = _records(name, attempt.resolvers, attempt.deadline())
    expected = keyauth.dns_value(attempt.key_authorization).encode("utf-8")
    for record in records:
        # Constant time, and over bytes: compare_digest on two str objects
        # raises for anything non-ASCII, and a TXT record is arbitrary text.
        if hmac.compare_digest(record.encode("utf-8"), expected):
            return
    raise AcmeError(
        ErrorType.incorrect_response,
        f"no TXT record at {name} matches the key authorization ({len(records)} found)",
    )


def _records(name: str, resolvers: tuple[str, ...], deadline: Deadline) -> list[str]:
    try:
        return lookup_txt(name, resolvers, deadline.check(name, ErrorType.dns))
    except dns.resolver.NXDOMAIN as exc:
        raise AcmeError(ErrorType.dns, f"{name} does not exist (NXDOMAIN)") from exc
    except dns.resolver.NoAnswer as exc:
        raise AcmeError(ErrorType.dns, f"{name} exists but has no TXT record") from exc
    except dns.exception.Timeout as exc:
        raise AcmeError(
            ErrorType.dns,
            f"the DNS lookup for {name} timed out after {deadline.budget:g} seconds",
        ) from exc
    except dns.exception.DNSException as exc:
        raise AcmeError(
            ErrorType.dns,
            f"the DNS lookup for {name} failed: {type(exc).__name__}",
        ) from exc
