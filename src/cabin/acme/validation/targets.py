"""What a validation attempt is aimed at, and which addresses cabin will
open a socket to (spec 0011 FR-9).

Validation is the one place in cabin where a value an unauthenticated client
chose -- the identifier of an order -- decides where the server makes an
outbound connection. That is a server-side request forgery primitive by
construction, and the only useful mitigation is to look at the address
*before* connecting and to connect to the address that was looked at.

Two rules, both narrower than they may look:

* **Loopback, link-local, multicast and the unspecified address are refused
  always.** Those are the ranges where "somewhere else on the network" turns
  into "cabin itself" or "the host's metadata service" -- reaching them
  proves nothing about an identifier and is exactly what an attacker who can
  place an order would aim for.
* **Private (RFC 1918 and friends) is allowed by default**, because an
  internal CA that refused to validate ``192.168.x`` would be useless. The
  ``allow_private_validation_targets`` setting can turn it off for an
  instance that only ever issues for public names.

The whole answer is checked, not just the address that gets used: an answer
of "192.168.1.5 and 127.0.0.1" must not become a coin flip over which one
cabin talks to. And the address that survived the check is what the
validators connect to, with the identifier carried in ``Host``/SNI -- so a
second lookup cannot return something different from the one that was
approved.
"""

import ipaddress
import socket
from dataclasses import dataclass
from time import monotonic

from cabin.acme.errors import AcmeError, ErrorType

#: The budget for one validation attempt (FR-3), in seconds -- the *whole*
#: attempt, not each operation inside it. See :class:`Deadline`.
VALIDATION_TIMEOUT = 10


class Deadline:
    """One wall-clock budget, shared by every operation in an attempt.

    Per-operation timeouts do not bound an attempt, and the difference is
    not academic. A target that sends one byte a second keeps every
    individual read inside its read timeout indefinitely; five redirects,
    each a fresh connection with its own ten seconds, is a minute. And
    because validation runs in the threadpool that serves every other
    request in cabin, an attacker who can register an account -- anyone --
    could hold those threads for as long as their own server feels like
    answering slowly.

    So each validator opens one of these and asks it, before every
    operation, how much time is left; :meth:`check` refuses once there is
    none. It uses :func:`time.monotonic`, so a clock adjustment mid-attempt
    cannot extend or shorten the budget.
    """

    def __init__(self, seconds: float = VALIDATION_TIMEOUT) -> None:
        self.budget = seconds
        self._expires = monotonic() + seconds

    def remaining(self) -> float:
        return self._expires - monotonic()

    def expired(self) -> bool:
        return self.remaining() <= 0

    def check(self, what: str, kind: ErrorType = ErrorType.connection) -> float:
        """The time left, or an :class:`AcmeError` if there is none."""
        left = self.remaining()
        if left <= 0:
            raise AcmeError(kind, f"validating {what} timed out after {self.budget:g} seconds")
        return left


@dataclass(frozen=True)
class Attempt:
    """Everything a validator needs, and nothing that ties it to a database
    row: one attempt is a pure function of these fields plus what the target
    answers, which is what makes the three validators testable on their own.
    """

    identifier_type: str
    identifier_value: str
    token: str
    key_authorization: str
    #: FR-9; see the module docstring.
    allow_private: bool = True
    #: dns-01 only: resolvers to ask instead of the system's (FR-5).
    resolvers: tuple[str, ...] = ()
    #: FR-3: the budget for this attempt. A field rather than a constant so
    #: a test can ask for a short one; nothing in the app changes it.
    timeout: float = VALIDATION_TIMEOUT

    def deadline(self) -> Deadline:
        return Deadline(self.timeout)


@dataclass(frozen=True)
class Endpoint:
    """A checked place to connect to: ``address`` is what the socket goes
    to, ``host`` is what identifies the target to it."""

    host: str
    address: str
    port: int

    @property
    def _host_is_literal(self) -> bool:
        return _parsed(self.host) is not None

    @property
    def netloc(self) -> str:
        """``address:port``, with an IPv6 literal bracketed as RFC 3986 wants."""
        if ":" in self.address:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"

    @property
    def host_header(self) -> str:
        """What goes into ``Host``. RFC 3986 3.2.2 brackets an IPv6 literal,
        and a server parsing ``Host: 2001:db8::1`` would read the last
        colon as a port separator."""
        if ":" in self.host:
            return f"[{self.host}]"
        return self.host

    @property
    def sni(self) -> str | None:
        """What goes into SNI, or None when there is nothing to send: RFC
        6066 3 says the server name is a DNS hostname, and "literal IPv4 and
        IPv6 addresses are not permitted". Sending one anyway is a
        protocol violation some stacks answer with an alert."""
        return None if self._host_is_literal else self.host


def lookup(host: str) -> list[str]:
    """Every address ``host`` resolves to.

    The seam the tests replace, and the only place this package calls the
    system resolver for an A/AAAA record. ``getaddrinfo`` has no timeout of
    its own; the resolver's own configuration is what bounds it.
    """
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    # dict.fromkeys: one entry per distinct address, in the order the
    # resolver returned them.
    return list(dict.fromkeys(str(answer[4][0]) for answer in answers))


def _blocked_reason(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str | None:
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    return None


def _parsed(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


#: The NAT64 well-known prefix (RFC 6052 2.1): 64:ff9b::/96 carries an IPv4
#: address in its last 32 bits.
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


def _embedded_v4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address inside an IPv6 one, if there is one.

    There are four ways to write "this IPv4 address, in IPv6": mapped
    (``::ffff:127.0.0.1``), compatible (``::127.0.0.1``), 6to4
    (``2002:7f00:1::``) and NAT64 (``64:ff9b::127.0.0.1``). Only the mapped
    form answers ``is_loopback`` truthfully, so without unmapping the other
    three, ``::127.0.0.1`` would be a supported spelling of a blocked
    address -- and the policy would be one notation away from useless.
    """
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    packed = int(address)
    if 0 < packed < 2**32:
        # ::a.b.c.d, the deprecated IPv4-compatible form (RFC 4291 2.5.5.1).
        return ipaddress.IPv4Address(packed)
    return None


def _forms(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address this one *is*, so the checks below apply to all of them."""
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_v4(address)
        if embedded is not None:
            return [address, embedded]
    return [address]


def _check(host: str, address: str, allow_private: bool) -> None:
    parsed = _parsed(address)
    if parsed is None:  # pragma: no cover - getaddrinfo returns literals
        raise AcmeError(
            ErrorType.connection,
            f"{host!r} resolved to something that is not an address: {address!r}"[:200],
        )
    for form in _forms(parsed):
        reason = _blocked_reason(form)
        if reason is not None:
            raise AcmeError(
                ErrorType.connection,
                f"refusing to validate {host!r}: it resolves to the {reason} address {address}",
            )
        if not allow_private and form.is_private:
            raise AcmeError(
                ErrorType.connection,
                f"refusing to validate {host!r}: it resolves to the private address {address}, "
                "and allow_private_validation_targets is off",
            )


def resolve(host: str, port: int, allow_private: bool) -> Endpoint:
    """The one address cabin will connect to for ``host``, or an
    :class:`AcmeError` explaining why there is none.

    Replaced wholesale in the tests, which is what lets them point an
    identifier at a server on an ephemeral loopback port -- something the
    policy above would otherwise (correctly) refuse.
    """
    literal = _parsed(host)
    addresses = [host] if literal is not None else lookup(host)
    if not addresses:
        raise AcmeError(ErrorType.connection, f"{host!r} does not resolve to any address")
    for address in addresses:
        _check(host, address, allow_private)
    return Endpoint(host=host, address=addresses[0], port=port)
