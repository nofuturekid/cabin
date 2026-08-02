"""Spec 0011: the key authorization, the three validators and the target
address policy (FR-1, FR-4, FR-5, FR-6, FR-9; AC-1, AC-2, AC-3, AC-4, AC-7).

Every network case runs against a real server on loopback (see
``challenge_servers``); the only stubbed things are the two functions that
would otherwise reach the outside world -- the address lookup and the DNS
resolver. No test in this file touches the internet.
"""

import hashlib
import re
import time
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import pytest
from challenge_servers import (
    acme_identifier_certificate,
    closed_port,
    dripping_http_server,
    http_server,
    point_at,
    serves,
    silent_tls_listener,
    tls_server,
)

from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.validation import dns01, http01, keyauth, targets, tlsalpn01
from cabin.acme.validation.targets import Attempt, Endpoint

#: A budget small enough to assert against in a test run, standing in for the
#: real :data:`targets.VALIDATION_TIMEOUT`.
SHORT_BUDGET = 1.0
#: How far past the budget an attempt may finish before the test calls it a
#: failure. Generous, because the point is "bounded", not "instant".
SLACK = 4.0

TOKEN = "DGyRejmCefe7v4NfDGDKfA"
#: A stand-in account key thumbprint: 32 base64url characters, like the real
#: SHA-256 one :mod:`cabin.acme.jws` computes.
THUMBPRINT = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
KEY_AUTHORIZATION = f"{TOKEN}.{THUMBPRINT}"


def attempt(**overrides: Any) -> Attempt:
    values: dict[str, Any] = {
        "identifier_type": "dns",
        "identifier_value": "nas.lan",
        "token": TOKEN,
        "key_authorization": KEY_AUTHORIZATION,
    }
    values.update(overrides)
    return Attempt(**values)


def b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fails(validate: Any, target: Attempt) -> AcmeError:
    """Run a validator that must fail, and return the failure."""
    __tracebackhide__ = True
    with pytest.raises(AcmeError) as caught:
        validate(target)
    return caught.value


# --- FR-1, AC-1: the key authorization ------------------------------------------------


def test_key_authorization_format() -> None:
    """AC-1: RFC 8555 8.1's ``token || '.' || base64url(thumbprint)``, and
    one helper behind all three validators -- the digest each of them
    compares is derived from the same string."""
    computed = keyauth.key_authorization(TOKEN, THUMBPRINT)

    assert computed == KEY_AUTHORIZATION
    # two base64url segments, no padding, nothing else
    assert re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", computed)
    assert computed.split(".") == [TOKEN, THUMBPRINT]

    # http-01 compares the string itself; dns-01 its base64url digest;
    # tls-alpn-01 the same digest wrapped in DER. All three are this one
    # helper -- the success tests below build what their servers answer with
    # from exactly these three calls, so a validator that grew a digest of
    # its own would fail there.
    digest = hashlib.sha256(computed.encode("utf-8")).digest()
    assert keyauth.digest(computed) == digest
    assert keyauth.dns_value(computed) == b64(digest)
    assert dns01.keyauth is keyauth
    assert tlsalpn01.keyauth is keyauth


# --- FR-4, AC-2: http-01 --------------------------------------------------------------


def test_http01_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """The happy path against a real HTTP server: the well-known path, the
    identifier as ``Host``, and the key authorization as the body."""
    path = f"/.well-known/acme-challenge/{TOKEN}"
    with http_server(serves(KEY_AUTHORIZATION.encode() + b"\n", path=path)) as server:
        point_at(monkeypatch, server.port)

        http01.validate(attempt())

    # trailing whitespace is trimmed (RFC 8555 8.3), and the request went to
    # the path and virtual host the RFC names
    assert server.requests == [(path, "nas.lan")]


def test_http01_wrong_content(monkeypatch: pytest.MonkeyPatch) -> None:
    with http_server(serves(b"not the key authorization")) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "key authorization" in error.detail


def test_http01_404(monkeypatch: pytest.MonkeyPatch) -> None:
    with http_server(serves(KEY_AUTHORIZATION.encode(), path="/elsewhere")) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "404" in error.detail


def test_http01_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    point_at(monkeypatch, closed_port())

    error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.connection
    assert "could not connect" in error.detail


def test_http01_body_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-4: 64 KiB is the cap. A validator that reads whatever a target
    sends is a memory exhaustion primitive an attacker can aim at cabin."""
    oversized = b"x" * (http01.MAX_BODY_BYTES + 1)
    with http_server(serves(oversized)) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert str(http01.MAX_BODY_BYTES) in error.detail


def test_http01_redirect_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-4: up to five redirects are followed; a sixth is a failure rather
    than a loop cabin runs until its timeout."""

    def router(path: str) -> tuple[int, bytes, dict[str, str]]:
        step = int(path.rsplit("/", 1)[-1]) if path.startswith("/hop/") else 0
        return 302, b"", {"Location": f"http://nas.lan/hop/{step + 1}"}

    with http_server(router) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert f"{http01.MAX_REDIRECTS} redirects" in error.detail
    # the first request plus exactly five hops, then a stop
    assert len(server.requests) == http01.MAX_REDIRECTS + 1


def test_http01_follows_a_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other half of FR-4's redirect rule: a redirect that leads to the
    right content is a success, and the ``Host`` follows the target."""

    def router(path: str) -> tuple[int, bytes, dict[str, str]]:
        if path.startswith("/.well-known/"):
            return 301, b"", {"Location": "http://nas.lan/moved"}
        return 200, KEY_AUTHORIZATION.encode(), {}

    with http_server(router) as server:
        point_at(monkeypatch, server.port)

        http01.validate(attempt())

    assert [path for path, _ in server.requests][-1] == "/moved"


@pytest.mark.parametrize(
    "location",
    [
        # a scheme validation has no business speaking...
        "gopher://nas.lan/x",
        # ...and a port that is not one
        "http://nas.lan:99999/x",
    ],
)
def test_http01_refuses_an_unusable_redirect(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    """A ``Location`` header is written by the target, so a malformed one is
    an answer cabin rejects -- not an exception it trips over."""
    with http_server(lambda path: (302, b"", {"Location": location})) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response


def test_http01_refuses_a_redirect_to_another_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-4/FR-9: a redirect names the port as well as the host, so without
    this an account holder could aim validation at every port of an internal
    address and read the outcome off the challenge's error field. Only the
    two ports the RFC's own text is about are followed."""
    with http_server(lambda path: (302, b"", {"Location": "http://nas.lan:8080/x"})) as server:
        point_at(monkeypatch, server.port)

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "80" in error.detail and "443" in error.detail
    # the second hop was never opened
    assert len(server.requests) == 1


def test_http01_rechecks_every_redirect_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-9, and the reason redirects are followed by hand: the address
    policy applies to every hop, not only to the identifier. Here the first
    hop reaches the test server and the second is a name that resolves to
    loopback -- which the *real* resolve() must refuse.

    Handing the redirect chain to the HTTP client instead would connect
    without ever consulting the policy, and this test is what notices.
    """
    stub_lookup(monkeypatch, "127.0.0.1")
    with http_server(lambda path: (302, b"", {"Location": "http://evil.lan/x"})) as server:
        point_at(monkeypatch, server.port, only="nas.lan")

        error = fails(http01.validate, attempt())

    assert error.kind == ErrorType.connection
    assert "refusing to validate 'evil.lan'" in error.detail
    assert "loopback" in error.detail
    assert len(server.requests) == 1


# --- FR-3: one budget for the whole attempt -------------------------------------------


def test_http01_slow_response_hits_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-3: the timeout is the budget for the *attempt*, not for each read.

    A target that sends one byte at a time keeps every individual read
    inside its own timeout forever; only a deadline for the whole attempt
    ends it. This matters more than it looks: validation runs in the
    threadpool that serves every other request, so an attacker with an
    account and a slow server would otherwise hold those threads for as long
    as they like.
    """
    with dripping_http_server() as server:
        point_at(monkeypatch, server.port)

        started = time.monotonic()
        error = fails(http01.validate, attempt(timeout=SHORT_BUDGET))
        elapsed = time.monotonic() - started

    assert error.kind == ErrorType.connection
    assert "timed out" in error.detail
    assert elapsed < SHORT_BUDGET + SLACK, f"took {elapsed:.1f}s for a {SHORT_BUDGET}s budget"


def test_http01_redirect_chain_hits_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-3: five permitted hops times a per-hop timeout is not a budget --
    the deadline spans the chain, so a slow chain ends inside it."""

    def router(path: str) -> tuple[int, bytes, dict[str, str]]:
        time.sleep(SHORT_BUDGET / 2)
        step = int(path.rsplit("/", 1)[-1]) if path.startswith("/hop/") else 0
        return 302, b"", {"Location": f"http://nas.lan/hop/{step + 1}"}

    with http_server(router) as server:
        point_at(monkeypatch, server.port)

        started = time.monotonic()
        error = fails(http01.validate, attempt(timeout=SHORT_BUDGET))
        elapsed = time.monotonic() - started

    assert error.kind == ErrorType.connection
    assert "timed out" in error.detail
    assert elapsed < SHORT_BUDGET + SLACK, f"took {elapsed:.1f}s for a {SHORT_BUDGET}s budget"
    # it gave up on the clock, before the redirect limit
    assert len(server.requests) < http01.MAX_REDIRECTS + 1


def test_tlsalpn01_connection_gets_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-3: the TLS validator is bounded by the same budget -- a target
    that accepts a connection and then never speaks must not hold a thread
    for the default socket timeout, which is forever."""
    with silent_tls_listener() as port:
        point_at(monkeypatch, port)

        started = time.monotonic()
        error = fails(tlsalpn01.validate, attempt(timeout=SHORT_BUDGET))
        elapsed = time.monotonic() - started

    assert error.kind in (ErrorType.tls, ErrorType.connection)
    assert elapsed < SHORT_BUDGET + SLACK, f"took {elapsed:.1f}s for a {SHORT_BUDGET}s budget"


# --- FR-5, AC-3: dns-01 ---------------------------------------------------------------


def stub_txt(
    monkeypatch: pytest.MonkeyPatch, *records: str, raises: Exception | None = None
) -> list[float]:
    """Replace the one function that talks to a resolver (FR-5's seam).

    Returns the list of lifetimes it was asked for, so a test can assert
    that the query is bounded by the attempt's budget (FR-3).
    """
    asked: list[float] = []

    def lookup(name: str, resolvers: tuple[str, ...], timeout: float) -> list[str]:
        assert name == "_acme-challenge.nas.lan"
        asked.append(timeout)
        if raises is not None:
            raise raises
        return list(records)

    monkeypatch.setattr(dns01, "lookup_txt", lookup)
    return asked


def test_dns01_query_is_bounded_by_the_attempt_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-3: dnspython's own lifetime is what bounds a resolver that never
    answers, so it has to be the attempt's remaining budget and not a
    default of its own."""
    asked = stub_txt(monkeypatch, keyauth.dns_value(KEY_AUTHORIZATION))

    dns01.validate(attempt(timeout=SHORT_BUDGET))

    assert asked and 0 < asked[0] <= SHORT_BUDGET


def test_dns01_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 8555 8.4: any record may carry the digest -- a name being
    validated twice at once has two TXT records, and both are valid."""
    expected = keyauth.dns_value(KEY_AUTHORIZATION)
    stub_txt(monkeypatch, "some other validation", expected)

    dns01.validate(attempt())


def test_dns01_missing_record(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_txt(monkeypatch, raises=dns.resolver.NoAnswer())

    error = fails(dns01.validate, attempt())

    assert error.kind == ErrorType.dns
    assert "no TXT record" in error.detail


def test_dns01_wrong_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_txt(monkeypatch, keyauth.dns_value("someone else's key authorization"))

    error = fails(dns01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "matches the key authorization" in error.detail
    assert "(1 found)" in error.detail


def test_dns01_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name that does not exist is a different failure from a name with no
    TXT record on it -- and the operator's next step differs too."""
    stub_txt(monkeypatch, raises=dns.resolver.NXDOMAIN())

    error = fails(dns01.validate, attempt())

    assert error.kind == ErrorType.dns
    assert "NXDOMAIN" in error.detail


def test_dns01_resolver_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-3's fourth case: a resolver that never answers must fail as itself
    rather than as "no record"."""
    stub_txt(monkeypatch, raises=dns.exception.Timeout())

    error = fails(dns01.validate, attempt())

    assert error.kind == ErrorType.dns
    assert "timed out" in error.detail


def test_dns01_rejects_ip_identifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-5: an address has no name to hang a TXT record on (RFC 8738 4).
    0010 never offers the challenge for one; this is the backstop."""
    error = fails(dns01.validate, attempt(identifier_type="ip", identifier_value="192.168.1.5"))

    assert error.kind == ErrorType.malformed


# --- FR-6, AC-4: tls-alpn-01 ----------------------------------------------------------


def test_tlsalpn01_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cert, key = acme_identifier_certificate(key_authorization=KEY_AUTHORIZATION, tmp_path=tmp_path)
    with tls_server(cert, key) as port:
        point_at(monkeypatch, port)

        tlsalpn01.validate(attempt())


def test_tlsalpn01_no_alpn(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """RFC 8737 3: without the negotiated protocol this is just some TLS
    server, and its certificate proves nothing about the identifier."""
    cert, key = acme_identifier_certificate(key_authorization=KEY_AUTHORIZATION, tmp_path=tmp_path)
    with tls_server(cert, key, alpn=()) as port:
        point_at(monkeypatch, port)

        error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.tls
    assert tlsalpn01.ACME_TLS_1 in error.detail


def test_tlsalpn01_wrong_digest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cert, key = acme_identifier_certificate(
        key_authorization="a different key authorization", tmp_path=tmp_path
    )
    with tls_server(cert, key) as port:
        point_at(monkeypatch, port)

        error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "does not match" in error.detail


def test_tlsalpn01_missing_extension(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cert, key = acme_identifier_certificate(with_extension=False, tmp_path=tmp_path)
    with tls_server(cert, key) as port:
        point_at(monkeypatch, port)

        error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "acmeIdentifier" in error.detail


def test_tlsalpn01_extension_not_critical(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """RFC 8737 3 makes the extension critical, so that a server which does
    not understand it cannot present the certificate by accident."""
    cert, key = acme_identifier_certificate(
        key_authorization=KEY_AUTHORIZATION, critical=False, tmp_path=tmp_path
    )
    with tls_server(cert, key) as port:
        point_at(monkeypatch, port)

        error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "critical" in error.detail


def test_tlsalpn01_san_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cert, key = acme_identifier_certificate(
        names=("other.lan",), key_authorization=KEY_AUTHORIZATION, tmp_path=tmp_path
    )
    with tls_server(cert, key) as port:
        point_at(monkeypatch, port)

        error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.incorrect_response
    assert "nas.lan" in error.detail


def test_tlsalpn01_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    point_at(monkeypatch, closed_port())

    error = fails(tlsalpn01.validate, attempt())

    assert error.kind == ErrorType.connection


# --- FR-9, AC-7: which addresses cabin will talk to -----------------------------------


def stub_lookup(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    monkeypatch.setattr(targets, "lookup", lambda host: list(addresses))


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.7.7", "link-local"),
        ("fe80::1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        # The four ways of writing an IPv4 address inside an IPv6 one. They
        # are the same machine in a different notation, and unmapping before
        # the check is what stops any of them being a way around the rule.
        ("::ffff:127.0.0.1", "loopback"),
        ("::127.0.0.1", "loopback"),
        ("64:ff9b::127.0.0.1", "loopback"),
        ("2002:7f00:1::1", "loopback"),
    ],
)
def test_blocked_targets_rejected(
    monkeypatch: pytest.MonkeyPatch, address: str, reason: str
) -> None:
    """AC-7: an identifier that resolves into one of these ranges is refused
    before a socket is opened, whatever the private-target setting says --
    validation is the one place where a name an attacker chose decides where
    cabin connects."""
    stub_lookup(monkeypatch, address)

    with pytest.raises(AcmeError) as caught:
        targets.resolve("nas.lan", 80, True)

    assert caught.value.kind == ErrorType.connection
    assert reason in caught.value.detail
    assert address in caught.value.detail


def test_blocked_target_poisons_the_whole_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One bad address in an answer rejects the name: picking a good one
    would let a DNS answer of "192.168.1.5 and 127.0.0.1" decide by luck
    which of them cabin connects to."""
    stub_lookup(monkeypatch, "192.168.1.5", "127.0.0.1")

    with pytest.raises(AcmeError):
        targets.resolve("nas.lan", 80, True)


def test_private_targets_are_allowed_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR-9: an internal CA validates RFC 1918 hosts by definition, so
    private is the normal case here -- not the dangerous one."""
    stub_lookup(monkeypatch, "192.168.1.5")

    endpoint = targets.resolve("nas.lan", 80, True)

    assert endpoint == Endpoint(host="nas.lan", address="192.168.1.5", port=80)


def test_private_targets_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_lookup(monkeypatch, "192.168.1.5")

    with pytest.raises(AcmeError) as caught:
        targets.resolve("nas.lan", 80, False)

    assert "private" in caught.value.detail


def test_ip_identifiers_are_checked_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ip identifier needs no lookup, but it gets the same policy: the
    address came from the same untrusted order."""
    with pytest.raises(AcmeError):
        targets.resolve("127.0.0.1", 443, True)

    assert targets.resolve("192.168.1.5", 443, True).address == "192.168.1.5"


def test_endpoint_writes_an_ipv6_target_the_way_the_protocols_want() -> None:
    """Two details that only show up with an ip identifier: a ``Host``
    header needs the brackets of RFC 3986, and SNI must not contain an
    address at all (RFC 6066 3) -- a server that reads one would see a name
    that cannot exist."""
    literal = Endpoint(host="2001:db8::1", address="2001:db8::1", port=443)

    assert literal.netloc == "[2001:db8::1]:443"
    assert literal.host_header == "[2001:db8::1]"
    assert literal.sni is None

    named = Endpoint(host="nas.lan", address="192.168.1.5", port=80)

    assert named.netloc == "192.168.1.5:80"
    assert named.host_header == "nas.lan"
    assert named.sni == "nas.lan"


def test_unresolvable_names_fail_as_connection_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_lookup(monkeypatch)

    with pytest.raises(AcmeError) as caught:
        targets.resolve("nas.lan", 80, True)

    assert caught.value.kind == ErrorType.connection
    assert "nas.lan" in caught.value.detail
