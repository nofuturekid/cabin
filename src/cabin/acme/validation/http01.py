"""http-01 (spec 0011 FR-4, RFC 8555 8.3).

Fetch ``http://<identifier>/.well-known/acme-challenge/<token>`` and compare
what comes back with the key authorization.

Three things here are deliberate rather than incidental:

* **Redirects are followed by hand.** The HTTP client is told not to follow
  them, and this module walks each hop itself, because every hop is a new
  address an unauthenticated client picked (a ``Location`` header is under
  the target's control) and every one of them has to go through the policy
  of :mod:`cabin.acme.validation.targets`. A client-side ``follow_redirects``
  would resolve and connect on its own, behind cabin's back.
* **The connection goes to a checked address, not to a name.** The URL cabin
  hands the client names the address; the identifier travels in ``Host``
  (and in SNI on an https hop). A second lookup could answer differently
  from the one that was approved.
* **The response body is read with a cap.** A validation target is chosen by
  whoever placed the order, so "read the whole body" would be an invitation
  to hand cabin a gigabyte.

The certificate on an https redirect target is *not* verified: RFC 8555 8.3
says so explicitly, and it is not a weakening -- the channel carried no
secret and the proof is the body, not the transport.
"""

import hmac
from urllib.parse import urlsplit, urlunsplit

import httpx2

from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.validation import targets
from cabin.acme.validation.targets import Attempt, Deadline, Endpoint

#: RFC 8555 8.3: the path validation fetches.
WELL_KNOWN_PREFIX = "/.well-known/acme-challenge/"
#: FR-4: how much of a response is read before giving up on it.
MAX_BODY_BYTES = 64 * 1024
#: FR-4: how far a chain of redirects may go.
MAX_REDIRECTS = 5
#: The 3xx codes that name a new location to fetch. 304 and 305 are not
#: redirects to follow, and 300 has no single target.
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
#: The scheme a hop may use, and the port it means without one. The initial
#: request is always port 80 (RFC 8555 8.3); a redirect names its own port,
#: and only these two are followed -- a redirect is written by the target,
#: so anything else would turn validation into a port scanner pointed at
#: whatever address the identifier resolves to, with the result readable in
#: the challenge's error field.
_DEFAULT_PORTS = {"http": 80, "https": 443}
_ALLOWED_PORTS = frozenset({80, 443})


def _host_in_url(attempt: Attempt) -> str:
    """The identifier as it appears in a URL: an IPv6 literal is bracketed
    (RFC 8738 uses the address itself as the host, RFC 3986 says how)."""
    value = attempt.identifier_value
    if attempt.identifier_type == "ip" and ":" in value:
        return f"[{value}]"
    return value


def validate(attempt: Attempt) -> None:
    """Prove control of ``attempt`` over HTTP, or raise :class:`AcmeError`."""
    url = f"http://{_host_in_url(attempt)}{WELL_KNOWN_PREFIX}{attempt.token}"
    body = _fetch(url, attempt.allow_private, attempt.deadline())
    # RFC 8555 8.3: trailing whitespace is tolerated, because every "echo the
    # token into a file" recipe adds a newline. Constant time, because this
    # comparison is the whole proof.
    if not hmac.compare_digest(body.strip(), attempt.key_authorization.encode("utf-8")):
        raise AcmeError(
            ErrorType.incorrect_response,
            f"the response from {url} does not match the key authorization",
        )


def _fetch(url: str, allow_private: bool, deadline: Deadline) -> bytes:
    with httpx2.Client(
        follow_redirects=False,
        # No proxy, no certificate bundle, no NO_PROXY: validation goes where
        # this module says it goes, not where the environment redirects it.
        trust_env=False,
        # See the module docstring: the transport is not the proof.
        verify=False,
        headers={"User-Agent": "cabin-acme-validator/1"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            response, body = _one_request(client, url, allow_private, deadline)
            if response.status_code in _REDIRECTS:
                url = _redirect_target(url, response)
                continue
            if response.status_code != 200:
                raise AcmeError(
                    ErrorType.incorrect_response,
                    f"{url} responded {response.status_code}, not 200",
                )
            return body
    raise AcmeError(
        ErrorType.incorrect_response,
        f"validating {url} took more than {MAX_REDIRECTS} redirects",
    )


def _one_request(
    client: httpx2.Client, url: str, allow_private: bool, deadline: Deadline
) -> tuple[httpx2.Response, bytes]:
    endpoint = _endpoint(url, allow_private)
    scheme, _, path, query, _ = urlsplit(url)
    request_url = urlunsplit((scheme, endpoint.netloc, path, query, ""))
    # Whatever is left of the budget, not a fresh timeout per hop: five hops
    # of ten seconds is not a ten-second attempt.
    left = deadline.check(url)
    extensions: dict[str, object] = {}
    if endpoint.sni is not None:
        # An https hop gets the identifier as SNI, so that a target serving
        # several names presents the right certificate. An ip identifier
        # gets none -- see Endpoint.sni.
        extensions["sni_hostname"] = endpoint.sni
    try:
        with client.stream(
            "GET",
            request_url,
            headers={"Host": endpoint.host_header},
            extensions=extensions,
            timeout=httpx2.Timeout(left),
        ) as response:
            return response, _read_capped(response, url, deadline)
    # Both messages name the address that was actually tried, which is what
    # an operator reading the audit log needs. The client is told something
    # coarser -- see cabin.acme.validation._client_problem.
    except httpx2.TimeoutException as exc:
        raise AcmeError(
            ErrorType.connection,
            f"fetching {url} from {endpoint.netloc} timed out after {deadline.budget:g} seconds",
        ) from exc
    except httpx2.HTTPError as exc:
        raise AcmeError(
            ErrorType.connection,
            f"could not connect to {url} at {endpoint.netloc}: {type(exc).__name__}",
        ) from exc


def _endpoint(url: str, allow_private: bool) -> Endpoint:
    """Where to connect for ``url``, checked.

    Everything read here after the first request comes from a ``Location``
    header the target chose, so each part is treated as input: an unknown
    scheme, a missing host and a port outside 0-65535 are all "cabin will
    not follow this", not exceptions to be surprised by.
    """
    parsed = urlsplit(url)
    scheme = parsed.scheme
    if scheme not in _DEFAULT_PORTS:
        raise AcmeError(
            ErrorType.incorrect_response,
            f"validation will not follow a redirect to {scheme!r}"[:200],
        )
    host = parsed.hostname
    if not host:
        raise AcmeError(ErrorType.incorrect_response, f"{url} names no host"[:200])
    try:
        port = parsed.port or _DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise AcmeError(ErrorType.incorrect_response, f"{url} names no usable port"[:200]) from exc
    if port not in _ALLOWED_PORTS:
        raise AcmeError(
            ErrorType.incorrect_response,
            f"validation only follows redirects to ports 80 and 443, not {port}",
        )
    # Module attribute, not a from-import: this is the seam the tests replace.
    return targets.resolve(host, port, allow_private)


def _read_capped(response: httpx2.Response, url: str, deadline: Deadline) -> bytes:
    """Read at most :data:`MAX_BODY_BYTES` and for at most as long as the
    attempt has left.

    Failing rather than truncating, because a truncated body that happened
    to start with the key authorization would otherwise validate. Checking
    the clock per chunk, because a target that dribbles the body out one
    byte at a time satisfies every individual read timeout forever.
    """
    chunks: list[bytes] = []
    read = 0
    for chunk in response.iter_bytes():
        deadline.check(url)
        read += len(chunk)
        if read > MAX_BODY_BYTES:
            raise AcmeError(
                ErrorType.incorrect_response,
                f"the response from {url} is larger than {MAX_BODY_BYTES} bytes",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _redirect_target(url: str, response: httpx2.Response) -> str:
    location = response.headers.get("location", "")
    if not location:
        raise AcmeError(
            ErrorType.incorrect_response,
            f"{url} redirected without a Location header",
        )
    # Resolved against the URL that was *asked for*, not against the address
    # it was fetched from -- otherwise a relative redirect would turn the
    # pinned address into the new host.
    target = httpx2.URL(url).join(location)
    return str(target)
