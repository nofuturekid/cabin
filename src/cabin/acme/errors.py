"""ACME problem documents (spec 0010 FR-3).

RFC 8555 section 6.7 answers every failure with an RFC 7807 problem document
whose ``type`` is a URN from the ACME registry. Two properties matter here:

* the mapping from problem type to HTTP status lives in exactly one place,
  so two routes cannot answer the same condition with different codes;
* raising is the only way to produce one. There is no "return an error dict"
  path, so a route cannot half-fail into a 200.
"""

from enum import StrEnum
from typing import Any

#: The IANA registry every ACME error type lives under (RFC 8555 6.7).
NAMESPACE = "urn:ietf:params:acme:error:"


class ErrorType(StrEnum):
    """The subset of the registry cabin can currently produce (FR-3)."""

    malformed = "malformed"
    bad_nonce = "badNonce"
    bad_public_key = "badPublicKey"
    bad_signature_algorithm = "badSignatureAlgorithm"
    unauthorized = "unauthorized"
    account_does_not_exist = "accountDoesNotExist"
    rate_limited = "rateLimited"
    server_internal = "serverInternal"
    unsupported_identifier = "unsupportedIdentifier"
    rejected_identifier = "rejectedIdentifier"
    user_action_required = "userActionRequired"
    # Spec 0011: the three ways a validation attempt fails at the target
    # rather than at the protocol. The distinction is the whole point --
    # "cabin could not reach you", "your DNS did not answer" and "what you
    # served was not what I asked for" have three different fixes.
    connection = "connection"
    dns = "dns"
    tls = "tls"
    incorrect_response = "incorrectResponse"


#: The status each type is answered with unless a caller overrides it.
#:
#: ``unauthorized`` is 403 rather than 401: the request *was* authenticated
#: (its JWS verified), it simply may not do this -- and a 401 would invite
#: clients to retry with an HTTP credential that cabin does not have.
_STATUS: dict[ErrorType, int] = {
    ErrorType.malformed: 400,
    ErrorType.bad_nonce: 400,
    ErrorType.bad_public_key: 400,
    ErrorType.bad_signature_algorithm: 400,
    ErrorType.unauthorized: 403,
    ErrorType.account_does_not_exist: 400,
    ErrorType.rate_limited: 429,
    ErrorType.server_internal: 500,
    ErrorType.unsupported_identifier: 400,
    ErrorType.rejected_identifier: 400,
    ErrorType.user_action_required: 403,
    # A validation failure is the client's problem to fix (its server, its
    # DNS, its certificate), so all four are 400 -- and they are answered as
    # the ``error`` field of a challenge rather than as a response status,
    # since the request that carried them succeeded.
    ErrorType.connection: 400,
    ErrorType.dns: 400,
    ErrorType.tls: 400,
    ErrorType.incorrect_response: 400,
}

#: RFC 7807's media type; a client that cannot parse the body still learns
#: from the content type that this is a problem document.
CONTENT_TYPE = "application/problem+json"


class AcmeError(Exception):
    """One ACME failure, on its way to becoming a problem document.

    ``extra`` carries the fields a specific error type is expected to add --
    ``algorithms`` for badSignatureAlgorithm, ``subproblems`` for a rejected
    identifier -- and ``headers`` the ones RFC 8555 attaches to a particular
    status, e.g. ``Location`` on the 409 of a key rollover.
    """

    def __init__(
        self,
        kind: ErrorType,
        detail: str,
        *,
        status: int | None = None,
        extra: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.status = status if status is not None else _STATUS[kind]
        self.extra = extra or {}
        self.headers = headers or {}

    @property
    def urn(self) -> str:
        return f"{NAMESPACE}{self.kind}"

    def problem(self) -> dict[str, Any]:
        """The RFC 7807 body. ``status`` is repeated inside the document
        because that is where a client library looks for it."""
        return {
            "type": self.urn,
            "detail": self.detail,
            "status": self.status,
            **self.extra,
        }
