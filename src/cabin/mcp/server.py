"""The MCP server (spec 0013): cabin's CA, inventory and issuance as tools
an assistant can call.

**No certificate logic lives here.** Every tool is a translation between an
MCP call and the same domain services the UI, the REST API and ACME use, and
the shapes it answers with come from :mod:`cabin.api.views` -- so a
certificate described over MCP is the certificate described over REST, field
for field.

Three things this module owns.

* **Where the endpoint is.** FR-1 asks for the MCP app under ``/mcp`` and
  warns about the sub-path problem (python-sdk#1367). A Starlette ``Mount``
  never matches its own prefix without a trailing slash, so a mount alone
  turns ``POST /mcp`` -- the URL an operator pastes into their client --
  into a 307 to ``/mcp/``: an extra round trip on every call, and a
  ``Location`` built from a ``Host`` header that behind a reverse proxy is
  not cabin's. :func:`create_mcp_app` therefore attaches the ASGI sub-app
  :meth:`FastMCP.http_app` returns as a ``Route`` at exactly ``/mcp``
  (which is how FastMCP attaches it inside that sub-app too), and mounts a
  flat 404 underneath -- so nothing lives at ``/mcp/…``, and the router
  cannot answer a request for one with a redirect that admits ``/mcp``
  exists. The published path and the served path are then one string.
* **The enablement gate.** FR-4: while ``mcp_enabled`` is off, ``/mcp`` is
  404 -- and that answer has to come *before* authentication, or a wrong
  token would reply 401 and admit that something is there. It is an ASGI
  wrapper around the sub-app rather than FastMCP middleware for exactly that
  ordering reason.
* **Readable failures.** A tool that raises returns its message to the model
  (FR-3). Domain errors become :class:`ToolError` with the sentence the
  domain layer wrote, and input is validated through the REST API's own
  request models, so the limits an MCP caller meets are the limits a REST
  caller meets -- from the same definition, not from a copy.

The transport is stateless streamable-HTTP: one POST is one complete
exchange. cabin's tools are request/response with no subscriptions and
nothing to stream, so a session to keep alive would be state without a
purpose -- and its absence is what lets each tool call own its database
session outright.
"""

from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.routing import BaseRoute, Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cabin import audit
from cabin.acme.http import directory_url
from cabin.api import views
from cabin.api.models import (
    CAInfo,
    CertificateDetail,
    CertificateList,
    CertificatePem,
    IssueRequest,
    KeyType,
    RevocationInfo,
    RevokeRequest,
    SignRequest,
    StatusFilter,
)
from cabin.api_tokens import ApiToken
from cabin.audit import AuditAction
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca.certs import (
    KEY_UNAVAILABLE,
    MAX_PAGE,
    MAX_QUERY_LENGTH,
    PER_PAGE,
    CertSource,
)
from cabin.ca.crl import RevocationError
from cabin.ca.leaf import DEFAULT_DAYS, IssueError, Profile
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import (
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    UnknownIssuerError,
)
from cabin.issuer_grants import IssuerForbiddenError, NoGrantedIssuerError, token_principal
from cabin.mcp.auth import CabinTokenVerifier, current_token
from cabin.secrets import SecretsError, SecretStore
from cabin.settings import ACME_ENABLED, BASE_URL, MCP_ENABLED, get_flag, get_setting
from cabin.users import Role
from cabin.web.deps import ADMIN_ROLES, client_ip

#: Where the endpoint lives, and the path FastMCP's sub-app routes on -- one
#: constant, so the published URL and the served one cannot drift.
MCP_PATH = "/mcp"

#: The audit detail every MCP-driven change carries (FR-5), so a reader of
#: the log can tell an assistant's work from a script's.
VIA = {"via": "mcp"}

#: What the tools are refused with when the token's role may not change
#: anything. Names the role it has and the one it would need: a model that is
#: told "forbidden" will retry, one that is told this will not.
_ROLE_REFUSED = (
    "this token's role is {role}, which may only read: issuing certificates, "
    "signing CSRs and revoking need a token with the admin or superadmin role"
)

_INSTRUCTIONS = (
    "cabin is an internal certificate authority. These tools inspect its CA "
    "and its issued certificates, and -- with an admin token -- issue, sign "
    "and revoke them. Issued certificates are real and are recorded in "
    "cabin's audit log."
)


class McpAcmeDirectory(BaseModel):
    """One issuer's ACME directory (spec 0019 FR-13): there is no longer a
    single URL to report, so this names which issuer a URL belongs to."""

    issuer_id: int
    url: str


class McpCAInfo(CAInfo):
    """:class:`CAInfo` plus the URLs only this front door reports: where
    ACME clients would go for each issuer, when the ACME server is switched
    on (FR-3)."""

    #: One entry per intermediate this instance holds, in the order
    #: :attr:`issuers` lists them. Empty while ACME is off or no base URL is
    #: set -- there is then no address that would work from anywhere but
    #: this request.
    acme_directory_urls: list[McpAcmeDirectory] = Field(default_factory=list)


def endpoint_url(db: Session) -> str | None:
    """The URL to hand a client, or None while no base URL is configured.

    Mirrors :func:`cabin.acme.http.directory_url` and
    :func:`cabin.ca.crl.distribution_url`: an address cabin puts in front of
    an operator has to be one that works from somewhere else, and only the
    configured base URL is known to be that.
    """
    base = get_setting(db, BASE_URL)
    return f"{base}{MCP_PATH}" if base else None


def is_enabled(db: Session) -> bool:
    """FR-4: whether ``/mcp`` answers at all.

    "No base URL" counts as off for the same reason it does for ACME: the
    endpoint publishes its own address, and a cabin that does not know its
    own address cannot publish one.
    """
    return get_flag(db, MCP_ENABLED) and bool(get_setting(db, BASE_URL))


@dataclass(frozen=True)
class McpServer:
    """What :mod:`cabin.app` needs to serve MCP: the routes to attach, and
    the lifespan they have to run inside -- the streamable-HTTP session
    manager is started and stopped there, and a sub-app attached to a parent
    router does not get a lifespan of its own."""

    routes: list[BaseRoute]
    lifespan: Callable[[], AbstractAsyncContextManager[None]]


async def _not_found(scope: Scope, receive: Receive, send: Send) -> None:
    """Everything under ``/mcp/`` -- there is nothing there, on or off.

    Registered as a mount so that ``/mcp/`` is a flat 404 rather than the
    router's redirect back to ``/mcp``: while MCP is switched off, a 307
    would be the router saying that ``/mcp`` is a route it knows.
    """
    await JSONResponse({"detail": "not found"}, status_code=404)(scope, receive, send)


#: Every method, so that nothing at ``/mcp`` can answer without having
#: passed the gate. A route that named only the methods the endpoint
#: implements would let Starlette answer the others with a 405 and an
#: ``Allow`` header of its own -- which is an admission that the path exists,
#: made before the gate ever ran (AC-1). Same reasoning, and the same list,
#: as :data:`cabin.acme.api._ANY_METHOD`; which methods the endpoint actually
#: speaks is then the sub-app's answer to give, and it gives a 405 too -- but
#: only once MCP is switched on.
_ANY_METHOD = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

#: What no cache between cabin and the caller may do with an MCP response.
#: ``no-cache`` and ``no-transform`` are what the streaming transport sets
#: for itself and are kept; ``no-store`` is the one this endpoint adds.
_NO_STORE = "no-store, no-cache, no-transform"


class _EnablementGate:
    """FR-4/AC-1: 404 for everything at ``/mcp`` while MCP is off, and
    ``no-store`` on what comes back when it is on.

    Wraps the sub-app rather than sitting inside it, so it runs before
    FastMCP's authentication: "switched off" must not be distinguishable
    from "does not exist", and a 401 would distinguish it. It is also the
    only place the caching headers can be set -- the transport composes the
    response itself and gives a tool no handle on it -- which is why they
    are set for the whole endpoint rather than for the one tool that returns
    a private key, the way ``api/v1._no_store`` can afford to.
    """

    def __init__(self, app: ASGIApp, session_factory: Callable[[], Session]) -> None:
        self._app = app
        self._session_factory = session_factory

    def _enabled(self) -> bool:
        db = self._session_factory()
        try:
            return is_enabled(db)
        finally:
            db.close()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def _no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = _NO_STORE
                headers["Pragma"] = "no-cache"
            await send(message)

        if not await run_in_threadpool(self._enabled):
            await JSONResponse({"detail": "not found"}, status_code=404)(scope, receive, _no_store)
            return
        await self._app(scope, receive, _no_store)


@contextmanager
def _readable_errors() -> Iterator[None]:
    """FR-3: a domain failure comes back as the sentence the domain layer
    wrote, never as a traceback.

    The same failures :func:`cabin.api.v1._domain_errors` maps onto HTTP
    statuses, mapped onto messages instead -- an MCP client has no status
    line to read, so the wording has to carry all of it. A
    :class:`ValidationError` is deliberately *not* caught: caller input is
    validated by :func:`_checked` before it gets here, so one raised in this
    block is one of our own response models failing, which is a bug and
    should be loud rather than blamed on the caller.
    """
    try:
        yield
    except ValidationError:
        raise
    except (
        IssueError,
        ValueError,
        RevocationError,
        CANotConfiguredError,
        UnknownIssuerError,
        IssuerRetiredError,
        IssuerRequiredError,
        IssuerForbiddenError,
        NoGrantedIssuerError,
    ) as exc:
        raise ToolError(str(exc)) from exc
    except SecretsError as exc:
        raise ToolError(KEY_UNAVAILABLE) from exc


def _checked[M: BaseModel](model: type[M], **fields: Any) -> M:
    """Validate a tool's arguments through the REST API's own request model
    (AC-8), so days, SAN count and CN length are bounded by one definition
    for both front doors -- and report the failure as a sentence.
    """
    try:
        return model.model_validate(fields)
    except ValidationError as exc:
        raise ToolError(
            "; ".join(
                f"{'.'.join(str(part) for part in error['loc']) or 'input'}: {error['msg']}"
                for error in exc.errors()
            )
        ) from exc


def _record(
    db: Session,
    token: ApiToken,
    action: AuditAction,
    *,
    summary: str,
    target_id: int,
    detail: dict[str, Any],
) -> None:
    """FR-5: every change through here is one event, attributed to the token
    that made it and marked as having come through MCP."""
    audit.record(
        db,
        audit.token_actor(token),
        action,
        summary=summary,
        target_type="certificate",
        target_id=target_id,
        detail={**detail, **VIA},
        ip=client_ip(get_http_request(), db),
    )


def _writer(db: Session) -> ApiToken:
    """FR-2: the token behind this call, refused unless its role may change
    something. The same line the UI and the REST API draw, taken from the
    same :data:`ADMIN_ROLES`."""
    token = current_token(db)
    if Role(token.role) not in ADMIN_ROLES:
        raise ToolError(_ROLE_REFUSED.format(role=token.role))
    return token


def create_mcp_app(
    session_factory: Callable[[], Session],
    secrets: Callable[[], SecretStore],
) -> McpServer:
    """Build the MCP endpoint.

    Both arguments are read at request time rather than now: they come from
    the application state that :func:`cabin.app.create_app`'s lifespan sets
    up, which does not exist yet when the routes are attached. Each tool call
    opens one session from ``session_factory`` and closes it again -- a tool
    runs in a worker thread, and a session shared across them would be a
    session shared across requests.
    """
    mcp: FastMCP[None] = FastMCP(
        name="cabin",
        instructions=_INSTRUCTIONS,
        auth=CabinTokenVerifier(session_factory),
        # Not the library's default (False), and the difference matters: an
        # exception cabin did not anticipate is otherwise relayed to the
        # caller as text, and the exceptions that reach here come from the
        # database. SQLAlchemy's StatementError puts the failing SQL *and
        # its bound parameters* in its message -- which in this application
        # means a certificate PEM and a sealed private key -- and SQLite's
        # OperationalError puts the path of the data directory in it. Every
        # message this module means the caller to read is raised as a
        # ToolError, which masking leaves alone.
        mask_error_details=True,
    )

    @contextmanager
    def _session() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    @mcp.tool
    def get_ca_info() -> McpCAInfo:
        """Describe this cabin instance's certificate authority.

        Returns one entry per CA row this instance holds -- subject, issuer,
        serial, validity, SHA-256 fingerprint, key type, status and where
        each row's own certificate and (for an intermediate) CRL are
        published -- together with the address cabin publishes itself at,
        and the ACME directory URL if the ACME server is switched on.

        Any live API token may call this.
        """
        with _session() as db, _readable_errors():
            info = views.ca_info(db)
            # Spec 0019 FR-13: one directory per intermediate, never a
            # single instance-wide URL -- built through the same helper the
            # ACME server itself resolves a directory with, so this can
            # never name a URL the server would not actually answer at.
            directories: list[McpAcmeDirectory] = []
            if get_flag(db, ACME_ENABLED):
                for issuer in info.issuers:
                    if issuer.kind != "intermediate":
                        continue
                    url = directory_url(db, issuer.id)
                    if url is not None:
                        directories.append(McpAcmeDirectory(issuer_id=issuer.id, url=url))
            # Named field by field rather than **info.model_dump(), so that a
            # future shape change to CAInfo is a type error here rather than
            # a pydantic failure discovered inside a live tool call.
            return McpCAInfo(
                issuers=info.issuers,
                base_url=info.base_url,
                acme_directory_urls=directories,
            )

    @mcp.tool
    def list_certificates(
        # The same bounds GET /api/v1/certificates declares on the same three
        # parameters, from the same constants: an out-of-range page is
        # refused rather than clamped and echoed back as a page number the
        # caller did not ask for.
        query: Annotated[str | None, Field(max_length=MAX_QUERY_LENGTH)] = None,
        status: StatusFilter | None = None,
        page: Annotated[int, Field(ge=1, le=MAX_PAGE)] = 1,
    ) -> CertificateList:
        """List the certificates cabin has issued, newest first.

        `query` is a case-insensitive substring matched against the common
        name, the subject alternative names and the serial. `status` narrows
        the list to valid, expiring (within 30 days), expired or revoked
        certificates; omitting it lists all of them. Results are paginated
        50 to a page.

        Metadata only -- no certificate or key material. Use
        `get_certificate` for that. Any live API token may call this.
        """
        now = datetime.now(UTC)
        with _session() as db:
            rows, total = certs_service.list_certificates(
                db,
                q=query or "",
                status=status or "all",
                page=page,
                per_page=PER_PAGE,
                now=now,
            )
            return views.certificate_list(rows, total, page, now)

    @mcp.tool
    def get_certificate(certificate_id: int) -> CertificatePem:
        """Look up one issued certificate by its cabin id.

        Returns its metadata, its PEM, and the issuer chain (intermediate
        then root) to deploy alongside it.

        Never returns a private key, whatever the token's role: the only key
        cabin will hand out is the one `issue_certificate` generates, in the
        response to the call that generated it. Any live API token may call
        this.
        """
        with _session() as db, _readable_errors():
            row = certs_service.get_certificate(db, certificate_id)
            if row is None:
                raise ToolError(f"no such certificate: {certificate_id}")
            return views.certificate_pem(db, row, datetime.now(UTC))

    @mcp.tool
    def issue_certificate(
        subject_cn: str,
        sans: Sequence[str] = (),
        profile: Profile = Profile.server,
        key_type: KeyType = "ecdsa-p256",
        days: int = DEFAULT_DAYS,
        issuer_id: int | None = None,
    ) -> CertificateDetail:
        """Issue a certificate with a freshly generated private key.

        `subject_cn` is the common name (at most 64 characters). `sans` are
        the subject alternative names, at most 100, each optionally prefixed
        `dns:`, `ip:` or `email:` -- an unprefixed entry is read as an IP if
        it parses as one, an email address if it contains `@`, and a hostname
        otherwise. Leaving `sans` empty falls back to the common name.
        `profile` picks server or client authentication, and `days` is the
        validity, between 1 and 3650. `issuer_id` names which active
        intermediate signs this leaf; omit it with exactly one active issuer
        and it resolves to that one, omit it with several and the call is
        refused rather than guessing, and naming a retired issuer is refused
        too.

        This is the one tool that returns a private key (`key_pem`), because
        there is no other way for the caller to obtain it -- cabin keeps its
        own encrypted copy, but will not hand it out again. Requires an admin
        or superadmin token, and is recorded in the audit log.
        """
        with _session() as db:
            # Authorization before input: a token that may not issue is told
            # that, not handed a critique of arguments it may not use.
            token = _writer(db)
            request = _checked(
                IssueRequest,
                subject_cn=subject_cn,
                sans=list(sans),
                profile=profile,
                key_type=key_type,
                days=days,
                issuer_id=issuer_id,
            )
            with _readable_errors():
                result = certs_service.issue_and_store(
                    db,
                    secrets(),
                    principal=token_principal(token),
                    profile=request.profile,
                    subject_cn=request.subject_cn,
                    sans=request.sans,
                    days=request.days,
                    key_type=request.key_type,
                    issuer_id=request.issuer_id,
                    source=CertSource.mcp,
                )
                row = result.row
                issued = CertificateDetail.model_validate(
                    {
                        **views.certificate_pem(
                            db, row, datetime.now(UTC), validity_capped_from=result.capped_from
                        ).model_dump(),
                        "key_pem": certs_service.key_pem(secrets(), row),
                    }
                )
            _record(
                db,
                token,
                AuditAction.cert_issued,
                summary=audit.issued_summary(row),
                target_id=row.id,
                detail=audit.certificate_detail(
                    row,
                    key_type=request.key_type,
                    days_requested=request.days if result.capped_from is not None else None,
                    validity_capped_from=result.capped_from,
                ),
            )
            return issued

    @mcp.tool
    def sign_csr(
        csr_pem: str,
        profile: Profile = Profile.server,
        days: int = DEFAULT_DAYS,
        sans: Sequence[str] | None = None,
        issuer_id: int | None = None,
    ) -> CertificatePem:
        """Sign a certificate signing request.

        The CSR contributes its public key, its common name and -- unless
        `sans` overrides them -- its subject alternative names. It never
        contributes its extensions: a CSR asking to be a CA is signed as an
        ordinary leaf. `days` is the validity, between 1 and 3650. `issuer_id`
        names which active intermediate signs this leaf -- see
        `issue_certificate` for the resolution rule.

        No private key is involved: cabin never sees the requester's. So
        `has_key` on the result is false and the key can never be downloaded
        from cabin later. Requires an admin or superadmin token, and is
        recorded in the audit log.
        """
        with _session() as db:
            token = _writer(db)
            request = _checked(
                SignRequest,
                csr_pem=csr_pem,
                profile=profile,
                days=days,
                sans=list(sans or []),
                issuer_id=issuer_id,
            )
            with _readable_errors():
                result = certs_service.sign_csr_and_store(
                    db,
                    secrets(),
                    principal=token_principal(token),
                    csr_pem=request.csr_pem,
                    profile=request.profile,
                    days=request.days,
                    sans_override=request.sans or None,
                    issuer_id=request.issuer_id,
                    source=CertSource.mcp,
                )
                row = result.row
                signed = views.certificate_pem(
                    db, row, datetime.now(UTC), validity_capped_from=result.capped_from
                )
            # The CSR body stays out of the log, here as everywhere else.
            _record(
                db,
                token,
                AuditAction.cert_signed,
                summary=audit.signed_summary(row),
                target_id=row.id,
                detail=audit.certificate_detail(
                    row,
                    days_requested=request.days if result.capped_from is not None else None,
                    validity_capped_from=result.capped_from,
                ),
            )
            return signed

    @mcp.tool
    def revoke_certificate(
        certificate_id: int,
        reason: RevocationReason = RevocationReason.unspecified,
    ) -> RevocationInfo:
        """Revoke an issued certificate and republish cabin's CRL.

        `reason` is an RFC 5280 revocation reason; use `key_compromise` if
        the private key may have leaked, `superseded` when it has been
        replaced.

        Idempotent: revoking an already-revoked certificate succeeds and
        leaves the original date and reason in place, so a retry is safe.
        Requires an admin or superadmin token, and is recorded in the audit
        log.
        """
        with _session() as db:
            token = _writer(db)
            request = _checked(RevokeRequest, reason=reason)
            # Only the call that actually revokes is a state change, and only
            # that one is an event -- a retry must not log a second one.
            existing = certs_service.get_certificate(db, certificate_id)
            was_revoked = existing is not None and existing.revoked_at is not None
            with _readable_errors():
                row = crl_service.revoke_certificate(
                    db,
                    secrets(),
                    certificate_id,
                    request.reason,
                    principal=token_principal(token),
                )
            if not was_revoked:
                _record(
                    db,
                    token,
                    AuditAction.cert_revoked,
                    summary=audit.revoked_summary(row, request.reason),
                    target_id=row.id,
                    detail=audit.revocation_detail(row, request.reason),
                )
            return views.revocation_info(db, row)

    http_app = mcp.http_app(path=MCP_PATH, stateless_http=True)

    @asynccontextmanager
    async def lifespan() -> AsyncIterator[None]:
        async with http_app.lifespan(http_app):
            yield

    return McpServer(
        routes=[
            Route(
                MCP_PATH,
                endpoint=_EnablementGate(http_app, session_factory),
                methods=_ANY_METHOD,
            ),
            Mount(MCP_PATH, app=_not_found),
        ],
        lifespan=lifespan,
    )
