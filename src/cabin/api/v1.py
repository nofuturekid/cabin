"""The /api/v1 endpoints (spec 0008 FR-4/FR-7).

Every route is a thin translation between JSON and the same domain services
the UI calls -- there is no certificate logic here, and there must never be.

Two things this module owns:

* **Error mapping.** :func:`_domain_errors` turns each domain failure into
  the status FR-4 asks for (400 bad input, 404 unknown, 409 state conflict),
  so no bad request can come back as a 500. What is left over -- a bug in
  cabin itself -- deliberately stays a 500, because pretending it was the
  caller's fault would only send them looking in the wrong place.
* **A scoped OpenAPI document.** ``/api/v1/openapi.json`` and
  ``/api/v1/docs`` describe *these* routes only. They are generated from
  this router rather than from a mounted sub-application, so the API keeps
  sharing the main app's state (database, secrets) and the UI routes are
  untouched. Both are unauthenticated: the schema documents the API, it
  does not expose anything from it (FR-7).
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cache
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import __version__, audit
from cabin.api import views
from cabin.api.models import (
    AuditEventInfo,
    AuditEventList,
    CAInfo,
    CertificateDetail,
    CertificateList,
    ErrorDetail,
    IssueRequest,
    RevocationInfo,
    RevokeRequest,
    SignRequest,
    StatusFilter,
)
from cabin.api_tokens import ApiToken
from cabin.audit import MAX_PAGE as AUDIT_MAX_PAGE
from cabin.audit import MAX_QUERY_LENGTH as AUDIT_MAX_QUERY_LENGTH
from cabin.audit import PER_PAGE as AUDIT_PER_PAGE
from cabin.audit import ActorKind, AuditAction, AuditEvent
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca.certs import (
    KEY_UNAVAILABLE,
    MAX_PAGE,
    MAX_QUERY_LENGTH,
    PER_PAGE,
    Certificate,
    CertSource,
)
from cabin.ca.crl import RevocationError
from cabin.ca.leaf import IssueError
from cabin.ca.service import CANotConfiguredError
from cabin.secrets import SecretsError
from cabin.users import Role
from cabin.web.api_deps import require_api_read, require_api_write
from cabin.web.deps import ADMIN_ROLES, certificate_or_404, client_ip, get_db

PREFIX = "/api/v1"

#: The two failures every route shares, documented once (FR-3/FR-7). The
#: per-route ones (400/404/409) are raised by :func:`_domain_errors`.
_AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {
        "model": ErrorDetail,
        "description": "Missing, unknown, revoked or expired token",
    },
    403: {
        "model": ErrorDetail,
        "description": "This token's role may not use this endpoint",
    },
}

router = APIRouter(prefix=PREFIX, tags=["cabin"], responses=_AUTH_RESPONSES)


@contextmanager
def _domain_errors() -> Iterator[None]:
    """FR-4: map domain failures onto HTTP, so no route needs its own
    opinion and none of them can leak a 500.

    ``ValueError`` rides along with :class:`IssueError` because the crypto
    layer raises it for input it cannot make sense of (an unsupported key
    type, an unparsable PEM); both mean "the request was wrong", which is a
    400. :class:`~fastapi.HTTPException` is not an ancestor of any of these
    and passes through untouched.
    """
    try:
        yield
    except ValidationError:
        # A ValidationError in here is *our* response model failing to build,
        # not the caller's input (FastAPI validates requests before the route
        # runs). It is a bug, and dressing it up as a 400 would blame the
        # caller for something they cannot fix -- let it be a 500 and a log
        # entry instead.
        raise
    except (IssueError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RevocationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CANotConfiguredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except SecretsError as exc:
        # The master key cannot open what the database holds: a state
        # conflict on our side, explicitly not a 500 and not the caller's
        # fault to fix by retrying.
        raise HTTPException(status_code=409, detail=KEY_UNAVAILABLE) from exc


def _key_fields(request: Request, token: ApiToken, row: Certificate) -> dict[str, str | None]:
    """FR-5: the private key for an admin+ caller on a certificate whose key
    cabin actually holds -- and, when that key can no longer be unsealed, a
    message saying so rather than a silently missing field.

    The unsealing itself is :func:`cabin.ca.certs.key_material`, shared with
    the UI's detail page, so the API cannot end up with a different idea of
    what a broken master key means.
    """
    if Role(token.role) not in ADMIN_ROLES:
        return {"key_pem": None, "key_error": None}
    key_pem, key_error = certs_service.key_material(request.app.state.secrets, row)
    return {"key_pem": key_pem, "key_error": key_error}


def _detail(
    request: Request, db: Session, token: ApiToken, row: Certificate, now: datetime
) -> CertificateDetail:
    return CertificateDetail.model_validate(
        {
            **views.certificate_pem(db, row, now).model_dump(),
            **_key_fields(request, token, row),
        }
    )


def _record_certificate_event(
    db: Session,
    request: Request,
    token: ApiToken,
    action: AuditAction,
    *,
    summary: str,
    target_id: int,
    detail: dict[str, Any],
) -> None:
    """Spec 0009 FR-4: the API's half of the audit wiring. Every event from
    here carries ``actor_kind="token"`` -- a script is not a person, and the
    log has to be able to say which one changed something."""
    audit.record(
        db,
        audit.token_actor(token),
        action,
        summary=summary,
        target_type="certificate",
        target_id=target_id,
        detail=detail,
        ip=client_ip(request, db),
    )


def _no_store(response: Response) -> None:
    """Mark a response that can carry an unsealed private key as
    uncacheable -- the same headers the UI's detail page sets, because a
    proxy does not care which door the key came out of."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


# --- CA ------------------------------------------------------------------------


@router.get("/ca", response_model=CAInfo, response_model_exclude_none=True, summary="CA info")
def get_ca(
    db: Session = Depends(get_db),
    _token: ApiToken = Depends(require_api_read),
) -> CAInfo:
    with _domain_errors():
        return views.ca_info(db)


# --- inventory -----------------------------------------------------------------


@router.get(
    "/certificates",
    response_model=CertificateList,
    response_model_exclude_none=True,
    summary="List certificates",
)
def list_certificates(
    q: str = Query("", max_length=MAX_QUERY_LENGTH),
    status: StatusFilter = "all",
    page: int = Query(1, ge=1, le=MAX_PAGE),
    db: Session = Depends(get_db),
    _token: ApiToken = Depends(require_api_read),
) -> CertificateList:
    # One clock for the filter and the reported status, so a row cannot be
    # selected as "expiring" and reported as "expired" a tick later.
    now = datetime.now(UTC)
    rows, total = certs_service.list_certificates(
        db, q=q, status=status, page=page, per_page=PER_PAGE, now=now
    )
    return views.certificate_list(rows, total, page, now)


# --- issuance ------------------------------------------------------------------
# Declared before /certificates/{cert_id}: routes match in registration
# order, and "sign" is not a certificate id.


@router.post(
    "/certificates",
    response_model=CertificateDetail,
    response_model_exclude_none=True,
    status_code=201,
    summary="Issue a certificate with a server-generated key",
)
def issue_certificate(
    body: IssueRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    token: ApiToken = Depends(require_api_write),
) -> CertificateDetail:
    """The only response that ever carries a freshly generated private key
    (FR-5) -- it is also stored, sealed, for later download."""
    _no_store(response)
    with _domain_errors():
        row = certs_service.issue_and_store(
            db,
            request.app.state.secrets,
            profile=body.profile,
            subject_cn=body.subject_cn,
            # Raw entries on purpose: the domain layer runs the same SAN
            # policy over them as it does over the UI's textarea lines.
            sans=body.sans,
            days=body.days,
            key_type=body.key_type,
            crl_url=crl_service.distribution_url(db),
            source=CertSource.api,
        )
        detail = _detail(request, db, token, row, datetime.now(UTC))
    _record_certificate_event(
        db,
        request,
        token,
        AuditAction.cert_issued,
        summary=audit.issued_summary(row),
        target_id=row.id,
        detail=audit.certificate_detail(row, key_type=body.key_type),
    )
    return detail


@router.post(
    "/certificates/sign",
    response_model=CertificateDetail,
    response_model_exclude_none=True,
    status_code=201,
    summary="Sign a CSR",
)
def sign_csr(
    body: SignRequest,
    request: Request,
    db: Session = Depends(get_db),
    token: ApiToken = Depends(require_api_write),
) -> CertificateDetail:
    """The CSR contributes its public key, CN and (unless ``sans`` overrides
    them) its SANs -- never its extensions."""
    with _domain_errors():
        row = certs_service.sign_csr_and_store(
            db,
            request.app.state.secrets,
            csr_pem=body.csr_pem,
            profile=body.profile,
            days=body.days,
            sans_override=body.sans or None,
            crl_url=crl_service.distribution_url(db),
            source=CertSource.api,
        )
        detail = _detail(request, db, token, row, datetime.now(UTC))
    # The CSR body stays out of the log, here as in the UI (FR-3).
    _record_certificate_event(
        db,
        request,
        token,
        AuditAction.cert_signed,
        summary=audit.signed_summary(row),
        target_id=row.id,
        detail=audit.certificate_detail(row),
    )
    return detail


@router.get(
    "/certificates/{cert_id}",
    response_model=CertificateDetail,
    response_model_exclude_none=True,
    summary="One certificate",
)
def get_certificate(
    cert_id: int,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    token: ApiToken = Depends(require_api_read),
) -> CertificateDetail:
    row = certificate_or_404(db, cert_id)
    _no_store(response)
    with _domain_errors():
        return _detail(request, db, token, row, datetime.now(UTC))


@router.post(
    "/certificates/{cert_id}/revoke",
    response_model=RevocationInfo,
    response_model_exclude_none=True,
    summary="Revoke a certificate",
)
def revoke_certificate(
    cert_id: int,
    body: RevokeRequest,
    request: Request,
    db: Session = Depends(get_db),
    token: ApiToken = Depends(require_api_write),
) -> RevocationInfo:
    """Idempotent: revoking an already-revoked certificate succeeds and
    leaves the original date and reason in place."""
    # Which means only the call that actually revokes is a state change, and
    # only that one is an event -- a retry after a timeout must not add a
    # second revocation to the log.
    existing = certs_service.get_certificate(db, cert_id)
    was_revoked = existing is not None and existing.revoked_at is not None
    with _domain_errors():
        row = crl_service.revoke_certificate(db, request.app.state.secrets, cert_id, body.reason)
    if not was_revoked:
        _record_certificate_event(
            db,
            request,
            token,
            AuditAction.cert_revoked,
            summary=audit.revoked_summary(row, body.reason),
            target_id=row.id,
            detail=audit.revocation_detail(row, body.reason),
        )
    return views.revocation_info(db, row)


# --- audit (spec 0009 FR-7) ----------------------------------------------------


def _audit_event(event: AuditEvent) -> AuditEventInfo:
    return AuditEventInfo.model_validate(
        {
            "id": event.id,
            "occurred_at": event.occurred_at_dt,
            "actor_kind": event.actor_kind,
            "actor_id": event.actor_id,
            "actor_label": event.actor_label,
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "summary": event.summary,
            "detail": event.detail,
            "ip": event.ip,
        }
    )


@router.get(
    "/audit",
    response_model=AuditEventList,
    response_model_exclude_none=True,
    summary="List audit events",
)
def list_audit_events(
    q: str = Query("", max_length=AUDIT_MAX_QUERY_LENGTH),
    action: AuditAction | None = None,
    actor_kind: ActorKind | None = None,
    page: int = Query(1, ge=1, le=AUDIT_MAX_PAGE),
    db: Session = Depends(get_db),
    _token: ApiToken = Depends(require_api_read),
) -> AuditEventList:
    """The same log the UI shows, paginated the same way. Readable by any
    live token (viewer+): entries are metadata, not secrets.

    Unlike the UI -- which treats an unknown ?action= as a typo and shows
    everything -- an unknown value here is a 422, for the same reason the
    inventory's status filter is: a script filtering on a name we do not have
    must be told, not quietly handed the whole log.
    """
    rows, total = audit.list_events(
        db,
        q=q,
        action=action.value if action is not None else "all",
        actor_kind=actor_kind.value if actor_kind is not None else "all",
        page=page,
        per_page=AUDIT_PER_PAGE,
    )
    return AuditEventList(
        items=[_audit_event(event) for event in rows],
        total=total,
        page=page,
        per_page=AUDIT_PER_PAGE,
        pages=max(1, (total + AUDIT_PER_PAGE - 1) // AUDIT_PER_PAGE),
    )


# --- FR-7: the API documents itself --------------------------------------------

_DESCRIPTION = (
    "Token-authenticated REST API for cabin. Authenticate with "
    "`Authorization: Bearer <token>`; tokens are created by a superadmin "
    "under /tokens and carry a viewer, admin or superadmin role."
)


@cache
def _schema() -> dict[str, Any]:
    """The OpenAPI document for this router alone, built once. Safe to cache:
    the route table is fixed at import time."""
    return get_openapi(
        title="cabin API",
        version=__version__,
        description=_DESCRIPTION,
        routes=router.routes,
    )


@router.get("/openapi.json", include_in_schema=False)
def openapi_json() -> JSONResponse:
    return JSONResponse(_schema())


#: swagger-ui-dist 5.32.11, vendored into web/static alongside htmx: cabin
#: ships as one container onto networks with no route to a CDN, where
#: FastAPI's default jsdelivr URLs render a blank page exactly where the
#: documentation is needed most. Bump both files and this version together.
_SWAGGER_JS = "/static/swagger-ui-bundle.js"
_SWAGGER_CSS = "/static/swagger-ui.css"


@router.get("/docs", include_in_schema=False)
def swagger_ui() -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url=f"{PREFIX}/openapi.json",
        title="cabin API — docs",
        swagger_js_url=_SWAGGER_JS,
        swagger_css_url=_SWAGGER_CSS,
        # An empty data: URI rather than FastAPI's hosted favicon -- the page
        # must make no outbound request at all. Same for SwaggerUI's default
        # "validate this schema" badge, which would POST the schema to
        # validator.swagger.io.
        swagger_favicon_url="data:,",
        swagger_ui_parameters={"validatorUrl": None},
    )
