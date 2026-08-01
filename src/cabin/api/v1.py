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

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import __version__
from cabin.api.models import (
    CACertificateInfo,
    CAInfo,
    CertificateDetail,
    CertificateList,
    CertificateSummary,
    ErrorDetail,
    IssueRequest,
    RevocationInfo,
    RevokeRequest,
    SignRequest,
    StatusFilter,
)
from cabin.api_tokens import ApiToken
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.certs import (
    KEY_UNAVAILABLE,
    MAX_PAGE,
    MAX_QUERY_LENGTH,
    PER_PAGE,
    Certificate,
    CertStatus,
    certificate_status,
)
from cabin.ca.crl import RevocationError
from cabin.ca.leaf import IssueError
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import CACertificate, CANotConfiguredError
from cabin.ca.x509 import describe_certificate
from cabin.secrets import SecretsError
from cabin.settings import BASE_URL, get_setting
from cabin.users import Role
from cabin.web.api_deps import require_api_read, require_api_write
from cabin.web.deps import ADMIN_ROLES, certificate_or_404, get_db

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

_NO_CA = "no CA has been created or imported yet"


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


def _hierarchy(db: Session) -> ca_service.CAHierarchy:
    hierarchy = ca_service.get_ca(db)
    if hierarchy is None:
        raise CANotConfiguredError(_NO_CA)
    return hierarchy


def _ca_info(row: CACertificate) -> CACertificateInfo:
    described = describe_certificate(x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8")))
    return CACertificateInfo.model_validate({**described, "kind": row.kind})


def _fields(row: Certificate, now: datetime) -> dict[str, Any]:
    """Everything both certificate response models share, computed once."""
    return {
        "id": row.id,
        "serial_hex": row.serial_hex,
        "subject_cn": row.subject_cn,
        "sans": row.sans,
        "profile": row.profile,
        "not_before": datetime.fromisoformat(row.not_before),
        "not_after": row.not_after_dt,
        "status": certificate_status(row.not_after_dt, now, row.revoked_at_dt),
        "has_key": row.key_sealed is not None,
        "revoked_at": row.revoked_at_dt,
        "revocation_reason": row.revocation_reason,
    }


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
    hierarchy = _hierarchy(db)
    return CertificateDetail.model_validate(
        {
            **_fields(row, now),
            "cert_pem": row.cert_pem,
            # Nearest issuer first, matching /certs/{id}/download/chain.pem.
            "chain_pem": hierarchy.intermediate.cert_pem + hierarchy.root.cert_pem,
            **_key_fields(request, token, row),
        }
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
        hierarchy = _hierarchy(db)
    return CAInfo(
        root=_ca_info(hierarchy.root),
        intermediate=_ca_info(hierarchy.intermediate),
        base_url=get_setting(db, BASE_URL),
        crl_url=crl_service.distribution_url(db),
    )


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
    return CertificateList(
        items=[CertificateSummary.model_validate(_fields(row, now)) for row in rows],
        total=total,
        page=page,
        per_page=PER_PAGE,
        pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
    )


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
        )
        return _detail(request, db, token, row, datetime.now(UTC))


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
        )
        return _detail(request, db, token, row, datetime.now(UTC))


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
    _token: ApiToken = Depends(require_api_write),
) -> RevocationInfo:
    """Idempotent: revoking an already-revoked certificate succeeds and
    leaves the original date and reason in place."""
    with _domain_errors():
        row = crl_service.revoke_certificate(db, request.app.state.secrets, cert_id, body.reason)
    revoked_at = row.revoked_at_dt
    assert revoked_at is not None  # revoke_certificate either sets it or raises
    return RevocationInfo(
        id=row.id,
        serial_hex=row.serial_hex,
        status=CertStatus.revoked,
        revoked_at=revoked_at,
        reason=RevocationReason(row.revocation_reason or RevocationReason.unspecified),
        crl_url=crl_service.distribution_url(db),
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
