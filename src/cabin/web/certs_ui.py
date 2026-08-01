"""UI routes for leaf issuance (spec 0005 FR-6): /certs/new carries both
forms (issue with a server-generated key | sign a pasted CSR) and is
admin-only because it exists solely to mutate; /certs/{id} shows the result
to any logged-in user, but the private key block only to admins.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.ca.leaf import (
    DEFAULT_DAYS,
    MAX_DAYS,
    MIN_DAYS,
    IssueError,
    Profile,
    parse_profile,
    parse_san_lines,
)
from cabin.ca.service import CANotConfiguredError
from cabin.ca.x509 import KEY_TYPES
from cabin.secrets import SecretsError
from cabin.users import Role, User
from cabin.web import templates
from cabin.web.deps import (
    ADMIN_ROLES,
    base_context,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/certs")

_NO_CA = "no CA yet: create or import one under CA before issuing certificates"
_KEY_UNAVAILABLE = (
    "the stored private key could not be decrypted: it was sealed with a different "
    "master key, or the stored value is damaged"
)


def _new_page(request: Request, user: User, error: str | None, status_code: int = 200) -> Response:
    context = base_context(request, user)
    context.update(
        {
            "error": error,
            "profiles": list(Profile),
            "key_types": list(KEY_TYPES),
            "default_days": DEFAULT_DAYS,
            "min_days": MIN_DAYS,
            "max_days": MAX_DAYS,
        }
    )
    return templates.TemplateResponse(request, "certs_new.html", context, status_code=status_code)


@router.get("/new")
def certs_new(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    error = None if ca_service.get_ca(db) is not None else _NO_CA
    return _new_page(request, user, error)


@router.post("/issue")
def certs_issue(
    request: Request,
    subject_cn: str = Form(...),
    sans: str = Form(""),
    profile: str = Form("server"),
    key_type: str = Form("ecdsa-p256"),
    days: int = Form(DEFAULT_DAYS),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        row = certs_service.issue_and_store(
            db,
            request.app.state.secrets,
            profile=parse_profile(profile),
            subject_cn=subject_cn,
            sans=parse_san_lines(sans),
            days=days,
            key_type=key_type,
        )
    except IssueError as exc:
        return _new_page(request, user, str(exc), status_code=400)
    except CANotConfiguredError:
        return _new_page(request, user, _NO_CA, status_code=400)
    # The key is never carried in the redirect: the result page re-derives
    # it from the sealed column for whoever is authorized to see it (FR-6).
    return RedirectResponse(f"/certs/{row.id}", status_code=303)


@router.post("/sign")
def certs_sign(
    request: Request,
    csr_pem: str = Form(...),
    profile: str = Form("server"),
    days: int = Form(DEFAULT_DAYS),
    sans_override: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        row = certs_service.sign_csr_and_store(
            db,
            request.app.state.secrets,
            csr_pem=csr_pem,
            profile=parse_profile(profile),
            days=days,
            sans_override=parse_san_lines(sans_override),
        )
    except IssueError as exc:
        return _new_page(request, user, str(exc), status_code=400)
    except CANotConfiguredError:
        return _new_page(request, user, _NO_CA, status_code=400)
    return RedirectResponse(f"/certs/{row.id}", status_code=303)


@router.get("/{cert_id}")
def cert_detail(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    row = certs_service.get_certificate(db, cert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such certificate")
    context = base_context(request, user)
    context["cert"] = row
    # FR-6: viewers see the certificate, never the private key.
    key_pem: str | None = None
    key_error: str | None = None
    if Role(user.role) in ADMIN_ROLES:
        try:
            key_pem = certs_service.key_pem(request.app.state.secrets, row)
        except SecretsError:
            # A key we can no longer unseal must not take the whole page
            # down: the certificate itself is still perfectly usable.
            key_error = _KEY_UNAVAILABLE
    context["key_pem"] = key_pem
    context["key_error"] = key_error
    response = templates.TemplateResponse(request, "cert_detail.html", context)
    # This page can render an unsealed private key -- no cache, anywhere,
    # may keep a copy of it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response
