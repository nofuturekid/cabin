"""UI routes for the certificate inventory (spec 0006 FR-1/FR-2) and leaf
issuance (spec 0005 FR-6): /certs lists what has been issued, /certs/new
carries both issuance forms (server-generated key | pasted CSR) and is
admin-only because it exists solely to mutate; /certs/{id} shows one
certificate to any logged-in user, but the private key block only to
admins. The download routes live in :mod:`cabin.web.certs_download_ui`.
"""

from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.ca.certs import (
    MAX_QUERY_LENGTH,
    PER_PAGE,
    STATUS_FILTERS,
    Certificate,
    certificate_status,
)
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
#: Shared with :mod:`cabin.web.certs_download_ui`: one wording for "this key
#: cannot be unsealed", whether it is a page or a download that hits it.
KEY_UNAVAILABLE = (
    "the stored private key could not be decrypted: it was sealed with a different "
    "master key, or the stored value is damaged"
)
#: How much of the serial identifies a certificate in the list and in
#: download filenames (FR-1/FR-4).
SERIAL_CHARS = 8
#: SANs shown per row before collapsing the rest into "+N more" (FR-1).
SAN_PREVIEW = 3


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


def _cert_row(row: Certificate, now: datetime) -> dict[str, object]:
    """One inventory line, fully computed here: the template renders values,
    it does not decide them (FR-1)."""
    sans = row.sans
    return {
        "id": row.id,
        "subject_cn": row.subject_cn,
        "profile": row.profile,
        "has_key": row.key_sealed is not None,
        "not_after": row.not_after_dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "status": certificate_status(row.not_after_dt, now).value,
        "sans": sans[:SAN_PREVIEW],
        "sans_more": max(len(sans) - SAN_PREVIEW, 0),
        "serial_short": row.serial_hex[:SERIAL_CHARS],
    }


def _page_url(q: str, status: str, page: int) -> str:
    """A pager link that keeps the active filters (FR-2)."""
    return "/certs?" + urlencode({"q": q, "status": status, "page": page})


@router.get("")
def certs_list(
    request: Request,
    q: str = "",
    status: str = "all",
    page: int = 1,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """FR-1/FR-2: the paginated inventory with its text and status filters,
    open to any logged-in user."""
    term = q.strip()[:MAX_QUERY_LENGTH]
    # An unknown ?status= is a typo, not an error: show everything.
    active = status if status in STATUS_FILTERS else "all"
    page = max(page, 1)
    # One clock for the filter and the badges, so a row can't be selected as
    # "expiring" and then rendered as "expired" a tick later.
    now = datetime.now(UTC)
    rows, total = certs_service.list_certificates(
        db, q=term, status=active, page=page, per_page=PER_PAGE, now=now
    )
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    context = base_context(request, user)
    context.update(
        {
            "certs": [_cert_row(row, now) for row in rows],
            "q": term,
            "status": active,
            "statuses": STATUS_FILTERS,
            "page": page,
            "pages": pages,
            "total": total,
            # Past the last page there is nothing behind us either, so the
            # back link is clamped to a page that actually has rows.
            "prev_url": _page_url(term, active, min(page - 1, pages)) if page > 1 else None,
            "next_url": _page_url(term, active, page + 1) if page < pages else None,
            "can_issue": Role(user.role) in ADMIN_ROLES,
        }
    )
    return templates.TemplateResponse(request, "certs_list.html", context)


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
    is_admin = Role(user.role) in ADMIN_ROLES
    key_pem: str | None = None
    key_error: str | None = None
    if is_admin:
        try:
            key_pem = certs_service.key_pem(request.app.state.secrets, row)
        except SecretsError:
            # A key we can no longer unseal must not take the whole page
            # down: the certificate itself is still perfectly usable.
            key_error = KEY_UNAVAILABLE
    context["key_pem"] = key_pem
    context["key_error"] = key_error
    # Spec 0006 AC-6: no key/PKCS#12 controls in a viewer's HTML at all, and
    # none for a CSR-signed certificate whose key cabin never had.
    context["can_download_key"] = is_admin and row.key_sealed is not None
    response = templates.TemplateResponse(request, "cert_detail.html", context)
    # This page can render an unsealed private key -- no cache, anywhere,
    # may keep a copy of it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response
