"""UI routes for the certificate inventory (spec 0006 FR-1/FR-2) and leaf
issuance (spec 0005 FR-6): /certs lists what has been issued, /certs/new
carries both issuance forms (server-generated key | pasted CSR) and is
admin-only because it exists solely to mutate; /certs/{id} shows one
certificate to any logged-in user, but the private key block only to
admins. The download routes live in :mod:`cabin.web.certs_download_ui`.
"""

from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.audit import Actor, AuditAction
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
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
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import CANotConfiguredError
from cabin.ca.x509 import KEY_TYPES
from cabin.users import Role, User
from cabin.web import templates
from cabin.web.deps import (
    ADMIN_ROLES,
    base_context,
    certificate_or_404,
    client_ip,
    current_actor,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/certs")

_NO_CA = "no CA yet: create or import one under CA before issuing certificates"
#: Spec 0007 FR-7: the confirm checkbox is the last stop before an
#: irreversible action, so a post without it is refused rather than assumed.
_CONFIRM_REVOKE = "tick the confirmation box: revoking a certificate cannot be undone"
#: The reason ends up in the CRL, so an unknown one is refused, not guessed.
_UNKNOWN_REASON = "unknown revocation reason: {!r}"
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
        "status": certificate_status(row.not_after_dt, now, row.revoked_at_dt).value,
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
            "prev_url": (_page_url(term, active, min(page - 1, pages)) if page > 1 else None),
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
    actor: Actor = Depends(current_actor),
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
            crl_url=crl_service.distribution_url(db),
        )
    except IssueError as exc:
        return _new_page(request, user, str(exc), status_code=400)
    except CANotConfiguredError:
        return _new_page(request, user, _NO_CA, status_code=400)
    audit.record(
        db,
        actor,
        AuditAction.cert_issued,
        summary=audit.issued_summary(row),
        target_type="certificate",
        target_id=row.id,
        detail=audit.certificate_detail(row, key_type=key_type),
        ip=client_ip(request, db),
    )
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
    actor: Actor = Depends(current_actor),
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
            crl_url=crl_service.distribution_url(db),
        )
    except IssueError as exc:
        return _new_page(request, user, str(exc), status_code=400)
    except CANotConfiguredError:
        return _new_page(request, user, _NO_CA, status_code=400)
    # The CSR itself is not recorded: it is bulky, and what it asked for is
    # already described by the certificate that came out of it (FR-3).
    audit.record(
        db,
        actor,
        AuditAction.cert_signed,
        summary=audit.signed_summary(row),
        target_type="certificate",
        target_id=row.id,
        detail=audit.certificate_detail(row),
        ip=client_ip(request, db),
    )
    return RedirectResponse(f"/certs/{row.id}", status_code=303)


def _detail_page(
    request: Request,
    user: User,
    row: Certificate,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    context = base_context(request, user)
    context["cert"] = row
    # FR-6: viewers see the certificate, never the private key. A key we can
    # no longer unseal must not take the whole page down either -- the
    # certificate itself is still perfectly usable.
    is_admin = Role(user.role) in ADMIN_ROLES
    key_pem, key_error = (
        certs_service.key_material(request.app.state.secrets, row) if is_admin else (None, None)
    )
    context["key_pem"] = key_pem
    context["key_error"] = key_error
    # Spec 0006 AC-6: no key/PKCS#12 controls in a viewer's HTML at all, and
    # none for a CSR-signed certificate whose key cabin never had.
    context["can_download_key"] = is_admin and row.key_sealed is not None
    revoked_at = row.revoked_at_dt
    context["revoked_at"] = (
        revoked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if revoked_at else None
    )
    # Spec 0007 FR-7: the form is for admins, and only while there is
    # something left to revoke.
    context["can_revoke"] = is_admin and revoked_at is None
    context["reasons"] = list(RevocationReason)
    context["error"] = error
    response = templates.TemplateResponse(
        request, "cert_detail.html", context, status_code=status_code
    )
    # This page can render an unsealed private key -- no cache, anywhere,
    # may keep a copy of it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/{cert_id}")
def cert_detail(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    return _detail_page(request, user, certificate_or_404(db, cert_id))


@router.post("/{cert_id}/revoke")
def cert_revoke(
    cert_id: int,
    request: Request,
    reason: str = Form(str(RevocationReason.unspecified)),
    confirm: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0007 FR-7: revocation cannot be undone, so it takes an explicit
    confirmation on top of CSRF and the admin role."""
    row = certificate_or_404(db, cert_id)
    # Revoking is idempotent, so "was it already revoked" decides whether
    # this request changes anything -- and only a change is an event.
    was_revoked = row.revoked_at is not None
    if not confirm:
        return _detail_page(request, user, row, _CONFIRM_REVOKE, status_code=400)
    try:
        # A reason cabin does not know is refused rather than quietly
        # downgraded: the operator would be told the certificate was revoked
        # for a reason that never reaches the CRL.
        parsed = RevocationReason(reason)
    except ValueError:
        return _detail_page(request, user, row, _UNKNOWN_REASON.format(reason), status_code=400)
    try:
        crl_service.revoke_certificate(db, request.app.state.secrets, cert_id, parsed)
    except CANotConfiguredError:
        return _detail_page(request, user, row, _NO_CA, status_code=400)
    if not was_revoked:
        audit.record(
            db,
            actor,
            AuditAction.cert_revoked,
            summary=audit.revoked_summary(row, parsed),
            target_type="certificate",
            target_id=row.id,
            detail=audit.revocation_detail(row, parsed),
            ip=client_ip(request, db),
        )
    return RedirectResponse(f"/certs/{cert_id}", status_code=303)
