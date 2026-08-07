"""UI routes for the CA hierarchies (spec 0017 FR-14): the wizard
(create/import) when no hierarchy exists at all, the list of every
hierarchy plus per-row actions once at least one does, and the PEM
downloads. GETs need only a logged-in session (viewer included); the
mutating POSTs need role admin or superadmin plus CSRF.
"""

from cryptography import x509
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import http as acme_http
from cabin.audit import Actor, AuditAction
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.service import (
    CACertificate,
    CAHierarchy,
    CANotConfiguredError,
    RetireError,
    UnknownIssuerError,
)
from cabin.ca.x509 import CAImportError
from cabin.settings import ACME_ENABLED, get_flag
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/ca")

_MIN_YEARS = 1
_MAX_YEARS = 50
#: FR-13/AC-11: below 1 no intermediate could be signed at all; the upper
#: bound is a sanity cap, not an X.509 invariant.
_MIN_PATH_LENGTH = 1
_MAX_PATH_LENGTH = 4


def _cert_info(row: CACertificate) -> dict[str, object]:
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    info = ca_x509.describe_certificate(cert)
    info["kind"] = row.kind
    return info


def _year_bounds_error(value: int, field: str) -> str | None:
    if not _MIN_YEARS <= value <= _MAX_YEARS:
        return f"{field} must be between {_MIN_YEARS} and {_MAX_YEARS}"
    return None


def _years_error(root_years: int, intermediate_years: int) -> str | None:
    return (
        _year_bounds_error(root_years, "root_years")
        or _year_bounds_error(intermediate_years, "intermediate_years")
        or (
            "intermediate_years must not exceed root_years"
            if intermediate_years > root_years
            else None
        )
    )


def _path_length_error(path_length: int) -> str | None:
    if not _MIN_PATH_LENGTH <= path_length <= _MAX_PATH_LENGTH:
        return f"path_length must be between {_MIN_PATH_LENGTH} and {_MAX_PATH_LENGTH}"
    return None


def _key_type_error(key_type: str) -> str | None:
    if key_type not in ca_x509.KEY_TYPES:
        return f"key_type must be one of: {', '.join(ca_x509.KEY_TYPES)}"
    return None


def _subject(hierarchy: CAHierarchy) -> str:
    """The signing CA's subject, read back off the stored certificate -- what
    an audit entry has to name, since "the CA" is otherwise anonymous."""
    return str(_cert_info(hierarchy.intermediate)["subject"])


def _row_view(db: Session, row: CACertificate, *, parent_has_key: bool) -> dict[str, object]:
    """One ``/ca`` row: identity, status, which actions are safe to offer
    (AC-13, an imported root has no stored key so creating an intermediate
    under it or renewing it would only ever 500), and -- for an intermediate
    -- where its CRL is published (spec 0007 FR-6, so an operator can see
    why a certificate carries no CDP)."""
    has_key = row.key_sealed is not None
    signing_key_available = has_key if row.kind == "root" else parent_has_key
    return {
        **_cert_info(row),
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "status": row.status,
        "can_create_intermediate": row.kind == "root" and has_key,
        "can_renew": signing_key_available,
        "can_retire": row.status == "active",
        "crl_url": crl_service.distribution_url(db, row.id) if row.kind == "intermediate" else None,
    }


def _groups(db: Session, rows: list[CACertificate]) -> list[dict[str, object]]:
    """Every row grouped under its root, root first then its intermediates
    in creation order (AC-12) -- ``list_cas`` already orders by id, so both
    the roots and each root's own children come out in that order too."""
    key_sealed_by_id = {row.id: row.key_sealed is not None for row in rows}
    children: dict[int, list[CACertificate]] = {}
    for row in rows:
        if row.kind == "intermediate" and row.parent_id is not None:
            children.setdefault(row.parent_id, []).append(row)
    return [
        {
            "root": _row_view(db, root, parent_has_key=False),
            "intermediates": [
                _row_view(db, child, parent_has_key=key_sealed_by_id.get(root.id, False))
                for child in children.get(root.id, [])
            ],
        }
        for root in rows
        if root.kind == "root"
    ]


def _list_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
) -> Response:
    rows = ca_service.list_cas(db)
    context = base_context(request, user)
    context["error"] = error
    if not rows:
        return templates.TemplateResponse(
            request, "ca_setup.html", context, status_code=status_code
        )
    context["groups"] = _groups(db, rows)
    # An installation-level property, not any one hierarchy's: 0019 gives
    # ACME a directory per issuer, but in 0017 it still uses the default
    # rule, so there is exactly one URL to show regardless of how many
    # hierarchies exist. Ordinary https, unlike the CDP/AIA URLs baked into
    # certificates (FR-12) -- this one is a service endpoint a client talks
    # to directly, so it is reached over TLS like everything else in cabin.
    context["acme_directory_url"] = (
        acme_http.directory_url(db) if get_flag(db, ACME_ENABLED) else None
    )
    return templates.TemplateResponse(request, "ca_list.html", context, status_code=status_code)


@router.get("")
def ca_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    return _list_page(request, db, user, None)


@router.post("/create")
def ca_create(
    request: Request,
    name: str = Form(...),
    key_type: str = Form("ecdsa-p256"),
    root_years: int = Form(20),
    intermediate_years: int = Form(10),
    path_length: int = Form(1),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = (
        _key_type_error(key_type)
        or _years_error(root_years, intermediate_years)
        or _path_length_error(path_length)
    )
    if form_error is not None:
        context = base_context(request, user)
        context["error"] = form_error
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    hierarchy = ca_service.create_hierarchy(
        db,
        request.app.state.secrets,
        name,
        key_type=key_type,
        root_years=root_years,
        intermediate_years=intermediate_years,
        path_length=path_length,
    )
    audit.record(
        db,
        actor,
        AuditAction.ca_created,
        summary=f"created CA hierarchy {name!r}",
        target_type="ca_certificate",
        target_id=hierarchy.intermediate.id,
        detail={
            "name": name,
            "key_type": key_type,
            "root_years": root_years,
            "intermediate_years": intermediate_years,
            "path_length": path_length,
            "subject": _subject(hierarchy),
        },
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


@router.post("/import")
def ca_import(
    request: Request,
    cert_pem: str = Form(...),
    key_pem: str = Form(...),
    key_passphrase: str = Form(""),
    chain_pem: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        hierarchy = ca_service.import_hierarchy(
            db,
            request.app.state.secrets,
            cert_pem,
            key_pem,
            key_passphrase or None,
            chain_pem,
        )
    except CAImportError as exc:
        context = base_context(request, user)
        context["error"] = str(exc)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    # The subject only -- neither the submitted key nor its passphrase has any
    # business in a log (spec 0004 FR-3).
    subject = _subject(hierarchy)
    audit.record(
        db,
        actor,
        AuditAction.ca_imported,
        summary=f"imported CA {subject}",
        target_type="ca_certificate",
        target_id=hierarchy.intermediate.id,
        detail={"subject": subject},
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


@router.post("/{root_id}/intermediate")
def ca_create_intermediate(
    root_id: int,
    request: Request,
    name: str = Form(...),
    key_type: str = Form("ecdsa-p256"),
    years: int = Form(10),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = _key_type_error(key_type) or _year_bounds_error(years, "years")
    if form_error is not None:
        raise HTTPException(status_code=400, detail=form_error)
    try:
        row = ca_service.create_intermediate_under(
            db,
            request.app.state.secrets,
            root_id,
            name,
            key_type=key_type,
            years=years,
        )
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (CANotConfiguredError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(
        db,
        actor,
        AuditAction.ca_created,
        summary=f"created intermediate {row.name!r} under root {root_id}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={"name": name, "key_type": key_type, "years": years, "root_id": root_id},
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


@router.post("/{ca_id}/renew")
def ca_renew(
    ca_id: int,
    request: Request,
    years: int = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = _year_bounds_error(years, "years")
    if form_error is not None:
        raise HTTPException(status_code=400, detail=form_error)
    try:
        row = ca_service.renew_in_place(db, request.app.state.secrets, ca_id, years)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CANotConfiguredError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(
        db,
        actor,
        AuditAction.ca_renewed,
        summary=f"renewed CA {row.name!r}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={"years": years},
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


@router.post("/{ca_id}/retire")
def ca_retire(
    ca_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    was_active = row.status == "active"
    try:
        ca_service.retire(db, ca_id)
    except RetireError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Retiring an already-retired row is a no-op (FR-4): only a real state
    # change is worth an event, the same rule the role/token routes apply.
    if was_active:
        audit.record(
            db,
            actor,
            AuditAction.ca_retired,
            summary=f"retired CA {row.name!r}",
            target_type="ca_certificate",
            target_id=ca_id,
            ip=client_ip(request, db),
        )
    return RedirectResponse("/ca", status_code=303)


@router.get("/{ca_id}.pem")
def ca_cert_pem(
    ca_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="no such CA") from exc
    return PlainTextResponse(row.cert_pem, media_type="application/x-pem-file")


@router.get("/{issuer_id}/chain.pem")
def ca_chain_pem(
    issuer_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    try:
        chain = ca_service.chain_for(db, issuer_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="no such CA") from exc
    body = "".join(row.cert_pem for row in chain)
    return PlainTextResponse(body, media_type="application/x-pem-file")
