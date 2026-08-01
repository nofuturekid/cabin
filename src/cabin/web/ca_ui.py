"""UI routes for the CA hierarchy (spec 0004 FR-5): wizard (create/import)
when no CA exists, an info page plus PEM downloads once one does. GETs
need only a logged-in session (viewer included, AC-5); the create/import
POSTs need role admin or superadmin plus CSRF.
"""

import threading

from cryptography import x509
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.service import CACertificate, CAExistsError
from cabin.ca.x509 import CAImportError
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/ca")

_MIN_YEARS = 1
_MAX_YEARS = 50

# Serializes create/import's check-then-insert so two near-simultaneous
# requests can't both see "no CA yet" and both create one -- mirrors
# ui.py's _setup_lock for the equivalent first-run race.
_ca_lock = threading.Lock()


def _cert_info(row: CACertificate) -> dict[str, object]:
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    info = ca_x509.describe_certificate(cert)
    info["kind"] = row.kind
    return info


def _years_error(root_years: int, intermediate_years: int) -> str | None:
    for value, field in (
        (root_years, "root_years"),
        (intermediate_years, "intermediate_years"),
    ):
        if not _MIN_YEARS <= value <= _MAX_YEARS:
            return f"{field} must be between {_MIN_YEARS} and {_MAX_YEARS}"
    if intermediate_years > root_years:
        return "intermediate_years must not exceed root_years"
    return None


def _key_type_error(key_type: str) -> str | None:
    if key_type not in ca_x509.KEY_TYPES:
        return f"key_type must be one of: {', '.join(ca_x509.KEY_TYPES)}"
    return None


@router.get("")
def ca_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    hierarchy = ca_service.get_ca(db)
    context = base_context(request, user)
    if hierarchy is None:
        context["error"] = None
        return templates.TemplateResponse(request, "ca_setup.html", context)
    context["certs"] = [_cert_info(hierarchy.root), _cert_info(hierarchy.intermediate)]
    return templates.TemplateResponse(request, "ca_info.html", context)


@router.post("/create")
def ca_create(
    request: Request,
    name: str = Form(...),
    key_type: str = Form("ecdsa-p256"),
    root_years: int = Form(20),
    intermediate_years: int = Form(10),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = _key_type_error(key_type) or _years_error(root_years, intermediate_years)
    if form_error is not None:
        context = base_context(request, user)
        context["error"] = form_error
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    try:
        with _ca_lock:
            ca_service.create_hierarchy(
                db,
                request.app.state.secrets,
                name,
                key_type=key_type,
                root_years=root_years,
                intermediate_years=intermediate_years,
            )
    except CAExistsError as exc:
        context = base_context(request, user)
        context["error"] = str(exc)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=409)
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
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        with _ca_lock:
            ca_service.import_hierarchy(
                db,
                request.app.state.secrets,
                cert_pem,
                key_pem,
                key_passphrase or None,
                chain_pem,
            )
    except CAExistsError as exc:
        context = base_context(request, user)
        context["error"] = str(exc)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=409)
    except CAImportError as exc:
        context = base_context(request, user)
        context["error"] = str(exc)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    return RedirectResponse("/ca", status_code=303)


@router.get("/root.pem")
def ca_root_pem(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    hierarchy = ca_service.get_ca(db)
    if hierarchy is None:
        raise HTTPException(status_code=404, detail="no CA configured")
    return PlainTextResponse(hierarchy.root.cert_pem, media_type="application/x-pem-file")


@router.get("/chain.pem")
def ca_chain_pem(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    hierarchy = ca_service.get_ca(db)
    if hierarchy is None:
        raise HTTPException(status_code=404, detail="no CA configured")
    body = hierarchy.root.cert_pem + hierarchy.intermediate.cert_pem
    return PlainTextResponse(body, media_type="application/x-pem-file")
