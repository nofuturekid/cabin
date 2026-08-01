"""Instance settings (spec 0007 FR-6): the public base URL cabin bakes into
the CRL distribution point of newly issued certificates.

Admin-only, like every page that exists to change something.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.settings import (
    BASE_URL,
    SettingError,
    get_setting,
    set_setting,
    validate_base_url,
)
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import base_context, get_db, require_admin, verify_csrf

router = APIRouter(prefix="/settings")


def _page(
    request: Request,
    user: User,
    base_url: str,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    context = base_context(request, user)
    context.update({"base_url": base_url, "error": error})
    return templates.TemplateResponse(request, "settings.html", context, status_code=status_code)


@router.get("")
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    return _page(request, user, get_setting(db, BASE_URL) or "")


@router.post("")
def settings_submit(
    request: Request,
    base_url: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        value = validate_base_url(base_url)
    except SettingError as exc:
        # Hand the rejected input back, not an empty form: an operator fixes
        # a typo, they don't retype the URL.
        return _page(request, user, base_url, str(exc), status_code=400)
    set_setting(db, BASE_URL, value)
    return RedirectResponse("/settings", status_code=303)
