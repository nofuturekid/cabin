"""Instance settings: the public base URL cabin bakes into the CRL
distribution point of newly issued certificates (spec 0007 FR-6), whether an
``X-Forwarded-For`` header may be believed (spec 0009 FR-5), and whether the
ACME server answers at all (spec 0010 FR-5).

Admin-only, like every page that exists to change something. Each changed
key is one audit event with its old and new value; saving a form that
changes nothing records nothing.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme.http import directory_url
from cabin.audit import Actor, AuditAction
from cabin.settings import (
    ACME_ENABLED,
    BASE_URL,
    FALSE,
    TRUE,
    TRUST_PROXY,
    SettingError,
    get_flag,
    get_setting,
    set_setting,
    validate_base_url,
)
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/settings")


def _page(
    request: Request,
    db: Session,
    user: User,
    base_url: str,
    trust_proxy: bool,
    acme_enabled: bool,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    context = base_context(request, user)
    context.update(
        {
            "base_url": base_url,
            "trust_proxy": trust_proxy,
            "acme_enabled": acme_enabled,
            # Spec 0010 FR-5: the URL an operator hands to a client -- None
            # until a base URL is set, because an ACME directory is only
            # useful as an absolute URL, and one guessed from this request
            # would work in this browser and nowhere else.
            "acme_directory_url": directory_url(db),
            "error": error,
        }
    )
    return templates.TemplateResponse(request, "settings.html", context, status_code=status_code)


def _save(
    request: Request,
    db: Session,
    actor: Actor,
    key: str,
    current: str,
    value: str,
) -> None:
    """Store one setting and record the change -- or do neither, when the
    submitted value is the one already in effect. ``current`` is the
    *effective* value (a never-set flag reads as "false"), so the first save
    of an unchanged default is not logged as a change that never happened.
    """
    if current == value:
        return
    set_setting(db, key, value)
    audit.record(
        db,
        actor,
        AuditAction.settings_changed,
        summary=f"changed setting {key} from {current!r} to {value!r}",
        target_type="setting",
        target_id=key,
        detail=audit.setting_change_detail(key, current or None, value),
        ip=client_ip(request, db),
    )


@router.get("")
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    return _page(
        request,
        db,
        user,
        get_setting(db, BASE_URL) or "",
        get_flag(db, TRUST_PROXY),
        get_flag(db, ACME_ENABLED),
    )


@router.post("")
def settings_submit(
    request: Request,
    base_url: str = Form(""),
    trust_proxy: str = Form(""),
    acme_enabled: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    # An unticked checkbox sends nothing at all, which is what the empty
    # default here means -- off.
    wants_proxy = bool(trust_proxy)
    wants_acme = bool(acme_enabled)
    try:
        value = validate_base_url(base_url)
        if wants_acme and not value:
            # Spec 0010 FR-5: ACME hands clients absolute URLs and checks the
            # ones they sign against them, so without a base URL the server
            # would have to believe the request's own Host header. The gate
            # refuses to serve in that state; say so here rather than store a
            # setting that reads as on and answers 404.
            raise SettingError("set a base URL before enabling the ACME server")
    except SettingError as exc:
        # Hand the rejected input back, not an empty form: an operator fixes
        # a typo, they don't retype the URL.
        return _page(
            request,
            db,
            user,
            base_url,
            wants_proxy,
            wants_acme,
            str(exc),
            status_code=400,
        )
    _save(request, db, actor, BASE_URL, get_setting(db, BASE_URL) or "", value)
    _save(
        request,
        db,
        actor,
        TRUST_PROXY,
        TRUE if get_flag(db, TRUST_PROXY) else FALSE,
        TRUE if wants_proxy else FALSE,
    )
    _save(
        request,
        db,
        actor,
        ACME_ENABLED,
        TRUE if get_flag(db, ACME_ENABLED) else FALSE,
        TRUE if wants_acme else FALSE,
    )
    return RedirectResponse("/settings", status_code=303)
