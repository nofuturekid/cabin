"""Instance settings: the public base URL cabin bakes into the CRL
distribution point of newly issued certificates (spec 0007 FR-6), whether an
``X-Forwarded-For`` header may be believed (spec 0009 FR-5), whether the
ACME server answers at all (spec 0010 FR-5), the two knobs ACME validation
has -- which addresses it may connect to and which resolvers it asks
(spec 0011 FR-5, FR-9) -- whether the MCP server answers, with the address
and the client command an operator needs for it (spec 0013 FR-4, FR-6), and,
with TLS on, which CA issuer signs cabin's own certificate (spec 0022 FR-17).

Admin-only, like every page that exists to change something. Each changed
key is one audit event with its old and new value; saving a form that
changes nothing records nothing.
"""

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.audit import Actor, AuditAction
from cabin.ca import service as ca_service
from cabin.mcp import endpoint_url as mcp_endpoint_url
from cabin.settings import (
    ACME_ENABLED,
    ALLOW_PRIVATE_VALIDATION_TARGETS,
    BASE_URL,
    DNS_RESOLVERS,
    FALSE,
    MCP_ENABLED,
    TLS_ISSUER_ID,
    TRUE,
    TRUST_PROXY,
    SettingError,
    get_flag,
    get_setting,
    set_setting,
    validate_base_url,
    validate_dns_resolvers,
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


def _tls_issuer_state(
    request: Request, db: Session
) -> tuple[bool, list[ca_service.CACertificate], str | None]:
    """Spec 0022 FR-17: whether the issuer select belongs on this page, the
    active issuers to offer, and which one -- if any -- counts as genuinely
    selected.

    ``selected`` is ``None`` whenever the stored value does not currently
    name an active intermediate -- unset, or naming one that has since been
    retired or never existed -- so the template can render the disabled
    placeholder instead of ever letting a browser fall back to highlighting
    its first ``<option>``, which would be indistinguishable from a real
    choice.
    """
    tls_enabled = bool(request.app.state.config.tls)
    if not tls_enabled:
        return False, [], None
    issuers = ca_service.active_issuers(db)
    valid_ids = {str(row.id) for row in issuers}
    stored = get_setting(db, TLS_ISSUER_ID) or ""
    selected = stored if stored in valid_ids else None
    return True, issuers, selected


def _page(
    request: Request,
    db: Session,
    user: User,
    base_url: str,
    trust_proxy: bool,
    acme_enabled: bool,
    mcp_enabled: bool,
    allow_private: bool,
    dns_resolvers: str,
    tls_enabled: bool,
    tls_issuers: list[ca_service.CACertificate],
    tls_issuer_selected: str | None,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    context = base_context(request, user)
    context.update(
        {
            "base_url": base_url,
            "trust_proxy": trust_proxy,
            "acme_enabled": acme_enabled,
            "mcp_enabled": mcp_enabled,
            # Spec 0013 FR-6: the address an operator pastes into their MCP
            # client, and None until there is a base URL to build it from --
            # the same rule the ACME directory URL below follows.
            "mcp_url": mcp_endpoint_url(db),
            # Spec 0011 FR-9: on unless it has been turned off, so the box
            # is ticked for an instance that has never touched it.
            "allow_private_validation_targets": allow_private,
            "dns_resolvers": dns_resolvers,
            # Spec 0022 FR-17: rendered only with TLS on, mirroring how the
            # issue form's own issuer selector renders only when there is a
            # choice to make (spec 0017 FR-14).
            "tls_enabled": tls_enabled,
            "tls_issuers": tls_issuers,
            "tls_issuer_selected": tls_issuer_selected,
            "error": error,
        }
    )
    return templates.TemplateResponse(request, "settings.html", context, status_code=status_code)


def save_setting(
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

    Public because the ACME page (spec 0012 FR-5) writes settings too, and
    two pages that record a settings change differently would be two
    versions of the audit log's most-read event.
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
    tls_enabled, tls_issuers, tls_issuer_selected = _tls_issuer_state(request, db)
    return _page(
        request,
        db,
        user,
        get_setting(db, BASE_URL) or "",
        get_flag(db, TRUST_PROXY),
        get_flag(db, ACME_ENABLED),
        get_flag(db, MCP_ENABLED),
        get_flag(db, ALLOW_PRIVATE_VALIDATION_TARGETS, default=True),
        get_setting(db, DNS_RESOLVERS) or "",
        tls_enabled,
        tls_issuers,
        tls_issuer_selected,
    )


@router.post("")
def settings_submit(
    request: Request,
    base_url: str = Form(""),
    trust_proxy: str = Form(""),
    acme_enabled: str = Form(""),
    mcp_enabled: str = Form(""),
    allow_private_validation_targets: str = Form(""),
    dns_resolvers: str = Form(""),
    tls_issuer_id: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    # An unticked checkbox sends nothing at all, which is what the empty
    # default here means -- off.
    wants_proxy = bool(trust_proxy)
    wants_acme = bool(acme_enabled)
    wants_mcp = bool(mcp_enabled)
    wants_private = bool(allow_private_validation_targets)
    tls_enabled = bool(request.app.state.config.tls)
    tls_issuer_choice = tls_issuer_id.strip()
    try:
        value = validate_base_url(base_url)
        resolvers = validate_dns_resolvers(dns_resolvers)
        if wants_acme and not value:
            # Spec 0010 FR-5: ACME hands clients absolute URLs and checks the
            # ones they sign against them, so without a base URL the server
            # would have to believe the request's own Host header. The gate
            # refuses to serve in that state; say so here rather than store a
            # setting that reads as on and answers 404.
            raise SettingError("set a base URL before enabling the ACME server")
        if wants_mcp and not value:
            # Spec 0013 FR-4: same story, and the same backstop in the gate --
            # the endpoint's whole purpose is an address to paste somewhere
            # else, and there is none to publish without a base URL.
            raise SettingError("set a base URL before enabling the MCP server")
        if tls_enabled and value:
            # Spec 0022 FR-13: with TLS on, the port a base URL names is the
            # *TLS* port -- the plaintext CDP/AIA listener runs on a
            # different one (CABIN_HTTP_PORT). An explicit port here, other
            # than 443 (which validate_base_url already drops), would be
            # baked into every certificate cabin issues as a CRL/AIA address
            # nothing is listening on, silently.
            port = urlparse(value).port
            if port is not None and port != 443:
                raise SettingError(
                    f"the base URL must not name an explicit port ({port}) while TLS is "
                    "on -- the plaintext CRL/AIA listener runs on a different port, and "
                    "certificates would carry an address nothing answers on"
                )
        if tls_enabled and tls_issuer_choice:
            try:
                issuer_row = ca_service.get_ca(db, int(tls_issuer_choice))
            except (ValueError, ca_service.UnknownIssuerError) as exc:
                raise SettingError("choose a valid, active issuer") from exc
            if issuer_row.kind != "intermediate" or issuer_row.status != "active":
                raise SettingError("choose a valid, active issuer")
    except SettingError as exc:
        # Hand the rejected input back, not an empty form: an operator fixes
        # a typo, they don't retype the URL.
        cur_tls_enabled, cur_tls_issuers, cur_tls_selected = _tls_issuer_state(request, db)
        return _page(
            request,
            db,
            user,
            base_url,
            wants_proxy,
            wants_acme,
            wants_mcp,
            wants_private,
            dns_resolvers,
            cur_tls_enabled,
            cur_tls_issuers,
            cur_tls_selected,
            str(exc),
            status_code=400,
        )
    previous_base_url = get_setting(db, BASE_URL) or ""
    save_setting(request, db, actor, BASE_URL, previous_base_url, value)
    save_setting(
        request,
        db,
        actor,
        TRUST_PROXY,
        TRUE if get_flag(db, TRUST_PROXY) else FALSE,
        TRUE if wants_proxy else FALSE,
    )
    save_setting(
        request,
        db,
        actor,
        ACME_ENABLED,
        TRUE if get_flag(db, ACME_ENABLED) else FALSE,
        TRUE if wants_acme else FALSE,
    )
    save_setting(
        request,
        db,
        actor,
        MCP_ENABLED,
        TRUE if get_flag(db, MCP_ENABLED) else FALSE,
        TRUE if wants_mcp else FALSE,
    )
    save_setting(
        request,
        db,
        actor,
        ALLOW_PRIVATE_VALIDATION_TARGETS,
        TRUE if get_flag(db, ALLOW_PRIVATE_VALIDATION_TARGETS, default=True) else FALSE,
        TRUE if wants_private else FALSE,
    )
    save_setting(
        request,
        db,
        actor,
        DNS_RESOLVERS,
        get_setting(db, DNS_RESOLVERS) or "",
        resolvers,
    )

    tls_issuer_changed = False
    if tls_enabled:
        previous_tls_issuer = get_setting(db, TLS_ISSUER_ID) or ""
        save_setting(request, db, actor, TLS_ISSUER_ID, previous_tls_issuer, tls_issuer_choice)
        tls_issuer_changed = previous_tls_issuer != tls_issuer_choice

    base_url_changed = previous_base_url != value
    if tls_enabled and (base_url_changed or tls_issuer_changed):
        # Spec 0022 FR-6/FR-17: either change can change what cabin's own
        # certificate should look like -- trigger the swap now rather than
        # waiting for the hourly check, so the new chain is served
        # immediately.
        tls_manager = request.app.state.tls
        if tls_manager is not None:
            tls_manager.ensure_current(db, request.app.state.secrets)
    return RedirectResponse("/settings", status_code=303)
