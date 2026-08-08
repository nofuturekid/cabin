"""The ACME operator page (spec 0012 FR-5): the two ACME switches, the
directory URL to hand a client, the external-account keys, and the commands
an operator copies into certbot or acme.sh.

**Where this lives.** The page is mounted at ``/acme/admin`` rather than at
``/acme`` itself, and the router is included *before* the ACME protocol
router in :func:`cabin.app.create_app`. Both halves of that matter.
``/acme`` is the protocol's own namespace: spec 0010 registers a route for
it precisely so that a bare ``GET /acme`` answers 404 instead of admitting,
via a redirect, that something lives under there while ACME is switched off
(AC-6). A UI page at that exact path would take that answer away. Being
registered first is what keeps the protocol router's catch-all -- which
matches every path and every method under ``/acme`` -- from swallowing this
page, and it is also what lets the page work while ACME is *off*, which it
must: turning ACME on is one of the things it is for.

Admin-only, like every page that exists to change something. The HMAC
secret of a new key is rendered exactly once, into the response of the
request that created it -- never stored in the clear, never redirected
through a URL, never shown again (see :mod:`cabin.acme.eab`).

**Spec 0019** gives an EAB key exactly one issuer (FR-1/FR-7) and makes
minting one a granted operation (FR-8): the issuer select on the create form
comes from this principal's own granted issuers, and the POST is refused --
403, no row written -- for one it does not name. It also turns "the
directory URL" into one row per intermediate (FR-13), because a directory
belongs to one issuer and there is no longer a single instance-wide address
to print. And it is where FR-12's boundary is stated in writing: with
external account binding switched off, an issuer grant does not stop an
ACME client from obtaining a certificate, and this page says so while the
switch that would close it is right there to flip.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import eab
from cabin.acme import http as acme_http
from cabin.audit import Actor, AuditAction
from cabin.ca import service as ca_service
from cabin.ca.service import IssuerRetiredError, UnknownIssuerError
from cabin.issuer_grants import (
    IssuerForbiddenError,
    NoGrantedIssuerError,
    Principal,
    granted_issuers,
    resolve_granted_issuer,
)
from cabin.settings import (
    ACME_ENABLED,
    ACME_REQUIRE_EAB,
    BASE_URL,
    FALSE,
    TRUE,
    get_flag,
    get_setting,
)
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    current_principal,
    get_db,
    require_admin,
    verify_csrf,
)
from cabin.web.settings_ui import save_setting

#: See the module docstring: not ``/acme``.
PATH = "/acme/admin"

router = APIRouter(prefix=PATH)

_NO_BASE_URL = "set a base URL under Settings before enabling the ACME server"
#: Spec 0019 FR-8: the two ways minting a key can be refused for a reason
#: that is not "you may not do this" -- an unknown, non-intermediate or
#: retired issuer, exactly like 0017's own issuance form (``certs_ui.py``).
_ISSUER_ERRORS = (UnknownIssuerError, IssuerRetiredError)
#: Spec 0019 FR-8: an authorization failure, not bad input -- 403, the
#: status 0018 FR-14 fixed for exactly this shape of refusal.
_GRANT_ERRORS = (IssuerForbiddenError, NoGrantedIssuerError)
#: Spec 0019 FR-8: shown next to the create form when this principal holds
#: no granted issuer at all -- the form still renders and the POST is still
#: refused server-side (AC-6); this is what tells the operator why before
#: they try.
_NO_GRANTED_ISSUER = "no issuer is granted to you: ask a superadmin to grant one under Users"
#: Placeholders in the onboarding snippets, so an operator can see the shape
#: of the command before they have created a key.
_KID_PLACEHOLDER = "<key id>"
_HMAC_PLACEHOLDER = "<hmac key>"
_DIRECTORY_PLACEHOLDER = "<the new key's own directory URL>"


def _issuer_rows(db: Session) -> list[dict[str, object]]:
    """Spec 0019 FR-13: one row per intermediate, active ones first --
    ``list_cas`` already orders by id, and a stable sort on "not active"
    keeps that order inside each of the two groups. Each row's URL is built
    through :func:`cabin.acme.http.directory_url`, the same function the
    ACME server itself resolves a directory with, never reassembled here.
    """
    intermediates = ca_service.list_cas(db, kind="intermediate")
    ordered = sorted(intermediates, key=lambda row: row.status != "active")
    return [
        {
            "id": row.id,
            "name": row.name,
            "status": row.status,
            "directory_url": acme_http.directory_url(db, row.id),
        }
        for row in ordered
    ]


def _key_row(row: eab.AcmeEabKey, issuer_names: dict[int, str]) -> dict[str, object]:
    """One table line, fully computed here: the template renders values, it
    does not decide them. ``issuer_names`` is looked up once per page render
    (spec 0019 FR-13's Issuer column) rather than once per row."""
    return {
        "id": row.id,
        "label": row.label,
        "created_at": _fmt(row.created_at),
        "bound_account_id": row.bound_account_id,
        "bound_at": _fmt(row.bound_at),
        "status": (
            "revoked" if row.revoked_at else ("bound" if row.bound_account_id else "unused")
        ),
        "can_revoke": row.revoked_at is None,
        "issuer_id": row.ca_certificate_id,
        "issuer_name": issuer_names.get(row.ca_certificate_id, f"#{row.ca_certificate_id}"),
    }


def _fmt(stored: str | None) -> str:
    """A stored ISO-8601 UTC timestamp as the page shows it."""
    if not stored:
        return "—"
    return datetime.fromisoformat(stored).strftime("%Y-%m-%d %H:%M UTC")


def _page(
    request: Request,
    db: Session,
    user: User,
    principal: Principal,
    *,
    acme_enabled: bool | None = None,
    require_eab: bool | None = None,
    error: str | None = None,
    secret: str | None = None,
    secret_key_id: str | None = None,
    secret_issuer_id: int | None = None,
    status_code: int = 200,
) -> Response:
    keys = eab.list_keys(db)
    issuer_names = {row.id: row.name for row in ca_service.list_cas(db, kind="intermediate")}
    issuer_options = granted_issuers(db, principal)
    context = base_context(request, user)
    context.update(
        {
            # The submitted values win over the stored ones when a save was
            # refused, so the operator sees the form they sent back.
            "acme_enabled": (get_flag(db, ACME_ENABLED) if acme_enabled is None else acme_enabled),
            "acme_require_eab": (
                get_flag(db, ACME_REQUIRE_EAB) if require_eab is None else require_eab
            ),
            "issuers": _issuer_rows(db),
            "base_url": get_setting(db, BASE_URL) or "",
            "keys": [_key_row(row, issuer_names) for row in keys],
            "issuer_options": issuer_options,
            "no_granted_issuer": _NO_GRANTED_ISSUER if not issuer_options else None,
            "secret": secret,
            "secret_key_id": secret_key_id,
            "error": error,
            # Shown with placeholders until a key exists, and with the real
            # key's own values right after one is created (spec 0019 FR-13):
            # an operator pasting the command then has to substitute
            # nothing, and cannot pair the right key with the wrong CA by
            # copying the wrong line.
            "snippet_directory": (
                acme_http.directory_url(db, secret_issuer_id)
                if secret_issuer_id is not None
                else _DIRECTORY_PLACEHOLDER
            ),
            "snippet_kid": secret_key_id or _KID_PLACEHOLDER,
            "snippet_hmac": secret or _HMAC_PLACEHOLDER,
        }
    )
    response = templates.TemplateResponse(request, "acme.html", context, status_code=status_code)
    # This page can carry a live credential -- no cache, anywhere, may keep a
    # copy of it (the same rule as /tokens and the certificate detail page).
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("")
def acme_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    principal: Principal = Depends(current_principal),
) -> Response:
    return _page(request, db, user, principal)


@router.post("")
def acme_settings(
    request: Request,
    acme_enabled: str = Form(""),
    acme_require_eab: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    principal: Principal = Depends(current_principal),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-5: the two ACME switches.

    ``acme_enabled`` is also on /settings, next to the base URL it depends
    on, and both write it through the same :func:`save_setting` -- so the
    audit log reads identically whichever page an operator used.
    """
    wants_acme = bool(acme_enabled)
    wants_eab = bool(acme_require_eab)
    if wants_acme and not get_setting(db, BASE_URL):
        # The same guard /settings has: without a base URL, ACME would have
        # to take the address it publishes from the request's Host header.
        return _page(
            request,
            db,
            user,
            principal,
            acme_enabled=wants_acme,
            require_eab=wants_eab,
            error=_NO_BASE_URL,
            status_code=400,
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
        ACME_REQUIRE_EAB,
        TRUE if get_flag(db, ACME_REQUIRE_EAB) else FALSE,
        TRUE if wants_eab else FALSE,
    )
    return RedirectResponse(PATH, status_code=303)


@router.post("/eab-keys")
def create_eab_key(
    request: Request,
    label: str = Form(""),
    issuer_id: int = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    principal: Principal = Depends(current_principal),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0019 FR-8: minting an EAB key is a granted operation -- the
    issuer this key will authorize has to be one 0018 granted this
    principal, resolved through the same
    :func:`cabin.issuer_grants.resolve_granted_issuer` every other granted
    door calls, not a second check invented here. An unknown, non-
    intermediate or retired issuer is 0017's own refusal (400); one that
    exists and is usable but is simply not granted to this principal is
    0018's (403). No key row is written on either.

    Renders the page rather than redirecting on success: the secret exists
    only in this response, and a 303 would either lose it or leak it into a
    URL.
    """
    try:
        issuer = resolve_granted_issuer(db, principal, issuer_id)
    except _GRANT_ERRORS as exc:
        return _page(request, db, user, principal, error=str(exc), status_code=403)
    except _ISSUER_ERRORS as exc:
        return _page(request, db, user, principal, error=str(exc), status_code=400)
    row, secret = eab.create_key(
        db, request.app.state.secrets, label=label, ca_certificate_id=issuer.id
    )
    # That a credential was minted, for whom and for which issuer -- never
    # the credential itself (spec 0009 FR-3; spec 0019 FR-14).
    audit.record(
        db,
        actor,
        AuditAction.acme_eab_key_created,
        summary=f"created ACME external account key {row.label!r}",
        target_type="acme_eab_key",
        target_id=row.id,
        detail={"key_id": row.id, "label": row.label, "issuer_id": issuer.id},
        ip=client_ip(request, db),
    )
    return _page(
        request,
        db,
        user,
        principal,
        secret=secret,
        secret_key_id=row.id,
        secret_issuer_id=issuer.id,
    )


@router.post("/eab-keys/{key_id}/revoke")
def revoke_eab_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Idempotent, and deliberately silent about an unknown id: the page
    lists exactly the keys that exist, so "it is gone" is the same answer
    either way."""
    row = eab.get_key(db, key_id)
    if eab.revoke_key(db, row) and row is not None:
        audit.record(
            db,
            actor,
            AuditAction.acme_eab_key_revoked,
            summary=f"revoked ACME external account key {row.label!r}",
            target_type="acme_eab_key",
            target_id=row.id,
            detail={"key_id": row.id, "label": row.label},
            ip=client_ip(request, db),
        )
    return RedirectResponse(PATH, status_code=303)
