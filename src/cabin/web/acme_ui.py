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
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import eab
from cabin.acme.http import directory_url
from cabin.audit import Actor, AuditAction
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
    get_db,
    require_admin,
    verify_csrf,
)
from cabin.web.settings_ui import save_setting

#: See the module docstring: not ``/acme``.
PATH = "/acme/admin"

router = APIRouter(prefix=PATH)

_NO_BASE_URL = "set a base URL under Settings before enabling the ACME server"
#: Placeholders in the onboarding snippets, so an operator can see the shape
#: of the command before they have created a key.
_KID_PLACEHOLDER = "<key id>"
_HMAC_PLACEHOLDER = "<hmac key>"


def _key_row(row: eab.AcmeEabKey) -> dict[str, object]:
    """One table line, fully computed here: the template renders values, it
    does not decide them."""
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
    *,
    acme_enabled: bool | None = None,
    require_eab: bool | None = None,
    error: str | None = None,
    secret: str | None = None,
    secret_key_id: str | None = None,
    status_code: int = 200,
) -> Response:
    directory = directory_url(db)
    context = base_context(request, user)
    context.update(
        {
            # The submitted values win over the stored ones when a save was
            # refused, so the operator sees the form they sent back.
            "acme_enabled": (get_flag(db, ACME_ENABLED) if acme_enabled is None else acme_enabled),
            "acme_require_eab": (
                get_flag(db, ACME_REQUIRE_EAB) if require_eab is None else require_eab
            ),
            "acme_directory_url": directory,
            "base_url": get_setting(db, BASE_URL) or "",
            "keys": [_key_row(row) for row in eab.list_keys(db)],
            "secret": secret,
            "secret_key_id": secret_key_id,
            "error": error,
            # Shown with placeholders until a key exists, and with the real
            # key id right after one is created -- an operator pasting the
            # command then has to substitute one thing, not two.
            "snippet_directory": directory or "<base URL>/acme/directory",
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
) -> Response:
    return _page(request, db, user)


@router.post("")
def acme_settings(
    request: Request,
    acme_enabled: str = Form(""),
    acme_require_eab: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
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
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Renders the page rather than redirecting: the secret exists only in
    this response, and a 303 would either lose it or leak it into a URL."""
    row, secret = eab.create_key(db, request.app.state.secrets, label=label)
    # That a credential was minted and for whom -- never the credential
    # itself (spec 0009 FR-3).
    audit.record(
        db,
        actor,
        AuditAction.acme_eab_key_created,
        summary=f"created ACME external account key {row.label!r}",
        target_type="acme_eab_key",
        target_id=row.id,
        detail={"key_id": row.id, "label": row.label},
        ip=client_ip(request, db),
    )
    return _page(request, db, user, secret=secret, secret_key_id=row.id)


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
