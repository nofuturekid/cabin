"""UI for API tokens (spec 0008 FR-6): create, list and revoke.

Superadmin-only, and the strictest page cabin has: a token here is a
standing credential for the whole API, which is a bigger grant than any
single certificate. The plaintext secret is rendered exactly once -- into
the response of the request that created it -- and is never stored, never
redirected through a URL, and never put in a flash message.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import api_tokens, audit, issuer_grants
from cabin.api_tokens import ApiToken, TokenError, token_status
from cabin.audit import Actor, AuditAction
from cabin.ca import service as ca_service
from cabin.ca.service import CACertificate
from cabin.users import Role, User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    get_db,
    require_role,
    verify_csrf,
)

router = APIRouter(prefix="/tokens")

require_superadmin = require_role(Role.superadmin)

_BAD_ROLE = "unknown role: {!r}"
_BAD_DATE = "the expiry date must look like 2026-12-31"
_PAST_DATE = "the expiry date must be in the future"
_FAR_DATE = "the expiry date is too far in the future: leave it empty for a token without expiry"


def _fmt(moment: datetime | None) -> str | None:
    """A stored (naive UTC) timestamp as the page shows it."""
    return moment.strftime("%Y-%m-%d %H:%M UTC") if moment is not None else None


def _token_row(
    db: Session,
    row: ApiToken,
    now: datetime,
    active_ids: set[int],
    all_intermediates: dict[int, CACertificate],
) -> dict[str, object]:
    """One table line, fully computed here: the template renders values, it
    does not decide them.

    Spec 0018 FR-11: ``granted_ids``/``granted_names`` describe this token's
    own grants, independent of any user's. ``retired_grants`` are grants on
    an issuer no longer active -- kept separate from the active set so the
    edit form (a checkbox per *active* intermediate) can preserve them as
    hidden fields instead of silently dropping them on the next save.
    """
    status = token_status(row, now)
    granted_ids = issuer_grants.issuers_of(db, issuer_grants.token_principal(row))
    return {
        "id": row.id,
        "label": row.label,
        "role": row.role,
        "created_at": _fmt(row.created_at),
        "last_used_at": _fmt(row.last_used_at) or "never",
        "expires_at": _fmt(row.expires_at) or "never",
        "status": status,
        "can_revoke": row.revoked_at is None,
        # A dead token's grants are shown but not editable -- there is
        # nothing left for them to permit.
        "can_edit_issuers": status == "active",
        "granted_ids": granted_ids,
        "granted_names": [
            all_intermediates[gid].name for gid in granted_ids if gid in all_intermediates
        ],
        "retired_grants": [
            {"id": gid, "name": all_intermediates[gid].name}
            for gid in granted_ids
            if gid not in active_ids and gid in all_intermediates
        ],
    }


def _page(
    request: Request,
    db: Session,
    user: User,
    error: str | None = None,
    secret: str | None = None,
    status_code: int = 200,
) -> Response:
    now = datetime.now(UTC)
    active_intermediates = ca_service.active_issuers(db)
    active_ids = {row.id for row in active_intermediates}
    all_intermediates = {row.id: row for row in ca_service.list_cas(db, kind="intermediate")}
    context = base_context(request, user)
    context.update(
        {
            "tokens": [
                _token_row(db, row, now, active_ids, all_intermediates)
                for row in api_tokens.list_tokens(db)
            ],
            "roles": list(Role),
            "error": error,
            "secret": secret,
            "active_intermediates": active_intermediates,
        }
    )
    response = templates.TemplateResponse(request, "tokens.html", context, status_code=status_code)
    # This page can carry a live credential -- no cache, anywhere, may keep
    # a copy of it (same rule as the certificate detail page).
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _parse_expiry(raw: str, now: datetime) -> datetime | None:
    """``YYYY-MM-DD`` (or empty for "never") -> the instant the token dies.

    The token stays usable through the *end* of the chosen day, UTC, which
    is what picking a date in a date field means to an operator.

    Every shape this field can arrive in is answered here, because the value
    comes straight off a form: unparsable, in the past, and -- the one that
    is easy to miss -- 9999-12-31, which a browser's native date picker
    offers as its maximum and whose "end of day" lies past
    :data:`datetime.max`.
    """
    value = raw.strip()
    if not value:
        return None
    try:
        day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TokenError(_BAD_DATE) from exc
    try:
        expires_at = day + timedelta(days=1)
    except OverflowError as exc:
        # A token expiring on the last day representable is one nobody meant
        # to bound; say so instead of turning a date picker click into a 500.
        raise TokenError(_FAR_DATE) from exc
    if expires_at <= now:
        raise TokenError(_PAST_DATE)
    return expires_at


def _parse_role(raw: str) -> Role:
    try:
        return Role(raw)
    except ValueError as exc:
        raise TokenError(_BAD_ROLE.format(raw)) from exc


@router.get("")
def tokens_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
) -> Response:
    return _page(request, db, user)


@router.post("")
def create_token(
    request: Request,
    label: str = Form(""),
    role: str = Form(Role.viewer.value),
    expires_at: str = Form(""),
    issuer_id: list[int] = Form([]),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Renders the page rather than redirecting: the secret exists only in
    this response, and a 303 would either lose it or leak it into a URL.

    Spec 0018 FR-11: ``issuer_id`` is optional and repeated, so a token can
    be born with its grants -- one created without any is an admin token
    that can do nothing until granted, which is the correct default.
    """
    try:
        parsed_role = _parse_role(role)
        expiry = _parse_expiry(expires_at, datetime.now(UTC))
        secret, row = api_tokens.create_token(db, label, parsed_role, expiry)
    except TokenError as exc:
        return _page(request, db, user, error=str(exc), status_code=400)
    # That a credential was minted, for whom and until when -- never the
    # credential itself (FR-3).
    audit.record(
        db,
        actor,
        AuditAction.token_created,
        summary=f"created API token {row.label!r} with role {row.role}",
        target_type="api_token",
        target_id=row.id,
        detail={
            "label": row.label,
            "role": row.role,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        },
        ip=client_ip(request, db),
    )
    if issuer_id:
        try:
            issuer_grants.set_issuers(db, issuer_grants.token_principal(row), issuer_id)
        except ValueError as exc:
            # The token was already created and its secret already minted --
            # losing the secret over a bad issuer id would be the worse bug
            # (FR-3: it exists only in this one response).
            return _page(request, db, user, error=str(exc), secret=secret, status_code=400)
    return _page(request, db, user, secret=secret)


@router.post("/{token_id}/issuers")
def update_token_issuers_route(
    token_id: int,
    request: Request,
    issuer_id: list[int] = Form([]),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0018 FR-11: replace this token's whole grant set. An unknown
    token id is a 404, deliberately unlike :func:`revoke_token`'s silence --
    that route is idempotent by design, this one is editing state that must
    exist."""
    row = api_tokens.get_token(db, token_id)
    if row is None:
        raise HTTPException(status_code=404)
    try:
        change = issuer_grants.set_issuers(db, issuer_grants.token_principal(row), issuer_id)
    except ValueError as exc:
        return _page(request, db, user, error=str(exc), status_code=400)
    if change.changed:
        audit.record(
            db,
            actor,
            AuditAction.token_issuers_changed,
            summary=f"changed issuer grants for token {row.label!r}",
            target_type="api_token",
            target_id=row.id,
            detail={"added": change.added, "removed": change.removed, "issuers": change.issuers},
            ip=client_ip(request, db),
        )
    return RedirectResponse("/tokens", status_code=303)


@router.post("/{token_id}/revoke")
def revoke_token(
    token_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Idempotent, and deliberately silent about an unknown id: the page
    lists exactly the tokens that exist, so "it is gone" is the same answer
    either way."""
    row = api_tokens.get_token(db, token_id)
    # An unknown token and an already-revoked one both leave the world
    # exactly as it was, so neither is an event.
    if row is None or row.revoked_at is not None:
        return RedirectResponse("/tokens", status_code=303)
    api_tokens.revoke_token(db, token_id)
    audit.record(
        db,
        actor,
        AuditAction.token_revoked,
        summary=f"revoked API token {row.label!r}",
        target_type="api_token",
        target_id=row.id,
        detail={"label": row.label, "role": row.role},
        ip=client_ip(request, db),
    )
    return RedirectResponse("/tokens", status_code=303)
