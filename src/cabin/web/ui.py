"""UI routes: first-run setup, login/logout, dashboard, user management.

Server-rendered Jinja2 + plain form posts (FR-6/FR-7). All routes except
/setup and /login require an authenticated session; /setup 404s once a
user exists.
"""

import json
import threading
from datetime import UTC, datetime

from cryptography import x509
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit, issuer_grants, sessions, settings, users
from cabin.audit import Actor, ActorKind, AuditAction
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate
from cabin.ca.service import CACertificate
from cabin.tls import TlsMode
from cabin.users import (
    InvalidCredentialsError,
    LastSuperadminError,
    Role,
    User,
    UserExistsError,
    UserNotFoundError,
    WeakPasswordError,
)
from cabin.web import templates
from cabin.web.deps import (
    SESSION_COOKIE,
    base_context,
    client_ip,
    current_actor,
    flash,
    get_current_user,
    get_db,
    redirect_if_no_users,
    require_superadmin,
    set_session_cookie,
    verify_csrf,
)

router = APIRouter()

#: How many expiring certificates the dashboard lists before deferring to the
#: inventory, and how many audit events it shows (spec 0016 FR-2/FR-7).
EXPIRING_SHOWN = 10
RECENT_EVENTS = 5
#: A CA replacement needs planning, so its warning starts a year out (FR-4).
CA_WARN_DAYS = 365

# Serializes first-run setup's check-then-create so two near-simultaneous
# requests can't both see zero users and both try to create a superadmin.
# This only protects a single process; the IntegrityError catch below is the
# backstop for a true cross-process race (e.g. multiple workers).
_setup_lock = threading.Lock()


def _login_and_redirect(request: Request, db: Session, user: User, to: str) -> RedirectResponse:
    token, _ = sessions.create_session(db, user)
    # Every path that hands out a session goes through here -- /login and the
    # first-run /setup -- so recording it here is what makes "no session is
    # created without an event" true by construction (spec 0009 FR-4).
    audit.record(
        db,
        audit.user_actor(user),
        AuditAction.login_success,
        summary=f"login for {user.username!r}",
        target_type="user",
        target_id=user.id,
        ip=client_ip(request, db),
    )
    resp = RedirectResponse(to, status_code=303)
    set_session_cookie(resp, request, token)
    return resp


def _tls_mode(request: Request) -> TlsMode | None:
    """Spec 0022 FR-14 / Interface Contract R1: `app.state.tls` is `None`
    when TLS is off, and its own `.mode` is `None` before the first
    `ensure_current` has decided anything -- both collapse to "nothing to
    show" for the pages that read this.
    """
    tls = request.app.state.tls
    return tls.mode if tls is not None else None


def _tls_banner(request: Request, db: Session) -> dict[str, object] | None:
    """Spec 0022 FR-14: what the dashboard's TLS banner says, or None when
    there is nothing to say (TLS off, or no material decided yet).

    Self-signed and CA-issued must read differently -- a banner identical in
    both states is worse than none. For CA-issued, the root to link is read
    off the most recently issued ``source == "system"`` certificate (FR-6's
    ``CertSource.system``) rather than assumed to be "the" CA, since an
    instance can hold more than one hierarchy.
    """
    mode = _tls_mode(request)
    if mode is None:
        return None
    if mode == TlsMode.self_signed:
        return {"mode": mode.value, "root_cer_url": None}
    system_cert = db.scalar(
        select(Certificate).where(Certificate.source == "system").order_by(Certificate.id.desc())
    )
    root_cer_url = None
    if system_cert is not None:
        # Spec 0021 FR-8: deliberately `chains_for(...).self_signed`, NOT
        # `chain_for`'s new default (`web/ca_ui.py`'s chain.pem route uses
        # that default on purpose -- do not "fix" this to match it). Once a
        # cross certificate exists, the default chain runs through it to an
        # older root; inheriting that here would tell an operator to install
        # the OLD root to keep trusting this instance, when the right answer
        # is the root that will outlive the cross certificate. This banner's
        # only job is "which root keeps this instance trusted", and that is
        # always the self-signed one, whatever else is being served.
        self_signed = ca_service.chains_for(db, system_cert.issuer_id).self_signed
        root_cer_url = f"/ca/{self_signed.anchor_id}.cer"
    return {"mode": mode.value, "root_cer_url": root_cer_url}


def _anon_context(request: Request, error: str | None) -> dict[str, object]:
    """Context for pre-auth pages (setup/login): no user yet, but
    layout.html's ``{% if user %}`` still needs the key to exist now that
    undefined variables are a hard error. ``tls_self_signed`` is spec 0022
    FR-14's flag for setup.html's first-run warning note.
    """
    return {
        "user": None,
        "error": error,
        "tls_self_signed": _tls_mode(request) == TlsMode.self_signed,
    }


# --- first-run setup -------------------------------------------------------


@router.get("/setup")
def setup_form(request: Request, db: Session = Depends(get_db)) -> Response:
    if users.count_users(db) > 0:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "setup.html", _anon_context(request, None))


@router.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    with _setup_lock:
        if users.count_users(db) > 0:
            raise HTTPException(status_code=404)
        try:
            user = users.create_user(db, username, password, Role.superadmin)
        except WeakPasswordError as exc:
            return templates.TemplateResponse(
                request, "setup.html", _anon_context(request, str(exc)), status_code=400
            )
        except (UserExistsError, IntegrityError):
            db.rollback()
            return templates.TemplateResponse(
                request,
                "setup.html",
                _anon_context(request, "setup already completed by another request"),
                status_code=400,
            )
    # Nobody is logged in yet, so the actor is cabin itself: an audit trail
    # that starts one event *after* the account that owns the instance was
    # created has a hole exactly where it matters most.
    audit.record(
        db,
        audit.SYSTEM_ACTOR,
        AuditAction.user_created,
        summary=f"first-run setup created superadmin {user.username!r}",
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "role": Role.superadmin.value},
        ip=client_ip(request, db),
    )
    return _login_and_redirect(request, db, user, "/")


# --- login / logout ---------------------------------------------------------


@router.get("/login")
def login_form(request: Request, _: None = Depends(redirect_if_no_users)) -> Response:
    return templates.TemplateResponse(request, "login.html", _anon_context(request, None))


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    _: None = Depends(redirect_if_no_users),
) -> Response:
    try:
        user = users.verify_credentials(db, username, password)
    except InvalidCredentialsError:
        # The one event that is not a successful state change (FR-4/AC-2):
        # the attempted username is recorded as the label, but no user id --
        # a failed login proves nothing about who was at the keyboard, and
        # the username may not even exist.
        attempted = username[: audit.MAX_LABEL_LENGTH]
        audit.record(
            db,
            Actor(kind=ActorKind.user, id=None, label=attempted),
            AuditAction.login_failed,
            summary=f"failed login for {attempted!r}",
            ip=client_ip(request, db),
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            _anon_context(request, "invalid username or password"),
            status_code=401,
        )
    # Re-logging in while already holding a session for the SAME user
    # replaces it rather than accumulating a second live row. If the
    # presented cookie belongs to someone else (e.g. a shared/kiosk
    # browser), it's not ours to invalidate -- leave it alone.
    old_token = request.cookies.get(SESSION_COOKIE)
    if old_token:
        old_session = sessions.get_session(db, old_token)
        if old_session is not None and old_session.user_id == user.id:
            sessions.delete_session(db, old_token)
    sessions.purge_expired(db)
    return _login_and_redirect(request, db, user, "/")


@router.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> RedirectResponse:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sessions.delete_session(db, token)
    audit.record(
        db,
        actor,
        AuditAction.logout,
        summary=f"logout for {user.username!r}",
        target_type="user",
        target_id=user.id,
        ip=client_ip(request, db),
    )
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# --- dashboard ---------------------------------------------------------------


def _days_until(moment: datetime) -> int:
    """Whole days from now until ``moment``, negative once it is past."""
    return (moment - datetime.now(UTC)).days


def _ca_expiry(row: CACertificate, now: datetime) -> dict[str, object]:
    """One CA certificate as the dashboard states it (spec 0016 FR-4; spec
    0017 FR-14: per issuer, not "the" CA).

    A retired row is flagged only once it has actually expired: its
    remaining job is signing its CRL, and a year's notice on something
    already stood down is noise -- so ``CA_WARN_DAYS`` only applies while
    the row is still active.
    """
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    not_after = cert.not_valid_after_utc
    days = (not_after - now).days
    if row.status == "retired":
        tag = "tag-bad" if days <= 0 else ""
    else:
        # Replacing a CA is not a five-minute job, so the warning comes a
        # year out rather than at the 30 days a leaf gets.
        tag = "tag-bad" if days <= 0 else ("tag-warn" if days <= CA_WARN_DAYS else "")
    return {
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "status": row.status,
        "not_after": not_after.replace(microsecond=0).isoformat(),
        "days": days,
        "tag": tag,
    }


def _authorities(rows: list[CACertificate], now: datetime) -> list[dict[str, object]]:
    """Spec 0030 FR-8/FR-9: the dashboard's CA rows, grouped the way spec 0028
    FR-5 groups `/ca`'s.

    One entry per ``kind == "root"`` row and one per ``kind == "cross"`` row,
    in ``list_cas`` order, each carrying its root's intermediates under
    ``issuers``. Cross rows stay at root level for spec 0028 FR-5's reason --
    a cross row's name equals its subject root's name and the list has no
    column to tell them apart -- and they stay in the list at all because
    spec 0017 FR-14 makes this one entry per ``ca_certificates`` row, so that
    no CA certificate's expiry warning can go missing.

    ``_ca_expiry`` is untouched: the grouping is built *around* it, not into
    it, so the number the dashboard prints for a row is the number it prints
    today.
    """
    children: dict[int | None, list[CACertificate]] = {}
    for row in rows:
        if row.kind == "intermediate":
            children.setdefault(row.parent_id, []).append(row)
    entries: list[dict[str, object]] = []
    for row in rows:
        if row.kind not in {"root", "cross"}:
            continue
        entry = _ca_expiry(row, now)
        entry["issuers"] = [
            _ca_expiry(child, now)
            for child in (children.get(row.id, []) if row.kind == "root" else [])
        ]
        entries.append(entry)
    return entries


@router.get("/")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """FR-1: what an operator needs to see first — what expires, whether
    revocation is being published, and what happened last.

    One clock is taken here and passed to every figure on the page, so a
    count, a badge and a "days remaining" on the same render cannot straddle
    a tick (FR-8, the rule spec 0006 set for the inventory).
    """
    now = datetime.now(UTC)
    rows = ca_service.list_cas(db)
    context = base_context(request, db, user)
    context["ca_configured"] = bool(rows)
    # Spec 0022 FR-14: which certificate cabin itself is serving right now,
    # shown regardless of whether a CA hierarchy exists yet -- stage 1
    # (self-signed) is exactly the state before one does.
    context["tls_banner"] = _tls_banner(request, db)
    if not rows:
        # Nothing to summarise before there is a CA (AC-8).
        return templates.TemplateResponse(request, "dashboard.html", context)

    # Spec 0024 FR-7 (amended, see spec's Change log): `ca_configured` alone
    # is `True` for a lone root, which used to render a full body including
    # a `Revocation` section with an empty issuer table -- a heading, an
    # explanation and nothing. The notice must be per hierarchy, not
    # instance-wide: an instance-wide flag goes True the moment ANY
    # hierarchy gets an active issuer, hiding every other hierarchy's own
    # bare root. A retired-only hierarchy counts the same as a bare one --
    # `active_issuers` already filters on status == "active", so a root
    # whose only intermediate was retired falls out of this the same way an
    # never-issued root does.
    #
    # One query (`active_issuers`) plus the `rows` this handler already
    # fetched -- no query per hierarchy.
    roots_with_active_issuer = {row.parent_id for row in ca_service.active_issuers(db)}
    context["ca_no_issuer_roots"] = [
        row for row in rows if row.kind == "root" and row.id not in roots_with_active_issuer
    ]

    expiring = certs_service.expiring_soon(db, now, limit=EXPIRING_SHOWN)
    counts = certs_service.status_counts(db, now)
    events, _ = audit.list_events(db, page=1, per_page=RECENT_EVENTS)
    # Spec 0017 FR-14: one CRL block per issuer, not "the" CRL -- every
    # intermediate signs and serves its own.
    crls = [
        {
            "issuer_name": intermediate.name,
            "state": (
                {
                    "number": state.crl_number,
                    "generated_at": state.generated_at.replace(
                        tzinfo=UTC, microsecond=0
                    ).isoformat(),
                    "next_update": state.next_update.replace(microsecond=0).isoformat(),
                    "stale": state.next_update <= now,
                }
                if (state := crl_service.stored_crl(db, intermediate.id)) is not None
                else None
            ),
            "url": crl_service.distribution_url(db, intermediate.id),
        }
        for intermediate in rows
        if intermediate.kind == "intermediate"
    ]
    context.update(
        {
            "expiring": [
                {
                    "id": row.id,
                    "subject_cn": row.subject_cn,
                    "sans": len(json.loads(row.sans_json or "[]")),
                    "not_after": row.not_after,
                    "days": _days_until(datetime.fromisoformat(row.not_after)),
                }
                for row in expiring
            ],
            "expiring_more": counts["expiring"] > len(expiring),
            "counts": counts,
            # Spec 0017 FR-14: one entry per ca_certificates row, not the
            # pair [intermediate, root] of a single hierarchy. Spec 0030 FR-8
            # groups them; `ca_certs` is gone with the flat table, because a
            # context key with no reader is the next spec's puzzle.
            "authorities": _authorities(rows, now),
            "crls": crls,
            "events": [
                {
                    "occurred_at": event.occurred_at,
                    "actor_label": event.actor_label,
                    "action": event.action,
                    "summary": event.summary,
                }
                for event in events
            ],
        }
    )
    # FR-6: the services section repeats what /settings says, so it keeps
    # /settings' role. Aggregating must not hand a viewer configuration they
    # are refused one page over.
    may_see_settings = bool(context["nav"]["settings"])  # type: ignore[index]
    context["services"] = (
        {
            "base_url": settings.get_setting(db, settings.BASE_URL) or "",
            "acme": settings.get_flag(db, settings.ACME_ENABLED),
            "mcp": settings.get_flag(db, settings.MCP_ENABLED),
        }
        if may_see_settings
        else None
    )
    return templates.TemplateResponse(request, "dashboard.html", context)


# --- user management (superadmin only for mutations) --------------------------


def _user_issuers_view(
    db: Session, row: User, active_ids: set[int], all_intermediates: dict[int, CACertificate]
) -> dict[str, object]:
    """Spec 0018 FR-11: one user's row on the grants column -- the ids for
    the checkbox checked-state, the names for the read-only view, and any
    grant on a since-retired intermediate kept separate so the edit form
    (only active intermediates get a checkbox) can preserve it as a hidden
    field instead of silently dropping it on the next save.
    """
    is_superadmin = Role(row.role) == Role.superadmin
    granted_ids = (
        [] if is_superadmin else issuer_grants.issuers_of(db, issuer_grants.user_principal(row))
    )
    return {
        "is_superadmin": is_superadmin,
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


def _users_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
    *,
    edit: int | None = None,
) -> Response:
    """Spec 0030 FR-11: ``edit`` is which row stands open, and it is the only
    thing this function gained. Same rows, same ``_user_issuers_view``, same
    ``can_manage``, same ``roles``, same status code -- the open row is a
    branch in the template, not a second page."""
    active_intermediates = ca_service.active_issuers(db)
    active_ids = {row.id for row in active_intermediates}
    all_intermediates = {row.id: row for row in ca_service.list_cas(db, kind="intermediate")}
    rows = [
        {
            "id": row.id,
            "username": row.username,
            "role": row.role,
            "created_at": row.created_at,
            **_user_issuers_view(db, row, active_ids, all_intermediates),
        }
        for row in users.list_users(db)
    ]
    context = base_context(request, db, user)
    context.update(
        {
            "users": rows,
            "roles": list(Role),
            "error": error,
            "can_manage": Role(user.role) == Role.superadmin,
            "active_intermediates": active_intermediates,
            "edit": edit,
        }
    )
    return templates.TemplateResponse(request, "users.html", context, status_code=status_code)


def _parse_role(role: str) -> Role:
    try:
        return Role(role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid role") from exc


@router.get("/users")
def users_list(
    request: Request,
    edit: str = "",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Spec 0030 FR-11: ``?edit={id}`` opens one row, and an unrecognised
    value -- a non-integer, or an id no row has -- renders the page with
    every row closed at 200, which is the rule ``certs_list``'s ``?status=``
    and ``ca_detail``'s ``?add=`` already follow."""
    return _users_page(request, db, user, error=None, edit=_parse_edit(db, edit))


def _parse_edit(db: Session, raw: str) -> int | None:
    """FR-11: the query value, or ``None`` if nothing answers to it.

    ``?edit=`` is a request to open a row and never a grant -- ``can_manage``
    still gates every control on the page, which is the one hole URL state
    opens that a server-decided boolean did not.
    """
    try:
        user_id = int(raw)
    except (TypeError, ValueError):
        return None
    return user_id if db.get(User, user_id) is not None else None


@router.post("/users")
def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        created = users.create_user(db, username, password, _parse_role(role))
    except (WeakPasswordError, UserExistsError) as exc:
        return _users_page(request, db, user, str(exc), status_code=400)
    # Spec 0030 FR-3: one sentence per action in this project. The f-string is
    # bound here and handed to both the log and the panel, so the two cannot
    # drift apart.
    summary = f"created user {created.username!r} as {created.role}"
    audit.record(
        db,
        actor,
        AuditAction.user_created,
        summary=summary,
        target_type="user",
        target_id=created.id,
        detail={"username": created.username, "role": created.role},
        ip=client_ip(request, db),
    )
    flash(request, db, summary)
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/role")
def update_role_route(
    user_id: int,
    request: Request,
    role: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        # Read the old role before the change: "who was demoted from what" is
        # the question this event exists to answer.
        old_role = users.get_user(db, user_id).role
        changed = users.update_role(db, user_id, _parse_role(role))
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    except LastSuperadminError as exc:
        return _users_page(request, db, user, str(exc), status_code=400, edit=user_id)
    # Re-submitting the role a user already has leaves the world exactly as
    # it was, so it is not an event -- the same no-op guard the settings,
    # revocation and token-revoke routes apply. Spec 0030 FR-3: no event, no
    # flash either; a panel saying something happened when nothing did is
    # worse than no panel.
    if changed.role != old_role:
        summary = f"changed role of {changed.username!r} from {old_role} to {changed.role}"
        audit.record(
            db,
            actor,
            AuditAction.user_role_changed,
            summary=summary,
            target_type="user",
            target_id=changed.id,
            detail={
                "username": changed.username,
                "old_role": old_role,
                "new_role": changed.role,
            },
            ip=client_ip(request, db),
        )
        flash(request, db, summary)
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/password")
def reset_password_route(
    user_id: int,
    request: Request,
    password: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        target = users.reset_password(db, user_id, password)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    except WeakPasswordError as exc:
        return _users_page(request, db, user, str(exc), status_code=400, edit=user_id)
    # The old password can no longer be used to justify any of that user's
    # existing sessions, so they don't get to keep using them either.
    sessions.delete_sessions_for_user(db, user_id)
    # That a password was reset is the event; the password itself is not part
    # of it, not even hashed (FR-3).
    summary = f"reset the password of {target.username!r}"
    audit.record(
        db,
        actor,
        AuditAction.user_password_reset,
        summary=summary,
        target_type="user",
        target_id=target.id,
        detail={"username": target.username},
        ip=client_ip(request, db),
    )
    flash(request, db, summary)
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/issuers")
def update_user_issuers_route(
    user_id: int,
    request: Request,
    issuer_id: list[int] = Form([]),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0018 FR-11: replace ``target``'s whole grant set. An empty post
    (no ``issuer_id`` field at all) is how a grant is taken away entirely."""
    try:
        target = users.get_user(db, user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    try:
        change = issuer_grants.set_issuers(db, issuer_grants.user_principal(target), issuer_id)
    except ValueError as exc:
        return _users_page(request, db, user, str(exc), status_code=400, edit=user_id)
    # Re-posting a set that is already in place changes nothing, so it is not
    # an event -- the same no-op rule update_role_route already follows.
    if change.changed:
        summary = f"changed issuer grants for {target.username!r}"
        audit.record(
            db,
            actor,
            AuditAction.user_issuers_changed,
            summary=summary,
            target_type="user",
            target_id=target.id,
            detail={"added": change.added, "removed": change.removed, "issuers": change.issuers},
            ip=client_ip(request, db),
        )
        flash(request, db, summary)
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/delete")
def delete_user_route(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        # Copy what identifies the user out before the row is gone -- after
        # the delete there is nothing left to describe the event with.
        target = users.get_user(db, user_id)
        deleted_username, deleted_role = target.username, target.role
        users.delete_user(db, user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404) from exc
    except LastSuperadminError as exc:
        return _users_page(request, db, user, str(exc), status_code=400, edit=user_id)
    # Deletion only got this far if it actually succeeded (LastSuperadminError
    # above would have stopped it), so it's now safe to drop any sessions
    # that pointed at this user -- no orphan rows left behind.
    sessions.delete_sessions_for_user(db, user_id)
    summary = f"deleted user {deleted_username!r}"
    audit.record(
        db,
        actor,
        AuditAction.user_deleted,
        summary=summary,
        target_type="user",
        target_id=user_id,
        detail={"username": deleted_username, "role": deleted_role},
        ip=client_ip(request, db),
    )
    flash(request, db, summary)
    return RedirectResponse("/users", status_code=303)
