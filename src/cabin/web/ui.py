"""UI routes: first-run setup, login/logout, dashboard, user management.

Server-rendered Jinja2 + plain form posts (FR-6/FR-7). All routes except
/setup and /login require an authenticated session; /setup 404s once a
user exists.
"""

import threading

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit, sessions, users
from cabin.audit import Actor, ActorKind, AuditAction
from cabin.ca import service as ca_service
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
    get_current_user,
    get_db,
    redirect_if_no_users,
    require_role,
    set_session_cookie,
    verify_csrf,
)

router = APIRouter()

require_superadmin = require_role(Role.superadmin)

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


def _anon_context(error: str | None) -> dict[str, object]:
    """Context for pre-auth pages (setup/login): no user yet, but
    layout.html's ``{% if user %}`` still needs the key to exist now that
    undefined variables are a hard error.
    """
    return {"user": None, "error": error}


# --- first-run setup -------------------------------------------------------


@router.get("/setup")
def setup_form(request: Request, db: Session = Depends(get_db)) -> Response:
    if users.count_users(db) > 0:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "setup.html", _anon_context(None))


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
                request, "setup.html", _anon_context(str(exc)), status_code=400
            )
        except (UserExistsError, IntegrityError):
            db.rollback()
            return templates.TemplateResponse(
                request,
                "setup.html",
                _anon_context("setup already completed by another request"),
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
    return templates.TemplateResponse(request, "login.html", _anon_context(None))


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
            _anon_context("invalid username or password"),
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


@router.get("/")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    context = base_context(request, user)
    context["ca_configured"] = ca_service.get_ca(db) is not None
    return templates.TemplateResponse(request, "dashboard.html", context)


# --- user management (superadmin only for mutations) --------------------------


def _users_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
) -> Response:
    context = base_context(request, user)
    context.update(
        {
            "users": users.list_users(db),
            "roles": list(Role),
            "error": error,
            "can_manage": Role(user.role) == Role.superadmin,
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
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    return _users_page(request, db, user, error=None)


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
    audit.record(
        db,
        actor,
        AuditAction.user_created,
        summary=f"created user {created.username!r} as {created.role}",
        target_type="user",
        target_id=created.id,
        detail={"username": created.username, "role": created.role},
        ip=client_ip(request, db),
    )
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
        return _users_page(request, db, user, str(exc), status_code=400)
    # Re-submitting the role a user already has leaves the world exactly as
    # it was, so it is not an event -- the same no-op guard the settings,
    # revocation and token-revoke routes apply.
    if changed.role != old_role:
        audit.record(
            db,
            actor,
            AuditAction.user_role_changed,
            summary=f"changed role of {changed.username!r} from {old_role} to {changed.role}",
            target_type="user",
            target_id=changed.id,
            detail={
                "username": changed.username,
                "old_role": old_role,
                "new_role": changed.role,
            },
            ip=client_ip(request, db),
        )
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
        return _users_page(request, db, user, str(exc), status_code=400)
    # The old password can no longer be used to justify any of that user's
    # existing sessions, so they don't get to keep using them either.
    sessions.delete_sessions_for_user(db, user_id)
    # That a password was reset is the event; the password itself is not part
    # of it, not even hashed (FR-3).
    audit.record(
        db,
        actor,
        AuditAction.user_password_reset,
        summary=f"reset the password of {target.username!r}",
        target_type="user",
        target_id=target.id,
        detail={"username": target.username},
        ip=client_ip(request, db),
    )
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
        return _users_page(request, db, user, str(exc), status_code=400)
    # Deletion only got this far if it actually succeeded (LastSuperadminError
    # above would have stopped it), so it's now safe to drop any sessions
    # that pointed at this user -- no orphan rows left behind.
    sessions.delete_sessions_for_user(db, user_id)
    audit.record(
        db,
        actor,
        AuditAction.user_deleted,
        summary=f"deleted user {deleted_username!r}",
        target_type="user",
        target_id=user_id,
        detail={"username": deleted_username, "role": deleted_role},
        ip=client_ip(request, db),
    )
    return RedirectResponse("/users", status_code=303)
