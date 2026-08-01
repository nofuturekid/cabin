# Spec 0003 — Auth & Users

## Context

Every later UI/API feature needs authentication and roles. This spec delivers
local users with argon2id hashing, DB-backed sessions, CSRF protection for UI
forms, a first-run setup flow that creates the superadmin, and the base UI
layout (Jinja2 + htmx, vendored assets) that all later pages extend.

## User Stories

- As the operator, on first start I'm guided to create the superadmin account
  before anything else is reachable.
- As a user, I log in with username/password and get a session cookie; logout
  kills the session server-side.
- As a superadmin, I manage users (create, change role, reset password,
  delete) — but can never delete/demote the last superadmin.
- As a viewer, I can see pages but every mutating action is denied.

## Functional Requirements

- FR-1: DB migration 0002 adds `users` (id PK, username UNIQUE NOT NULL,
  password_hash NOT NULL, role NOT NULL CHECK in superadmin/admin/viewer,
  created_at) and `sessions` (token_hash PK, user_id FK, created_at,
  expires_at).
- FR-2: Passwords: argon2id (`argon2-cffi`, library defaults), min length 12.
  `cabin.users` module: create/verify/list/update/delete + role enum; sentinel
  errors (`UserExistsError`, `InvalidCredentialsError`, `WeakPasswordError`,
  `LastSuperadminError`).
- FR-3: Sessions: 32-byte urlsafe token in cookie `cabin_session` (HttpOnly,
  SameSite=Lax, Secure iff `COOKIE_SECURE`), DB stores only `sha256(token)`;
  lifetime 24h sliding (touch on use, max 1 refresh/hour); expired rows purged
  opportunistically on login.
- FR-4: CSRF: per-session random token; all mutating UI POST forms carry it as
  hidden input `csrf_token`; mismatch → 403. (REST/ACME are exempt by design —
  they use tokens/JWS, not cookies; REST comes in spec 0008.)
- FR-5: First-run: if `users` is empty, every request redirects to `/setup`
  (GET form / POST create superadmin + auto-login). After setup, `/setup`
  → 404.
- FR-6: Routes: `GET/POST /login`, `POST /logout`, `GET /` (dashboard stub
  showing version + current user), `GET/POST /users` + row actions (htmx
  partials ok but plain forms acceptable); all under auth except
  /login, /setup, /healthz. Role guard: viewer=read-only pages,
  admin=mutations except user management, superadmin=everything.
- FR-7: Base template `layout.html` (nav: Dashboard, Users; footer with
  version), vendored `htmx.min.js` + `cabin.css` served from `/static`
  (go:embed-style: files inside the package, no CDN). Design tokens as CSS
  custom properties; dark mode via `prefers-color-scheme`.
- FR-8: New deps: `argon2-cffi`, `python-multipart`. `itsdangerous` NOT used —
  sessions are DB-backed, not signed cookies.

## Acceptance Criteria

- AC-1: Fresh DB → GET / redirects to /setup; POST /setup with 12+ char
  password creates superadmin, logs in, redirects to /; /setup afterwards 404.
- AC-2: POST /login wrong password → error, no cookie; correct → cookie set
  (HttpOnly, SameSite=Lax; Secure iff COOKIE_SECURE), GET / shows username.
- AC-3: POST /logout deletes the session row; the old cookie no longer
  authenticates.
- AC-4: Mutating POST without/with wrong csrf_token → 403 and no change.
- AC-5: viewer POSTing a mutation → 403; admin managing users → 403;
  superadmin managing users → ok.
- AC-6: Deleting/demoting the last superadmin → error, user unchanged.
- AC-7: Session row expired → request unauthenticated (redirect /login).
- AC-8: Weak password (<12) rejected on setup, user-create, and password
  reset.

## Test list

test_setup_flow_first_run, test_setup_404_after_users_exist,
test_login_wrong_password, test_login_sets_cookie_flags,
test_logout_invalidates_session, test_csrf_missing_or_wrong_403,
test_role_viewer_cannot_mutate, test_role_admin_cannot_manage_users,
test_last_superadmin_protected, test_expired_session_unauthenticated,
test_weak_password_rejected, test_password_hash_is_argon2id

## Out of Scope

Password self-service/reset mails, 2FA, OIDC/LDAP, API tokens (spec 0008),
audit entries (spec 0009), rate limiting.
