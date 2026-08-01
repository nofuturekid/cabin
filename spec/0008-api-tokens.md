# Spec 0008 — API Tokens & REST

## Context

Everything so far is browser-driven. Automation (scripts, Ansible, the MCP
server in spec 0013) needs a token-authenticated JSON API. This spec adds API
tokens with roles and the REST surface over the existing domain services —
no new certificate logic, just a second front door.

## User Stories

- As an admin, I create an API token with a role and a label, copy the secret
  once, and use it from scripts.
- As a script, I issue a certificate, sign a CSR, list the inventory, fetch a
  certificate, and revoke one — all with `Authorization: Bearer …`.
- As an admin, I see all tokens (label, role, created, last used, expiry) and
  revoke any of them immediately.

## Functional Requirements

- FR-1: Migration 0006: `api_tokens` (id PK, label NOT NULL, token_hash UNIQUE
  NOT NULL, role NOT NULL CHECK superadmin/admin/viewer, created_at NOT NULL,
  last_used_at NULL, expires_at NULL, revoked_at NULL).
- FR-2: `cabin.api_tokens` module: `create_token(db, label, role, expires_at)`
  → (plaintext secret, row). Secret format `cabin_<43 chars urlsafe base64 of
32 random bytes>`; stored as `sha256(secret)` hex (fast hash is correct here
  — the secret is high-entropy, not a password). `verify_token(db, secret,
now)` → row or None (rejects revoked/expired; touches `last_used_at` at most
  once per minute). `list_tokens(db)`, `revoke_token(db, id)`.
- FR-3: Dependency `require_api_role(*roles)` in a new `cabin/web/api_deps.py`:
  parses `Authorization: Bearer <secret>`, verifies, enforces role, returns
  the token row. Failures → RFC 7807-ish JSON `{"detail": …}` with 401
  (missing/invalid) or 403 (role). API routes NEVER accept session cookies and
  never require CSRF — mutually exclusive auth paths.
- FR-4: REST under `/api/v1` (all JSON, OpenAPI-documented via response
  models):
  - `GET /ca` → CA info (subjects, fingerprints, validity, base_url) — viewer+
  - `GET /certificates?q=&status=&page=` → paginated list — viewer+
  - `GET /certificates/{id}` → metadata + cert_pem + chain_pem — viewer+
  - `POST /certificates` → issue (body: subject_cn, sans[], profile, key_type,
    days) → 201 with metadata + cert_pem + chain_pem + key_pem — admin+
  - `POST /certificates/sign` → sign CSR (csr_pem, profile, days, sans[]) →
    201 (no key_pem) — admin+
  - `POST /certificates/{id}/revoke` → (reason) → 200 with revocation info —
    admin+
  - `GET /crl` is NOT duplicated here (public /crl already exists).
    Domain errors (IssueError, CAImportError-like, RevocationError,
    CANotConfiguredError, SecretsError) map to 400/404/409 with a clear message,
    never a 500 traceback.
- FR-5: Pydantic models for every request/response; `key_pem` only ever
  appears in the POST-issue response and in GET /certificates/{id} when the
  caller is admin+ AND the key exists (viewer: field absent, not null-with-
  hint). Validation mirrors the UI limits (days 1..3650, ≤100 SANs, CN ≤64).
- FR-6: UI `/tokens` (superadmin only, CSRF): create form (label, role,
  optional expiry date), list with revoke buttons, one-time display of the new
  secret after creation (in-page, with a copy hint and a "shown once" warning).
  Nav entry "API tokens" for superadmins only — thread the role into the nav
  context via `base_context` (also fixes the existing Settings/Issue links
  being shown to viewers: hide entries the user cannot use).
- FR-7: `/api/v1/openapi.json` and `/api/v1/docs` are served (FastAPI's
  built-ins scoped to the API router) and require no auth for the schema
  itself (it documents, it does not expose data).

## Acceptance Criteria

- AC-1: Created token: response shows the secret once; DB stores only the
  sha256; the same secret authenticates; a wrong secret does not.
- AC-2: Expired token → 401; revoked token → 401; viewer token on a POST →
  403; missing header → 401 with JSON body (not an HTML redirect).
- AC-3: Session cookie alone does NOT authenticate any /api/v1 route (401),
  and an API token does NOT authenticate UI routes (303 to login).
- AC-4: POST /certificates issues a real certificate (parses, chains to the
  intermediate) and the response key_pem matches the certificate's public key;
  the row appears in GET /certificates.
- AC-5: POST /certificates/sign with the smuggling CSR from spec 0005 yields a
  leaf without CA extensions; bad CSR → 400 JSON with a message.
- AC-6: POST revoke marks it revoked and the serial appears in the CRL served
  by /crl; revoking twice → 200 both times (idempotent).
- AC-7: last_used_at updates on use (at most once per minute).
- AC-8: UI: superadmin creates and revokes tokens; admin/viewer get 403 on
  /tokens; nav shows the entry only for superadmins.

## Test list

test_create_token_returns_secret_once, test_token_hash_stored_not_secret,
test_verify_token_rejects_wrong_expired_revoked,
test_last_used_throttled, test_api_requires_bearer,
test_api_role_enforced, test_cookie_does_not_authenticate_api,
test_token_does_not_authenticate_ui, test_api_get_ca,
test_api_list_and_get_certificate, test_api_issue_certificate,
test_api_issue_key_visibility_by_role, test_api_sign_csr,
test_api_sign_csr_smuggling_blocked, test_api_revoke_updates_crl,
test_api_revoke_idempotent, test_api_errors_are_json_not_tracebacks,
test_openapi_served, test_ui_tokens_superadmin_only, test_nav_hides_unusable_entries

## Out of Scope

Rate limiting, token scopes finer than roles, JWT/OAuth, per-token audit
(spec 0009 covers audit generally), pagination cursors, webhooks.
