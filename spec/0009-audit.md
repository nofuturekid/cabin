# Spec 0009 — Audit Log

## Context

A CA must be able to answer "who issued/revoked what, and when". cabin has
three actors (UI users, API tokens, and later ACME accounts), so the audit
trail must record the actor kind, not just a user id. This spec adds an
append-only log, writes entries at every state-changing operation, and a
viewer UI.

## User Stories

- As an operator, I see a chronological log of logins, issuance, signing,
  revocation, CA setup, settings changes and user/token management.
- As an operator investigating an incident, I filter by actor, action or a
  free-text term and follow the link to the affected certificate.
- As an auditor, I can be confident entries are not edited or deleted through
  the app.

## Functional Requirements

- FR-1: Migration 0007: `audit_events` (id PK, occurred_at NOT NULL ISO UTC,
  actor_kind NOT NULL CHECK user/token/system/acme, actor_id NULL,
  actor_label NOT NULL (username / token label / "system"), action NOT NULL,
  target_type NULL, target_id NULL, summary NOT NULL, detail_json NULL,
  ip NULL). Index on occurred_at DESC and on action.
- FR-2: `cabin.audit` module: `Actor` dataclass (kind, id, label),
  `record(db, actor, action, *, summary, target_type=None, target_id=None,
detail=None, ip=None, now=None)` appending one row. Actions are a StrEnum
  `AuditAction`: login_success, login_failed, logout, user_created,
  user_role_changed, user_password_reset, user_deleted, ca_created,
  ca_imported, settings_changed, cert_issued, cert_signed, cert_revoked,
  token_created, token_revoked. No update/delete functions exist (append-only
  by construction).
- FR-3: `detail_json` never contains secrets: no private keys, no passwords,
  no token secrets, no CSR content — only identifiers, names, serials,
  profile/key_type, reasons, and changed setting keys with old/new values for
  non-secret settings.
- FR-4: Wiring — every state change records exactly one event:
  UI login/logout (incl. failed logins with the attempted username and IP),
  user management, CA create/import, settings change, issuance, CSR signing,
  revocation (UI, API and later ACME), token create/revoke. API routes record
  with `actor_kind="token"`; UI with `"user"`. Failures do not write an event
  (only successful state changes, except login_failed which is the point).
- FR-5: Actor resolution: a small dependency `current_actor` yields an `Actor`
  for UI sessions and API tokens; the client IP comes from
  `request.client.host`, honouring `X-Forwarded-For`'s first entry only when
  the setting `trust_proxy` is true (new setting, default false, in
  /settings).
- FR-6: UI `/audit` (any authenticated user; entries are metadata, not
  secrets): newest first, 50/page, filters `q` (substring over actor_label,
  action, summary), `action` (select) and `actor_kind`; each row shows time,
  actor (kind + label), action, summary, and links to `/certs/{id}` when
  target_type is "certificate". Nav entry "Audit".
- FR-7: `GET /api/v1/audit` (viewer+) returns the same data paginated as JSON.

## Acceptance Criteria

- AC-1: Every action in FR-4 produces exactly one row with the right
  actor_kind/label and a non-empty summary — one test per action group.
- AC-2: A failed login writes login_failed with the attempted username in
  summary and no user id; a successful one writes login_success.
- AC-3: detail_json for issuance contains serial/profile/key_type but no key
  material; for a settings change it contains the key and old/new values; a
  scan of all written events in the test suite finds no "PRIVATE KEY",
  password or token secret substring.
- AC-4: `/audit` lists newest first, filters work individually and combined,
  pagination behaves like the inventory (out-of-range → empty, no error).
- AC-5: Certificate links resolve to the right detail page; a deleted target
  does not break rendering.
- AC-6: `X-Forwarded-For` is ignored unless trust_proxy is on; when on, the
  first entry is stored.
- AC-7: `/api/v1/audit` mirrors the UI list for a token actor and rejects
  unauthenticated calls with 401.

## Test list

test_record_appends_row, test_actions_enum_complete,
test_login_success_and_failure_recorded, test_logout_recorded,
test_user_management_recorded, test_ca_create_import_recorded,
test_settings_change_recorded, test_cert_issued_recorded,
test_cert_signed_recorded, test_cert_revoked_recorded_ui_and_api,
test_token_create_revoke_recorded, test_no_secrets_in_details,
test_audit_list_filters, test_audit_pagination,
test_audit_cert_link, test_forwarded_for_respects_trust_proxy,
test_api_audit_list, test_api_audit_requires_token

## Out of Scope

Log export/rotation, tamper-evident hashing/signing of the log, retention
policy, syslog/SIEM forwarding, ACME events (wired when 0010-0012 land),
per-user visibility restrictions.

Two deliberate omissions, recorded here so they read as decisions rather
than oversights:

- **Reads are not audited.** FR-4 covers state changes only, so downloading
  a private key (`/certs/{id}/download/key.pem`) or a PKCS#12 bundle writes
  no event, even though both hand out key material. "Who exported this key"
  is a real audit question and wants a `cert_key_exported` action, but it is
  a different class of event from this spec's — one that a viewer's page
  refresh can trigger — and pulling it in would change what the log means.
  Deferred to its own spec.
- **No retention or rate limiting for `login_failed`.** Those rows are the
  only ones an unauthenticated caller can cause, so a login-guessing script
  grows the table unbounded. That is the accepted cost of recording failed
  logins at all in v1; retention (above) and login throttling both belong to
  a later spec, and neither changes the shape of the table.
