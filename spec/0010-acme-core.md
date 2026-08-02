# Spec 0010 — ACME Core (RFC 8555)

## Context

The largest self-built component: cabin's own ACME v2 server. This spec covers
the protocol skeleton — directory, nonces, JWS-authenticated requests,
accounts, orders and authorizations. Challenge validation lands in 0011,
finalize/certificate/revoke and EAB in 0012. Nothing here issues a
certificate yet; the goal is that a real client (certbot/acme.sh) can create
an account and an order and read back its authorizations.

**License guardrail:** django-ca and acme2certifier are GPLv3 — they may be
consulted for _behavior_ only. All code here is written from RFC 8555 /
RFC 7807 / RFC 7515 and the `josepy` API.

## User Stories

- As an ACME client, I fetch the directory, get a nonce, create an account
  with my key, and place an order for `nas.lan`.
- As an operator, ACME is off until I enable it, and I can see the directory
  URL to hand to clients.

## Functional Requirements

- FR-1: Dependency `josepy` for JWS/JWK handling.
- FR-2: Migration 0008 creates:
  - `acme_accounts` (id PK, kid_hash UNIQUE (sha256 of the account URL path
    segment), jwk_json NOT NULL, jwk_thumbprint UNIQUE NOT NULL (RFC 7638
    SHA-256, base64url), status NOT NULL (valid/deactivated/revoked),
    contacts_json, tos_agreed_at NULL, created_at)
  - `acme_nonces` (nonce PK, issued_at NOT NULL)
  - `acme_orders` (id PK, account_id FK NOT NULL, status NOT NULL
    (pending/ready/processing/valid/invalid), identifiers_json NOT NULL,
    not_before NULL, not_after NULL, expires_at NOT NULL, certificate_id NULL
    FK certificates, error_json NULL, created_at)
  - `acme_authorizations` (id PK, order_id FK NOT NULL, identifier_type NOT
    NULL (dns/ip), identifier_value NOT NULL, status NOT NULL
    (pending/valid/invalid/expired), expires_at NOT NULL, wildcard NOT NULL
    default 0)
  - `acme_challenges` (id PK, authz_id FK NOT NULL, type NOT NULL, token NOT
    NULL, status NOT NULL (pending/processing/valid/invalid), validated_at
    NULL, error_json NULL)
    All ids are opaque random strings (22+ chars urlsafe) used directly in URLs
    — no sequential integers in the ACME namespace.
- FR-3: `cabin/acme/` package, framework-light core:
  - `errors.py`: `AcmeError` with ACME problem types
    (urn:ietf:params:acme:error:\*) → JSON `application/problem+json` with the
    right HTTP status; `malformed`, `badNonce`, `unauthorized`,
    `accountDoesNotExist`, `rateLimited`, `serverInternal`,
    `unsupportedIdentifier`, `rejectedIdentifier`, `badPublicKey`,
    `badSignatureAlgorithm`, `userActionRequired`.
  - `nonces.py`: `issue(db)` (random 128-bit, stored), `consume(db, nonce)`
    (single-use, returns False if unknown/used/older than 24h), plus
    opportunistic purge.
  - `jws.py`: `verify_request(db, body, url, expected_kid_or_jwk)` —
    parses a flattened JWS (`protected`, `payload`, `signature`), enforces:
    alg in {RS256, ES256, ES384, EdDSA} (never `none`/HS\*), exactly one of
    `jwk`/`kid`, `url` header matching the request URL, `nonce` present and
    consumable, signature valid over `protected.payload`. Returns the parsed
    payload (JSON or empty for POST-as-GET) + the account/key context.
  - `service.py`: account/order/authz creation and lookup, status transitions,
    expiry defaults (`ORDER_LIFETIME = 7d`, `AUTHZ_LIFETIME = 7d`).
- FR-4: HTTP routes in `cabin/acme/api.py` under `/acme` (public, no session
  auth, no CSRF — JWS is the authentication):
  - `GET /acme/directory` → newAccount/newNonce/newOrder/revokeCert/keyChange
    URLs + `meta` (website, caaIdentities omitted; `externalAccountRequired`
    reflects the EAB setting placeholder, default false)
  - `HEAD|GET /acme/new-nonce` → 200/204 with `Replay-Nonce`
  - `POST /acme/new-account` → 201 (new) / 200 (existing key), `Location: kid`;
    honours `onlyReturnExisting`, `termsOfServiceAgreed`, `contact`
  - `POST /acme/account/{id}` (POST-as-GET or update contacts/deactivate)
  - `POST /acme/new-order` → 201 with identifiers, authorizations, finalize
    URL, expires; rejects unsupported identifier types and identifiers that
    fail the SAN policy from spec 0005 (`rejectedIdentifier`)
  - `POST /acme/order/{id}`, `POST /acme/authz/{id}`, `POST /acme/chal/{id}`
    (POST-as-GET; challenge POST with `{}` is spec 0011's trigger — here it
    returns the challenge object unchanged)
  - `POST /acme/key-change` may return `serverInternal`/unimplemented for now
    ONLY if documented; prefer implementing it (it is small) — decide and
    state it.
    Every response includes a fresh `Replay-Nonce`; every ACME error response
    too. `Link: <directory>;rel="index"` on ACME responses.
- FR-5: Enablement: setting `acme_enabled` (default false) on /settings. When
  off, all `/acme/*` routes return 404 (not 403 — do not advertise). When on
  and no CA exists → directory still serves, but new-order returns
  `serverInternal` with a clear detail. Directory URL shown on /settings and
  /ca when enabled (`<base_url>/acme/directory`).
- FR-6: Audit: account creation, order creation and account deactivation
  record events with `actor_kind="acme"` and the account thumbprint prefix as
  label.
- FR-7: Identifier policy: only `dns` and `ip`; DNS values are validated with
  the spec-0005 hostname rules (wildcards allowed as `*.example.com` — stored
  with `wildcard=1` and the base value); IP values via `ipaddress`.

## Acceptance Criteria

- AC-1: Directory returns all required fields; new-nonce returns a
  `Replay-Nonce` that is accepted exactly once (second use →
  `badNonce` 400 with a fresh nonce in the response).
- AC-2: JWS verification rejects: wrong signature, `alg: none`, HS256, both
  jwk+kid, neither, wrong `url`, missing/expired nonce, tampered payload —
  each with the correct ACME error type and HTTP status.
- AC-3: new-account with a fresh key → 201 + Location; same key again → 200
  with the same Location; `onlyReturnExisting` with an unknown key →
  `accountDoesNotExist` 400.
- AC-4: new-order for `nas.lan` → 201 with one pending authorization
  containing http-01, dns-01 and tls-alpn-01 challenges with distinct tokens;
  a wildcard order yields an authorization with `wildcard: true` and (per RFC)
  only a dns-01 challenge.
- AC-5: POST-as-GET (empty payload) works for account, order, authz and
  challenge; a GET (not POST) on those resources → 405.
- AC-6: With `acme_enabled=false` every `/acme/*` path returns 404.
- AC-7: An end-to-end test using the `acme` client library (the certbot ACME
  library, BSD-licensed — add as a DEV dependency only) registers an account
  and creates an order against the app, proving real-client compatibility.
- AC-8: Rejected identifiers (`http://x`, `nas.lan/../`, an unsupported type)
  return `rejectedIdentifier`/`unsupportedIdentifier`, not 500.

## Test list

test_directory_fields, test_new_nonce_headers, test_nonce_single_use,
test_jws_rejects_bad_signature, test_jws_rejects_none_and_hs256,
test_jws_rejects_jwk_and_kid_together, test_jws_rejects_wrong_url,
test_jws_rejects_stale_nonce, test_new_account_creates_and_is_idempotent,
test_only_return_existing, test_account_update_contacts_and_deactivate,
test_new_order_creates_authz_and_challenges, test_wildcard_order_dns01_only,
test_post_as_get_all_resources, test_get_method_not_allowed,
test_acme_disabled_returns_404, test_identifier_policy_rejections,
test_audit_records_acme_events, test_real_client_account_and_order

## Out of Scope

Challenge validation (0011), finalize/certificate/revokeCert/EAB (0012),
ARI (RFC 9773), CAA checking, rate limiting, account key rollover beyond
what FR-4 decides, pre-authorization, STAR certificates.
