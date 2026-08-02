# Changelog

All notable changes to cabin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor = feature, patch = fix).

## [Unreleased]

### Added

- Spec 0001 (foundation): project skeleton, config (flag > env > default),
  SQLite via SQLAlchemy + Alembic with migrations applied at startup,
  `/healthz` endpoint, `cabin` CLI entry point, CI (ruff, mypy, pytest).
- Spec 0002 (crypto-secrets): `cabin.secrets.SecretStore` with AES-256-GCM
  seal/unseal, atomic `secret.key` creation (mode 0600), optional
  `CABIN_MASTER_PASSPHRASE`-derived scrypt KEK wrapping the master key, and
  `app.state.secrets` wired up during app startup.
- Spec 0003 (auth-users): local users with argon2id password hashing and
  superadmin/admin/viewer roles (`cabin.users`), DB-backed sliding sessions
  with sha256-hashed cookie tokens (`cabin.sessions`), CSRF-protected UI
  forms, a first-run `/setup` flow that creates the superadmin and 404s
  afterwards, and a server-rendered Jinja2 + htmx base layout with vendored
  static assets served from `/static`. New `COOKIE_SECURE` config flag.
- Spec 0004 (ca-core): create or import the CA hierarchy (`cabin.ca.x509`
  pure crypto, `cabin.ca.service` orchestration), root+intermediate wizard
  defaulting to ecdsa-p256 (ecdsa-p384/rsa-4096/ed25519 also supported),
  import of an existing signing CA with validation (key match,
  BasicConstraints, KeyUsage, expiry, single-level chain), sealed private
  keys in the new `ca_certificates` table (migration 0003), and a `/ca` UI
  with root/chain PEM downloads open to any logged-in user.
- Spec 0005 (issue-sign): leaf issuance with `server`/`client` profiles
  (`cabin.ca.leaf` pure crypto, `cabin.ca.certs` storage), either with a
  server-generated key sealed into the new `certificates` table
  (migration 0004) or by signing a pasted CSR — which contributes only its
  public key, CN and SANs, never its extensions. One SAN policy for form
  and CSR input alike (`dns:`/`ip:`/`email:` prefixes, auto-detection,
  CN fallback, ASCII/punycode hostnames), validity of
  1..3650 days clamped to the intermediate, and a `/certs/new` UI plus a
  `/certs/{id}` result page whose private key block is admin-only.
- Spec 0006 (inventory-download): a paginated `/certs` inventory (50 per
  page) with case-insensitive text search over CN, SANs and serial, a
  valid/expiring/expired status filter and 30-day expiry badges, plus
  per-certificate downloads — leaf PEM and full chain for any logged-in
  user, private key PEM and password-protected PKCS#12 bundles for admins,
  all served as no-store attachments named after CN and serial.
- Spec 0007 (revoke-crl): certificate revocation with reason codes
  (`cabin.ca.revocation` pure CRL building, `cabin.ca.crl` storage and
  orchestration), a single current CRL with a monotonic CRL number kept in
  the new `crl_state` table (migration 0005, which also adds `revoked_at`
  and `revocation_reason` to `certificates`), and public `GET /crl` (DER)
  and `GET /crl.pem` endpoints that regenerate a stale CRL on access — no
  scheduler, no login. Newly issued certificates carry a CRL distribution
  point derived from a new `base_url` setting, configurable by admins at
  `/settings`; without it they are issued without a CDP. The inventory
  gains a `revoked` status filter and badge (revocation outranks expiry),
  and the certificate detail page an admin-only, CSRF-protected revoke form.
- Spec 0008 (api-tokens): API tokens with viewer/admin/superadmin roles,
  optional expiry and immediate revocation (`cabin.api_tokens`, migration
  0006), stored as a sha256 digest of a 32-byte secret and shown in
  plaintext exactly once — on the new superadmin-only `/tokens` page that
  creates, lists and revokes them. A token-authenticated REST API under
  `/api/v1` (`Authorization: Bearer …`, never cookies, never CSRF) covering
  CA info, the paginated inventory, certificate detail, issuance, CSR
  signing and revocation, with Pydantic request/response models mirroring
  the UI's limits, domain errors mapped to 400/404/409 JSON bodies instead
  of tracebacks, and its own OpenAPI document at `/api/v1/openapi.json`
  plus a Swagger UI at `/api/v1/docs` served entirely from vendored assets
  (swagger-ui-dist 5.32.11, no CDN — it works on an isolated network, like
  the rest of cabin's UI). Navigation now hides the entries a
  role cannot use (Issue for viewers, Settings for non-admins, API tokens
  for non-superadmins); the route guards are unchanged.
- Spec 0009 (audit): an append-only audit log (`cabin.audit`, migration 0007) recording every state change with the actor that caused it — a UI
  user, an API token, or cabin itself, so the trail stays readable once
  ACME accounts join them. Logins (including failed ones, with the
  attempted username), logouts, user management, CA creation and import,
  settings changes, issuance, CSR signing, revocation and token
  create/revoke each write exactly one event; failed and no-op requests
  write none. Entries carry identifiers, names, serials, profiles and
  reasons only — never key material, passwords, token secrets or CSR
  bodies. A new `/audit` page (any authenticated user) lists them newest
  first, 50 per page, filtered by text, action and actor kind, and links
  certificate targets to their detail page; `GET /api/v1/audit` returns the
  same for viewer+ tokens. New `trust_proxy` setting (default off) decides
  whether `X-Forwarded-For` may be believed for the recorded client IP.
- Spec 0010 (acme-core): cabin's own ACME v2 server (`cabin.acme`, migration
  0008), written from RFC 8555 — directory, single-use nonces (128-bit,
  spent by the DELETE that reads them, expiring after 24h), JWS request
  verification against an explicit algorithm allowlist (RS256/ES256/ES384/
  EdDSA — never `none`, never HS\*, never a key that cannot carry the
  algorithm it announces), and account, order, authorization and challenge
  resources. Accounts are identified by their RFC 7638 key thumbprint, so
  new-account is idempotent on the key; `onlyReturnExisting`, contact
  updates, deactivation and key rollover (RFC 8555 7.3.5) are all
  implemented. An order for `nas.lan` yields one pending authorization with
  http-01, dns-01 and tls-alpn-01 challenges carrying distinct tokens; a
  wildcard yields a `wildcard: true` authorization with dns-01 only, and an
  IP identifier one without dns-01 (RFC 8738). Identifiers go through the
  SAN policy of spec 0005, so a name that could not be typed into the
  issuance form cannot arrive through an order either; DNS names are
  case-folded, and an order or authorization past its `expires` reads as
  invalid/expired however the row was left. POSTs must be
  `application/jose+json` (415 otherwise, RFC 8555 6.2), and every response
  to one — success and RFC 7807 problem document alike — carries a fresh
  `Replay-Nonce`, attached by middleware so no route can omit it; the
  directory `Link: <directory>;rel="index"` is on every ACME response.
  Account creation, order creation and deactivation are audited with
  `actor_kind="acme"` and the account key's thumbprint prefix as the label.
  All of it is behind a new `acme_enabled` setting, default off, and off
  means 404 on every `/acme/…` path rather than 403. Enabling it requires
  the `base_url` setting: every URL cabin publishes, and the RFC 8555 6.4
  check that a signature covers the URL it was sent to, come from that
  setting alone and never from the request's `Host` header. The directory
  URL is shown on /settings and /ca once it is on. Challenge validation
  (0011) and
  finalize/certificate/revokeCert/EAB (0012) are not implemented yet: those
  URLs are advertised, as RFC 8555 requires, and answer with a 501 problem
  document rather than a bare 404. Interoperability is verified against the
  certbot `acme` client library, added as a dev dependency; `josepy` is a
  new runtime dependency.
- Spec 0011 (acme-challenges): the three RFC 8555/8737 validation methods
  (`cabin.acme.validation`), so an ACME client can actually prove control of
  a name. One key-authorization helper (RFC 8555 8.1) feeds all three:
  http-01 fetches `http://<identifier>/.well-known/acme-challenge/<token>`
  on port 80, follows up to five redirects (each one address-checked again),
  reads at most 64 KiB and compares in constant time; dns-01 reads TXT
  records at `_acme-challenge.<identifier>` through dnspython and accepts any
  record carrying the digest; tls-alpn-01 opens a TLS connection with ALPN
  `acme-tls/1` and checks the presented certificate's SAN and its critical
  `id-pe-acmeIdentifier` extension. `POST /acme/chal/{id}` with an empty JSON
  object triggers a validation — it answers immediately with the challenge in
  `processing` plus `Link: <authz>;rel="up"` and runs the attempt as a
  background task with a session of its own, with no retries. One monotonic
  deadline of 10 seconds bounds the whole attempt rather than each operation
  inside it, so a target that dribbles a response out one byte at a time, or
  a slow chain of redirects, cannot hold a worker thread indefinitely. The
  move out of `pending` is a conditional UPDATE, so two triggers that arrive
  together produce one validation, and a late failure can no longer overwrite
  a challenge that has already succeeded. Re-triggering a processing or valid
  challenge is a no-op;
  triggering a failed one, or one whose authorization is no longer pending,
  is `malformed`. A valid challenge makes its authorization valid, and an
  order whose authorizations are all valid now reads `ready` (an expired or
  failed one makes it `invalid`); a failed challenge carries an RFC 7807
  problem document in its `error` field and leaves the authorization pending,
  so another challenge type can still be tried. Every attempt is audited as
  `acme_challenge_validated` / `acme_challenge_failed`. Validation targets
  are attacker-influenced, so identifiers are resolved before connecting and
  refused when any resolved address is loopback, link-local, multicast or
  unspecified — including the IPv4-mapped, IPv4-compatible, 6to4 and NAT64
  spellings of those. Every redirect hop is resolved and checked again, and
  only ports 80 and 443 are followed, so a redirect cannot aim validation at
  an arbitrary internal port; a connection-level failure tells the client
  only that cabin could not reach the name, while the audit log keeps the
  precise reason and address. Private addresses are allowed by default (an
  internal CA validates RFC 1918 hosts by definition) and can be switched off
  with the new `allow_private_validation_targets` setting; the new
  `dns_resolvers` setting (comma-separated IPs) overrides the system resolver
  for dns-01. Both are configurable on /settings. `httpx2` is a new runtime
  dependency for the outbound HTTP of http-01, alongside `dnspython`. The
  certbot client drives trigger, validation and polling to a valid
  authorization end to end in the interop test.
- Spec 0012 (acme-finalize-eab): the end of an ACME order, which completes
  the ACME server. `POST /acme/order/{id}/finalize` takes the client's CSR
  (base64url DER), checks its signature and requires its subjectAltName set
  to be *exactly* the order's identifiers — DNS names compared
  case-insensitively, IPs compared as addresses, a wildcard identifier
  matching the wildcard SAN — and a common name, if present, to be one of
  them; each mismatch is its own `badCSR` detail (`cabin.acme.csr`). The key
  a CSR asks cabin to certify is held to the same floor as an account key —
  RSA of at least `jws.MIN_RSA_BITS`, P-256, P-384 or Ed25519 — so a client
  cannot be issued for a key it could not have registered with. A CSR with
  no subject at all is accepted, as RFC 8555 7.4 allows and the certbot
  library produces: its common name is then the first ordered identifier
  short enough to be one, and an order whose names are all longer than 64
  characters is issued with an empty subject and a critical subjectAltName
  (RFC 5280 4.2.1.6) rather than refused. Issuance goes through the
  spec-0005 path with the `server` profile, the configured CRL distribution
  point and the SANs taken from the order rather than from the CSR. The move
  out of `ready` is a conditional UPDATE, so two finalize requests that
  arrive together mint one certificate, not two — the loser is answered with
  the `processing` order and a `Retry-After`; finalizing an already-issued
  order returns the same order and the same certificate URL, and an issuance
  that fails puts the order back where it was.
  `POST /acme/cert/{id}` (POST-as-GET, ownership checked against the order)
  serves leaf + intermediate + root as `application/pem-certificate-chain`;
  an id that is not a row id — out of range, non-ASCII digits, a leading
  zero — is the same 404 problem document as an unknown one.
  `POST /acme/revoke-cert` implements both authorizations of RFC 8555 7.6 —
  the account that placed the order, or a JWS signed with the certificate's
  own key pair, matched on its DER SubjectPublicKeyInfo — accepts only the
  RFC 5280 reason codes spec 0007 can put on a CRL (`removeFromCRL`,
  `certificateHold` and the CA-compromise codes are `badRevocationReason`),
  answers `alreadyRevoked` on the second attempt, refuses a certificate
  cabin did not issue after comparing the submitted bytes rather than
  trusting its serial, and republishes the CRL. External account binding
  (RFC 8555 7.3.4) arrives with the new `acme_require_eab` setting, which
  the directory's `meta.externalAccountRequired` reflects: the inner JWS is
  verified on a separate, explicit HS256 path that shares no algorithm table
  with the account-key allowlist, with the MAC compared in constant time,
  and the operator's HMAC keys are stored sealed (`acme_eab_keys`, migration
  0009) and shown exactly once, base64url, on creation. A key binds one
  account, enforced by a conditional UPDATE plus a unique index; revoked and
  already-bound keys — and a second key for an account that already has one,
  which loses against the index — are refused with one wording, so a client
  learns nothing about which keys exist. New admin page `/acme/admin` (nav
  entry "ACME") with the two ACME switches, the directory URL, the EAB key
  table and copy-ready certbot/acme.sh snippets; /settings keeps the enable
  switch next to the base URL it depends on and cross-links to it. New
  `certificates.source` column (migration 0009, `ui`/`api`/`acme`, existing
  rows backfilled to `ui`) threaded through every issuance path and shown as
  a badge in the inventory. New audit actions `acme_certificate_issued`,
  `acme_certificate_revoked`, `acme_eab_key_created` and
  `acme_eab_key_revoked`. The certbot client drives the full flow — account,
  order, http-01, finalize, chain download — and the same flow again with
  EAB required, in the interop tests.
- Spec 0013 (mcp): a Model Context Protocol server (`fastmcp`, new runtime
  dependency) so an assistant can operate the CA directly. Six tools
  (`cabin.mcp.server`): `get_ca_info`, `list_certificates`,
  `get_certificate`, `issue_certificate`, `sign_csr` and
  `revoke_certificate` — a second consumer of the same domain services, with
  the response shapes factored out of `/api/v1` into the new
  `cabin.api.views` so both front doors describe a certificate identically,
  and the REST request models reused for parameter validation so the limits
  (days 1..3650, ≤100 SANs, CN ≤64) come from one definition and failures
  come back as sentences rather than tracebacks. Authentication is the
  spec-0008 API token (`Authorization: Bearer`, no cookies, no CSRF): a
  missing or dead token is the transport's 401, and a viewer token is
  refused the three mutating tools with a message naming the role it would
  need. Only `issue_certificate` ever returns a private key — the one it
  just generated — which the new `CertificatePem` model makes a property of
  the type rather than of the code. Off by default behind the new
  `mcp_enabled` setting, which needs a base URL for the same reason ACME
  does; while it is off, `/mcp` and everything under it answer 404 before
  authentication runs. The endpoint is attached as a route at exactly `/mcp`
  (stateless streamable-HTTP) so the URL an operator pastes into their
  client is the one that answers, rather than a 307 to `/mcp/`
  (python-sdk#1367). MCP-driven changes are recorded with
  `actor_kind="token"`, the token's label and the detail `{"via": "mcp"}`,
  and carry the new `mcp` value in `certificates.source`. An exception
  cabin did not anticipate is masked rather than relayed
  (`mask_error_details`), so a database error cannot carry SQL, its bound
  parameters or a filesystem path to the caller — everything cabin does
  mean the caller to read is raised as an explicit tool error. The
  endpoint accepts every HTTP method so that the gate, not the router
  above it, answers for the ones it does not implement (a 405 with an
  `Allow` header would admit the path exists while MCP is off), and every
  response it sends carries `Cache-Control: no-store`. /settings gains
  the switch, the endpoint URL and a ready-to-paste `claude mcp add` line.
