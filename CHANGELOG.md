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
