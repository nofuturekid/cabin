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
