# Spec 0002 — Crypto & Secrets

## Context

Everything sensitive cabin stores (CA private keys, EAB HMAC keys, later API
material) must be encrypted at rest. This spec delivers the secrets layer: a
master key in the data volume, optionally protected by a passphrase-derived
KEK, and a seal/unseal API used by all later specs.

## User Stories

- As the operator, I run cabin with zero config and secrets are encrypted with
  an auto-generated master key stored next to the DB.
- As a security-conscious operator, I set `CABIN_MASTER_PASSPHRASE` so the key
  file alone (e.g. in a stolen backup) is useless without the passphrase.
- As a developer, I call `seal`/`unseal` and never touch raw key material.

## Functional Requirements

- FR-1: Module `cabin.secrets` exposes `SecretStore` with
  `seal(plaintext: bytes) -> str` and `unseal(token: str) -> bytes`.
  AES-256-GCM; token format `base64url(nonce || ciphertext+tag)` with a fresh
  96-bit nonce per seal. Tampered or truncated tokens raise `SecretsError`.
- FR-2: `SecretStore.open(data_dir: Path, passphrase: str | None)` loads or
  creates `data_dir/secret.key` (JSON):
  - without passphrase: `{"v": 1, "kdf": "none", "key": "<b64 32B>"}`
  - with passphrase: `{"v": 1, "kdf": "scrypt", "salt": "<b64 16B>",
"n": 32768, "r": 8, "p": 1, "wrapped": "<b64 nonce||ct>"}` — the random
    32-byte master key wrapped (AES-256-GCM) with the scrypt-derived KEK
    (stdlib `hashlib.scrypt`).
- FR-3: Key file is created atomically (write temp file 0600 in the same dir,
  `os.link` to the final name, unlink temp; on `FileExistsError` re-read the
  existing file) so two concurrent first-starts cannot clobber each other.
  File mode 0600.
- FR-4: Mismatches fail loudly with `SecretsError` and a clear message:
  (a) file has `kdf: none` but a passphrase is set; (b) file has
  `kdf: scrypt` but no passphrase is set; (c) wrong passphrase (GCM tag
  failure on unwrap); (d) unknown version/kdf.
- FR-5: `Config` gains `master_passphrase: str | None`, read **only** from env
  `CABIN_MASTER_PASSPHRASE` (never a CLI flag — process lists leak). The app
  factory opens the `SecretStore` during lifespan startup and exposes it as
  `app.state.secrets`.
- FR-6: `cryptography` becomes a runtime dependency (pinned `>=50`).

## Data Model

No DB tables — the key file lives outside the DB on purpose (DB backups and
key material stay separable).

## Acceptance Criteria

- AC-1: Given an empty data dir and no passphrase, when the store opens, then
  `secret.key` exists with mode 0600, `kdf` is `none`, and a seal/unseal
  roundtrip returns the plaintext.
- AC-2: Given a store, when a token is tampered with (any byte flipped) or
  truncated, then `unseal` raises `SecretsError`.
- AC-3: Given `CABIN_MASTER_PASSPHRASE=x` on first start, then the key file
  has `kdf: scrypt`, and reopening with the same passphrase unseals data
  sealed before; reopening with passphrase `y` raises `SecretsError`.
- AC-4: Given a `kdf: none` key file and a set passphrase (or vice versa),
  when the store opens, then `SecretsError` with a message naming the fix.
- AC-5: Two seals of the same plaintext produce different tokens (fresh
  nonces).
- AC-6: App startup (TestClient lifespan) exposes a working
  `app.state.secrets`; existing spec-0001 behavior is unchanged.

## Test list

- test_open_creates_keyfile_mode_600_kdf_none (AC-1)
- test_seal_unseal_roundtrip (AC-1)
- test_unseal_rejects_tampered_and_truncated (AC-2)
- test_passphrase_wraps_key_scrypt (AC-3)
- test_wrong_passphrase_rejected (AC-3)
- test_kdf_mismatch_rejected_both_directions (AC-4)
- test_seal_uses_fresh_nonce (AC-5)
- test_app_state_has_secret_store (AC-6)

## Out of Scope

Key rotation / re-wrap tooling, KMS/TPM backends, encrypting the SQLite file
itself.
