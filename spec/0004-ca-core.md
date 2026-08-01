# Spec 0004 — CA Core

## Context

The heart of cabin: creating or importing the CA hierarchy. After this spec,
cabin holds a signing CA (intermediate) whose sealed private key lives in the
DB, plus the root certificate for chain building. Issuance itself is spec 0005.

## User Stories

- As the operator, on a fresh instance I create a root + intermediate in a
  guided wizard (sensible defaults, one form).
- As an operator with an existing CA (e.g. exported from step-ca or XCA), I
  import my signing CA (cert + key, optionally passphrase-protected) and the
  parent/root certificate.
- As any user, I see the CA hierarchy, validity, and fingerprints, and can
  download the root/chain PEM (that's public material).

## Functional Requirements

- FR-1: Module `cabin.ca` (package allowed) with pure functions on top of
  pyca/cryptography — no FastAPI imports:
  - `generate_key(key_type)` for `ecdsa-p256` (default), `ecdsa-p384`,
    `rsa-4096`, `ed25519`.
  - `create_root(subject_cn, key_type, years=20)`: self-signed; extensions
    BasicConstraints(ca=True, path_length=1) critical, KeyUsage(key_cert_sign,
    crl_sign) critical, SubjectKeyIdentifier; NotBefore backdated 5 min.
  - `create_intermediate(root_cert, root_key, subject_cn, key_type, years=10)`:
    BasicConstraints(ca=True, path_length=0) critical, KeyUsage(key_cert_sign,
    crl_sign) critical, SKI + AuthorityKeyIdentifier(from root SKI).
  - `load_import(cert_pem, key_pem, key_passphrase, chain_pem)`: parses and
    validates an imported signing CA.
- FR-2: Import validation fails with `CAImportError` naming the reason when:
  cert/key don't match; cert has no BasicConstraints CA=true; KeyUsage lacks
  keyCertSign; cert is expired/not yet valid; key PEM can't be decrypted with
  the given passphrase; chain_pem (if given) doesn't verify the cert's
  signature (single-level parent check is enough for v1).
- FR-3: Migration 0003 adds table `ca_certificates` (id, kind CHECK
  root/intermediate, cert_pem NOT NULL, key_sealed NULLABLE — root key may be
  discarded/absent for imports, created_at). At most ONE active hierarchy:
  creating/importing when one exists → 409-style error (no rotation in v1).
  Private keys are sealed with `app.state.secrets` before insert (never
  plaintext in the DB).
- FR-4: `cabin.ca.service` (or equivalent): `get_ca(db)` returns the active
  hierarchy (or None), `create_hierarchy(db, secrets, ...)`,
  `import_hierarchy(db, secrets, ...)`, `signing_credentials(db, secrets)` →
  (intermediate cert, unsealed private key) for later specs; root key is
  unsealed ONLY inside create_hierarchy to sign the intermediate, then sealed
  and stored (kept for future CRL-of-intermediates/rotation, not used
  elsewhere).
- FR-5: UI at `/ca`: without CA → wizard page with two forms (create | import);
  with CA → info page: subject, issuer, serial, validity window, SHA-256
  fingerprint per cert, key type, and download links `GET /ca/root.pem` and
  `GET /ca/chain.pem` (root+intermediate). Downloads and info need login
  (viewer ok); create/import POSTs need role admin or superadmin + CSRF.
  Dashboard shows "CA: not set up" hint linking to /ca when absent.
- FR-6: The wizard defaults: root CN "<name> Root CA", intermediate CN
  "<name> Intermediate CA" derived from one "CA name" input; key type
  ecdsa-p256; validity 20y/10y (form fields, server-validated 1..50y).

## Acceptance Criteria

- AC-1: Wizard create → two rows in ca_certificates; parsed root has
  BasicConstraints ca=true pathlen=1 + KeyUsage certSign+crlSign (both
  critical) + SKI; intermediate has pathlen=0, AKI == root SKI, and its
  signature verifies against the root public key.
- AC-2: key_sealed values are NOT valid PEM (i.e. actually sealed) and can be
  unsealed back to a working private key via signing_credentials.
- AC-3: Import with matching cert+key (incl. encrypted PKCS#8 + passphrase)
  and chain succeeds; the five FR-2 failure cases each raise CAImportError
  with distinct messages (test each).
- AC-4: Second create/import attempt → error page/409, DB unchanged.
- AC-5: /ca info shows CN + fingerprints; /ca/root.pem and /ca/chain.pem
  return `application/x-pem-file` with 1 resp. 2 certificates; viewer can
  GET everything under /ca but POSTs are 403.
- AC-6: ed25519 hierarchy creates and verifies too (guard against
  sign-algorithm assumptions baked into helpers).

## Test list

test_create_root_extensions, test_create_intermediate_chain_verifies,
test_generate_key_types, test_keys_sealed_in_db,
test_signing_credentials_roundtrip, test_import_success_with_encrypted_key,
test_import_rejects_mismatched_key, test_import_rejects_non_ca_cert,
test_import_rejects_missing_keycertsign, test_import_rejects_expired,
test_import_rejects_bad_chain, test_second_hierarchy_rejected,
test_ca_wizard_ui_flow, test_ca_downloads_pem, test_viewer_readonly_on_ca,
test_ed25519_hierarchy

## Out of Scope

Leaf issuance (0005), CRL/CDP (0007), rotation/renewal of CA certs, multiple
parallel hierarchies, offline-root workflows beyond import, HSM/KMS.
