# Spec 0005 — Issue & Sign

## Context

With the CA hierarchy in place (spec 0004), cabin can now issue leaf
certificates: either fully server-side (cabin generates the key) or by signing
a pasted CSR. This spec covers the domain logic, persistence, and the UI flow.
REST endpoints follow in spec 0008 (api-tokens) where Bearer auth exists —
cookie-authenticated JSON endpoints would just re-open the CSRF question.

## User Stories

- As an admin, I issue a server certificate for `nas.lan` with SANs in one
  form; cabin generates the key and shows me cert + key PEM.
- As an admin, I paste a CSR from another system, pick a profile, and get the
  signed certificate — cabin never sees that private key.
- As an operator, every issued certificate is recorded (inventory UI in 0006).

## Functional Requirements

- FR-1: `cabin.ca.issue` (pure, no FastAPI/DB): profiles `server` (EKU
  serverAuth; KU digitalSignature, + keyEncipherment for RSA keys) and
  `client` (EKU clientAuth; KU digitalSignature). Every leaf gets:
  BasicConstraints(ca=False) critical, KU critical, EKU non-critical, SKI,
  AKI(from issuer), SAN (see FR-3), serial `x509.random_serial_number()`,
  NotBefore backdated 5 min, signature hash per issuer key type (reuse the
  0004 helper).
- FR-2: `issue_certificate(issuer_cert, issuer_key, profile, subject_cn, sans,
days, key_type)` generates the key server-side (key types as in 0004) and
  returns (cert, key). `sign_csr(issuer_cert, issuer_key, csr_pem, profile,
days, sans_override=None)` parses + verifies the CSR signature
  (`csr.is_signature_valid`), takes subject CN from the CSR, and NEVER copies
  CSR extensions except SAN. Invalid PEM / invalid signature →
  `IssueError` with distinct messages.
- FR-3: SAN policy: explicit SANs (form/override) win; else CSR SANs (DNS, IP,
  email allowed); else fall back to the CN as DNS-SAN when it is a valid
  hostname, or as IP-SAN when it parses as an IP; otherwise `IssueError("no
usable SAN")`. CN length/charset validated (<=64, no control chars).
- FR-4: Validity: `days` bounded 1..3650, default 365; `not_valid_after` is
  clamped to the intermediate's `not_valid_after_utc` (reuse the clamp idea
  from 0004). Uses `signing_credentials` from spec 0004.
- FR-5: Migration 0004 adds `certificates`: id PK, serial_hex UNIQUE NOT NULL,
  subject_cn NOT NULL, sans_json NOT NULL (JSON array of strings like
  "DNS:nas.lan", "IP:10.0.0.5"), profile NOT NULL, not_before/not_after
  (tz-aware ISO), cert_pem NOT NULL, key_sealed NULLABLE (sealed PKCS#8 PEM
  for server-generated keys; NULL for CSR-signed), created_at. Service
  functions in `cabin.ca.service` (or a new `cabin.certs` service module —
  implementer's call): `issue_and_store(...)`, `sign_csr_and_store(...)`,
  `get_certificate(db, id)`.
- FR-6: UI `/certs/new` (admin+superadmin, CSRF): two forms (Issue | Sign
  CSR). Issue form: CN, SANs (one per line, `dns:`/`ip:` prefix optional —
  bare entries auto-detected), profile, key type, days. Sign form: CSR
  textarea, profile, days, optional SAN override lines. Success → `/certs/{id}`
  result page: metadata + cert PEM in a copyable block; for server-generated
  keys ALSO the key PEM with a clear "shown here; also stored encrypted"
  note. Errors re-render the form with a banner (400). Viewer: GET /certs/new
  → 403 (it is a mutation-only page); `/certs/{id}` viewable by all
  authenticated users but the key PEM block is rendered ONLY for
  admin+superadmin.
- FR-7: Nav gets "Issue" linking to /certs/new (inventory link lands in 0006).
  Dashboard: no changes.

## Acceptance Criteria

- AC-1: Issued server cert: BasicConstraints ca=False critical, KU critical
  with digitalSignature (RSA: + keyEncipherment; ECDSA/Ed25519: not), EKU
  serverAuth, SAN matches input, AKI == intermediate SKI, chain verifies
  against intermediate; client profile → EKU clientAuth.
- AC-2: sign_csr: CSR SANs preserved (DNS+IP mix), CSR extension smuggling
  blocked (a CSR carrying BasicConstraints CA=true or KU certSign yields a
  leaf WITHOUT those — test explicitly), tampered CSR signature → IssueError.
- AC-3: SAN fallback ladder per FR-3 incl. IP CN; "no usable SAN" error case.
- AC-4: days=5000 request → cert not_after == min(now+5000d, intermediate
  not_after); days=0 / 4000 → validation error 1..3650.
- AC-5: DB row: serial_hex matches cert serial, sans_json round-trips, sealed
  key unseals to the generated key (server flow), key_sealed NULL (CSR flow).
- AC-6: UI: both happy paths end on /certs/{id} with correct PEM blocks; key
  PEM visible for admin, absent for viewer; bad CSR → 400 banner; viewer GET
  /certs/new → 403; unauthenticated → 303 login.

## Test list

test_issue_server_profile_extensions, test_issue_client_profile_extensions,
test_issue_rsa_keyusage_includes_keyencipherment, test_issue_chain_verifies,
test_sign_csr_preserves_sans, test_sign_csr_blocks_extension_smuggling,
test_sign_csr_rejects_bad_signature, test_san_fallback_cn_dns,
test_san_fallback_cn_ip, test_san_missing_errors, test_days_clamped_to_ca,
test_days_range_validated, test_store_seals_key_server_flow,
test_store_no_key_csr_flow, test_ui_issue_flow, test_ui_sign_csr_flow,
test_ui_key_visibility_by_role, test_ui_viewer_403_on_new

## Out of Scope

Inventory list/search/downloads incl. PKCS#12 (0006), revocation/CRL (0007),
REST API (0008), audit (0009), ACME (0010+), renewal.
