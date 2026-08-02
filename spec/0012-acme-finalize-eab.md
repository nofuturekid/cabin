# Spec 0012 — ACME Finalize, Certificate, Revocation & EAB

## Context

Specs 0010/0011 get an order to `ready`. This spec closes the loop: finalize
with a CSR, issue and serve the certificate, support `revokeCert`, and add
External Account Binding so the CA can require operator-issued credentials
before a client may register. After this spec cabin is a complete ACME CA.

**License guardrail:** RFC 8555 §7.4/§7.4.2/§7.6, §7.3.4 (EAB), RFC 8738.
No GPL code.

## User Stories

- As an ACME client, once my authorizations are valid I POST my CSR to the
  finalize URL and download the issued certificate chain.
- As an operator who does not want every host on the network to be able to get
  certificates, I turn on EAB, hand out key IDs and HMAC keys from the UI, and
  clients must present them at registration.
- As an ACME client, I revoke a certificate I hold, either with my account key
  or with the certificate's own key.

## Functional Requirements

- FR-1: `POST /acme/order/{id}/finalize` (replaces the 0010 stub, with full
  JWS verification):
  - order must belong to the account and be `ready` → else `orderNotReady`
    (add the error type) or `unauthorized`
  - payload `{"csr": "<base64url DER>"}`; parse with
    `x509.load_der_x509_csr`; verify `csr.is_signature_valid`
  - the CSR's SAN set must equal the order's identifier set (case-insensitive
    for DNS, IP-aware); a CN, if present, must also be in that set; anything
    else → `badCSR` with a specific detail. Wildcard identifiers match the
    wildcard SAN.
  - issue via the spec-0005 path (`sign_csr_and_store`) with the `server`
    profile and the configured CRL URL; store `certificate_id` on the order;
    order → `valid`
  - respond 200 with the order object including `certificate` URL
  - the whole issuance is idempotent per order: finalizing an already-`valid`
    order returns the same order/certificate, never a second certificate
- FR-2: `POST /acme/cert/{id}` (POST-as-GET, JWS-authenticated, ownership
  checked) → `application/pem-certificate-chain`: leaf + intermediate + root,
  with `Link: <alternate chain?>` omitted (single chain only in v1).
- FR-3: `POST /acme/revoke-cert` (replaces the 0010 stub):
  - payload `{"certificate": "<base64url DER>", "reason": <int?>}`
  - authorized either by the account that owns the certificate's order, or by
    a JWS signed with the certificate's own key pair (jwk mode) — implement
    BOTH per RFC 8555 §7.6
  - reason codes limited to the spec-0007 set; `removeFromCRL` (8) and
    unsupported codes → `badRevocationReason`
  - already-revoked → `alreadyRevoked`
  - delegates to `cabin.ca.crl.revoke_certificate`, so the CRL updates
  - certificates cabin did not issue → `unauthorized`
- FR-4: EAB (RFC 8555 §7.3.4):
  - migration 0009: `acme_eab_keys` (id PK = the key identifier, hmac_sealed
    NOT NULL (sealed via SecretStore), label, created_at, bound_account_id
    NULL, bound_at NULL, revoked_at NULL)
  - setting `acme_require_eab` (default false); when true, `new-account`
    without `externalAccountBinding` → `externalAccountRequired`
  - the EAB JWS: outer payload carries `externalAccountBinding`, an inner
    flattened JWS whose protected header has `alg: HS256`, `kid` = key
    identifier, `url` = the new-account URL, and whose payload is the
    account's JWK; verify with the unsealed HMAC key in constant time;
    mismatch → `unauthorized`/`malformed` per RFC
  - one-time binding: a key already bound to an account cannot bind another
    (`unauthorized`); revoked keys rejected
  - directory `meta.externalAccountRequired` reflects the setting
- FR-5: UI `/acme` (admin): enable/disable ACME, require-EAB toggle, the
  directory URL with a copy hint, an EAB key table (label, key id, bound
  account, created) with "New key" (shows the HMAC secret ONCE, base64url) and
  "Revoke". Client onboarding snippets for certbot and acme.sh including the
  EAB flags. Nav entry "ACME" (admin only). The settings that live on
  /settings today (acme_enabled) move here or are cross-linked — state which.
- FR-6: Audit: `acme_certificate_issued`, `acme_certificate_revoked`,
  `acme_eab_key_created`, `acme_eab_key_revoked`, plus the existing account/
  order actions.
- FR-7: The issued certificate appears in the normal inventory (spec 0006)
  with its ACME origin visible — add a `source` column to `certificates`
  (migration 0009, values `ui`/`api`/`acme`, default `ui`) and show it as a
  badge; the inventory filter gains it as a status-independent facet only if
  cheap — otherwise just display it.

## Acceptance Criteria

- AC-1: Full happy path with the certbot `acme` library: account → order →
  http-01 → finalize → download chain; the chain verifies to the root and the
  leaf's SANs equal the ordered identifiers.
- AC-2: CSR mismatch cases (extra SAN, missing SAN, CN not in identifiers,
  bad signature, not-DER) each → `badCSR` with distinct details, order stays
  `ready`.
- AC-3: Finalizing twice returns the same certificate URL and creates exactly
  one certificate row.
- AC-4: `POST /acme/cert/{id}` returns a PEM chain of 3 certificates with the
  right content type; another account's certificate → 403/`unauthorized`.
- AC-5: revokeCert works both account-authorized and certificate-key-authorized;
  the serial appears in `/crl`; double revoke → `alreadyRevoked`; reason 8 →
  `badRevocationReason`; a foreign certificate → `unauthorized`.
- AC-6: With `acme_require_eab` on: registration without EAB →
  `externalAccountRequired`; with a valid EAB → 201 and the key is marked
  bound; reusing that key for a second account → `unauthorized`; a revoked key
  → `unauthorized`; a tampered inner signature → `unauthorized`.
- AC-7: The certificate shows up in `/certs` with source `acme` and is
  revocable from the UI (which also updates the CRL).
- AC-8: With EAB required, the certbot client completes registration when
  given the key id/HMAC (interop, not just unit tests).

## Test list

test_finalize_happy_path, test_finalize_requires_ready_order,
test_finalize_csr_must_match_identifiers, test_finalize_bad_csr_variants,
test_finalize_is_idempotent, test_certificate_download_chain,
test_certificate_ownership_enforced, test_revoke_by_account,
test_revoke_by_certificate_key, test_revoke_reason_validation,
test_revoke_already_revoked, test_revoke_foreign_certificate,
test_eab_required_rejects_plain_registration, test_eab_valid_binds_key,
test_eab_key_single_use, test_eab_revoked_key_rejected,
test_eab_tampered_signature_rejected, test_acme_ui_key_lifecycle,
test_inventory_shows_acme_source, test_audit_acme_issue_revoke,
test_client_full_flow_with_eab

## Out of Scope

Alternate chains, ARI (RFC 9773), STAR, pre-authorization, account key
rollover changes, rate limiting, CAA.
