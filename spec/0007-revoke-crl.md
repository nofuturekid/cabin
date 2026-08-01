# Spec 0007 — Revocation & CRL

## Context

An internal CA must be able to withdraw trust. cabin's v1 revocation story is
CRL-based (no OCSP — see ADR-0001 / plan): revoking marks the certificate in
the DB, regenerates the CRL, and serves it at a stable URL that newly issued
certificates point to via a CRL Distribution Point extension.

## User Stories

- As an admin, I revoke a certificate with a reason and see it marked revoked
  in the inventory immediately.
- As a relying party, I fetch `/crl` (DER) or `/crl.pem` and see the revoked
  serial with its reason and revocation date.
- As an operator, certificates cabin issues carry a CDP pointing at my
  instance, so clients can find the CRL without extra configuration.

## Functional Requirements

- FR-1: Migration 0005: `certificates` gains `revoked_at` (nullable, ISO UTC)
  and `revocation_reason` (nullable text); new table `crl_state`
  (id PK CHECK id=1, crl_number INTEGER NOT NULL, generated_at NOT NULL,
  crl_der BLOB NOT NULL) holding exactly one row — the current CRL.
- FR-2: Reasons: `unspecified`, `key_compromise`, `affiliation_changed`,
  `superseded`, `cessation_of_operation` (map to
  `x509.ReasonFlags`). Default `unspecified`.
- FR-3: `cabin.ca.revocation` (pure): `build_crl(issuer_cert, issuer_key,
revoked_entries, crl_number, this_update, next_update)` →
  `x509.CertificateRevocationList` with CRLNumber and AuthorityKeyIdentifier
  extensions; each entry carries serial, revocation date and (unless
  `unspecified`) a CRLReason extension. Signature hash per issuer key type
  (reuse `signing_algorithm`).
- FR-4: `cabin.ca.certs`: `revoke_certificate(db, secrets, cert_id, reason,
now)` sets revoked_at/reason (idempotent: revoking twice is a no-op returning
  the existing state, NOT an error), then regenerates and stores the CRL in
  one transaction. `RevocationError` when the certificate does not exist.
  `regenerate_crl(db, secrets, now)` increments `crl_number` monotonically;
  `next_update = now + CRL_VALIDITY` (7 days, module constant); an empty
  revocation list still produces a valid (empty) CRL.
- FR-5: Serving: `GET /crl` → `application/pkix-crl` (DER),
  `GET /crl.pem` → `application/x-pem-file`; both PUBLIC (no auth — a CRL is
  public by design), `Cache-Control: public, max-age=3600`. When no CA exists
  → 404. When the stored CRL is older than `next_update`, regenerate lazily on
  request (self-healing without a scheduler).
- FR-6: New certificates get a CDP extension pointing at `<base_url>/crl`,
  where `base_url` comes from the `settings` table (key `base_url`), settable
  in the UI at `/settings` (admin only; validated as an absolute http(s) URL
  without trailing slash). When `base_url` is unset, certificates are issued
  WITHOUT a CDP (no broken URLs) and the CA page shows a hint. Existing
  certificates are unaffected.
- FR-7: UI: inventory rows show a "revoked" badge and status filter gains
  `revoked`; the detail page gets a revoke form (admin, CSRF, reason select,
  confirm checkbox) and shows revocation date/reason when revoked. Revoked
  certificates cannot be revoked again through the UI (form hidden).

## Acceptance Criteria

- AC-1: Revoking sets revoked_at+reason; the stored CRL contains that serial
  with the right reason code; revoking again changes nothing (same revoked_at,
  crl_number incremented at most once more) and returns success.
- AC-2: CRL parses via `x509.load_der_x509_crl`, `issuer == intermediate
subject`, signature verifies against the intermediate public key, carries
  CRLNumber + AKI, `next_update == this_update + 7d`.
- AC-3: crl_number strictly increases across regenerations.
- AC-4: `/crl` and `/crl.pem` are reachable WITHOUT login, right content types,
  cache header present; 404 without a CA; a stale stored CRL is regenerated on
  access (crl_number increases, next_update in the future).
- AC-5: With `base_url` set, a newly issued certificate has a CDP with exactly
  `<base_url>/crl`; without it, no CDP extension. Invalid base_url input
  (relative, ftp://, trailing slash) → 400 with the form re-rendered.
- AC-6: UI: admin revokes via the form (CSRF enforced, viewer 403), row shows
  the revoked badge, `status=revoked` filters to it, and the revoke form is
  gone afterwards.

## Test list

test_build_crl_extensions_and_signature, test_build_crl_reason_codes,
test_build_crl_empty_list, test_revoke_sets_fields_and_updates_crl,
test_revoke_is_idempotent, test_revoke_unknown_certificate_errors,
test_crl_number_monotonic, test_crl_next_update_window,
test_crl_endpoint_der_public, test_crl_endpoint_pem_public,
test_crl_endpoint_404_without_ca, test_crl_lazy_regeneration_when_stale,
test_cdp_present_with_base_url, test_cdp_absent_without_base_url,
test_base_url_validation, test_ui_revoke_flow, test_ui_revoke_requires_admin,
test_inventory_revoked_badge_and_filter

## Out of Scope

OCSP (explicitly deferred), delta CRLs, IDP extension, CRL signing with a
dedicated CRL signer certificate, revocation of the CA itself, scheduled
background regeneration (lazy-on-access is enough for v1), ACME revokeCert
(spec 0012 wires it to `revoke_certificate`).
