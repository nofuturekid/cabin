# Spec 0006 — Inventory & Download

## Context

Spec 0005 issues certificates but only shows them once, on the result page.
This spec adds the inventory: a searchable list of everything cabin has
issued, with per-certificate downloads (PEM, full chain, private key, PKCS#12
bundle) and expiry visibility.

## User Stories

- As an operator, I see all issued certificates with CN, SANs, profile,
  expiry, and a clear "expires soon"/"expired" marker.
- As an operator with many certificates, I filter by text (CN/SAN/serial) and
  by status (valid / expiring / expired).
- As an admin, I download a certificate as PEM, as a full chain, as the key,
  or as a password-protected PKCS#12 for import into Windows/macOS.

## Functional Requirements

- FR-1: `GET /certs` (any authenticated user) lists certificates newest first,
  paginated (50/page, `?page=`), showing: CN, profile, key present (yes/no),
  not_after with status badge, first 3 SANs (+N more), short serial. Empty
  state links to /certs/new for admins.
- FR-2: Filters via query params: `q` (case-insensitive substring over
  subject_cn, sans_json, serial_hex — trim and cap at 200 chars) and `status`
  in (all | valid | expiring | expired). "expiring" = not_after within the
  next 30 days and not yet expired. Filters combine; they are reflected in the
  form and preserved in pagination links.
- FR-3: `cabin.ca.certs` gains `list_certificates(db, q, status, page,
  per_page, now) -> (rows, total)` and `certificate_status(not_after, now)`;
  status logic is pure and unit-tested (boundaries: exactly now, exactly
  +30d). `certificate_status` takes the expiry instant rather than a row so
  it stays testable without a database (rows expose `not_after_dt`);
  `list_certificates` takes the clock the caller renders badges with, so a
  page's filter and its badges cannot straddle a tick, and it clamps `page`
  itself so no caller can turn a hand-edited page number into an unbindable
  OFFSET.
- FR-4: Downloads (all under `/certs/{id}/download/...`, filename from CN
  slug + short serial):
  - `cert.pem` — leaf only, `application/x-pem-file` (any authenticated user)
  - `chain.pem` — leaf + intermediate + root (any authenticated user)
  - `key.pem` — sealed key unsealed, `application/x-pem-file`, admin only,
    404 when key_sealed is NULL
  - `bundle.p12` — PKCS#12 with leaf + key + chain, `application/x-pkcs12`,
    admin only, POST with CSRF and a required `password` form field
    (min 8 chars); 404 when key_sealed is NULL
    All download responses carry `Content-Disposition: attachment; filename=…`
    and `Cache-Control: no-store`.
- FR-5: PKCS#12 built with `cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`
  using a modern encryption profile; friendly name = CN. pyca/cryptography
  50 does serialize Ed25519 into PKCS#12, so no key type cabin issues is
  rejected today; the requirement is therefore that a refusal by the
  serializer — for whatever key, on whatever version — yields a clean 400,
  never a traceback.
- FR-6: The cert detail page (0005) gets the download links/form; nav gets
  "Certificates" → /certs. A `SecretsError` on any key-bearing path renders/
  returns a clean error, never a 500.

## Acceptance Criteria

- AC-1: With 3 certs, `/certs` lists all 3 newest-first; `q` matching one CN
  returns only it; `q` matching a SAN substring works; `status=expired`
  returns only expired ones; combined `q`+`status` intersect.
- AC-2: Pagination: 60 certs → page 1 has 50, page 2 has 10, links keep
  filters; out-of-range page → empty list, no error.
- AC-3: Status boundaries: not_after = now+31d → valid; now+30d → expiring;
  now-1s → expired.
- AC-4: `cert.pem` returns exactly 1 PEM cert; `chain.pem` returns 3 (leaf,
  intermediate, root) in that order; both `attachment` + `no-store`.
- AC-5: `key.pem` 200 for admin, 403 for viewer, 404 for a CSR-signed cert;
  `bundle.p12` requires CSRF + password ≥8 (400 otherwise) and the produced
  bytes load back via `pkcs12.load_key_and_certificates` with that password,
  yielding the same leaf + a non-empty chain.
- AC-6: Viewer sees the list and cert/chain downloads but no key/p12 controls
  in the HTML and 403 on those routes; unauthenticated → 303.

## Test list

test_list_orders_newest_first, test_filter_q_matches_cn,
test_filter_q_matches_san, test_filter_q_matches_serial,
test_filter_status_expired, test_filter_combined, test_pagination_pages,
test_pagination_out_of_range, test_status_boundaries,
test_download_cert_pem, test_download_chain_pem_order,
test_download_key_pem_admin_only, test_download_key_404_for_csr_signed,
test_p12_requires_password_and_csrf, test_p12_roundtrip_loads,
test_p12_ed25519_clean_error, test_downloads_have_attachment_and_no_store,
test_viewer_sees_no_key_controls

## Out of Scope

Revocation/CRL (0007), REST API (0008), audit (0009), bulk export, renewal,
sorting by arbitrary columns, per-user visibility scoping.
