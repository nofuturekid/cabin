# Spec 0011 — ACME Challenges

## Context

Spec 0010 creates orders, authorizations and challenge objects but never
validates anything. This spec implements the three validation methods —
http-01, dns-01 and tls-alpn-01 — plus the challenge trigger, the async
validation flow and the authorization/order status transitions that follow.

**License guardrail:** RFC 8555 §8, RFC 8737 (tls-alpn-01) and RFC 8738 (IP
identifiers) are the sources. No GPL code.

## User Stories

- As an ACME client, I POST `{}` to a challenge, cabin fetches my token from
  the well-known URL / DNS TXT record / TLS-ALPN handshake, and the
  authorization turns valid.
- As an operator, a failed validation tells me exactly why (wrong content,
  connection refused, NXDOMAIN, wrong certificate) in the challenge's error
  field and in the audit log.

## Functional Requirements

- FR-1: Key authorization: `token + "." + base64url(SHA256(account JWK
thumbprint))` per RFC 8555 §8.1 — one helper, used by all three methods.
- FR-2: `POST /acme/chal/{id}` with an empty JSON object `{}` (as opposed to
  POST-as-GET) moves the challenge `pending → processing`, schedules
  validation, and returns 200 with the challenge object plus
  `Link: <authz>;rel="up"`. Re-triggering a `processing` or `valid` challenge
  is a no-op returning the current object (never an error). Triggering an
  `invalid` challenge, or one whose authorization is not `pending`, →
  `malformed`.
- FR-3: Validation runs in the background (FastAPI `BackgroundTasks` or an
  asyncio task started from the route — pick one and document it) with a fresh
  DB session; the HTTP response never waits for it. Every validator has a hard
  timeout (`VALIDATION_TIMEOUT = 10s` total per attempt) and no retries in v1
  (the client re-triggers; RFC allows this).
- FR-4: http-01 (RFC 8555 §8.3): GET `http://<identifier>/.well-known/acme-challenge/<token>`
  over **HTTP on port 80 only**, following up to 5 redirects (http and https
  both allowed as redirect targets, per RFC), max 64 KiB response, no
  authentication, `Host` = identifier. Compare the trimmed body to the key
  authorization with `hmac.compare_digest`. IP identifiers use the IP
  literal as host.
- FR-5: dns-01 (RFC 8555 §8.4): resolve TXT for `_acme-challenge.<identifier>`
  (for wildcard authorizations: the base domain), accept if ANY record equals
  `base64url(SHA256(key_authorization))`. Uses dnspython with the system
  resolver by default; a `dns_resolvers` setting (comma-separated IPs) can
  override. Not applicable to IP identifiers → the challenge type must not be
  offered for them (already true in 0010).
- FR-6: tls-alpn-01 (RFC 8737): open a TLS connection to the identifier on
  port 443 with ALPN `acme-tls/1` and SNI = identifier, requiring the server
  to negotiate that protocol; the presented certificate must carry a
  SubjectAlternativeName matching the identifier and a CRITICAL
  `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) whose payload is
  the DER OCTET STRING of SHA256(key authorization). Self-signed is expected —
  do NOT verify the chain, but DO compare the extension in constant time.
- FR-7: Status transitions: challenge valid → its authorization becomes
  `valid` (validated_at set); challenge invalid → challenge `invalid` with an
  ACME problem in `error_json`, authorization stays `pending` so the client
  can try another challenge type; when ALL authorizations of an order are
  valid the order becomes `ready`; if an authorization expires or definitively
  fails, the order becomes `invalid`. Status is computed on read where the
  0010 helpers already do that.
- FR-8: Audit: one `acme_challenge_validated` / `acme_challenge_failed` event
  per attempt with the identifier, challenge type and (on failure) the error
  detail. Add both to `AuditAction`.
- FR-9: Safety: validation targets are attacker-influenced (SSRF surface).
  Refuse to connect to identifiers that resolve to loopback, link-local or
  multicast addresses UNLESS the setting `allow_private_validation_targets`
  is on (default ON for this product, since an internal CA validates RFC1918
  hosts by definition — but loopback/link-local/multicast stay blocked
  regardless). Document the reasoning in the spec and code.

## Acceptance Criteria

- AC-1: key authorization matches the RFC example format and is identical
  across the three validators (one helper, asserted).
- AC-2: http-01 succeeds against a local test HTTP server serving the right
  content; fails with a distinct error for: wrong content, 404, connection
  refused, body > 64 KiB, more than 5 redirects.
- AC-3: dns-01 succeeds with a stub resolver returning the right TXT; fails
  distinctly for: no record, wrong digest, NXDOMAIN, resolver timeout.
- AC-4: tls-alpn-01 succeeds against a local TLS server presenting a correct
  acmeIdentifier certificate; fails distinctly for: no ALPN negotiation, wrong
  digest, missing extension, extension not critical, SAN mismatch.
- AC-5: Triggering moves pending → processing and the response is immediate
  (the test asserts the challenge object, then waits for the background task
  and re-reads to see `valid`).
- AC-6: A valid challenge makes its authorization valid and, when it is the
  only one, the order `ready`; a failed challenge leaves the authorization
  `pending` with the challenge `invalid` carrying a problem document.
- AC-7: Blocked targets (127.0.0.1, ::1, 169.254.x, 224.x) fail validation
  with a clear error even when the identifier resolves there.
- AC-8: An end-to-end test drives the certbot `acme` client through
  trigger → poll → authorization valid for http-01 against a local server.

## Test list

test_key_authorization_format, test_http01_success,
test_http01_wrong_content, test_http01_404, test_http01_connection_refused,
test_http01_body_too_large, test_http01_redirect_limit, test_dns01_success,
test_dns01_missing_record, test_dns01_wrong_digest, test_dns01_nxdomain,
test_tlsalpn01_success, test_tlsalpn01_no_alpn,
test_tlsalpn01_wrong_digest, test_tlsalpn01_missing_extension,
test_trigger_sets_processing_and_is_idempotent,
test_authorization_and_order_transitions, test_failed_challenge_keeps_authz_pending,
test_blocked_targets_rejected, test_audit_challenge_events,
test_client_completes_http01

## Out of Scope

Finalize/certificate/revokeCert/EAB (0012), retries and backoff, CAA checking,
IPv6-only validation nuances beyond what the stdlib gives, multi-perspective
validation, ARI.
