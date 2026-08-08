# Changelog

All notable changes to cabin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor = feature, patch = fix).

## [Unreleased]

## [0.2.0] - 2026-08-08

Six specifications, 0017–0022. cabin stops assuming there is one CA: it runs
several hierarchies side by side, rotates between them, restricts who may
issue from which and what each of them may sign, gives each its own ACME
directory, and can cross-sign a root so that devices trusting an old one keep
a path to certificates issued under a new one. It also terminates TLS itself,
so reaching it over HTTPS no longer requires a reverse proxy in front of it.

Three things to know before running it, because each of them costs something
to get wrong.

**A 0.1.x database cannot be brought forward, and the only path is an empty
data directory.** Migrations 0003, 0004, 0005, 0008 and 0009 were rewritten in
place rather than superseded. Alembic tracks the revision id and nothing about
the schema behind it, so against a 0.1.0 database it applies the one genuinely
new revision (0010), reports the database as current, and leaves five earlier
revisions describing tables that no longer look like that. Nothing fails at
startup — the first query fails instead, which is the worse of the two places
to find out. This is safe only because 0.1.0 was never deployed and there is
no instance to carry forward. That is the entire justification, and it is not
available again after this release.

If you did run 0.1.0, the procedure is: stop cabin, empty `DATA_DIR` —
`cabin.db` and `secret.key` both — and start again from the setup wizard.
There is no export, no partial carry-over and no repair. `secret.key` encrypts
every private key in the database, so discarding it discards the CA: the old
root has to come out of every trust store that holds it, the new one has to go
in, and every certificate 0.1.0 issued has to be issued again. Those old
certificates also become unrevocable in the same moment, because the CRL that
would carry them is signed by a key that no longer exists — they stay valid
until they expire. Keeping the database instead and pointing 0.2.0 at it is
the one option that is not available, however much it looks like it is.

**Cross-signing has to be planned a root generation ahead.** The cross path is
one certificate longer than any other path cabin builds, so the signing root
needs a `pathLenConstraint` of at least 2. cabin's default is 1, and renewal
carries BasicConstraints over unchanged — so a root created with the default
can never cross-sign anything, and no operation cabin has repairs it. The
attempt is refused with an error naming `path_length` and the value the root
actually carries, rather than producing a certificate no validator would build
a path through. A root that may ever have to cross-sign another has to be
created with at least 2, and the hint under the field now says so. An operator
who did not plan it has 0017's two hierarchies running in parallel, which is
the honest answer and for most transitions the better one anyway.

**Per-issuer permissions do not bind ACME unless external account binding is
required.** With `acme_require_eab` on, every link holds: only an identity
granted an issuer can mint an EAB key for it, only such a key registers an
account at that issuer's directory, that account is bound to that issuer for
life, and every certificate it obtains is signed by it — an administrator
holding no grant obtains no certificate over ACME. With it off, they still do.
Anyone who can reach the port registers at any issuer's directory and orders
from it; what remains is that an account is confined to one hierarchy, which
is worth having and is not access control. The `/acme` page carries the
warning next to the switch. "cabin has per-issuer permissions" is the sentence
someone will quote without this paragraph.

### Added

- Spec 0017 (multi-ca): a hierarchy stops being a singleton.
  `create_hierarchy` and `import_hierarchy` each add a further one and take a
  name; `create_intermediate_under` adds an intermediate to an existing root,
  which is what makes rotation ordinary operation rather than a mechanism of
  its own — new intermediate, old one retired, nothing already deployed
  invalidated. `retire` stands a row down, and for a root every descendant
  with it, but refuses the last active intermediate, because an instance that
  cannot issue anything has no way back; a retired issuer still serves its
  chain, still signs and publishes its CRL, and still has its certificates
  revoked. `renew_in_place` re-signs the same public key, the same subject and
  the same row with a later `not_after`, so the SubjectKeyIdentifier does not
  move and everything issued earlier keeps validating — that is the whole
  point of the operation. Which issuer signs is chosen per request and
  defaults to the only active one; with several active, omitting it is an
  error rather than a guess. A leaf now records its issuer
  (`certificates.issuer_id`, NOT NULL) and every chain is assembled from that
  row rather than from "the" hierarchy, and there is one CRL per issuer, keyed
  and numbered per issuer. A validity clamped to the issuer's remaining life
  is said out loud instead of applied silently — on the result page, as
  `validity_capped_from` in REST and MCP, and in the audit detail. Every leaf
  gains an AIA `caIssuers` pointing at `/ca/{issuer_id}.cer`, so a client
  handed only a leaf can repair the chain itself; that URL and the CRL
  distribution point are forced to `http://`, because validating a cabin
  certificate must not require fetching a CRL over TLS. A root's `path_length`
  is chosen at creation (1..4, default 1) — the one decision about a root that
  cannot be corrected afterwards. `/ca` becomes the list of hierarchies with
  create, import, add-intermediate, renew and retire on it; new audit actions
  `ca_renewed` and `ca_retired`. Migrations 0003, 0004 and 0005 rewritten in
  place.
- Spec 0018 (issuer-permissions): who may issue from which CA is now a grant,
  held by users and by API tokens in two join tables (migration 0010,
  appended). Tokens carry their own rather than inheriting a user's, because
  cabin deliberately gives them no owning user — and MCP authenticates with
  the same tokens, so it inherits token grants for free. Enforcement is a
  required keyword-only `principal` parameter on the domain functions, not a
  FastAPI dependency: the issuer to check arrives in the request body, when it
  is omitted it is derivable only from the database and the principal
  together, and MCP has no dependency layer at all. A ninth issuance path
  added later is therefore a type error rather than a silent bypass. Issuing
  intersects the grants with the active issuers; revoking is deliberately
  blind to status, so an operator who retires a compromised intermediate does
  not thereby lose the ability to revoke what it signed. One granted issuer is
  as unambiguous as one active issuer, so an admin granted one of three issues
  without naming it while a superadmin on the same instance has to choose.
  `superadmin` is implicit and needs no rows, and whoever creates a hierarchy
  is granted its intermediate in the same request — superadmin included, so a
  later demotion does not take away the CA they built. Grants are read fresh
  on every decision, with nothing cached on a session, a token or an MCP
  transport, so withdrawing one takes effect on the next request. Two
  exemptions, both named constants and neither of them an absent principal:
  ACME, which has no cabin identity behind it, and cabin issuing its own TLS
  certificate. Deleting a user clears their grants in the application rather
  than by cascade, so the cleanup is the application's job and stays
  observable. Visibility is unchanged and that is a decision: the inventory,
  the CA list, the dashboard and the audit log go on showing everything to
  everyone who can log in, because a filtered inventory is also a filtered
  expiry warning and a log that shows each reader only their own actions is
  not an audit log. New grant editors on `/users` and `/tokens` (superadmin +
  CSRF), granted issuers in the issue and sign selectors, new audit actions
  `user_issuers_changed` and `token_issuers_changed`, and 403 for an
  authorization failure against the 400 an unknown, retired or ambiguous
  issuer already returns. A self-issuance cabin cannot complete also stops
  being invisible: `TlsManager` records the last error, the dashboard banner
  gains a third state naming it, and `tls_certificate_failed` is audited on
  the transition into failure rather than once an hour forever.
- Spec 0019 (acme-per-issuer): an ACME account belongs to one issuer. The URL
  selects it and external account binding authorises it —
  `/acme/ca/{issuer_id}/directory` and `/acme/ca/{issuer_id}/new-account`
  replace the two shared paths, and every other ACME URL is unchanged because
  it already knows its issuer through the account. An account is bound at
  registration and for life; re-presenting its key at another issuer's
  directory is refused rather than silently rebound, which would let a bare
  account key move itself between hierarchies by visiting a URL. An EAB key
  names one CA row, and one presented at another issuer's directory is refused
  with the same wording every other binding failure uses — so a client learns
  nothing about which keys exist — and is not spent. The grant check moves to
  the one moment an operator actually decides something: minting an EAB key,
  which now takes a required `issuer_id` and resolves it through the grants,
  giving a chain from grant to key to account to certificate. Finalize passes
  the account's issuer explicitly instead of riding 0017's default rule, and
  new-order refuses when that account's issuer is retired, which is a
  different question from whether the instance has any active issuer at all. A
  retired issuer keeps serving its directory, because the accounts bound to it
  still poll and a 404 there would say cabin is gone rather than that the CA
  was stood down; what it refuses is new-account and new-order. The `index`
  link is emitted only on the two per-issuer paths, since there is no longer a
  single directory to name. Migrations 0008 and 0009 rewritten in place.
- Spec 0020 (name-constraints): an intermediate can be restricted to the names
  it is allowed to sign, with a critical `NameConstraints` extension carrying
  dNSName and iPAddress subtrees. The extension is the easy half. The half
  that matters is that cabin checks its own constraints before signing, beside
  the SAN validation, in a function that takes no new parameter and therefore
  cannot be forgotten by a caller — every issuance path runs through it,
  including ACME, where nobody is watching and a refusal surfaces as a renewal
  that quietly stopped. Writing the extension and trusting the client would
  mean cabin cheerfully issues certificates every validator then rejects.
  Constraints are set when an intermediate is created, on both creation paths
  so the first intermediate of a hierarchy can be restricted too; they live in
  the issuer's certificate rather than in a column, so the rule and the
  certificate cannot disagree, and a renewal carries them over byte for byte,
  because a routine renewal that silently widened what a CA may sign would go
  unnoticed for years. Roots take none. Operator input is parsed in one place:
  an address with host bits set is refused rather than widened (`10.1.2.3/8`
  is not `10.0.0.0/8`), a wildcard is refused because RFC 5280's subtree
  already means "and everything below it", an empty entry is refused because
  an empty dNSName constraint matches every name, a leading dot is accepted
  and stripped, and at most 50 entries per side. The matching rules follow the
  validators rather than being merely stricter: excluded beats permitted, an
  empty permitted set for a name form permits every name of that form,
  restrictions apply per name form, DNS matching is by label boundary, an
  IPv4-only permitted set forbids every IPv6 address while a DNS-only one
  forbids no address at all, and the common name is checked as a DNS name only
  when the SAN list carries no DNS entry. A constraint form cabin cannot
  evaluate — which an imported CA may legitimately carry — refuses a name of
  that form rather than ignoring it. The refusal is a subclass of the existing
  issuance error, so every ordinary door rejects it unchanged; ACME is the one
  exception and answers `rejectedIdentifier` instead of the `serverInternal`
  that every issuance failure used to become, because telling a correct client
  the server is broken invites it to retry forever. `/ca` shows the
  constraints of every row that carries them, read from that row's own
  certificate, and `ca_created` records them. cabin's own TLS certificate is
  not exempt: an issuer constrained to exclude cabin's own hostname stops
  renewing it 30 to 90 days later, which is now measured rather than
  discovered. No migration.
- Spec 0021 (cross-signing): a root already in cabin can sign another root
  (`POST /ca/{ca_id}/cross-sign`), or a cross certificate produced elsewhere
  can be imported (`POST /ca/cross-import` — two PEMs and no private key,
  because nobody holds the key of a certificate somebody else produced). It is
  a second certificate for a root that already exists, same subject and same
  public key, so relying parties trusting the older root have a path to
  certificates issued under the newer one. It is in scope for devices whose
  trust store cannot be reached and which will outlive a root generation; for
  everything else 0017's two hierarchies side by side are the better
  transition, and cross-signing is the most error-prone mechanism in PKI. The
  import compares the SubjectPublicKeyInfo and the subject's DER encoding, not
  the name as a string: without that, any CA certificate whose subject happens
  to read `CN=cabin Root CA` could be stapled into the chain cabin serves to
  every client. A leaf under a cross-signed root then has two valid paths and
  both are served — the default is the earliest cross path, signed by the
  oldest root generation and therefore the one in the most trust stores, with
  the self-signed path always present as an alternate. Alternates are offered
  as `?anchor={ca_id}` on the chain downloads and, over ACME, as
  `Link ...;rel="alternate"` plus `POST /acme/cert/{cert_id}/{anchor_id}`,
  which cabin did not emit before, so `certbot --preferred-chain` can pin
  either path from the client side. Expiry is checked where the chain is
  assembled, on every request, against no cached value, no column and no
  background job: when DST Root CA X3 expired in 2021, clients broke because
  path building preferred an expired route while a valid one sat beside it,
  and a chain that is correct until somebody visits a page is not correct. A
  cross certificate carries exactly the name constraints of the root it
  duplicates, because a constraint that existed only on the long path would be
  enforced by the relying parties that took it and by nobody else, cabin
  included. `/ca` renders cross rows under the root they duplicate and names
  which path is served by default and which is offered alongside; the
  dashboard's "install this root" link deliberately keeps pointing at the
  self-signed root, and carries a comment saying so, because an operator
  following it must not install the wrong thing. Retiring a cross certificate
  is the kill switch and takes the path out of every chain on the next
  request — but it is not a revocation, and cabin cannot revoke one: a cross
  certificate is signed by a root, cabin publishes no CRL for a root, so there
  is no document its serial could go into, and a relying party that already
  cached it is told nothing. The UI says that next to the button. New audit
  actions `ca_cross_signed` and `ca_cross_imported`; `IssuerInfo` gains
  `cross` as a kind and a `cross_of_id`. Migration 0003 edited in place again;
  the chain still ends at 0010.
- Spec 0022 (https): cabin can terminate TLS itself, opt-in and off by
  default. It starts self-signed before the listener accepts anything, issues
  itself a certificate from its own CA once one exists and swaps it onto the
  live `SSLContext` without a restart, and serves the same certificate after a
  restart. That certificate is an ordinary inventory row with a new `system`
  source, so it is visible, revocable and counted like any other. Its private
  key is sealed at rest with the same store that protects every CA key and is
  materialised only into an anonymous `memfd` for the duration of one
  `load_cert_chain` call — a descriptor with no name in any filesystem —
  falling back to an immediately unlinked 0600 file only if `memfd_create`
  raises. Renewal runs on a clock (90 days, renewed at 30, checked hourly) and
  not lazily on access: the certificate is presented during the handshake,
  below Python, so the only request that could trigger a lazy renewal is one
  the expired certificate has already prevented. A replacement is issued only
  when it gains at least a day of life, or an instance whose bound issuer is
  nearly expired would clamp every certificate straight back into the renewal
  window and add thousands of rows and sealed keys a year. Which issuer signs
  cabin's own certificate is a stored binding rather than a silent default,
  because it decides the chain operators have installed in their trust stores;
  with several active issuers and no binding, cabin keeps serving self-signed
  and asks, since reachable with a warning beats correct and unreachable, and
  it never downgrades itself from CA-issued back to self-signed. Retiring the
  bound issuer is refused, including through the cascade from retiring its
  root, because the symptom would otherwise appear months after the cause.
  With TLS on, a second plaintext listener on `CABIN_HTTP_PORT` serves the CRL
  and CA-certificate routes and nothing else — no route that accepts a
  credential, no `Location`, no `Set-Cookie` — because those URLs are baked
  into certificates and must stay `http://`. The consequence for deployment is
  that it belongs on host port 80 of the host named in `base_url`, and a
  `base_url` carrying any other explicit port is now refused while TLS is on.
  `COOKIE_SECURE` is forced on, and cabin refuses to start with more than one
  worker while TLS is on, because the swap would reach one process and leave
  the rest serving an expired certificate silently. `/ca` now shows each
  issuer's CDP and AIA URLs exactly as they are embedded, so a wrongly mapped
  port is visible in seconds instead of years. New audit actions
  `tls_certificate_issued` and `tls_certificate_failed`, a dashboard banner
  and first-run notes explaining that the initial browser warning is expected
  and what ends it, a scheme-aware container health check, and compose, Unraid
  and README updates. The reverse-proxy deployment is unchanged. Turning TLS
  on is four steps and the order matters: set `base_url` to the host cabin
  will be reached at, with no explicit port, because it decides the name on
  the certificate; set `CABIN_TLS=true`; publish `CABIN_HTTP_PORT` on host
  port **80** of that host, because that is where every certificate cabin
  issues says its CRL and CA certificate are; and, on an instance with more
  than one active issuer, pick on `/settings` which one signs cabin's own
  certificate, or cabin will keep serving self-signed rather than choose for
  you. The third step is the one that fails quietly — miss it and the
  certificates are perfectly valid while their distribution points are dead,
  which surfaces whenever some relying party first enforces revocation. The
  README's _Security notes_ has the whole sequence in full.

### Changed

- **Seven environment variables, not five.** `CABIN_TLS` (default `false`) and
  `CABIN_HTTP_PORT` (default `8081`) are new, and they are the first values
  since spec 0014 to live in the environment rather than in the settings
  table. `docs/adr/0002-tls-environment-variables.md` records the deviation
  rather than making it quietly: a setting that can make the interface
  unreachable has to be changeable from somewhere that does not depend on that
  interface being reachable. Recoverability, not convenience, is the test the
  ADR holds the next such request to.
- **The CRL and CA-certificate endpoints are per issuer.** `GET
/crl/{issuer_id}`, `GET /crl/{issuer_id}.pem` and the new `GET
/ca/{ca_id}.cer` replace `/crl` and `/crl.pem`, and the authenticated
  `/ca/{ca_id}.pem` and `/ca/{issuer_id}/chain.pem` replace `/ca/root.pem` and
  `/ca/chain.pem`. All four old paths are removed with no alias and no
  redirect, so anything fetching them has to be repointed — including any
  certificate issued by 0.1.0, whose distribution point names a URL that no
  longer answers.
- **The ACME directory URL is per issuer**, so every existing client
  configuration changes. Read the new URL before changing anything: `/ca` and
  `/acme` show one per hierarchy, and the issuer id in the path cannot be
  guessed or derived from the old URL — `/settings` no longer prints a
  directory URL at all, because there is no longer a single one to print. With
  that id in hand, a certbot or acme.sh setup pointing at `/acme/directory`,
  which now answers with a 404 problem document, moves to
  `/acme/ca/{issuer_id}/directory`; `/acme/new-account` is gone the same way.
- `GET /api/v1/ca` and the MCP `get_ca_info` tool return `{"issuers": [...]}`,
  one entry per row with its `crl_url` and `ca_url`, instead of a
  `{root, intermediate}` pair that can no longer describe the instance.
  `CertificateDetail` and `CertificatePem` gain `validity_capped_from`,
  present only on an issuance response whose validity was actually clamped.
  The issue and sign forms and their REST bodies gain an optional `issuer_id`.

### Fixed

- **Foreign keys were never enforced.** SQLite ignores them unless
  `PRAGMA foreign_keys = ON` is set per connection, and cabin never set it, so
  every foreign key in the schema was decorative — a certificate row
  referencing a CA that does not exist was written without complaint. The
  pragma now comes from a SQLAlchemy connect listener, so it covers every
  connection the pool creates rather than only the first, and it is skipped
  for other backends. This predates 0.2.0; multiple hierarchies made it
  load-bearing, because a chain is now assembled from `certificates.issuer_id`
  naming a real row.
- **ACME wrote its order rows in an unspecified order**, which turning the
  pragma on is what exposed. `create_order` built the order, its
  authorizations and their challenges in a single flush with no
  `relationship()` between the mappers, and SQLAlchemy derives its
  cross-mapper insert ordering from relationships rather than from raw foreign
  key columns — so parent-before-child had only ever been correct by luck, in
  every ACME order since the feature shipped. Explicit flushes now force it.

## [0.1.0] - 2026-08-03

First release. cabin is an all-in-one internal certificate authority in one
container: a web interface, a REST API, an RFC 8555 ACME server
(http-01/dns-01/tls-alpn-01, external account binding), direct issuance and
CSR signing, CRL-based revocation, an MCP server and an audit log. Specs
0001–0016.

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
- Spec 0014 (deployment): cabin ships. A multi-stage `Dockerfile` builds a
  wheel with uv and installs it into a virtualenv that is copied into a
  `python:3.13-slim` runtime pinned by digest — no uv, no compiler and no
  source tree in the final image, which runs as the nonroot uid 65532, keeps
  its state in the `/data` volume and health-checks itself with the standard
  library rather than a bundled curl. Measured at **216 MB uncompressed on
  linux/amd64** and 243 MB on linux/arm64 (235 MB and 262 MB as the sum of
  layer sizes), against the 250 MB target the spec sets for amd64. The virtualenv stays root-owned
  and read-only to the runtime user, so a code execution bug cannot rewrite
  the code it runs as — and the shipped compose file and Unraid template add
  `no-new-privileges` and `--cap-drop ALL`, which cabin needs none of and
  which defuse the eight setuid-root binaries the Debian base image brings.
  An unwritable `DATA_DIR` — the wrong-owner bind mount every one of those
  files warns about — is now caught before the database is opened and
  reported as one sentence naming the directory, the effective uid and the
  `chown` that fixes it, instead of as a SQLAlchemy traceback. The release
  version is stamped into the wheel's metadata at build
  time (`--build-arg VERSION` → `uv version`), so `/healthz`, the OpenAPI
  document and the UI footer all report it from one source and a plain
  source build still reports the version in `pyproject.toml`. New
  `docker-compose.yml` (bind-mounted `./data`, the optional environment
  variables and a PostgreSQL alternative as comments), new
  `deploy/unraid/cabin.xml` template plus icon — mapping appdata to `/data`
  and running as `99:100`, the owner of an Unraid appdata share — and two
  GitHub Actions lanes that build linux/amd64 + linux/arm64 with buildx and
  QEMU and push to `ghcr.io/nofuturekid/cabin`: `release.yml` (tag, plus
  `:latest` for stable releases or `:beta` for prereleases) and `main.yml`
  (the moving `:main` tag, versioned with a `+main.<sha>` local segment).
  The `:main` lane hangs off CI finishing green rather than off the push, so
  a red test suite cannot move the tag people pull.
  `make docker-smoke` builds the image, runs it as the invoking uid against
  an empty data directory, waits for `/healthz` and checks the version and
  the 0600 `secret.key` it created. README rewritten around what cabin is,
  what it can do, the two ways to install it, the five environment variables
  and what to back up.
- Spec 0015 (ui-layout): the page chrome is rebuilt around one layout. The UI
  had three competing content widths (`main` 60rem, `.card` 24rem,
  `.card-wide` 48rem), so settings rendered at half the width of the
  inventory; tables had no scroll container, so `/certs` drew its last three
  columns 275px outside the card and off the screen; serials, key ids and
  base URLs had no break opportunity and were painted through their
  container's border; and nothing was responsive. Pages now compose from a
  grouped navigation rail plus a content column that uses the window, and
  from four primitives — `.scroller` (the only element allowed to scroll
  sideways), `.section` (a heading and its explanation beside its controls),
  `.field` and `.tag`. `form` is no longer a layout, so buttons are sized by
  their text instead of stretching across the page, and settings and ACME
  read as sections rather than one flat form. Both colour schemes are
  complete, the rail is sticky so it cannot scroll away and take the logout
  button with it, it collapses to a wrapping nav strip below 60rem, and the
  current page is marked with `aria-current`. Issuing and CSR signing are now two pages with two rail entries — the
  choice of who holds the private key is the whole point of the difference,
  and it was buried in the second half of one page (new `GET /certs/sign`;
  the `POST` of the same path is unchanged). Two SIL OFL fonts are vendored
  (Public Sans and IBM Plex Mono, 57 KB of woff2 with their licences) — cabin
  still fetches nothing from a CDN. Verified by rendering all ten
  authenticated pages in headless Chrome with a 60-character common name and
  five SANs and measuring every element against its container at 1440px and
  390px; the same probe reports the pre-0015 pages as broken, which is what
  makes the green result mean anything.
- Spec 0016 (dashboard): `/` stops being the stub spec 0003 called it and
  becomes the page an operator opens first. Four counts (valid / expiring /
  expired / revoked), each linking to the inventory filtered to it and backed
  by a new `status_counts` that runs the *same* filters the inventory runs, so
  a tile and the page behind it cannot disagree. The certificates expiring
  within 30 days, soonest first. The CA's own expiry — flagged a year ahead,
  because replacing an intermediate means touching every trust store it lives
  in, and nothing surfaced that before. Whether the published CRL is still
  inside its validity window, which is the difference between clients seeing a
  revocation and clients silently trusting a revoked certificate. Which
  services are on, for the roles that may see `/settings` — the dashboard
  aggregates pages with different roles attached and keeps each one, so it
  cannot become a way around authorisation. And the last five audit entries.
  No new table, no background job, no new dependency: every figure is read
  from what the database already holds, off one clock taken per request.
