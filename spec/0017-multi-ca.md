# Spec 0017 — Multiple CA Hierarchies

## Context

The question that started this was what happens when the intermediate or the
root runs out. Today's answers are all bad:

1. Before expiry, every newly issued certificate is **silently** clamped to
   the issuer's remaining life (`ca/leaf.py:286`). Ask for a year three days
   before the intermediate expires, get three days, hear nothing.
2. After expiry, issuance fails (`ca/leaf.py:288`), every deployed
   certificate becomes untrusted because its chain is, and the CRL keeps
   being signed by the expired intermediate — `ca/crl.py:109` checks nothing.
3. There is no way out, because there is no second hierarchy:
   `ca_certificates.kind` is unique
   (`store/migrations/versions/0003_ca_certificates.py:33`), and both create
   and import raise `CAExistsError` (`ca/service.py:24`). `spec/0004-ca-core.md:92`
   lists rotation and parallel hierarchies as out of scope on purpose.

Rather than bolting rotation on as a special case, cabin moves to **several
hierarchies side by side**. Rotation then stops being a mechanism of its own
and becomes ordinary operation: a new intermediate under the same root, the
old one retired.

Three assumptions are baked into the code today, and all three are wrong
after this spec. They are the actual work:

- There is exactly one hierarchy (`get_ca` at `ca/service.py:64-74` returns
  "the" root and "the" intermediate).
- A leaf does not remember who issued it — the chain is reassembled live from
  the one hierarchy on every download (`web/certs_download_ui.py:69-77`,
  `api/views.py:104-108`, `acme/api_finalize.py:307-318`).
- `crl_state` is a singleton (`CHECK id = 1`,
  `store/migrations/versions/0005_revocation.py:34`) whose CRL iterates over
  **every** revoked certificate in the database (`ca/crl.py:69-84`).

**Migrations 0003, 0004 and 0005 are rewritten, not extended.** There is no
production instance, no existing data, and no backwards compatibility with a
0.1.x database. This is deliberate and it has a price worth naming: if
someone did carry a 0.1.0 database forward, Alembic would read "revision
0009, nothing to do" and leave the old schema in place while the code expects
the new one. There is no repair path other than emptying `/data`. This
belongs in the CHANGELOG and the release notes; the next version is 0.2.0.

Two consequences of the schema change reach further than the plan's list of
removed endpoints, and are specified here because nothing else can absorb
them: `/ca/root.pem` and `/ca/chain.pem` (`web/ca_ui.py:195-215`) name a
"the" that no longer exists, and `GET /api/v1/ca` (`api/models.py:63-70`)
plus the MCP `get_ca_info` tool (`mcp/server.py:335-347`) return a
`{root, intermediate}` pair that can no longer describe the instance.

## User Stories

- As an operator whose intermediate expires next month, I create a second
  intermediate under the same root, retire the old one, and keep issuing —
  without invalidating anything already deployed.
- As an operator, I run two hierarchies at once (one for internal services,
  one for a lab network), and each certificate carries the CRL and the CA URL
  of the hierarchy it actually came from.
- As an operator issuing a certificate three days before the issuer expires,
  I am told that I asked for a year and got three days, on the page, in the
  API response and in the audit log.
- As an operator whose root has ten years left and needs twenty, I renew it
  in place, and everything already issued under it keeps validating.
- As a relying party handed only a leaf by a badly configured server, I
  follow its AIA `caIssuers` URL and complete the chain myself.
- As an operator, I see every hierarchy on one page — which are active, which
  are retired, when each expires — instead of one hierarchy's detail view.

## Functional Requirements

- FR-1: **Schema, by rewriting migrations 0003/0004/0005 in place.** No new
  revision, no backfill, no compatibility with an existing database.
  - `ca_certificates`: the `UniqueConstraint` on `kind` is gone. New columns:
    `name` (String(64), NOT NULL) — the operator-facing label, not unique,
    because a rotation deliberately produces a second row with the same
    label; `parent_id` (Integer, FK `ca_certificates.id`, NULL for a
    self-signed root); `status` (String(16), NOT NULL, default `active`,
    `CHECK status IN ('active', 'retired')`).
  - `certificates`: new `issuer_id` (Integer, FK `ca_certificates.id`, **NOT
    NULL**). A leaf that does not know its issuer cannot have its chain built
    or its revocation published, so this is not nullable and has no default.
  - `crl_state`: `CHECK id = 1` is gone. The primary key becomes `issuer_id`
    (FK `ca_certificates.id`) — one CRL per issuer, not one per instance.
    The `id` column is dropped.
- FR-2: **`cabin.ca.service` stops assuming one hierarchy.** `CAExistsError`
  is deleted along with both check-then-insert guards
  (`ca/service.py:93-94`, `:144-145`) and the `IntegrityError` backstops that
  existed only for the unique constraint (`:117-125`, `:170-174`).
  `create_hierarchy` and `import_hierarchy` each add a **further** hierarchy
  and take a `name`. New functions:
  - `list_cas(db, *, status=None, kind=None)` — the rows, ordered by id.
  - `chain_for(db, ca_id)` — that row and its ancestors, nearest first, root
    last, walking `parent_id`. Raises `UnknownIssuerError` for an unknown id.
  - `active_issuers(db)` — the active rows with `kind == "intermediate"`,
    i.e. what may sign a leaf.
  - `resolve_issuer(db, issuer_id)` — FR-6's rule in one place.
  - `get_ca(db, issuer_id)` — replaces the no-argument version; returns the
    `CACertificate` row or raises `UnknownIssuerError`.
  - `signing_credentials(db, secrets, issuer_id)` — the named issuer's
    certificate and unsealed key. Still raises `CANotConfiguredError` when
    its `key_sealed` is NULL.
- FR-3: **`create_intermediate_under(root_id, name, key_type, years)`** — the
  rotation path. Inserts one row with `parent_id = root_id`,
  `status = "active"`. It signs with the root's key, so it raises
  `CANotConfiguredError` naming the reason when `root.key_sealed is None` —
  which is the case for **every imported hierarchy** (`ca/service.py:162`
  stores the imported parent with `key_sealed=None`). Rejects a `root_id`
  that is not a `kind == "root"` row, and clamps `years` to the root's
  remaining validity the way `ca/x509.py:164` already does.
- FR-4: **`retire(db, ca_id)`** sets `status = "retired"` on the row and, for
  a root, on every descendant of it as well: a root that must not be used is
  not one whose intermediates may keep issuing. A retired row still serves
  its chain, still signs and serves its CRL, and still appears in the
  inventory — it only stops being offered as an issuer. **The last active
  intermediate cannot be retired** (`RetireError`), for the same reason the
  last superadmin cannot be deleted (`users.py:75-79`): the instance would be
  unable to issue anything and have no way back. Retiring an already retired
  row is a no-op, not an error.
- FR-5: **`renew_in_place(db, secrets, ca_id, years)`** issues a new
  certificate for **the same public key, the same subject and the same row
  id**, with a later `not_after`, and overwrites `cert_pem`. Because the key
  does not change, the SubjectKeyIdentifier does not change either, so the
  AuthorityKeyIdentifier of everything already issued still matches and every
  existing certificate keeps validating — that is the entire point of the
  operation and what AC-6 measures. A root is re-signed with its own key; an
  intermediate with its parent's, clamped to the parent's `not_after`.
  Requires the signing key, so it raises `CANotConfiguredError` for an
  imported root (no key) and for an intermediate whose imported parent has
  none. BasicConstraints (including `path_length`), KeyUsage and the SKI are
  carried over unchanged; the serial number is new. A new pure helper
  `ca/x509.py:renew_certificate(cert, key, parent_cert, parent_key, years)`
  does the rebuilding, so no route reaches into a `CertificateBuilder`.
- FR-6: **Issuer selection.** `issue_and_store` and `sign_csr_and_store`
  (`ca/certs.py:159`, `:197`) gain an `issuer_id: int | None = None`
  parameter and store it on the row. `resolve_issuer` decides:
  - `issuer_id` given → that row, provided it exists, is an intermediate and
    is `active`; otherwise `UnknownIssuerError` / `IssuerRetiredError`.
  - `issuer_id` omitted and exactly one active issuer exists → that one.
  - `issuer_id` omitted and several exist → `IssuerRequiredError`.
  - no active issuer at all → `CANotConfiguredError`.

  The default keeps the single-CA installation ergonomic and keeps the
  existing 0005–0013 issuance tests meaningful. All seven entry points pass
  the parameter through: `web/certs_ui.py:204` and `:246`, `api/v1.py:243`
  and `:285`, `acme/api_finalize.py:222`, `mcp/server.py:438` and `:494`.
  ACME does not choose an issuer in this spec — it passes `None` and lives
  with the default rule (spec 0019 gives it a directory per issuer).

- FR-7: **A clamped validity is said out loud.** `ca/leaf.py:286` keeps
  clamping — issuing past the issuer's expiry is not an option — but stops
  doing it quietly. `issue_certificate` and `sign_csr` return the
  `not_after` that was requested but not granted (`None` when the full
  request was met), `issue_and_store` and `sign_csr_and_store` return an
  `Issued(row, capped_from)` dataclass instead of a bare row, and each of the
  seven entry points reports it:
  - UI: the issue/sign result page carries a notice naming both the requested
    and the granted expiry.
  - REST and MCP: `CertificateDetail` / `CertificatePem` gain
    `validity_capped_from: datetime | None`, absent (via the existing
    `response_model_exclude_none=True`) when nothing was clamped. It is set
    **only** on an issuance response, never recomputed on a later lookup —
    the requested validity is not stored, and re-deriving "was this clamped"
    from `leaf.not_after == issuer.not_after` would silently become wrong the
    moment FR-5 extends the issuer.
  - Audit: `audit.certificate_detail` gains `days_requested` and
    `validity_capped_from` when, and only when, the clamp fired.

  This is never a rejection. A certificate that is shorter than asked for is
  still the certificate the operator needs.

- FR-8: **The chain comes from the leaf.** Everywhere a chain is assembled it
  is built from `chain_for(db, row.issuer_id)` instead of the one hierarchy:
  `web/certs_download_ui.py:69-77` (`_chain`, also feeding the PKCS#12
  bundle at `:166`), `api/views.py:104-108` (`chain_pem`, feeding
  `certificate_pem` and therefore both REST and MCP), and
  `acme/api_finalize.py:307-318`.
- FR-9: **One CRL per issuer.** `regenerate_crl` takes an `issuer_id` and
  selects only rows with `Certificate.issuer_id == issuer_id`
  (`ca/crl.py:69-84`), signs with that issuer's credentials, and reads and
  writes the `crl_state` row keyed by that issuer — `FOR UPDATE` semantics
  and the monotonic `crl_number` are per issuer and otherwise unchanged.
  `stored_crl(db, issuer_id)` and `current_crl(db, secrets, issuer_id, now)`
  take the same argument. `revoke_certificate` (`ca/crl.py:159`) keeps its
  signature: the issuer comes off the row it is already loading, so its four
  call sites do not change. Revoking a certificate issued by a **retired**
  issuer works and republishes that issuer's CRL — a retired issuer that
  could not publish revocations would be worse than one still issuing.
- FR-10: **Public endpoints.** `GET /crl/{issuer_id}` (`application/pkix-crl`)
  and `GET /crl/{issuer_id}.pem` replace `/crl` and `/crl.pem`, which are
  removed with no alias. New: `GET /ca/{ca_id}.cer` — one certificate, DER,
  `application/pkix-cert`. All three are unauthenticated, like the CRL routes
  they follow (`web/crl_ui.py:1-9`); the first-run redirect is a per-route
  dependency and so does not apply. An unknown id, or an id that is not an
  intermediate for the CRL routes, is a 404. The authenticated PEM downloads
  become `GET /ca/{ca_id}.pem` (one certificate) and
  `GET /ca/{issuer_id}/chain.pem` (the issuer and its ancestors, root last),
  replacing `/ca/root.pem` and `/ca/chain.pem`.
- FR-11: **AIA `caIssuers`.** Every leaf gains an
  `AuthorityInformationAccess` extension (non-critical) with one
  `AccessDescription` for `caIssuers` pointing at `/ca/{issuer_id}.cer`,
  built next to the CDP in `ca/leaf.py:246-258` and omitted entirely — like
  the CDP — when no base URL is configured. cabin emits no AIA at all today;
  this is what lets a client repair a chain from a server that ships only the
  leaf.
- FR-12: **CDP and AIA URLs are always `http://`, never `https://`.** A new
  pure helper `ca/leaf.py:public_http_origin(base_url) -> str` derives the
  public HTTP origin from the configured base URL: scheme forced to `http`,
  an explicit `:443` dropped, everything else (host, port, path) left as
  configured. `crl.distribution_url` and `crl.ca_issuers_url` call it rather
  than reimplementing it, so there is exactly one place the scheme is forced.
  Reason: a relying party validating a cabin certificate would otherwise need
  a CRL it can only fetch over TLS, which needs a validated certificate. This
  is not a detail to be tidied up later — it is the constraint spec 0022's
  second, plaintext listener exists to satisfy. `settings.validate_base_url`
  (`settings.py:139-176`) is unchanged and still accepts an `https://` base
  URL; only what goes into a certificate is rewritten.

  The helper lives in `ca/leaf.py`, not in `ca/crl.py` as an earlier draft of
  this requirement said. `ca/leaf.py` and `ca/x509.py` are the only two
  modules under `ca/` that import no session, no ORM and no settings;
  `ca/crl.py` imports all three. The helper takes a string and returns a
  string, and the consumer that must not get it wrong is the certificate
  builder next door. Putting it in `ca/crl.py` would have made the
  pure-crypto module — and `tests/test_ca_leaf.py`, which never opens a
  database — reach through the persistence layer for a string transformation,
  and would have parked the whole pure-crypto lane behind FR-9's rework of
  `ca/crl.py`.

- FR-13: **`path_length` is chosen when a root is created.** `ca/x509.py:126`
  hard-codes `path_length=1`; `create_root` takes it as a parameter and the
  create form offers it, default 1, server-validated 1..4. Below 1 no
  intermediate could be signed at all; the upper bound is a sanity cap. It is
  a parameter because it is the one decision about a root that cannot be
  corrected afterwards — and cross-signing (spec 0021) needs room in it.
- FR-14: **UI.** `/ca` becomes the list of hierarchies: each root with its
  intermediates, and per row the name, kind, status, subject, validity window
  and fingerprint. Actions on the page: create a root (+ intermediate),
  import a root (+ intermediate), create an intermediate under a named root,
  renew a named row, retire a named row. Each POST is admin + CSRF, as
  `ca_create`/`ca_import` already are. The wizard at `ca_setup.html` remains
  what an instance with no CA at all sees. The issue and sign forms
  (`certs_new.html`, `certs_sign.html`) gain an issuer select, populated from
  `active_issuers(db)` and **rendered only when there is more than one** — a
  single-CA installation sees no new field. The dashboard's `ca_certs`
  (`web/ui.py:226-238`) lists one entry per `ca_certificates` row rather than
  the pair `[intermediate, root]`; `CA_WARN_DAYS` (`web/ui.py:55`) applies to
  `active` rows, while a `retired` row is flagged only once it has actually
  expired — its remaining job is signing its CRL, and that job ends with the
  certificate, so a year's notice on something already stood down is noise.
- FR-15: **Audit and API surface.** New `AuditAction` members `ca_renewed`
  and `ca_retired`; all four CA actions (`ca_created`, `ca_imported` included)
  record `target_type="ca_certificate"` with the row id as `target_id`,
  replacing today's `target_type="ca"` at `web/ca_ui.py:135` and `:187` —
  one table, one target type. `GET /api/v1/ca` returns
  `{"issuers": [...]}`, one entry per row with `id`, `name`, `kind`,
  `status`, `parent_id`, the fields `describe_certificate` already produces,
  and the row's `crl_url` and `ca_url`; the MCP `get_ca_info` tool
  (`mcp/server.py:335-347`) reports the same list. `CAInfo`'s
  `{root, intermediate}` shape (`api/models.py:63-70`) is removed.

## Interface Contract

The Functional Requirements above say what changes. This section says exactly
what the changed things are called, what they take and what they return, so
that the modules on either side of a seam cannot be built against two
different guesses. It was written after the test suites and reconciles them;
where two of them assumed different things, the choice made here is the one
that stands and the note says why.

### The naming rule

`ca_certificates.name` is always the subject common name of that row's
`cert_pem`. For a hierarchy cabin generates, cabin composes the subject from
the operator's label — `create_hierarchy(name="cabin")` produces
`CN=cabin Root CA` and `CN=cabin Intermediate CA`, and the two rows are named
that. For an imported hierarchy the subject already exists and was chosen by
whoever ran that CA, so the row takes it verbatim; `import_hierarchy` derives
both names from the submitted certificates and takes no `name` argument, and
`POST /ca/import` has no name field. A second, cabin-local label for an
imported CA would let `/ca` show one name while the certificate an operator
hands to a relying party says another. One name, read off the certificate.

### `cabin.ca.x509` — pure crypto, no database

- `create_root(subject_cn, key_type, years=20, path_length=1)` — FR-13.
  `path_length` follows `years`, so existing keyword calls are unaffected.
  This layer does not enforce the 1..4 bound; the form does (AC-11), because
  the bound is a policy about what an operator may ask for, not an X.509
  invariant.
- `renew_certificate(cert, key, parent_cert, parent_key, years) -> x509.Certificate`
  — FR-5. For a root, `parent_cert`/`parent_key` are the certificate's own.
  Carries over the subject, the public key, the SubjectKeyIdentifier,
  BasicConstraints (including `path_length`) and KeyUsage; issues a new
  serial and a later `not_after`.

### `cabin.ca.leaf` — pure crypto, no database

- `public_http_origin(base_url: str) -> str` — FR-12.
- `issue_certificate(issuer_cert, issuer_key, profile, subject_cn, sans, days=DEFAULT_DAYS, key_type="ecdsa-p256", crl_url=None, ca_issuers_url=None) -> tuple[x509.Certificate, PrivateKey, datetime | None]`
- `sign_csr(issuer_cert, issuer_key, csr_pem, profile, days=DEFAULT_DAYS, sans_override=None, crl_url=None, ca_issuers_url=None, subject_cn_fallback=None, allow_empty_subject=False) -> tuple[x509.Certificate, datetime | None]`

  The last element of each return is FR-7's `capped_from`: the `not_after`
  that was requested but not granted, and `None` when the full request was
  met. It is returned from here, and not re-derived in `ca/certs.py`, because
  `_build_leaf` is the only place that holds both the requested `days` and
  the `now` the clamp was measured against (`ca/leaf.py:284-286`). A second
  module recomputing it would need `_BACKDATE` and its own clock, and the two
  answers would drift apart at exactly the boundary the clamp is about. This
  changes the shape of both returns; every call site unpacks one more value.

  `ca_issuers_url` builds FR-11's AIA the way `crl_url` builds the CDP: one
  non-critical `AuthorityInformationAccess` extension with exactly one
  `caIssuers` `UniformResourceIdentifier`, omitted entirely when the argument
  is `None`.

### `cabin.ca.service`

- `create_hierarchy(db, secrets, name, key_type="ecdsa-p256", root_years=20, intermediate_years=10) -> CAHierarchy`
  — unchanged apart from the deleted guards (FR-2).
- `import_hierarchy(db, secrets, cert_pem, key_pem, key_passphrase, chain_pem) -> CAHierarchy`
  — unchanged signature; see the naming rule above for why it gains no
  `name`.
- `create_intermediate_under(db, secrets, root_id, name, key_type="ecdsa-p256", years=10) -> CACertificate`
  — FR-3. Subject `CN={name} Intermediate CA`, `parent_id = root_id`,
  `status="active"`. A `root_id` that is not a `kind == "root"` row is a
  plain `ValueError` whose message names "root": it is a programming error at
  the call site, not a state the operator can be in through the UI, which
  only offers the action on roots.
- `retire(db, ca_id) -> None` — FR-4.
- `renew_in_place(db, secrets, ca_id, years) -> CACertificate` — FR-5,
  returning the same row it was given, with `cert_pem` overwritten.
- `list_cas(db, *, status=None, kind=None) -> list[CACertificate]` — ordered
  by id.
- `chain_for(db, ca_id) -> list[CACertificate]` — that row first, root last.
- `active_issuers(db) -> list[CACertificate]`.
- `resolve_issuer(db, issuer_id: int | None) -> CACertificate` — FR-6's rule.
- `get_ca(db, issuer_id) -> CACertificate` — no longer returns `None` and no
  longer returns a `CAHierarchy`; an unknown id raises.
- `signing_credentials(db, secrets, issuer_id) -> tuple[x509.Certificate, PrivateKey]`.
- `CAExistsError` is deleted. `tests/test_ca_service.py` asserts its absence
  from the module, not merely that nothing raises it.

### `cabin.ca.certs`

- `Issued(row: Certificate, capped_from: datetime | None)` — a frozen
  dataclass, FR-7.
- `issue_and_store(db, secrets, *, profile, subject_cn, sans, days=DEFAULT_DAYS, key_type="ecdsa-p256", issuer_id=None, source=CertSource.ui) -> Issued`
- `sign_csr_and_store(db, secrets, *, csr_pem, profile, days=DEFAULT_DAYS, sans_override=None, subject_cn_fallback=None, allow_empty_subject=False, issuer_id=None, source=CertSource.ui) -> Issued`

  Both **lose** their `crl_url` parameter. Under FR-6 the issuer is resolved
  inside these functions, so when `issuer_id` is omitted no caller can know
  which issuer's CRL and CA URL belong in the certificate. These two
  functions call `crl.distribution_url` and `crl.ca_issuers_url` for the
  issuer they resolved and pass the results to `leaf`. That is also what
  makes FR-12 hold for every front door at once instead of seven times over.

- `_store(..., *, issuer_id: int)` — required, keyword-only, no default, so
  that a caller which forgets it is a type error rather than an
  `IntegrityError` in whichever entry point runs first (work split R1).

### `cabin.ca.crl`

- `distribution_url(db, issuer_id) -> str | None` — `<http origin>/crl/{issuer_id}`,
  `None` without a configured base URL.
- `ca_issuers_url(db, issuer_id) -> str | None` — `<http origin>/ca/{issuer_id}.cer`,
  `None` without a configured base URL. New in FR-11.
- `regenerate_crl(db, secrets, issuer_id, now=None) -> CRLState`
- `stored_crl(db, issuer_id) -> CRLState | None`
- `current_crl(db, secrets, issuer_id, now=None) -> CRLState`
- `revoke_certificate(db, secrets, cert_id, reason, now=None) -> Certificate`
  — signature unchanged (FR-9).
- `CRLState`'s primary key is `issuer_id`; `_STATE_ID` is deleted.

### New exceptions

All four are defined in `cabin.ca.service` and imported from there by every
other module and every test. None of them is defined twice.

| Exception             | Raised by                                                                        | When                                                                     |
| --------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `UnknownIssuerError`  | `get_ca`, `chain_for`, `resolve_issuer`, `signing_credentials`, `renew_in_place` | No `ca_certificates` row has that id                                     |
| `IssuerRetiredError`  | `resolve_issuer`                                                                 | The named row exists and is an intermediate, but its `status` is retired |
| `IssuerRequiredError` | `resolve_issuer`                                                                 | No `issuer_id` was given and more than one active issuer exists          |
| `RetireError`         | `retire`                                                                         | The operation would leave the instance with no active issuer             |

`CANotConfiguredError` stays where it is and keeps its two existing jobs: no
active issuer at all (from `resolve_issuer`), and a row whose `key_sealed` is
NULL where a signature is needed (from `signing_credentials`,
`create_intermediate_under`, `renew_in_place`). Its message names the missing
key in the latter case, which AC-13 asserts on.

### Routes

`ca_ui.py` mounts `APIRouter(prefix="/ca")` with `Depends(get_current_user)`
on its GETs; `crl_ui.py` remains the only router in cabin without an
authentication dependency, and its docstring changes from "the public CRL
endpoints" to "the public PKI endpoints".

| Method | Path                         | Module          | Auth         | Response                      |
| ------ | ---------------------------- | --------------- | ------------ | ----------------------------- |
| GET    | `/crl/{issuer_id:int}`       | `web/crl_ui.py` | none         | `application/pkix-crl` (DER)  |
| GET    | `/crl/{issuer_id:int}.pem`   | `web/crl_ui.py` | none         | `application/x-pem-file`      |
| GET    | `/ca/{ca_id:int}.cer`        | `web/crl_ui.py` | none         | `application/pkix-cert` (DER) |
| GET    | `/ca`                        | `web/ca_ui.py`  | session      | `text/html`                   |
| GET    | `/ca/{ca_id}.pem`            | `web/ca_ui.py`  | session      | `application/x-pem-file`      |
| GET    | `/ca/{issuer_id}/chain.pem`  | `web/ca_ui.py`  | session      | `application/x-pem-file`      |
| POST   | `/ca/create`                 | `web/ca_ui.py`  | admin + CSRF | 303 to `/ca`                  |
| POST   | `/ca/import`                 | `web/ca_ui.py`  | admin + CSRF | 303 to `/ca`                  |
| POST   | `/ca/{root_id}/intermediate` | `web/ca_ui.py`  | admin + CSRF | 303 to `/ca`                  |
| POST   | `/ca/{ca_id}/renew`          | `web/ca_ui.py`  | admin + CSRF | 303 to `/ca`                  |
| POST   | `/ca/{ca_id}/retire`         | `web/ca_ui.py`  | admin + CSRF | 303 to `/ca`                  |

Removed with no alias and no redirect: `GET /crl`, `GET /crl.pem`,
`GET /ca/root.pem`, `GET /ca/chain.pem`.

Form fields: `/ca/create` takes `name`, `key_type`, `root_years`,
`intermediate_years` and the new optional `path_length` (default 1);
`/ca/import` takes `cert_pem`, `key_pem`, optional `key_passphrase` and
`chain_pem`; `/ca/{root_id}/intermediate` takes `name`, `key_type`, `years`;
`/ca/{ca_id}/renew` takes `years`; `/ca/{ca_id}/retire` takes nothing beyond
the CSRF token. `/certs/issue` and `/certs/sign` gain an optional `issuer_id`
field, and `POST /api/v1/certificates` and `/api/v1/certificates/sign` gain
an optional `issuer_id` JSON key.

**The two `/ca` routes do not shadow each other, and this is not luck.**
Starlette compiles `/ca/{ca_id}.pem` to `^/ca/(?P<ca_id>[^/]+)\.pem$` and
`/ca/{ca_id}.cer` to `^/ca/(?P<ca_id>[^/]+)\.cer$`; the two regexes are
disjoint, so registration order cannot decide between them. Verified against
FastAPI by registering the authenticated router first (as `app.py` does) and
then again with the order reversed: `/ca/7.cer` answers anonymously both
times.

**The two `/crl` routes do collide, and the `:int` convertor is what
separates them.** `^/crl/(?P<issuer_id>[^/]+)$` matches `/crl/7.pem`, so with
plain `{issuer_id}` the DER route wins whenever it is registered first, and
`GET /crl/7.pem` answers **422** — a wrong status, for the wrong reason, from
the wrong handler. Both CRL routes therefore declare `{issuer_id:int}`, which
compiles the parameter to `[0-9]+` and makes the two paths disjoint whatever
order they are registered in. `/ca/{ca_id:int}.cer` uses the same convertor
for consistency; it also turns `/crl/abc` into a 404 instead of a 422.

**404 conditions on the public routes.** Both CRL routes answer 404 for an
unknown id (`UnknownIssuerError`) and for a row whose `kind` is not
`intermediate` — a root never signs a CRL, so there is nothing to serve and
nothing to say about it. `/ca/{ca_id}.cer` answers 404 only for an unknown
id: serving a root's certificate is exactly what a client repairing a chain
may need. `/ca/{ca_id}.pem` and `/ca/{issuer_id}/chain.pem` answer 404 for an
unknown id once past the session check.

### Changed return types, in one list

| Was                                             | Is                                                |
| ----------------------------------------------- | ------------------------------------------------- |
| `get_ca(db) -> CAHierarchy \| None`             | `get_ca(db, issuer_id) -> CACertificate`, raising |
| `issue_certificate(...) -> (cert, key)`         | `-> (cert, key, capped_from)`                     |
| `sign_csr(...) -> cert`                         | `-> (cert, capped_from)`                          |
| `issue_and_store(...) -> Certificate`           | `-> Issued`                                       |
| `sign_csr_and_store(...) -> Certificate`        | `-> Issued`                                       |
| `CAInfo{root, intermediate, base_url, crl_url}` | `CAInfo{issuers: list[IssuerInfo], base_url}`     |

`IssuerInfo` carries `id`, `name`, `kind`, `status`, `parent_id`, everything
`describe_certificate` already produces (`subject`, `issuer`, `serial`,
`not_valid_before`, `not_valid_after`, `fingerprint`, `key_type`), plus
`crl_url` and `ca_url`. `crl_url` is `None` for a `kind == "root"` row,
because there is no CRL route that would answer for it; `ca_url` is set for
every row, because `/ca/{id}.cer` answers for every row.

`CertificateDetail` and `CertificatePem` gain
`validity_capped_from: datetime | None`, set only on an issuance response
(FR-7) and omitted from the JSON entirely when `None`.

`mcp/server.py:get_ca_info` builds its response by naming each field rather
than splatting `views.ca_info(db).model_dump()`, so that the shape change is
a type error at build time instead of a pydantic failure inside a tool call
(work split R6).

## Acceptance Criteria

Wherever a chain or a CRL is asserted below, the check is a real validation
against the **right** material and a matching failure against the **wrong**
material. An assertion that only proves bytes were returned proves nothing;
this project has shipped two such tests already.

- AC-1: Two hierarchies are created; one certificate is issued from each with
  an explicit `issuer_id`. For each leaf, `openssl verify` with its own chain
  as the CAfile exits 0, and the same command with the other hierarchy's
  chain exits non-zero with an "unable to get local issuer certificate" style
  error. Swapping the two CAfiles must flip both outcomes — a test that only
  runs the positive half fails this criterion.
- AC-2: With two active issuers, `issue_and_store` without `issuer_id` raises
  `IssuerRequiredError` and writes no row; the UI form posts without one and
  gets 400 with the form re-rendered; `POST /api/v1/certificates` without one
  gets 400. After retiring one of the two, the same three calls succeed and
  the stored `issuer_id` is the remaining active issuer's.
- AC-3: Issuing with the `issuer_id` of a retired issuer is refused
  (`IssuerRetiredError`, 400 at both front doors) while `chain_for` and
  `GET /crl/{that id}` for the same issuer still answer 200.
- AC-4: Rotation end to end. Under one root: issue leaf A from intermediate
  I1, retire I1, create I2 under the same root, issue leaf B from I2. A and B
  both verify against their own chains and both fail against each other's.
  `GET /crl/{I1}` and `GET /crl/{I2}` are two distinct CRLs, and
  `openssl crl -noout -issuer` reports I1's resp. I2's subject. Revoking A puts
  its serial in I1's CRL and **not** in I2's — asserted in both directions.
- AC-5: Retiring the last active intermediate raises `RetireError` and
  changes no row. Retiring a root also retires its intermediates, and is
  refused when doing so would leave no active issuer anywhere.
- AC-6: Renewal without rekey. A leaf is issued, then its root is renewed
  with `renew_in_place`. The root row keeps its id, its subject and its
  SubjectKeyIdentifier byte for byte, gets a new serial and a later
  `not_after`, and the leaf issued _before_ the renewal verifies against the
  _renewed_ root with `openssl verify`. Counter-check: a root rebuilt with a
  fresh key instead fails that same verification, which is what proves the
  test is measuring the key's reuse and not just that a file was written.
- AC-7: Clamping is visible. With an issuer three days from expiry, a request
  for 365 days yields a certificate whose `not_after` equals the issuer's;
  the UI result page names both the requested and the granted expiry, the
  REST response carries `validity_capped_from` equal to the requested
  instant, and the audit entry's detail carries `days_requested: 365`. The
  same request against a fresh issuer carries none of the three — the field
  is absent from the response, not `null`-and-present.
- AC-8: Every issued leaf carries an `AuthorityInformationAccess` extension
  with exactly one `caIssuers` `UniformResourceIdentifier`, equal to
  `<http origin>/ca/{its issuer_id}.cer`; `GET` on that URL without a session
  returns 200, `application/pkix-cert`, and DER bytes that
  `x509.load_der_x509_certificate` parses into a certificate whose subject
  equals the leaf's issuer name. With no base URL configured, neither the AIA
  nor the CDP extension is present.
- AC-9: With `base_url = https://ca.example.lan`, a newly issued leaf's CDP
  and AIA URLs both start with `http://ca.example.lan` and neither contains
  `https`. With `base_url = https://ca.example.lan:443` the URLs are
  `http://ca.example.lan/...`; with `https://ca.example.lan:8443` the port
  survives.
- AC-10: `/crl` and `/crl.pem` return 404 — no redirect, no alias.
  `/crl/{intermediate id}` returns `application/pkix-crl` with the cache
  header, `/crl/{intermediate id}.pem` returns PEM, both without a session;
  `/crl/{a root's id}` and `/crl/999999` return 404. A stale stored CRL for
  one issuer is regenerated on access without touching the other issuer's
  `crl_number`.
- AC-11: A root created with `path_length=2` parses back with
  `BasicConstraints(ca=True, path_length=2)`; `path_length=0` and
  `path_length=5` are both rejected by the form with a 400 and no row
  written. The default remains 1.
- AC-12: `/ca` lists every `ca_certificates` row grouped under its root, with
  its status; the create-intermediate, renew and retire POSTs are 403 for a
  viewer and require CSRF for an admin. With exactly one active issuer,
  `/certs/new` and `/certs/sign` render no issuer select at all (assert the
  control's absence, not the absence of a string); with two, the select lists
  both by id and the posted id is the one stored on the row.
- AC-13: `create_intermediate_under` and `renew_in_place` on an imported root
  raise `CANotConfiguredError` whose message names the missing key, and the
  `/ca` page presents those actions as unavailable for that root rather than
  offering a button that 500s.
- AC-14: `ca_renewed` and `ca_retired` appear in the audit log with
  `target_type="ca_certificate"` and the row id, and are selectable in the
  audit filter (which is generated from `AuditAction`, so this is an
  assertion on the rendered options).
- AC-15: `GET /api/v1/ca` returns one entry per row with `status` and
  `parent_id`; after retiring an issuer the same call reports it as
  `retired`. The MCP `get_ca_info` tool returns the same ids and statuses as
  the REST call against the same database.
- AC-16: A fresh database created from the rewritten migrations 0003–0005 has
  no unique constraint on `ca_certificates.kind`, no `CHECK id = 1` on
  `crl_state`, and a NOT NULL `certificates.issuer_id`; inserting a
  `certificates` row without one fails at the database, not only in Python.

## Test list

test_two_hierarchies_verify_against_own_chain_only (openssl, both
directions), test_issuer_required_with_multiple_active,
test_issuer_defaulted_with_single_active, test_issue_with_retired_issuer_refused,
test_retired_issuer_still_serves_chain_and_crl,
test_create_intermediate_under_root, test_rotation_leaves_old_certs_valid,
test_crl_per_issuer_partitions_revocations (openssl crl, both directions),
test_retire_last_active_issuer_refused,
test_retire_root_retires_its_intermediates,
test_renew_in_place_keeps_key_and_id,
test_certs_issued_before_renewal_verify_against_renewed_ca (openssl, plus the
rekeyed counter-check), test_renew_in_place_without_key_errors,
test_create_intermediate_under_imported_root_errors,
test_capped_validity_reported_in_ui, test_capped_validity_in_api_response,
test_capped_validity_in_audit_detail, test_uncapped_issuance_reports_nothing,
test_leaf_has_aia_caissuers, test_ca_cer_endpoint_public_der,
test_cdp_and_aia_are_http_when_base_url_is_https,
test_https_base_url_port_443_dropped, test_old_crl_routes_are_gone,
test_crl_route_per_issuer, test_crl_route_404_for_root_and_unknown,
test_crl_lazy_regeneration_is_per_issuer, test_root_path_length_configurable,
test_root_path_length_bounds_rejected, test_ca_page_lists_hierarchies,
test_ca_actions_require_admin_and_csrf, test_issuer_select_hidden_when_single,
test_issuer_select_posts_stored_issuer, test_dashboard_warns_per_issuer,
test_dashboard_retired_issuer_only_flagged_when_expired,
test_audit_ca_renewed_and_retired, test_api_ca_lists_issuers,
test_mcp_ca_info_matches_rest, test_schema_has_no_singleton_constraints

Two more, missing from the list above and from every suite written so far.
Both would let a wrong implementation pass everything else in this document,
so they are named here rather than left to be noticed:

- **`test_issuance_entry_points_use_the_forced_http_origin`** — the
  highest-value missing test in this spec. Every existing FR-12 test either
  calls `public_http_origin` directly or hands a pre-built URL to
  `issue_certificate`. Nothing checks that the real issuance entry points —
  `web/certs_ui.py`, `api/v1.py`, `acme/api_finalize.py` and `mcp/server.py`,
  FR-6's seven call sites between them — actually route production traffic
  through the helper. An implementation that gets the helper exactly right
  and forgets to wire one door to it ships `https://` CDP and AIA URLs into
  real certificates and passes every test in this document. The test issues
  through each of the four modules with an `https://` base URL configured and
  parses the CDP and AIA off the resulting certificate; asserting on the
  helper's return value does not satisfy it.
- **`test_no_aia_on_root_and_intermediate_certificates`** — FR-11 specifies
  AIA for leaves only, and the Out of Scope section says so again, but
  nothing asserts it. A root or intermediate carrying a `caIssuers` pointer
  is the kind of extension that is added once "for symmetry" and then never
  questioned. Assert the extension's **absence** on a generated root, on its
  intermediate, and on an intermediate from `create_intermediate_under`.

The 0005–0013 issuance and revocation tests carry the rest and are expected
to keep passing on the FR-6 default rule; where they assert `{root,
intermediate}` REST shapes or the `/crl` path they are updated, not deleted.

## Out of Scope

**Backwards compatibility with a 0.1.x database.** Migrations 0003, 0004 and
0005 are rewritten in place rather than superseded, which means a database
stamped at revision 0009 by an older cabin will report itself up to date and
keep the old schema. There is no upgrade path and no migration to write one;
the fix is an empty `/data`. Stated here so it cannot later be read as an
oversight.

Per-issuer permissions (spec 0018) — in 0017 any admin may use any active
issuer. A per-issuer ACME directory (0019) — ACME keeps using the FR-6
default rule, which means a two-issuer instance cannot yet be driven by ACME
without ambiguity, and that is the gap 0019 closes. Name constraints (0020).
Cross-signing (0021) — `path_length` becomes configurable here, but nothing
consumes the extra room yet. HTTPS for cabin itself (0022), including the
plaintext listener that FR-12's `http://` rule will eventually need.

Also out: OCSP and HSM/KMS (decided against, see the plan). Hierarchies
deeper than root → intermediate → leaf: `path_length` is selectable, the
third CA level is not built. Visibility filtering of the inventory — every
logged-in user still sees every certificate from every hierarchy. Moving a
leaf between issuers, or re-issuing one under a different issuer. An AIA
extension on intermediates (only leaves get one; the intermediate is what the
AIA URL serves). Automatic renewal of anything, CA or leaf — `renew_in_place`
is an operator action, and the CRL's lazy refresh remains cabin's only
scheduler. Adding 0015/0016 to `spec/README.md:8-23`, where they are still
missing.
