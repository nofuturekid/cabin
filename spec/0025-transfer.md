# Spec 0025 — Transfer

## Context

Everything that moves material into cabin or out of it is currently
either hidden in the CA group or missing. `/ca/import` carries two
unrelated import forms on one page (`ca_import.html:17-74`) and sits in
the rail group about hierarchies, next to `Create`, as if importing a CA
were a variant of creating one. There is no export at all: an operator
who wants the roots this instance vouches for, or the inventory as a
file, or the key of a CA cabin generated, has no page to go to.

This spec gives that its own rail group with five pages — two imports
that move here, and three exports that do not exist yet.

**The three exports are not equally risky, and the difference is the
whole substance of this spec.**

A **trust bundle** is a concatenation of certificates cabin already
serves one at a time at `/ca/{ca_id}.pem` (`ca_ui.py:909-919`), open to
any logged-in user. Nothing in it is secret.

The **inventory export** is the same rows `/certs` already renders to
every logged-in user (`certs_ui.py:280-319`), in a file instead of a
table. `spec/0006-inventory-download.md:92` put "bulk export" out of
scope for that spec; this is that decision being reversed on purpose,
not a question nobody had asked. Nothing in it is secret either — it
carries no key material and no PEM, only the columns the inventory
already shows.

**The CA key export crosses a line cabin has never crossed.** cabin
hands out leaf private keys today: `/certs/{id}/download/key.pem` and
`/certs/{id}/download/bundle.p12`, both admin+
(`certs_download_ui.py:150-206`). It has never handed out a **CA** key;
the only ingress for one is `POST /ca/import`, and every path that uses
one — issuing, renewing, cross-signing — unseals it, uses it and drops
it inside one request (`ca/service.py:183-188`).

Whoever receives that file can issue as that CA, for as long as the CA
certificate is valid, and cabin will not see any of it. That is the part
that makes it different in kind rather than in degree from a leaf key:
a leaf key gives its holder one certificate cabin issued, knows about
and can revoke; a CA key gives its holder an unbounded supply of
certificates cabin never learns of. cabin's CRL covers what cabin
issued (`ca/crl.py`), so the only remedy left afterwards is retiring or
distrusting the whole hierarchy — which invalidates every certificate
under it, not the ones the key holder made.

Four things follow from that, and they are requirements below rather
than comments in the route:

- **Superadmin, not admin** (FR-6). Spec 0018's per-issuer grants govern
  issuing and revoking with an issuer; handing over its signing key is
  strictly more powerful than either, and unlike a grant it cannot be
  withdrawn.
- **A password** (FR-7), on the pattern the leaf PKCS#12 export already
  sets (`certs_download_ui.py:165-206`).
- **An audit event** (FR-8). `spec/0009-audit.md:96-103` deliberately
  writes none for a leaf key download and defers the question to its own
  spec. That is defensible for a leaf; for a CA key it is not, and the
  deviation is named rather than made quietly.
- **Nothing in plaintext on disk** (FR-10). `spec/0022-https.md` AC-19
  has a watcher poll the TLS directory while a renewal runs and requires
  that no loadable plaintext key is ever visible in it. An export that
  wrote a file and then served it would undercut that; the bundle is
  built in memory and streamed, as `bundle.p12` already is.

Two smaller things this spec has to get right.

**The rail grows from twelve entries to sixteen.** Spec 0023 added a
second `nav-group` and the rail outgrew a short viewport, breaking the
guarantee that the logout button — the only way out of a page — stays
reachable; the fix was to let the nav list scroll inside the rail
(`cabin.css:143-152`). Sixteen entries is well past where that was last
measured, and there is an existing headless-Chrome test for exactly this
(`test_web_layout.py:486-511`, probing at 1440×700). It is measured
again at this size rather than assumed to still hold.

**Per-certificate downloads do not move.** `/certs/{id}/download/…`
belongs to its certificate, and `cert_detail.html:41-55` has had a
section for it since spec 0006. "All import and export in one place" is
an invitation to drag those four routes in here, and doing so would mean
a certificate detail page that sends an operator somewhere else to fetch
its own files. FR-14 says so explicitly so that it reads as a decision.

## User Stories

- As an operator, everything that moves material in or out of cabin is
  under one heading in the rail, and each of those five things is its own
  page rather than a form sharing a page with an unrelated one.
- As an operator setting up a client, I download one file containing
  every root this instance vouches for, and I do not have to visit each
  hierarchy and copy its PEM out by hand.
- As an operator asked what certificates exist, I export the inventory as
  CSV or JSON — the whole filtered set, not the page I happen to be
  looking at.
- As a superadmin moving a CA to another system, I export its certificate
  and private key as one password-protected PKCS#12 file, and I am told
  in the page itself what handing that file over means.
- As a superadmin, the CA key page does not offer me rows whose key this
  instance does not hold, so I never pick something that can only fail.
- As an admin who is not a superadmin, I can import a CA and I cannot
  export a CA key, and the rail does not offer me the page that would
  refuse me.
- As an operator on a short screen, the rail still ends in a logout
  button I can reach, with sixteen entries in it.

## Functional Requirements

- FR-1: **A rail group of five pages.**

  | Page                         | Contents                                             | Guard          |
  | ---------------------------- | ---------------------------------------------------- | -------------- |
  | `GET /transfer/ca-import`    | Import an existing CA: certificate, key, chain       | admin          |
  | `GET /transfer/cross-import` | Import a cross certificate produced elsewhere        | admin          |
  | `GET /transfer/trust-bundle` | The roots this instance vouches for, as one PEM file | logged in      |
  | `GET /transfer/ca-key`       | One CA's certificate and private key as PKCS#12      | **superadmin** |
  | `GET /transfer/inventory`    | The certificate inventory as CSV or JSON             | logged in      |

  Templates: `transfer_ca_import.html`, `transfer_cross_import.html`,
  `transfer_trust_bundle.html`, `transfer_ca_key.html` and
  `transfer_inventory.html`. `ca_import.html` is deleted (FR-2). Each
  sets exactly one `nav_current`, as 0015 FR-2 requires and
  `test_web_layout.py:56-64` already checks for every content template.

  All five live in a new module `cabin.web.transfer_ui`, with the two
  import POSTs (FR-2), so that each page and the POST whose errors
  re-render it stay in one module — the rule 0023 applied to pages,
  applied to modules.

- FR-2: **`/ca/import` becomes two pages, and both POST paths stay.**
  `ca_import.html`'s two `.section` blocks become two templates, one per
  rail entry. `GET /ca/import` (`ca_ui.py:466-468`) and `_import_page`
  (`ca_ui.py:437-442`) are removed with it.

  `POST /ca/import` and `POST /ca/cross-import` keep their paths,
  methods, form fields, guards and CSRF rule exactly. That is the
  difference between a cheap reorganisation and an expensive one — 0023
  FR-7 made the same call for the same reason, and roughly ninety tests
  reach these two paths. Their handlers move from `ca_ui.py:575-619` and
  `ca_ui.py:778-821` into `transfer_ui`, unchanged apart from which page
  they re-render:

  | POST               | Error re-renders         | Success redirects to |
  | ------------------ | ------------------------ | -------------------- |
  | `/ca/import`       | `/transfer/ca-import`    | `/ca`                |
  | `/ca/cross-import` | `/transfer/cross-import` | `/ca`                |

  Both keep redirecting to `/ca` on success, for 0023 FR-7's reason:
  what they produce is a new entry on that list.

  **`GET /ca/import` gets no redirect to its successor.** It answers 405
  afterwards, because `POST /ca/import` still lives at that path. That is
  acceptable here and would not be in general: the GET was introduced by
  spec 0023, on this branch, and has never appeared in a release — there
  is no bookmark anywhere that this breaks.

- FR-3: **The rail: one new group, one new nav flag, twelve entries to
  sixteen.**
  - A group `Transfer` sits after `Certificates` and before `Access`
    (`layout.html:19-34`), because it moves both CA material and
    certificate material and can only be read after both.
  - `Import` (`/ca/import`) leaves the `Certificate authority` group,
    which keeps `Hierarchies` and `Create`. Twelve entries minus that one
    plus five is sixteen.
  - Labels, in group order: `Import a CA`, `Import a cross certificate`,
    `Trust bundle`, `CA key`, `Inventory export`. The last is not called
    `Inventory`: that label is already in the rail for `/certs`, and two
    entries with one label is a rail nobody can read.
  - `base_context` (`deps.py:62-71`) gains a sixth nav flag, `ca_key`,
    `role == Role.superadmin`, gating the `CA key` entry. It is
    deliberately not `tokens`, for the reason 0023 FR-6 gave when it
    refused to reuse `issue` for `ca_admin`: exporting a CA key and
    managing API tokens are different privileges that happen to have the
    same holder today, and the day one of them stops being superadmin-only
    the flag that has to change must already exist. The two import
    entries reuse `ca_admin` — they are the same privilege as before,
    only shown in a different group. Like every other `nav.*` flag it is
    cosmetic; each route keeps its own dependency.
  - `nav_current` values: `transfer_ca_import`, `transfer_cross_import`,
    `trust_bundle`, `ca_key`, `inventory_export`.

- FR-4: **The trust bundle.** `GET /transfer/trust-bundle` lists every
  `kind == "root"` row with its name, status and how many intermediates
  it carries, and links the files. Two files, one route:
  - `GET /transfer/trust-bundle.pem` — every **active** root's
    `cert_pem`, concatenated in `list_cas` order
    (`ca/service.py:204-215`), filename `cabin-trust-bundle.pem`.
  - `GET /transfer/trust-bundle.pem?ca={root_id}` — one hierarchy: that
    root plus its active intermediates, in id order, filename
    `{slug(root.name)}-{root_id}-trust-bundle.pem`. A `ca` that names no
    row, or names a row whose `kind` is not `root`, is a 404 with the
    wording `ca_detail` already uses (`ca_ui.py:492-495`) — a hierarchy
    is named by its root.

  **`kind == "cross"` rows are in neither file.** A cross certificate is
  path material, not an anchor: it carries the same subject and public
  key as the root it duplicates (spec 0021 FR-1), so trusting it adds
  nothing that trusting that root does not already give, and `chains_for`
  already serves it in the chain where it belongs
  (`ca/service.py:248-299`). An operator who wants one has it at
  `/ca/{ca_id}.pem`.

  Media type `application/x-pem-file`, the same the existing PEM routes
  serve (`ca_ui.py:919`). Guard: any logged-in user, including a viewer —
  this is the same material `/ca/{ca_id}.pem` already serves under the
  same guard, in bulk. **An imported root is fully present here**: the
  bundle needs certificates only, and `key_sealed` being NULL
  (`ca/service.py:511-517`) makes no difference to it. That is the one
  export where the FR-9 exclusions do not apply, and it is worth stating
  because the CA key page's row list looks superficially similar.

- FR-5: **The inventory export, and the reversal it is.**
  `spec/0006-inventory-download.md:92` lists "bulk export" as out of
  scope. This spec puts it back in, deliberately: the reason it was
  excluded was scope, not risk, and the rows involved carry no key
  material — `certificate_fields` (`api/views.py:77-96`) is already what
  `GET /api/v1/certs` returns to any token holder.

  `GET /transfer/inventory` carries the same two filter controls `/certs`
  has — `q` and `status` (`certs_ui.py:281-300`) — the number of rows the
  current filter selects, and two links carrying those filters:
  - `GET /transfer/inventory.csv` — `text/csv; charset=utf-8`, filename
    `cabin-inventory.csv`, written with the standard library's
    `csv.writer` into an in-memory buffer.
  - `GET /transfer/inventory.json` — `application/json`, filename
    `cabin-inventory.json`, an object with `generated_at`, `filter`
    (`q` and `status` as applied), `total`, and `items`.

  **The whole filtered set, not one page.** `list_certificates`
  (`ca/certs.py:438-473`) is paginated and clamps `page` to `MAX_PAGE`;
  an export that passed a large `per_page` would be a lie about what it
  returns. `ca/certs.py` gains `export_certificates` — signature in the
  Interface Contract below — returning every matching row in the same
  order, built from the same `_filters` (`ca/certs.py:404-436`) so the
  export and the list can never disagree about what a filter means.

  **The columns are the API's field names, not a third description of a
  certificate.** Both files carry exactly the keys of
  `certificate_fields` (`api/views.py:84-96`), in that order: `id`,
  `serial_hex`, `subject_cn`, `sans`, `profile`, `not_before`,
  `not_after`, `status`, `has_key`, `revoked_at`, `revocation_reason`.
  Datetimes are rendered `astimezone(UTC).replace(microsecond=0).isoformat()`,
  the shape `ca_ui.py:771` already writes into an audit detail. In CSV,
  `sans` is the list joined with a single space, `has_key` is `true` or
  `false`, and an absent `revoked_at`/`revocation_reason` is an empty
  cell; in JSON they are a list, a boolean and `null`. Guard: any
  logged-in user, the guard `/certs` itself has.

- FR-6: **The CA key export is superadmin-only.** `GET /transfer/ca-key`
  and `POST /transfer/ca-key` both depend on `require_superadmin`
  (FR-13), not `require_admin`.

  The argument, because this is the one place in cabin where a guard is
  stricter than the surrounding ones and a later reader will want to know
  why: spec 0018 made issuing and revoking per-issuer permissions that a
  superadmin grants and can withdraw (`issuer_grants.py`). Handing over
  the signing key grants both, to whoever holds the file, permanently and
  invisibly — cabin's inventory and CRL only ever cover what cabin itself
  issued. A permission that cannot be withdrawn and whose use cannot be
  observed does not belong at the same level as the ones that can.

  The page renders **no form at all** for a user who is not a superadmin;
  the route refuses one with 403 regardless, since `nav.ca_key` is
  cosmetic.

- FR-7: **A password, on the pattern that already exists.**
  `POST /transfer/ca-key` takes `ca_id`, `password` and `csrf_token`.
  `password` is declared `Form("")` — an explicit default — and its
  length is checked in the handler, for the reason
  `certs_download_ui.py:174-179` records: `Form(...)` treats an empty
  submitted value as _missing_, which FastAPI answers with a 422 before
  any handler code runs, and a missing password must be the same clean
  400 as a too-short one. The minimum is `MIN_P12_PASSWORD`
  (`certs_download_ui.py:37`, 8) imported from there rather than
  redefined, and the encryption is the same
  `serialization.BestAvailableEncryption` the leaf bundle uses
  (`certs_download_ui.py:198`).

  The bundle carries the CA's own certificate as `cert`, its unsealed
  key, and as `cas` the rest of its default chain: everything
  `chain_for` (`ca/service.py:232-240`) returns after the row itself,
  which is nothing for a root and the root for an intermediate. The
  friendly name is the row's `name`.
  Filename `{slug(row.name)}-{row.id}.p12`; the id is in it because
  `name` is not unique (`ca/service.py:69-71`) and a renewal deliberately
  produces a second row with the same one.

- FR-8: **A CA key export is audited, and that is a deviation.**
  `AuditAction` (`audit.py:67-127`) gains `ca_key_exported`. The event is
  written after the bundle has been built and before the response is
  returned, with `target_type="ca_certificate"`, `target_id=ca_id`, and a
  detail naming the row's `kind`, its subject and its fingerprint. The
  password is not in the event, in the detail or in the summary — spec
  0004 FR-3's rule, the same one `ca_import` follows
  (`ca_ui.py:598-599`).

  `spec/0009-audit.md:96-103` states that reads are not audited and names
  `/certs/{id}/download/key.pem` and `bundle.p12` as the deliberate
  omission, deferring "who exported this key" to a later spec. **This
  spec deviates from that for CA keys only, and does not settle the
  deferred question for leaf keys.** The reason the omission held is that
  a leaf key download is a read a viewer's page refresh could trigger and
  that changes nothing; a CA key export is neither — it is a
  superadmin-only POST with CSRF that permanently changes what somebody
  outside cabin can do, which is exactly what FR-4 of 0009 covers. A
  refused export writes no event: nothing left the instance.

- FR-9: **What cannot be exported is not offered.** A row is exportable
  iff `key_sealed is not None`. The page builds its `<select>` from
  exportable rows only — the same shape `can_renew` and
  `can_create_intermediate` already have (`ca_ui.py:243-244`), an action
  that cannot succeed is not offered rather than offered and then
  refused. Excluded, and why:
  - **an imported root** — `import_hierarchy` stores it with
    `key_sealed=None` (`ca/service.py:511-517`), because the root's key
    was never supplied;
  - **the signing root of an imported cross certificate** —
    `import_cross` inserts it the same way (`ca/service.py:790-810`);
  - **every `kind == "cross"` row** — a cross certificate is a second
    certificate for a key cabin may or may not hold, and the row itself
    never carries one (`ca/service.py:726`, `:795`, `:807`).

  **An imported _intermediate_ is exportable**, and that is not an
  oversight: its key was uploaded through `POST /ca/import` and is sealed
  in the row (`ca/service.py:520-527`). The list distinguishes the two
  halves of an imported hierarchy rather than treating "imported" as a
  category.

  The page lists **every** CA row with its state — exportable, or "no
  private key on this instance" — so an operator who cannot find a row in
  the select is told why instead of wondering. With no exportable row at
  all the page renders no form and says so: a `<select>` with no options
  above a submit button is a form that can only produce a 400.

- FR-10: **Nothing is written to disk.** The PKCS#12 bundle, the trust
  bundle and both inventory files are built in memory and returned as the
  response body. No `tempfile`, no file under `DATA_DIR`, no path handed
  to `openssl`. `spec/0022-https.md` AC-19 requires that no loadable
  plaintext key is ever visible in cabin's own TLS directory, including
  to a watcher polling _during_ the operation; an export that wrote a
  `.p12` and served it afterwards would put a file containing a CA key on
  the same disk that requirement is about, and a failure between writing
  and unlinking would leave it there. `bundle.p12` already works this way
  (`certs_download_ui.py:186-206`) and this follows it.

- FR-11: **Every refusal of the key export has a shape, and none is a 500.** In this order, before the key is unsealed:

  | Condition                          | Answer                                  |
  | ---------------------------------- | --------------------------------------- |
  | not a superadmin                   | 403 (`require_superadmin`)              |
  | missing/short `password`           | 400, page re-rendered with the message  |
  | `ca_id` names no row               | 404, `UnknownIssuerError`'s own message |
  | that row has no `key_sealed`       | 400, page re-rendered with the message  |
  | the master key cannot unseal it    | 409                                     |
  | PKCS#12 cannot carry this key type | 400, page re-rendered with the message  |

  The 409 follows `certs_download_ui.py:97-108`, which already rules that
  a key that exists but cannot be decrypted is a state conflict and
  explicitly not a 500. Nothing on the CA side catches `SecretsError`
  today, so this is the first route that does; it is required here and
  nowhere else, since this spec does not touch renew or cross-sign. The
  last row is the `except (TypeError, ValueError)` guard
  `certs_download_ui.py:200-205` describes: every key type in
  `KEY_TYPES` (`ca/x509.py:35`) serializes today, Ed25519 included, and
  this is the guard for the day one does not.

- FR-12: **One download response shape, one filename shape.**
  `_attachment` (`certs_download_ui.py:62-72`) and `_slug`
  (`certs_download_ui.py:51-55`) lose their leading underscore and are
  imported by `transfer_ui`, exactly as `certs_download_ui` already
  imports `SERIAL_CHARS` from `certs_ui` (`certs_download_ui.py:25`).
  Copying either would mean two definitions of `Cache-Control: no-store`,
  and that is the header that matters on the one response in cabin that
  carries a CA key. Their bodies do not change; the four existing call
  sites are renamed with them.

- FR-13: **`require_superadmin` gets one definition.** It exists twice
  today — `ui.py:60` and `tokens_ui.py:35`, both
  `require_role(Role.superadmin)` — and a third copy in `transfer_ui`
  would be the point at which nobody can say where the superadmin guard
  lives. It moves to `deps.py`, next to `require_admin`
  (`deps.py:169-181`), and both existing modules import it from there;
  `deps.py:27-29` already states why guards and visibility checks are
  defined once. No behaviour changes anywhere.

- FR-14: **Per-certificate downloads stay on the certificate.** The four
  routes under `/certs/{id}/download/…` (`certs_download_ui.py:111`,
  `:123`, `:150`, `:165`) keep their paths, guards, methods and
  responses, and `cert_detail.html:41-55` keeps its `Downloads` section
  and its PKCS#12 form. None of the five transfer pages links to a
  per-certificate download. A file that belongs to one object is fetched
  from that object's page; the transfer area is for material that belongs
  to the instance, not to a row on it. This is written down because "all
  import and export in one place" invites the opposite, and the result
  would be a certificate page that cannot hand over its own key.

- FR-15: **Templates are edited by a script through Bash, never with
  Edit/Write**, and `git diff` is read after every template change: the
  PostToolUse formatter breaks Jinja tags apart, turning
  `{% if x == "y" %}` into `{% if x="" ="y" %}`. This has cost this
  project a debugging session three times (0021 FR-13, 0023 FR-11,
  0024 FR-10), and this spec writes five new templates.

## Interface Contract

### Routes

| Method | Path                         | Auth              | Change                                            |
| ------ | ---------------------------- | ----------------- | ------------------------------------------------- |
| GET    | `/transfer/ca-import`        | admin             | new — the CA import form                          |
| GET    | `/transfer/cross-import`     | admin             | new — the cross certificate import form           |
| GET    | `/transfer/trust-bundle`     | session           | new — the roots, and the download links           |
| GET    | `/transfer/trust-bundle.pem` | session           | new — `?ca=` narrows to one hierarchy             |
| GET    | `/transfer/ca-key`           | superadmin        | new — the export form                             |
| POST   | `/transfer/ca-key`           | superadmin + CSRF | new — returns the PKCS#12 bundle                  |
| GET    | `/transfer/inventory`        | session           | new — filters, count, download links              |
| GET    | `/transfer/inventory.csv`    | session           | new — `?q=`/`?status=` as on `/certs`             |
| GET    | `/transfer/inventory.json`   | session           | new — same rows, same fields                      |
| POST   | `/ca/import`                 | admin + CSRF      | unchanged; errors render `/transfer/ca-import`    |
| POST   | `/ca/cross-import`           | admin + CSRF      | unchanged; errors render `/transfer/cross-import` |
| GET    | `/ca/import`                 | —                 | **removed** (FR-2)                                |

No other route changes. `/certs/{id}/download/…`, `/ca/{ca_id}.pem`,
`/ca/{issuer_id}/chain.pem`, every `/api/v1` route and MCP are untouched.

`transfer_ui` declares two routers so that the paths above are exactly
what they say: `router = APIRouter(prefix="/transfer")` for the nine new
routes, and `ca_router = APIRouter(prefix="/ca")` for the two import
POSTs whose paths are pinned by their existing callers (FR-2). Both are
included in `app.py` after `ca_router` (`app.py:102-105`); nothing
shadows anything, because `/ca/import` and `/ca/cross-import` cannot
match `/ca/{ca_id:int}` (`ca_ui.py:471`).

### `cabin.web.transfer_ui`

```python
def _ca_key_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    status_code: int = 200,
) -> Response: ...


def _exportable(row: CACertificate) -> bool: ...


def _trust_bundle_rows(db: Session, root_id: int | None) -> list[CACertificate]: ...


def _inventory_rows(db: Session, q: str, status: str, now: datetime) -> list[Certificate]: ...
```

- `_ca_key_page` is the one renderer for `transfer_ca_key.html`, used by
  the GET and by every 400 the POST produces (FR-11), the shape
  `_detail_page` has in `ca_ui.py:405-428`.
- `_exportable` is `row.key_sealed is not None` and is the only place
  FR-9's rule is written; the row list and the `<select>` both use it.
- `_trust_bundle_rows` returns FR-4's set: with `root_id is None`, every
  active `kind == "root"` row; otherwise that root plus its active
  intermediates. Never a `kind == "cross"` row.
- `_inventory_rows` is a thin wrapper over `export_certificates` that
  applies `/certs`' own normalisation of `q` and `status`
  (`certs_ui.py:291-293`), so the export accepts an unknown `?status=`
  the same way the list does rather than erroring on it.

### `cabin.ca.certs`

```python
def export_certificates(
    db: Session, *, q: str = "", status: str = "all", now: datetime | None = None
) -> list[Certificate]: ...
```

Every row matching the filters, in `list_certificates`' order
(`created_at` descending, then `id` descending), unpaginated, built from
the same `_filters`. `list_certificates` is unchanged.

### `cabin.web.deps`

`require_superadmin` moves here (FR-13) and `base_context` returns a
sixth nav flag:

```python
"nav": {
    "issue": role in ADMIN_ROLES,
    "ca_admin": role in ADMIN_ROLES,
    "ca_key": role == Role.superadmin,
    "settings": role in ADMIN_ROLES,
    "acme": role in ADMIN_ROLES,
    "tokens": role == Role.superadmin,
},
```

### `cabin.web.certs_download_ui`

`_attachment` → `attachment`, `_slug` → `slug` (FR-12). Bodies, headers
and behaviour unchanged; `_filename` and the four routes are unchanged
apart from the renamed calls.

### `cabin.audit`

`AuditAction` gains `ca_key_exported`. `ACTION_FILTERS`
(`audit.py:130`) picks it up automatically, so the audit page's filter
dropdown and the enum stay in step, which is what that line is for.

### `cabin.web.ca_ui`

Loses `ca_import_page`, `ca_import`, `ca_cross_import` and
`_import_page` (FR-2). Everything else — the list, the detail page,
`/ca/new`, every other POST, both PEM routes — is unchanged.

### Schema, API, MCP, ACME

Unchanged. No migration, no column, no change to `api/`, `mcp/` or
`acme/`. The audit action is an enum value, not a schema change.

## Acceptance Criteria

Every criterion is anchored to the element it is about — the form with
that action, the row in the database, the parsed bundle — never to a
substring appearing somewhere in the page. This project has twice
shipped a UI test that passed while the feature was visibly broken, both
times because it searched for a string. Scoping is by parsed element or
by `_row(...)`, as `test_web_ca_pages.py` already does.

Where a state is meant to differ, both halves are in one criterion: a
build that refuses everybody and a build that refuses nobody must each
fail. That rule does the most work in AC-6, where a criterion asserting
only that a viewer is refused would be green against an implementation
that refuses the superadmin too.

The fixture, unless stated otherwise: hierarchy **alpha**, generated
(root `Alpha Root`, intermediate `Alpha Issuing`), hierarchy **beta**,
generated, one **imported** hierarchy, one cross certificate for alpha's
root signed by beta's, and at least one issued leaf.

- AC-1: **Five pages, five entries, sixteen in the rail.** For a
  superadmin, each of `/transfer/ca-import`, `/transfer/cross-import`,
  `/transfer/trust-bundle`, `/transfer/ca-key` and `/transfer/inventory`
  returns 200 and marks exactly one rail entry with `aria-current="page"`,
  and it is `Import a CA`, `Import a cross certificate`, `Trust bundle`,
  `CA key` and `Inventory export` respectively — collected the way
  `test_web_layout.py:258-280` collects them. In the same test the rail
  contains a `nav-group` labelled `Transfer`, the total number of `<a>`
  elements inside `<nav>` is **16**, and no entry has `href="/ca/import"`.
  _Goes red if_: a page is added without its entry, two entries are
  marked, or `Import` is left in the CA group as a thirteenth entry.

- AC-2: **Role gating, both directions, one test.** A viewer gets 200
  from `/transfer/trust-bundle` and `/transfer/inventory` and 403 from
  the other three; an admin gets 200 from all but `/transfer/ca-key`,
  which is 403; a superadmin gets 200 from all five. The viewer's rail
  contains `href="/transfer/trust-bundle"` and no `href="/transfer/ca-key"`;
  the admin's rail contains both import entries and no
  `href="/transfer/ca-key"`; the superadmin's contains all five hrefs.
  _Goes red if_: the CA key page is admin-only after all, or the two
  read-only exports are gated to admins and a viewer is locked out of
  material the viewer can already read one row at a time.

- AC-3: **The imports split, and their errors land on their own page.**
  Across every template, exactly one `<form>` has `action="/ca/import"`
  and exactly one has `action="/ca/cross-import"`, and they are in
  different templates. `ca_import.html` does not exist and no module
  refers to it. `POST /ca/import` with an unparseable `cert_pem` returns
  400 and the response marks `Import a CA`; `POST /ca/cross-import` with
  an unparseable `cross_pem` returns 400 and marks
  `Import a cross certificate`; `select count(*) from ca_certificates` is
  unchanged after both. A valid `POST /ca/import` returns 303 to `/ca`
  and adds two rows.
  _Goes red if_: the two forms end up on one page again, if an error
  re-renders the other page, or if the POST paths moved and every
  existing caller of them broke.

- AC-4: **The trust bundle is the anchors, and nothing else.**
  `GET /transfer/trust-bundle.pem` is parsed with
  `x509.load_pem_x509_certificates`: the result is exactly the active
  roots — alpha's, beta's and the imported hierarchy's root, compared as
  a set of fingerprints — it contains no intermediate and not the cross
  certificate, and the body contains no `PRIVATE KEY` header. Then
  `?ca={alpha_root}` parses to exactly alpha's root and alpha's
  intermediate, in that order, and `?ca={alpha_intermediate}` is a 404.
  Both responses carry `Content-Disposition: attachment` and
  `application/x-pem-file`.
  _Goes red if_: the whole-instance file also carries intermediates (an
  operator installing it would trust an issuer directly), if the imported
  root is skipped because it has no key, or if a cross row is included.

- AC-5: **The inventory export is the whole filtered set, and its fields
  are the API's.** With `PER_PAGE + 5` certificates issued
  (`ca/certs.py:33`), `GET /transfer/inventory.csv` has
  `PER_PAGE + 5 + 1` lines and its header row equals
  `list(certificate_fields(row, now))` — read from `api/views.py`, not
  copied into the test — and `GET /transfer/inventory.json` has the same
  number of `items` with the same keys. Then one certificate is revoked
  and `?status=revoked` returns exactly that one row in both formats,
  with its `revocation_reason` filled in CSV and non-`null` in JSON. The
  CSV response is `text/csv; charset=utf-8` with
  `Content-Disposition: attachment`.
  _Goes red if_: the export is built on `list_certificates` and stops at
  fifty rows — the count assertion is the only thing that catches it —
  or if the two files describe a certificate differently from
  `/api/v1/certs`.

- AC-6: **The CA key export works for a superadmin and is refused for
  everybody else, and the bundle is real.** One test, three halves.
  `POST /transfer/ca-key` with alpha's intermediate id and
  `password="correcthorse"` returns 200,
  `application/x-pkcs12`, `Content-Disposition: attachment` and
  `Cache-Control: no-store`. The body is loaded with
  `pkcs12.load_key_and_certificates(body, b"correcthorse")`: the
  certificate it yields equals alpha's intermediate `cert_pem`, the
  **private key's public key equals that certificate's public key**, and
  the additional certificates are exactly alpha's root. The same request
  as an admin is 403 and as a viewer is 403, and neither response is a
  PKCS#12 body.
  _Goes red if_: the export returns an empty or unopenable file, if it
  bundles a key that does not belong to the certificate beside it, if the
  chain is omitted, or if the guard refuses everyone — the first half is
  what catches that, and it is in this criterion for that reason.

- AC-7: **The password is required, checked, and enforced before
  anything is unsealed.** `POST /transfer/ca-key` with the `password`
  field entirely absent returns **400, not 422**; with a seven-character
  password it returns 400; both responses are the page carrying the
  `<form>` with action `/transfer/ca-key` and an error naming the
  minimum, neither is `application/x-pkcs12`, and no `ca_key_exported`
  event exists afterwards. With eight characters it returns 200 and a
  loadable bundle.
  _Goes red if_: `password` is declared `Form(...)` and FastAPI answers
  422 before the handler runs — which is exactly the defect
  `certs_download_ui.py:174-179` documents for the leaf bundle — or if
  the length check runs after the key has already been unsealed.

- AC-8: **What has no key is not offered, and what has one is.** On the
  full fixture, `GET /transfer/ca-key` renders a `<select>` named `ca_id`
  whose option values are exactly the ids of the rows with
  `key_sealed is not None`: alpha's root and intermediate, beta's root
  and intermediate, and **the imported hierarchy's intermediate**. It
  contains no option for the imported hierarchy's root, and none for the
  cross row. In the same test the page's row list does contain the
  imported root and the cross row, each marked as having no private key
  on this instance.
  _Goes red if_: "imported" is treated as a category and the imported
  intermediate — whose key was uploaded — is excluded with its root, or
  if the unexportable rows are dropped from the page entirely and an
  operator is left looking for a CA that is not there.

- AC-9: **The export is audited; a refusal is not.** After a successful
  `POST /transfer/ca-key`, exactly one `ca_key_exported` event exists,
  its `target_id` is the exported row's id, its detail names that row's
  subject and fingerprint, and neither its summary nor its detail
  contains the password string anywhere — asserted over the serialized
  detail, the way `test_web_audit.py`'s `test_no_secrets_in_details`
  already does. After a refused export (short password, and a row with no
  key) the count of `ca_key_exported` events is unchanged.
  _Goes red if_: the event is written before the bundle is built, so a
  refusal logs an export that never happened, or if the password reaches
  the log.

- AC-10: **Nothing touches the disk.** The set of files under `DATA_DIR`
  is captured before and after a successful `POST /transfer/ca-key` and
  is identical; and, while the request runs, a second thread polls
  `DATA_DIR` continuously and records every filename it sees — none of
  them is new. That is the shape `spec/0022-https.md` AC-19's third
  assertion uses, and it is here for the same reason: the before/after
  comparison alone would pass a write-serve-unlink implementation.
  _Goes red if_: the bundle is serialized through a temporary file, which
  the first assertion cannot see.

- AC-11: **Every refusal has its own status code.** In one test, all
  against `POST /transfer/ca-key` as a superadmin with a valid password:
  an id no row has returns 404; the imported hierarchy's **root** id
  returns 400 with the page and a message naming the missing key, and
  writes no event; a request made with a `SecretStore` that cannot unseal
  the row returns **409, not 500** (the rule
  `certs_download_ui.py:97-108` already sets). None of the three returns
  a body with media type `application/x-pkcs12`.
  _Goes red if_: an unexportable row reaches `signing_credentials` and
  becomes a 500, or a broken master key does.

- AC-12: **Per-certificate downloads did not move.** The four routes
  `/certs/{id}/download/cert.pem`, `chain.pem`, `key.pem` and
  `bundle.p12` answer exactly as before, with the same guards, and
  `cert_detail.html` still contains links to the first three and the
  `bundle.p12` form. Across the five `transfer_*.html` templates, no
  `href` or `action` matches `/certs/` followed by a number.
  _Goes red if_: the downloads are pulled into the transfer area, leaving
  the certificate page unable to hand over its own files.

- AC-13: **The rail still ends in a reachable logout button with sixteen
  entries.** `test_web_layout.py:486-511` re-run at 1440×700 with a page
  rendered for a **superadmin** — whose rail carries all sixteen entries
  and five group labels — asserts, as it does today, that the logout
  button's box is entirely inside the viewport after scrolling to the
  bottom. The probe additionally reports the rail's `<nav>`
  `scrollHeight` and `clientHeight`, and the test asserts
  `scrollHeight > clientHeight`: without it the criterion would pass
  vacuously on a viewport the rail happens to fit into, and it is
  `cabin.css:143-152`'s internal scroll that is actually under test. If a
  later layout makes the rail fit at 700, the height in the test is
  lowered until it does not, rather than the assertion being dropped.
  _Goes red if_: sixteen entries push the foot out of the viewport, which
  is the exact regression spec 0023 shipped once already.

- AC-14: **No page scrolls sideways.** 0015 AC-1 and AC-2 re-run with the
  five new pages added to the page dict at `test_web_layout.py:516-545`:
  at 1440×1150 and at 390×900, with the full fixture,
  `document.scrollingElement.scrollWidth` does not exceed `clientWidth`
  and no element's right edge extends past its container's. The CA key
  page's row list and the inventory page's filter row are the two new
  wide things on the page.

- AC-15: **Everything that was not this spec's subject still works.** The
  0004–0024 suite passes: `POST /ca/import` and `POST /ca/cross-import`
  keep their paths, fields, guards, CSRF rule, audit events and success
  redirects; `/ca`, `/ca/new` and `/ca/{ca_id}` render as before; the
  API, MCP, ACME, CRL and cabin's own TLS are untouched; and
  `require_superadmin` moving into `deps.py` changes no answer any
  `/users` or `/tokens` route gives. The only test changes are the ones
  the Test list names.

## Test list

New:

test_transfer_pages_mark_their_rail_entries,
test_rail_has_sixteen_entries_and_a_transfer_group,
test_transfer_guards_for_viewer_admin_and_superadmin,
test_import_forms_are_two_pages_and_errors_stay_on_them,
test_trust_bundle_is_active_roots_only,
test_trust_bundle_for_one_hierarchy,
test_inventory_export_covers_every_matching_row,
test_inventory_export_fields_match_the_api,
test_ca_key_export_roundtrips_and_is_superadmin_only,
test_ca_key_export_password_is_required_and_checked,
test_ca_key_select_offers_only_rows_with_a_key,
test_ca_key_export_is_audited_and_a_refusal_is_not,
test_ca_key_export_writes_nothing_to_disk,
test_ca_key_export_refusal_status_codes,
test_per_certificate_downloads_did_not_move,
test_rail_stays_in_view_with_sixteen_entries (headless Chrome),
test_no_horizontal_overflow (0015, five pages added)

Existing tests that change, each named because each is load-bearing:

- **`test_web_layout.py:258-280`** `test_nav_current_marked_once_per_page`
  maps `/ca/import` to `Import`. That URL is gone (FR-2); the map gains
  the five transfer paths and their labels.
- **`test_web_layout.py:282-311`** `test_nav_entries_still_role_gated`
  asserts a viewer's rail carries no `href="/ca/import"`. It asserts the
  new href instead, and gains `/transfer/ca-key` for the admin case —
  which is the first entry in this file's list that an _admin_ must not
  see either.
- **`test_web_layout.py:516-545`** `test_no_horizontal_overflow` gains
  the five pages (AC-14).
- **`test_web_layout.py:486-511`** `test_rail_stays_in_view_on_a_long_page`
  gains the nav-overflow assertion and a superadmin rail (AC-13).
- **`test_web_ca_pages.py`** — every test that GETs `/ca/import`, and
  0023 AC-4's assertion that an import error marks the `Import` entry.
  The POST halves do not move; only the page they land on does.
- **`test_web_name_constraints.py:543`** asserts the import form carries
  no name-constraint field, on `ca_import.html`. It asserts it on
  `transfer_ca_import.html`; 0020 FR-9's reason is unchanged.
- **`test_web_audit.py`** — `ACTION_FILTERS` grows by one value, which
  the filter-dropdown test reads off the enum rather than a literal list;
  `test_no_secrets_in_details` gains the new event (AC-9).
- **`tests/test_web_downloads.py`** (or wherever `_attachment`/`_slug`
  are referenced by name) — the two renames of FR-12.

## Out of Scope

**Leaf key downloads stay unaudited.** FR-8 deviates from
`spec/0009-audit.md:96-103` for CA keys only. Whether
`/certs/{id}/download/key.pem` and `bundle.p12` should write a
`cert_key_exported` event is the question 0009 deferred, and it stays
deferred: it is a decision about what the log means for reads in
general, and settling it as a side effect of a CA key export would be
the wrong way round.

**Retired roots are not in the trust bundle.** FR-4 takes active roots
only, and that has a cost worth recording: retiring a CA means it stops
issuing (spec 0017 FR-4), not that it is distrusted, so leaves it issued
stay valid until they expire and a relying party still needs its anchor.
An operator in that position fetches `/ca/{ca_id}.pem`, which is
unchanged. Whether the bundle should carry retired roots — or carry them
in a second file — is a real question and is left to whoever hits it.

**CSV formula escaping.** A cell whose first character is `=`, `+`, `-`
or `@` is executed as a formula by some spreadsheet applications, and
`subject_cn` is the one free-form column in the export. FR-5 requires
correct RFC 4180 quoting through `csv.writer` and no more: prefixing
those cells would change the exported data for every consumer that is
not a spreadsheet. It is named here so that it is a known gap rather
than an oversight.

**No link from `/certs` to the inventory export.** The rail entry is the
way there. A second entry point is a page change measured by no
criterion here.

**No export of an inventory row's certificate or key in bulk.** The
inventory export carries the columns the list shows and no PEM. A bulk
key export would be the leaf-key equivalent of FR-6 and would need its
own argument about who may do it; it is not made here by omission.

**No new key material, no new format.** No PEM-with-passphrase variant
of the CA key export, no JKS, no bundle of several CAs at once. One
CA, one file, one password.

No change to permissions beyond FR-6's new superadmin route, no schema
change, no migration, no new layout primitive. No version bump: 0.2.0
and PR #17 stay as they are.
