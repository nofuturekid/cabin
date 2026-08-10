# Spec 0024 — CA Names, Separate Creation, Action Layout

## Context

Spec 0023 split `/ca` into four pages. An operator clicked through the
result and named three things, and looking at the screenshots found two
more.

**Names get a suffix appended to them.** `create_hierarchy` and
`create_intermediate_under` build the subject from the operator's label:
`ca/service.py:401, 406, 416, 425, 533, 542` all interpolate
`f"{name} Root CA"` or `f"{name} Intermediate CA"`. Typing `Acme Root CA`
produces `CN=Acme Root CA Root CA`. Nothing should ever be appended to a
name an operator types.

**A root automatically gets an intermediate.** `POST /ca/create` always
writes two rows. An operator who wants a root now, and will decide about
issuers later, cannot say so; an operator who wants two intermediates
under one root creates one he did not ask for and then adds his own.

**The two actions on the detail page are hard to find.** `Add intermediate`
and `Cross-sign with another root` are `<summary>` lines of `<details>`
elements (`ca_detail.html:22, 23`). `<details>` is used **nowhere else in
this project** — every other form in cabin stands open in its own
`.section` with a heading and `.help` in the left column and fields in the
right: `cert_detail.html`, `users.html`, `tokens.html`, `acme.html`,
`ca_new.html`, `settings.html`. The disclosure was invented in 0023 to
keep two actions from crowding a page that also carried a list; the page
no longer carries a list.

**The most dangerous action is the loudest thing on the page.** Retire is
a red button next to Renew, in the same `<form>`, with no confirmation
(`ca_detail.html:21, 31, 49`) — and it repeats once per row, so a
hierarchy with one intermediate and one cross certificate shows three of
them stacked. `cert_detail.html:80-106` already has this project's pattern
for a dangerous action: its own section, a `.help` line naming the
consequence, a confirmation checkbox, then the button — and
`certs_ui.py:515, 527` refuses the POST without the checkbox rather than
assuming it.

**The intermediate rows leave the left grid column empty.** The whole
hierarchy sits inside one `.section` (`ca_detail.html:16-55`) whose right
column holds everything; every `.ca-row` is therefore rendered against an
empty half-width column.

### Why 0017's naming rule is being reversed

`spec/0017-multi-ca.md:274-285` wrote the rule down deliberately, and it
has two halves:

- `ca_certificates.name` is always the subject CN of that row's own
  `cert_pem`, so `/ca` can never show a name that disagrees with the
  certificate a relying party is handed. **This half stands** and is not
  touched here.
- For a hierarchy cabin generates, cabin _composes_ the subject from the
  operator's label. **This half is dropped.** It was a convenience for
  cabin, not for the operator: it guarantees a well-formed CN by refusing
  to let anybody name their own CA, and it produces the doubled-suffix
  subject above the moment somebody types what they actually want the
  certificate to say. `import_hierarchy` already takes the CN verbatim
  (`_subject_name`, `service.py:168-181`), so today's two write paths
  disagree; after this spec they do not.

The reversal is cheap because `name` is a display label and nothing else.
It is never parsed, compared or used as a key. Identity runs on subject
DER plus public key (`_same_ca`, `service.py:553-571`), whose own
docstring dismisses the CN as "a string that isn't unique and that cabin
itself generates from an operator's label" — an argument for this change
written a spec before it.

**What that makes mandatory: a name check, which does not exist anywhere
today.** Neither the route nor the service layer validates `name`.
`Form(...)` requires presence, not non-emptiness. Today `name=""` becomes
`" Root CA"` — a certificate whose subject starts with a space — and is
accepted. Without the suffix the CN would be empty, `x509.NameAttribute`
raises `ValueError`, and `POST /ca/create` has no handler for it, so the
operator gets a 500 instead of a form error. On
`POST /ca/{root_id}/intermediate` the same `ValueError` _is_ caught
(`ca_ui.py:649`) and would be rendered as a form error reading
`Attribute's length must be >= 1 and <= 64, but it was 0` — not a 500, but
cryptography's sentence rather than cabin's. This spec adds the check that
removes both outcomes.

**Separating root creation from intermediate creation turns a rare state
into the normal one.** "A CA exists but has no active issuer" is reachable
today — `import_cross` writes a bare root (`service.py:710-718`), and
retiring one hierarchy's intermediate leaves that hierarchy without one —
but it is unusual enough that four places describe it wrongly, all with
the same sentence. After this spec it is the state of every instance
between creating a root and adding its first intermediate, which is to say
the state of every fresh instance.

### The suffix was not merely cosmetic

Dropping `" Root CA"`/`" Intermediate CA"` (FR-1) has a second consequence
the User Stories above don't name: nothing stops an operator from typing
the same label for a root and the intermediate created under it, and both
are built as a single-CN subject the same way
(`ca/x509.py:create_root`/`create_intermediate`), so that types a root and
its own intermediate into carrying an **identical subject DN**:

```
root          subject=CN=Smuggle    issuer=CN=Smuggle
intermediate  subject=CN=Smuggle    issuer=CN=Smuggle
```

Two tests that passed before this suffix came off went red, and both are
real, not fixture artefacts: `tests/test_cross_signing.py`'s
`test_smuggled_cross_certificate_fails_path_length_in_openssl` — which
builds a cross certificate whose path length lets it smuggle in an
out-of-subtree subtree, and relies on `openssl verify` refusing it — now
finds `openssl verify` **accepting** the chain, because with the root and
its intermediate sharing one subject DN, OpenSSL's path builder resolves
the issuer for the smuggled certificate to the wrong one of the two
identically-named certificates. `tests/test_name_constraints_doors.py`'s
`test_openssl_rejects_a_smuggled_name` degrades the same way: it expects
OpenSSL error 47 (`X509_V_ERR_PERMITTED_VIOLATION`, the name-constraint
refusal being tested) and gets error 7 (a signature failure) instead, for
the same reason — the wrong certificate was picked while building the
path. In both cases this is exactly the failure mode a real relying party's
validator would hit, not a fixture that happened to collide: an operator
who names a root and its intermediate the same thing has built a hierarchy
that degrades path validation for everyone who trusts it. FR-13 below
closes it.

## User Stories

- As an operator, the CA I create is called what I typed. If I type
  `Acme Root CA`, the certificate says `CN=Acme Root CA`, and if I type
  nothing I get told so on the form instead of a 500 or a CA whose name
  begins with a space.
- As an operator, creating a root creates a root. Whether it gets one
  intermediate, three, or none for now is a separate decision I make on
  the hierarchy's own page.
- As an operator who has just created a root, the dashboard and the issue
  form tell me that this hierarchy has no issuer yet and where to add one,
  rather than telling me to create a CA I am plainly looking at.
- As an operator on a hierarchy page, every action is a heading I can see
  without opening anything, and the page reads down the left column like
  every other page in cabin.
- As an operator, retiring a CA takes the same deliberate two steps that
  revoking a certificate already does, and does not sit under my cursor as
  the reddest thing on the page.

## Functional Requirements

- FR-1: **A name is stored and signed exactly as it was typed.** The six
  interpolations at `ca/service.py:401, 406, 416, 425, 533, 542` are
  removed. `create_root` (FR-6) passes `name` to
  `ca_x509.create_root(subject_cn=...)` and stores the same string in
  `name`; `create_intermediate_under` does the same through
  `ca_x509.create_intermediate`. The 0017 invariant that `name` equals the
  CN of that row's own certificate holds on every write path, generated
  and imported alike.

- FR-2: **The name check.** A new `_name_error(name) -> str | None` in
  `web/ca_ui.py`, next to `_key_type_error` and `_year_bounds_error`, is
  applied by `POST /ca/create` and `POST /ca/{root_id}/intermediate`
  before anything is written, and its message is rendered by the form the
  request came from — `/ca/new` for the first, the detail page for the
  second, both at 400, with the submitted values kept (FR-8 of 0023).

  The rule, in order: strip leading and trailing whitespace; refuse an
  empty result; refuse a result whose UTF-8 encoding exceeds **64 bytes**.
  The stripped value is what is signed and stored.

  Sixty-four **bytes**, not characters: `x509.NameAttribute` measures the
  encoded value, so 64 U+00E4 characters are 128 bytes and are refused
  (cryptography 49.0.0, `Attribute's length must be >= 1 and <= 64`). The
  bound is not cabin's policy — it is what `NameOID.COMMON_NAME` enforces,
  and a name that passes it always fits `ca_certificates.name`'s
  `sa.String(64)` (`service.py:71`), which counts characters.

  The check lives at the route and not in `ca/service.py`, following the
  precedent `path_length` set: "this layer does not bound it, the create
  form does" (`service.py:382-389`). A service-level caller that passes an
  unusable name still gets cryptography's `ValueError`, in the same way one
  that passes `path_length=99` gets a certificate nobody wanted.

- FR-3: **`POST /ca/create` creates a root and nothing else.** One row,
  `kind="root"`, and a redirect to `/ca` as before.

  `/ca/new` therefore loses every field that only ever described the
  intermediate: `intermediate_years`, `permitted_names` and
  `excluded_names`. Name constraints apply to the intermediate only and
  never to a root — `create_hierarchy`'s docstring says why
  (`service.py:391-398`): a root does not sign leaves in cabin, so a
  constraint on it would only ever be evaluated by somebody else's
  validator. Those three fields already exist, unchanged, on the detail
  page's `Add intermediate` form; this spec does not add a field
  anywhere. `_years_error` (`ca_ui.py:99-108`) collapses to the single
  bound check on `root_years`, and the two-argument comparison it existed
  for goes with the second field.

  The `path_length` field and its hint stay on `/ca/new`: it is a property
  of the root and cannot be changed later.

- FR-4: **`ca_created` for a root names the root.** The audit event
  written by `POST /ca/create` (`ca_ui.py:510-529`) gets
  `target_id = root.id` and a `subject` read off the root's own
  certificate; its detail loses `intermediate_years`, `permitted`,
  `excluded` and `granted_to`, and keeps `name`, `key_type`, `root_years`,
  `path_length` and `subject`. `_subject` (`ca_ui.py:123-126`) takes the
  row whose subject is meant rather than a `CAHierarchy`.

- FR-5: **The grant follows the intermediate, and so does the TLS hook.**
  Two behaviours currently hang off `POST /ca/create` because that is
  where an intermediate used to appear. Both move to
  `POST /ca/{root_id}/intermediate`, which is where one appears now.
  - Spec 0018 FR-8 grants the creator the new **intermediate**
    (`ca_ui.py:504`). A root-only create has no intermediate, so it writes
    no `user_issuers` row. The rule is unchanged; it keeps exactly one
    call site on this path, the one that already exists at
    `ca_ui.py:662`.
  - Spec 0022 FR-6 calls `tls_manager.ensure_current` after a create so
    the swap away from the self-signed certificate can happen immediately
    (`ca_ui.py:536-538`). After a root-only create it cannot:
    `resolve_tls_issuer` looks for active intermediates and returns `None`
    (`tls.py:220-226`), so the instance keeps its self-signed certificate
    until an intermediate exists. Without moving the hook, a fresh
    instance would serve a self-signed certificate for up to an hour after
    its CA is complete, with nothing on screen explaining the delay. The
    call moves to `ca_create_intermediate`, after the audit record and
    before the redirect, with the same rule 0022 wrote for it: a failure
    is logged and audited by `ensure_current` itself and never turned into
    a 5xx. `POST /ca/import` keeps its own hook — an import still produces
    an intermediate.

- FR-6: **`create_hierarchy` survives, as an honest composition.**

  `create_root` is the root half of today's function, extracted; the new
  `create_hierarchy` is `create_root` followed by
  `create_intermediate_under`, and returns the same `CAHierarchy` it does
  today. It takes **two** names instead of one prefix, because there is no
  longer a rule by which one name could produce two subjects. Both
  signatures are pinned in the Interface Contract below.

  **It survives deliberately, and this is the sentence that says so, so
  that nobody later removes it as dead weight.** It has no production
  caller after FR-3 — `web/ca_ui.py` is the only one today
  (`ca_ui.py:491`) and it will call `create_root`. It has 194 call sites
  across 32 test files, counting `ca_fixtures.make_hierarchy`, which is
  the same composition written a second time. Keeping it as a composition
  is what confines this spec's test cost to the ten HTTP helpers of FR-11
  plus the name-reading assertions, instead of spreading it over every
  suite that needs a signing CA to exist. A test helper that builds a
  fixture is a legitimate caller; a function used only by tests is not
  automatically dead.

- FR-7: **"There is no CA" and "there is a CA with no issuer" stop being
  the same sentence.** Four places conflate them, all reachable the moment
  a root exists on its own.
  - `certs_ui.py:81`: `_NO_CA` reads "no CA yet: create or import one under
    CA before issuing certificates". `_no_issuer_message`
    (`certs_ui.py:119-123`) picks it whenever `active_issuers` is empty,
    which is now the normal state right after a create. It gains a
    `list_cas` branch: with no row at all it keeps today's sentence and
    points at `/ca/new`; with rows but no active issuer it says the
    hierarchy has no issuer and points at that root's own detail page,
    `/ca/{root_id}`, where the action to fix it lives. The distinction
    reaches the three `except CANotConfiguredError` handlers at
    `certs_ui.py:356, 419, 540`, which use the constant directly today
    and go through the chooser instead.
  - `resolve_issuer` (`service.py:335-340`) raises "no CA hierarchy has
    been created or imported yet". Its comment justifies the wording by
    arguing that `retire` cannot produce this state — which is true only
    instance-wide, was already imprecise for a single hierarchy, and is
    now wrong outright. Both the message and the comment change.
  - `issuer_grants.py:252` raises the **same sentence** from
    `resolve_granted_issuer`, and that is the path the API, MCP and ACME
    finalize actually take. It is not mentioned in the plan this spec
    comes from and is easy to miss because it duplicates the string rather
    than importing it. Both raises take their message from one place in
    `ca/service.py`, so the two cannot drift again.
  - Dashboard: `ca_configured` is `bool(rows)` (`ui.py:320`), which is
    `True` for a lone root, so the page renders its full body including a
    `Revocation` section whose `crls` list is empty
    (`ui.py:353-355`, `dashboard.html:122-150`) — a heading, an
    explanation, and nothing. The context gains a second flag for "an
    active issuer exists"; the dashboard renders an element saying this
    hierarchy has no issuer yet, linking to its detail page, and the
    revocation section renders its issuer tables only when there is at
    least one.

- FR-8: **Every action on the detail page is a section.** `<details>` and
  `<summary>` leave `ca_detail.html`. Each action becomes a `.section`
  with an `<h2>` and a `.help` line in the left column and its form in the
  right, the shape `cert_detail.html:41-106` and `ca_new.html:17-64`
  already use.

  Each row of the hierarchy becomes a `.section` too — the root, each
  intermediate, each cross certificate — with the row's name and tags as
  its heading. That is what fills the left column that `.ca-row` leaves
  empty, and it is the same fix, not a second one: a page whose sections
  each have a heading has no empty column to explain.

  `_detail_page`'s `open_form` parameter (`ca_ui.py:376-394`) and the
  `open_form` context key are removed, with the two call-site arguments at
  `ca_ui.py:633, 657, 713, 723`. **This overturns 0023 FR-8's second half
  and its AC-3, one spec later.** 0023 required the re-filled form's
  `<details>` to carry `open`, and that requirement was correct: a
  re-filled form inside a collapsed disclosure is a form nobody can see.
  The disclosure is what goes; the requirement it protected is satisfied
  by there being nothing to open. Re-filling the form (0023 FR-8's first
  half) stands unchanged.

- FR-9: **Retire gets the treatment this project already has for a
  dangerous action.** `cert_detail.html:80-106` is the pattern: its own
  block, a `.help` line naming the consequence, a `.field-check`
  confirmation checkbox, then the `danger` button. It is reused, not
  reinvented, and no new CSS is written for it — `.field-check` already
  exists (`cabin.css:334-345`).

  Applied per row, inside that row's section from FR-8:
  - Renew and Retire become two separate `<form>` elements. Today they
    share one form and are told apart by `formaction`
    (`ca_detail.html:21, 31, 49`); a confirmation checkbox that belonged to
    both would be a checkbox the renew button also had to satisfy.
  - The retire form carries no `years` input, a `.help` line saying what
    retiring that row does — for a root, that it cascades to every
    intermediate under it (`service.py:751-777`) — the confirmation
    checkbox, and the button.
  - `POST /ca/{ca_id}/retire` gains `confirm: str = Form("")` and refuses
    an unticked request before touching the row, exactly as
    `certs_ui.py:515, 527` does for revocation. The refusal re-renders the
    row's own detail page at 400 with the message, through
    `_detail_page(... _root_of(db, row) ...)`. This is the one place this
    spec extends 0023's Out of Scope note about `ca_retire`'s bare
    `HTTPException`: a missing checkbox is a state an operator reaches by
    forgetting one click, and answering it with a JSON error document is
    the defect 0023 FR-8 exists to remove. `ca_renew` is untouched.

  The cross-row note about retirement not being revocation
  (`ca_detail.html:50`) moves into that row's retire block, where it is
  the consequence being warned about.

- FR-10: **The stylesheet loses what nothing uses.** `.ca-row`,
  `.inline-form`, `details`, `details summary` and `details[open] summary`
  (`cabin.css:657-694`) are used by `ca_detail.html` and by no other
  template; when their uses go, the rules go with them. `.constraints`
  stays — the constraints block is unchanged. 0023 AC-11 asserted that
  every class a template uses has a rule; this is the other direction, and
  it is asserted once here rather than left to accumulate.

  Templates are edited **by a script through Bash, never with
  Edit/Write**, and `git diff` is read after every template change: the
  PostToolUse formatter breaks Jinja tags apart, turning
  `{% if x == "y" %}` into `{% if x="" ="y" %}`. This has cost this project
  a debugging session twice (0021 FR-13, 0023 FR-11).

- FR-11: **The second copy of the convention, in the fixtures.**
  `tests/ca_fixtures.py:92, 96, 102, 111` appends the same two suffixes
  itself, independently of `ca/service.py`. Left alone, `make_hierarchy`
  stays green and quietly names every fixture hierarchy differently from
  production — the test world keeps the convention that production just
  dropped, and the next reader has two rules to choose between. It is
  changed with the service, not after it.

  `create_ca_via_http` (`ca_fixtures.py:150-176`) posts to `/ca/create`
  and asserts a 303. After FR-3 it produces a root and no issuer, so
  every test that uses it to get a signing CA breaks. It, and the nine
  per-file `_create_ca` helpers (`test_web_ca.py:99`,
  `test_web_certs.py:68`, `test_web_name_constraints.py:132`,
  `test_web_audit.py:88`, `test_web_certs_inventory.py:59`,
  `test_web_crl.py:86`, `test_web_dashboard.py:67`, `test_api_v1.py:72`,
  `test_tls.py:848`), post the intermediate as a second request. Ten
  helper bodies, not the ninety-odd tests that call them.

- FR-12: **Nothing else moves.** No route is added or removed, no guard
  changes, no CSRF rule changes, no schema change, no migration. `/ca`'s
  list, `/ca/import`, the API, MCP and ACME are untouched except for the
  one shared message of FR-7.

- FR-13: **An intermediate may not carry its own parent root's exact
  subject.** `create_intermediate_under` (`service.py:533-588`) refuses
  with `ValueError` when the subject it is about to build — the same
  single-CN `x509.Name` `ca/x509.py:create_intermediate` builds from
  `name` — has the same DER encoding as `root_id`'s own certificate's
  subject. Compared as parsed subject DER, not as the `name` string against
  `root.name`: the two happen to always agree under 0017's naming
  invariant, but the collision that matters is between the encoded
  subjects a validator actually compares, and comparing the DER is what
  stays correct if that invariant ever stops holding. Not compared with
  `_same_ca` (`service.py:591-607`) either — its public-key half can never
  match a freshly generated intermediate key, which would make it a silent
  no-op here; this check is deliberately subject-only.

  The check lives in the service layer, not the route, for the same reason
  spec 0018 made `issuer_id` a required parameter rather than a
  route-level convention: a second caller of `create_intermediate_under` —
  another route, a script, a future MCP tool — gets the refusal for free,
  where a check bolted onto `POST /ca/{root_id}/intermediate` alone would
  need to be remembered a second time and could be forgotten.

  **This must never fire for cross-signing.** `cross_sign_root`
  (`service.py:610-688`) and `import_cross` (`service.py:691-769`)
  deliberately produce a `kind="cross"` row whose subject equals the root
  it duplicates — that duplication is spec 0021's entire point (FR-1) and
  is exactly what `ChainSet`/`chains_for` exist to serve as an alternate
  path. Neither function calls `create_intermediate_under`; FR-13 only
  reaches a `kind="intermediate"` row being created under its own
  `parent_id`-to-be, never a cross row, so it cannot touch either path.

## Interface Contract

### Routes

| Method | Path                         | Auth         | Change                                                           |
| ------ | ---------------------------- | ------------ | ---------------------------------------------------------------- |
| GET    | `/ca/new`                    | admin        | three fields removed (FR-3)                                      |
| POST   | `/ca/create`                 | admin + CSRF | creates a root only; `name` validated; three form params removed |
| POST   | `/ca/{root_id}/intermediate` | admin + CSRF | `name` validated; grants and TLS hook now live here              |
| POST   | `/ca/{ca_id}/retire`         | admin + CSRF | new `confirm` field; unticked re-renders `/ca/{ca_id}` at 400    |
| GET    | `/ca/{ca_id:int}`            | session      | same data, re-laid out; no `<details>`                           |

Every other route in the table of 0023's Interface Contract is unchanged
in path, method, guard, fields and response.

### `cabin.ca.service`

```python
def create_root(
    db: Session,
    secrets: SecretStore,
    name: str,
    key_type: str = "ecdsa-p256",
    years: int = 20,
    path_length: int = 1,
) -> CACertificate: ...


def create_hierarchy(
    db: Session,
    secrets: SecretStore,
    root_name: str,
    intermediate_name: str,
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    intermediate_years: int = 10,
    path_length: int = 1,
    constraints: leaf.NameConstraintSpec | None = None,
) -> CAHierarchy: ...
```

- `create_root` writes one `kind="root"` row with the sealed key, commits,
  and returns it. `name` is used verbatim as the subject CN and as
  `name`.
- `create_hierarchy` calls `create_root` and then
  `create_intermediate_under(root.id, intermediate_name, ...)`, and
  returns `CAHierarchy(root, intermediate)`. It is a composition with no
  logic of its own.
- `create_intermediate_under` keeps its signature; the two interpolations
  inside it change, and it gains the FR-13 subject-collision check, raising
  `ValueError` when `name` would build the same subject as `root_id`'s own.
- `import_hierarchy`, `import_cross`, `cross_sign_root`, `retire`,
  `renew_in_place`, `chains_for` and every other function are unchanged.
  `import_cross` and `cross_sign_root` in particular: FR-13's check lives
  only inside `create_intermediate_under`, which neither calls.
- One module-level message for "no usable issuer", raised by
  `resolve_issuer` and imported by `issuer_grants.resolve_granted_issuer`,
  replacing the two duplicated string literals at `service.py:340` and
  `issuer_grants.py:252`. It distinguishes an instance with no
  `ca_certificates` row from one whose rows carry no active intermediate.

### `cabin.web.ca_ui`

```python
def _name_error(name: str) -> str | None: ...


def _detail_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    status_code: int = 200,
) -> Response: ...
```

- `_name_error` returns `None` or the message the form shows. Callers
  strip the name themselves and pass the stripped value on.
- `_detail_page` loses `open_form` (FR-8); everything else about it is
  unchanged.
- `_years_error` loses its `intermediate_years` argument (FR-3).
- `_subject` takes a `CACertificate` (FR-4).

### `cabin.web.certs_ui`

`_NO_CA` keeps its wording and its meaning — no row at all. A second
constant carries the new case, and `_no_issuer_message` chooses between
three sentences instead of two: no CA, a CA with no active issuer, or no
grant. `_NO_GRANT` is unchanged.

### `cabin.web.ui`

The dashboard context keeps `ca_configured` (`bool(rows)`, unchanged
meaning) and gains one flag for "an active issuer exists". No other key
changes.

> **Correction (post-implementation):** the flag above is the wrong shape.
> "An active issuer exists" is an instance-wide question; the notice it
> drives is about one hierarchy at a time. Read literally, a single boolean
> is `True` the moment any one hierarchy gets an active issuer, which hides
> every other hierarchy's own bare root from the notice for as long as that
> stays true. The dashboard context instead gains a list of the hierarchies
> (root rows) that currently have no active issuer — empty when every
> hierarchy has one, one entry for a single bare root (the AC-8 case below
> is unaffected), more than one when several are bare. A hierarchy whose
> only intermediate was retired belongs on this list on the same grounds as
> one that was never given an intermediate — both are "no active issuer",
> which is what `active_issuers` already tests for. No other key changes.

### Schema, API, MCP, ACME

Unchanged. No migration, no column. `api/views.py:36`'s `NO_CA` already
branches on `list_cas` and is already correct; it is not touched.

## Acceptance Criteria

Every criterion is anchored to the element it is about — the form with
that action, the element with that id, the row in the database — and never
to a substring appearing somewhere in the page. This project has twice
shipped a UI test that passed while the feature was visibly broken, both
times because it searched for a string. Scoping is by parsed element or by
`_row(...)`, as `test_web_ca_pages.py` already does.

Where a state is meant to differ, both halves are in one criterion: a
build that renders nothing and a build that renders everything must each
fail.

The fixture, unless stated otherwise: one root named `Acme Root CA` with
one intermediate named `Acme Issuing CA`, and a second hierarchy so that
cross-signing is offered.

- AC-1: **A name is not decorated.** `POST /ca/create` with
  `name="Acme Root CA"` writes exactly one row; its `name` is
  `"Acme Root CA"` and the CN parsed out of its own `cert_pem` is
  `"Acme Root CA"`. Then `POST /ca/{root_id}/intermediate` with
  `name="Acme Issuing CA"` writes one row whose `name` and parsed CN are
  both `"Acme Issuing CA"`. In the same test, no row on the instance has a
  `name` that differs from its own certificate's CN.
  _Goes red if_: a suffix survives on either path, or a name is stored
  that the certificate does not carry.

- AC-2: **The name check refuses, and the message is cabin's.** Four
  requests to `POST /ca/create`, each asserted against
  `select count(*) from ca_certificates`, which stays at zero throughout:
  `name=""` returns 400; `name="   "` returns 400; `name="a" * 65` returns
  400; `name="ä" * 33` returns 400 — sixty-six bytes, which proves the
  limit counts bytes rather than characters. Every one of the four returns
  the `/ca/new` page containing the `<form>` with action `/ca/create`, and
  an error box whose text does not contain `Attribute's length`. Then
  `name="a" * 64` returns 303 and `name="ä" * 32` returns 303, and both
  rows carry the exact name submitted.
  _Goes red if_: the check is missing (a 500 or a 200 on the empty name),
  if it counts characters (the 33-umlaut case is accepted, or the
  32-umlaut case refused), or if cryptography's `ValueError` reaches the
  operator unwrapped.

- AC-3: **Whitespace is stripped from what is signed.**
  `POST /ca/create` with `name="  Acme  "` returns 303, and the row's
  `name` and its certificate's CN are both `"Acme"` — no leading or
  trailing space in either.
  _Goes red if_: the name is validated after stripping but stored
  unstripped, which is today's `" Root CA"` bug with one space fewer.

- AC-4: **The intermediate route refuses the same way, on its own page.**
  `POST /ca/{root_id}/intermediate` with `name="   "` and otherwise valid
  fields returns 400; the response contains the `<form>` whose action is
  `/ca/{root_id}/intermediate`, its `key_type` and `years` inputs still
  carrying what was submitted, and an error box whose text does not
  contain `Attribute's length`. `select count(*)` is unchanged. The same
  request with a usable name returns 303 and adds one row.
  _Goes red if_: the check is only wired into `/ca/create` — the response
  is then still a 400 with a form, so only the message assertion catches
  it.

- AC-5: **A create makes a root, and only the second step makes an
  issuer.** After `POST /ca/create` alone: one row, `kind == "root"`,
  `active_issuers(db) == []`, and `GET /ca/{root_id}` contains a `<form>`
  with action `/ca/{root_id}/intermediate`. After posting that form: two
  rows, one active issuer, and `GET /certs/new` renders a `<select>` named
  `issuer_id` with exactly one `<option>`.
  _Goes red if_: create still writes two rows, or if the second step is
  unreachable from the page.

- AC-6: **`/ca/new` no longer asks about the intermediate.** The `/ca/new`
  page contains inputs named `name`, `key_type`, `root_years` and
  `path_length`, and contains no element named `intermediate_years`,
  `permitted_names` or `excluded_names`. In the same test,
  `GET /ca/{root_id}` does contain `permitted_names` and `excluded_names`
  inside the form whose action is `/ca/{root_id}/intermediate`.
  _Goes red if_: the fields are merely hidden rather than removed, or if
  removing them from the create page also removed them from the place they
  belong.

- AC-7: **The two empty states differ, on the issue form.** On an instance
  with no `ca_certificates` row, `GET /certs/new` renders the no-CA
  message and a link whose href is `/ca/new`. On an instance with one root
  and no intermediate, the same page renders a different message and a
  link whose href is `/ca/{root_id}`. The two message strings are asserted
  to be unequal, and the second contains no link to `/ca/new`.
  _Goes red if_: both states share one sentence, which is today's
  behaviour and passes any test that merely looks for "no CA".

- AC-8: **The dashboard tells the two states apart.** With one root and no
  intermediate, `GET /` contains no element with the "CA: not set up"
  error id, does contain an element saying this hierarchy has no issuer
  with a link whose href is `/ca/{root_id}`, and its `Revocation` section
  contains no issuer table. After the intermediate is added, the same page
  contains no such element and its `Revocation` section contains exactly
  one issuer table naming that intermediate. One test, both halves.
  _Goes red if_: `ca_configured` alone still drives the page, which
  renders an empty revocation block, or if the new flag suppresses the
  revocation block once an issuer exists.

- AC-9: **No disclosure, and no empty column.** For an admin,
  `GET /ca/{root_id}` on the full fixture contains zero `<details>`
  elements and zero `<summary>` elements. The element wrapping the form
  with action `/ca/{root_id}/intermediate` has class `section`, and that
  section's first child element contains an `<h2>`; the same holds for the
  cross-sign form's section and for the section containing the
  intermediate's `chain.pem` link. Measured additionally as effect in
  headless Chrome at 1440: every `.section` element on the page has a
  first child element whose `textContent.trim()` is non-empty.
  _Goes red if_: `<details>` survives anywhere, if an action is moved into
  a section that has no heading, or if the intermediate rows are left
  inside one section's right column.

- AC-10: **Retire is confirmed, and the confirmation is enforced on the
  server.** `GET /ca/{root_id}` contains a `<form>` with action
  `/ca/{root_id}/retire` holding a checkbox input named `confirm` and no
  `years` input, and a separate `<form>` with action
  `/ca/{root_id}/renew`. `POST /ca/{root_id}/retire` without
  `confirm` returns 400, the response contains that same retire form, and
  the root's `status` in the database is still `"active"`. The same POST
  with `confirm="on"` returns 303 and the status is `"retired"`. One test,
  all four halves.
  _Goes red if_: the checkbox is decoration the route ignores, if the
  unticked POST answers with a JSON error document instead of the page, or
  if renew and retire still share one form.

- AC-11: **A dangerous button never stands alone.** In headless Chrome on
  `GET /ca/{root_id}` with the full fixture, every `button.danger` on the
  page has, inside the same `<form>`, an `input[name="confirm"]`. Asserted
  over all of them, so a hierarchy with an intermediate and a cross
  certificate proves the treatment repeats rather than being applied to
  the root alone.
  _Goes red if_: the pattern is applied to the first row and copied
  without the checkbox to the others — the exact shape of today's defect.

- AC-12: **The stylesheet has no rules for constructs nothing uses.**
  `cabin.css` contains no `details` selector, no `.inline-form` and no
  `.ca-row`; no template contains a `<details>` tag or those two class
  names. 0023 AC-11's forward direction is re-run unchanged in the same
  test: every class name appearing in a `class="..."` attribute of any
  template has a rule.
  _Goes red if_: the markup is changed and the stylesheet is not, or the
  reverse.

- AC-13: **The TLS swap happens when an issuer appears, not before.** On
  an instance with TLS on: after `POST /ca/create` alone, the certificate
  cabin serves is still self-signed (`issuer == subject`) and
  `TLS_ISSUER_ID` is unset. After `POST /ca/{root_id}/intermediate`, in
  the same request cycle and without waiting for a renewal tick, the
  served certificate's issuer is that intermediate's subject. One test,
  both halves.
  _Goes red if_: the hook is left on `/ca/create`, where it is a no-op —
  the first half then still passes and the second fails an hour short.

- AC-14: **The grant and the audit event follow the row that exists.**
  After `POST /ca/create`, `user_issuers` has no row, and the
  `ca_created` event's `target_id` is the root's id with no `granted_to`
  key in its detail. After `POST /ca/{root_id}/intermediate`,
  `user_issuers` has exactly one row for the acting user and that
  intermediate, and the second `ca_created` event's `target_id` is the
  intermediate's id with `granted_to` naming the acting user. One test.
  _Goes red if_: the create path still tries to grant something (it would
  raise or grant the root, which is not an issuer), or if the audit event
  keeps naming a row it did not write.

- AC-15: **The fixtures follow production's naming _rule_, not a literal
  reading production has since made impossible.** This criterion was
  written before FR-13 existed and, read literally, asks
  `ca_fixtures.make_hierarchy` to give a root and its own intermediate the
  same name -- exactly the subject collision FR-13 makes
  `create_intermediate_under` refuse. The rule production actually follows
  is narrower and still applies to the fixtures: a name is never decorated
  and always equals the CN of that row's own certificate. Applied to a
  hierarchy, where root and intermediate are two rows, that rule requires
  two _distinguishable_ names, not one name worn twice.

  `ca_fixtures.make_hierarchy` derives both from the single `name` its
  callers pass -- the root keeps `name` verbatim, the intermediate is
  `f"{name} Intermediate"` -- so that for every row it writes, `name`
  equals the CN of that row's own certificate, and the root and its
  intermediate never collide the way FR-13 forbids. `create_ca_via_http`
  followed by its intermediate request produces the same two names a
  direct `create_hierarchy` call with those two names produces. Asserted
  over the fixture module itself, so the convention cannot survive in the
  test world after leaving production.
  _Goes red if_: `ca_fixtures.py` keeps its own copy of the old suffix
  convention (invisible: every suite stays green while naming everything
  differently), if `make_hierarchy`'s root and intermediate end up sharing
  one name (the exact collision FR-13 refuses in production), or if `name`
  disagrees with the CN of either row's own certificate.

- AC-16: **Everything that was not this spec's subject still works.** The
  0004-0023 suite passes: every POST path, guard and CSRF rule is
  unchanged, `/ca` and `/ca/import` render as before, `chains_for`,
  cross-signing, name constraints, CRL, ACME, the API and MCP are
  untouched apart from FR-7's message, and the detail page still shows the
  same data — every intermediate's CRL, AIA and ACME URL, every cross
  row's served state, both constraints blocks — in its new layout. The
  only test changes are the ones the Test list names.

- AC-17: **No page scrolls sideways.** 0015 AC-1 and AC-2 re-run over the
  page list at `test_web_layout.py:484`, with the detail page rendered
  from the full fixture: at 1440x1150 and at 390x900,
  `document.scrollingElement.scrollWidth` does not exceed `clientWidth`
  and no element's right edge extends past its container's. The section
  split multiplies the number of grid rows on the detail page, which is
  exactly the change that has broken this before.

- AC-18: **The subject collision is refused, and cross-signing still
  works.** Both halves belong in one test: a check that only proves
  `create_intermediate_under` refuses the collision would equally pass an
  implementation that (wrongly) blocks cross-signing too. `create_root` a
  root named `"Smuggle"`, then call `create_intermediate_under` for that
  root with `name="Smuggle"`: raises `ValueError`, and `active_issuers(db)`
  for that root is still empty afterwards. The same call with
  `name="Smuggle Issuing"` succeeds. Then, on a second root,
  `cross_sign_root` (and, from an exported PEM, `import_cross`) still
  succeeds when the resulting cross row's subject equals the root it
  duplicates — which it always does, by spec 0021 FR-1 — proving FR-13 did
  not turn into a blanket "no two rows may share a subject" rule.
  _Goes red if_: the collision is not refused, if it is refused by
  comparing `name` strings rather than parsed subjects and therefore misses
  a case the string comparison can't see, or if the refusal (or a broader
  one written to get AC-18's first half green) also raises for
  `cross_sign_root`/`import_cross`.

## Test list

New:

test_created_name_is_stored_and_signed_verbatim,
test_intermediate_name_is_stored_and_signed_verbatim,
test_create_refuses_empty_blank_and_oversized_names,
test_name_limit_counts_bytes_not_characters,
test_create_strips_surrounding_whitespace,
test_intermediate_name_error_renders_the_detail_page,
test_create_writes_only_a_root,
test_intermediate_step_produces_the_first_issuer,
test_ca_new_has_no_intermediate_fields,
test_issue_form_distinguishes_no_ca_from_no_issuer,
test_dashboard_distinguishes_no_ca_from_no_issuer,
test_detail_page_has_no_details_and_no_empty_column (headless Chrome),
test_retire_requires_the_confirmation_box,
test_every_danger_button_has_a_confirmation (headless Chrome),
test_stylesheet_and_templates_agree_in_both_directions,
test_tls_swaps_when_the_intermediate_appears,
test_grant_and_audit_follow_the_intermediate,
test_fixtures_name_rows_the_way_production_does,
test_no_horizontal_overflow (0015, re-run),
test_intermediate_matching_root_subject_is_refused_cross_signing_unaffected
(AC-18)

Existing tests that change, each named because each is load-bearing:

- **`tests/ca_fixtures.py:92, 96, 102, 111`** — the second copy of the
  convention (FR-11). Changed with the service, not after it.
- **`tests/ca_fixtures.py:150-176`** `create_ca_via_http`, and the nine
  per-file `_create_ca` helpers listed in FR-11. Each posts the
  intermediate as a second request. These ten bodies are the whole HTTP
  cost of FR-3.
- **The 194 `create_hierarchy`/`make_hierarchy` call sites across 32 test
  files** take a second name argument where they call `create_hierarchy`
  directly. Roughly 26 of them then read a cabin-generated name back and
  assert on it; those assertions change to the name that was passed.
  `test_web_ca.py`, `test_ca_service.py`, `test_ca_multi.py`,
  `test_cross_signing.py` and `test_web_name_constraints.py` carry most of
  them.
- **`tests/test_cross_signing.py`**'s
  `test_smuggled_cross_certificate_fails_path_length_in_openssl` and
  **`tests/test_name_constraints_doors.py`**'s
  `test_openssl_rejects_a_smuggled_name` both call `create_hierarchy` with
  the same string for `root_name` and `intermediate_name` (see "The suffix
  was not merely cosmetic" above). FR-13 makes that call raise, so both
  fixtures need a root name and an intermediate name that differ — a
  one-line change to the two calls, not to what either test asserts.
- **`test_web_ca_pages.py:459-490`**
  `test_intermediate_error_refills_the_form_and_opens_the_details` asserts
  `block.details_open is True` (0023 AC-3). The re-fill half stays; the
  `<details>` half goes, together with the `details_open` tracking in the
  parser at `:235-282`. `:383` already asserts `/ca` has no `<details>`
  and now holds for the detail page too.
- **`test_web_name_constraints.py`** — the constraint fields move off
  `/ca/new` entirely (FR-3), so every test that submits them through
  `POST /ca/create` submits them through
  `POST /ca/{root_id}/intermediate` instead, including 0023's counter-proof
  at `:543` that the create form grows those fields.
- **`test_web_audit.py:283-291`** asserts `ca_created`'s detail for a
  create; it gains the second event and the split of FR-4 and FR-14.
- **`test_mcp.py:941`** expects the exact sentence
  `"no CA hierarchy has been created or imported yet"` from the
  `issuer_grants` path (FR-7). It asserts the no-row sentence on a no-row
  instance, and gains the root-only case.
- **`test_tls.py:848`** `_create_ca_via_live_client` drives a real
  subprocess through stage 2; it needs the intermediate request, and it is
  where AC-13's live half belongs.
- **`test_web_dashboard.py`** — FR-7's fourth site. This file still scopes
  with fixed character windows; where this work touches it, those are
  replaced with `_row(...)`-style element scoping rather than given a
  wider window.

## Out of Scope

The name of an **imported** row. `_subject_name` (`service.py:168-181`)
takes the CN verbatim already and falls back to the full RFC 4514 subject
for a certificate with no CN at all — a string that can exceed
`sa.String(64)`. That is a pre-existing edge on a path this spec does not
touch, and it is recorded here rather than fixed silently.

Renaming an existing CA. `name` is the subject CN of a signed certificate;
changing it would mean re-signing, which is what renewal is, and no
operator has asked for it.

The bare `HTTPException` on `POST /ca/{ca_id}/renew`, and on retire's
`RetireError` and TLS-issuer refusal (`ca_ui.py:806, 812, 846`). FR-9
adds the confirmation refusal to the retire route because that is the one
an operator reaches by forgetting a click; the domain refusals still
arrive as JSON error documents, exactly as 0023 left them.

The transfer area — import and export under their own rail group. That is
spec 0025, and it moves `/ca/import` out of the group this spec is
rearranging, which is why it comes second.

Any change to `/ca`'s list. A root with no intermediate renders `0` in the
`Intermediates` column, which is accurate.

No version bump: 0.2.0 and PR #17 stay as they are. No new layout
primitive, no permission change, no schema change, no migration.
