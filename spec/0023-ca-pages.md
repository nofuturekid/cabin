# Spec 0023 — CA Pages

## Context

`/ca` is one page doing three unrelated jobs: creating a hierarchy,
importing one, and managing every hierarchy that already exists. An
operator clicking through a fresh 0.2.0 instance said so in as many
words, and the page is worse the more it is used — the parts that
repeat are the per-root ones.

**Nobody designed it this way.** Four consecutive specifications each
added to the same template and none of them looked at the result:
spec 0017 put the hierarchy list and its per-row actions there, 0020
added the name-constraint fields and their blocks, 0021 added the
cross-signing action, the cross rows and the cross-certificate import,
and 0022 added the TLS setup note. Every one of those was a small,
correct addition to the page in front of it. This is accumulated debt,
not a layout somebody chose, and it is worth writing down so that a
reader in a year does not go looking for the reasoning behind it.

Counted out of `ca_list.html` (164 lines) and `ca_ui.py`:

- **A page whose form count grows with the data.** Three page-wide
  forms — create (seven fields), import CA, import cross certificate —
  plus per root a renew/retire form, an `Add intermediate` block (five
  fields) and a `Cross-sign` block, plus one inline form per
  intermediate and per cross row. Two hierarchies of one intermediate
  each render nine `<form>` elements, eleven when both roots can
  cross-sign each other. Five hierarchies would render twenty.
- **The create and the import form exist twice**, in
  `ca_setup.html:22-101` and `ca_list.html:57-136`, and the duplication
  is deliberately asserted by a test
  (`test_web_name_constraints.py:543`) because it is a copy-paste
  hazard.
- **One error box at the top of the page** (`ca_list.html:12`) for
  whichever of those forms produced the error.
- **A form error while creating a second hierarchy renders
  `ca_setup.html`** (`ca_ui.py:388`), throwing the operator from the
  list back onto the first-run wizard.
- **`POST /ca/{root_id}/intermediate` raises a bare `HTTPException` on
  every refusal** (`ca_ui.py:510, 523, 525`). Five filled-in fields —
  name, key type, years and two blocks of name constraints — are gone,
  and the operator gets a JSON error document instead of the page.
  `ca_cross_sign`'s docstring (`ca_ui.py:570`) records why it was done
  differently there: "because the action lives inside a details block
  on `/ca` rather than on its own page". That reason is what this spec
  removes.
- **Three class names carry no rules at all.** `.ca-row`,
  `.inline-form` and `.constraints` are used by `ca_list.html` and
  appear nowhere in `cabin.css`; `<details>` has no rule either. The
  rows are not visually separated because nothing separates them.

The fix is the move spec 0015 FR-10 already made for issuing and CSR
signing: split the page by activity, give each part a rail entry, and
let the page that owns a form be the page its errors come back to.
Nothing about authorisation, CSRF, data or the POST paths changes.

## User Stories

- As an operator, `/ca` tells me which hierarchies exist and how
  healthy they are, and nothing else — it is a place to look, not a
  place to fill in forms.
- As an operator working on one hierarchy, everything about it is on
  one page: its root, its issuers with their CRL, AIA and ACME URLs,
  its cross certificates, and every action that applies to it.
- As an operator who mistyped a name constraint while adding an
  intermediate, I get the page back with what I typed still in it,
  instead of a JSON error and five empty fields.
- As an operator creating a hierarchy, the form has the page to itself
  and I am not looking at seven other forms while I do it.
- As an operator on a fresh instance, `/ca` says there is no hierarchy
  yet and where to go, rather than being a wizard that disappears the
  moment it has been used once.
- As a viewer, I can read a hierarchy in full and cannot see a single
  control that would answer 403.

## Functional Requirements

- FR-1: **Four pages where there was one.**

  | Page              | Contents                                                    | Guard     |
  | ----------------- | ----------------------------------------------------------- | --------- |
  | `GET /ca`         | The list of hierarchies. No forms.                          | logged in |
  | `GET /ca/{ca_id}` | One hierarchy in full, plus every action that belongs to it | logged in |
  | `GET /ca/new`     | Create a hierarchy. One form on the page.                   | admin     |
  | `GET /ca/import`  | Import an existing CA, and import a cross certificate.      | admin     |

  Templates: `ca_list.html` (rewritten), `ca_detail.html`, `ca_new.html`
  and `ca_import.html`. `ca_setup.html` is deleted (FR-10).

- FR-2: **`/ca` is a list.** One entry per `kind == "root"` row, in
  `list_cas` order: the root's name, a `root` tag, its status tag, the
  date it expires, how many intermediates and how many cross
  certificates hang off it, and a link to `/ca/{root_id}`. No form, no
  `<details>`, no PEM, no fingerprint, no CRL or ACME URL — those are
  the detail page's job.

  The counts come from the rows already loaded. The expiry does not:
  `ca_certificates` has no `not_after` column (`ca/service.py:61-95`),
  so the date is still read out of the parsed `cert_pem`. What the
  split buys here is that the list parses **one certificate per
  hierarchy** instead of one per row, and calls neither
  `crl_service.distribution_url`, nor `acme_http.directory_url`, nor
  `chains_for`, nor `leaf.constraints_of` at all.

  **With no hierarchy at all** the page renders an element with
  `id="ca-empty"` saying so. For an admin it links to `/ca/new` and to
  `/ca/import`; for a viewer it says an administrator has to create
  one, and carries no link to either. This is the page the dashboard's
  "CA: not set up" banner points at (`dashboard.html:31`) and the page
  a first run lands on, so it may not be a dead end.

- FR-3: **`/ca/{ca_id}` is one hierarchy.** `ca_id` names the
  hierarchy's **root** row; anything else — an intermediate id, a cross
  id, an id that does not exist — is a 404 saying a hierarchy is named
  by its root. The page carries, for that root only, exactly what
  `ca_list.html` renders today: the root with its status, expiry,
  served-chain sentence, `root.pem` link, subject, fingerprint and
  constraints block; each intermediate with its tags, expiry,
  `cert.pem` and `chain.pem` links, CRL and AIA URLs or the note that
  no base URL is set, its ACME directory URL, and its constraints
  block; each cross certificate with the root that signed it, its
  served state, its inline actions and FR-10-of-0021's
  "this is not a revocation" note.

  **The page loads every row, not just this hierarchy's.**
  `_cross_sign_candidates` (`ca_ui.py:215-231`) answers "which other
  root could sign this one", and every candidate is by definition
  outside the group being displayed. A detail page that queried only
  its own subtree would render an empty select and silently remove the
  cross-signing action from an instance that can perform it.

  For an admin the page also carries the actions: renew and retire per
  row, the `Add intermediate` block and the `Cross-sign` block (or the
  note explaining why no root here can sign this one). **For a viewer
  it carries no `<form>` at all** — not a disabled one, not a hidden
  one — while everything above stays readable. The gate is
  `nav.ca_admin` (FR-6), the same flag that decides the rail entries,
  so the page and the menu cannot drift apart on what admin means.

- FR-4: **`/ca/new`** renders the seven-field create form of
  `ca_setup.html:22-69` and nothing else, with its `path_length` hint
  unchanged (`ca_list.html:89`), and links to `/ca/import` — the same
  way `certs_new.html:11` and `certs_sign.html:11` name each other, so
  the choice between generating and bringing your own stays visible
  from either side.

- FR-5: **`/ca/import`** carries both import forms — an existing CA
  (`ca_list.html:106-136`) and a cross certificate
  (`ca_list.html:138-163`) — and links to `/ca/new`. Neither import
  form gains a name-constraint field, for the reason 0020 FR-9 gave:
  the certificate is already signed and a field that appeared to
  change its constraints would change nothing.

- FR-6: **A rail group, and a fifth nav flag.**
  - `/ca` leaves the group "Overview", which is then the dashboard
    alone. A new group "Certificate authority" sits between "Overview"
    and "Certificates" — a hierarchy has to exist before a certificate
    can be issued, so it is read in that order — holding
    `Hierarchies` (`/ca`), `Create` (`/ca/new`) and `Import`
    (`/ca/import`). That is the shape "Certificates" already has with
    Inventory / Issue / Sign a CSR (`layout.html:22-25`).
  - The entry for `/ca` is relabelled from "Certificate authority" to
    "Hierarchies", because the group heading now carries that name.
  - `base_context` (`deps.py:62-71`) gains a fifth flag, `ca_admin`,
    gating the two new entries and FR-3's actions. It is
    `role in ADMIN_ROLES`, the same value `issue` has today, and it is
    deliberately not `issue` itself: issuing a certificate and creating
    a certificate authority are different privileges, and the day one
    of them stops being admin-only the flag that has to change must
    already exist. Like every other `nav.*` flag it is cosmetic — each
    route keeps its own dependency.
  - `nav_current`: `ca` for both `/ca` and `/ca/{ca_id}` (a detail page
    marks its list entry, as `cert_detail.html` does), `ca_new` for
    `/ca/new`, `ca_import` for `/ca/import`. Every content template
    sets exactly one, as 0015 FR-2 requires.

- FR-7: **Every POST keeps its path.** `/ca/create`, `/ca/import`,
  `/ca/cross-import`, `/ca/{root_id}/intermediate`,
  `/ca/{ca_id}/cross-sign`, `/ca/{ca_id}/renew` and
  `/ca/{ca_id}/retire` are untouched in path, method, form fields,
  guard and CSRF. `/ca/create` alone appears in roughly ninety tests
  but in only nine helper definitions (`test_web_ca.py:99`,
  `test_web_certs.py:68`, `test_web_name_constraints.py:131`,
  `ca_fixtures.py:150` and one each in `test_web_audit.py`,
  `test_web_certs_inventory.py`, `test_web_crl.py`,
  `test_web_dashboard.py`, `test_api_v1.py`), none of which changes if
  the path does not. That is the difference between a cheap
  reorganisation and an expensive one.

  What changes is where a response goes:

  | POST                         | Error re-renders | Success redirects to |
  | ---------------------------- | ---------------- | -------------------- |
  | `/ca/create`                 | `/ca/new`        | `/ca`                |
  | `/ca/import`                 | `/ca/import`     | `/ca`                |
  | `/ca/cross-import`           | `/ca/import`     | `/ca`                |
  | `/ca/{root_id}/intermediate` | `/ca/{root_id}`  | `/ca/{root_id}`      |
  | `/ca/{ca_id}/cross-sign`     | `/ca/{ca_id}`    | `/ca/{ca_id}`        |
  | `/ca/{ca_id}/renew`          | unchanged (400)  | `/ca/{root_of_row}`  |
  | `/ca/{ca_id}/retire`         | unchanged (400)  | `/ca/{root_of_row}`  |

  An error re-renders at 400 with the message in that page's error box,
  before anything is written — the rule `ca_create` already follows
  (`ca_ui.py:384-388`). `root_of_row` is the row itself for a root, its
  `parent_id` for an intermediate and its `cross_of_id` for a cross
  row: an action started on a page comes back to that page.
  `/ca/import` and `/ca/create` still redirect to `/ca` on success,
  because what they produce is a new entry on the list.

- FR-8: **The intermediate form keeps what was typed.** This is the
  defect FR-3 exists to make fixable. `POST /ca/{root_id}/intermediate`
  re-renders that root's detail page at 400 with the message, and the
  form is filled from the submitted values — `name`, `key_type`,
  `years`, `permitted_names`, `excluded_names` — through the same
  `values` dict `certs_new.html` and `certs_sign.html` already use
  (`certs_ui.py:162-197`). The `<details>` element wrapping it carries
  `open`, because a re-filled form inside a collapsed disclosure is a
  form nobody can see, and the operator would be looking at an error
  message about fields that appear to be gone.

  `UnknownIssuerError` stays a 404: no page can be rendered for a root
  that does not exist. `/ca/{ca_id}/cross-sign` re-renders the same
  detail page it already re-rendered the list page for, with its own
  `<details>` open.

- FR-9: **Route shapes, so nothing shadows anything.** The detail route
  is declared `@router.get("/{ca_id:int}")`, with the path converter,
  following `crl_ui.py:93`'s `"/ca/{ca_id:int}.cer"`. Without it a bare
  `/{ca_id}` compiles to `^/ca/(?P<ca_id>[^/]+)$` and swallows three
  things that must keep working:
  - `/ca/new` and `/ca/import`, which would match it and answer 422 on
    the int conversion;
  - `/ca/{ca_id}.pem` (`ca_ui.py:714`), where `/ca/5.pem` would bind
    `ca_id="5.pem"` and answer 422 — 0017's `/crl/7.pem` bug exactly;
  - `/ca/{ca_id:int}.cer`, which lives in the **crl router**
    (`crl_ui.py:93`) and is included after the CA router
    (`app.py:103, 116`), so a greedy `/ca/{ca_id}` shadows it across
    module boundaries and breaks the root download the dashboard banner
    links to (`ui.py:128`).

  With the converter none of this depends on declaration order, which
  is the point. `GET /ca/import` and `POST /ca/import` share a path and
  are separated by method, which Starlette resolves through its partial
  match. AC-8 asserts all of it rather than reasoning about it.

- FR-10: **`ca_setup.html` is deleted.** With `/ca/new` and
  `/ca/import` as pages of their own there is no second place for the
  same two forms, and `_list_page`'s branch on `if not rows`
  (`ca_ui.py:344-347`) goes with it: `/ca` renders one template in both
  states, with FR-2's empty state inside it.

  **The TLS note stays on `/ca`.** `ca_setup.html:14-20` carries
  `id="tls-setup-note"`, checked by
  `test_web_tls_ui.py:661` in three states. It moves into FR-2's empty
  state, under the same `tls_self_signed` condition, which reproduces
  today's behaviour exactly: the note is visible only while cabin
  serves a self-signed certificate **and** no hierarchy exists, since
  that is when `ca_setup.html` was the template being rendered. The
  test keeps its URL and both halves. It is not duplicated onto
  `/ca/new`: the note says the browser warning stops once a CA exists,
  which is a statement about the instance, not about the form.

- FR-11: **The three unstyled classes, and `<details>`.** `.ca-row`,
  `.inline-form` and `.constraints` either get rules in `cabin.css` or
  are replaced by primitives that already have them; `<details>` and
  `<summary>` get a rule so a disclosure block is visibly a block
  rather than text that happens to be clickable. No new layout
  primitive is invented — `.section`, `.field`, `.actions`, `.tag`,
  `.scroller` and `.note` (0015 FR-3/FR-5/FR-6) cover this — and both
  colour schemes are complete, as 0015 FR-8 requires.

  Templates are edited **by a script through Bash, never with
  Edit/Write**, and `git diff` is read after every template change: the
  PostToolUse formatter breaks Jinja tags apart, turning
  `{% if x == "y" %}` into `{% if x="" ="y" %}`. This has cost this
  project a debugging session before (0021 FR-13).

## Interface Contract

### Routes

| Method | Path                         | Auth         | Change                                    |
| ------ | ---------------------------- | ------------ | ----------------------------------------- |
| GET    | `/ca`                        | session      | list only; empty state when there is none |
| GET    | `/ca/{ca_id:int}`            | session      | new — one hierarchy, actions for admin    |
| GET    | `/ca/new`                    | admin        | new — the create form                     |
| GET    | `/ca/import`                 | admin        | new — both import forms                   |
| POST   | `/ca/create`                 | admin + CSRF | unchanged; errors render `/ca/new`        |
| POST   | `/ca/import`                 | admin + CSRF | unchanged; errors render `/ca/import`     |
| POST   | `/ca/cross-import`           | admin + CSRF | unchanged; errors render `/ca/import`     |
| POST   | `/ca/{root_id}/intermediate` | admin + CSRF | unchanged; errors render `/ca/{root_id}`  |
| POST   | `/ca/{ca_id}/cross-sign`     | admin + CSRF | unchanged; errors render `/ca/{ca_id}`    |
| POST   | `/ca/{ca_id}/renew`          | admin + CSRF | unchanged but for its redirect target     |
| POST   | `/ca/{ca_id}/retire`         | admin + CSRF | unchanged but for its redirect target     |
| GET    | `/ca/{ca_id}.pem`            | session      | unchanged                                 |
| GET    | `/ca/{issuer_id}/chain.pem`  | session      | unchanged                                 |

No route is removed, none changes its guard, and no form field is added
or renamed anywhere.

### `cabin.web.ca_ui`

```python
def _overview(db: Session, rows: list[CACertificate]) -> list[dict[str, object]]: ...


def _group(
    db: Session,
    rows: list[CACertificate],
    root: CACertificate,
    *,
    acme_enabled: bool,
) -> dict[str, object]: ...


def _root_of(db: Session, row: CACertificate) -> CACertificate: ...


def _detail_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    open_form: str | None = None,
    status_code: int = 200,
) -> Response: ...


def _new_page(
    request: Request, user: User, error: str | None, status_code: int = 200
) -> Response: ...


def _import_page(
    request: Request, user: User, error: str | None, status_code: int = 200
) -> Response: ...
```

- `_overview` returns FR-2's rows: `id`, `name`, `status`,
  `not_valid_after`, `intermediate_count`, `cross_count`. It does not
  call `_row_view`.
- `_group` is today's `_groups` (`ca_ui.py:234-328`) for a single root,
  with the same keys — `root`, `intermediates`, `cross_certificates`,
  `chain`, `cross_sign_candidates` — and the same body otherwise.
  `rows` is **every** row, because `_cross_sign_candidates` needs them
  (FR-3); `root` names which group to build. `_groups` itself is
  removed; nothing needs every group any more.
- `_root_of` implements FR-7's redirect target and is the only place
  that mapping lives.
- `_detail_page` is the one renderer for `ca_detail.html`, used by the
  GET and by the three POSTs that re-render it. `open_form` is
  `"intermediate"`, `"cross-sign"` or `None` and decides which
  `<details>` carries `open` (FR-8).
- `_list_page` (`ca_ui.py:331-349`) is removed with `ca_setup.html`.
  `_cert_info`, `_row_view` and `_cross_sign_candidates` are unchanged.

### `cabin.web.deps`

`base_context` returns a fifth nav flag and changes nothing else:

```python
"nav": {
    "issue": role in ADMIN_ROLES,
    "ca_admin": role in ADMIN_ROLES,
    "settings": role in ADMIN_ROLES,
    "acme": role in ADMIN_ROLES,
    "tokens": role == Role.superadmin,
},
```

### Schema, services, API, MCP

Unchanged. No migration, no new column, no change to `ca/service.py`,
`api/`, `acme/` or `mcp/`. This spec touches `web/ca_ui.py`,
`web/deps.py`, the templates and `static/cabin.css`.

## Acceptance Criteria

Every criterion is anchored to the element it is about — the form with
that action, the element with that id, the rail entry with that href —
and never to a substring appearing somewhere in the page. Two of this
project's UI tests have been green while the feature was visibly
broken, both for that reason, and `test_web_ca.py:168` exists because a
fixed-character-window helper broke when markup grew and the production
markup was compacted to fit the test. Nothing here reintroduces that:
scoping is by parsed element or by `_row(...)`.

Where a state is meant to differ, both halves are in the same
criterion. A build that renders nothing and a build that renders
everything must each fail.

The fixture, unless stated otherwise: hierarchy **alpha** (root created
with `path_length=2`, one intermediate) and hierarchy **beta**
(default `path_length`, one intermediate), both active.

- AC-1: **`/ca` has no forms and no per-hierarchy detail.** With the
  fixture, the `<form>` elements in `GET /ca` are exactly one, the
  rail's logout form with `action="/logout"` — asserted by collecting
  every form's `action`, not by searching for a string. The page
  contains a link to `/ca/{alpha_root}` and one to `/ca/{beta_root}`,
  and contains neither intermediate's name, neither root's fingerprint,
  and no `<details>`. The same fixture on the page this spec replaces
  renders nine forms.
  _Goes red if_: any form is left behind, or the list is built from
  `_group` and quietly renders the whole old page under a new name.
- AC-2: **The detail page is one hierarchy, and the other one is not on
  it.** `GET /ca/{alpha_root}` contains alpha's intermediate name and
  alpha's root fingerprint, and does not contain beta's intermediate
  name; `GET /ca/{beta_root}` is the mirror image. `GET /ca/{id}` for
  alpha's _intermediate_ id is 404, and so is an id no row has.
  _Goes red if_: the detail page renders every group and scrolls to
  one, or accepts any row id and renders a group for a non-root.
- AC-3: **The five fields survive a refused intermediate.** Posting to
  alpha's `/intermediate` route with `name="edge"`, with
  `permitted_names="not a name constraint!!"` and with the other three
  fields set returns **400**, and in the response: the `<form>` whose
  action is `/ca/{alpha_root}/intermediate` has `value="edge"` on its
  `name` input, the submitted text inside its `permitted_names`
  textarea, and the submitted `years` on its `years` input; the
  `<details>` element containing that form carries `open`; the error
  box holds the parse message. `select count(*) from ca_certificates`
  is unchanged. The same request with a valid constraint returns 303 to
  `/ca/{alpha_root}` and adds exactly one row.
  _Goes red if_: the refusal is still an `HTTPException` (there is no
  form to scope to at all), if the page re-renders empty (the value
  assertions fail), or if the form is re-filled inside a closed
  `<details>`.
- AC-4: **Errors land on the page that owns the form.** Each of these
  returns 400 and, in the returned page, the rail marks exactly one
  entry with `aria-current="page"`, and it is: `Create` for
  `POST /ca/create` with `path_length=9`; `Import` for `POST /ca/import`
  with an unparseable `cert_pem`; `Import` for `POST /ca/cross-import`
  with an unparseable `cross_pem`; `Hierarchies` for
  `POST /ca/{beta_root}/cross-sign` with `years=0`. Each response
  contains the `<form>` the request came from, and the row count is
  unchanged in all four.
  _Goes red if_: any of them still renders `ca_setup.html` or the list
  page, which the marked entry names unambiguously.
- AC-5: **The rail.** For `/ca`, `/ca/{alpha_root}`, `/ca/new` and
  `/ca/import`, exactly one entry carries `aria-current="page"` and it
  is `Hierarchies`, `Hierarchies`, `Create` and `Import` respectively.
  The rail contains a `nav-group` labelled "Certificate authority", and
  the entries between the "Overview" group label and the next group
  label are exactly one link, `href="/"`.
  _Goes red if_: `/ca` stays in Overview, if the detail page marks
  nothing (it sets no `nav_current`), or if two entries are marked.
- AC-6: **Viewer and admin, in one test.** A viewer gets 200 from `/ca`
  and from `/ca/{alpha_root}`, and 403 from `/ca/new` and
  `/ca/import`. The viewer's rail contains no `href="/ca/new"` and no
  `href="/ca/import"` while containing `href="/ca"`. The viewer's
  `/ca/{alpha_root}` contains alpha's intermediate name and its CRL URL
  — it is readable — and exactly one `<form>`, the logout form. The
  admin's `/ca/{alpha_root}`, in the same test, contains forms with
  actions `/ca/{alpha_root}/intermediate` and `/ca/{alpha_root}/renew`.
  _Goes red if_: the actions are rendered for everybody, or the whole
  page is gated and a viewer sees an empty hierarchy.
- AC-7: **Cross-signing candidates come from every row, not from the
  group.** `GET /ca/{beta_root}` contains a `<select>` named
  `signing_root_id` with an `<option>` whose value is
  **alpha's root id** — a row that is on a different detail page. In
  the same test, `GET /ca/{alpha_root}` contains no such select and
  carries the note explaining that no other root here can sign this one,
  because beta's `path_length` is 1.
  _Goes red if_: the detail page passes only its own group's rows to
  `_cross_sign_candidates`, which produces an empty select and silently
  removes the action.
- AC-8: **Nothing shadows anything.** For an admin: `GET /ca/new` and
  `GET /ca/import` return 200 (not 422); `GET /ca/{alpha_root}.pem`
  returns 200 with `application/x-pem-file`; `GET /ca/{alpha_root}.cer`
  returns 200; `GET /ca/{alpha_int}/chain.pem` returns 200;
  `GET /ca/does-not-exist` returns 404, not 422 and not 500. Asserted
  against the running application, not against the route table.
  _Goes red if_: the detail route is declared without the `:int`
  converter — the first four then answer 422 in some order that depends
  on which module was included first.
- AC-9: **The duplication is gone and the empty state is not a dead
  end.** `ca_setup.html` does not exist and no template or module
  refers to it. Across every template exactly one `<form>` has
  `action="/ca/import"` and exactly one has `action="/ca/create"`. On a
  fresh instance with no hierarchy, `GET /ca` returns 200 with an
  element `id="ca-empty"` whose links include `/ca/new` and
  `/ca/import`; for a viewer the same element exists and contains
  neither link.
  _Goes red if_: the wizard is kept alive under a new name, or the
  empty state is admin-only and a viewer's `/ca` renders a blank page.
- AC-10: **The TLS note kept its page and its condition.** On a fresh
  instance serving a self-signed certificate, `GET /ca` contains an
  element `id="tls-setup-note"`; on the same instance after a hierarchy
  is created it does not; with TLS off it does not, before or after.
  Three states, one test, the same page, as `test_web_tls_ui.py:661`
  already does for `/setup`.
  _Goes red if_: the note is rendered unconditionally on the new page,
  or is dropped with `ca_setup.html`.
- AC-11: **The classes the templates use are styled.** No class name
  appearing in a `class="..."` attribute of any template is absent from
  `cabin.css` — `.ca-row`, `.inline-form` and `.constraints` named
  explicitly, since they are today's three offenders — and `details`
  has a rule. Measured additionally as effect in headless Chrome on
  `/ca/{alpha_root}` at 1440: a `.ca-row` element's computed
  `border-top-width` or vertical padding is greater than zero, and a
  `<details>` element's computed border is not `none`.
  _Goes red if_: the classes are dropped from the markup but left in
  the stylesheet, or given a rule that sets nothing visible.
- AC-12: **No page scrolls sideways.** 0015 AC-1 and AC-2 repeated with
  `/ca/{ca_id}`, `/ca/new` and `/ca/import` added to the page list
  (`test_web_layout.py:484`): at 1440×1150 and at 390×900, with two
  hierarchies, two intermediates and a cross certificate,
  `document.scrollingElement.scrollWidth` does not exceed
  `clientWidth` and no element's right edge extends past its
  container's.
- AC-13: **Everything that was not this spec's subject still works.**
  The 0004–0022 suite passes with no change to any POST path, form
  field or guard: `/ca/create`, `/ca/import`, `/ca/cross-import`,
  `/ca/{id}/intermediate`, `/ca/{id}/cross-sign`, `/ca/{id}/renew` and
  `/ca/{id}/retire` answer as before, `POST /ca/import` still redirects
  to `/ca`, the audit events and grants written by each are unchanged,
  and `/api/v1` and MCP are untouched. The only test changes are the
  ones the "Test list" names.

## Test list

test_ca_list_has_no_forms_and_links_each_hierarchy,
test_ca_list_empty_state_links_for_admin_and_not_for_viewer,
test_ca_detail_shows_only_its_own_hierarchy,
test_ca_detail_404_for_a_non_root_id,
test_intermediate_error_refills_the_form_and_opens_the_details,
test_intermediate_error_writes_no_row,
test_form_errors_render_the_page_that_owns_the_form,
test_rail_marks_the_ca_group_entries,
test_overview_group_holds_only_the_dashboard,
test_viewer_reads_the_detail_page_and_sees_no_form,
test_viewer_rail_has_no_ca_new_or_ca_import,
test_cross_sign_candidates_come_from_every_row,
test_ca_routes_are_not_shadowed_by_the_detail_route,
test_ca_setup_template_is_gone_and_forms_are_not_duplicated,
test_tls_setup_note_only_on_an_empty_ca_page_when_self_signed,
test_every_template_class_has_a_rule,
test_ca_row_and_details_are_visually_separated (headless Chrome),
test_no_horizontal_overflow (0015, three pages added)

Existing tests that change, all named because each is load-bearing:

- `test_web_ca.py:374` scopes with `_row(html, ..., class_name="section")`
  on the assumption that one root group is one `.section` on `/ca`. It
  becomes two GETs of two detail pages — the generated root's page
  offering `/ca/{id}/intermediate` and `/ca/{id}/renew`, the imported
  root's page offering neither — keeping both halves in one test.
- `test_web_ca.py:198` `test_ca_wizard_ui_flow` asserts `/ca` contains
  "Create a new CA" before the first CA. It asserts FR-2's empty state
  and its links instead.
- `test_web_ca.py:529-533` asserts an imported intermediate's name on
  `/ca`; it moves to that hierarchy's detail page.
- `test_web_name_constraints.py:487` slices
  `html[beta_int_i:html.index("Create a new CA")]`, which depends on
  the create form sitting under the groups. It moves to beta's detail
  page and scopes with `_row(...)`. **The character-window pattern is
  replaced, never widened** — that is what compacted production markup
  once already.
- `test_web_name_constraints.py:543` asserts the import form carries no
  constraint field _on both templates_. With one template left it
  asserts it once, and its counter-proof — that the create form does
  grow those fields — moves to `/ca/new`.
- `test_web_layout.py:224` maps `/ca` to "Certificate authority" and
  needs "Hierarchies" plus the three new pages; `:242` lists what a
  viewer must not see and gains `/ca/new` and `/ca/import`; `:484`
  gains the three pages; `:53` covers the new templates for free.
- `test_web_tls_ui.py:661` keeps its URL and both halves (FR-10).

`test_web_dashboard.py` and `test_web_tls_ui.py` still scope with fixed
character windows. They are not rewritten here unless this work touches
them; if it does, they are replaced by `_row(...)`-style element
scoping rather than given a bigger window.

## Out of Scope

No change to permissions, CSRF, sessions, data, migrations or any POST
path — this is a page split. No version bump: 0.2.0 and PR #17 stay as
they are.

Re-filling the create and the import forms after an error. FR-8 fixes
the intermediate form because that is the defect this spec names; the
other three lose their contents on a refusal exactly as they do today.
Widening it would be a second change measured by no criterion here, and
it is recorded rather than left to be discovered.

The bare `HTTPException` on `POST /ca/{ca_id}/renew` and
`POST /ca/{ca_id}/retire` (`ca_ui.py:660, 666, 692, 698`). Both carry a
single number and lose nothing an operator typed, so the argument FR-8
makes does not apply — but the TLS-issuer refusal
(`ca_ui.py:169-172`) is a sentence worth reading and it still arrives
as a JSON error document. A later spec can render it on the detail page
now that one exists.

New columns, sorting, filtering or paging on `/ca`; a hierarchy count
large enough to need any of those is not a state this project has seen.
Merging the dashboard's CA expiry table (`ui.py:269-295`) into the new
list, which duplicates some of it — the dashboard's job is what is
about to expire, the list's is what exists. New layout primitives. A
dark/light toggle. Client-side interactivity beyond the htmx already in
use.
