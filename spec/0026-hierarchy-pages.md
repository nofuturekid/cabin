# Spec 0026 — Hierarchy Tables and Row Pages

## Context

Spec 0023 gave every hierarchy its own page and spec 0024 re-laid that
page out. An operator clicked through the result on a fresh instance and
said the issuers are "not visible without scrolling", and that each one
takes up a great deal of space.

That is a structural fact rather than a matter of taste.
`ca_detail.html` renders, in this order: the root section, the
_Add intermediate_ form, the _Cross-sign_ form, then one full `.section`
per intermediate (`ca_detail.html:133-153`) and one per cross
certificate (`:155-167`). The two forms are tall — five fields and two —
and every intermediate is a section with a four-to-five line floor plus
its CRL/AIA pair, its ACME directory line, its constraints block and its
renew and retire forms. Everything that repeats is therefore below
everything that does not.

**The measurement, as evidence and not as a requirement.** On the
fixture this spec re-uses — one root, two intermediates, one of them
carrying name constraints, rendered for an admin in headless Chrome at
1440 — the page is **2368 pixels** tall today, and the first
intermediate starts below the fold. The same fixture is measured again
after the change and the number recorded beside it here. Neither number
is an acceptance criterion: a pixel bound measures font metrics and the
Chrome version as much as it measures this layout. What is a criterion
is the relation between them (FR-15, AC-13) — an intermediate must cost
a table row, not a section.

> Measured after the change: _to be recorded on the same fixture, in the
> same probe, when the implementation lands._

Asked between three shapes, the operator chose one, and two of the four
decisions below came from him directly and are not reopened here:

- **the intermediates become a compact table directly under the root,
  and everything else about an intermediate moves to its own page**;
- **the two forms move below the tables.**

Cross certificates get the same treatment, for the reason FR-3 gives.

This is the move spec 0023 already made once — a page carrying both a
list and full detail is split into a list plus per-item pages — and
`.scroller` + `<table>` is what `/ca` itself (`ca_list.html:14-35`),
`certs_list.html:38-52`, `users.html`, `tokens.html` and `audit.html`
all already use for many short rows. No layout primitive is invented
here and no CSS class is added (FR-14).

**Two things this must not do.** It must not reintroduce `<details>`:
spec 0024 FR-8 removed it deliberately, argued at length, and two tests
forbid it (`test_ca_names_and_actions.py:1079` counts the tag on the
page, `:1237` forbids it in every template and in the stylesheet). And
it must not reach for htmx: htmx is vendored and loaded by
`layout.html`, but nothing in this project has ever used it, and every
interaction here is a link or a form POST.

### Where the controls go, and what follows from it

Renew and retire move to the row's own page, because a row's controls
belong with that row's detail. Three consequences follow, none of them
optional and none of them visible in a green test suite today:

- The retire form must keep its confirmation checkbox immediately before
  its danger button, in the same `<form>` (spec 0024 FR-9). That holds
  by construction once the markup becomes a shared macro (FR-13) rather
  than a second copy.
- **`ca_retire`'s unticked-confirm branch must re-render the page that
  owns the form** (FR-10). Today it renders the root page
  (`ca_ui.py:782`); after the split that page no longer carries the form
  the operator just failed to submit. This is spec 0023 FR-7's rule —
  an action started on a page comes back to that page — applied to the
  pages this spec adds.
- **Redirects follow the row** (FR-11). After retiring an intermediate
  the operator must land on that intermediate and see `retired` with the
  controls gone, not on the root page wondering whether anything
  happened. No existing test asserts these `Location` headers, so this
  needs a new assertion rather than an edited one.

## User Stories

- As an operator opening a hierarchy, I see its issuers immediately,
  as a short table under the root, and I do not scroll past two forms
  to reach them.
- As an operator, a hierarchy with four issuers is one screen longer
  than a hierarchy with one, not four screens longer.
- As an operator who wants everything about one issuer — its CRL, its
  AIA, its ACME directory, its constraints, its downloads, renew and
  retire — that is one page, and its URL says which hierarchy it belongs
  to.
- As an operator who has just created a root, the page tells me it has
  no issuer yet and takes me to the form that adds one, instead of
  showing me an empty stretch of page.
- As an operator with two cross certificates on one root, I can tell
  them apart, because the table says who signed each one.
- As an operator retiring an issuer, I confirm it on that issuer's own
  page, I am refused on that same page if I forget to tick, and I land
  back on it afterwards.
- As a viewer, I can read both new pages in full and cannot see a single
  control that would answer 403.

## Functional Requirements

- FR-1: **`/ca/{root_id}` in a new order.** The page renders, top to
  bottom:
  1. page head and error box — unchanged;
  2. the **root section** — unchanged, including its own renew and
     retire forms. A row's controls sit with that row's detail, and the
     root's detail is on this page;
  3. **Issuers** (FR-2), or the empty state (FR-4);
  4. **Cross certificates** (FR-3), when any exist;
  5. **Add intermediate** — the same content it has today
     (`ca_detail.html:59-101`), moved here, and gaining
     `id="add-intermediate"` on its `.section` so FR-4's empty state can
     link to it;
  6. **Cross-sign with another root** — the same content it has today
     (`ca_detail.html:103-131`), moved here.

  The root section keeps every field it carries today: its tags and
  expiry, the `Serving:` sentence naming the default and alternate
  chains, its `root.pem` link, its subject and fingerprint, its
  constraints block and its renew and retire forms. It is the one row
  whose detail is not on a page of its own, because this page _is_ its
  page (FR-11 maps a root to `/ca/{id}`).

- FR-2: **The issuers table.** A `.section` headed `Issuers` whose left
  column carries the `.help` line and whose right column carries a
  `<div class="scroller">` around a `<table>`, one row per intermediate
  of this root, in the order `_group` already produces them. Columns:

  | Column  | Contents                                       |
  | ------- | ---------------------------------------------- |
  | Name    | the row's name, and it is the link to its page |
  | Status  | the status tag, `tag-bad` when retired         |
  | Expires | `not_valid_after`, `class="nowrap"`            |

  **The name cell is the link**, as in `ca_list.html:27` and
  `certs_list.html:40`. A separate `Open` column would repeat the name
  as a target and cost a fourth column at 390 pixels, where the table
  has the least room.

  Nothing else about an intermediate is on this page: no subject, no
  fingerprint, no `cert.pem` or `chain.pem` link, no CRL or AIA URL, no
  ACME directory URL, no constraints block, no renew and no retire form.
  All of it is on that intermediate's own page (FR-6), and AC-2's second
  half asserts its absence here so that "moved" cannot quietly become
  "duplicated".

- FR-3: **The cross-certificate table.** The same shape, headed
  `Cross certificates`, **omitted entirely when this root has none** —
  a heading over an empty table is a page telling an operator about a
  feature in answer to a question nobody asked. Columns:

  | Column    | Contents                                        |
  | --------- | ----------------------------------------------- |
  | Name      | the row's name, and it is the link to its page  |
  | Signed by | the name of the root whose key signed it        |
  | Status    | the status tag                                  |
  | Serving   | `default`, `alternate` or `not served`, as tags |
  | Expires   | `not_valid_after`, `class="nowrap"`             |

  **`Signed by` is not decoration.** A cross row's name equals its
  subject root's name (spec 0021 FR-1: it is a second certificate for
  the same subject and the same public key), so with two cross
  certificates for one root the name column shows the same string twice
  and the table cannot be read. The signer is the only column that tells
  them apart. It is the value `_group` already computes as `signed_by`
  (`ca_ui.py:360`).

  `Serving` stays on the table because it is the one thing about a cross
  row an operator scans for. The **full** explanatory clause — that a
  `not served` row is outside its validity window, was dropped
  automatically and needs no action — stays on the row's own page, where
  there is room for a sentence (FR-6, AC-16).

- FR-4: **A root with no intermediates says so, in three variants.**
  This is the normal state of every instance between creating a root and
  adding its first issuer (spec 0024 FR-3 made it so), and it is where
  the dashboard's `#ca-no-issuer` notice sends the operator. In place of
  the table, an element `id="ca-no-intermediates"` with class `note`,
  modelled on `ca_list.html:38`'s `#ca-empty`:
  - **admin, root with a key**: says this hierarchy has no issuer yet
    and links to `#add-intermediate`, the form further down this same
    page;
  - **viewer**: says the same and carries no link, because the form is
    not rendered for a viewer at all (spec 0023 FR-3) and a link to an
    anchor that does not exist is worse than no link;
  - **admin, root whose key this instance does not hold**: says that
    too. `can_create_intermediate` is `False` for an imported root
    (`ca_ui.py:245`), so `Add intermediate` is not on the page and the
    anchor does not exist. Pointing at it would send an operator to a
    form that is not there, and the reason — no private key here — is
    what they actually need to read.

- FR-5: **Two new pages.**

  | Method | Path                                       | Guard     |
  | ------ | ------------------------------------------ | --------- |
  | GET    | `/ca/{root_id:int}/issuer/{issuer_id:int}` | logged in |
  | GET    | `/ca/{root_id:int}/cross/{cross_id:int}`   | logged in |

  One new template, `ca_issuer.html`, and one renderer, `_issuer_page`,
  serve both: the two pages differ in which fields their row has, not in
  what kind of page they are.

  **Two paths rather than one** because cabin reserves the word
  "issuer" for something that signs leaves — that is what
  `resolve_issuer`, `active_issuers` and every ACME directory URL mean
  by it — and a cross certificate signs nothing. One URL covering both
  would be a page lying about what it shows.

  **Nested under the root, not a generalisation of `/ca/{ca_id}`.**
  That path means "the hierarchy whose root is `{ca_id}`" and refuses
  every non-root id, a refusal pinned by
  `test_web_ca_pages.py::test_ca_detail_404_for_a_non_root_id`. Widening
  it would overturn a requirement one spec after it was written. Nesting
  costs nothing — both ids are in hand wherever the link is rendered —
  and it buys the guard of FR-7: a URL naming a row and a hierarchy that
  do not belong together is caught rather than served.

  `:int` on **both** parameters, for the reason spec 0023 FR-9 gives:
  without the converter a non-numeric segment reaches the handler and
  answers 422 from conversion instead of 404 from routing (AC-8).

- FR-6: **What a row's own page carries.** For an intermediate, exactly
  what `ca_detail.html:133-153` renders for it today, and for a cross
  row exactly what `:155-167` renders:
  - a back link to `/ca/{root_id}` naming the root, the shape
    `cert_detail.html:7` already uses;
  - an identity table — kind, status, valid from and until, subject,
    fingerprint, and for a cross row the signing root and its serving
    state — in the `.scroller` + key/value `<table>` shape
    `cert_detail.html:21-38` already uses;
  - the downloads: `cert.pem` for either kind, and `chain.pem` for an
    intermediate;
  - the published URLs: the CRL and AIA pair for an intermediate, or the
    existing note that no base URL is set and where to set one; and the
    ACME directory URL when ACME is enabled;
  - the name-constraints block when the row carries constraints;
  - the renew and the retire sections, under the same `nav.ca_admin`
    gate and with the same per-kind `.help` sentences the row has today.

  **Every sentence is lifted verbatim** from `ca_detail.html` — the
  no-base-URL note, the two retire warnings, the cross row's "this is
  not a revocation" paragraph. The wording an operator recognises, and
  the substrings a dozen existing tests match on, both survive the move
  intact; anything reworded here would be a second change measured by no
  criterion in this spec.

- FR-7: **Every refusal of the two new routes, one at a time.** One
  helper, `_load_pair(db, root_id, row_id, *, kind)`, is the only place
  these live, so the two routes cannot drift apart:

  | #   | Condition                                             | Answer |
  | --- | ----------------------------------------------------- | ------ |
  | 1   | `root_id` names no row                                | 404    |
  | 2   | `root_id` names a row whose `kind` is not `root`      | 404    |
  | 3   | `row_id` names no row                                 | 404    |
  | 4   | on `/issuer/`, the row's `kind` is not `intermediate` | 404    |
  | 5   | on `/cross/`, the row's `kind` is not `cross`         | 404    |
  | 6   | an intermediate whose `parent_id` is not `root_id`    | 404    |
  | 7   | a cross row whose `cross_of_id` is not `root_id`      | 404    |

  Refusals 4 and 5 are each two cases worth naming: `/issuer/` refuses
  both a root id and a cross id, `/cross/` refuses both a root id and an
  intermediate id. Refusal 2 reuses `ca_detail`'s own wording, "a
  hierarchy is named by its root, not by this id" (`ca_ui.py:483`),
  because it is the same refusal.

- FR-8: **The cross-certificate guard is written against `cross_of_id`,
  and this is the paragraph that says why.** On a `kind == "cross"` row
  the two foreign keys mean different things: `parent_id` is the
  **signing** root, whose key produced the certificate, and
  `cross_of_id` is the **subject** root, whose name and public key the
  certificate carries. The row is displayed under its subject —
  `_group` selects `cross_of_id == root.id` (`ca_ui.py:333`), and
  `test_cross_chains.py::test_ca_page_shows_the_cross_row_under_the_subject_root`
  pins it.

  A guard written against `parent_id` would therefore be exactly wrong
  and would still look right in a hurry. It would refuse
  `/ca/{subject}/cross/{id}` — the URL the table on the subject's page
  actually links to — and serve `/ca/{signer}/cross/{id}`, a page
  reachable from no table on the instance. The failure is silent in the
  ordinary case where an instance has one cross certificate and a test
  fixture that happens to build the URL the same wrong way.

  Both directions are asserted, in one criterion (AC-7): under the
  subject root the page is 200, under the signing root it is 404. A
  criterion carrying only the 404 half would pass against an
  implementation that refuses every cross page there is.

- FR-9: **A mismatch is a 404, not a redirect and not a 403.**

  Not a redirect to the correct hierarchy: the next thing an operator
  does on that page is renew or retire, and a silently corrected URL
  means acting on a hierarchy they did not think they had open. This is
  the rule `ca_chain_pem` already applies to a bad `?anchor=` — "a
  client that asked for a specific anchor and got a different one has
  been misinformed about the one thing it asked about"
  (`ca_ui.py:825-831`).

  Not a 403: every logged-in user, viewer included, may read every row
  at its correct URL (FR-5's guard), so a 403 would claim a boundary
  that does not exist and would tell an operator to go and ask for a
  permission that would not help.

- FR-10: **The unticked retire re-renders the page that owns the
  form.** `ca_retire`'s confirmation branch (`ca_ui.py:781-782`)
  currently renders `_detail_page` for `_root_of(row)` whatever the row
  is. After this spec that page carries the retire form only when the
  row is the root itself. The branch chooses by kind: `_detail_page` for
  a root, `_issuer_page` for an intermediate or a cross row. Status code
  400 and the message are unchanged, and so is the rule spec 0024 FR-9
  set — the row is not touched before the check.

- FR-11: **Renew and retire redirect to the row's own page.** A new
  `_page_of(row)` is the only place the mapping lives:

  | Row kind       | Page                           |
  | -------------- | ------------------------------ |
  | `root`         | `/ca/{id}`                     |
  | `intermediate` | `/ca/{parent_id}/issuer/{id}`  |
  | `cross`        | `/ca/{cross_of_id}/cross/{id}` |

  `POST /ca/{ca_id}/renew` and `POST /ca/{ca_id}/retire` redirect there
  instead of to `/ca/{root_of_row}`. This is not a new rule but spec
  0023 FR-7's own rule following the row: the page that owns the control
  is now the row's page, so that is where the 303 goes. After retiring
  an intermediate the operator sees that intermediate marked `retired`
  with its controls gone, which is the confirmation the redirect exists
  to give.

  `_page_of` is also what renders the `href` in both tables (FR-2,
  FR-3), so a link and a redirect can never disagree about where a row
  lives.

- FR-12: **A table row is built as a table row.** `_child_view` builds
  only what FR-2 and FR-3 display — id, name, status, expiry and href —
  and calls neither `leaf.constraints_of`, nor
  `crl_service.distribution_url`, nor `crl_service.ca_issuers_url`, nor
  `acme_http.directory_url`. It parses the row's certificate once,
  through `ca_x509.describe_certificate`, exactly as `_overview` does
  and for the reason `_overview`'s docstring gives.

  This is spec 0023 FR-2's argument one level down. The root page today
  parses three certificates through `_cert_info` and makes four URL
  lookups per intermediate that its new shape does not display; leaving
  that work in place would mean a page doing hidden work for output it
  no longer produces, and the next reader could not tell which of the
  two — the work or the output — was the mistake. AC-12 measures the
  calls rather than the markup, because markup absence is equally
  consistent with the lookups still running.

- FR-13: **One copy of the renew/retire markup.** A new
  `ca_macros.html` holds `constraints_block` and `renew_retire`, moved
  out of `ca_detail.html:14-42` unchanged, and both pages import them.

  `renew_retire` is the markup that carries the confirmation checkbox
  spec 0024 FR-9 requires in the same `<form>` as the danger button.
  Two drifting copies of it is a security-shaped defect: the copy that
  loses its checkbox still renders a working red button, and the test
  that would catch it (AC-14) has to be pointed at the page that has the
  bad copy. One definition removes the possibility rather than testing
  for it.

  This costs exactly one honest test edit.
  `test_web_layout.py::test_every_content_template_sets_nav_current`
  requires every template outside a fixed exclusion set to declare its
  `nav_current`, and a macro library is not a page: it extends nothing,
  defines no `content` block and is never rendered on its own. The
  exclusion set gains `ca_macros.html`, and — so that the exclusion
  cannot later hide a real page that forgot its `nav_current` — the same
  test asserts that `ca_macros.html` neither extends a layout nor
  defines a content block, and that every non-excluded template does
  extend `layout.html` (AC-18).

- FR-14: **`cabin.css` is not touched, and that is a requirement rather
  than an outcome.** Both tables live in a `.section`'s right column
  inside a `.scroller`; the identity table of FR-6 reuses
  `cert_detail.html`'s key/value pattern; the empty state reuses
  `.note`. No class gains a first user and none loses its last, so
  `test_stylesheet_and_templates_agree_in_both_directions`
  (`test_ca_names_and_actions.py:1237`) passes in both directions by
  construction once the two new pages are added to its page list
  (AC-15). If a layout need seems to want a new class, the answer is
  `.section` + `.scroller`; spec 0015 FR-3/FR-5/FR-6 already provide
  every primitive this page uses.

- FR-15: **The height requirement is a relation, not a number.** The
  requirement is that **an intermediate costs a table row, not a
  section**. It is measured as growth: the same hierarchy rendered with
  one intermediate and with four, and the per-intermediate increment
  bounded (AC-13). A hard pixel bound on the page would measure the font
  metrics and the Chrome version of whoever runs it; a growth bound
  measures the thing the spec actually claims. The absolute numbers in
  Context are evidence that the problem was real, and nothing asserts
  them.

- FR-16: **No `<details>`, and no htmx.** No template gains a
  `<details>` or `<summary>` element, and no new page carries an
  `hx-` attribute. Spec 0024 FR-8 removed the disclosure deliberately —
  every other form in cabin stands open in its own headed `.section` —
  and reintroducing it to make a long page shorter would be this spec's
  problem solved by re-creating the previous spec's. Every interaction
  added here is a link or a form POST.

- FR-17: **The dashboard's notice keeps its href.** `#ca-no-issuer`
  links `/ca/{root_id}`, with no fragment, and does not change. Three
  tests assert exact membership in that notice's `anchor_hrefs`
  (`test_ca_names_and_actions.py:841, 903, 926`), and the page it lands
  on now carries its own empty state (FR-4) pointing further down. A
  fragment added here would break three assertions to save a scroll the
  page already handles.

- FR-18: **Templates are edited by a script through Bash, never with
  Edit/Write**, and `git diff` is read after every template change: the
  PostToolUse formatter breaks Jinja tags apart, turning
  `{% if x == "y" %}` into `{% if x="" ="y" %}`. This has cost this
  project a debugging session four times (0021 FR-13, 0023 FR-11, 0024
  FR-10, 0025 FR-15), and this spec rewrites one template and writes two
  new ones. Its check is the diff read after each edit, plus AC-20's
  suite.

## Interface Contract

### Routes

| Method | Path                                       | Auth         | Change                                                 |
| ------ | ------------------------------------------ | ------------ | ------------------------------------------------------ |
| GET    | `/ca/{root_id:int}/issuer/{issuer_id:int}` | session      | new — one intermediate in full                         |
| GET    | `/ca/{root_id:int}/cross/{cross_id:int}`   | session      | new — one cross certificate in full                    |
| GET    | `/ca/{ca_id:int}`                          | session      | reordered; per-row detail replaced by two tables       |
| POST   | `/ca/{ca_id}/renew`                        | admin + CSRF | unchanged but for its redirect target (`_page_of`)     |
| POST   | `/ca/{ca_id}/retire`                       | admin + CSRF | unchanged but for its redirect target and its 400 page |

No other route changes: `/ca`, `/ca/new`, `/ca/create`,
`/ca/{root_id}/intermediate`, `/ca/{ca_id}/cross-sign`,
`/ca/{ca_id}.pem`, `/ca/{issuer_id}/chain.pem`, everything under
`/transfer`, `/api/v1`, MCP, ACME and the CRL routes are untouched in
path, method, guard, form fields and response.

Nothing shadows anything: both new paths have three segments after
`/ca`, so they cannot collide with `/ca/{ca_id:int}` (one),
`/ca/{ca_id}/renew` or `/ca/{issuer_id}/chain.pem` (two). AC-8 asserts
this against the running application rather than reasoning about it,
the way spec 0023 AC-8 does.

### `cabin.web.ca_ui`

```python
def _child_view(row: CACertificate) -> dict[str, object]: ...


def _page_of(row: CACertificate) -> str: ...


def _load_pair(
    db: Session, root_id: int, row_id: int, *, kind: str
) -> tuple[CACertificate, CACertificate]: ...


def _group(db: Session, rows: list[CACertificate], root: CACertificate) -> dict[str, object]: ...


def _issuer_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    row: CACertificate,
    error: str | None,
    *,
    status_code: int = 200,
) -> Response: ...
```

This contract enumerates every key that changes shape, including the
ones inside the dictionaries. Spec 0024's contract said of a context
change that it "gains one flag ... no other key changes"; implementing
that sentence faithfully produced a defect that survived a green suite,
and the correction is recorded in that spec's Interface Contract. A
summary sentence is not a contract.

- **`_child_view`** returns exactly five keys and no others: `id`,
  `name`, `status`, `not_valid_after`, `href`. `href` is `_page_of(row)`
  (FR-11). It parses the row's certificate through
  `ca_x509.describe_certificate`, never `_cert_info` (FR-12).

- **`_page_of`** takes the row alone. The mapping is FR-11's table and
  needs no `Session`: `parent_id` and `cross_of_id` are on the row.
  `_root_of` (`ca_ui.py:393`) keeps its `db` parameter because it
  loads the parent row, and keeps exactly one call site — FR-10's
  re-render, which needs the root **row** to build an issuer page, not a
  path.

- **`_load_pair`** answers FR-7's seven refusals with
  `HTTPException(404)` and otherwise returns `(root, row)`. `kind` is
  `"intermediate"` or `"cross"`. It is the only place those checks
  exist.

- **`_group` loses its `acme_enabled` keyword.** Its remaining
  signature is `(db, rows, root)`. Its returned keys keep their names,
  and two of them change contents:

  | Key                     | Before                              | After                                              |
  | ----------------------- | ----------------------------------- | -------------------------------------------------- |
  | `root`                  | `_row_view(...)`                    | unchanged                                          |
  | `intermediates`         | list of `_row_view(...)`            | list of `_child_view(...)` — five keys             |
  | `cross_certificates`    | `_row_view` + `signed_by`, `served` | `_child_view` + `signed_by`, `served` — seven keys |
  | `chain`                 | unchanged                           | unchanged                                          |
  | `cross_sign_candidates` | unchanged                           | unchanged                                          |

  What the two lists **lose**, named individually because a template
  reading a key that is no longer there renders an empty string in
  silence: `subject`, `fingerprint`, `not_valid_before`, `kind`,
  `can_create_intermediate`, `can_renew`, `can_retire`, `crl_url`,
  `ca_url`, `acme_directory_url`, `has_constraints`, `permitted_dns`,
  `permitted_ip`, `excluded_dns`, `excluded_ip`, and everything else
  `describe_certificate` puts into `_cert_info`. All of it is on the
  row's own page instead (FR-6).

- **`_row_view` is unchanged**, in signature and in body. `_group` now
  calls it exactly once, for the root, with `acme_enabled=False`. That
  is not a behaviour change: `_row_view` computes
  `acme_directory_url` only on its `is_intermediate` branch
  (`ca_ui.py:250-252`), and a root is never an intermediate, so the
  flag's value cannot reach the result. `_issuer_page` passes the real
  flag (below).

- **`_detail_page` keeps its signature exactly** —
  `(request, db, user, root, error, *, values=None, status_code=200)` —
  and stops calling `get_flag(db, ACME_ENABLED)`, because nothing it
  renders depends on it any more. That lookup moves to `_issuer_page`.

- **`_issuer_page`** is the one renderer for `ca_issuer.html`, used by
  both GETs and by FR-10's 400. Its context, over `base_context`:
  `error`; `root` as `{"id", "name"}` for the back link; and `row`, a
  full `_row_view(db, row, parent_has_key=..., acme_enabled=get_flag(db, ACME_ENABLED))`
  plus, for a cross row, `signed_by` and `served` computed from
  `ca_service.chains_for(db, root.id)` exactly as `_group` computes them
  today (`ca_ui.py:337-363`).

  **`parent_has_key` is read from `row.parent_id`, not from `root`.**
  For an intermediate the two are the same row; for a cross row they are
  not — `parent_id` is the signing root (FR-8) — and `_row_view` uses
  `parent_has_key` to decide `can_renew` (`ca_ui.py:237`). Taking it
  from the subject root would offer a Renew button on an imported cross
  certificate that only ever 500s, and hide the button on a cross
  certificate cabin itself signed. AC-5 asserts both halves.

  `ca_issuer.html` sets `nav_current = "ca"`, marking the `Hierarchies`
  entry, as a detail page marks its list entry (spec 0023 FR-6).

### `cabin.web.templates`

- `ca_detail.html` — reordered (FR-1); the two per-row loops become two
  tables; `constraints_block` and `renew_retire` are imported from
  `ca_macros.html` instead of defined inline.
- `ca_issuer.html` — new (FR-6).
- `ca_macros.html` — new (FR-13). Holds `constraints_block` and
  `renew_retire`, moved unchanged. It is not a page: no `{% extends %}`,
  no `content` block, no `nav_current` (AC-18).

### `cabin.web.static/cabin.css`

Untouched (FR-14).

### Schema, services, API, MCP, ACME

Unchanged. No migration, no column, no change to `ca/service.py`,
`api/`, `mcp/` or `acme/`. No audit action is added: this spec adds two
`GET`s and moves two redirect targets, and spec 0009 FR-4 audits state
changes, not reads.

## Acceptance Criteria

Every criterion is anchored to the element it is about — the form with
that action, the `<tr>` containing that link, the row in the database —
never to a substring appearing somewhere in the page. This project has
shipped UI tests that passed while the feature was visibly broken, most
recently an assertion that could not fail because the template escaped
an apostrophe in the string being searched for. Scoping is by parsed
element or by `_row(...)`, as `test_web_ca_pages.py` already does.

Where a state is meant to differ, both halves are in one criterion: a
build that renders nothing and a build that renders everything must each
fail. That rule does the most work in AC-7, where a criterion asserting
only the 404 would be green against an implementation whose cross pages
all 404.

The fixture, unless stated otherwise: hierarchy **alpha** (root with
`path_length=2`, one intermediate carrying `permitted_names`), hierarchy
**beta** (default `path_length`, one intermediate), a cross certificate
for beta's root signed by alpha's root, and a base URL set so CRL and
AIA URLs exist.

- AC-1: **The tables are above the forms, and the anchor exists.** On
  `GET /ca/{beta_root}` as an admin, five blocks are located with
  `_row(...)` — the root's own `.section` by its `<h2>`, the `Issuers`
  section, the `Cross certificates` section, the `.section` holding
  the `<form>` with action `/ca/{beta_root}/intermediate` and the one
  holding `/ca/{beta_root}/cross-sign` — and their positions in the
  document are asserted to be in that order. The order is asserted
  over blocks that were each parsed out first, never over a raw
  `index()` of a bare string. The `.section` holding the intermediate
  form carries `id="add-intermediate"`.
  _Goes red if_: the tables are added but the forms stay above them,
  which is the operator's actual complaint and which no other criterion
  here would notice.

- AC-2: **An intermediate is a row, and only a row.** On
  `GET /ca/{alpha_root}`, the `Issuers` table has exactly one `<tr>` in
  its `<tbody>`; that row's first cell contains an `<a>` whose `href` is
  `/ca/{alpha_root}/issuer/{alpha_int}` and whose text is the
  intermediate's name; the row also contains its status and its
  `not_valid_after`. In the same test the whole page contains none of:
  the intermediate's fingerprint, its subject, `href="/ca/{alpha_int}.pem"`,
  `/ca/{alpha_int}/chain.pem`, its CRL URL, its AIA URL, its ACME
  directory URL, its permitted-name entry, or a `<form>` with action
  `/ca/{alpha_int}/renew` or `/ca/{alpha_int}/retire`.
  _Goes red if_: the table is added beside the sections rather than in
  place of them — the page would then be longer than before and every
  other criterion here would still pass.

- AC-3: **The cross table tells two rows apart, and does not exist
  without rows.** With a **second** cross certificate for beta's root,
  signed by a third root created with `path_length=2` so that it can
  carry the extra hop, `GET /ca/{beta_root}`'s
  `Cross certificates` table has two `<tr>` elements; the two rows carry
  the same name (spec 0021 FR-1) and different `Signed by` cells, naming
  alpha's root and the third root respectively; each row's name cell
  links to `/ca/{beta_root}/cross/{that row's id}`. On
  `GET /ca/{alpha_root}`, which has no cross certificate, the page
  contains no element with the heading `Cross certificates`.
  _Goes red if_: the signer column is dropped as redundant — the two
  rows are then indistinguishable — or if the empty table is rendered
  with a heading over it.

- AC-4: **The empty state, three variants, one test.** On a root created
  with no intermediate: for an admin, `GET /ca/{root}` contains
  `id="ca-no-intermediates"` whose `anchor_hrefs` include
  `#add-intermediate`, and the page contains an element with that id
  further down. For a viewer, the same element exists, contains no
  anchor at all, and the page's form actions are exactly `["/logout"]`.
  For an admin on an **imported** root (`key_sealed is None`), the
  element exists, contains no `#add-intermediate` link, and its text
  differs from the first variant's — asserted as a string inequality,
  not by matching a phrase. After an intermediate is added, the element
  is absent and the table has one row.
  _Goes red if_: all three variants render one sentence, if the keyless
  variant links to an anchor that is not on its page, or if the note
  survives the first intermediate.

- AC-5: **The row's page carries everything the root page lost, and
  renew follows the signing key.** `GET /ca/{alpha_root}/issuer/{alpha_int}`
  returns 200 and contains: the intermediate's subject and fingerprint,
  a link to `/ca/{alpha_int}.pem` and one to `/ca/{alpha_int}/chain.pem`,
  its CRL URL and its AIA URL as anchors, its ACME directory URL with
  ACME enabled, its permitted-name entry inside a constraints block, a
  `<form>` with action `/ca/{alpha_int}/renew` and one with action
  `/ca/{alpha_int}/retire` carrying an `input[name="confirm"]`, and a
  link back to `/ca/{alpha_root}`. For the cross row,
  `GET /ca/{beta_root}/cross/{cross_id}` contains its subject and
  fingerprint, its `cert.pem` link, the name of the signing root, the
  "not a revocation" paragraph, and — because alpha's root holds its key
  — a renew form. With a cross certificate imported through
  `POST /ca/cross-import`, whose signing root has no key on this
  instance, its own page carries **no** renew form while still carrying
  its identity table.
  _Goes red if_: a field is lost in the move (each is named separately,
  so the failure says which), or if `parent_has_key` is taken from the
  subject root — the last two halves are the only thing that catches
  that, and they disagree in opposite directions.

- AC-6: **Each refusal of FR-7, asserted on its own.** As a logged-in
  user, each of the following returns **404**, and none returns 200, a
  3xx or a 422: `/ca/999999/issuer/{alpha_int}`;
  `/ca/{alpha_int}/issuer/{alpha_int}` (a `root_id` naming an
  intermediate); `/ca/{alpha_root}/issuer/999999`;
  `/ca/{alpha_root}/issuer/{alpha_root}` (a root id in the issuer slot);
  `/ca/{alpha_root}/issuer/{cross_id}` (a cross id in the issuer slot);
  `/ca/{alpha_root}/cross/{alpha_int}` (an intermediate id in the cross
  slot); `/ca/{alpha_root}/issuer/{beta_int}` (an intermediate under a
  different root). In the same test `/ca/{alpha_root}/issuer/{alpha_int}`
  is 200, so a build refusing everything fails.
  _Goes red if_: any guard is missing, or a mismatch answers with a
  redirect to the correct hierarchy (FR-9) — which a status-code
  assertion catches and a "does it eventually show the right page"
  assertion would not.

- AC-7: **A cross row belongs to its subject root, both directions.**
  For the cross certificate on beta's root signed by alpha's root:
  `GET /ca/{beta_root}/cross/{cross_id}` returns 200 and names alpha's
  root as the signer, and `GET /ca/{alpha_root}/cross/{cross_id}`
  returns 404. In the same test, the `href` the cross table on
  `/ca/{beta_root}` renders for that row equals the URL that returned
  200 — so the table and the guard are proven to agree rather than
  separately asserted.
  _Goes red if_: the guard is written against `parent_id` (FR-8). The
  two halves then swap: the linked URL 404s and an unreachable one is
  served, and the third assertion says so in one line.

- AC-8: **Nothing shadows anything, and a non-numeric id is a 404.**
  `GET /ca/{alpha_root}/issuer/not-a-number` and
  `GET /ca/not-a-number/issuer/1` return **404, not 422**. In the same
  test `GET /ca/{alpha_root}` is 200, `GET /ca/{alpha_root}.pem` is 200
  with `application/x-pem-file`, `GET /ca/{alpha_root}.cer` is 200,
  `GET /ca/{alpha_int}/chain.pem` is 200 and `GET /ca/new` is 200.
  Asserted against the running application, not the route table.
  _Goes red if_: either parameter is declared without `:int` — spec 0023
  FR-9's failure exactly, one path deeper.

- AC-9: **The unticked retire is refused on the page that carries the
  form.** `POST /ca/{alpha_int}/retire` with no `confirm` returns 400;
  the response body contains the `<form>` whose action is
  `/ca/{alpha_int}/retire` **and** the back link to `/ca/{alpha_root}`,
  and contains no `<form>` with action
  `/ca/{alpha_root}/intermediate` — that is what distinguishes the
  issuer page from the root page in the response. `alpha_int`'s status
  in the database is still `active`. The same POST with `confirm="on"`
  returns 303 and the status is `retired`.
  _Goes red if_: the branch still renders the root page, which carries
  no retire form for this row at all — the operator would be looking at
  an error message about a control that is not on their screen.

- AC-10: **Every redirect lands on the row that was acted on.** Three
  `Location` headers, in one test, with `follow_redirects=False`:
  `POST /ca/{alpha_root}/renew` → `/ca/{alpha_root}`;
  `POST /ca/{alpha_int}/renew` → `/ca/{alpha_root}/issuer/{alpha_int}`;
  `POST /ca/{cross_id}/retire` with `confirm="on"` →
  `/ca/{beta_root}/cross/{cross_id}`. Each redirect is then followed and
  returns 200, so a well-formed path that no route serves fails here.
  _Goes red if_: the redirect keeps going to the root page (the operator
  loses sight of what they changed), or if a cross row is sent to
  `/ca/{parent_id}/cross/{id}` — FR-8's trap on the redirect side, which
  the follow-up GET turns into a 404.

- AC-11: **A viewer reads both new pages and sees no control.** As a
  viewer: `GET /ca/{alpha_root}/issuer/{alpha_int}` and
  `GET /ca/{beta_root}/cross/{cross_id}` both return 200, each contains
  the row's fingerprint and — for the issuer page — its CRL URL, and
  `_form_actions(...)` on each is exactly `["/logout"]`. In the same
  test an admin's `/ca/{alpha_root}/issuer/{alpha_int}` contains form
  actions `/ca/{alpha_int}/renew` and `/ca/{alpha_int}/retire`.
  _Goes red if_: the pages are gated to admins (a viewer can already
  read every one of these fields today), or if the controls are rendered
  for everybody and refused only at the POST.

- AC-12: **The root page does the work its output needs, and no more.**
  With `crl_service.distribution_url`, `crl_service.ca_issuers_url`,
  `acme_http.directory_url` and `leaf.constraints_of` wrapped in
  counting spies, rendering `GET /ca/{beta_root}` on a hierarchy with
  two intermediates and one cross row calls the first three **zero**
  times and `constraints_of` **once** (the root's own block). Rendering
  `GET /ca/{beta_root}/issuer/{beta_int}` calls each of the first three
  exactly once.
  _Goes red if_: `_child_view` is written as a thinner `_row_view`
  wrapper that still computes the URLs and drops them at the template —
  the markup is identical either way, which is why this is measured at
  the call and not on the page.

- AC-13: **Per-intermediate growth is bounded.** In headless Chrome at
  1440, one root with **one** intermediate and the same root with
  **four**, rendered for an admin and measured as
  `document.body.scrollHeight`: `(h4 - h1) / 3` is under 80 pixels. In
  the same test the four-intermediate page contains four `<a>` elements
  whose `href` matches `/ca/{root}/issuer/`, and `h4 > h1`.
  _Goes red if_: an intermediate is still a section (today's shape adds
  roughly 300 pixels each), or — and this is what the last two
  assertions are for — if the table renders no rows at all, which would
  make the growth bound pass perfectly.

- AC-14: **Every dangerous button on every new page has its
  confirmation, and every section has a heading.** The section probe and
  the danger probe of `test_ca_names_and_actions.py` run over three
  pages — the root page, an issuer page and a cross page — each
  preceded by a `_count_danger_buttons(html) >= 1` sanity assertion, so
  a page that renders no button cannot pass by having nothing to check.
  Every `.section` on each page has a first child element whose
  `textContent.trim()` is non-empty, and every `button.danger` has an
  `input[name="confirm"]` inside the same `<form>`.
  _Goes red if_: the retire markup is copied instead of shared (FR-13)
  and one copy loses its checkbox, or if a table is dropped into a
  section with no heading, recreating the empty left column spec 0024
  FR-8 removed.

- AC-15: **No disclosure, no new class, both directions.** Across all
  three pages, `<details>` and `<summary>` each occur zero times, and no
  template file contains `<details`. `cabin.css` is byte-identical to
  its state before this spec. Every class name appearing in a
  `class="..."` attribute of the two new pages has a rule in
  `cabin.css`, with those two pages added to the page list of
  `test_stylesheet_and_templates_agree_in_both_directions`.
  _Goes red if_: a new class is introduced for the tables, or
  `<details>` comes back to shorten the page.

- AC-16: **An expired cross certificate says so in both places.** With
  the cross certificate's validity moved wholly into the past,
  `/ca/{beta_root}`'s cross table row — scoped by the `<tr>` containing
  its link — contains `not served`, and
  `/ca/{beta_root}/cross/{cross_id}` contains the full clause naming the
  validity window and stating that the fallback needs no action. Both
  halves in one test.
  _Goes red if_: the tag is put on the table and the explanation is lost
  in the move, or the reverse — the operator then either has no
  explanation or has to open the page to find out anything is wrong.

- AC-17: **No page scrolls sideways.** Spec 0015 AC-1 and AC-2 re-run
  with the two new pages added to the page dict at
  `test_web_layout.py:657`: at 1440×1150 and at 390×900, with the full
  fixture, `document.scrollingElement.scrollWidth` does not exceed
  `clientWidth` and no element's right edge extends past its
  container's. The five-column cross table is the widest new thing on a
  page and it sits in a grid column, which is exactly where a naive
  table breaks out.

- AC-18: **The macro library is not a page, and the exemption is not a
  hole.** `test_every_content_template_sets_nav_current` excludes
  `ca_macros.html` and, in the same test, asserts that file contains
  neither `{% extends` nor `{% block content %}`, and that every
  template it does check contains `{% extends "layout.html" %}`.
  _Goes red if_: a real page is added to the exclusion set to silence a
  failure, which is the only way this exemption can do harm.

- AC-19: **The dashboard notice is unchanged.** The three existing
  assertions on `#ca-no-issuer`'s `anchor_hrefs` pass without
  modification, and in the same test the notice's hrefs contain
  `/ca/{root_id}` and do not contain `/ca/{root_id}#add-intermediate`.
  _Goes red if_: the fragment is added to the dashboard as well as to
  the page's own empty state, which breaks three exact-membership
  assertions elsewhere.

- AC-20: **Everything that was not this spec's subject still works.**
  The 0004–0025 suite passes: every POST path, form field, guard and
  CSRF rule is unchanged; `/ca`, `/ca/new` and the five `/transfer`
  pages render as before; `POST /ca/{root_id}/intermediate` still
  re-fills its form on a 400 (spec 0023 FR-8) on the root page, where
  that form still lives; the API, MCP, ACME, the CRL and cabin's own
  TLS are untouched; and no audit event's shape changes. The only test
  changes are the ones the Test list names.

## Test list

New, in `tests/test_ca_issuer_pages.py` unless noted:

test_tables_sit_above_both_forms,
test_an_intermediate_is_a_row_and_only_a_row,
test_cross_table_names_the_signer_and_is_omitted_when_empty,
test_empty_state_for_admin_viewer_and_keyless_root,
test_issuer_page_carries_the_full_inventory,
test_cross_page_carries_its_signer_and_renew_follows_the_signing_key,
test_issuer_and_cross_pages_refuse_every_mismatched_pair,
test_cross_page_belongs_to_its_subject_root_not_its_signer,
test_non_numeric_ids_answer_404_not_422,
test_unticked_retire_returns_400_on_the_page_that_owns_the_form,
test_renew_and_retire_redirect_to_the_rows_own_page,
test_viewer_reads_both_new_pages_and_sees_no_form,
test_root_page_makes_no_per_intermediate_lookups,
test_expired_cross_is_marked_in_the_table_and_explained_on_its_page,
test_per_intermediate_growth_stays_bounded (headless Chrome, AC-13),
test_section_and_danger_probes_cover_all_three_pages (headless Chrome,
AC-14)

Existing tests that change. Each is named with the requirement it was
protecting and where that requirement lives afterwards, because a test
edited without that argument is a requirement silently dropped, and this
spec touches roughly a dozen of them.

- **`tests/test_ca_names_and_actions.py:1079`**
  `test_detail_page_has_no_details_and_no_empty_column` protects three
  things: no `<details>` on the page; every action is a headed
  `.section` whose first column is non-empty; and the three blocks it
  locates are pairwise distinct, which is what proves the page is not
  one giant wrapper. It locates the third block by a `chain.pem` link
  the root page no longer has. All three requirements survive: the first
  two on the root page, over the intermediate form, the cross-sign form
  and the two table sections; the third moves to the issuer page, which
  joins the section probe (AC-14).
- **`tests/test_ca_names_and_actions.py:1174`**
  `test_every_danger_button_has_a_confirmation` protects spec 0024
  AC-11: the confirmation treatment repeats over every dangerous button,
  not just the first. It runs over the root page only, which after the
  split has one danger button — it would stay green while covering none
  of the moved ones. It probes three pages, each with the
  `_count_danger_buttons(html) >= 1` sanity assertion it already has, so
  it cannot pass vacuously (AC-14).
- **`tests/test_ca_names_and_actions.py:1237`**
  `test_stylesheet_and_templates_agree_in_both_directions` protects
  spec 0024 AC-12: no class without a rule, no rule without a class, no
  `<details>` anywhere. Unchanged in substance; its page list gains the
  issuer and cross pages, without which the two new templates would be
  the only markup in the project exempt from it (AC-15).
- **`tests/test_web_ca_pages.py:431`**
  `test_ca_detail_shows_only_its_own_hierarchy` protects `_group`'s
  `parent_id == root.id` filter, and its own comment records why it
  asserts on the intermediate's **fingerprint**: that is the field that
  moves when the filter breaks, while the root fingerprint stays
  correct either way. After this spec no fingerprint is on the root
  page, so the field that moves is the row's **link**: alpha's page
  contains `href="/ca/{alpha_root}/issuer/{alpha_int}"` and no href
  containing `/issuer/{beta_int}`. The fingerprint half moves to the two
  issuer pages, keeping the requirement it was written for.
- **`tests/test_web_ca_pages.py:621`**
  `test_viewer_reads_the_detail_page_and_sees_no_form` protects two
  things: a viewer can read the hierarchy in full (measured on the CRL
  URL) and sees exactly one form, the logout form. The CRL URL is no
  longer on the root page, so the readable-in-full half moves to the
  issuer page; the no-form half stays on the root page and is extended
  to both new pages (AC-11).
- **`tests/test_web_ca.py:285`** `test_ca_page_lists_hierarchies`
  protects that a status belongs to the row it is rendered on rather
  than being sprayed across the page — it retires beta's intermediate
  and asserts `retired` inside beta's block and not inside alpha's. The
  requirement is unchanged; the block is now that intermediate's `<tr>`,
  scoped by the link in its name cell.
- **`tests/test_web_crl.py:599`** protects spec 0017 FR-12's visible
  half: the **exact** forced-`http` CDP URL an issued certificate
  carries is shown to the operator, and the `https` form is not. It
  moves to that issuer's own page, unchanged in what it compares.
- **`tests/test_web_crl.py:630`** protects the explanation that appears
  in place of the URLs when no base URL is set, so an operator can find
  out why their certificates carry no CDP. It moves to the issuer page,
  which is where that note now lives.
- **`tests/test_web_tls_ui.py:386`** protects that CRL and AIA URLs are
  per-issuer and differ between hierarchies. It moves to the two issuer
  pages; the inequality assertions are what carry the requirement and
  they do not change.
- **`tests/test_web_tls_ui.py:394`**
  `test_displayed_urls_match_issued_certificate` protects the strongest
  statement in this area: the hrefs on the page equal, string for
  string, the CDP and AIA embedded in a real issued leaf — compared
  against the certificate, not against the helper a second time. It
  transfers **verbatim** to the issuer page; only the URL it GETs
  changes. This is the important one.
- **`tests/test_web_tls_ui.py:449`**
  `test_ca_page_urls_absent_without_base_url` protects that the links
  are absent and the note is present in their place. It moves to the
  issuer page, and its 900-character `_window` is dropped in favour of
  scoping to the note's own section — the character-window pattern is
  replaced, never widened, which is the rule spec 0023's Test list set
  after compacted production markup once broke a test that used one.
- **`tests/test_acme_api.py:883`** protects spec 0019 FR-13: a
  directory belongs to one issuer and is shown in that issuer's own row
  rather than once per page. That row is now a page, and the assertion
  follows it there.
- **`tests/test_web_name_constraints.py:540`** and **`:570`** protect
  AC-12's two halves — a constrained intermediate shows its entries
  inside its own block, an unconstrained one shows no block at all,
  neither found by page-wide search. Both move to the intermediate's own
  page and keep their scoping discipline, now against the constraints
  block on that page.
- **`tests/test_web_name_constraints.py:601`** protects that an
  **imported root**'s own constraints are displayed. The root section
  does not move (FR-1), so the requirement stays where it is; its
  scoping does change — it currently slices
  `html[root_i:intermediate_i]`, a window that only works because the
  intermediate's section follows the root's, and the intermediate is now
  a table row. It scopes to the root's own `.section` by its `<h2>`,
  the way `test_web_ca.py:389` already does.
- **`tests/test_web_name_constraints.py:696`** protects that an imported
  **intermediate**'s constraints are displayed, read from its
  certificate. It moves to that intermediate's page.
- **`tests/test_cross_chains.py:848`**
  `test_ca_page_shows_the_cross_row_under_the_subject_root` protects the
  `cross_of_id` invariant FR-8 is about: the row is displayed under its
  subject, not under its signer. It keeps that requirement and gains
  teeth — the row's link on the subject's page resolves to 200 and the
  same id under the signing root is 404 (AC-7) — instead of comparing
  string positions.
- **`tests/test_cross_chains.py:945`**
  `test_ca_page_marks_an_expired_cross_certificate_as_not_served`
  protects that an expired cross certificate is visibly not being
  served. Its `_dom_row` marker is an `<h2>` followed by a `cross` tag,
  markup this spec removes. It asserts both halves instead: the tag in
  the table cell, scoped by the row's link, and the full explanatory
  clause on the cross page (AC-16).
- **`tests/test_web_layout.py:56`**
  `test_every_content_template_sets_nav_current` protects spec 0015
  FR-2: a page must name itself or the rail cannot mark it. Its
  exclusion set gains `ca_macros.html`, which is not a page, and it
  gains the counter-assertions of AC-18 so the exclusion cannot be
  widened later to silence a real failure.
- **`tests/test_web_layout.py:629`** `test_no_horizontal_overflow` gains
  the two new pages in its page dict (AC-17).
- **The `_row`/`_dom_row` helpers** in `test_web_ca.py:201`,
  `test_web_ca_pages.py:184`, `test_ca_names_and_actions.py:262`,
  `test_cross_chains.py:217` and `test_web_name_constraints.py:291`
  gain an optional `class_name`, so a `<tr>` can be scoped by a marker
  inside it. Table rows carry no class and giving them one would put a
  selector in the stylesheet that AC-15's both-directions test would
  then require to be used and styled. This keeps "scoped by parsed
  element, never a character window" intact rather than trading it away
  for a window.

## Out of Scope

**No version bump.** Everything stays 0.2.0 and PR #17 stays open. The
change is UI-visible — two new URLs — and gets its entry under
`[Unreleased]` in `CHANGELOG.md`, which is the project's workflow rather
than a requirement of this spec.

**No schema change, no migration, no API, MCP or ACME change.** No
column, no table, no enum value, no route under `/api/v1`, no MCP tool
and nothing under `/acme`. The two new pages read rows that already
exist.

**No new CSS class and no new layout primitive** (FR-14). `.section`,
`.scroller`, `.tag`, `.note` and `.field-check` cover every element
added here.

**No htmx** (FR-16). It is vendored and loaded and has never been used
in this project; a table that expands a row in place is exactly the
temptation, and it would be the first client-side interactivity in
cabin, introduced as a side effect of a layout change.

**No `<details>`, ever again on these pages** (FR-16). Spec 0024 FR-8
removed it with an argument, and
`test_ca_names_and_actions.py:1079` and `:1237` forbid it. Making a long
page shorter by collapsing its rows is this spec's problem solved by
recreating the previous spec's.

**No sorting, filtering or paging on either table.** A hierarchy with
enough intermediates to need any of those is not a state this project
has seen, and the tables are bounded by what one root carries. Spec 0023
recorded the same decision for `/ca`.

**No change to `/ca`'s list.** The `Intermediates` and
`Cross certificates` counts it already shows are what the two new tables
now detail one level down; merging or cross-linking them is a second
change measured by no criterion here.

**Renew keeps its bare `HTTPException` on a bounds error**
(`ca_ui.py:736`), as do retire's `RetireError` and TLS-issuer refusals.
Spec 0024 FR-9 added the form response for the missing checkbox because
that is the refusal an operator reaches by forgetting one click; this
spec moves that response to the right page (FR-10) and does not widen
it. The domain refusals still arrive as JSON error documents, exactly as
0023 and 0024 left them.

**The two questions still open from the previous round** — whether three
red retire buttons on one page are too loud, and the changelog's
`[Unreleased]`-above-a-released-0.2.0 structure — are untouched here.
This spec reduces the first incidentally, by moving two of those buttons
onto pages of their own, but does not decide it.
