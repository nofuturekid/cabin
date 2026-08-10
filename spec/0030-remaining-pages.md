# Spec 0030 — The Remaining Pages, the Flash Message and Not Permitted

## Context

Spec 0027 put the design's shell and token layer around every page,
spec 0028 moved the detail and list pages into the design's arrangement,
and spec 0029 gave the five form pages their preview panels and this
project its first htmx. What is left is everything else: the dashboard,
the certificate inventory, users, API tokens, ACME, the audit log,
settings, the three remaining transfer pages, and login and setup.

It also holds the two things the design draws that cabin has no
counterpart for at all.

**The toast.** Six of the design's screens end an action with a panel
that slides in at the bottom-left corner and disappears 3.2 seconds
later (brief §6.12). Server-rendered that is a flash message, and the
brief's §9.5 says so. cabin has nowhere to put one: every mutation
redirects, and a redirect discards everything the handler knew.

**The refusal.** `deps.py:214` raises a bare `HTTPException(403)` and
FastAPI answers it with `{"detail": "forbidden for this role"}`. A
viewer who follows a link to `/tokens`, or who has an admin page open
when their role changes, gets a JSON body in a browser window. The
design draws the page that should be there instead (§5.2) and cabin
has never had it.

### The flash: a column, and why not a query parameter

The flash is one nullable column on the `sessions` row, written by the
POST and popped by the next render. It is the only schema change in the
whole redesign, and the alternative — `?flash=…` on the redirect target
— needs no migration at all, so it is worth saying exactly what the
migration buys.

A query parameter is **in the URL**, and everything that follows is a
consequence of that. It survives a bookmark, so a page saved after a
deletion greets its owner with `deleted user 'root'` a month later. It
survives a refresh, so `F5` re-announces an action that happened once.
It is **forgeable**: any link anyone sends is a sentence cabin will say
in its own voice, in its own chrome, and the one thing a message from
the server is worth is that the server said it. It leaks into the
browser history, into `Referer` and into every proxy log between here
and the operator. And it has to be re-encoded into eighteen redirect
targets, two of which (`_page_of(row)`, `/ca/{root_id}`) are built by
functions with other callers.

The column has none of those properties: it is read once, by the
session that owns it, and deleted in the same transaction. Its cost is
real and is named rather than glossed — **an authenticated GET becomes
a write** whenever a flash is pending. That is a page render that can
no longer be served from a read-only replica, and with two tabs open
the first render to commit is the one that shows the message. Both are
accepted; neither is invisible, because FR-2 says where the write is.

**What is lost against the prototype:** the message cannot be dismissed
early. The 3.2-second timer becomes a CSS animation with a delay and
`forwards` fill, which can hide the element but cannot remove it and
cannot be interrupted — no close button is possible without JavaScript,
and spec 0029's rule has no route-shaped answer for one. The other loss
is that the message no longer appears without a page change: it arrives
with the redirect, which is the only moment cabin has.

**What is not gained, and why.** The brief's §9.5 suggests three dot
colours now that a flash carries meaning across a redirect. It does not
ship, and the reason is a fact about cabin rather than a preference:
**no failing UI POST redirects.** Every one of them re-renders its own
page at 400 with its own error box, next to the field that caused it —
which is a better place for an error than a corner panel — so a
`warn` or `bad` flash would have no producer. Shipping the two extra
tones would mean two rules in `cabin.css` with no literal user, and
`test_stylesheet_and_templates_agree_in_both_directions` fails in its
reverse direction on exactly that (spec 0027 FR-20). The level column
arrives with the first failing redirect, in the spec that adds one.
FR-2 ships one column, which is what the plan says.

### The boundary that is the requirement most likely to be got wrong

An exception handler that renders HTML is four lines. An exception
handler that renders HTML **for the interface and not for the three
other front doors** is the whole of FR-6, because an API client
receiving an HTML error page is a worse regression than the JSON body
this spec exists to replace: cabin's own REST client, the ACME client
that retries on a problem document, and MCP all parse what comes back.

The obvious implementation is a path test, and the obvious path test is
wrong here. **`/acme/admin` is a UI page** — `acme_ui.py` mounts its
router at `PATH = "/acme/admin"`, deliberately before the protocol
router (`app.py:115-119`) — so `path.startswith("/acme")` sends cabin's
own ACME settings page back as `application/problem+json`, and a rule
carved to exempt it is one string away from exempting `/acme/administrator`
too. FR-6 therefore decides by **which router owns the matched route**,
never by the path, and AC-5 measures it in both directions: over every
route the application has, and over four live requests.

### The one rule this spec does not restate

**Every htmx target is a URL that also works as a page.** Spec 0029
FR-2 states it in four clauses and
`docs/adr/0003-url-state-disclosure-and-htmx.md` records it; this spec
reuses both without repeating either. Two consequences are worth
naming because they are what makes this spec's interactivity free:

- **htmx adds no endpoint here at all** (FR-20). The users row edit is
  `GET /users?edit={id}`, the inventory's filter bar and pager are the
  URLs `_page_url` already builds, and the audit pills are the URLs
  `audit_ui._page_url` already builds. Every one of them answers a page
  today; htmx fetches the same page and takes one region out of it with
  `hx-select`. The ADR predicted this ("spec 0030's two remaining uses
  … need none at all") and it holds.
- **No mutation runs through htmx**, so the first render after any POST
  is always a full navigation. That is what makes the flash safe: the
  pop happens in `base_context`, which an htmx swap also reaches, and a
  swap that ate a pending message would be a message nobody saw. There
  is no state in which a swap is the first render after a mutation
  because no `hx-post` exists on any page this spec touches (AC-3).

### What this spec overturns, and where

Every entry is argued in the requirement named beside it. Nothing else
in specs 0023–0029 changes.

| #   | Overturned                                             | By        | In one line                                                                                                             |
| --- | ------------------------------------------------------ | --------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1   | 0029 AC-13's second half (five reserved names)         | FR-18     | all five are rendered here, so the reserved-and-undefined list becomes empty and the criterion inverts rather than shrinks |
| 2   | 0029 FR-15's `[aria-hidden="true"]` census             | FR-9      | the tree glyph gains two more pages; the census names them rather than being widened to "anywhere"                       |
| 3   | 0027 FR-19's `.nav-count` as a reserved name           | FR-7      | the rail's count badge is rendered here, which is what the name was reserved for                                        |
| 4   | 0025 AC-1's `Transfer` rail group                      | FR-7      | the label and the membership move to the design's together, because either half alone names a group for what it is not  |
| 5   | 0029 AC-1's "the number this spec introduces"          | FR-20, AC-3 | the target set grows and half of it is interpolated, so the walker collects from rendered pages as well as templates    |
| 6   | 0016 FR-4's flat per-row CA list on the dashboard      | FR-8      | **not overturned** — every row still appears; only its position changes. Recorded so no reader infers it from row 7     |
| 7   | 0006's inventory status filter as a `<select>`         | FR-10     | **not overturned** — 0006 requires a `status` filter, not a control; recorded because the `<select>` does disappear     |
| 8   | 0028 FR-9's census of which `cols-*` classes may exist | FR-17     | eleven more column templates ship, so that census becomes a subset check and the full one moves to AC-16               |

Rows 3, 5 and 6 are not in the plan's list. They surface when the plan
is checked against 0027's, 0029's and 0016's own text, and a spec that
shipped them silently would leave two criteria failing and one reader
wondering.

Row 8 is not in the plan's list either, and it surfaced later than the
others: **only when the spec was checked against the tests.** Rows 1
and 2 are the criteria behind two of the three checks this spec breaks
(`test_the_reserved_classes_are_still_reserved` and
`test_the_tree_glyph_is_the_only_decoration`) and were argued from the
start; the third,
`test_ca_issuer_pages.py::test_the_column_templates_are_the_designs`,
asserts an equality no requirement here mentions and no reading of
0028's text predicts. Each of the three now names its test in the
Re-pointed list, because this table is where a reader checks what will
break and an entry argued in one requirement and absent from here is an
entry that reader does not find.

## User Stories

- As an operator who has just deleted a user, cabin tells me so on the
  page it sends me to, in the same sentence the audit log records —
  and tells me once.
- As an operator who bookmarks a page after an action, the bookmark
  does not greet me with that action a month later.
- As a viewer who follows a link to a page my role cannot open, I get
  cabin's own page saying so, with a way back — not a line of JSON.
- As a script calling `/api/v1`, and as an ACME client, and as an
  assistant on MCP, a refusal is the same bytes it has always been.
- As an operator on the inventory, the status filter is five links I
  can middle-click, bookmark and share, and it keeps my search text.
- As an operator editing a user, the open row has an address, and with
  JavaScript off I get the same row one navigation later.
- As an operator on a phone, nothing on any of these pages scrolls
  sideways and every message is inside the viewport.
- As an operator who reads every sentence on these pages today, every
  one of them still says exactly what it said.

## Functional Requirements

- FR-1: **The boundary.** This spec changes
  `src/cabin/web/templates/layout.html`, `dashboard.html`,
  `certs_list.html`, `users.html`, `tokens.html`, `acme.html`,
  `audit.html`, `settings.html`, `transfer_trust_bundle.html`,
  `transfer_ca_key.html`, `transfer_inventory.html`, `login.html` and
  `setup.html`; adds `src/cabin/web/templates/not_permitted.html`;
  changes `src/cabin/sessions.py`, `src/cabin/web/deps.py`,
  `src/cabin/app.py`, `src/cabin/web/ui.py`, `certs_ui.py`,
  `audit_ui.py`, `tokens_ui.py`, `acme_ui.py`, `settings_ui.py`,
  `ca_ui.py`, `transfer_ui.py` and
  `src/cabin/web/static/cabin.css`; and adds
  `src/cabin/store/migrations/versions/0011_session_flash.py`. It
  appends entries to the "everything else" divergence register of
  `docs/design/0027-brief.md` (FR-19) — the brief's own instruction for
  a deliberate departure.

  **No route is added and no route is removed.** Two optional query
  parameters are added, `edit` on `GET /users` (FR-11) and nothing
  else; every existing path, method, guard, CSRF rule, form field,
  status code and redirect target is unchanged. One column is added to
  one table (FR-2). No audit action, no API, MCP or ACME change.
  Wording is unchanged except for the strings FR-19 enumerates.

  **`ca_ui.py` and `certs_ui.py` are in the boundary although this spec
  redesigns none of their detail or form pages.** `certs_ui.py` is here
  for the inventory (FR-10); both are here for the flash call site on
  the mutations they own (FR-3). A spec that shipped the flash mechanism and wired it only to
  the pages it was already editing would ship an inconsistency — some
  actions confirming and some not — which is the state FR-3 exists to
  make impossible.

- FR-2: **The flash lives in one nullable column, and exactly two
  functions touch it.** `sessions.UserSession` gains

  ```python
  flash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
  ```

  and `0011_session_flash.py` (`revision = "0011"`,
  `down_revision = "0010"`) adds it with `op.add_column` and drops it in
  `downgrade`. `sa.Text` rather than a bounded `String`: the longest
  message this spec can produce is `imported CA {subject}`, a subject is
  operator-supplied, and a length cap would mean inventing a truncation
  rule and an ellipsis nobody asked for.

  Two functions, in `cabin/sessions.py`, and no third:

  ```python
  def set_flash(db: Session, row: UserSession, message: str) -> None: ...


  def pop_flash(db: Session, row: UserSession) -> str | None: ...
  ```

  `set_flash` writes and commits. `pop_flash` reads, sets the column to
  `None`, commits, and returns what it read — **the clear is in the
  same call as the read**, never a second call a caller can forget,
  because a flash that is shown and not cleared is shown on every page
  for the rest of the session and a defect nobody reports as one.

  The web layer reaches them through exactly two places:
  `deps.flash(request, db, message)`, which writes to
  `request.state.session` — the row `get_current_user` has already
  loaded (`deps.py:180`) — and `deps.base_context`, which pops. Nothing
  else in `src/cabin/web/` may name the column.

- FR-3: **What sets a flash, and what deliberately does not.** The rule
  is one sentence, so that no page needs a judgement of its own:

  > A UI POST that answers 303 and records exactly one audit event sets
  > the flash to that event's own `summary`. Every other request sets
  > none.

  It ships with **no new copy at all**, because the summary is already
  written: `created user 'bob' as admin`, `revoked API token 'ci'`,
  `renewed CA 'alpha Root'`. At each call site the f-string is bound to
  a local and passed to both `audit.record(summary=…)` and
  `deps.flash(…)`, so there is one sentence per action in this project
  and the panel cannot drift from the log.

  The eighteen routes it applies to:

  | Module              | Routes                                                                                                            |
  | ------------------- | ----------------------------------------------------------------------------------------------------------------- |
  | `ui.py`             | `POST /users`, `/users/{id}/role`, `/users/{id}/password`, `/users/{id}/issuers`, `/users/{id}/delete`            |
  | `ca_ui.py`          | `POST /ca/create`, `/ca/{root_id}/intermediate`, `/ca/{ca_id}/cross-sign`, `/ca/{ca_id}/renew`, `/ca/{ca_id}/retire` |
  | `certs_ui.py`       | `POST /certs/issue`, `/certs/sign`, `/certs/{id}/revoke`                                                          |
  | `tokens_ui.py`      | `POST /tokens/{id}/issuers`, `/tokens/{id}/revoke`                                                                |
  | `transfer_ui.py`    | `POST /ca/import`, `/ca/cross-import`                                                                             |
  | `acme_ui.py`        | `POST /acme/admin/eab-keys/{id}/revoke`                                                                           |

  > **Confirmed (test-authoring): the rule's precondition holds for all
  > eighteen, measured rather than assumed.** The rule is "a UI POST
  > that answers 303 and **records exactly one audit event**", and which
  > routes satisfy it was a claim about eighteen handlers nobody had
  > counted. Each was posted once against the fixture, with the
  > `audit_events` rows before and after: all eighteen answered **303**
  > and every one of them recorded **exactly one** event — including the
  > four that had a plausible reason not to (`POST /ca/create` and
  > `POST /ca/{root_id}/intermediate`, which also write a grant;
  > `POST /ca/import`, which inserts two `ca_certificates` rows;
  > `POST /users/{id}/delete`, which also deletes sessions). None of
  > those side effects is an event.
  >
  > Their redirect targets were read off the same eighteen responses and
  > are the ones FR-1 says are unchanged: `/users` five times, `/ca`
  > three, `/tokens` twice, `/acme/admin` once, and the six built per
  > row (`/ca/{root_id}`, `_page_of(row)` twice, `/certs/{id}` three
  > times). AC-3 clause 2 keeps asserting it, because the check is
  > cheap and the eighteen call sites are where a redirect target gets
  > "tidied".

  And the exclusions, each for a reason and not by omission:

  - **`POST /settings` and `POST /acme/admin`** record *one event per
    changed setting* through `settings_ui.save_setting`, so a request
    can leave zero, one or seven sentences behind and none of them is
    "what just happened". Showing the last is misleading, counting them
    is new copy describing a request rather than a change, and the
    audit log holds all of them. Declined here, recorded in Out of
    Scope.
  - **`POST /tokens` and `POST /acme/admin/eab-keys`** do not redirect:
    they render the page with a secret shown exactly once
    (`tokens_ui.py:179`). They must keep doing so. Routing them through
    a flash would put a live bearer token in a database column in clear
    text and show it again on the next page load — AC-14 forbids it by
    effect, because it is the one change here that would be a security
    regression dressed as consistency.
  - **`POST /transfer/ca-key`** answers a file, not a page.
  - **`POST /login`, `POST /setup`, `POST /logout`.** The first two have
    no session to write to until after they answer; the third deletes
    the one it would write to. All three are named so that "every
    mutation flashes" is not read as covering them.
  - **A no-op that records nothing sets nothing.** `revoke_token` on an
    already-revoked token and `update_token_issuers_route` with an
    unchanged set both redirect without an event
    (`tokens_ui.py:240, 268`). They stay silent, because a panel saying
    something happened when nothing did is worse than no panel — the
    same judgement spec 0029 FR-4 makes about a preview. AC-2 is that
    case, in both directions.
  - **Every 4xx re-render.** The error box is already on the page, next
    to the field.

- FR-4: **The flash is rendered in the shell, once, and times itself
  out in CSS.** `layout.html` gains, inside `.shell` and as a sibling
  of `<aside class="rail">` and `<main>` — which is where the design
  puts it (brief §4) — `{% if flash %}<div class="flash" role="status">…</div>{% endif %}`.
  It renders only when the context carries one, which means only when
  `base_context` popped one, which means only on an authenticated page.

  - **The dot.** One `<span>` with `aria-hidden="true"`, because the
    message is the words beside it (FR-9's census names it).
  - **`role="status"`.** The panel appears without the operator moving
    focus to it and is gone on the next navigation; a live region is
    what makes it reach a screen reader at all. It is `status` and not
    `alert`: nothing here is an error, by FR-3.
  - **The timer.** `animation: cabinToast .2s ease-out, cabinToastOut .3s ease-in 3.2s forwards`.
    `cabinToast` already exists in `cabin.css` (`:1227`) and has had no
    user since spec 0027 shipped it; this is its first. `cabinToastOut`
    is new and is a **third** keyframe where the brief §7 says there are
    exactly two — recorded as a divergence, with its reason: the
    prototype's 3.2 seconds is a `setTimeout` (brief §8), and the only
    way to spend 3.2 seconds without JavaScript is a delayed animation
    that fills forwards.
  - **Reduced motion.** Both the entry and the hide are wrapped:
    `cabin.css`'s existing `@media (prefers-reduced-motion: reduce)`
    block gains `.flash`, so the panel appears with no motion and
    **stays** until the next navigation. That is deliberate — hiding it
    on a timer is the motion — and it is the safer half of the trade,
    since a message that lingers is readable and one that vanishes
    early is not.
  - **Below the shell's breakpoint** the panel is not at the design's
    `left: 250px`. There is no 230px rail there (spec 0027 FR-7 releases
    the shell below 60rem), and 250px of left offset on a 390px viewport
    with a `max-width: 520px` panel is a page that scrolls sideways.
    It takes the content column's own width and the page's own padding
    instead. AC-19 measures it.

  The panel carries **no close control**. Spec 0029's rule admits no
  route for one and this spec adds no JavaScript.

- FR-5: **The "Not permitted" page.** `not_permitted.html` extends
  `layout.html` like every other page, so the refusal arrives inside
  the shell with the rail — an operator who is refused one page is
  still logged in and every other page is one click away. Brief §5.2:
  a narrow column, `<h1>Not permitted</h1>`, a body paragraph, and one
  primary link.

  - The link is `<a class="button-link" href="/certs">Back to the inventory</a>`.
    `/certs` is guarded by `get_current_user` alone, so it is the one
    page every role that can be refused anything can still open. A
    button pointing at a page the reader has just been refused would
    be the same defect with a nicer border.
  - **Two body texts, chosen by cabin's two actual causes** rather than
    by the prototype's roles. The design names an auditor and a missing
    issuer grant; cabin has neither an auditor role nor a 403 raised by
    a grant check — its 403s come from `require_role` and from
    `verify_csrf`, and those are the two the reader needs told apart,
    because one is answered by asking someone for a role and the other
    by reloading the page. Both strings are new copy and both are in
    FR-19's table.
  - `nav_current` is unset, so no rail entry is marked: the page is not
    one of the rail's destinations and marking the one the reader was
    refused would be a lie about where they are.

- FR-6: **The refusal is HTML for the interface and unchanged for the
  three other front doors.** This is the requirement most likely to be
  got wrong and it has its own criterion, in both directions (AC-5).

  `app.py` registers one handler for `HTTPException`. It renders
  `not_permitted.html` when **both** of these hold, and delegates to
  `fastapi.exception_handlers.http_exception_handler` otherwise:

  1. `exc.status_code == 403`;
  2. the matched route belongs to one of the ten interface routers —
     `ui_router`, `ca_router` (`ca_ui`), `transfer_router`,
     `transfer_ca_router`, `certs_router`, `certs_download_router`,
     `settings_router`, `acme_ui_router`, `tokens_router`,
     `audit_router`.

  **Clause 2 is decided from the routers, never from the request
  path.** `create_app` builds one frozen set of the endpoint callables
  those ten routers carry, and the handler asks whether
  `request.scope.get("endpoint")` is in it. Three things follow, and
  each is why this shape rather than a prefix test:

  - **`/acme/admin` is a UI page under `/acme`.** `path.startswith("/acme")`
    would answer cabin's own ACME settings page as
    `application/problem+json`, and the carve-out that fixes it
    (`not path.startswith("/acme/admin")`) also exempts
    `/acme/administrator`, a path that does not exist today and is one
    router away from existing.
  - **A new API or ACME route lands outside the set automatically**, so
    it keeps answering JSON with nobody remembering anything. A new UI
    router lands outside the set too — and the failure direction of
    that is today's behaviour, a JSON body on one UI page, not an HTML
    page on an API client. The mistake this can make is the recoverable
    one.
  - **MCP is not `include_router`ed at all** (`app.py:136`); its routes
    are a `Route` and a `Mount` extended onto `app.router.routes`, so
    they carry no endpoint this set could contain even by accident.

  Everything else is unchanged and is asserted so: the status stays
  **403**, the headers stay what FastAPI sets, 404 and 422 keep
  answering JSON on every route including the UI's (the design draws no
  page for either, and inventing one is a second spec), `AcmeError` and
  `AuthRedirect` keep their own handlers, and `/api/v1`, `/acme` below
  `/acme/admin`, `/mcp` and the public CRL routes answer byte-for-byte
  what they answer today.

- FR-7: **The rail's fourth group, and the count badge.** _Supersedes
  spec 0025 AC-1's `Transfer` group_ and _spec 0027 FR-19's reservation
  of `.nav-count`_.

  **The label and the membership move together.** The plan settles
  `Transfer` → `Export`, from the brief's own instruction to pick the
  rail over `github.md` (§4). Checked against cabin, that resolution
  applies to a group cabin does not have: the design's `Export` holds
  Trust bundle and CA key, and puts Import CA and Import Cross
  Certificate under `Certificate authorities`. cabin's fourth group
  holds all five. Renaming the label alone would produce a group
  called `Export` whose first two entries are `Import a CA` and
  `Import a cross certificate` — a label that is wrong in a way the
  current one is not.

  So both move: the two import links join the `Certificate authority`
  group, in the design's order, and the fourth group becomes `Export`
  with Trust bundle, CA key and Inventory export. **Nothing else about
  the rail changes** — the count stays 16, every `href` stays, every
  `nav_current` name stays, and no link's label changes, so
  `test_transfer_pages_mark_their_rail_entries` passes untouched. The
  design's own group heading `Certificate authorities` is **not**
  adopted: cabin's is `Certificate authority`, that is wording, and
  wording is out of scope (FR-19).

  **The count badge.** The Inventory entry carries
  `<span class="nav-count">` when, and only when, at least one
  certificate is expiring. The number is `status_counts(db)["expiring"]`
  — the same call the dashboard's tiles already make, so the badge and
  the tile cannot show two different numbers — and the design's amber
  (brief §6.8) is the tone cabin already uses for that state. At zero
  the element is **absent**, not `0`: the design draws it "only when
  > 0" and a badge reading zero is a decoration that says nothing.

  Its cost is one aggregate query per authenticated page render, and
  it is paid in `base_context`, which is why that function gains a
  `db` parameter (Interface Contract) — the same parameter FR-2's pop
  needs, so it is one change serving two.

- FR-8: **The dashboard.** `dashboard.html` takes the design's §5.1
  arrangement and loses nothing it renders today.

  1. **Stat tiles.** Already `<a class="tile" href="/certs?status={{ name }}">`
     (`dashboard.html:37-45`) — the design's clickable, pre-filtering
     tile exists. It gains the design's geometry and hover only.
  2. **Expiring** — the `.rows` table, `.cols-expiring`, rows clickable
     through the `.rowlink` spec 0028 FR-3 defined. The days-left cell
     is `tag-bad` at ≤ 7 days and `tag-warn` otherwise, which is the
     design's rule and **is a change of threshold from nothing**: the
     template renders no days-left tag today, so this is new markup
     over a value (`row.days`) the context already carries.
  3. **Authorities** — the grouped list (FR-9), `.cols-authorities`,
     replacing the flat `The CA itself` table.
  4. **Revocation** — one `.panel` per CRL in a two-column grid, each
     holding the issuer name, a `stale` tag when stale, the `.kv` grid
     spec 0029 FR-15 defined (CRL number / Generated / Next update) and
     the CRL URL in mono with `word-break: break-all`. The values are
     the values `crls` already carries; no table survives here, because
     a two-row table per CRL is a definition list wearing a `<table>`
     and the design draws cards.
  5. **Services** — three inline chips, from the same `services`
     dictionary and behind the same `may_see_settings` gate
     (`ui.py:412`), which is a permission check and is not touched.
  6. **Activities** — the `.rows` table, `.cols-activity`, not
     clickable, with `RECENT_EVENTS` unchanged at five.

  `EXPIRING_SHOWN` stays 10 where the design shows 5: the number is
  spec 0016's and changing it is a content change behind a layout one.

- FR-9: **The grouped list is reused, not defined a second time.** Spec
  0028 FR-5 built it for `/ca` and said in its own text that the
  dashboard's authorities block and the CA-key page were its two
  waiting users (brief §6.3). They arrive here, and what they reuse is
  the component: `.rows`, `.row-root`, `.row-child`, `.tree`,
  `.state-active`, `.state-retired`, `.rowlink` and `.tag`. **No second
  rule is written for any of them** — AC-8 asserts each of those names
  has exactly one rule block in `cabin.css`.

  > **Correction (test-authoring): "no second rule" is about this spec,
  > not about the count.** The sentence above read that AC-8 asserts each
  > of those names has *exactly one* rule block in `cabin.css`, and no
  > build can satisfy that — spec 0028's grouped list ships a base rule
  > **and** descendant rules under the same names (`.row-root` and
  > `.row-root td:first-child a`, `.row-child` and
  > `.row-child td:first-child`, `.rowlink::after` beside the two
  > `tr:has(.rowlink)` rules). The count was already false at this spec's
  > base commit, so a build that met it would have had to delete part of
  > the component this requirement asks to be *reused*.
  >
  > What the requirement means is that **this spec** writes no rule for
  > any of those names, and that is what AC-8 clause 4 now measures: the
  > selectors naming each of the six are the ones the file carried at the
  > base commit. A grouped list re-implemented here under these names
  > adds a selector and fails; one re-implemented under new names is
  > caught by clauses 1 to 3, which read the rendered rows.

  What each of the three lists gets of its own is exactly one class:
  its column template (FR-17). That is 0028's own vocabulary — a column
  set is a `cols-*` class on the `<table>` and nothing else — and it is
  why the three lists can carry three different column sets without
  three grouped lists.

  **No shared Jinja macro.** The three lists agree on their structure
  and differ in every cell: `/ca` shows two counts, the dashboard shows
  an expiry and two tags, the CA-key page shows where the key is. A
  macro parameterised over the cells would be a template engine written
  inside a template, and the thing worth not duplicating — the border
  recipe that turns per-row borders into one rounded box, the tree
  glyph's rule, the root fill — is in the stylesheet already.

  **The tree glyph's census grows by two pages.** _Supersedes spec 0029
  FR-15's widening of spec 0028 AC-14_, which asserts that across the
  probe's page list the elements matching `[aria-hidden="true"]` are
  exactly the tree glyphs on `/ca` and the constraint marks on
  `/certs/new`. The dashboard's and the CA-key page's glyphs are the
  same decoration for the same reason (spec 0028 FR-13), and the flash
  dot (FR-4) is a fourth. The census becomes those four, named. It is
  widened by naming its users, never by dropping the count, so that a
  fifth still has to be argued for in the spec that adds it.

  **Cross rows keep their place.** Spec 0028 FR-5 refused to indent
  cross rows under a root on `/ca`, because a cross row's name equals
  its subject root's name and the list has no column to tell them
  apart. The same holds here — but the dashboard's list has a second
  job `/ca`'s does not: spec 0017 FR-14 makes it one entry per
  `ca_certificates` row, so that no CA certificate's expiry warning can
  go missing. Both survive: roots and their intermediates are grouped,
  and every cross row follows at root level with its own `cross` kind
  tag. AC-8 asserts the row count equals the table's row count today.

- FR-10: **The inventory's filter bar, its pager, and the sort that
  does not ship.**

  **The status filter becomes the design's segmented control, as five
  links.** `certs_list.html`'s `<select name="status">` is replaced by
  `<div class="seg">` holding one `<a>` per `STATUS_FILTERS` entry —
  five, in the tuple's order, labels unchanged — each `href` equal to
  `_page_url(q, that_status, 1)`, so every link carries the active
  search text through and resets to page 1. The active one carries
  `seg-on`, written literally in an `{% if %}` and never interpolated
  (spec 0028 FR-10). Each carries `hx-get` on its own href,
  `hx-select="#inventory"`, `hx-target="#inventory"`,
  `hx-swap="outerHTML"` and `hx-push-url="true"`.

  This is **not** a supersession of spec 0006: that spec requires a
  `status` filter with named values and says nothing about the control.
  It is recorded in the table above anyway, because the `<select>` does
  disappear and a reader of 0006's UI section will look for it.

  **The search box stays a `<form method="get">` with a submit.** Brief
  §9.6 is explicit — no live filtering as you type — and the form now
  carries the active `status` as a hidden input, so submitting a search
  keeps the filter the way the links keep the search. It gains no `hx-`
  attribute: a GET form submit is already a navigation to a URL that
  works, and the only thing htmx would add is a second way to write the
  same request.

  **The pager keeps working as plain links** and gains the same four
  `hx-` attributes. It is already `<a href="{{ prev_url }}">` /
  `<a href="{{ next_url }}">` (`certs_list.html:70-71`) from
  `_page_url`, and it stays outside the `{% if certs %}` branch for the
  reason the comment there gives.

  **Sorting does not ship.** The design's §5.3 makes `Common name` and
  `Valid until` sortable headings, and cabin has no sort at all:
  `list_certificates` orders by `created_at desc, id desc`
  (`ca/certs.py:469`) and that ordering is the page's own lead
  sentence — **"Everything this CA has issued, newest first."** Adding
  a sort would make that sentence false for every state but one, and
  wording is out of scope (FR-19); changing the sentence to suit a
  control is exactly the trade this redesign has refused eight times.
  It is also not a layout change: it needs a query parameter, a
  whitelist, a tie-breaker, and the same ordering in
  `export_certificates` or the CSV disagrees with the page that offered
  it. Declined, recorded in the brief's register, and AC-10 asserts
  both halves — the sentence is there and no heading is a link.

  The `Profile` heading is likewise not a segmented control, for spec
  0029's reason: it renders `list(Profile)` and hard-coding an enum's
  cardinality into markup buys nothing.

- FR-11: **Users gains inline row editing, and under spec 0029's rule
  that is URL state.** The design (§5.17) swaps every cell of a clicked
  row to a control. In this project that is a row re-rendered as a form
  **at its own URL** — `GET /users?edit={id}` — and not a client-side
  widget, for the same four reasons ADR 0003 gives: the state can be
  linked to, it survives an error re-render, it needs no new endpoint,
  and it works with JavaScript off.

  - **Closed.** Every row is text: username, role tag, the granted
    issuer names (the branch `users.html:53` already renders for a
    reader who cannot manage), the created date, and one `<a>` reading
    `Edit` whose `href` is `/users?edit={id}#user-{id}`, carrying
    `hx-get` on the same URL and `hx-select`/`hx-target` on
    `#user-{id}`. The `<tr>` carries `id="user-{id}"` in **both**
    states, so the anchor and the swap target survive the swap.
  - **Open.** The same `<tr>`, same id, plus `.editing`, holding the
    four forms that stand there today — `/users/{id}/issuers`,
    `/role`, `/password`, `/delete` — unchanged in fields, method,
    action and CSRF, each in the cell it belongs to, plus one `<a>`
    reading `Cancel` pointing at `/users`.
  - An unrecognised `edit` — an unknown id, a non-integer — renders the
    page with every row closed at status 200, which is the rule
    `certs_list`'s `?status=` and `ca_detail`'s `?add=` already follow.
  - **A viewer sees no form at either URL.** `can_manage` still gates
    every control; `?edit=` is a request to open a row, never a grant.
    This is the one hole URL state opens that a server-decided boolean
    did not, spec 0029 found it in review, and AC-11 closes it here
    rather than after.
  - Every re-render that carries a form error opens that row:
    `POST /users/{id}/role` failing re-renders at 400 with
    `edit={id}`, which is spec 0023 AC-3's requirement in the shape
    FR-11 gives it.

  **What it costs, stated rather than implied.**
  - **A whole page render per swap.** `hx-select` throws the rest of
    the response away. ADR 0003 accepts that for a disclosure clicked
    occasionally, and this is one.
  - **Four buttons, not the design's one `Save`.** cabin's four
    mutations are four routes with four audit actions and four guards,
    and one `Save` would be a new endpoint — which ADR 0003 says this
    use needs none of — collapsing four log entries into one. The
    design's row has one button because the prototype has no server;
    this one has four because cabin's log is worth more than the
    symmetry.
  - **No `Delete? Yes / No` state.** The design's third state maps to
    `?delete={id}`, and cabin's delete has no confirmation today. Adding
    one is a behaviour change and new copy. Declined, recorded.
  - **No avatar-plus-full-name cell.** cabin has a `username` and no
    first name, last name or email (`users.py:56-67`). The 26px avatar
    circle ships with the username's first character; the second line
    the design stacks under it has nothing to hold, and inventing an
    `@login` prefix would be new copy for a string that is already
    there.

- FR-12: **The audit log's pills are links; its action filter stays a
  control.** The design (§5.18) draws five filter pills. cabin's page
  has two `<select>`s and a search box in one GET form, and exactly one
  of the three maps onto the pills: `actor_kind`, whose
  `ACTOR_KIND_FILTERS` are five values, which is the shape the design
  draws.

  > **Correction (test-authoring): five, but not those five.** The
  > design's pills are `all / ui / api / acme / mcp`; cabin's
  > `ACTOR_KIND_FILTERS` are `all / user / token / system / acme`. Only
  > the cardinality matches, and the earlier wording — "the five values
  > the design names" — would send an implementer looking for `ui` and
  > `mcp` in an enum that has neither.
  >
  > **cabin's five stay, unchanged.** They are `ActorKind`, the column
  > the audit log actually filters on (spec 0009 FR-1), and they answer
  > a different question from the design's: the design names the *door*
  > a request came through, cabin names the *kind of actor* it was
  > blamed on — `system` is cabin itself with no door at all, and `user`
  > covers the UI whether the operator came from a browser or not.
  > Renaming them to match the drawing would be a schema change with a
  > CHECK constraint behind it and a filter value in every existing
  > bookmark, to make a chip read differently. Wording is out of scope
  > (FR-19) and this is more than wording.

  - **`actor_kind` becomes `.pill` links**, one per filter value, each
    `href` equal to `_page_url(q, action, that_kind, 1)` — so a pill
    carries the search text and the action filter through and resets
    the page — with `pill-on` written literally on the active one, and
    the same four `hx-` attributes as FR-10's, targeting `#audit-log`.
  - **`action` stays a `<select>` inside the GET form.** It has one
    option per `AuditAction`, which is a two-figure list that grows
    with every spec; as pills it would be a wall, and spec 0009's own
    UI line calls it a select. The search box stays a search box, for
    brief §9.6's reason.
  - The pager keeps its links and gains the same `hx-` attributes.

  So the answer to "which of these is a real control" is: the two
  `<select>`s and the search input are controls inside one form with
  one submit; the pills, the segmented control on the inventory, the
  pager arrows and the users `Edit`/`Cancel` triggers are links with
  addresses. Nothing in this spec is a control that mutates on change.

- FR-13: **The ACME and settings toggles are checkboxes, and the design's
  own recommendation is declined with a measurement behind it.** Brief
  §9.7 offers two shapes for the toggle switch: a `<form>` whose submit
  button *is* the track, or a `<input type="checkbox">` styled as one
  with a visible Save. It recommends the first and calls the second
  "arguably worse".

  cabin ships the second, because on both of these pages the first is
  not merely worse — it is broken. `POST /acme/admin` reads
  `acme_enabled` and `acme_require_eab` from one submission
  (`acme_ui.py:214-218`) and an absent checkbox means off; `POST /settings`
  does the same for seven fields from one wrapping `<form>`
  (`settings.html:14`). A per-toggle submit button posts that form, so
  turning EAB on would turn ACME off, and turning MCP on would clear
  `trust_proxy`, `allow_private_validation_targets` and the base URL.
  AC-13 is that case, asserted as effect.

  So the toggle is `<input type="checkbox" class="toggle">` — the real
  control, keeping its `id`, its `name`, its `value="on"` and its
  position in the form it is already in — drawn with `appearance: none`
  as the design's track and a `::after` knob, with the design's
  `transition: background .15s` and `transition: transform .15s`
  (brief §7's second and third transitions, which have had no user
  until now). Because the checkbox is still the focusable element,
  spec 0027 FR-15's focus ring lands on the track with no extra rule,
  and the knob's slide survives the click — which is the half of the
  design's motion the brief expected to lose.

  What is genuinely lost is what the brief warns about: the knob shows
  the *pending* state, not the saved one, until `Save` is pressed. That
  is the semantics `/settings` has had since spec 0001 and `/acme/admin`
  since spec 0019 — this page has always been edit-then-save — so the
  toggle inherits it rather than introducing it.

- FR-14: **API tokens.** `tokens.html` takes the design's §5.16.

  - The one-time secret keeps its current path exactly:
    `POST /tokens` renders the page at 200 with `Cache-Control: no-store`
    (`tokens_ui.py:88-119`) and the secret in it. It gains the design's
    accent banner, which is the `.callout` this page already uses, and
    the secret goes in a `<code class="copyable">`.
  - **`.copyable` is `user-select: all`** — brief §9.8's answer to the
    two copy buttons the design draws, which are impossible without
    JavaScript. One click selects the whole value. Its three users are
    the API-token secret, the EAB secret and the ACME directory URL;
    it is not put on `.pem`, where selecting one line of a PEM body is
    a thing an operator does.
  - The list becomes `.rows`/`.cols-tokens` with its eight columns
    unchanged, the role as a tag, and `Revoke` right-aligned.
  - The create row keeps its `.section`, its fields and its ids.

- FR-15: **The three remaining transfer pages.**

  - **Trust bundle** (§5.13): `.rows`/`.cols-trust-bundle`, four
    columns as today, rows **not** clickable — no `.rowlink`, so no
    hover fill either (spec 0028 FR-8 scopes it to
    `tr:has(.rowlink)`) — and the per-hierarchy download link stays the
    only anchor in its row. The closing footnote takes the design's
    `max-width`.
  - **CA key** (§5.14): the flat Name/Kind/Key table becomes the
    grouped list (FR-9) with `.cols-ca-keys`, rows not clickable. The
    `Key` cell's three states keep the strings they have and take the
    design's three colours from tokens already in `:root`. The export
    form keeps its fields and its `POST /transfer/ca-key`; its button
    takes the design's danger-outline treatment, which is
    `.panel-danger`'s palette on a button and needs no new token.
    The design's "Delete a stored key" section has no cabin
    counterpart and none is invented.
  - **Inventory export** (§ none — the design has no such screen; its
    CSV/JSON are buttons on the inventory itself): it takes the same
    filter-bar treatment as FR-10's, which is the only way it can look
    like the rest of the application. Its `<select name="status">`
    becomes the same `.seg` links, built from the same
    `_normalize_filters` values, and its two download links stay links.

- FR-16: **Login, setup, and the pages that have no rail.** The design
  contains no login screen and no first-run screen — nineteen screens,
  none of them either — so **nothing is invented here**. What these two
  pages get is what they have never had:

  - They are added to the probe list. Neither has ever been walked by
    the overflow, contrast or focus probes: `page_paths` does not
    contain them and `NOT_PAGES` excludes them from the template
    checks, so the one pass this project makes over its own geometry
    has never looked at the first two screens anybody sees. AC-19
    adds them, at both widths and in both schemes.
  - `.card-narrow` takes the design's panel geometry — surface, border,
    radius and padding from the tokens spec 0027 already ships — which
    is the same treatment `.panel` got, applied to the box these two
    pages already use.
  - `layout.html` renders no flash for them, because `base_context` is
    never called for them (`_anon_context`, `ui.py:130`), and no rail,
    because there is no `user` in the context. Both are today's
    behaviour and both are asserted, so that adding a `<div class="shell">`
    around them cannot quietly give them a rail-shaped hole.

  The `Not permitted` page is the third page in this group in one
  respect only — it has no `nav_current` — and is unlike them in the
  one that matters: it *does* wear the rail, because its reader is
  logged in (FR-5).

- FR-17: **The column templates, exactly, and the rule for the ones the
  design does not give.** Each is a class on the `<table>` and every
  track is `minmax(0, Nfr)`, per spec 0028 FR-9. No `<td>` of a `.rows`
  table is `white-space: nowrap` (0028 FR-9, same reason).

  | Class                 | Page                        | Tracks                                   | From                    |
  | --------------------- | --------------------------- | ---------------------------------------- | ----------------------- |
  | `.cols-expiring`      | dashboard                   | `2fr .6fr 1.1fr .8fr`                    | brief §5.1, verbatim    |
  | `.cols-authorities`   | dashboard                   | `1.6fr 1.1fr 1fr .8fr`                   | brief §5.1, verbatim    |
  | `.cols-activity`      | dashboard                   | `1.1fr .9fr 1.3fr 2fr`                   | brief §5.1, verbatim    |
  | `.cols-certs`         | `/certs`                    | `1.7fr .7fr .7fr 1.5fr 1fr .5fr 1.2fr`   | brief §5.3, verbatim    |
  | `.cols-trust-bundle`  | `/transfer/trust-bundle`    | `2fr .8fr .9fr 1.2fr`                    | brief §5.13, verbatim   |
  | `.cols-ca-keys`       | `/transfer/ca-key`          | `2fr 1fr 1.6fr`                          | brief §5.14, verbatim   |
  | `.cols-audit`         | `/audit`                    | `1.1fr .9fr 1.2fr 2.2fr .6fr`            | brief §5.18, re-ordered |
  | `.cols-users`         | `/users`                    | `1.5fr .8fr 1.5fr .7fr .8fr`             | brief §5.17, reduced    |
  | `.cols-tokens`        | `/tokens`                   | `1.2fr .7fr 1.4fr .7fr 1fr 1fr 1fr .6fr` | brief §5.16, extended   |
  | `.cols-eab`           | `/acme/admin`               | `1.2fr 1.4fr 1.2fr .7fr 1.4fr 1fr .6fr`  | brief §5.15, extended   |
  | `.cols-directories`   | `/acme/admin`               | `1.6fr .8fr 2.2fr`                       | brief §5.15, derived    |

  Six ship the design's numbers unchanged, because cabin's column set
  for those tables is already the design's. The other five cannot,
  and the rule is stated once so that no track is a matter of taste:

  - **Where cabin renders a column the design's set does not have**
    (`.cols-tokens`, `.cols-eab`), the design's tracks stay on the
    columns they name and each extra column takes the share the
    design gives that *kind* of cell elsewhere: a name or label `1.2fr`,
    a status chip `.7fr`, a mono timestamp `1fr`, a right-aligned
    action cell `.6fr`.
  - **Where the design has a column cabin does not**
    (`.cols-users`: no Email), that track is dropped and the rest keep
    their shares — including onto a column of the same *kind*: cabin's
    `Created` takes the `.7fr` the design gives `Last seen`, because
    both are a date and the rule above is about kinds.
  - **Where the design's list is not cabin's list at all**
    (`.cols-audit`'s `Door` chip is cabin's `From` address;
    `.cols-directories` has no §5.15 track list because the design
    draws that block as cards), the tracks are derived from the same
    kinds and the divergence is recorded in the brief's register.

  So that a reader can check the two extended lists rather than trust
  them, both are mapped out:

  | `.cols-tokens` | Label | Role | Issuers | Status | Created | Last used | Expires | Actions |
  | -------------- | ----- | ---- | ------- | ------ | ------- | --------- | ------- | ------- |
  | track          | 1.2fr | .7fr | 1.4fr   | .7fr   | 1fr     | 1fr       | 1fr     | .6fr    |
  | from           | §5.16 Name | §5.16 Role | §5.16 Grant | chip | §5.16 Created | §5.16 Last used | timestamp | §5.16 Revoke |

  | `.cols-eab` | Label | Issuer | Key ID | Status | Bound account | Created | Actions |
  | ----------- | ----- | ------ | ------ | ------ | ------------- | ------- | ------- |
  | track       | 1.2fr | 1.4fr  | 1.2fr  | .7fr   | 1.4fr         | 1fr     | .6fr    |
  | from        | label | §5.15 Issued for | §5.15 Key id | chip | **divergence** | §5.15 Created | action |

  > **Correction (test-authoring), two entries in this requirement.**
  >
  > **`.cols-users` drops one track, not two.** The rule read "no Email,
  > no Last seen" and the list has five tracks against the design's six,
  > so only Email's `1.4fr` is gone; `Last seen`'s `.7fr` is what
  > cabin's `Created` column stands in. The tracks were right and the
  > sentence describing them was not, which is the worse way round: a
  > reader following the rule as written arrives at four tracks and a
  > table that does not line up.
  >
  > **And cabin renders one fewer cell than that list has tracks, for a
  > reader.** `users.html` wraps the `Actions` column in
  > `{% if can_manage %}`, so a viewer's row has four cells against five
  > tracks and the last one is empty. That is the existing behaviour and
  > this spec does not change it — FR-11 keeps `can_manage` gating every
  > control — but a track list is a claim about a row, and the claim is
  > only true for a superadmin. Named rather than fixed: making the
  > track set depend on the role is a second `cols-*` class for one
  > empty column, and hiding the heading for everyone is a content
  > change behind a layout one.
  >
  > **`.cols-eab`'s fifth track is a divergence and is now recorded as
  > one.** Under the rule above, `Bound account` maps onto the design's
  > `Used` and would take `.8fr`. It ships `1.4fr` because cabin's cell
  > holds *two* values where the design's holds one — a mono account id
  > and the parenthesised instant it was bound — and `.8fr` puts them on
  > two lines at every width. Recorded in the brief's "everything else"
  > register with that reason (FR-1). Before this correction the list
  > matched neither the design nor the rule that supposedly derived it,
  > and no criterion could catch it: AC-16 reads the brief only for the
  > six marked *verbatim*.

  > **Confirmed (test-authoring): the six marked *verbatim* are
  > verbatim.** Each was parsed back out of `docs/design/0027-brief.md`
  > §5 and compared against the list above — `2fr .6fr 1.1fr .8fr`,
  > `1.6fr 1.1fr 1fr .8fr` and `1.1fr .9fr 1.3fr 2fr` out of §5.1,
  > `1.7fr .7fr .7fr 1.5fr 1fr .5fr 1.2fr` out of §5.3,
  > `2fr .8fr .9fr 1.2fr` out of §5.13 and `2fr 1fr 1.6fr` out of §5.14
  > — and all six match. AC-16 keeps doing it from the file rather than
  > from numbers repeated in a test, which is what makes the word mean
  > something after the next edit to either.

  Dropping cabin's extra columns to match the design's track count is
  **not** an option, in either direction: a column is content, this is
  a redesign, and spec 0028 FR-5 already refused the symmetrical
  temptation for exactly this reason.

- FR-18: **Every class this spec renders is defined here, and the
  reserved list empties.** Spec 0027 FR-18, spec 0028 FR-10 and spec
  0029 FR-15 settled the rule: a class is defined by the spec that
  first renders one, because
  `test_stylesheet_and_templates_agree_in_both_directions` fails in its
  reverse direction on a rule with no user.

  | Class                       | First user                                                              |
  | --------------------------- | ------------------------------------------------------------------------- |
  | `.flash`                    | `layout.html` (FR-4)                                                     |
  | `.nav-count`                | the rail's Inventory entry (FR-7)                                        |
  | `.seg`, `.seg-on`           | the inventory's and the inventory export's status filter (FR-10, FR-15)  |
  | `.pill`, `.pill-on`         | the audit log's `actor_kind` filter (FR-12)                              |
  | `.toggle`                   | the ACME and settings checkboxes (FR-13)                                 |
  | `.copyable`                 | the two one-time secrets and the ACME directory URL (FR-14)              |
  | `.editing`                  | the open row on `/users` (FR-11)                                         |
  | `.avatar`                   | the users list and the rail footer (FR-11)                               |
  | `.chips`                    | the dashboard's services row (FR-8)                                      |
  | `.crl-grid`                 | the dashboard's revocation section (FR-8)                                |
  | the eleven `.cols-*` above  | FR-17                                                                    |

  _Supersedes spec 0029 AC-13's second half_, which asserts that each
  of `.nav-count`, `.seg`, `.pill`, `.toggle` and `.flash` has **no**
  rule in `cabin.css`. All five are rendered here — they are the design's
  remaining components and these are the pages that hold them — so the
  reserved-and-undefined list becomes empty and the criterion inverts:
  AC-17 asserts each of the five now has a rule **and** a literal user.
  That is the same guard doing the same job from the other side; what it
  stops is a sixth component being defined "while we are in the file",
  and with the list empty the general reverse direction is what stops
  it.

  `.panel`, `.panel-danger`, `.rows`, `.rowlink`, `.row-root`,
  `.row-child`, `.tree`, `.state-active`, `.state-retired`, `.facts`,
  `.kv`, `.kicker`, `.callout`, `.callout.warning`, `.note`, `.tag`,
  `.tile`, `.tile-count`, `.tile-label`, `.section`, `.field`,
  `.actions`, `.mono`, `.scroller`, `.card-narrow` and `.button-link`
  are reused and not redefined.

  **Status-like classes are written literally, never interpolated**
  (0028 FR-10, 0029 FR-15, same reason): `seg-on`, `pill-on`,
  `editing`, `state-active` and `state-retired` come out of an
  `{% if %}`, never a prefix glued to a value.

  **No new token.** `.flash` is `--surface` with the accent border the
  design gives its toast; `.nav-count` is the amber trio already in
  `:root`; the CA-key page's three key states are `--ok`, `--warn` and
  `--text-faint`. AC-18 keeps the palette register pinned at three rows.

- FR-19: **Wording is unchanged, and the exceptions are named here.**
  Every sentence, label, heading, help line and hint that exists on the
  thirteen templates today is byte-identical afterwards. Several
  hundred assertions depend on it, and this is the requirement that
  keeps this spec from touching them.

  There are two kinds of exception and both are enumerated:

  **One string changes.**

  | Before     | After    | Where              | Why                                                                     |
  | ---------- | -------- | ------------------ | ------------------------------------------------------------------------- |
  | `Transfer` | `Export` | the rail's fourth `nav-group` | the plan settles it from brief §4; FR-7 moves the membership with it |

  **New copy, string by string**, so that "new copy" cannot later mean
  "an edit to something that was already there":

  | String                                                                                                        | Where                | Source                                        |
  | ------------------------------------------------------------------------------------------------------------- | -------------------- | ----------------------------------------------- |
  | `Not permitted`                                                                                               | `not_permitted.html` h1 | brief §5.2, verbatim                          |
  | `Back to the inventory`                                                                                       | `not_permitted.html` button | brief §5.2, verbatim                      |
  | `Your role does not allow this page. Ask a superadmin if you need it.`                                        | `not_permitted.html` body | new; the `require_role` refusal (FR-5)      |
  | `This form was submitted with a token this session does not recognise. Open the page again and retry.`        | `not_permitted.html` body | new; the `verify_csrf` refusal (FR-5)       |
  | `Edit`                                                                                                        | every closed user row | new; the row-edit trigger (FR-11)             |
  | `Cancel`                                                                                                      | the open user row    | new; the way back out (FR-11, brief §5.17)    |

  Six strings, and the flash contributes **none of them** — FR-3's
  message is the audit summary that already exists. That is the point
  of deriving it: the largest new surface in this spec ships without a
  sentence anybody had to write.

  > **Correction (test-authoring): `stale` was in this table and is not
  > new copy.** `dashboard.html` already renders
  > `<span class="tag tag-bad">stale</span>` on a CRL past its next
  > update; FR-8 moves that tag from a table row into a card and moves
  > nothing else. It belongs in the paragraph below with the other
  > sentences this spec relocates without editing.
  >
  > The table is down to six. It is worth correcting rather than
  > shrugging at, because the table's whole job is stated one line
  > above it — "so that 'new copy' cannot later mean 'an edit to
  > something that was already there'" — and a string listed as new
  > that was already there is that failure, in the list written to
  > prevent it.

  The status filter's five labels, the audit pills' five labels, the
  `stale` tag on a CRL and the key-state sentences on the CA-key page
  are **not** new copy: they are the `<option>`, tag and cell text those
  pages render today, moved into a link, a card or a cell. Moving a sentence is not editing it, and AC-18
  compares multisets of text nodes, not positions.

- FR-20: **htmx adds no endpoint, and the attribute set is still
  closed.** Spec 0029 FR-2's four clauses hold unchanged and are not
  restated. What this spec adds to them, because it is the first spec
  to use the rule on a URL it did not also invent:

  1. Every `hx-get` here names a URL that exists for the
     no-JavaScript path first — `/users?edit={id}`,
     `/certs?q=&status=&page=`, `/audit?q=&action=&actor_kind=&page=`
     — and is fetched by htmx second. **No new route, no new query
     parameter except `edit`, no new handler.**
  2. **No `hx-post` appears anywhere in this spec.** Every mutation is
     a real form submit to the URL it submits to today. That is what
     makes FR-4's pop safe (Context) and it is asserted directly
     (AC-3).
  3. Each `hx-get` target answers **byte-identical** responses with and
     without `HX-Request` — spec 0029 AC-1's corrected clause, which is
     what forbids a fragment-aware branch creeping into a page handler.

- FR-21: **The geometry is re-proved over the whole application, with
  the pages that have never been probed.** This spec touches thirteen
  of the nineteen screens and adds three states no probe has seen: the
  flash panel, the not-permitted page, and login and setup.

  The overflow probe (spec 0027 FR-3, repaired), the contrast probe
  (0027 FR-14) and the focus probe (0027 AC-11) run over the full page
  list **plus** `/login`, `/setup` and a refused render, at 1440×1150
  and 390×900, in the dark and the light stylesheet, with `bad == []`
  and, **per page**, an `examined` floor that page can reach (AC-19).
  The flash is staged into at least one of those pages with a real
  message rather than left absent, since a panel that is not rendered
  is not a panel that can push a page sideways.

  **The three screens this spec adds have to be in the states they are
  probed for**, which is the other half of what "the fixture has all of
  them" means (AC-16's note). The probe fixture sets a base URL, holds
  an EAB key and holds a certificate expiring inside 30 days, because
  `.cols-directories`, `.cols-eab` and `.cols-expiring` are rendered by
  nothing otherwise — and every one of those states is reached by a
  request whose status is **asserted**, so that a refused fixture POST
  cannot leave a criterion looking satisfied by a page that was never
  drawn.

- FR-22: **Templates, the stylesheet and this spec's markdown are
  edited by a script through Bash, never with Edit/Write, and
  `git diff` is read after every change.** The PostToolUse formatter
  breaks Jinja tags apart — it has turned `{% if x == "y" %}` into
  `{% if x="" ="y" %}` — and it reflows markdown far outside the edited
  region, once turning a parenthetical containing a digit into a list
  marker. It also runs `ruff format` over Python blocks inside markdown,
  and spec 0029 shipped a gate failure that way. This has cost the
  project a debugging session eight times (0021 FR-13, 0023 FR-11, 0024
  FR-10, 0025 FR-15, 0026 FR-18, 0027 FR-25, 0028 FR-18, 0029 FR-18).
  This spec rewrites thirteen templates, writes a fourteenth, edits the
  stylesheet, and edits two markdown files under `docs/`.

## Interface Contract

### Routes

| Method | Path      | Auth    | Change                                              |
| ------ | --------- | ------- | ----------------------------------------------------- |
| GET    | `/users`  | session | one optional query parameter, `edit` (FR-11); same data |

**That is the whole of it.** No route is added, none is removed, and
every route in specs 0003–0029's contracts is unchanged in path,
method, guard, CSRF rule, form fields, status codes and redirect
target — `/api/v1`, MCP, ACME, the CRL routes and `/healthz` included.

Eighteen POSTs gain one call each (FR-3) and none of them changes what
it returns. One handler is registered for `HTTPException` (FR-6): it
changes the **body and content type** of a 403 raised on an interface
route and nothing else — not the status, not the headers, and not a
single byte of any other status or any other route.

### `cabin.sessions`

```python
class UserSession(Base):
    flash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


def set_flash(db: Session, row: UserSession, message: str) -> None: ...


def pop_flash(db: Session, row: UserSession) -> str | None: ...
```

- One column added; `token_hash`, `user_id`, `csrf_token`, `created_at`
  and `expires_at` are unchanged in type, nullability and meaning.
- `pop_flash` **reads and clears in one call**, and commits. It returns
  `None` when the column is `None`, and calling it twice on one row
  returns the message and then `None` — the property the whole
  mechanism rests on (AC-1).
- `create_session`, `get_session`, `touch_session`, `delete_session`,
  `delete_sessions_for_user` and `purge_expired` are unchanged in
  signature and in body. A new session's `flash` is `None` by column
  default, which is why `create_session` does not name it.

### `cabin.web.deps`

```python
def flash(request: Request, db: Session, message: str) -> None: ...


def base_context(request: Request, db: Session, user: User) -> dict[str, object]: ...
```

- **`flash` is new.** It reads `request.state.session` — the row
  `get_current_user` already loaded — and calls `sessions.set_flash`.
  It is the only door from the web layer to that column.
- **`base_context` gains a required `db` parameter**, positionally
  second. Every call site already holds a `Session` and passes that
  one; a second session opened for this would be a second transaction
  around a read-modify-write on the same row. The parameter is
  required rather than defaulted, for spec 0029 FR-6's reason: a
  default is a way for two call sites to disagree, and a test cannot
  pin it.
- `base_context` gains **exactly two context keys**: `flash`, the
  string `pop_flash` returned or `None`, and `nav["expiring"]`, the
  count FR-7's badge renders. `user`, `csrf_token` and the six existing
  `nav` flags are unchanged in name and in value.
- `get_current_user`, `require_role`, `require_admin`,
  `require_superadmin`, `current_principal`, `verify_csrf`,
  `current_actor`, `client_ip`, `certificate_or_404`, `is_htmx`,
  `preview_fragment`, `set_session_cookie`, `get_db`, `get_secrets`,
  `redirect_if_no_users` and `AuthRedirect` are unchanged in signature
  and in body. **In particular the two `raise HTTPException(403, …)`
  statements are not touched**: the detail strings stay
  `"forbidden for this role"` and `"csrf token mismatch"`, because FR-6's
  handler reads them to choose its body and because the API answers
  built from them must not move.

### `cabin.app`

```python
def _html_403_endpoints() -> frozenset[object]: ...
```

- `create_app` builds one frozen set of the endpoint callables carried
  by the ten interface routers FR-6 names, and registers one handler
  for `HTTPException` that renders `not_permitted.html` when the status
  is 403 **and** `request.scope.get("endpoint")` is in that set, and
  otherwise delegates to
  `fastapi.exception_handlers.http_exception_handler`.
- The set is built from the routers, never from a list of path
  prefixes (FR-6). A route the set does not contain keeps today's
  behaviour exactly, which is the direction a mistake here has to fail
  in.
- The `AcmeError` handler, the `AuthRedirect` handler, both
  middlewares, `/healthz`, the router inclusion order and the
  `/static` mount are unchanged. No handler is registered for
  `RequestValidationError` or for `Exception`.

### `cabin.web.ui`

```python
def _authorities(rows: list[CACertificate], now: datetime) -> list[dict[str, object]]: ...


def _users_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
    *,
    edit: int | None = None,
) -> Response: ...
```

- **`_authorities` is new** (FR-8/FR-9). One entry per `kind == "root"`
  row and one per `kind == "cross"` row, in `list_cas` order, each
  being `_ca_expiry`'s dictionary plus one key: `issuers`, a list of
  `_ca_expiry` dictionaries for that root's intermediates, empty for a
  cross row. **`_ca_expiry` is unchanged** in signature, in body and in
  its seven keys — the grouping is built around it, not into it, so
  that the number the dashboard prints for a row is the number it
  prints today.
- **`_users_page` gains `edit`**, keyword-only, default `None`. It
  becomes the context key of the same name and nothing else about the
  function changes: same rows, same `_user_issuers_view`, same
  `can_manage`, same `roles`, same status code.
- `users_list` gains `edit: str = ""` and passes it through after
  mapping an unrecognised value — a non-integer, or an id no row has —
  to `None` (FR-11). `create_user_route`, `update_role_route`,
  `reset_password_route`, `update_user_issuers_route` and
  `delete_user_route` pass `edit=user_id` on their error re-renders,
  call `deps.flash` on their success paths (FR-3), and are otherwise
  unchanged — same guards, same fields, same 400, same 303, same audit
  event.
- `dashboard` gains `_authorities`'s output under the context key
  `authorities`; **`ca_certs` is removed from the context**, because
  nothing renders it once the grouped list ships and a context key with
  no reader is the next spec's puzzle. `expiring`, `expiring_more`,
  `counts`, `crls`, `events`, `services`, `ca_configured`,
  `ca_no_issuer_roots` and `tls_banner` are unchanged.
- `_login_and_redirect`, `_tls_mode`, `_tls_banner`, `_anon_context`,
  `_days_until`, `_parse_role`, `_user_issuers_view`, `setup_form`,
  `setup_submit`, `login_form`, `login_submit` and `logout` are
  unchanged.

### `cabin.web.certs_ui`, `audit_ui`, `tokens_ui`, `acme_ui`, `settings_ui`, `ca_ui`, `transfer_ui`

- **No new function in any of them**, and no signature change except
  the `db` argument each now passes to `base_context`.
- `certs_ui._page_url` and `audit_ui._page_url` are unchanged and gain
  a second caller each: the filter links of FR-10 and the pills of
  FR-12 are built from the function the pager already uses, which is
  what keeps a filter link and a pager link from disagreeing about
  what "carry the other parameters through" means.
- `certs_list`, `audit_page`, `tokens_page`, `acme_page`,
  `settings_page`, `trust_bundle_page`, `ca_key_page` and
  `inventory_page` are unchanged in signature, guard and returned
  context, except that `_ca_key_page`'s rows are grouped the way
  `_authorities` groups the dashboard's (FR-9) — one entry per root
  with its intermediates under `issuers`, one per cross row at root
  level — carrying the same three cell values per row it carries today.
- The thirteen POSTs in these modules named by FR-3 gain one
  `deps.flash(...)` call each, on the success path, after
  `audit.record`, with the same string. Nothing else in them changes:
  not a guard, not a form field, not a status code, not a redirect
  target, not an audit action, not a detail payload.
- `certs_ui._issue_preview`, `_sign_preview`, `ca_ui._create_preview`,
  `transfer_ui._import_preview` and the four preview routes spec 0029
  added are untouched, and **no preview writes a flash** — a preview is
  a read (spec 0029 FR-3) and a read that leaves a message behind is
  not one.

### `cabin.web.templates`

| File                          | Change                                                                                                   |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `not_permitted.html`          | **new**; extends `layout.html`, no `nav_current`, one of two bodies (FR-5)                                |
| `layout.html`                 | the flash panel inside `.shell` (FR-4); the fourth nav group's label and membership, and the count badge (FR-7); the footer avatar |
| `dashboard.html`              | tiles, expiring, the grouped authorities list, CRL cards, service chips, activity (FR-8)                 |
| `certs_list.html`             | the `.seg` filter links, the hidden `status`, the `#inventory` region, the pager's `hx-` attributes (FR-10) |
| `users.html`                  | closed rows with an `Edit` trigger, the `.editing` row, the avatar cell (FR-11)                          |
| `audit.html`                  | the `.pill` links, the `#audit-log` region (FR-12)                                                       |
| `acme.html`                   | the two toggles, `.cols-directories`, `.cols-eab`, `.copyable` on the URL and the secret (FR-13, FR-14)  |
| `settings.html`               | the two toggles inside the one form (FR-13)                                                              |
| `tokens.html`                 | the secret banner, `.copyable`, `.cols-tokens` (FR-14)                                                   |
| `transfer_trust_bundle.html`  | `.rows`/`.cols-trust-bundle`, rows not clickable (FR-15)                                                 |
| `transfer_ca_key.html`        | the grouped list, `.cols-ca-keys`, the danger-outline export button (FR-15)                              |
| `transfer_inventory.html`     | the same `.seg` filter links as `/certs` (FR-15)                                                         |
| `login.html`, `setup.html`    | nothing but the `.card-narrow` treatment; no markup added, no string changed (FR-16)                     |

No template gains a `<details>`, a `<summary>`, a `<script>` or an
`hx-post` (spec 0026 FR-16's first half stands; spec 0029 FR-2 clause 3
and 4 stand). No template's `nav_current` changes.
`form_macros.html` and `ca_macros.html` are untouched and
`test_web_layout.NOT_PAGES` gains `not_permitted.html` **only if** the
page is found not to name itself to the rail — it does extend
`layout.html` and it does render inside it, so it is a page and stays
out of that set; what it lacks is a `nav_current`, and AC-5 asserts
that no rail entry is marked on it.

### `cabin.web.static/cabin.css`

The classes of FR-18, the eleven column templates of FR-17, one new
`@keyframes cabinToastOut`, `.flash` added to the existing
`@media (prefers-reduced-motion: reduce)` block, and the `@media` rule
that repositions the flash below 60rem. **No token is added and no
colour literal is written outside the two `:root` blocks** (spec 0027
FR-21). No existing class is renamed: the eleven load-bearing names
spec 0027 AC-16 pins survive untouched, and so do the twelve numbers of
spec 0027 FR-22.

### Schema, services, API, MCP, ACME

One column on one table, one migration (FR-2). No other column, no enum
value, no index, no constraint. No change to `ca/service.py`,
`ca/certs.py`, `ca/leaf.py`, `audit.py`, `api/`, `mcp/` or `acme/`. No
new audit action: the flash carries an existing summary and records
nothing of its own.

## Acceptance Criteria

Every criterion is anchored to the element, the computed value, the row
or the call it is about — a parsed element, a computed style, a column
read back out of the database — never to a substring appearing
somewhere in a page. Where a state is meant to differ, both halves are
in one criterion, so that a build rendering nothing and a build
rendering everything each fail.

No criterion here states what any test outside this spec will do. Spec
0029 AC-18 made that claim, it was wrong, and the cost of it was hidden
until the implementation existed.

The fixture, unless stated otherwise: hierarchy **alpha** — a root with
two intermediates — hierarchy **beta** with one intermediate, a cross
certificate for beta's root signed by alpha's root, a superadmin, an
admin, a viewer, one API token, one certificate expiring inside 30
days and one expiring outside it, and a base URL set.

- AC-1: **The flash is written once, shown once, and gone.** Five
  clauses, one test, as a superadmin:
  1. `POST /users/{viewer}/role` with a role change returns 303.
  2. Reading the `sessions` row for this session directly out of the
     database, `flash` is not `None` and equals the `summary` of the
     `audit_events` row that POST wrote — the two are compared to each
     other, not both to a literal.
  3. `GET /users` renders exactly one element with class `flash`,
     inside `.shell` and as a sibling of `<main id="main">`, whose text
     contains that summary.
  4. Reading the same `sessions` row again, `flash` **is** `None`.
  5. A second `GET /users` renders **zero** elements with class
     `flash`.

  _Goes red if_: the clear is not committed — clause 4 passes on the
  in-memory object and clause 5 is the one that catches it, which is
  why the criterion asserts the second render and not only the column.
  A build that writes and never renders fails clause 3; one that
  renders and never clears fails clauses 4 and 5; one that never writes
  fails clause 2. **Nothing else in the suite would notice any of
  them**: no existing test reads that column or looks for that element.

- AC-2: **A no-op says nothing, and a real change says something.**
  Both halves, one test, against one API token:
  1. `POST /tokens/{id}/revoke` on a live token returns 303,
     `audit_events` gains exactly one row, the session's `flash` equals
     that row's summary, and `GET /tokens` renders it.
  2. `POST /tokens/{id}/revoke` on the **same, now revoked** token
     returns 303, `audit_events` gains **no** row, the session's
     `flash` is `None`, and `GET /tokens` renders zero `.flash`
     elements.

  _Goes red if_: the flash is set before the work rather than after the
  event, or set unconditionally at the top of the handler — clause 2
  would announce a revocation that did not happen, which is the panel
  saying something when nothing did.

- AC-3: **The flash is not in the URL, and no mutation runs through
  htmx.** Three clauses, one test:
  1. `GET /users?flash=deleted+user+%27root%27` as a superadmin returns
     200 and renders **zero** `.flash` elements, so a link cannot make
     cabin say anything.
  2. Each of the eighteen POSTs of FR-3 is exercised once and its
     `Location` header is parsed: none carries a `flash` query
     parameter, and each equals the target that route redirects to
     today, string for string.
  3. Across every file in `src/cabin/web/templates/`, the `hx-post`
     attributes are **exactly spec 0029's four previews**, one each in
     `ca_new.html`, `certs_new.html`, `certs_sign.html` and
     `transfer_ca_import.html`, and the count of `hx-get` attributes is
     greater than zero — so a build that renders no htmx at all cannot
     pass clause 3 by having nothing to count.

  > **Correction (test-authoring), clause 3.** It read "the count of
  > `hx-post` attributes is **zero**" and no build can satisfy that.
  > Spec 0029 FR-3 put four of them on the four preview pages, and this
  > spec's own Interface Contract says those four preview routes are
  > untouched — so the clause forbade markup this spec deliberately
  > leaves in place. What FR-20 clause 2 actually requires is that *this
  > spec* adds none, and the satisfiable form of that is the one above:
  > the four are pinned to the four files that carry them, by name, so
  > that a fifth fails and so does moving one of the four.
  >
  > Pinned rather than counted, for the reason spec 0029's own
  > correction gives about `<script>`: a count alone passes on a build
  > that moved one.

  _Goes red if_: the flash is smuggled into the redirect target "so it
  survives a lost session", which is the query-parameter design with a
  column beside it and inherits every property the column was chosen
  to avoid.

- AC-4: **The panel animates, and stops animating when asked to.**
  Parsed out of `cabin.css`, in one test:
  1. the rule set selecting `.flash` declares an `animation` naming
     both `cabinToast` and `cabinToastOut`, with a delay of `3.2s` and
     `forwards` on the second;
  2. `cabin.css` declares exactly three `@keyframes` blocks, named
     `cabinIn`, `cabinToast` and `cabinToastOut`;
  3. the set of selectors that declare an `animation` **outside** the
     `@media (prefers-reduced-motion: reduce)` block is a subset of the
     set of selectors that appear **inside** it — computed from the
     file both times, never a hard-coded list, so a fourth animated
     element added later fails this rather than passing unnoticed;
  4. inside that media block, every one of those selectors' `animation`
     is `none`.

  In the same test, rendered in Chrome at 1440 with a flash present:
  the computed `animation-name` on the `.flash` element names both
  keyframes and `animation-fill-mode` contains `forwards`.
  _Goes red if_: the hide is written as a `transition` (which needs a
  state change nothing produces), or the reduced-motion block is
  extended by copying its current selector rather than by covering the
  new one — clause 3 is a set comparison for exactly that reason.

- AC-5: **HTML for the interface, unchanged bytes for the other three
  doors.** Both directions, one test.

  **HTML, on three URLs chosen because each would fail a different
  wrong implementation:**
  - a `viewer` session `GET /tokens` (a plain UI prefix) → 403,
    `Content-Type` starts `text/html`, the body parses to an `<html>`
    with `<aside class="rail">`, `<main id="main">`, exactly one `<h1>`
    reading `Not permitted`, exactly one `<a>` **inside
    `<main id="main">`** — carrying `button-link`, whose `href` is
    `/certs` — and **no** element carrying `aria-current="page"`;
  - a `viewer` session `GET /acme/admin` → the same, which is the
    clause a path test on `/acme` fails;
  - a `viewer` session `POST /users/{id}/delete` with a valid CSRF
    token → 403 and the same page, so the rule is about the route and
    not about the method.

  **JSON, on three more:**
  - an API token whose role may not write, on a `POST /api/v1` route it
    is refused → the status, the `Content-Type` and the parsed body it
    returns today, compared against the same request made against the
    application built without this spec's handler registered;
  - an ACME request that is refused → likewise, `application/problem+json`
    and its own document, through `AcmeError`'s own handler;
  - `POST /mcp` with no credential → likewise.

  **And the census, which is what makes the six requests a sample
  rather than the whole claim:** over every route the application
  will match, the set the handler would answer HTML for is computed and
  asserted equal to the set of routes contributed by the ten interface
  routers of FR-6, collected from those router objects. Both sets are
  asserted non-empty and neither is allowed to be all of them.

  > **Two mechanical traps, found while writing this (test-authoring).**
  >
  > **`app.routes` does not hold this application's routes.** FastAPI
  > 0.141 appends one `_IncludedRouter` wrapper per `include_router`
  > call rather than splicing the routes in, so `app.routes` is five
  > entries — the four FastAPI adds and `/healthz` — plus fourteen
  > wrappers. A census written literally over `app.routes` looks at
  > none of cabin's own routes and passes on everything. It has to walk
  > each wrapper's `original_router.routes`; done that way it is 106
  > routes. This is why the sentence above says "every route the
  > application will match" rather than naming the attribute.
  >
  > **`GET /mcp` is a 405 that no exception handler sees.** Starlette
  > answers method-not-allowed while routing, before the handler stack
  > this requirement is about runs at all, so a comparison made on it is
  > green against every implementation — including one that renders HTML
  > for every 403 on every door. The MCP door is exercised as a `POST`
  > with the streamable-HTTP `Accept` header, which reaches MCP's own
  > credential check and answers 401. Any door whose refusal is a 405
  > measures routing, not this boundary.

  > **Correction (test-authoring): this criterion contradicted FR-5 and
  > the requirement is the half that was right.** It asked for "exactly
  > one `<a>` whose `href` is `/certs`" over the whole page, and FR-5's
  > own first sentence puts the rail on that page — a rail whose
  > Inventory entry is `href="/certs"`. The two cannot both hold, and the
  > only way to satisfy the count as written is to point the button
  > somewhere else, which makes FR-5's own literal
  > `<a class="button-link" href="/certs">` false.
  >
  > FR-5 is right and stands unchanged. What the clause is for is the
  > design's §5.2 "one primary link", and a primary link is part of the
  > page's own content, not of the shell around it — so it is counted
  > inside `<main id="main">`, where exactly one is exactly the claim.
  > The rail's link is not a second primary link; it is the rail, and
  > FR-5 wants it there.

  _Goes red if_: the classifier is a path prefix (the `/acme/admin`
  clause), if it is registered for every status (a 404 on `/api/v1`
  would change), or if it is registered for `Exception` and swallows
  ACME's own handler.

- AC-6: **The two bodies are told apart, and the status never moves.**
  One test, two halves:
  1. a `viewer` `GET /tokens` → 403 whose body contains the role
     sentence of FR-19 and **not** the CSRF sentence;
  2. an admin `POST /settings` with a wrong `csrf_token` → 403 whose
     body contains the CSRF sentence and **not** the role sentence.

  In both, the status is 403 and not 400, 401 or 302, and
  `audit_events` gains no row.
  _Goes red if_: one body is rendered for both causes — the reader of a
  stale form would be told to ask a superadmin for a role they already
  have, and the fix that works is the one they are not offered.

- AC-7: **The rail's fourth group, and a badge that is absent at
  zero.** One test, both halves:
  1. `GET /` as a superadmin: the `nav-group` labels are exactly
     `["Overview", "Certificate authority", "Certificates", "Export", "Access"]`
     in that order; the rail holds exactly 16 links; the hrefs of
     `/transfer/ca-import` and `/transfer/cross-import` appear between
     the second group heading and the third, and `/transfer/trust-bundle`,
     `/transfer/ca-key` and `/transfer/inventory` between the fourth and
     the fifth; and the labels of all 16 are unchanged.
  2. With one certificate expiring inside 30 days, the `/certs` link
     contains exactly one `.nav-count` whose text equals
     `certs.status_counts(db, now)["expiring"]` as an integer. On a
     second instance with none, the `/certs` link contains **zero**
     `.nav-count` elements — not one reading `0`.

  _Goes red if_: the label moves and the membership does not, or the
  badge is rendered unconditionally.

- AC-8: **The dashboard's authorities block is the grouped list, and no
  row is lost.** On `GET /` as an admin, with alpha (root + two
  intermediates), beta (root + one) and one cross certificate:
  1. the block's `<tbody>` holds exactly as many `<tr>` elements as
     there are `ca_certificates` rows — spec 0017 FR-14, measured
     against the database and not against a literal;
  2. the two root rows carry `row-root`, each root's intermediates
     carry `row-child` and follow their own root immediately in
     document order, and the cross row carries `row-root` with a kind
     tag reading `cross`;
  3. each row's expiry text equals `_ca_expiry(row, now)["not_after"]`
     for that row;
  4. in `cabin.css`, the set of rule-block selectors naming each of
     `row-root`, `row-child`, `tree`, `state-active`, `state-retired`
     and `rowlink` is **the set the file carried at this spec's base
     commit** — this spec adds a rule for none of them (FR-9's
     correction; each set is also asserted non-empty, so the comparison
     cannot pass on a stylesheet that never had the component in it).

  _Goes red if_: the grouped list is re-implemented here under new
  names (clause 4), or a cross row is dropped because it has no root to
  hang under (clause 1) — which is the shape the change would take if
  the block were built by filtering for `kind == "root"`.

- AC-9: **The inventory's filter bar is five links that keep the search,
  and everything still works with no htmx.** On
  `GET /certs?q=nas&status=valid&page=1` as an admin:
  1. exactly one `.seg` element, containing exactly five `<a>`
     elements, whose texts are `STATUS_FILTERS` in that order;
  2. each `href` equals `certs_ui._page_url("nas", that_status, 1)` —
     so each carries `q=nas` and `page=1` — and exactly one of the five
     carries `seg-on`, the one whose status is `valid`;
  3. each carries `hx-get` equal to its own `href`,
     `hx-select="#inventory"` and `hx-target="#inventory"`, and the
     element with `id="inventory"` exists and contains the table and
     the pager;
  4. the search form is still `method="get" action="/certs"` and now
     carries `<input type="hidden" name="status" value="valid">`.

  Then, with **no `HX-Request` header anywhere in the test**: following
  the `expired` link returns 200 with `seg-on` on `expired` and the
  search text still in the box; and with 51 certificates the pager's
  `Next →` returns 200 and a second page of rows.
  _Goes red if_: the links drop `q` — every click would silently
  discard the operator's search, which no other assertion here would
  see — or if the control is a `<button>` or a `#`-only anchor, which
  has no address to follow without JavaScript.

- AC-10: **The inventory still says newest first, and means it.** On
  `GET /certs` as an admin:
  1. the page's lead paragraph reads
     `Everything this CA has issued, newest first.`, byte for byte;
  2. no `<th>` on the page is an `<a>` or contains one;
  3. `GET /certs?sort=subject_cn&dir=asc` returns 200 and the list of
     rendered common names is identical, in order, to `GET /certs`'s.

  _Goes red if_: sorting is implemented after all — the page would keep
  a sentence that is false in every state but one, and clause 3 is what
  catches an implementation that quietly honours a parameter the spec
  declined.

- AC-11: **The users row edit is URL state, in both directions, and
  `?edit=` grants nothing.** One test, as a superadmin unless stated:
  1. `GET /users`: **zero** `<form>` elements inside `<tbody>`; every
     row carries `id="user-{id}"` and exactly one `<a>` whose `href` is
     `/users?edit={id}#user-{id}` with `hx-get` on the same URL and
     `hx-select`/`hx-target` on `#user-{id}`; the Issuers cell is text.
  2. `GET /users?edit={id}`: exactly one `<tr>` carries `editing`, its
     `id` is `user-{id}`, and it contains exactly four `<form>`
     elements whose actions are `/users/{id}/issuers`, `/users/{id}/role`,
     `/users/{id}/password` and `/users/{id}/delete`, each with the
     fields, method and hidden `csrf_token` it carries today; every
     other row still holds no form.
  3. `GET /users?edit=999999` and `GET /users?edit=banana` return 200
     with zero `editing` rows.
  4. As a **viewer**, `GET /users?edit={id}` returns 200 with zero
     `<form>` elements inside `<tbody>` and zero `editing` rows.
  5. `POST /users/{id}/role` with a role that would remove the last
     superadmin returns 400 and its body has that row `editing`.

  _Goes red if_: `?edit=` is read before `can_manage` (clause 4) — the
  hole spec 0029 found in review, in the one place this spec repeats
  the pattern — or if the id moves with the state (clauses 1 and 2 both
  name `user-{id}`), which breaks the anchor and the swap target at
  once.

- AC-12: **The audit pills are links and carry the other filters.** On
  `GET /audit?q=cabin&action=ca_renewed&actor_kind=token`:
  1. the `.pill` elements are exactly the `ACTOR_KIND_FILTERS` values,
     in order, and every one is an `<a>`; zero `<button>` elements
     appear among them;
  2. each `href` equals `audit_ui._page_url("cabin", "ca_renewed", that_kind, 1)`,
     so each carries the search text and the action filter through;
  3. exactly one carries `pill-on`, the one for `token`;
  4. the `action` `<select>` is still inside the GET form, with one
     `<option>` per `ACTION_FILTERS` entry and the same submit button.

  Then, with no `HX-Request` header, following the `acme` pill returns
  200 with `pill-on` on `acme` and `action=ca_renewed` still active.

  > **Correction (test-authoring): this criterion still used the design's
  > five.** FR-12's own correction records that cabin's pill values are
  > `ACTOR_KIND_FILTERS` — `all / user / token / system / acme` — and not
  > the design's `all / ui / api / acme / mcp`; only the cardinality
  > matches. The criterion was written before that correction and kept
  > `api` and `mcp`, neither of which cabin has. `audit_ui.py:67`
  > normalises an unrecognised `actor_kind` to `all`, so clause 3 asked
  > for `pill-on` on a filter the page cannot carry and the last clause
  > asked a pill that does not exist to be followed — a criterion no
  > build could pass, in the requirement whose own correction was written
  > to stop exactly this. `token` is the value the design calls `api`;
  > `acme` is the one name both lists share, which is why it is the pill
  > that gets followed.

  _Goes red if_: the pills drop the action filter, which would make
  every pill a reset disguised as a narrowing.

- AC-13: **The toggles are checkboxes, and one Save still writes both
  flags.** One test, both halves, which is the case the design's own
  recommendation would have broken:
  1. On `GET /acme/admin` as an admin: the elements with `id="acme_enabled"`
     and `id="acme_require_eab"` are `<input type="checkbox">` carrying
     `toggle`, both inside the single `<form action="/acme/admin">`,
     which has exactly one `<button type="submit">`; neither id belongs
     to a `<button>` or an `<a>`.
  2. `POST /acme/admin` with both checked → both settings read back
     true. Then `POST /acme/admin` with **only** `acme_enabled` → 
     `acme_enabled` is true and `acme_require_eab` is false, which is
     the behaviour spec 0019 already has.
  3. The same shape on `/settings` for `acme_enabled` and
     `mcp_enabled`, plus: after a POST that changes only `mcp_enabled`,
     `base_url` and `dns_resolvers` read back what they were before.

  _Goes red if_: a toggle is made its own submit button — clause 2's
  second POST would come from a form the browser submits in full, and
  the other flag would be cleared. That is the failure the brief's
  recommended shape produces on these two pages and nothing else here
  would see it.

- AC-14: **A one-time secret is shown once and stored nowhere.** One
  test:
  1. `POST /tokens` returns **200**, not 303, with `Cache-Control: no-store`,
     and the secret inside an element carrying `copyable`;
  2. in Chrome, that element's computed `user-select` is `all`;
  3. the secret string appears in **no** `sessions` row's `flash`, in
     **no** `audit_events` row's `summary` or `detail`, and in no
     response to the following `GET /tokens`;
  4. the same four clauses for `POST /acme/admin/eab-keys` and its EAB
     secret.

  _Goes red if_: either route is "made consistent" with FR-3 by
  redirecting with a flash — a live bearer token would be written to a
  database column in clear text and shown again on the next page load.
  This is the one change in this spec that would be a security
  regression wearing the shape of a tidy-up, which is why it is a
  criterion and not a sentence.

- AC-15: **The CA-key page groups, and the trust bundle stays
  unclickable.** One test:
  1. `GET /transfer/ca-key` as a superadmin: the table carries
     `cols-ca-keys`, its rows are grouped exactly as AC-8 clause 2
     describes, and the multiset of `Key` cell texts equals the
     multiset that page renders at this spec's base commit;
  2. `GET /transfer/trust-bundle`: zero `.rowlink` elements, and each
     row's only `<a>` is its `Download this hierarchy` link;
  3. in Chrome, hovering a trust-bundle row leaves its computed
     `background-color` unchanged, and hovering an authorities row on
     `/` does not — the hover is scoped to rows that go somewhere
     (spec 0028 FR-8), and both halves are here because a build that
     highlights everything and a build that highlights nothing must
     each fail.

  > **Correction (test-authoring): the base commit's multiset is
  > recorded, not resolved.** Clause 1 read the two `Key` sentences out
  > of `transfer_ca_key.html` with `git show` at the base commit. That
  > commit is on `feat/0.2.0`: CI checks out shallow and does not have
  > the object, and a squash merge of PR #17 deletes it — so the
  > comparison failed on the runner while passing locally, and
  > deepening the checkout would only have moved the failure to the
  > merge. The two sentences are frozen in `CA_KEY_STATES` instead,
  > because what FR-15 claims is not "these match a commit" but "the
  > page keeps the strings it has", and that is a claim about the
  > strings. The clause is also **strengthened**: the fixture must
  > render *both* branches of `row.exportable`, or a subset check
  > against a one-branch render would pass a reworded `else`.

- AC-16: **The column templates are the design's where the design has
  one.** In Chrome at 1440, for each of the eleven `cols-*` classes of
  FR-17, `getComputedStyle(tr).gridTemplateColumns` resolves to widths
  in the proportion its track list describes, within one pixel per
  track; and each is read off `cabin.css` in the `minmax(0, Nfr)` form,
  because only the file says which form was written (spec 0028 AC-9's
  shape). The six marked *verbatim* are compared against the numbers
  parsed out of `docs/design/0027-brief.md` §5, not against numbers
  repeated in the test. The stylesheet declares column templates for
  **exactly** these eleven plus spec 0028 FR-9's three, which is the
  census row 8 of the overturns table moves here.
  _Goes red if_: a bare `Nfr` is written, or a "verbatim" track list
  drifts from the brief — the last clause is what makes the word
  verbatim mean something.

  > **Note (test-authoring): the eleven have to be *rendered* before a
  > browser can measure them.** `.cols-expiring` needs a certificate
  > expiring inside 30 days, `.cols-eab` an EAB key, `.cols-ca-keys` a
  > stored CA key — the criterion's fixture has all of them, and the
  > probe's page list is what carries them to Chrome. A class no
  > rendered row uses is reported as missing rather than skipped, so
  > "measured against a browser" cannot quietly become "measured
  > against the file twice".
  >
  > **Correction (test-authoring): the fixture did not have them, and
  > saying it did is how that went unnoticed.** The probe fixture's
  > base-URL POST was refused (a base URL may not name a port while TLS
  > is on, and the probes run with TLS on) and its EAB-key POST was a
  > 422 (no `issuer_id`), and neither status was asserted — so no base
  > URL was ever set, no EAB key ever existed, and `/acme/admin` rendered
  > neither `.cols-directories` nor `.cols-eab` for a browser to measure.
  > Its one certificate ran for 90 days, so the dashboard's
  > `Expiring soon` table was never drawn either. Three of the eleven
  > column templates were checked against the file and against nothing
  > else. FR-21 now states the states, and each of them is reached by a
  > request whose status is asserted: a fixture whose POST is refused is
  > a fixture that never arrives, and it is the assertion that says so.

- AC-17: **The stylesheet and the templates agree, in both directions,
  and nothing is reserved any more.** Stated as the property, over the
  full page list — the nineteen screens plus `/login`, `/setup` and a
  refused render:
  1. every class name any of those pages renders has a rule in
     `cabin.css`;
  2. every class name `cabin.css` declares a rule for has a user — a
     name on one of those pages, or a name written **literally** in a
     template — with one exemption, the `tag-*` values that exist only
     as a `tag-{{ … }}` interpolation, and **no addition** to it;
  3. each of `.nav-count`, `.seg`, `.pill`, `.toggle` and `.flash` has
     a rule **and** a literal user in some template, and the set of
     names reserved-and-undefined by specs 0027–0029 is empty.

  > **Correction (test-authoring).** This criterion named
  > `test_stylesheet_and_templates_agree_in_both_directions` and said
  > it would pass — a claim about a test outside this spec, which this
  > section's own preamble forbids and cites spec 0029 AC-18 for. The
  > preamble was right and the criterion was wrong: written that way it
  > is satisfied by editing that test, and the reader cannot tell from
  > it what the build has to do. The three clauses above are the
  > property; which test carries them is a matter for the Test list.

  > **Confirmed (test-authoring): clause 1 bites, and what it caught is
  > `tag-unused`.** With the probe fixture actually holding an EAB key
  > (FR-21), `/acme/admin` renders `<span class="tag tag-unused">` for a
  > key that has not been bound — `acme_ui.py:133`'s third status,
  > unchanged by this spec — and `cabin.css` declares a rule for
  > `.tag-bound` and for `.tag-revoked` and none for `.tag-unused`. The
  > gap is older than this spec and no criterion could see it, because no
  > fixture in the suite had ever created an EAB key. Clause 1 takes no
  > exemption: the `tag-*` exemption belongs to clause 2 and is about
  > rules with no user, not about markup with no rule.

  _Goes red if_: a `cols-*` or a state class is written as
  `cols-{{ … }}` or `seg-{{ … }}` — the rule would have no literal
  user and clause 2 would fail.

- AC-18: **Not one existing sentence changed, and the one that did is
  the one named.** For each of the thirteen templates FR-1 edits, the
  multiset of text a reader sees — every literal run left after the
  Jinja tags, the HTML tags and the comments are removed — is compared
  against the same template as it stood at this spec's base commit,
  read out of git.
  - Nothing is lost, with **one** permitted removal on **one**
    template: the string `Transfer` from `layout.html`'s rail, which
    FR-19 replaces with `Export`.
  - Every addition is one of FR-19's two tables: the one string that
    changes, and the seven new ones. An addition not in them fails.
  - `not_permitted.html` carries nothing but strings from those tables,
    and carries all four of its own.

  > **Correction (test-authoring), twice over.**
  >
  > **The instrument cannot be built.** This asked for each page
  > "rendered through the templates as they stood at this spec's base
  > commit, **on one instance with one database**". One instance cannot
  > render both generations: FR-8 removes `ca_certs` from the
  > dashboard's context (Interface Contract) and `web/__init__.py` sets
  > `StrictUndefined`, so the base commit's `dashboard.html` against the
  > new context is a hard error rather than a comparison. A second
  > instance is not a way out either — the two would differ in every
  > serial, date and id, which is exactly what the "named additions"
  > clause was there to absorb.
  >
  > What FR-19 actually says is about the *templates*: "every sentence,
  > label, heading, help line and hint that exists on the thirteen
  > templates today is byte-identical afterwards." That is what is
  > compared, and it is the stronger instrument for this requirement: it
  > is deterministic, it needs no fixture to reach every branch, and it
  > sees a help line dropped from a page no fixture renders. What it
  > gives up is a sentence that moves out of a template and into
  > Python — nothing in FR-1's boundary does that, and FR-3 ships the
  > flash with no copy of its own precisely so that none has to.
  >
  > **The `/users` union clause is gone with it.** It existed because a
  > *rendered* closed row does not carry the four forms' labels. The
  > templates carry both states in one file, so the disclosure needs no
  > special case at all.
  >
  > **The last bullet named three tests outside this spec and said they
  > would pass** — the claim this section's preamble forbids and cites
  > spec 0029 AC-18 for. The preamble was right. What that bullet was
  > reaching for is already a requirement: FR-18 says no token is added
  > and no colour literal is written outside the two `:root` blocks, and
  > the palette register is pinned at three rows by spec 0027's own
  > criterion. Restating it here bought nothing and broke the rule this
  > spec had just written down.

  _Goes red if_: a heading is "improved" while the markup around it is
  rewritten, which fails both halves at once. This is the change that
  costs several hundred text assertions and that no other criterion
  here would see.

  > **Correction (test-authoring), third: the first two clauses are
  > retired and the third is kept.** They cannot be measured after this
  > branch merges. The base commit is on `feat/0.2.0`; CI's checkout is
  > shallow and does not have the object, so this failed on the runner
  > while passing locally, and a squash merge of PR #17 would delete it
  > outright. Deepening the checkout buys exactly one merge.
  >
  > That is what forced the question, not what answers it. The answer
  > is that clauses 1 and 2 assert **a property of one diff, not of the
  > codebase** — "the diff from the base commit to the 0030 merge
  > reworded nothing" was true when it was written, stays true, and no
  > later commit can falsify it, so there is no regression left to
  > catch. Its evidence is the diff, which is better evidence than a
  > test because it cannot be edited into agreeing with the templates.
  > This is spec 0028's own argument for retiring
  > `test_only_layout_html_changed`, applied to the same shape.
  >
  > Clause 3 is different and is **kept, as its own test**
  > (`test_the_refusal_page_carries_only_the_copy_fr_19_names`).
  > `not_permitted.html` did not exist before this spec, so every
  > sentence on it is new by construction: there is no baseline it
  > could be compared against and none it needs, and "the page carries
  > nothing but strings FR-19 names, and all four of its own" stays
  > checkable against the file forever.
  >
  > What the retired clauses were also buying is not lost. The four
  > sentences' *behaviour* — which refusal renders which — is AC-6,
  > read off real 403 responses; `Transfer` → `Export` is AC-7, read
  > off the rendered rail; and the flash carrying no copy of its own is
  > AC-3.

- AC-19: **Nothing scrolls sideways, everything is readable, and the
  flash is inside the viewport.** The overflow probe, the contrast
  probe and the focus probe over the full page list plus `/login`,
  `/setup` and a refused render, at 1440×1150 and 390×900, in the dark
  and the light stylesheet, `bad == []` **and an `examined` floor per
  page**, with a flash staged into at least one page in each run rather
  than left absent. In the same run, at 390 the flash element's
  `getBoundingClientRect().left` is `>= 0` and its `right` is
  `<= innerWidth`; at 1440 its `left` is the design's 250.

  The floors are two tiers:

  | Probe    | The twenty application screens | `/login` | `/setup` | the refused render |
  | -------- | ------------------------------ | -------- | -------- | ------------------ |
  | overflow | `>= 20`                        | `>= 10`  | `>= 10`  | `>= 20`            |
  | contrast | `>= 30`                        | `== 4`   | `== 5`   | `>= 15`            |
  | focus    | `>= 5`                         | `== 3`   | `== 3`   | `>= 5`             |

  > **Correction (test-authoring), twice over.**
  >
  > **The floor is per page, and it is written per page here because
  > that is what it has always been measured as.** This criterion said
  > "per run". Summed over a run, a screen the probe went blind on hides
  > behind the twenty-two it did not, which is the failure the floor
  > exists to catch — so the wording is corrected to the measurement
  > rather than the measurement loosened to the wording.
  >
  > **And a floor calibrated on an application screen is one the three
  > screens FR-16 adds cannot reach.** `/login` offers two fields and a
  > submit and draws four elements carrying text of their own; `/setup`
  > adds one `.note` paragraph; the refused render is a viewer's rail,
  > a heading, a sentence and a link. FR-16 adds no markup to any of
  > them and forbids inventing some, so `examined >= 30` on `/login` is
  > a criterion that can only be met by changing the page it is about.
  > They get their own tier, and every number in it is far above what a
  > blind probe reports — the overflow walker leaves exactly **one**
  > element examined when it excuses a page (spec 0027 FR-4), the
  > contrast and focus probes leave **none**. On the four readings whose
  > numbers are smallest the entry is not a floor at all but the count
  > the page's own markup declares, which is *stronger* than the floor
  > the application screens carry: a probe that excused one control on
  > `/login` reports two and fails, where `>= 3` would pass it. The
  > refused render keeps floors rather than counts, because it wears the
  > rail and what a viewer's rail holds is a property of the role table
  > rather than of this page.

  _Goes red if_: the design's `left: 250px` ships unqualified — at 390
  the panel starts 250px into a 390px viewport, which is the one piece
  of geometry this spec adds and the one an eye on a desktop screenshot
  cannot see.

- AC-20: **Everything that was not this spec's subject still behaves the
  same.** Asserted as behaviour, not as a claim about other tests:
  - every route in the Interface Contract's table of unchanged routes
    is exercised and returns the status, the `Location` (where it
    redirects) and the guard behaviour it returns today — anonymous
    redirected to `/login`, the wrong role refused, a missing or wrong
    CSRF token refused;
  - every one of the nineteen screens plus `/login`, `/setup` and a
    refused render returns its expected status and parses as HTML;
  - the set of routes the application carries — path, methods and
    endpoint — and `/api/v1`'s set of operations are identical to the
    same sets recorded at this spec's base commit;
  - `sessions` round-trips: an existing session created before the
    migration — inserted through `sessions.create_session`, which never
    names the column, exactly as an upgraded database already holds
    one — authenticates, renders every page, and shows no flash.

  > **Correction (test-authoring): the CRL clause was impossible.** It
  > asked for "a CRL byte-identical to the same response from the
  > application at this spec's base commit". A CRL is signed, by a key
  > this fixture generates, and carries `thisUpdate`/`nextUpdate` from
  > the clock — two runs of the *same* commit do not produce the same
  > bytes, so no build could ever satisfy it and a reader would have
  > spent a session finding out why. MCP's tool list has the same
  > problem for a weaker reason: it needs a live session before it will
  > answer at all.
  >
  > What is actually deterministic is what is compared: the route
  > inventory and the OpenAPI operation set, recorded at the base commit
  > and checked in beside the tests. That is the Interface Contract's
  > own first sentence — no route is added and none is removed — and it
  > is the clause a new route, a moved guard or a renamed handler fails.
  > The CRL, the ACME directory and MCP keep their own specs' tests;
  > restating them here would have been the claim about other tests that
  > this section's preamble forbids.

  _Goes red if_: the migration is written with a `NOT NULL` column and
  no server default, which upgrades a populated database into a state
  where every existing session fails.

## Test list

**New**, in `tests/test_web_flash_and_refusal.py` unless noted:

test_the_flash_is_written_once_and_popped_once (AC-1),
test_a_no_op_mutation_leaves_no_flash (AC-2),
test_the_flash_is_not_a_query_parameter (AC-3),
test_the_flash_animation_is_declared_and_reducible (AC-4, the rendered
half in `tests/test_web_design_shell.py`),
test_the_refusal_is_html_for_the_ui_and_json_for_the_doors (AC-5),
test_the_refusal_names_its_cause (AC-6),
test_the_rail_group_moved_and_the_badge_is_absent_at_zero and
test_the_badge_is_absent_rather_than_zero (AC-7, in
`tests/test_transfer.py`, beside the assertion it re-points — two
tests, because "absent at zero" needs a database that has never had an
expiring certificate and revoking one back out leaves a `revoked` row
whose absence from the count is a different fact),
test_the_dashboard_authorities_block_is_the_grouped_list (AC-8, in
`tests/test_web_dashboard.py`),
test_the_inventory_filter_is_five_links_that_keep_the_search (AC-9, in
`tests/test_web_certs_inventory.py`),
test_the_inventory_is_still_newest_first (AC-10, same file),
test_the_users_row_edit_is_url_state (AC-11, in `tests/test_web_auth.py`,
where the users page's own assertions live),
test_the_audit_pills_carry_the_other_filters (AC-12, in
`tests/test_web_audit.py`),
test_one_save_still_writes_both_flags and
test_one_save_still_writes_every_settings_flag (AC-13, in
`tests/test_web_acme_ui.py`; two, because the criterion's third clause
is the same shape on `/settings`, where seven fields share one form),
test_a_one_time_secret_is_stored_nowhere (AC-14, in `tests/test_web_tokens.py`),
test_the_eab_secret_is_stored_nowhere (AC-14 clause 4, in
`tests/test_web_acme_ui.py`),
test_the_ca_key_page_groups_and_the_bundle_does_not_click (AC-15),
test_the_column_templates_are_the_designs and
test_the_column_templates_resolve_in_the_browser (AC-16, the second
headless Chrome, both in `tests/test_web_design_shell.py`; two, because
the file says which *form* was written and the browser says what the
columns came out as, and a template declared but never applied — a row
that is not `display: grid` — satisfies the first and draws nothing),
test_the_flash_panel_animates_in_the_browser (AC-4's rendered half and
AC-19's geometry clause, headless Chrome, same file),
test_the_refusal_page_carries_only_the_copy_fr_19_names (AC-18
clause 3; clauses 1 and 2 are retired — see the criterion, and the
retirement note at the end of this list),
test_the_remaining_pages_do_not_scroll_sideways (AC-19, headless Chrome),
test_the_unchanged_routes_are_unchanged (AC-20)

Two files carry no test and are listed because they are contract:
**`tests/dom.py`**, one parsed element tree for the whole suite — this
spec's criteria are anchored to elements and to where they sit ("inside
`.shell` and as a sibling of `<main id="main">`", "exactly five `<a>`
inside one `.seg`", "zero `<form>` elements inside `<tbody>`") and none
of that can be measured with a substring search; six more one-off
`HTMLParser` subclasses would be six things to repair, which is the
argument `tests/probes.py` already makes one level up. And two
recorded baselines: **`tests/data/0030_routes.json`**, the route and
OpenAPI inventory at
this spec's base commit, which AC-20 compares against, and
**`tests/data/0030_grouped_list_selectors.json`**, the selectors that
named spec 0028's grouped-list classes there, which AC-8 clause 4
compares against. Both are regenerated only by a deliberate act, and a
diff in either is a decision.

**Three of these criteria are green at the base commit and it is worth
saying so.** AC-10 is entirely "must not change" — the lead sentence is
already there, no `<th>` is already a link, and `?sort=` is already
ignored — as are AC-7's zero-badge half and AC-20's route, OpenAPI and
guard clauses. Nothing an implementer does *before* going wrong makes
them fail. They stay because what they catch is the change nobody
proposed: a sort control added "while we are in the file", a badge
rendered unconditionally, a route quietly added beside the eighteen
call sites FR-3 touches.

**Re-pointed** — the requirement is unchanged, the selector or the page
it is read from moved. Each names, at its call site, the requirement it
protects.

- **`tests/test_transfer.py`'s `test_rail_has_sixteen_entries_and_a_transfer_group`**
  protects spec 0025 AC-1: the five transfer pages have five rail
  entries and the rail has sixteen. Its `assert "Transfer" in _nav_group_labels(html)`
  becomes `"Export"`, and it gains the group-membership assertion of
  AC-7 clause 1 — the count, the hrefs and every label are unchanged,
  which is the whole of what 0025 AC-1 measures.
- **`tests/test_web_certs_inventory.py`'s status-filter assertions**
  protect spec 0006 FR-2: filtering by `status` narrows the list and an
  unknown value shows everything. They are re-pointed from the
  `<select>`/`<option>` to the `.seg` links; what each asserts about
  the *rows* is unchanged.
- **`tests/test_web_audit.py`'s `actor_kind` filter assertions** protect
  spec 0009 FR-6, re-pointed from the `<select>` to the `.pill` links
  in the same way. Its `action` filter assertions are **not**
  re-pointed and must pass unchanged, which is what keeps FR-12's
  "one of the three becomes pills" honest.
- **`tests/test_web_auth.py`'s `test_role_can_view_users_list`**
  protects spec 0003 FR-7 and spec 0018 FR-10 for a reader: a viewer
  and an admin can open `/users` and are offered nothing on it. It is
  **strengthened, not re-pointed** — it asserts a status code and
  nothing else today — to "zero `<form>` elements inside `<tbody>`", at
  `/users` **and** at `/users?edit={id}`, because with `edit` coming
  from the query string "no form is offered" has to hold at the URL
  that would open one.

  > **Correction (test-authoring).** This entry read "`tests/test_web_auth.py`'s
  > and `tests/test_web_issuer_grants.py`'s users-page form assertions
  > … Each is re-pointed at `GET /users?edit={id}`". **There are no such
  > assertions.** `test_role_can_view_users_list` asserts
  > `resp.status_code == 200`; `test_web_issuer_grants.py` posts to
  > `/users` and never reads the page. Nothing anywhere in the suite
  > asserts which forms `/users` offers a superadmin or withholds from a
  > viewer — a build that rendered every management control to every
  > role passes the suite at this spec's base commit.
  >
  > The superadmin half is therefore **new**, not re-pointed: it is
  > AC-11 clauses 1 and 2. The viewer half is the strengthening above.
  > This is worth recording rather than quietly fixing: a spec that
  > lists a test it has not opened is how a requirement gets assumed
  > covered, and the assumption survives every review because the
  > sentence naming it reads like evidence.
- **`tests/test_web_dashboard.py`'s CA-expiry assertions** protect spec
  0016 FR-4 and spec 0017 FR-14: one entry per `ca_certificates` row,
  flagged a year ahead. They are re-pointed from the flat
  `The CA itself` table to the grouped block; the row count, the tag
  and the expiry each assert exactly what they assert today.
- **`tests/test_web_layout.py`'s page list** protects that every probe
  runs over the same list rather than a second one that drifts (spec
  0027 FR-20). It gains `/login`, `/setup` and the refused render, and
  `render_pages`'s "assert each one is actually a page" gains an
  expected status per entry.

  > **Correction (test-authoring): two of the three cannot be entries in
  > `page_paths`.** That function returns paths for one authenticated
  > client to fetch, and:
  >
  > - **`/setup` answers 404 to every client** on a database that has a
  >   user (`ui.py:148`), and the probe fixture's first act is to create
  >   one. There is no status it can be given here; it has to come from
  >   a second instance with an empty database.
  > - **a refusal needs a role that is refused something**, and the
  >   fixture's client is a superadmin, who is refused nothing. It has
  >   to come from a second client over the *same* application, logged
  >   in as a viewer — the same application, so that the page is the
  >   one under test rather than a fixture mimicking it.
  >
  > So the three are built by a function beside `page_paths` and the two
  > are joined into **one** list every probe takes, which is the whole
  > of what FR-20 asks. `/login` alone is a plain entry: it answers 200
  > to an authenticated client, because `login_form` has no auth
  > dependency.

- **`tests/test_ca_issuer_pages.py`'s `test_the_column_templates_are_the_designs`**
  protects spec 0028 FR-9: its three `cols-*` classes carry the brief's
  ratios in the `minmax(0, …)` form. Its census clause —
  `set(declared) == set(BRIEF_TRACKS)` — becomes a subset check, because
  FR-17 adds eleven more templates to the stylesheet and the census of
  *which* may exist moves to AC-16's test, which owns all fourteen.
  What 0028 FR-9 measures about its own three is unchanged.
- **`tests/test_web_design_shell.py`'s `test_the_reserved_classes_are_still_reserved`**
  protects spec 0027 FR-18: a class is defined by the spec that first
  renders one. It asserts today that the reserved list has five names
  and that none of them has a rule. FR-18 renders all five, so the list
  becomes empty and the criterion inverts — each of the five now has to
  have a rule **and** a literal user, which is AC-17 clause 3. The
  guard is not dropped: with the list empty it is clause 2 that stops a
  sixth component being defined "while we are in the file".
- **`tests/test_web_design_shell.py`'s `test_the_tree_glyph_is_the_only_decoration`**
  protects spec 0028 AC-14: the decoration exemption
  `CONTRAST_PROBE` grants is bounded rather than trusted. Its census is
  `the set of [aria-hidden="true"] elements equals the set of .tree
  glyphs`; FR-9 gives the glyph two more pages and FR-4 adds the flash
  dot, so the census becomes those four, **named** — the dot identified
  by the panel it sits in, because FR-4 gives it no class and a census
  keyed on one the spec does not require would pass for the wrong
  reason.

  > **Correction (test-authoring): none of these three was in this
  > list.** Each fails against a correct implementation of this spec —
  > the first on FR-17's eleven new templates, the second on FR-18's
  > five, the third on FR-4's dot — and the spec's "What this spec
  > overturns" table names none of them. Two of the three are argued
  > elsewhere in the spec (AC-17 inverts the reserved list, FR-9 widens
  > the census) and only the bookkeeping was missing; the column-template
  > census is not argued anywhere at all. The table is where a reader
  > checks what will break, so an entry argued in one requirement and
  > absent from the table is an entry the reader does not find.
  >
  > Spec 0029's own experience is the reason to write this down: three
  > of the rows in that table "surface when the plan is checked against
  > 0027's, 0029's and 0016's own text", and these three surface only
  > when it is checked against the tests.

- **`tests/test_ca_issuer_pages.py`'s `test_no_sentence_changed_on_the_five_pages`**
  and **`tests/test_web_form_previews.py`'s
  `test_no_sentence_changed_on_the_form_pages`** protect spec 0028 FR-15
  and spec 0029 FR-14: nothing those specs' pages said is gone. Both
  render whole pages through a *template directory* — the baseline one
  for the `before` pass and today's for the `after` — so `layout.html` is
  in both renders and this spec's two changes to it land on every page
  they cover. Each names them, per page: FR-19's one changed string
  (`Transfer` → `Export`) as a permitted removal and an addition, and
  FR-11's rail-footer avatar as an addition, derived from the fixture's
  own username rather than typed as a letter. AC-18's own instrument sees
  neither, because it compares template *files*, where the avatar is a
  Jinja expression and not a literal.

  > **Superseded (test-authoring): both are retired.** The re-pointing
  > above was done and was correct at the time; it is recorded because
  > it is what this spec did before CI showed that neither test can
  > survive the merge. See the retirement note at the end of this list
  > — and note that each re-pointing here is itself the argument: a
  > test that has to be taught about every later spec's diff is no
  > longer measuring the diff it was written for.
- **`tests/test_cross_signing.py`'s `test_migration_chain_still_ends_at_0010`**
  and **`tests/test_name_constraints.py`'s
  `test_no_constraint_column_exists_in_the_migrated_schema`** protect
  spec 0021's and spec 0020's "this spec adds no migration". Both wrote
  it as the head those specs happened to leave behind, and FR-2 moves the
  head to 0011. Each is re-pointed at the requirement itself: the
  migrated head equals the newest revision on disk — a stale head still
  fails — and no revision after 0010 touches `ca_certificates` or
  `certificates`, which a name-constraint column or a cross-signing
  column would have to.
- **`tests/test_issuer_permissions.py`'s `test_granted_viewer_still_refused`**
  protects spec 0018 AC-3: a viewer holding every grant is refused at
  every door, with the *role* refusal and not a grant refusal. FR-6 makes
  a UI refusal an HTML page, so the string that told the causes apart is
  no longer `{"detail": "forbidden for this role"}` but FR-19's role
  sentence — asserted present, with the CSRF sentence asserted absent, so
  that "refused" still means refused for the role.
- **`tests/test_web_certs_inventory.py`'s `test_list_page_filters`**
  protects spec 0006 FR-2: a status filter narrows the list. It read
  `"printer.lan" not in resp.text`, and FR-3 puts
  `issued certificate for 'printer.lan'` on the next page the fixture's
  own POST sends it to, so the page-wide reading measures the flash panel
  rather than the filter. Re-pointed at the inventory's rows, which is
  what spec 0006 is about.
- **`tests/test_cross_chains.py`'s
  `test_dashboard_warns_a_year_before_a_cross_certificate_expires`**
  protects spec 0021 AC-16: a cross certificate is on the dashboard and
  is flagged a year ahead. FR-8/FR-9 replace the flat table with the
  grouped list, so the row is no longer `<tr><th>name</th>`. Re-pointed
  at the grouped block and scoped by the row's own `cross` kind tag
  rather than by "the last row naming X" — a cross row's name equals its
  subject root's, and FR-9 gives it the one mark that tells them apart.
- **`tests/test_web_design_shell.py`'s `test_the_twelve_numbers`**
  protects spec 0027 FR-22's twelfth number, the design's `10px 12px`
  list row. Spec 0028 FR-12 moved that reading onto `/certs` because
  every table on `/ca/{root}` had become a `.rows` grid; FR-17 makes
  `/certs` one too, so there is no unconverted list left to move it to.
  It stays on `/certs` in the grid form — the cell's `10px` and the row's
  `12px` — and the clause asking whether the row is a grid **inverts**:
  it now has to be one, which is the same check AC-16 splits its two
  tests over.
- **`tests/test_web_layout.py`'s `test_nav_current_marked_once_per_page`**
  protects spec 0027 AC-5: exactly one rail entry is marked, and it is
  the page being viewed. It read the marked label with
  `>([^<]+)</a>`, and FR-7 puts the count badge *inside* the Inventory
  link, so that anchor stops matching the moment a certificate is
  expiring — which FR-21's fixture now guarantees. Re-pointed at the
  anchor's own text; the badge is a child element and a number, not a
  label.

  > **Correction (test-authoring): none of the eight above was in this
  > list either.** Each fails against a correct implementation of this
  > spec, for a reason argued in one of its requirements, and the earlier
  > correction three entries up says exactly why that matters: "the table
  > is where a reader checks what will break, so an entry argued in one
  > requirement and absent from the table is an entry the reader does not
  > find." Three were found when the spec was checked against the tests;
  > these eight were found only when the tests were run against the
  > build, which is one round later than it should have taken and is the
  > reason they are written down rather than quietly repaired.

**Strengthened** — the requirement grows:

- **`tests/test_web_form_previews.py`'s `test_every_hx_target_answers_a_full_page`**
  protects spec 0029 FR-2 clause 1: every htmx target answers a full
  page without the header. _Supersedes spec 0029 AC-1's clause that the
  set of targets has the size 0029 introduces._ It grows in two ways,
  and both are needed for it to keep meaning anything here:
  1. the expected set becomes 0029's six plus this spec's, **derived**
     from `certs_ui._page_url`, `audit_ui._page_url` and the fixture's
     own user rows and asserted as a lower bound, so that a build
     rendering no `hx-` attribute still cannot pass by finding nothing;
     and every target found is checked against the routes the
     application already has — its path is one of them and its query
     carries nothing beyond the one parameter the Interface Contract
     adds, which is FR-20 clause 1 measured rather than restated;
  2. **the targets are collected from the rendered pages as well as
     from the template files.** Half of this spec's targets are
     interpolated — `/users?edit={{ row.id }}`, `_page_url`'s output —
     and a value still containing `{{` cannot be fetched. The walker
     takes literal targets from the templates and resolved ones from
     the nineteen rendered screens, and **counts what it skipped**, so
     that a build in which every target is unresolvable is
     distinguishable from one in which there are none.
  The byte-identical clause of 0029 AC-1's correction applies to every
  target this spec adds, and the fixture must have no pending flash
  when it runs — a popped message is a difference between two otherwise
  identical responses, and it is the response that had it that is
  correct.

  > **Correction (test-authoring), clause 1.** It asked for "an exact
  > number", and this spec never says which targets that number counts.
  > It is not derivable either: FR-10 gives the inventory's five links
  > their `hx-` attributes and FR-15 says the inventory **export** page
  > "takes the same filter-bar treatment", without saying whether that
  > includes them — so two readers get two numbers and one of them
  > writes a test the other's build fails for no reason anybody can
  > name.
  >
  > A lower bound built from the same functions the pages build their
  > links with keeps everything the exact number was for: a build with
  > no `hx-` attribute fails it, a filter link that quietly dropped `q`
  > fails it as a missing target rather than as a string nobody
  > compared. What the exact number was *also* reaching for — that no
  > sixth kind of target appears — is the no-new-endpoint check above,
  > which measures the thing itself instead of a count that stands in
  > for it.
- **`tests/test_web_design_shell.py`'s contrast and focus probes**
  protect spec 0027 FR-14 and FR-15. They gain `/login`, `/setup` and
  the refused render, three screens they have never covered, and the
  `.toggle` control, which is the first `appearance: none` element in
  this project and therefore the first one whose focus ring is drawn by
  cabin rather than by the browser.
- **`tests/probes.py`'s `CONTRAST_PROBE`** protects spec 0027 FR-14.
  Its `[aria-hidden="true"]` skip gains two more users (the tree glyphs
  on the dashboard and the CA-key page) and a third kind (the flash
  dot), and AC-18's census names all four (FR-9). It could not
  previously catch a glyph rendered in an unreadable colour on those
  pages, because those pages had no glyph.
- **`tests/test_store_schema.py` gains migration 0011's own two tests.**
  There is no sweep to extend: that file holds four tests about the
  *shape* of a freshly migrated database and no Alembic up/down test at
  all — the only one in the suite is
  `test_issuer_grants.py::test_migration_0010_downgrade_drops_both_tables`,
  written by the spec that added 0010. This spec follows that
  precedent: one test asserting 0011's `down_revision`, the column's
  nullability and type, and that the five existing columns are
  unchanged; one asserting the up/down cycle against a `sessions` row
  written **before** the upgrade through raw SQL naming only the
  pre-0011 columns — which is the only way AC-20's last clause can fail
  on a build that adds the column `NOT NULL`. Inserting through the ORM
  after the model has gained the attribute supplies a value for it and
  measures nothing.

  > **Correction (test-authoring).** This entry read "protects spec 0001
  > FR-5: every migration runs forward and backward against a populated
  > database. It gains `0011`". No such test exists to gain anything;
  > see the correction under the users-page entry above for why a spec
  > naming a test it has not opened is worth recording rather than
  > quietly fixing.

**Retired — three, with their argument written where each test was.**

All three compared the pages or the templates against a *commit*, and
all three failed on CI for the same mechanical reason: the commits are
on `feat/0.2.0`, the runner checks out shallow, and PR #17 may squash.
Deepening the checkout was the obvious repair and is the wrong one — it
would buy one merge and then pin the suite to a history that by
definition changes.

The argument for retiring rather than re-pointing is spec 0028's, from
when it retired `test_only_layout_html_changed`: each asserts **a
property of one diff, not of the codebase**. "This spec removed no
sentence from these pages" was true when it was written, is true now,
and nothing a later commit can do makes it false, so there is no
regression left for it to catch. The diff is the evidence, and it is
better evidence than a test, because it cannot be edited into agreeing
with the code.

- **`tests/test_ca_issuer_pages.py`, `test_no_sentence_changed_on_the_five_pages`**
  (spec 0028 AC-16). It had also stopped being about spec 0028: 0029
  had to teach it that `ca_detail` is three URLs, 0030 had to teach it
  `Transfer` → `Export` and the rail avatar. An exception list that
  grows once per spec is a test being kept green.
- **`tests/test_web_form_previews.py`, `test_no_sentence_changed_on_the_form_pages`**
  (spec 0029 AC-14). Its "every addition is named" half is asserted
  positively and by name on the rendered page by 0029's own AC-3,
  AC-9, AC-10 and AC-11; only the "nothing is lost" half needed the
  baseline, and that half is the claim about the diff.
- **`tests/test_web_flash_and_refusal.py`, `test_no_sentence_changed_on_the_remaining_pages`**
  (this spec's AC-18, clauses 1 and 2). Clause 3 survives as its own
  test; see the correction under the criterion.

**Converted — three, which kept their assertion and lost the lookup.**
A standing invariant expressed against an old commit is still a
standing invariant. `test_the_ca_key_page_groups_and_the_bundle_does_not_click`
(AC-15) and `test_the_dashboard_authorities_block_is_the_grouped_list`
(AC-8 clause 4) now read frozen baselines — one a constant, one
`tests/data/0030_grouped_list_selectors.json`. Spec 0029's
`test_the_disclosure_is_url_state` (AC-12) needed no baseline at all:
the fields the opened form must carry are read off
`ca_create_intermediate` and `verify_csrf`, which is stronger in both
directions than the commit it used to read — a field the handler gains
and the form never offers now fails too.

**Deleted: none.**

## Out of Scope

**No version bump.** Everything stays 0.2.0 and PR #17 stays open. The
change is UI-visible and gets its entry under `[Unreleased]` in
`CHANGELOG.md`, which is the project's workflow rather than a
requirement of this spec.

**No flash on `POST /settings` or `POST /acme/admin`** (FR-3). Both
record one event per changed setting, so a request leaves zero, one or
seven sentences behind and none of them is "what just happened". The
shape that would work is a message that counts rather than names, which
is new copy describing a request rather than a change. If it is wanted
later it is a small spec of its own and its criterion is AC-1's shape.

**No second flash tone, no error flash** (Context). No failing UI POST
redirects; every one re-renders its own page with its own error box.
Two more `.flash-*` rules would be two rules with no literal user and
the agreement test's reverse direction fails on exactly that.

**No sorting on the inventory** (FR-10). The page's own lead sentence
is `Everything this CA has issued, newest first.` and a sort control
makes it false; it also needs a query parameter, a whitelist, a
tie-breaker, and the same ordering in `export_certificates` or the CSV
disagrees with the page that offered it. Declined, not forgotten, and
recorded in the brief's register.

**No `?delete={id}` confirmation on Users** (FR-11). The design's third
row state maps cleanly to a URL, and cabin's delete has no confirmation
today, so adding one is a behaviour change and new copy — and it would
leave `POST /users/{id}/delete` as the only destructive route in cabin
whose confirmation is a URL rather than the checkbox spec 0023 FR-9 and
spec 0007 use. Whichever way that is settled, it is settled for all of
them at once.

**No one `Save` on the users row** (FR-11). Four mutations, four routes,
four audit actions; one button would be a new endpoint and one log
entry where there are four.

**No 404 or 422 page.** The design draws neither, this spec's handler
answers only 403, and inventing a page for a status the design has no
drawing for is the thing the brief's §0 warns against.

**No ACME "Recent orders" section** (brief §5.15) and **no Environment
grid on Settings** (§5.19). Both are blocks of content cabin's pages do
not have; adding them is a feature with a query behind it, not a
restyle.

**No "Delete a stored key" section on the CA-key page** (§5.14). cabin
has no route that deletes a stored CA key, and the design's section is
a form for one.

**No copy-to-clipboard buttons** (brief §9.8). They are impossible
without JavaScript; `user-select: all` is the answer the brief itself
gives and FR-14 ships it.

**No htmx anywhere else, no `hx-post`, no new endpoint** (FR-20). Spec
0029 FR-2's rule and `docs/adr/0003-url-state-disclosure-and-htmx.md`
hold unchanged and are not restated here.

**No `<details>`, ever** (0026 FR-16's first half, 0024 FR-8). The row
edit this spec adds is a URL, an anchor and a server-rendered branch.

**No change to any guard, any audit action, any REST, MCP or ACME
behaviour, and no new token in the palette.** Eighteen POSTs gain one
line each and nothing else about them moves.
