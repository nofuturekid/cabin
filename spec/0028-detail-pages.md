# Spec 0028 — The Detail and List Pages

## Context

Spec 0027 put the design's shell, token layer and retuned vocabulary
around every page and deliberately touched no content template's markup
(0027 FR-18). This spec is the first one that moves content, and it
moves the pages Thomas named: the hierarchy list, the hierarchy page,
the issuer and cross pages and the certificate page. His words were
that the design should be followed closely, **especially its
fundamental division and listing on the detail pages**, so where this
spec and spec 0026 disagree, the design wins and the disagreement is
written down.

Seven differences from spec 0026 were identified in the plan. Six of
them turn out to be supersessions and one does not, and this spec says
which is which rather than recording seven for symmetry. Each
supersession names the requirement it overturns and argues that the new
arrangement is better rather than merely different: spec 0026 landed
this morning, it was verified, and overturning a verified requirement
hours later is churn unless the argument is on the page.

The design's sections this spec is built from are the brief's **5.7**
(hierarchies list), **5.8** (hierarchy detail), **5.9** (issuer and
cross detail), **5.4** (certificate detail), **6.2** (lists), **6.3**
(grouped list) and **6.14** (definition grid).

### The one technical decision everything else rests on

The brief §6.2's own advice for real HTML is to keep `<table>` and put
the design's column template on the `<tr>` with `display: grid`. That
is what this spec does (FR-8), and it is what makes the rest possible:

- a `<table>`'s columns size to their content and refuse to shrink,
  which is why spec 0026 argued that a fourth column costs too much at
  390 pixels. A grid row's `minmax(0, Nfr)` tracks do have a zero
  minimum and do shrink to whatever the container gives them — but that
  is **not** what makes the fourth column affordable, and the first
  draft of this spec said it was. Shrinking the track only moves the
  problem into the cell: what makes the column affordable is that the
  cell's content is allowed to **wrap** (FR-9). The measurement that
  disproved the original claim, and the measurement that replaced it,
  are both recorded in FR-9;
- a `<tr>` that is a grid container is a real box, so it can be
  `position: relative` and carry the stretched link of FR-3;
- `<table>`, `<thead>`, `<tbody>`, `<th>` and `<td>` all stay, so the
  semantics stay, `.scroller` stays, and
  `test_every_table_is_wrapped_in_scroller` (spec 0015 FR-4) passes
  unchanged.

### What this spec overturns, and where

Every entry is argued in the FR named beside it. Nothing else in spec
0026 or spec 0027 changes.

| #   | Overturned                      | By    | In one line                                                                                                    |
| --- | ------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------- |
| 1   | 0026 FR-2 (three columns)       | FR-2  | a fourth column costs nothing once the columns can shrink, and Kind is what the shared component is keyed on   |
| 2   | 0026 FR-2/FR-3 (the link alone) | FR-3  | the whole row is the target; the name cell stays the link, so the old assertion survives                       |
| 3   | 0026 FR-1 clause 2              | FR-4  | the root's renew and retire get their own section, which puts the page's one danger control in one place       |
| 4   | 0026 Out of Scope, `/ca`        | FR-5  | `/ca` becomes the grouped list — the operator's "fundamental listing", and the component two later pages reuse |
| 5   | **nothing**                     | FR-6  | the definition grid restyles 0026 FR-6; it does not overturn it, and this spec says so                         |
| 6   | 0026 FR-6 (cross field list)    | FR-7  | the signer and serving state become a banner, moved and not duplicated                                         |
| 7   | 0027 AC-6 clause 3              | FR-11 | one status colour's provenance is a §1 paragraph, not a §1 table row                                           |
| 8   | 0027 FR-22 row 12 / AC-18       | FR-12 | the row-padding number is measured on a table this spec does not convert                                       |

Numbers 7 and 8 are not in the plan's list of seven. They are
consequences of it that surfaced while checking the plan against spec
0027's own criteria, and a spec that shipped them silently would leave
two criteria failing with no argument beside them.

## User Stories

- As an operator opening `/ca`, I see every hierarchy and the issuers
  under it in one list, and I can go straight to an issuer without
  opening its root first.
- As an operator scanning a table, clicking anywhere on a row opens it,
  and I can see which row I am on from the keyboard as well as from the
  mouse.
- As an operator on a hierarchy page, the two things that cannot be
  undone are in one place at the bottom, under their own heading, and
  not mixed in with the root's identity.
- As an operator reading an issuer's facts, they are a plain two-column
  list of label and value, not a table pretending each fact is a row of
  data.
- As an operator opening a cross certificate, the sentence saying who
  signed it and what that means for the chains cabin serves is a banner
  at the top, in one piece, and not two cells of a table.
- As an operator on a phone, none of these pages scrolls sideways,
  including the four-column and five-column tables.
- As an operator who reads every sentence on these pages today, every
  one of them still says exactly what it said.

## Functional Requirements

- FR-1: **The boundary.** This spec changes
  `src/cabin/web/templates/ca_list.html`, `ca_detail.html`,
  `ca_issuer.html`, `ca_macros.html`, `cert_detail.html`,
  `src/cabin/web/static/cabin.css` and `src/cabin/web/ca_ui.py`. No
  route, method, guard, CSRF rule, form field, redirect target, status
  code, audit event, schema, migration, API, MCP or ACME behaviour
  changes, and no sentence on any page changes (FR-15).

  **`src/cabin/web/certs_ui.py` is not changed**, although the plan
  lists it. Every change this spec makes to `cert_detail.html` is a
  change of markup around values the context already carries, and the
  two additions the design's §5.4 would need — an `Issuer` fact and a
  status tag beside the title carrying "valid · 18 days" — are content
  this page does not have today. Adding them is a content change, not a
  layout change, and spec 0026's discipline is that a move must not
  quietly become an addition. Out of Scope records both, so that a
  later reader can see they were considered and declined rather than
  forgotten.

- FR-2: **The issuers table gains a Kind column.** _Supersedes spec
  0026 FR-2's three-column table._ Its columns become, in order:

  | Column  | Contents                                       |
  | ------- | ---------------------------------------------- |
  | Name    | the row's name, and it is the link to its page |
  | Kind    | the row's kind, as a `.tag`                    |
  | Status  | the status tag, `tag-bad` when retired         |
  | Expires | `not_valid_after`, **and it may wrap** (FR-9)  |

  **`class="nowrap"` comes off the Expires cell**, on this table and on
  the other two (FR-9). It is what made the fourth column unaffordable:
  `not_valid_after` renders as a full 25-character timestamp
  (`2036-08-06 15:53:37+00:00`), which needs 170px and cannot break, so
  in an 84px track it hangs 86px out of the cell and takes the table
  with it. Measured, both ways, in FR-9. Nobody is to put it back for
  tidiness: a date on two lines at 390 pixels is the design working, and
  a table that scrolls sideways is not.

  0026 FR-2 gave two reasons for three columns. The first — that an
  `Open` column "would repeat the name as a target" — is about an
  `Open` column and does not reach this one: Kind repeats nothing. The
  second is the real one, and it is overturned: a fourth column "would
  cost a fourth column at 390 pixels, where the table has the least
  room". That is true of a `<table>`, whose columns cannot be made
  narrower than their widest unbreakable word — and it stays true of a
  grid row for exactly the same reason, because a track that shrinks
  under an unbreakable word does not make the word any narrower. What
  overturns it is FR-9: the widest unbreakable word on this table was a
  timestamp cabin itself made unbreakable with `class="nowrap"`, and
  once that comes off there is no such word left. Then, and only then,
  the tracks' zero minimum means a fourth column costs no width, only
  share.

  **This is re-proved, not asserted**, and by an instrument that can
  fail: AC-1 measures the table against **its own `.scroller` box** at
  390 and requires it to fit without scrolling. The page-level overflow
  probe is run there too, but it answers a different question and cannot
  answer this one — it excuses everything inside a `.scroller` by
  design, which is what a scroller is for. The first draft of this spec
  asked that probe to carry FR-2's whole argument; FR-9 records what
  happened when that was measured.

  **The cost, stated rather than glossed.** On this table every row is
  an intermediate, so every Kind cell reads the same word. A column
  whose every value is identical carries no information on this page,
  and spec 0026 FR-3 refused exactly that kind of column ("`Signed by`
  is not decoration"). It is paid here for a reason that is about the
  set of tables rather than this one: Kind is the column that
  distinguishes a root from an issuer in the grouped list (FR-5) and a
  root from an intermediate on the CA-key page the design gives the
  same component (brief §5.14), and the design specifies it on all
  three. A column that appeared in two of the three renderings would
  make one list look like a different component from the others, which
  is the opposite of what "follow the design's fundamental listing"
  asks for.

- FR-3: **The whole row is the click target.** _Supersedes spec 0026
  FR-2's and FR-3's "the name cell is the link" as the whole story; the
  clause itself stands._ Every row of a clickable table carries
  `position: relative`, and the `<a>` in its name cell carries
  `.rowlink`, whose `::after` is an absolutely positioned overlay
  covering the row. The brief §9.4 names this construct and its reason:
  it preserves the full-row hover the design draws, and it needs no
  JavaScript.

  **The name cell is still the link**, so spec 0026 AC-2's assertion —
  the row's first cell contains an `<a>` whose `href` is the row's page
  and whose text is the row's name — passes unchanged, and so do the
  four `_row(..., tag="tr")` scopings — two in `test_web_ca.py`, one in
  `test_cross_chains.py`, one in `test_ca_issuer_pages.py` — which find
  a row by the link inside it. (The plan said five and named
  `test_web_name_constraints.py`; that file scopes by `.section` and
  `.constraints` and uses no `tag="tr"` at all. Counted, not assumed.)

  **It earns a focus treatment, and the treatment is additive.** Spec
  0027 FR-15 gives every focusable element a 2px accent ring, which on
  a stretched link paints around the name text and not around the row
  the click actually opens. The obvious fix — suppressing the anchor's
  own outline and drawing one on the row — is forbidden: 0027 FR-15
  requires that **no rule anywhere sets `outline: none` or
  `outline: 0`**, and AC-11 greps the stylesheet for exactly that. So
  the treatment is added rather than moved: the anchor keeps its ring,
  and `tr:has(.rowlink:focus-visible)` additionally takes the hover
  fill and an inset 2px accent bar, which is the design's own idiom for
  "this row is the one" (brief §3, the active nav item). Both are
  drawn, spec 0027 AC-11's probe keeps finding the anchor's ring, and
  the row is visibly the target.

  Only one link may sit in a stretched row, or the overlay covers the
  others. Every table this spec renders has exactly one, and AC-2
  asserts it per row rather than trusting it.

- FR-4: **The root's renew and retire move into their own section.**
  _Supersedes spec 0026 FR-1 clause 2_, which said the root section is
  unchanged "including its own renew and retire forms" and argued that
  "a row's controls sit with that row's detail, and the root's detail
  is on this page".

  **That argument survives and is not what changes.** The root's
  controls are still on the root's page; only their position within it
  moves. What changes is that they stop being the tail of an identity
  block and become a section of their own, headed `Renew and retire`,
  **last on the page**, after the `Add intermediate` section and the
  `Cross-sign` one. The design's §5.8 lists the hierarchy page's
  sections in exactly that order and gives renew-and-retire the fifth
  and last slot.

  **The upside worth recording**, because spec 0026 left the question
  open in its own Out of Scope: 0026 asked whether three red retire
  buttons on one page were too loud and declined to decide, noting it
  had incidentally reduced them to one. This finishes the thought — the
  hierarchy page's one danger control now sits in one place, below
  everything constructive, under a heading that says what it is, and
  the operator reading the root's identity is no longer reading it
  beside a red button. The section heading and its `.help` line are
  lifted verbatim from `ca_issuer.html:79-80`, which already carries
  the same section for a row, so this adds no wording (FR-15).

  The new order, top to bottom, replacing 0026 FR-1's list:
  1. page head and error box;
  2. the root section — everything it carries today **except** the
     renew and retire forms: its tags and expiry, the `Serving:`
     sentence, `root.pem`, subject and fingerprint, its constraints
     block;
  3. **Issuers** (FR-2), or the empty state (0026 FR-4, unchanged);
  4. **Cross certificates**, when any exist (0026 FR-3, plus FR-2's
     grid treatment);
  5. **Add intermediate**, keeping `id="add-intermediate"`;
  6. **Cross-sign with another root**;
  7. **Renew and retire**, under the same `nav.ca_admin` gate the forms
     carry today.

- FR-5: **`/ca` becomes the grouped list.** _Supersedes spec 0026's Out
  of Scope clause "No change to `/ca`'s list."_ That clause was a scope
  boundary rather than a requirement — its argument was that merging
  the counts with the two new tables "is a second change measured by no
  criterion here". This spec is that second change and measures it.

  `ca_list.html`'s table keeps its five columns exactly as they are —
  Name / Status / Expires / Intermediates / Cross certificates, which
  is already the design's §5.7 column set — and gains, under each root
  row, one row per intermediate of that root, in `list_cas` order:
  - the **root row** carries `.row-root`: the `--surface-hover` fill,
    its name at weight 600 with the `root` tag beside it, and a 2px
    left status bar (FR-11);
  - each **issuer row** carries `.row-child`: the name column indented,
    preceded by a mono `├`/`└` tree glyph (FR-13); the name linking to
    `_page_of(row)`, with its own `intermediate` kind tag **beside the
    name**; the **Status column carrying the row's status**, `active` or
    `retired`, as the same tag with the same `tag-bad` on `retired` that
    every other status in cabin uses; and the two count columns empty.

    An earlier draft of this clause was mis-punctuated into saying the
    kind tag takes the Status column's place, which would have left the
    child rows with no status at all. They keep it, and the reason is
    the point of the page: `/ca` is where an operator looks to see what
    is **active**. A child row is the row you would most want to see
    marked — a retired issuer disappearing into a list of live ones is
    how someone signs against the wrong hierarchy, or believes they
    cannot sign at all when an issuer is merely retired. The design
    draws the kind tag beside the name (brief §5.7) and says nothing
    about dropping the status; reading it as a replacement would make
    this list less informative than the one it replaces, which is the
    opposite of why FR-5 exists. AC-5 asserts it by effect;

  - a root with no intermediate gets a single row in their place
    reading **"This hierarchy has no issuer yet, so nothing can be
    signed under it."** — lifted verbatim from
    `ca_detail.html:59`'s `#ca-no-intermediates`, so the design's own
    sentence for this state is not introduced and FR-15 holds.

  **Why this is better and not merely different.** `/ca` today answers
  "which hierarchies exist" and makes the operator open a root to find
  out what can actually sign. The counts tell them a number and not a
  name, and an issuer is what they were looking for: every issuance,
  every ACME directory and every grant is named by an issuer, not by a
  root. One list that names both, with the tree structure drawn, is one
  navigation instead of two for the commonest reason anyone opens this
  page. It is also the component the design reuses for the dashboard's
  Authorities block and the CA-key page (brief §6.3), both of which
  spec 0030 renders — so defining it here has two users waiting, and
  defining it anywhere else would mean defining it twice.

  **What it does not become.** Cross certificates are not listed under
  their root here; the `Cross certificates` count column stays, and the
  cross rows stay on the hierarchy page (0026 FR-3). The design's §5.7
  indents issuers only, and a cross row's name equals its subject
  root's name (spec 0021 FR-1), so indenting it under that root would
  print the same string twice with nothing to tell the two apart —
  which is the defect 0026 FR-3's `Signed by` column exists to prevent
  and which this list has no column for.

- FR-6: **The identity block becomes a definition grid, and this
  overturns nothing.** The plan lists this as a supersession of spec
  0026 FR-6. Checked against FR-6's actual text, it is not one, and the
  finding is recorded here rather than a supersession being written for
  symmetry.

  FR-6 requires "an identity table — kind, status, valid from and
  until, subject, fingerprint, and for a cross row the signing root and
  its serving state — in the `.scroller` + key/value `<table>` shape
  `cert_detail.html:21-38` already uses". After this spec the block is
  still a `<table>`, still inside a `.scroller`, still one label and
  one value per row, and still carries every field FR-6 names except
  the two FR-7 moves. What changes is the rendering: the `<tr>` becomes
  `display: grid; grid-template-columns: auto minmax(0, 1fr)` and the
  cells take the brief §6.14 treatment — label at 12px in
  `--text-faint`, value at 12.5px, `9px 0` padding, a `--rule-row`
  border on each cell. That is a restyle of the shape FR-6 named, not a
  replacement of it.

  The same treatment applies to `cert_detail.html`'s fact table, whose
  value column additionally takes the design's `padding-left: 24px`
  (brief §6.14, "24px omitted on 5.9"), and whose SANs cell renders one
  name per line (brief §5.4) instead of a comma-joined string. The
  values are the same values; `cert.sans` is already a list.

  Two deliberate divergences from the brief, both recorded here because
  the brief's own rule is that a divergence is written down beside its
  reason:
  - **The grid keeps its `.scroller` box**, which the design's fact
    grid does not have. `test_every_table_is_wrapped_in_scroller`
    (`test_web_layout.py:87`) requires every `<table>` in every
    template to be wrapped, and it protects spec 0015 FR-4 — a table is
    the one thing wide enough to push a page sideways. Dropping the
    wrapper to match the design would mean editing that test in the
    same change that introduces four new tables, which is the worst
    possible moment to weaken it.
  - **`cert_detail.html`'s grid stays one column of pairs**, not the
    design's `repeat(2, minmax(0, 1fr))` of two such grids. The field
    count on that page is variable — the `Revoked` row appears only
    when the certificate is revoked — and a two-column pairing built
    from one linear `<tbody>` either reorders the fields as the count
    changes or leaves a hole. Two `<table>`s would fix the geometry and
    would split one fact list into two, which is worse.

- FR-7: **The cross page's signer and serving state become a banner.**
  _Supersedes spec 0026 FR-6's field list for a cross row_, which put
  "the signing root and its serving state" in the identity table. The
  design's §5.9 makes it a panel above the facts: "Signed by **X**, in
  place of Y's own signature." with the serving tag inline.

  **Moved, not duplicated.** The banner is a `.panel` rendered only for
  `row.kind == "cross"`, carrying the two sentences `ca_issuer.html:21`
  and `:22` render today, byte for byte — including the full clause a
  `not served` active row gets, naming the validity window and saying
  the fallback needs no action. The definition grid then carries
  neither, and AC-8 asserts both halves in one criterion, because a
  build that renders the banner and leaves the rows in place would
  otherwise pass everything else here.

  **Why a banner is better than two rows.** The two facts are one
  sentence about what this certificate is for, and the serving clause
  is 40 words long. In an `auto 1fr` grid it is a paragraph squeezed
  into a value cell beside a two-word label, and the label `Serving`
  says less than the sentence does. Spec 0026 FR-3 already made this
  judgement in the other direction — it kept the short `Serving` tag on
  the table and moved "the **full** explanatory clause … where there is
  room for a sentence" to this page. This gives the sentence the room
  0026 sent it here to find.

- FR-8: **A table is a `<table>` whose rows are grids.** The design has
  no `<table>` at all — every list in the prototype is a stack of
  `<div>`s sharing a `grid-template-columns` — and the brief §6.2's own
  advice for real HTML is to reproduce them "as `<table>` with
  `display:grid` on `<tr>`". That is what ships:

  ```css
  table.rows,
  table.facts {
    display: block;
  }
  table.rows thead,
  table.rows tbody,
  table.facts tbody {
    display: block;
  }
  table.rows tr,
  table.facts tr {
    display: grid;
  }
  ```

  `<th>` and `<td>` need no rule: a grid item's `display: table-cell`
  is blockified by CSS Display §2.7, so the cells become blocks by
  being in a grid. Every element and every attribute stays, so the
  markup is still a table to a screen reader, `.scroller` still wraps
  it, and `test_every_table_is_wrapped_in_scroller` passes unchanged
  (AC-10).

  On a `.rows` table the row is the box: `<tr>` takes the design's
  padding, its `column-gap: 12px` and a `border-top` in `--rule-row`,
  and `.rows tbody td` takes `padding: 10px 0` and no border, so that
  the rule runs the full width of the row as the design draws it. On a
  `.facts` table the **cell** is the box, per brief
  §6.14: each cell carries its own `9px 0` padding and its own
  `--rule-row` top border, which is why `.facts` is a second treatment
  and not a column set of the first.

  The hover fill is scoped to rows that are actually clickable —
  `.rows tbody tr:has(.rowlink):hover` — which the brief §6.2 states as
  a rule ("Hover is `background:#1d1f2c` **only** where the row is
  clickable") and which cabin's current global `tbody tr:hover` does
  not honour: it highlights the certificate page's fact rows, which go
  nowhere.

- FR-9: **The column templates, exactly — and the cell content wraps.**
  Each template is a class on the `<table>`, and every track is
  `minmax(0, Nfr)`:

  | Class               | Page              | Tracks (brief)              | Columns                                                      |
  | ------------------- | ----------------- | --------------------------- | ------------------------------------------------------------ |
  | `.cols-hierarchies` | `/ca` (§5.7)      | `2fr .8fr 1fr .9fr 1.1fr`   | Name / Status / Expires / Intermediates / Cross certificates |
  | `.cols-issuers`     | `/ca/{id}` (§5.8) | `2fr 1.2fr .8fr 1.1fr`      | Name / Kind / Status / Expires                               |
  | `.cols-crosses`     | `/ca/{id}` (§5.8) | `1.7fr 1.3fr .8fr .9fr 1fr` | Name / Signed by / Status / Serving / Expires                |
  | `.facts`            | §5.9, §5.4, §6.14 | `auto minmax(0,1fr)`        | label / value                                                |

  **No `<td>` of a `.rows` table is `white-space: nowrap`.** This is the
  requirement that makes FR-2's fourth column affordable, and the one
  the first draft of this spec got wrong. `class="nowrap"` comes off the
  `Expires` cell of all three tables; the `.tag` chips inside a cell
  stay nowrap (they are two short words and they fit), and `thead th`
  stays as it is.

  **The measurement, because the argument this replaces was wrong.**
  All figures are headless Chrome at 390×900, on the real page with the
  real stylesheet, reading each table's own `.scroller`:
  `scrollWidth − clientWidth`, i.e. how far the table fails to fit the
  box it is in. The fixture is the long-name one
  (`test_web_layout._populate`, names of 43–56 characters):

  | Build                                 | Issuers | Crosses |
  | ------------------------------------- | ------- | ------- |
  | today: plain `<table>`, 3-col issuers | 0       | **78**  |
  | plain `<table>`, 4-col, `nowrap` kept | **18**  | 78      |
  | grid, `minmax(0, …)`, `nowrap` kept   | **75**  | **90**  |
  | grid, bare `Nfr`, `nowrap` kept       | 0       | 18      |
  | grid, `minmax(0, …)`, wrapping        | **0**   | **0**   |
  | grid, bare `Nfr`, wrapping            | 0       | 0       |

  All six rows are one run of one script against one fixture, so they
  are comparable with each other; the figures move by a pixel or two
  with the rendered timestamp's own width.

  Three things follow, and the first two contradict this spec's first
  draft:
  1. `minmax(0, …)` with the timestamp still `nowrap` is the **worst**
     of every option measured — four times worse than simply adding the
     fourth column to the plain `<table>` spec 0026 kept (75 against
     18), and worse on the cross table too (90 against 78). That is the
     row someone will disbelieve, and it is why it is in the table: the
     construct this spec introduced to make a fourth column affordable,
     measured against the construct it replaced, lost. The zero minimum
     shrinks the track to 84px; the 170px timestamp inside it does not
     shrink at all, and 86px of it hangs out of the cell. "The fourth
     column costs no width, only share" was true of the tracks and false
     of the table.
  2. A bare `Nfr` track does **not** reproduce the `<table>`'s refusal
     to shrink at this width — it fits, in both the `nowrap` and the
     wrapping build. The claim that it "would reproduce the very problem
     spec 0026 FR-2 was avoiding" was asserted, not measured, and it is
     wrong. `minmax(0, …)` is kept because it is the design's own form
     (brief §6.14) and because it bounds the tracks to the container for
     any content, including content this fixture does not contain; it is
     no longer claimed to be what makes the column affordable.
  3. Wrapping is what makes it affordable, and it does so for **both**
     tables at once — including the pre-existing defect FR-16 records.

  AC-9 reads the `minmax(0, …)` form off both the computed style and
  the file, because only the file says which form was written.

- FR-10: **Every class this spec renders is defined here, and nothing
  else is.** Spec 0027 FR-18 settled the rule: a class is defined by
  the spec that first renders one, because
  `test_stylesheet_and_templates_agree_in_both_directions` fails in its
  reverse direction on a rule with no user, and its only exemption list
  is for `^tag-` names. Of the eight names 0027 reserved without
  defining, this spec renders two — `.panel` (FR-7's banner and the
  danger panels) and `.group-row`, which is dropped in favour of the
  two clearer names below. The other six stay reserved and undefined.

  The fourteen classes this spec defines, each with its user:

  | Class                             | First user                                            |
  | --------------------------------- | ----------------------------------------------------- |
  | `.rows`                           | the three list tables                                 |
  | `.cols-hierarchies`               | `ca_list.html`                                        |
  | `.cols-issuers`, `.cols-crosses`  | `ca_detail.html`                                      |
  | `.facts`                          | `ca_issuer.html`, `cert_detail.html`                  |
  | `.facts-indent`                   | `cert_detail.html` (brief §6.14's 24px)               |
  | `.rowlink`                        | the name cell of every clickable row                  |
  | `.row-root`, `.row-child`         | `ca_list.html`'s grouped rows                         |
  | `.state-active`, `.state-retired` | the 2px left status bar on `ca_list.html`'s root rows |
  | `.tree`                           | the `├`/`└` glyph on `ca_list.html`'s child rows      |
  | `.panel`                          | `ca_issuer.html`'s cross banner                       |
  | `.panel-danger`                   | `ca_macros.html`'s retire form, `cert_detail.html`    |

  **Status classes are written literally, never interpolated.** The
  agreement test's definition of "used" (spec 0027 FR-20) counts a
  template's class tokens only when they are static: a `state-` prefix
  glued to a `{{ row.status }}` interpolation contributes no name at
  all, so `.state-retired` would be a rule with no user and the reverse
  direction would fail. The
  templates therefore branch — `{% if %}state-active{% else %}state-retired{% endif %}`
  — and AC-11 asserts the agreement test passes in both directions with
  no addition to its exemption list.

- FR-11: **The status bar's colour, and the one criterion it
  overturns.** The design draws a 2px left edge bar on hierarchy-list
  root rows in three states (brief §1): `#3f7d55` active, `#8c3f3d`
  expired, `#3f424d` retired. cabin ships two of them:
  - **active** — a new token `--bar-active: #3f7d55`;
  - **retired** — `var(--line-control)`, which is `#3f424d`, the value
    the design gives;
  - **expired is not shipped.** A `ca_certificates` row's `status` is
    `active` or `retired`; cabin computes no expired state for a CA
    row anywhere, and inventing one here would be a content change
    behind a colour. Recorded rather than silently dropped.

  _Supersedes spec 0027 AC-6 clause 3._ That clause admits a token
  whose value the brief's §10 block does not name, provided the value
  "appears verbatim as a colour literal **in a table row** of the
  brief's §1". `#3f7d55` appears in §1, but in the paragraph after the
  status table — "Two more status colours appear exactly once each, as
  the 2px left edge bar on hierarchy-list rows" — and not in a row of
  any table. Clause 3 becomes "**in the brief's §1**". The clause's
  purpose is unchanged and its narrowness is unchanged in the way that
  matters: §1 is the design's inventory of what it is made of, clause 3
  still cannot re-value a token §10 already names, and the divergence
  register is still pinned at exactly three rows. Only the accident of
  which typographic construct a colour was written into stops counting.

  The new token also takes a light-scheme counterpart that differs from
  its default, as spec 0027 FR-13 requires of every colour-valued
  token, and the whole rule stays inside the two `:root` blocks so
  0027 FR-21's "no colour literal outside the token blocks" holds
  (AC-12).

- FR-12: **The twelfth number is re-pointed.** _Supersedes spec 0027
  FR-22 row 12 and the twelfth assertion of AC-18._ That row asserts
  `tbody td` padding computes to `10px 12px`, read from a rendered
  `/ca/{root}` at 1440. After FR-8 every table on that page is a
  `.rows` table, where the 12px horizontal inset is on the `<tr>` and
  the cells are `10px 0` — so the assertion would fail against a build
  that is exactly right.

  The requirement is unchanged: **a list row's padding is the design's
  `10px 12px`.** Two things change, and both keep it measured:
  - the `tbody td` reading moves to a rendered `/certs`, whose table
    this spec does not convert and which is the design's ordinary list
    row (brief §6.2, "10px 12px (inventory, issuer lists)");
  - a thirteenth reading is added on `/ca/{root}`: on a `.rows` `<tr>`,
    the computed vertical padding of a `td` is 10px and the row's own
    horizontal padding is 12px, so the same two numbers are still
    asserted on the page they were asserted on before.

  A number moved to a page where it can be read is still that number; a
  number left where it cannot be is a criterion that gets deleted the
  first time someone is in a hurry.

- FR-13: **The tree glyph is decoration, and that is settled here.**
  Spec 0027's Out of Scope left it open: `#5d5294` (`--accent-deep`) on
  `--bg` is 2.60:1, the design uses it for the `├`/`└` characters, and
  "the honest answer there is likely that the glyph is decoration …
  rather than that the colour needs lifting." It is decoration. The
  indentation, the kind tag and the position under the root all carry
  the structure; the glyph draws a line.

  So the glyph ships in the design's colour, inside
  `<span class="tree" aria-hidden="true">`, and spec 0027's
  `CONTRAST_PROBE` — which walks every element with its own non-empty
  text node and would otherwise report it on every render of `/ca` —
  **gains** `[aria-hidden="true"]` in its
  `el.closest(':disabled, [disabled], [aria-disabled="true"]')` clause.
  An earlier draft of this requirement said the probe "already skips
  `[aria-hidden="true"]`" through that clause. It did not: the clause
  named `aria-disabled`, which is a different attribute, and nothing in
  the probe looked at `aria-hidden` at all. The skip is a change this
  spec makes, and it is verified by the counter-check AC-14 carries —
  the planted element is reported without the attribute and not reported
  with it. A requirement that describes the world wrongly is how spec
  0024's defect got in.

  **The exemption is guarded rather than trusted.** WCAG 1.4.3 exempts
  text that is pure decoration, and an exemption keyed on an attribute
  an author writes is an exemption an author can spread. AC-14
  therefore asserts, over all the pages in the probe's list, that the
  set of elements matching `[aria-hidden="true"]` is exactly the tree
  glyphs on `/ca` — so a second user has to be argued for in the spec
  that adds it, not discovered later in a screenshot.

- FR-14: **No row is dimmed with `opacity`.** The design gives
  non-active rows `opacity: .65` (brief §5.7, §6.3). cabin does not
  ship it, and the reason is not taste: `opacity` composites the whole
  subtree after `getComputedStyle` has reported its `color`, so a
  dimmed row's real contrast is invisible to spec 0027's contrast probe
  — the probe would report 4.5:1 for text that renders at roughly 3:1.
  A property that quietly defeats the check spec 0027 built to hold
  contrast honest is not a property this project adds in the spec after
  it.

  A retired row is marked the way every other retired thing in cabin is
  marked: its status tag reads `retired` and carries `tag-bad`, and its
  left status bar is the retired colour (FR-11). AC-15 asserts no
  `opacity` declaration exists in any rule this spec adds, and that a
  retired row's text still clears 4.5:1 on the rendered page.

- FR-15: **Wording is unchanged, and there is no exception.** Every
  sentence, label, heading, help line, empty state and tag label on the
  five templates is byte-identical to what it says today. This is the
  rule for the whole redesign — it is what keeps several hundred text
  assertions from being touched — and this spec takes no named
  exception from it:
  - FR-4's new section reuses `ca_issuer.html`'s existing heading
    `Renew and retire` and its existing `.help` line;
  - FR-5's per-root empty state reuses the first clause of
    `ca_detail.html`'s `#ca-no-intermediates` sentence rather than the
    design's own ("No issuer yet — nothing can be signed under this
    root.");
  - FR-7's banner carries `ca_issuer.html:21-22`'s text unchanged;
  - the column heading `Kind` (FR-2) is already the label
    `ca_issuer.html:18` renders for the same value.

  AC-16 asserts this directly rather than trusting it, by comparing the
  multiset of visible text nodes on each of the five pages before and
  after.

- FR-16: **The widened tables are re-proved at 390.** They are not
  argued at 1440. The overflow probe (spec 0027 FR-3, repaired) runs over
  `/ca`, `/ca/{root}`, the issuer page, the cross page and the
  certificate page at 1440×1150 and 390×900, in both the dark and the
  light stylesheet, with `bad == []` and `examined >= 20` on each run.
  `/ca` at 390 was one of the two thinnest pages spec 0027 measured
  when it set that floor (30 examined); the grouped list adds rows, so
  the floor is safe and stays where it is.

  **That probe owns the page, and only the page.** It excuses every
  element inside a `.scroller`, which is correct and deliberate — a
  scroller exists so that a wide table scrolls instead of breaking the
  page (spec 0015 FR-4). So it is evidence that no page scrolls
  sideways, and it is not evidence for FR-2 or FR-9: it reports
  `bad == []` at 390 for the three-column table shipping today, for a
  four-column plain `<table>`, and for a four-column grid with the
  timestamp still `nowrap` — the build FR-9 measured at 75px of
  overflow. Every table's fit inside its own scroller is measured
  separately, by AC-1, on all three `.rows` tables.

  **Two pre-existing defects this makes visible, and fixes.** Neither
  was named by any requirement, and both were hidden by the same
  exemption — the only instrument ever pointed at them was the page
  probe, and the page probe excuses exactly this. Measured on the
  long-name fixture, each table against its own `.scroller` at 390:

  | Table                                   | Before | After |
  | --------------------------------------- | ------ | ----- |
  | `Cross certificates` (5 col, spec 0026) | 78     | **0** |
  | `/ca`'s hierarchies list (5 col, 0023)  | ~160   | **0** |

  So spec 0026 declined a fourth column to protect a width its own
  five-column table was already 78 pixels over, and `/ca` — the page
  that argument was about — was over by twice that and had been since 0023. FR-9's wrapping requirement brings both to zero. AC-1 covers all
  three `.rows` tables for that reason, and the criterion is not widened
  to let either of them pass.

  (`/ca`'s figure moves with the timestamp's width and with whether the
  page is long enough to take a scrollbar — the same one-or-two-pixel
  caveat FR-9's table carries. It has been measured at 158 and at 160 on
  different fixtures; what is not in doubt is the order of magnitude or
  the sign.)

- FR-17: **What changes in `ca_ui.py`, exactly.** The Interface
  Contract enumerates every key, including the ones inside the
  dictionaries. Spec 0024's contract once described a context change as
  "gains one flag … no other key changes"; that sentence was
  implemented faithfully and produced a defect that survived a green
  suite, and the correction is recorded in that spec's own contract. A
  summary sentence is not a contract.

  Two builders change and no other function does. `_child_view` gains
  `kind`, so a table row can render the Kind cell (FR-2) and the
  grouped list can tell a root row from a child row (FR-5). `_overview`
  gains `issuers`, a list of `_child_view` entries for that root's
  intermediates in `list_cas` order.

  **The work bound of spec 0026 FR-12 follows the component to `/ca`.**
  `_overview` builds its issuer rows through `_child_view`, which calls
  neither `leaf.constraints_of`, nor `crl_service.distribution_url`,
  nor `crl_service.ca_issuers_url`, nor `acme_http.directory_url`, and
  parses each row's certificate once through
  `ca_x509.describe_certificate`. Spec 0026 AC-12 measured that on the
  hierarchy page; AC-6 here measures it on `/ca`, where the temptation
  is now identical and stronger — the obvious way to get a name, a
  status and an expiry for an intermediate is `_row_view`, which makes
  three URL lookups and a constraints parse per row that nothing on
  this page displays.

- FR-18: **Templates and the stylesheet are edited by a script through
  Bash, never with Edit/Write, and `git diff` is read after every
  change.** The PostToolUse formatter breaks Jinja tags apart — it has
  turned `{% if x == "y" %}` into `{% if x="" ="y" %}` — and it
  reflows markdown far outside the edited region. This has cost the
  project a debugging session six times (0021 FR-13, 0023 FR-11, 0024
  FR-10, 0025 FR-15, 0026 FR-18, 0027 FR-25), and this spec rewrites
  five templates and edits the stylesheet. Its check is the diff read
  after each edit, plus AC-20's suite.

## Interface Contract

### Routes

**No route changes.** Not a path, not a method, not a guard, not a form
field, not a status code, not a redirect target. `/ca`, `/ca/{ca_id}`,
`/ca/{root_id}/issuer/{issuer_id}`, `/ca/{root_id}/cross/{cross_id}`,
`/ca/new`, `/ca/create`, `/ca/{root_id}/intermediate`,
`/ca/{ca_id}/cross-sign`, `/ca/{ca_id}/renew`, `/ca/{ca_id}/retire`,
`/ca/{ca_id}.pem`, `/ca/{issuer_id}/chain.pem`, `/certs/{cert_id}` and
everything under `/transfer`, `/api/v1`, MCP, ACME and the CRL routes
are untouched.

### `cabin.web.ca_ui`

```python
def _child_view(row: CACertificate) -> dict[str, object]: ...


def _overview(db: Session, rows: list[CACertificate]) -> list[dict[str, object]]: ...
```

- **`_child_view` returns exactly six keys and no others**: `id`,
  `name`, `kind`, `status`, `not_valid_after`, `href`. `kind` is
  `row.kind` — the string already on the row, no lookup. Spec 0026's
  contract said "exactly five keys and no others"; this is the
  sentence that overturns it. Everything else about the function is
  unchanged, including that it never calls `_cert_info`,
  `leaf.constraints_of`, `crl_service.distribution_url`,
  `crl_service.ca_issuers_url` or `acme_http.directory_url` (spec 0026
  FR-12).

- **`_overview` entries gain exactly one key**, `issuers`, and lose
  none. The full set per entry is `id`, `name`, `status`,
  `not_valid_after`, `intermediate_count`, `cross_count`, `issuers` —
  seven. `issuers` is one `_child_view` entry per intermediate of this
  root, in `list_cas` order. `intermediate_count` is **not**
  replaced by `len(issuers)` in the template: the count column and the
  child rows are two different statements to the reader and the column
  is the design's (brief §5.7).

  `db` stays unused and stays in the signature, for the symmetry with
  `_group` the current docstring gives.

- **`_group` is unchanged** in signature and in returned keys. Its
  `intermediates` and `cross_certificates` entries gain `kind` because
  `_child_view` does — six keys and eight respectively, the cross rows
  keeping `signed_by` and `served`.

- **`_row_view`, `_page_of`, `_load_pair`, `_root_of`, `_detail_page`,
  `_issuer_page`, `_new_page` and every handler are unchanged**, in
  signature and in body.

### `cabin.web.certs_ui`

**Unchanged.** No function, no constant, no context key. See FR-1.

### `cabin.web.templates`

| File               | Change                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------- |
| `ca_list.html`     | the table becomes a `.rows`/`.cols-hierarchies` grid table with grouped root and child rows (FR-5)        |
| `ca_detail.html`   | section order (FR-4); the two tables gain the grid treatment and the issuers table a Kind column          |
| `ca_issuer.html`   | the identity table becomes `.facts` (FR-6); the cross rows become the `.panel` banner (FR-7)              |
| `ca_macros.html`   | `renew_retire`'s retire form gains the `.panel-danger` wrapper; `constraints_block` unchanged             |
| `cert_detail.html` | the fact table becomes `.facts`/`.facts-indent`; SANs one per line; the revoke form gains `.panel-danger` |

No template gains a `<details>`, a `<summary>` or an `hx-` attribute
(spec 0026 FR-16 stands; htmx arrives in spec 0029 under its own rule).
No template's `nav_current` changes.

### `cabin.web.static/cabin.css`

One token added to both `:root` blocks (`--bar-active`, FR-11) and the
fourteen classes of FR-10, plus the scoping changes FR-8 names to
`tbody td`, `tbody tr:hover` and the table display rules. No existing
class is renamed: all eleven load-bearing names spec 0027 AC-16 pins
survive untouched.

### Schema, services, API, MCP, ACME

Unchanged. No migration, no column, no enum value, no change to
`ca/service.py`, `certs/service.py`, `api/`, `mcp/` or `acme/`. No
audit action: this spec renders existing state.

## Acceptance Criteria

Every criterion is anchored to the element or the computed value it is
about — a parsed `<tr>`, a computed style, a probe's own counters —
never to a substring appearing somewhere in a page. Where a state is
meant to differ, both halves are in one criterion, so that a build
rendering nothing and a build rendering everything each fail.

The fixture, unless stated otherwise, is spec 0026's: hierarchy
**alpha** (root with `path_length=2`, one intermediate carrying
`permitted_names`), hierarchy **beta** (one intermediate), a cross
certificate for beta's root signed by alpha's root, and a base URL set.

- AC-1: **The Kind column exists and costs no width.** On
  `GET /ca/{alpha_root}` the `Issuers` table's `<thead>` has exactly
  four `<th>` elements reading `Name`, `Kind`, `Status`, `Expires` in
  that order, and the one `<tr>` in its `<tbody>` has four cells whose
  second contains a `.tag` reading `intermediate`.

  Then **two measurements at 390×900, both of which can fail**, because
  the single measurement the first draft asked for could not:
  1. **The page does not overflow.** The overflow probe over that page
     reports `bad == []` with `examined >= 20`. This is the question
     that probe genuinely owns, and it is worth asking — but it is not
     evidence about the table, because it excuses everything inside a
     `.scroller` (FR-16).
  2. **Each table fits its own box.** For every `.rows` table on `/ca`
     and `/ca/{root}` — the four-column `Issuers`, the five-column
     `Cross certificates` and `/ca`'s five-column grouped list — its
     `.scroller`'s `scrollWidth` is at most its `clientWidth`: the table
     fits without scrolling. In the same test, no `<td>` of a `.rows`
     table computes `white-space: nowrap` (FR-9's mechanism, measured on
     the computed style rather than on the markup). The failure names
     the offending cell, what it needs and what it has.

  Both are counter-checked in the test rather than trusted: a 4000px
  element planted **inside** the scroller must be reported by clause 2
  and is invisible to clause 1, which is the difference between the two
  stated as an experiment.
  _Goes red if_: the column is added and the table stops fitting at 390
  — which is what spec 0026 FR-2 predicted, what the `nowrap` timestamp
  actually caused (FR-9), and what clause 1 on its own reports as
  perfectly green. Clause 2 also goes red for the cross table's
  pre-existing 78px overflow (FR-16) unless this spec fixes it.

- AC-2: **The whole row is the target and the name cell is still the
  link.** On `GET /ca/{alpha_root}`, the issuers row's first cell
  contains exactly one `<a>`, its `href` is
  `/ca/{alpha_root}/issuer/{alpha_int}`, its text is the
  intermediate's name, and it carries `class="rowlink"` — spec 0026
  AC-2's assertion, re-run unmodified, plus the class. In headless
  Chrome at 1440 the `::after` box of that anchor is asserted to cover
  the row: its rect's width and height equal the `<tr>`'s within 1px.
  Every `<tr>` in every `.rows` table on the three pages contains at
  most one `<a>`.
  _Goes red if_: the overlay is drawn against the page rather than the
  row (`position: relative` missing on the `<tr>`), in which case it
  covers the whole table and the last row wins every click — a defect
  no markup assertion sees.

- AC-3: **Focus is visible on the row, not only on the name.** In
  Chrome, focusing the `.rowlink` of the second row of `/ca`'s grouped
  list: the anchor's own computed outline still satisfies spec 0027
  AC-11 (style not `none`, width ≥ 2px), **and** the `<tr>`'s computed
  background differs from an unfocused sibling row's. In the same test
  `cabin.css` contains no `outline: none` and no `outline: 0`.
  _Goes red if_: the anchor's ring is suppressed to make room for the
  row's, which is the obvious implementation and which spec 0027 FR-15
  forbids.

- AC-4: **Renew and retire are last, and the tables are still above the
  forms.** On `GET /ca/{beta_root}` as an admin, six blocks are located
  with `_row(...)` — the root's `.section`, `Issuers`,
  `Cross certificates`, the `.section` holding the form with action
  `/ca/{beta_root}/intermediate`, the one holding
  `/ca/{beta_root}/cross-sign`, and the one holding
  `/ca/{beta_root}/retire` — and their document positions are asserted
  to be in that order. Spec 0026 AC-1's five-block order is the first
  five of them and is unchanged. The root's own `.section` contains no
  `<form>`; the last section's `<h2>` reads `Renew and retire`.
  _Goes red if_: the forms are moved out of the root section but land
  above the tables, undoing the fix spec 0026 exists for, or if they
  are left in place and a second copy is added below.

- AC-5: **`/ca` is the grouped list.** On `GET /ca` with alpha and beta
  and no cross certificate on alpha: the table has one `.row-root` per
  root and, beneath each, one `.row-child` per intermediate of **that**
  root, in that order — asserted over the document positions of the
  parsed rows, so a build that renders every issuer at the bottom
  fails. Each child row's name cell links to
  `/ca/{that root}/issuer/{that intermediate}`, and following the link
  returns 200. Each root row still carries its `Intermediates` and
  `Cross certificates` counts. For a root created with no intermediate,
  one row in place of the children reads the sentence lifted from
  `#ca-no-intermediates`, and the root row's count column reads `0`.

  **A child row carries its status, and the test proves it by effect**
  (FR-5). One issuer is retired through the real `POST /ca/{id}/retire`,
  and afterwards: that issuer's own `.row-child` on `/ca` has a
  `tag-bad` tag reading `retired` in the `Status` column, and every
  other child row on the page still reads `active` there. Both halves,
  because a build that marks every row retired and a build that marks
  none would otherwise each pass.
  _Goes red if_: the children are rendered under the wrong root — the
  positional assertion is the only thing that catches it, since every
  name and link would still be present somewhere on the page — or if
  the kind tag is rendered _instead of_ the status, which was the
  mis-punctuated reading of FR-5 and which leaves a retired issuer
  indistinguishable from a live one on the page an operator opens to
  find out which is which.

- AC-6: **`/ca` does the work its output needs and no more.** With
  `crl_service.distribution_url`, `crl_service.ca_issuers_url`,
  `acme_http.directory_url` and `leaf.constraints_of` wrapped in
  counting spies, rendering `GET /ca` on an instance with two
  hierarchies and three intermediates calls each of the four **zero**
  times. In the same test the page contains three `/issuer/` links, so
  a build that renders no children cannot pass by doing no work.
  _Goes red if_: `_overview` reaches for `_row_view` to get a name and
  an expiry — the markup is identical either way, which is why this is
  measured at the call.

- AC-7: **The definition grid keeps every field and its box.** On
  `GET /ca/{alpha_root}/issuer/{alpha_int}` the `.facts` table's rows
  carry the labels `Kind`, `Status`, `Valid from`, `Valid until`,
  `Subject`, `Fingerprint` and the values spec 0026 AC-5 asserts, and
  the table is inside a `<div class="scroller">`. In Chrome its `<tr>`
  computes `grid-template-columns` to two tracks. On
  `GET /certs/{cert_id}` the same treatment applies and the SANs cell
  contains **one element per entry of `cert.sans`** — the model's own
  stored values, `DNS:` prefix and all, which is what that cell renders
  today and what FR-6 means by "the values are the same values".

  **"Per name" was ambiguous, and the ambiguity made this criterion and
  AC-16 mutually unsatisfiable.** `certificates.sans_json` stores a SAN
  prefixed (`ca/certs.py`: "the stored SAN strings (`DNS:nas.lan`,
  ...)"), so read as "one element per name **as requested**" this
  criterion required the page to strip the prefix — which is a change to
  what the page says, forbidden by FR-15, and a text node lost, which
  AC-16 forbids in the same breath. No build could satisfy both
  readings; the first draft of this spec's own test was written to the
  wrong one and failed both criteria for that single reason. A pair of
  criteria that cannot both hold is the same class of defect as one that
  cannot fail, and it is corrected here rather than worked around in the
  test.
  _Goes red if_: the restyle drops a field — each is named separately,
  so the failure says which — or drops the `.scroller` wrapper, which
  `test_every_table_is_wrapped_in_scroller` would then also catch.

- AC-8: **The cross banner carries the signer and the serving clause,
  and the grid carries neither.** On
  `GET /ca/{beta_root}/cross/{cross_id}`: a `.panel` element contains
  the signing root's name, the phrase `in place of`, and the serving
  tag; the `.facts` table contains no row labelled `Signed by` and none
  labelled `Serving`. With the cross certificate's validity moved
  wholly into the past, the banner contains the full clause naming the
  validity window and stating the fallback needs no action (spec 0026
  AC-16's second half, re-pointed), and the hierarchy page's cross row
  still contains `not served`.
  _Goes red if_: the banner is added and the rows are left in place —
  the second clause is the only assertion that fails, and it is what
  turns "moved" into a fact.

- AC-9: **The column templates are the design's.** In Chrome at 1440,
  `getComputedStyle(tr).gridTemplateColumns` on a row of each of the
  three `.rows` tables resolves to 5, 4 and 5 tracks respectively, and
  the track widths are in the brief's ratios within 2%. In the same
  test the stylesheet's declaration for each `.cols-*` class is parsed
  and every track is asserted to be a `minmax(0, …)` form.
  _Goes red if_: the design's ratios are not what ships, or a track is
  written in a form that does not bound itself to the container. The
  first draft of this clause said a bare `Nfr` "reproduces the
  `<table>`'s refusal to shrink at 390 — the computed widths would pass
  and AC-1's probe would fail". Both halves were wrong and both are
  measured in FR-9: a bare `Nfr` fits at 390 on this content, and AC-1's
  probe cannot fail for that reason at all. What this criterion actually
  protects is that the file says `minmax(0, …)` — the design's own form,
  which holds for content this fixture does not contain — and that the
  rendered ratios are the brief's. The claim that a bare `Nfr` breaks
  390 is not made here any more; AC-1 clause 2 measures the fit
  directly, whatever the tracks are written as.

- AC-10: **Every table is still a table, and still wrapped.**
  `test_every_table_is_wrapped_in_scroller` passes unmodified. Across
  the five templates, `<table>`, `<thead>`, `<tbody>`, `<th>` and
  `<td>` are still the elements used — no `<div role="table">`, no bare
  `<div>` rows — and every `.rows` table has a `<thead>` with one `<th>`
  per track.
  _Goes red if_: the design's `<div>` stack is reproduced literally,
  which is the brief's own explicit "do not" (§6.2).

- AC-11: **The stylesheet and the templates agree, in both
  directions.** `test_stylesheet_and_templates_agree_in_both_directions`
  passes over the full page list with no addition to its `tag-*`
  exemption list: every class in a rendered `class="…"` attribute has a
  rule, and every rule has a user in the union of the rendered pages
  and the templates' literal class tokens. In the same test, each of
  the six names spec 0027 reserved and this spec does not render —
  `.nav-count`, `.seg`, `.pill`, `.toggle`, `.kicker`, `.flash` — has
  no rule in `cabin.css`.
  _Goes red if_: a status class is written as `state-{{ … }}`, which
  makes `.state-retired` a rule with no literal user, or if the
  redesign's later components are defined here "while we are in the
  file".

- AC-12: **The new colour has provenance and a counterpart.**
  `--bar-active` is `#3f7d55`, that literal appears in §1 of
  `docs/design/0027-brief.md`, the light `:root` block defines it with
  a different value, and `test_the_palette_equals_the_checked_in_brief`
  passes with clause 3 widened to §1 (FR-11). In the same test every
  `#`-literal and `rgba(` in `cabin.css` still falls inside one of the
  two `:root` blocks, and the divergence register still has exactly
  three rows.
  _Goes red if_: the bar's colour is written into the rule instead of a
  token, or the register is widened to launder it — the three-row pin
  is what stops the second.

- AC-13: **The twelfth number is still asserted, on a page where it can
  be read.** `test_the_twelve_numbers` reads `tbody td` padding from a
  rendered `/certs` and gets `10px 12px`; on `/ca/{root}` a `.rows`
  `td` computes `10px 0` and its `<tr>` computes `0 12px`. The other
  eleven numbers are read exactly where spec 0027 AC-18 reads them and
  are unchanged.
  _Goes red if_: the number is deleted rather than re-pointed, or the
  grid row's insets drift from the design while the old assertion
  passes on a page nobody changed.

- AC-14: **The tree glyph is decoration and the exemption has exactly
  one user.** On `/ca`, every `.tree` span carries
  `aria-hidden="true"`; the contrast probe runs over the full page list
  in both schemes with `bad == []` and `examined >= 30` per page; and
  across all those pages the set of elements matching
  `[aria-hidden="true"]` is exactly the `.tree` spans.
  _Goes red if_: `aria-hidden` is used to silence a contrast failure on
  something that is not decoration, which is the only way this
  exemption can do harm.

- AC-15: **Nothing is dimmed with opacity, and a retired row is still
  readable.** No rule added by this spec declares `opacity`, asserted
  by parsing `cabin.css`. With beta's intermediate retired, the
  contrast probe over `/ca` and `/ca/{beta_root}` reports `bad == []`,
  and that row's `<tr>` — scoped by the link in its name cell —
  contains a `tag-bad` tag reading `retired`.
  _Goes red if_: the design's `opacity: .65` is shipped, in which case
  the probe reports nothing and the page is a third less legible than
  the probe believes.

- AC-16: **Not one sentence changed.** For each of `/ca`,
  `/ca/{root}`, an issuer page, a cross page and a certificate page,
  the multiset of non-empty visible text nodes is compared against the
  same page rendered through the templates as they stood at this spec's
  base commit — one instance, one database, one set of rows, so that
  every difference is a difference of markup and not of data.

  The comparison is **not** an equality, and an earlier draft of this
  criterion asked for one ("equal — modulo the tree glyphs"). It cannot
  be equal: FR-2 adds a `Kind` heading and a kind cell, FR-5 adds a row
  per intermediate, FR-4 gives `ca_detail.html` a section heading and
  its help line, FR-6 splits `cert_detail.html`'s comma-joined SANs into
  one element per name, and FR-7 takes two labels off the cross page.
  Four of those five are this spec's own requirements. So the comparison
  is exact in the direction that carries FR-15 and named in the other:
  - **nothing is lost.** Every text node the page had before is still
    there, with the same multiplicity. The only permitted removals are
    the two labels FR-7 moves (`Signed by`, `Serving`) and the one
    comma-joined SAN string FR-6 splits — listed literally, per page.
  - **every addition is named**, per page, from the fixture's own data:
    the tree glyphs, the `Kind` heading, the kind and status words, the
    issuer names and expiries FR-5's rows carry, and FR-4's heading and
    help line. An addition that is not in the list fails.

  > **Correction (spec 0029 FR-13):** `/ca/{root}` is no longer one URL,
  > and this criterion's "with the same multiplicity" cannot survive that
  > unamended. Spec 0029 turns the `Add intermediate` and `Cross-sign
  > with another root` forms into URL state: the closed page renders
  > neither form's fields, and the two are never open at once. So a text
  > node this spec's base commit had is absent from the closed URL by
  > construction, and `Validity (years)` — which **both** forms carried —
  > cannot appear twice at any URL again, whatever is pooled.
  >
  > The comparison for that one page therefore reads the union of
  > `/ca/{root}`, `?add=intermediate` and `?add=cross-sign`, and on it
  > both directions are compared as **sets**: a sentence absent from all
  > three still fails, and a sentence that merely appears at a second URL
  > is not an addition. The other four pages are one URL each and keep
  > the exact multiset this criterion has always asked for. What is given
  > up is narrow and worth naming: on `/ca/{root}` alone, a duplicated
  > row dropped to a single row would no longer be caught here — the two
  > tables on that page are rendered identically in all three states, and
  > spec 0026 AC-2's row assertions cover them directly.
  >
  > Two strings join the addition list with it: `Add an intermediate` and
  > `Cross-sign with another root`, the closed states' trigger anchors.
  > Spec 0029 FR-14 takes both from copy that already existed — the empty
  > state's link text and the section's own `<h2>` — so neither is new
  > wording, but on a root that has an issuer the empty state does not
  > render, and the first is a string this page did not carry.
  >
  > The correction is recorded here rather than only in spec 0029,
  > because this is the criterion that makes the claim about these five
  > pages, and a criterion corrected somewhere else is a criterion whose
  > next reader will implement the version in front of them.

  Both SAN lists — the joined string that goes and the elements that
  arrive — are **`cert.sans`'s own values**, prefix included (AC-7).
  Naming them in any other form makes this criterion unsatisfiable
  against a build that satisfies AC-7, which is exactly what happened
  the first time.

  _Goes red if_: a heading is "improved" while the markup around it is
  rewritten — which fails both halves at once, since the old wording
  disappears and the new wording is in nobody's list. This is the change
  that costs several hundred text assertions and that no other criterion
  here would see.

- AC-17: **No page scrolls sideways, at either width, in either
  scheme.** The overflow probe over `/ca`, `/ca/{root}`, the issuer
  page, the cross page and the certificate page at 1440×1150 and
  390×900, in the dark and the light stylesheet: `bad == []` and
  `examined >= 20` for each of the 20 runs. The full 19-screen run of
  spec 0027 AC-3 also still passes. This criterion is about the **page**
  — whether a table fits inside its own scroller is AC-1 clause 2, and
  neither criterion can stand in for the other.
  _Goes red if_: a `.scroller` is dropped from something that still
  needs one, or a page draws something outside the viewport that no
  scroller is holding.

- AC-18: **The view builders return exactly what the contract says.**
  `_child_view(row)` returns exactly the keys
  `{id, name, kind, status, not_valid_after, href}` — asserted as set
  equality, so an extra key fails as loudly as a missing one — and
  `kind` equals `row.kind` for an intermediate and for a cross row.
  Each `_overview` entry returns exactly
  `{id, name, status, not_valid_after, intermediate_count, cross_count, issuers}`,
  and `len(entry["issuers"]) == entry["intermediate_count"]` for every
  entry.
  _Goes red if_: `issuers` is built from a different query than the
  count, in which case the page's own two statements about the same
  hierarchy disagree.

- AC-19: **The probes spec 0026 and spec 0027 left running still
  run.** `test_section_and_danger_probes_cover_all_three_pages` passes
  with the danger button now in its own section: every `.section` on
  the three pages has a non-empty first child, every `button.danger`
  has an `input[name="confirm"]` in the same `<form>`, and spec 0027
  AC-21's armed/disarmed colour assertion holds inside
  `.panel-danger`. `test_per_intermediate_growth_stays_bounded` still
  gives `(h4 - h1) / 3 < 80` with `h4 > h1`.
  _Goes red if_: wrapping the retire form in a panel puts the checkbox
  outside the `<form>`, or the section probe's page list stops
  including the new section.

- AC-20: **Everything that was not this spec's subject still works.**
  The 0003–0027 suite passes: every route, guard, CSRF rule, form
  field, redirect and audit event is unchanged; every page still
  renders 200; the API, MCP, ACME, the CRL and cabin's own TLS are
  untouched. The only test changes are the ones the Test list names.

## Test list

**New**, in `tests/test_ca_issuer_pages.py` unless noted:

test_issuers_table_has_a_kind_column_and_still_fits_at_390 (AC-1,
headless Chrome),
test_the_row_is_the_click_target_and_the_name_is_still_the_link (AC-2,
Chrome),
test_focus_paints_on_the_row_and_on_the_link (AC-3, Chrome),
test_renew_and_retire_is_its_own_section_and_comes_last (AC-4),
test_ca_list_groups_issuers_under_their_own_root (AC-5, in
`tests/test_web_ca.py`),
test_ca_list_makes_no_per_issuer_lookups (AC-6, in
`tests/test_web_ca.py`),
test_the_fact_grid_keeps_every_field_and_its_scroller (AC-7),
test_the_cross_banner_carries_what_the_grid_lost (AC-8),
test_the_column_templates_are_the_designs (AC-9, Chrome),
test_the_tables_are_still_tables (AC-10),
test_the_reserved_classes_are_still_reserved (AC-11, in
`tests/test_web_design_shell.py`),
test_the_status_bar_colour_has_provenance (AC-12, in
`tests/test_web_design_shell.py`),
test_the_tree_glyph_is_the_only_decoration (AC-14, Chrome, in
`tests/test_web_design_shell.py`),
test_no_row_is_dimmed_with_opacity (AC-15),
test_no_sentence_changed_on_the_five_pages (AC-16),
test_child_view_and_overview_return_exactly_their_keys (AC-18)

**Re-pointed** — the requirement is unchanged, the selector or the page
it is read from moved. Each is named with what it was protecting and
where that requirement lives afterwards:

- **`tests/test_web_design_shell.py`, `test_the_twelve_numbers`**
  protects spec 0027 FR-22: the design's geometry is the rendered
  geometry, not a value in a file. Its twelfth reading moves from
  `/ca/{root}` — where every table is now a grid table — to `/certs`,
  and gains a thirteenth reading on `/ca/{root}` asserting the same two
  numbers on a `.rows` row (FR-12, AC-13). The eleven others do not
  move.
- **`tests/test_web_design_shell.py`,
  `test_the_palette_equals_the_checked_in_brief`** protects spec 0027
  FR-10: no colour enters the stylesheet without provenance in the
  checked-in brief. Clause 3 widens from "a table row of §1" to "§1"
  (FR-11, AC-12); both other clauses and the three-row register pin are
  unchanged.
- **`tests/test_web_ca.py:245` `test_ca_wizard_ui_flow`** protects that
  an operator with no CA is pointed at the two pages that can make one.
  Its comment states that `/ca` "shows only root rows and counts",
  which FR-5 makes false; the comment is corrected and no assertion in
  it changes.
- **`tests/test_cross_chains.py:848` and the cross assertions in
  `tests/test_ca_issuer_pages.py`** protect that a cross row is
  displayed under its subject root and that an expired one says so on
  its own page. The page assertion moves from the identity table to the
  `.panel` banner (FR-7, AC-8); what it compares does not change.
- **`tests/test_web_name_constraints.py:540, :570, :696`** protect that
  a constrained intermediate shows its entries inside its own block and
  an unconstrained one shows no block. They scope by `.section` and by
  `.constraints`, neither of which this spec touches; they are listed
  here only because the pages under them are rewritten and the scoping
  is re-verified rather than assumed.
- **`tests/test_web_ca_pages.py:431`
  `test_ca_detail_shows_only_its_own_hierarchy`** protects `_group`'s
  `parent_id == root.id` filter, measured on the row's link. Unchanged
  in substance; re-verified against the grid `<tr>`, which is still a
  `<tr>`.
- **`tests/test_web_ca_pages.py:381`
  `test_ca_list_has_no_forms_and_links_each_hierarchy`** protects spec
  0023 AC-1: _`/ca` is a list — no forms, and no per-hierarchy detail,
  which belongs on the hierarchy's own page._ It measured that with two
  proxies, and FR-5 supersedes one of them: an intermediate's **name**
  no longer counts as detail, because naming every issuer is what the
  grouped list is for — every issuance, every ACME directory and every
  grant is named by an issuer and not by a root, and a count tells an
  operator a number when what they wanted was a name. The assertion is
  inverted rather than dropped, and tightened while it moves: the name
  must now be present **as a link to the issuer's own page**, which a
  stray mention of the string would not satisfy. The other proxy — no
  fingerprint of any row on the list — is untouched, and it is the one
  now carrying the requirement whole.
- **`tests/test_web_ca.py:641`
  `test_ca_page_hides_unavailable_actions_for_imported_root`** protects
  that an imported root, which has no stored key, is offered no renew.
  FR-4 moves the root's renew form into the `Renew and retire` section,
  so the positive control follows it there; it is **not** relaxed into a
  page-wide search, which would pass on a build that offered the form
  somewhere else entirely. The negative gains two clauses that the move
  makes necessary: the blocked URL is absent from the whole page (an
  absence scoped to one block says little once the block has moved), and
  the imported root's own `Renew and retire` section is asserted to
  exist and to carry its retire form — so this is an absence inside a
  block that is there, not the absence of the block.

**Strengthened** — the requirement grows. Each is named with what it
was protecting and what it could not catch:

- **`tests/probes.py`, `CONTRAST_PROBE`** protects spec 0027 FR-14:
  contrast is measured on what is drawn, not on the token table. Its
  skip clause gains `[aria-hidden="true"]`, and AC-14 adds the guard
  that the exemption has exactly the users this spec names — without
  which an attribute an author writes would be an exemption an author
  can spread. It could not previously catch that at all, because it had
  no notion of a decorative element.
- **`tests/test_web_layout.py:87`
  `test_every_table_is_wrapped_in_scroller`** protects spec 0015 FR-4.
  Unchanged in substance and it passes unmodified; AC-10 adds to it the
  assertion that the five templates still use table elements at all,
  which the old test cannot see — a page that replaced its `<table>`
  with `<div>`s would satisfy it vacuously by having no `<table>` left
  to wrap.
- **`tests/test_ca_issuer_pages.py:1222`
  `test_section_and_danger_probes_cover_all_three_pages`** protects
  spec 0024 AC-11 and spec 0027 AC-21. The hierarchy page gains a
  seventh `.section` and the retire form gains a wrapper, so the
  danger probe's armed/disarmed half now runs inside `.panel-danger`;
  the assertion shape does not change and the
  `_count_danger_buttons(html) >= 1` sanity clause stays.

**Retired — one, with its argument.**

- **`tests/test_web_design_shell.py`, `test_only_layout_html_changed`**
  protected spec 0027 FR-18/AC-1: _0027 touched no content template's
  markup_. It compared every template against commit `c455922` and
  required `layout.html` to be the only one that differed. This spec
  edits five templates by requirement (FR-1), so it now fails on exactly
  the change it existed to license later.

  It is **retired, not re-pointed**, and the reason is that what it
  asserted is a property of one commit rather than of the codebase. "The
  diff from `c455922` to the 0027 merge touched one template" was true
  when it was written, is true now, and cannot be made false by anything
  a later commit does — so there is no regression for it to catch.
  Re-pointing it at a second fixed pair of commits would assert only
  that git history is immutable, which git already guarantees and which
  no reader would think to check. Its evidence is the commit itself, and
  a commit is better evidence than a test here, because it cannot be
  edited into agreeing with the code.

  Its second half — the formatter guard, a Jinja tag in the new file
  that was not in the old one — is not lost with it. FR-18 restates the
  rule with the same enforcement, and the twenty pages
  `render_pages` fetches with `assert resp.status_code == 200` before
  any probe runs are what a mangled `{% if %}` cannot survive.

**Deleted: none.**

## Out of Scope

**No version bump.** Everything stays 0.2.0 and PR #17 stays open. The
change is UI-visible and gets its entry under `[Unreleased]` in
`CHANGELOG.md`, which is the project's workflow rather than a
requirement of this spec.

**No schema change, no migration, no API, MCP or ACME change.** No
column, no table, no enum value, no route, no tool.

**No `certs_ui.py` change**, and two named consequences (FR-1). The
design's §5.4 puts an **Issuer** row in the certificate's fact grid and
a **status tag beside the title** reading "valid · 18 days" or
"revoked · keyCompromise". Both are content this page does not carry
today: the first needs a new context key, the second needs a computed
status and a days-left number and would be new copy, which FR-15
forbids. They are declined here, not forgotten, and either would be a
small spec of its own.

**No status tag beside the `h1`** on the hierarchy or issuer pages
either, although the design draws one (§5.8, §5.9). The status is a row
of the definition grid and of the root section today; moving it to the
head would overturn spec 0026 FR-6's field list for no gain this
spec's own division and listing needs, and duplicating it would put the
same tag on one page twice.

**No `<details>` and no htmx** (spec 0026 FR-16 stands). Spec 0029
gives htmx its first user, under the rule that every htmx target is a
URL that also works as a page. Nothing here needs client-side state:
every row is a link and every control is a form POST.

**No sorting, filtering or paging** on any of these tables, for the
reason spec 0026 and spec 0023 both recorded: a hierarchy with enough
intermediates to need them is not a state this project has seen.

**No per-group box on `/ca`.** The design's §6.3 draws each root and
its children as one rounded box built from per-row borders. cabin's
`.scroller` is already that box (spec 0015 FR-5) and already wraps the
whole table, and nesting a second border inside it would draw two.
The root row's fill and its 2px status bar are what separate one group
from the next.

**No `opacity` dimming** (FR-14), **no expired status bar** (FR-11) and
**no design fact grid without its `.scroller`** (FR-6) — three
deliberate divergences from the brief, each argued where it is
required.

**The remaining pages.** The dashboard's Authorities block and the
CA-key page both render the grouped list this spec defines; they are
spec 0030's, and they reuse `.rows`, `.cols-*`, `.row-root` and
`.row-child` without redefining them.
