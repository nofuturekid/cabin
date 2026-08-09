# Spec 0027 — Shell, Tokens and Component Vocabulary

## Context

Thomas had Claude Design draw a full redesign of cabin against this
branch and asked that it be followed as closely as possible. The
prototype it produced turns out not to use its own design system:
`class=` appears zero times in its markup, `var(--…)` appears zero
times, every style is an inline `style="…"` attribute with a hard-coded
hex, and the design-system bundle it links is an empty stub. So the
prototype's markup is not the specification. The distilled brief is,
and this spec checks it in at `docs/design/0027-brief.md` (FR-1) so
that "matches the design" is a comparison a test can make rather than a
matter of opinion.

Three decisions were taken from concrete alternatives before this spec
was written, and are not reopened here: **dark becomes the default and
light stays** under `prefers-color-scheme: light`; **htmx is wired up**
for the live preview panels (spec 0029, not here); and the work runs
**shell first, then the detail pages, then the rest**, with the suite
run after each.

This spec is the shell. It rewrites `src/cabin/web/static/cabin.css`,
edits `layout.html`, changes which fonts are vendored — and **touches
no content template's markup** (FR-18). That boundary is what makes it
one verifiable step: after 0027 the suite is still at 1000 passing with
only the test edits the Test list enumerates, and every page wears the
design's chrome around the content it already has. Specs 0028, 0029 and
0030 then move the content.

### Three findings that shape the order

**The overflow probe would go vacuously green the moment the shell
lands.** `test_web_layout.py`'s `PROBE` skips any element that has an
ancestor whose computed `overflow-x` is `auto`, `scroll` or `hidden`
(`test_web_layout.py:537-543`). The design's shell is
`height:100vh; display:flex; overflow:hidden`, and its `<main>` is
`overflow:auto`. Every element on every page would therefore gain such
an ancestor, the probe would return `[]` for all 19 screens at both
widths, and `assert offenders == {}` would pass while measuring
nothing. Measured directly: a three-element document inside an
`overflow:hidden` flex shell reports `seen: 3, skipped: 1` — the one
skipped being the only element actually inside the shell. This is the
suite's most valuable test, it exists in **two copies**
(`test_web_layout.py:533` and `test_ca_names_and_actions.py:567`), and
it is repaired first (FR-2..FR-4).

**The stylesheet-agreement test covers 7 CA pages, not 19**, and its
reverse direction is three hard-coded string checks rather than a real
`defined - used` assertion (`test_ca_names_and_actions.py:1265-1330`).
Widened in FR-20. Widening it immediately finds two classes that are
used and have no rule — `tile-label` in `dashboard.html:42` and
`warning` in `acme.html:42` — on pages the current list does not look
at.

**`.section` is already the design's section row.** cabin's is a
two-column grid with a label column and a top border; the design's is
`250px minmax(0,1fr); gap:28px; padding:22px 0; border-top`. Same
construct, different numbers. That is the pattern for the whole job:
keep the vocabulary, change the values. It is why none of the 31
class-scoped assertions in the suite needs editing — they scope by ten
class names (`section`, `note`, `constraints`, `error`, `tag`,
`scroller`, `rail`, `rail-foot`, `nav-group`, `card-narrow`) and all
ten survive. FR-19 turns that from a happy accident into a guarded
fact.

### What this spec overturns in spec 0015

Every requirement listed here is named again in the FR that overturns
it. Nothing else in 0015 changes.

- **0015 FR-1** — the two-column CSS grid on `body` and the sticky,
  one-viewport-tall rail become a `height:100vh; display:flex;
overflow:hidden` shell whose `<main>` scrolls (FR-6). The requirement
  0015 FR-1 was defending — the rail is the only way off a page and may
  not scroll away with the logout button — **stands and is re-asserted**,
  by a different mechanism and a rewritten probe (FR-23).
- **0015 FR-3** — `main`'s fluid `clamp(1rem, 3vw, 2.5rem)` padding
  becomes the design's `26px 34px 60px` around an inner
  `max-width: 1180px` (FR-6, FR-22). "One content width, no page sets
  its own" **stands**; it is exactly what the `card` ban keeps from
  being quietly undone (FR-19).
- **0015 FR-4** — "`.scroller` is the only element allowed to scroll
  horizontally" **stands and is tightened**: `pre.pem` loses its
  `overflow-x: auto`, so the permitted set becomes exactly `{.scroller}`
  and the probe's allow-list can be compared against the stylesheet
  (FR-5). "`body` never scrolls sideways" becomes "the shell never
  scrolls in either axis and `<main>` scrolls only vertically".
- **0015 FR-7** — Public Sans retires and Inter is vendored in its
  place; IBM Plex Mono stays (FR-17). The requirement — both faces
  vendored under `static/fonts/`, both SIL OFL 1.1, licence text
  alongside, nothing fetched from a CDN — **stands verbatim**. Only the
  filenames change.
- **0015 FR-8** — "defined on `:root` and overridden in
  `@media (prefers-color-scheme: dark)`" is inverted: the dark values
  are the defaults and the override block is
  `@media (prefers-color-scheme: light)` (FR-8). The requirement —
  both schemes complete, no token defined in only one — **stands and is
  strengthened three ways** (FR-13).
- **0015 FR-9** — the below-60rem behaviour is kept in substance and
  retuned (FR-7): the shell releases its `100vh`/`overflow:hidden`, the
  rail stacks above the content, `.section` collapses to one column.
  The clause "interactive controls keep a visible `:focus-visible`
  outline in both schemes" **stands and is widened** into FR-15, because
  the design contains no focus state at all.

Spec 0026 FR-14 ("`cabin.css` is not touched") was a requirement of
0026 about 0026 and is not overturned; its acceptance criterion AC-15
compared the file against its state before that spec, not against a
future one.

## User Stories

- As an operator, cabin looks like the design that was drawn for it:
  dark by default, the sidebar fixed, the page's content scrolling
  under it rather than the whole window moving.
- As an operator whose desktop is set to light, cabin is legible —
  every colour has a light counterpart that was solved for the light
  ground rather than copied from the dark one.
- As an operator who has raised their browser's base font size, the
  type scales with it; at the default 16px it is pixel-identical to the
  design.
- As an operator who works from the keyboard, I can see where I am:
  every link, button, field and checkbox draws a focus ring, which the
  design does not contain because everything in the prototype was an
  unfocusable `<div>`.
- As an operator on a phone, the page still never scrolls sideways, and
  the test that proves that still actually measures something.
- As a reviewer, "this matches the design" is a comparison against a
  file in the repository, and every place we deliberately depart from
  it is a row in that file with the reason beside it.
- As the next person to touch the stylesheet, renaming a load-bearing
  class is a deliberate act with an argument, not a side effect.

## Functional Requirements

- FR-1: **The brief is checked in, and it is what the palette is tested
  against.** `docs/design/0027-brief.md` carries the design brief
  verbatim — the distillation of the prototype, its palette, its type
  scale, its geometry and its component inventory — with a short header
  that records where it came from, when it was copied, and the rule
  that governs it.

  The rule: **a deliberate divergence from the design is made by
  editing this file, with the reason written beside the value, in the
  same change as the stylesheet.** The header carries two registers. The
  **palette register** is a table of
  `token | brief value | shipped value | reason`, and FR-10's fidelity
  test reads §10's token block _and_ that table, applying its
  overrides. The second is prose, for the divergences that are not a
  token — FR-5's `<main>` overflow rule, FR-17's mono stack, FR-16's
  dropped 9.5px step — followed by a third list for what the design
  does not contain at all and this spec adds: the light scheme, the
  focus state, `prefers-reduced-motion`. Only the first is machine
  read; the other two exist so the file is the whole account rather than
  the part a test happens to parse. A stylesheet that
  disagrees with the file is a failure; a divergence with no reason
  beside it is a failure; and a value quietly changed in the stylesheet
  alone cannot pass. This is what makes "matches the design"
  mechanically true rather than a matter of opinion, and what makes a
  later change of mind show up as a diff someone can read.

  The file is not otherwise edited by this spec. Its own §0 "Note on
  location" paragraph is stale on arrival — it was written while the
  document lived in a scratch directory — and is left in place, because
  the body being verbatim is worth more than the paragraph being tidy.
  The header says so.

- FR-2: **The overflow probe is repaired before any page changes, and
  it has exactly one definition.** The probe, its `_serve` helper and
  its Chrome invocation move into a new `tests/probes.py`, and
  `test_web_layout.py` and `test_ca_names_and_actions.py` both import
  it. There are two copies of the walker today, character for
  character, and a repair applied to one of them leaves the other
  vacuously green over nine CA and transfer pages — which is the same
  defect this spec exists to fix, one level up. `tests/` already holds
  shared helper modules (`ca_fixtures.py`, `live_server.py`,
  `acme_client.py`), so this introduces no new convention.

- FR-3: **What the repaired walker does.** The `scrollable(el)` helper —
  which walks an element's ancestors and returns true if any has a
  computed `overflow-x` of `auto`, `scroll` or `hidden` — is **deleted**
  and replaced by an allow-list expressed as a selector:

  ```js
  function excused(el) {
    return el.closest(".scroller") !== null;
  }
  ```

  An element is skipped only when it sits inside the one construct
  spec 0015 FR-4 permits to scroll horizontally. Computed style is no
  longer consulted for this decision, because computed style is exactly
  what the design's shell falsifies: `overflow:hidden` on an ancestor
  now means "this overflow is invisible", which is the strongest reason
  to report it, not to excuse it.

  The rest of the probe is unchanged and keeps working: `container(el)`
  still walks to the first non-inline ancestor with a non-zero width,
  and both comparisons still use `getBoundingClientRect()`, which
  reports layout geometry and is unaffected by clipping. The
  "past viewport" clause therefore still catches an element drawn
  outside the window even though the shell now clips it.

- FR-4: **The probe reports what it examined, and a negative control
  proves it can still fail.** The probe's result becomes
  `{"bad": [...], "examined": N, "excused": M}` instead of a bare list.
  Every caller asserts `bad == []` **and** `examined >= 40` per page.
  Forty is far below any real cabin page and far above the two or three
  elements a walker that excuses everything would leave — the exact
  number the current walker would report once the shell lands.

  In addition, one test injects a `<div style="width:4000px">` into a
  rendered page and asserts the probe names it. A probe that cannot be
  made to fail is not evidence, and this project has shipped assertions
  that could not fail more than once. AC-2 is that test.

- FR-5: **The stylesheet's horizontal-scroll set is exactly
  `{.scroller}`, and the probe's allow-list is compared against it.**
  This re-asserts spec 0015 FR-4 and tightens it:
  - `pre.pem` loses its `overflow-x: auto`. The design's PEM block is
    `white-space: pre-wrap; word-break: break-all` (brief §6.9), so it
    wraps instead of scrolling and no longer needs the exemption it has
    today. That removes the one element besides `.scroller` that the
    old probe would have had to excuse.
  - `<main>` is `overflow-y: auto; overflow-x: hidden`, **not** the
    brief §4's `overflow: auto`. A `<main>` that scrolls horizontally is
    a page that scrolls sideways with extra steps, which is the defect
    spec 0015 exists for. Recorded as a divergence from the brief
    (FR-1's second register, the prose one), with that as the reason.
  - The shell itself is `overflow: hidden` in both axes.

  A test reads `cabin.css` and asserts that the set of selectors
  declaring `overflow-x: auto|scroll` or `overflow: auto|scroll` is
  exactly `{.scroller}` (plus `overflow-y: auto` on `<main>` and on
  `.rail nav`, which are vertical and permitted). The probe's allow-list
  and the stylesheet cannot drift apart without one of them failing.

- FR-6: **The shell** (supersedes spec 0015 FR-1 and FR-3's padding
  clause). `layout.html` wraps the rail and `<main>` in one element
  `<div class="shell">`; `<aside class="rail">`, `<main>` and
  `<body class="{% if user %}with-rail{% endif %}">` keep their names
  and their nesting order, because ten test assertions and the rail
  probes scope by them (FR-19).

  | Element  | Design                                                                                                                                                      |
  | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `.shell` | `height:100vh; display:flex; overflow:hidden; position:relative; background:var(--bg)`                                                                      |
  | `.rail`  | `width:230px; flex:none; background:var(--surface-low); border-right:1px solid var(--line-panel); display:flex; flex-direction:column; padding:18px 0 14px` |
  | `main`   | `flex:1; min-width:0; overflow-y:auto; overflow-x:hidden; padding:26px 34px 60px`, with an inner wrapper at `max-width:1180px`                              |

  `.rail` is no longer `position: sticky`: it cannot scroll away
  because the shell does not scroll. `.rail nav` keeps its own
  `flex:1; min-height:0; overflow-y:auto`, which is what keeps the
  footer — and the logout button in it — on screen when the entry list
  is taller than the viewport. That is the requirement spec 0015 FR-1
  was defending and FR-23 re-measures it.

  `position: relative` on the shell exists for the flash message spec
  0030 will place at `left:250px; bottom:22px`; it is declared here
  because it is part of the shell, and nothing in 0027 renders inside
  it.

- FR-7: **Below 60rem the shell releases** (supersedes spec 0015 FR-9's
  numbers, keeps its behaviour). The design is desktop-only — the brief
  describes no narrow viewport anywhere — so the responsive rules cabin
  already has are kept and retuned, not dropped: `.shell` returns to
  `display:block; height:auto; overflow:visible`, the rail stacks above
  the content as a wrapping strip, `main` drops to `padding:18px 16px
40px`, and `.section` collapses to one column. AC-3's 390-pixel half
  of the overflow probe is what holds this honest.

  The consequence is deliberate and stated here so a later reader does
  not have to infer it: the "shell never scrolls" criterion (AC-12) is
  asserted at 1440 only, because below the breakpoint the page is
  supposed to scroll again.

- FR-8: **The token layer, dark first** (supersedes spec 0015 FR-8's
  direction, keeps its requirement). Every token is declared in
  `:root` with its dark value. The light scheme is **exactly one**
  `@media (prefers-color-scheme: light)` block containing **exactly
  one** `:root` rule containing **only** custom-property declarations —
  no other selector, no other rule, nothing else in the block.

  That shape is a requirement rather than a style preference: FR-14's
  contrast probe forces the light scheme by stripping the media wrapper
  from a copy of the stylesheet so the block applies unconditionally,
  and that transformation is only faithful if the block holds nothing
  but token overrides. A test asserts the shape (AC-9).

- FR-9: **Token names: cabin's where the role is unchanged, the
  brief's where a role splits.** The mapping is in the Interface
  Contract and is exhaustive. In summary: `--bg`, `--text` and
  `--accent` keep their names; `--panel`/`--panel-2` split into
  `--surface-low`, `--surface` and `--surface-hover`; `--dim`/`--faint`
  become a seven-step text ramp; `--line`/`--line-strong` become
  `--line-panel`/`--line-control` plus two `rgba()` rules; the single
  `--radius` becomes `--r-chip`/`--r-control`/`--r-panel`; `--rail`
  becomes `--shell-nav`; and `--ok`/`--warn`/`--bad` become the design's
  five status triples.

  `--accent-bg`, `--accent-ink`, `--bad-bg`, `--bad-ink`, `--pad` and
  `--space-1..4` are **retired**, and the contract says what replaces
  each. The design has no filled primary button — its primary is an
  outline with an accent label — so the fill/ink pair has no role left,
  and the brief's own finding is that the spacing is ad hoc rather than
  a scale ("Nocturne's `--space-*` is not used at all. Do not adopt
  it."), so the four spacing tokens are replaced by the design's named
  structural values, not by a different scale.

- FR-10: **Palette fidelity, asserted against the checked-in file.** A
  test parses the token block in §10 of `docs/design/0027-brief.md`,
  applies the divergence register from that file's header (FR-1), and
  asserts that every resulting `name: value` pair appears in `:root`
  exactly. Both directions: a token in the brief and missing from
  `:root` fails, and a colour-valued token in `:root` that the brief
  does not name fails unless it is in the register.

  This is the criterion that turns "follow the design as closely as
  possible" into something a suite can hold. Without it, the palette is
  76 screenshots and an opinion.

- FR-11: **Three colours are lifted to reach 4.5:1, and this is a
  deliberate divergence from the design.** The design uses them as body
  text on the page ground; they do not clear WCAG 1.4.3's 4.5:1 for
  text under 18.66px, and every one of them is used at 10–12px.
  Measured with the WCAG 2.x relative-luminance formula, against
  `--bg: #161826` unless stated:

  | Token                  | Brief   | Ratio                 | Shipped     | Ratios (bg / low / hover / surface) |
  | ---------------------- | ------- | --------------------- | ----------- | ----------------------------------- |
  | `--text-faint`         | #75798c | 4.08:1                | **#888b9c** | 5.21 / 4.96 / 4.84 / 4.50           |
  | `--text-hint`          | #63677a | 3.15:1                | **#818699** | 4.87 / 4.63 / 4.52 / 4.20           |
  | `--danger-disarmed-fg` | #6d5259 | 2.17:1 on `--surface` | **#a3848c** | — / — / — / 4.51                    |

  `--text-faint` is lifted until it clears 4.5:1 on all four grounds it
  is drawn on, including `--surface` (#232532), because the design uses
  it for panel kickers. `--text-hint` is lifted until it clears 4.5:1
  on `--bg`, `--surface-low` and `--surface-hover`; it is never drawn
  on `--surface` in the design, and FR-14's probe — which measures
  rendered pairs, not intended ones — is what holds that true rather
  than a comment.

  Two consequences are recorded rather than hidden. First, the two
  faintest steps of the seven-step ramp end up **1.07:1 apart**: the
  ramp has no room left below the floor, so they are near-neighbours in
  the dark scheme. They stay distinct tokens because their roles differ
  and the light scheme has more room. Second, the third row is not in
  the plan, which named two failing colours. `#6d5259` is the
  "disarmed" danger-button label, and cabin's retire and revoke buttons
  are live `<button>` elements whose confirmation is checked on the
  server — they are not HTML-disabled, so WCAG's incidental exemption
  does not reach them. Lifted on the same grounds as the other two, and
  it still reads as disarmed against the armed `#e9908e` because it is
  desaturated, not merely dimmer.

  `--text-disabled` (#5a5d6b) and the busy-button label (#6b6f80) are
  **not** lifted: those are genuinely disabled controls and are exempt.
  FR-21 makes that exemption checkable rather than asserted, by
  requiring `--text-disabled` to appear only in rules whose selector
  carries `:disabled`, `[disabled]` or `[aria-disabled="true"]`.

- FR-12: **The light palette is derived, not inverted.** It has never
  existed as a design; the prototype is dark-only. Three rules govern
  it, and all three are checkable:
  1. **The ground order is preserved, not mirrored.** In both schemes
     `luminance(--surface-low) < luminance(--bg) < luminance(--surface)`.
     A naive inversion breaks exactly this — it puts the recessed
     surface above the page and the raised panel below it, so every
     input looks raised and every card looks sunken.
  2. **The text ramp stays a ramp.** In both schemes the six body-text
     tokens are strictly ordered by contrast against `--bg`:
     `--text` > `--text-2` > `--text-3` > `--text-muted` >
     `--text-faint` > `--text-hint`, and each light token's ratio
     against its light ground is not lower than its dark counterpart's
     against the dark one.
  3. **The accent is re-solved, not mirrored.** `#9184d9` on white is
     **3.23:1** — fine as a focus ring, not as link text. The light
     scheme therefore takes its own three accent values, anchored here:

     | Token             | Dark    | Light   | Light ratios (white / --bg / --surface-low) |
     | ----------------- | ------- | ------- | ------------------------------------------- |
     | `--accent`        | #9184d9 | #6a5cc2 | 5.35 / 4.84 / 4.42                          |
     | `--accent-text`   | #b5abfc | #5b4bb8 | 6.68 / 6.04 / 5.52                          |
     | `--accent-bright` | #d2cefd | #4a3f99 | 8.53 / 7.71 / 7.05                          |

     `--accent-bright` is named for its dark-scheme value, where the
     emphatic end of the accent ramp is the brighter one. In the light
     scheme it is the **darker** end, because emphasis moves away from
     the ground and not toward white. The name is kept because the
     brief gives it and FR-10 compares names; the role is "the emphatic
     end", in both schemes.

  The light grounds are anchored as `--bg: #f3f3f8`,
  `--surface-low: #e8e9f1`, `--surface: #ffffff`. Every other light
  token is derived under rules 1–3, and FR-14's probe over the rendered
  pages in the light scheme is what proves the derivation rather than a
  table someone eyeballed.

- FR-13: **`test_css_defines_dark_counterpart_for_every_token` is
  rewritten, not deleted, and the rewrite is stronger in three named
  ways.** The requirement is spec 0015 FR-8's and is unchanged — a
  token defined in only one scheme is unreadable in the other. Only the
  block it reads moves (FR-8 inverts the default). The three
  strengthenings:
  1. **It accepts `rgba()`, not only `#`.** The current filter is
     `value.strip().startswith("#")` (`test_web_layout.py:133-137`), so
     any token whose value is not a hex literal is silently dropped from
     the set being checked. The design's two dividers —
     `--rule-section: rgba(233,233,237,.08)` and
     `--rule-row: rgba(233,233,237,.07)` — are the border between every
     section and every list row on every page, and under the current
     regex they would have escaped the check entirely.
  2. **It runs in both directions.** `defaults - overrides == set()`
     **and** `overrides - defaults == set()`. An override for a token
     that no longer has a default is dead CSS: it will never apply in
     the default scheme, and it is what a half-finished rename leaves
     behind.
  3. **It rejects an override that merely repeats its default.** Values
     are compared after normalising whitespace and case. This is the
     clause that matters most, and it exists because **copying the dark
     value into the light block satisfies "a counterpart exists" while
     being exactly the defect the test was written for** — the light
     scheme would then paint dark-scheme greys on a white ground, which
     is unreadable, which is the thing spec 0015 FR-8 forbids. The
     old test would have passed against that build.

     The clause rejects a _repeating override_, not a
     scheme-independent token. A token whose value is genuinely the same
     in both schemes is declared once in `:root` and simply not
     overridden; it is then not in `overrides` and the clause never
     sees it.

- FR-14: **Contrast is measured on rendered elements, in both schemes,
  not on the token table.** A Chrome probe walks every element with a
  non-empty text node on all 19 pages, computes its effective colour
  and its effective background (walking up through transparent
  ancestors to the first opaque one), and asserts 4.5:1 — or 3:1 where
  the computed font size is ≥ 24px, or ≥ 18.66px at weight ≥ 700.
  Elements matching `:disabled`, `[disabled]` or `[aria-disabled="true"]`
  are skipped, and the count of elements examined is reported and
  floored exactly as FR-4 requires of the overflow probe.

  It measures rendered pairs because that is the requirement. A token
  table can be correct in the abstract and wrong on the page: FR-11's
  `--text-hint` clears 4.5:1 on three grounds and not on the fourth,
  and only a probe that looks at what is actually drawn on what can
  tell the difference.

  **How the scheme is forced.** Headless Chrome on this machine reports
  `prefers-color-scheme: dark`, so the dark run needs no flag and the
  light run cannot rely on one. The probe copies `cabin.css` into its
  serving directory twice: once verbatim (the dark scheme, since dark
  is now the `:root` default), and once with the
  `@media (prefers-color-scheme: light) { … }` wrapper removed so its
  `:root` block — which comes after the default one and has equal
  specificity — applies unconditionally. FR-8's shape requirement is
  what makes that transformation faithful, and AC-9 asserts the shape
  so the mechanism cannot silently stop being valid. No browser flag,
  no CDP, and both runs use the real values from the real file.

- FR-15: **The focus state the design does not contain.** Every
  clickable thing in the prototype is a `<div onClick>`, so nothing in
  it is focusable and no focus state was ever drawn. The only focus
  rule the brief carries is for `input`/`select`/`textarea`
  (brief §6.4). cabin uses real links, buttons, forms and checkboxes on
  every page.
  - Global: `:focus-visible { outline: 2px solid var(--accent);
outline-offset: 2px }`.
  - Fields keep the design's tighter variant:
    `input:focus-visible, select:focus-visible, textarea:focus-visible
{ outline: 2px solid var(--accent); outline-offset: 1px }`.
  - No rule anywhere sets `outline: none` or `outline: 0`. Asserted by
    reading the stylesheet, because a suppressed outline is invisible to
    a screenshot review and obvious to a grep.
  - `accent-color: var(--accent)` on `input[type="checkbox"]`, which the
    brief calls out (§6.4): the design leaves the checkbox as unstyled
    browser chrome, and on a dark ground in most browsers that is wrong.
  - `--accent` must reach **3:1** against every ground a focused element
    sits on, in both schemes (WCAG 1.4.11). In the dark scheme #9184d9
    is 5.45 on `--bg`, 5.19 on `--surface-low`, 4.71 on `--surface` and
    4.43 on `--accent-tint`; in the light scheme FR-12's #6a5cc2 is
    5.35 / 4.84 / 4.42 on white / `--bg` / `--surface-low`.

  A probe focuses every focusable element on every page in turn and
  asserts the computed outline is at least 2px wide, is not
  `outline-style: none`, and has a colour different from the element's
  own background. AC-11.

- FR-16: **Type in rem at a 16px root, line-height set explicitly,
  motion honoured.**
  - Every font size is declared in `rem` against a 16px root, so at
    default settings the rendered pixel sizes are the design's exactly
    and a raised base font size is still honoured. The prototype had no
    user whose settings could be honoured; cabin does. The scale, in
    px at a 16px root: 30, 29, 17, 13, 12.5, 12, 11.5, 11, 10.5, 10.
    The prototype's 9.5px step is dropped with the element that used it
    (the "Prototype only — view as" control, brief §8).
  - `line-height: 1.5` is set explicitly on `body`. The prototype omits
    it and relies on the browser default (≈1.2), which is not
    reproducible across engines.
  - The two keyframes (`cabinIn`, `cabinToast`) are declared and both
    are wrapped in `@media (prefers-reduced-motion: reduce) { animation:
none }`, which the prototype does not do. `cabinIn` is applied to
    `main`'s inner wrapper — the one element 0027 owns — so that the
    entry animation is in place before 0028 touches a page.
  - Structural geometry stays in px, because the brief's own finding is
    that the spacing is ad hoc rather than a scale and rem-ifying it
    would invent a scale the design does not have.

- FR-17: **Fonts** (supersedes spec 0015 FR-7's font list, keeps its
  requirement). Inter is vendored under `src/cabin/web/static/fonts/`
  as a variable woff2 with its SIL OFL 1.1 licence text alongside it,
  with `font-display: swap` and `system-ui, sans-serif` behind it in
  the stack. Public Sans and its licence are deleted. Weights 400, 500
  and 600 only: the design's `@import` asks for 700 and uses it
  nowhere.

  **IBM Plex Mono stays**, with the design's `ui-monospace,
SFMono-Regular, Menlo, monospace` behind it as fallback rather than in
  front of it. This is a deliberate divergence from the brief §2, and
  the reason is worth stating rather than assuming: cabin's monospace
  carries fingerprints, serials, PEM bodies and CRL/AIA URLs — strings
  an operator compares character by character and copies into other
  tools — and a bare system stack renders them at different advance
  widths on every platform, so a fingerprint that lines up on one
  machine wraps mid-group on another. The prototype never linked a mono
  face at all, so its stack is the absence of a decision rather than a
  decision to prefer the system's.

  The two font tests are **edited, not deleted**: vendored, licensed,
  served with `font/woff2`, nothing from a CDN is the requirement, and
  the filenames were the old look.

- FR-18: **No content template's markup is touched.** `layout.html` is
  the only template this spec edits, and its only change is the
  `.shell` wrapper of FR-6. No other file under
  `src/cabin/web/templates/` changes by a byte. This is the boundary
  that makes 0027 verifiable in one step and it is asserted directly
  (AC-1): every template except `layout.html` is byte-identical to its
  state at `c455922`.

  It has a second effect worth naming, because it decides something the
  plan left open. **0027 defines no class that has no user.** The
  design's new components — `.panel`, `.nav-count`, the grouped-list
  rows, the segmented control, the filter pills, the toggle — are named
  here (FR-19) and defined by the spec that first renders one, because
  FR-20's reverse direction fails on a rule with no user and an
  exemption list for "declared ahead of its users" would be a hole
  large enough to drive the whole redesign through. What 0027 ships is
  the token layer, the shell, and the retuned values of every class
  that already exists.

- FR-19: **Component naming is constrained, and the constraint is
  guarded.**
  - **`.card` and `.badge*` stay banned.**
    `test_no_template_uses_card_or_badge_classes`
    (`test_web_layout.py:101`) forbids `class="… card …"` (except
    `card-narrow`) and any `badge*` in every template, and it is not a
    fossil. Spec 0015's first defect was three competing content widths
    — `main` at 60rem, `.card` at 24rem, `.card-wide` at 48rem — and the
    `card` clause is what keeps "one content width" (0015 FR-3, FR-6
    above) from being quietly undone the moment someone wants a box
    around something. The design's raised box is **`.panel`** and its
    dashboard box is **`.tile`**, which already exists. The `badge`
    clause protects the `tag-*` naming that a dozen assertions in
    `test_web_certs_inventory`, `test_web_acme_ui` and `test_mcp` scope
    by.
  - **The nav count is `.nav-count`**, not `.nav-badge`. It has no user
    until a spec renders it, so it is a reserved name here and not a
    rule (FR-18).
  - **A guard test names the load-bearing class names**: `rail`,
    `rail-foot`, `nav-group`, `shell`, `section`, `scroller`, `tag`,
    `note`, `constraints`, `error`, `card-narrow`. Each must have a rule
    in `cabin.css` and appear in at least one template. Renaming one is
    then a deliberate act with an argument, rather than a side effect of
    a stylesheet rewrite that happens to leave 31 assertions scoping by
    a selector nothing emits any more.

- FR-20: **The agreement test is widened to every page and to a real
  reverse direction.** `test_stylesheet_and_templates_agree_in_both_directions`
  (`test_ca_names_and_actions.py:1265`) protects spec 0024 AC-12. Today
  its forward direction covers 7 CA pages and its reverse direction is
  three hard-coded string checks (`details`, `.inline-form`, `.ca-row`).
  - **Forward**: the page list becomes the same 19 screens the overflow
    probe uses. Every class in a rendered `class="…"` attribute must
    have a rule. This immediately finds two: `tile-label`
    (`dashboard.html:42`) and `warning` (`acme.html:42`) are used and
    have no rule, on pages the current list does not fetch. Both get a
    rule in this spec — the classes are used, so this is not FR-18's
    forbidden case.
  - **Reverse**: `defined - used == set()`, computed from real class
    selectors rather than from `re.findall(r"\.([a-zA-Z][\w-]*)")` over
    the whole file — that pattern matches `woff2` inside
    `url("…/PublicSans.woff2")` and would report a font filename as an
    unused class forever.
  - The reverse direction carries **one** exemption list, for `tag-*`
    values the fixture cannot reach in a single run. Each entry must
    match `^tag-` and must be shown to be produced by a `tag-{{ … }}`
    interpolation in some template; any other name in the list fails the
    test. The three string checks stay as they are: they are cheap and
    they forbid specific things by name.

- FR-21: **No colour literal outside the token blocks, and no
  `color-mix()`.** Every `#rrggbb`, `#rgb` and `rgba(` in `cabin.css`
  appears inside the `:root` block or the light `:root` block. This is
  the one check that proves the token layer is genuinely the source of
  every colour rather than a table sitting beside a stylesheet that
  ignores it.

  `color-mix()` goes with it. Today it computes the three `.tag-*`
  border colours and the `.error` box from `--ok`/`--warn`/`--bad`; the
  design supplies an explicit background, text and border for each of
  its five status families and for each of its three note tones, so the
  computation has nothing left to do. The brief's §9.11 records the same
  conclusion from the other side: no modern colour function is required
  anywhere in this design.

  `--text-disabled` may appear only in a rule whose selector carries
  `:disabled`, `[disabled]` or `[aria-disabled="true"]`. That is what
  makes FR-11's WCAG exemption a fact about the stylesheet rather than
  a claim about intent.

- FR-22: **The twelve numbers the design is made of, asserted as
  computed styles.** Read from a rendered page in Chrome at 1440, not
  from the stylesheet text:

  | #   | Value      | Where                       |
  | --- | ---------- | --------------------------- |
  | 1   | 230px      | `.rail` width               |
  | 2   | 250px      | `.section` first column     |
  | 3   | 28px       | `.section` column gap       |
  | 4   | 22px       | `.section` vertical padding |
  | 5   | 26/34/60px | `main` padding              |
  | 6   | 1180px     | content wrapper `max-width` |
  | 7   | 4px        | `--r-chip`, on `.tag`       |
  | 8   | 6px        | `--r-control`, on `button`  |
  | 9   | 8px        | `--r-panel`, on `.scroller` |
  | 10  | 29px       | `h1` font-size              |
  | 11  | 17px       | `h2` font-size              |
  | 12  | 10px 12px  | `tbody td` padding          |

  Computed styles rather than a text match, because a value in the file
  and a value on the screen are different claims and only the second
  one is the design.

- FR-23: **The rail probe is rewritten in both copies, and the height
  probe is re-pointed.** Neither test loses a requirement.
  - `test_rail_stays_in_view_on_a_long_page` (`test_web_layout.py:654`)
    and `test_rail_stays_in_view_with_sixteen_entries`
    (`test_transfer.py:452`) both do
    `window.scrollTo(0, document.body.scrollHeight)` and then assert
    `scrolled > 400`. The window can no longer scroll, so `window.scrollY`
    stays 0 and both go red — loudly, not vacuously. The mechanism
    becomes: scroll `main` to its end, assert `main.scrollTop > 400`,
    and assert the logout button's rect is still inside the viewport.
    The guard both tests carry — `nav.scrollHeight > nav.clientHeight`,
    "a viewport the rail merely fit into would pass without the internal
    scroll ever engaging" — is kept **verbatim**, because it is the half
    that makes the criterion non-vacuous and the shell does not make it
    redundant: the rail's footer is still pushed out of a 100vh column
    and clipped by `overflow:hidden` if `nav` does not scroll on its own.
  - `_HEIGHT_PROBE` (`test_ca_issuer_pages.py:682`) reports
    `document.body.scrollHeight`. With the shell at `100vh` that is now
    the viewport height for every page, so spec 0026 AC-13's growth
    bound `(h4 - h1) / 3 < 80` would compute `0 < 80` and pass while
    measuring nothing. It is re-pointed at `#main`'s `scrollHeight`.
    `<main>` gains `id="main"` in `layout.html` for this, which is the
    one further change FR-18 permits to that file.

- FR-24: **The danger button's armed and disarmed states are a
  stylesheet fact, and the danger probe gains a second half.** The
  design's confirmation checkbox changes the button's colour the
  instant it is ticked, and the brief (§9.9) points out this is the one
  interactive nuance in the whole design that costs no JavaScript:

  ```css
  form:has(input[name="confirm"]:checked) button.danger {
    color: var(--dead-fg);
    border-color: var(--dead-line);
  }
  ```

  It lands here because it is a stylesheet rule over markup that already
  exists — spec 0024 FR-9 and spec 0026 FR-13 put the checkbox and the
  button in the same `<form>` on every page that has one — so no
  template changes. `_DANGER_PROBE`
  (`test_ca_issuer_pages.py:662`) keeps its existing half, which
  asserts every `button.danger` has an `input[name="confirm"]` in the
  same form, and gains a second: with the box unchecked the button's
  computed colour equals the disarmed value, and with it checked the
  armed one. Two states, one run, and the design's visual contract
  becomes checkable instead of a screenshot.

  The plan assigns this to no particular spec; it is here because the
  rule it depends on is here.

- FR-25: **`layout.html` is edited by a script through Bash, never with
  Edit/Write, and `git diff` is read after every change.** The
  PostToolUse formatter breaks Jinja tags apart — it has turned
  `{% if x == "y" %}` into `{% if x="" ="y" %}` — and this has cost the
  project a debugging session five times (0021 FR-13, 0023 FR-11, 0024
  FR-10, 0025 FR-15, 0026 FR-18). The same rule covers
  `docs/design/0027-brief.md`: 1333 lines of markdown containing
  fourteen tables, copied with `cp`, and the copy verified byte for
  byte against its source before anything else is done to it.

## Interface Contract

### Files

| File                                  | Change                                                 |
| ------------------------------------- | ------------------------------------------------------ |
| `src/cabin/web/static/cabin.css`      | rewritten                                              |
| `src/cabin/web/templates/layout.html` | `.shell` wrapper, `id="main"` — nothing else           |
| `src/cabin/web/static/fonts/`         | Inter in, Public Sans out, IBM Plex Mono unchanged     |
| `docs/design/0027-brief.md`           | new — the checked-in brief and its divergence register |
| `tests/probes.py`                     | new — the one definition of the overflow probe         |
| every other template                  | **byte-identical** (FR-18, AC-1)                       |

No route, no handler, no guard, no wording, no schema, no migration, no
audit action, no API, MCP or ACME change. No Python outside `tests/`
changes except the static-asset wiring for the retired font, if any is
needed.

### Tokens

This table is exhaustive for the tokens that exist today, in both
directions: every token in the current `:root` appears with its fate,
and every token in the brief's §10 appears with its source. Spec 0024's
Interface Contract once said of a context change that it "gains one
flag … no other key changes"; implementing that sentence faithfully
produced a defect that survived a green suite, and the correction is
recorded in that spec's own contract. A summary sentence is not a
contract, and neither is "the tokens are the brief's".

**Kept, value changes only:** `--bg` (#f2f3f4 → #161826), `--text`
(#191d21 → #e9e9ed), `--accent` (#8a5a09 → #9184d9), `--sans`, `--mono`.

**Split — one token becomes several, and the old name is gone:**

| Today           | Becomes                                                          |
| --------------- | ---------------------------------------------------------------- |
| `--panel`       | `--surface-low` #1b1d29, `--surface` #232532                     |
| `--panel-2`     | `--surface-hover` #1d1f2c                                        |
| `--line`        | `--line-panel` #2f3240                                           |
| `--line-strong` | `--line-control` #3f424d                                         |
| `--dim`         | `--text-2` #cfd3e5, `--text-3` #b2b6ca, `--text-muted` #9397ab   |
| `--faint`       | `--text-faint`, `--text-hint` (FR-11), `--text-disabled` #5a5d6b |
| `--radius`      | `--r-chip` 4px, `--r-control` 6px, `--r-panel` 8px               |
| `--rail`        | `--shell-nav` 230px                                              |
| `--ok`          | `--good-bg` #17291f, `--good-fg` #8fd3a8, `--good-line` #264734  |
| `--warn`        | `--warn-bg` #33291a, `--warn-fg` #e8c98e, `--warn-line` #4d3f24  |
| `--bad`         | `--bad-bg` #3a2029, `--bad-fg` #e8a9b4, `--bad-line` #55303c     |

**New, with no predecessor:** `--rule-section` rgba(233,233,237,.08),
`--rule-row` rgba(233,233,237,.07), `--accent-text` #b5abfc,
`--accent-bright` #d2cefd, `--accent-tint` #2b2741, `--accent-edge`
#423a6a, `--accent-deep` #5d5294, `--dead-bg` #3a1c1d, `--dead-fg`
#e9908e, `--dead-line` #5b2c2b, `--flat-bg` #282a33, `--flat-fg`
#b2b6ca, `--flat-line` #3f424d, `--note-warn-bg` #1e1c17,
`--note-bad-bg` #1e1a1d, `--note-info-bg` #1e2032,
`--danger-disarmed-fg` (FR-11), `--danger-disarmed-line` #3a2b30,
`--section-label` 250px, `--content-max` 1180px.

**Retired, with what replaces each:**

| Retired                | Replaced by                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------- |
| `--accent-bg`          | nothing — the design's primary button is an outline, not a fill                                               |
| `--accent-ink`         | nothing — no text is drawn on an accent fill except on `--accent-tint`, where `--accent-bright` is the colour |
| `--bad-bg` (as a fill) | re-used as the `bad` tag's background; the filled danger button is gone                                       |
| `--bad-ink`            | nothing — same reason as `--accent-ink`                                                                       |
| `--pad`                | the design's explicit paddings (FR-22 rows 4 and 5)                                                           |
| `--space-1..4`         | nothing — the brief's finding is that the spacing is ad hoc                                                   |

`--bad-bg` and `--bad-ink` are called out separately because the names
survive in one case and not the other: `--bad-bg` keeps its name and
gains an entirely different meaning (it was `#a52c22`, a fill for a red
button; it becomes `#3a2029`, the ground of a `bad` status tag). A
template or rule that kept using it for a button fill would compile and
would be wrong, which is why it is named here rather than left to the
diff.

### `cabin.css` — classes

Every class that exists today keeps its name and gains the design's
values. Nothing is added that has no user (FR-18), with the two
exceptions the widened agreement test forces:

- `.tile-label` — used by `dashboard.html:42`, no rule today.
- `.warning` — used by `acme.html:42`, no rule today.

`.shell` is added and is used by `layout.html`. Reserved but **not
defined** here, because their first user arrives later: `.panel`,
`.nav-count`, `.seg`, `.pill`, `.toggle`, `.group-row`, `.kicker`,
`.flash`.

### `tests/probes.py`

```python
OVERFLOW_PROBE: str
CONTRAST_PROBE: str
FOCUS_PROBE: str


def serve(root: Path) -> tuple[ThreadingHTTPServer, int]: ...


def dump_dom(url: str, width: int, height: int) -> str: ...


def overflow(url: str, width: int, height: int) -> dict[str, object]: ...
```

`overflow` returns `{"bad": list[str], "examined": int, "excused": int}`
(FR-4). The two existing callers —
`test_web_layout.py::test_no_horizontal_overflow` and
`test_ca_names_and_actions.py::test_no_horizontal_overflow` — import
from here and delete their local copies. Their page lists, fixtures and
parametrisation are unchanged.

## Acceptance Criteria

Every criterion is anchored to the thing it is about — a computed
style, a parsed rule, a probe's own counters — never to a substring
appearing somewhere in a file. Where a state is meant to differ, both
halves are in one criterion, so that a build rendering nothing and a
build rendering everything each fail.

The fixture, unless stated otherwise, is `_populate(..., second_issuer=True)`
and the 19 pages of `test_web_layout.py:722-743`.

- AC-1: **The boundary holds.** Every file under
  `src/cabin/web/templates/` except `layout.html` is byte-identical to
  its content at `c455922`, asserted by hashing the directory. In the
  same test, `layout.html` differs, and its diff against `c455922`
  contains no `{% if`, `{% for`, `{% block` or `{{` token that is not
  also in the original — the formatter's failure mode (FR-25) is a
  broken Jinja tag, and this is what catches it in the file this spec
  actually edits.
  _Goes red if_: a content template is "just slightly" adjusted to make
  a new rule look right — which would make the 1000-test claim
  meaningless, since it is that claim that says the chrome fits the
  content as it is.

- AC-2: **The overflow probe can still fail, and it examines the
  page.** On a rendered `/certs` with the shell in place, at 1440: the
  probe reports `bad == []` and `examined >= 40`. The same page with
  `<div style="width:4000px">x</div>` appended to `main` reports that
  div in `bad`. In the same test, the pre-repair walker — the
  `scrollable()` function as it stands at `c455922`, kept in the test
  as a literal string — is run over the same page and reports
  `examined <= 5`, so the defect this criterion exists for is
  demonstrated and not merely described.
  _Goes red if_: the repair is applied to the allow-list but the shell
  still excuses everything, or if the probe is "fixed" by widening it
  until nothing can trip it.

- AC-3: **No page scrolls sideways, at either width, in either
  scheme.** Spec 0015 AC-1/AC-2 re-run with the repaired probe over all
  19 pages at 1440×1150 and 390×900, in both the dark and the light
  stylesheet of FR-14: `bad == []` and `examined >= 40` for each of the
  76 runs.
  _Goes red if_: the shell's `overflow:hidden` hides a real overflow
  rather than removing it — which is the whole reason the probe had to
  be repaired first.

- AC-4: **The probe has one definition.** `tests/` contains exactly one
  occurrence of the string `function container(` across all files, and
  both `test_no_horizontal_overflow` tests import it from
  `tests/probes.py`.
  _Goes red if_: a copy is left behind, which is how the second copy
  came to exist in the first place.

- AC-5: **The horizontal-scroll set is exactly `{.scroller}`.** Parsing
  `cabin.css`, the set of selectors declaring `overflow-x: auto|scroll`
  or `overflow: auto|scroll` is exactly `{".scroller"}`; `main`
  declares `overflow-x: hidden` and `overflow-y: auto`; `pre.pem`
  declares neither and declares `white-space: pre-wrap`. In the same
  test the probe's allow-list selector is asserted equal to that set.
  _Goes red if_: a second element is given a horizontal scroll to make
  something fit, which is the change that would quietly re-excuse a
  whole subtree from AC-3.

- AC-6: **The palette equals the checked-in brief.** Parsing §10 of
  `docs/design/0027-brief.md` and its header's palette register: every
  token the brief names appears in `:root` with the register's value
  where there is one and the brief's value where there is not; and
  every colour-valued token in `:root` is named by one of the two. In
  the same test the palette register has exactly three rows, each
  naming a token, both values and a non-empty reason.
  _Goes red if_: a colour is nudged in the stylesheet without the file
  being told, or the register is used to launder an undocumented
  change.

- AC-7: **The three lifted colours reach 4.5:1 and the unlifted ones
  are exempt for a checkable reason.** Computed with the WCAG 2.x
  formula in the test itself: `--text-faint` ≥ 4.5:1 against `--bg`,
  `--surface-low`, `--surface-hover` and `--surface`; `--text-hint`
  ≥ 4.5:1 against the first three; `--danger-disarmed-fg` ≥ 4.5:1
  against `--surface`. In the same test, each shipped value differs
  from the brief's, and `--text-disabled` appears in `cabin.css` only
  in rules whose selector matches `:disabled`, `[disabled]` or
  `[aria-disabled="true"]`.
  _Goes red if_: a value is lifted to 4.5:1 against the page ground
  only and then used on a panel — the second and third grounds are the
  ones that catch it.

- AC-8: **The light palette is derived, not inverted.** In both
  schemes: `luminance(--surface-low) < luminance(--bg) <
luminance(--surface)`; the six body-text tokens are strictly ordered by
  contrast against `--bg`; and each light text token's ratio against
  its light ground is ≥ its dark counterpart's against the dark one. In
  the same test `--accent` ≥ 3:1 and `--accent-text` ≥ 4.5:1 against
  `--bg`, `--surface-low` and `--surface` in both schemes, and the
  light `--accent` is not `#9184d9`.
  _Goes red if_: the light block is produced by inverting the dark one —
  the ground order flips, and the first assertion says so in one line —
  or if the accent is mirrored rather than re-solved, which the last
  clause names directly.

- AC-9: **Both schemes are complete, in both directions, with no
  repeats.** FR-13's rewritten test: every colour-valued token in the
  default `:root` — including `rgba()` ones — has an override, every
  override has a default, and no override's value equals its default
  after normalisation. In the same test the light block is asserted to
  be exactly one `@media (prefers-color-scheme: light)` containing
  exactly one `:root` rule containing only `--` declarations, which is
  what FR-14's scheme-forcing depends on. And, as a counter-check, a
  copy of the stylesheet in which one override is replaced by its
  default is asserted to make the test fail.
  _Goes red if_: a token is added to `:root` and forgotten in the light
  block, or a light value is filled in by copying the dark one — which
  the old test would have passed.

- AC-10: **Contrast holds on the rendered page, in both schemes.**
  FR-14's probe over all 19 pages in both schemes: every text-bearing,
  non-disabled element reaches its threshold, and `examined >= 30` per
  page.
  _Goes red if_: a token that is fine against the ground it was solved
  for is used against a different one — the case FR-11 names for
  `--text-hint`, and the only case a token-table check cannot see.

- AC-11: **Focus is visible on every interactive element.** On each of
  the 19 pages, every element matching
  `a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])`
  is focused in turn; its computed `outline-style` is not `none`, its
  `outline-width` is ≥ 2px, and its `outline-color` differs from its own
  computed background. The count of elements focused is reported and
  asserted ≥ 5 per page. In the same test, `cabin.css` contains no
  `outline: none` and no `outline: 0`.
  _Goes red if_: the design's field-only focus rule is copied across
  unchanged, which leaves every link, button and checkbox in cabin
  without one — the gap the prototype could not have noticed, because
  nothing in it was focusable.

- AC-12: **The shell does not scroll, and `main` does.** At 1440×900 on
  a certificate detail page: `document.scrollingElement.scrollHeight <=
clientHeight + 1`, `document.querySelector('.shell').scrollHeight <=
clientHeight + 1`, and `#main.scrollHeight > #main.clientHeight`.
  _Goes red if_: the shell's height or overflow is wrong and the whole
  window scrolls again, taking the rail with it — the third clause is
  what stops a build where nothing scrolls at all from passing.

- AC-13: **The rail is still the way off a long page.** Both rewritten
  probes (FR-23): scrolled to the end of `#main` at 1440×700, the
  logout button's rect is inside the viewport, `main.scrollTop > 400`,
  and `nav.scrollHeight > nav.clientHeight`.
  _Goes red if_: the footer is pushed out of the 100vh column and
  clipped, which is the new way to lose the logout button and is not
  the old way.

- AC-14: **Per-intermediate growth is still bounded.** Spec 0026 AC-13
  re-run with `_HEIGHT_PROBE` reading `#main`'s `scrollHeight`:
  `(h4 - h1) / 3 < 80`, `h4 > h1`, and four `/issuer/` links on the
  four-intermediate page.
  _Goes red if_: the probe is left pointing at `document.body`, where
  `h4 == h1 == viewport height` and the bound passes vacuously — the
  `h4 > h1` clause is what catches that.

- AC-15: **The stylesheet and the templates agree, over every page, in
  both directions.** FR-20's widened test: no class used on any of the
  19 pages lacks a rule, no rule lacks a user, the exemption list
  contains only `tag-*` names each of which is produced by a
  `tag-{{ … }}` interpolation in a template, and `.tile-label` and
  `.warning` both have rules.
  _Goes red if_: a rule is written for a component 0028 will render but
  0027 does not — FR-18's decision — or if the exemption list is used
  to park an ordinary unused class.

- AC-16: **The load-bearing names survive.** Each of `rail`,
  `rail-foot`, `nav-group`, `shell`, `section`, `scroller`, `tag`,
  `note`, `constraints`, `error`, `card-narrow` has a rule in
  `cabin.css` and appears in at least one template. `card` (other than
  `card-narrow`) and `badge*` appear in no template and in no rule.
  _Goes red if_: `.section` is renamed to something the design's
  vocabulary suggests, which would leave 20 assertions scoping by a
  selector nothing emits — they would not fail, they would find
  nothing, which is worse.

- AC-17: **No colour outside the token blocks, and no `color-mix`.**
  Every `#`-literal and `rgba(` in `cabin.css` falls inside one of the
  two `:root` blocks; `color-mix` appears zero times.
  _Goes red if_: one rule keeps a hard-coded hex "just for now", which
  is how the prototype ended up with 90 computed style strings and no
  design system.

- AC-18: **The twelve numbers.** FR-22's table asserted as computed
  styles on a rendered `/ca/{root}` at 1440, each with its own
  assertion so a failure names the number.
  _Goes red if_: the design's geometry is approximated — the section
  label column at 16rem instead of 250px, the content column at 72rem
  instead of 1180px — which no screenshot review reliably catches.

- AC-19: **Type is in rem and honours a raised root.** At a 16px root,
  `h1` computes to 29px and `h2` to 17px; with the document's root
  font-size set to 20px by the probe, both scale by 1.25 (±1px).
  `body`'s computed `line-height` is 1.5× its font-size.
  _Goes red if_: the scale is written in px, which reproduces the
  design exactly for everyone except the operator who needed the
  setting.

- AC-20: **The fonts are vendored, licensed and local.**
  `/static/fonts/Inter.woff2` and `/static/fonts/IBMPlexMono.woff2`
  return 200 with `font/woff2` and begin `wOF2`;
  `LICENSE-Inter.txt` and `LICENSE-IBMPlexMono.txt` exist and are
  non-empty; `cabin.css` references exactly those font files and no
  `url(http…)`; `PublicSans.woff2` and `LICENSE-PublicSans.txt` are
  gone and no file references them. In the same test the `--mono` stack
  begins with `"IBM Plex Mono"` and contains `ui-monospace`.
  _Goes red if_: Inter is added and Public Sans is left behind — 27 KB
  of dead weight and two stacks that disagree about what the body font
  is — or if the mono stack is replaced by the design's system stack,
  which is the divergence FR-17 argues against.

- AC-21: **The danger button changes colour when the box is ticked.**
  FR-24's probe on a page carrying a retire form: with the checkbox
  unchecked the button's computed `color` equals
  `--danger-disarmed-fg`; with it checked, `--dead-fg`. Both in one
  run, preceded by the `_count_danger_buttons(html) >= 1` sanity
  assertion the probe already carries.
  _Goes red if_: the `:has()` rule is written against the wrong
  selector and the button never arms, or is written so loosely that it
  arms without the box — the two halves fail in opposite directions.

- AC-22: **Everything that was not this spec's subject still works.**
  The 0003–0026 suite passes: every route, guard, CSRF rule, form
  field, redirect and audit event is unchanged; every page still
  renders 200; the API, MCP, ACME, the CRL and cabin's own TLS are
  untouched; and no assertion about page **wording** changes anywhere,
  because wording is out of scope for the whole redesign (Out of
  Scope). The only test changes are the ones the Test list names.

## Test list

**New**, in `tests/test_web_design_shell.py` unless noted:

test_the_overflow_probe_reports_what_it_examined,
test_the_overflow_probe_catches_a_planted_overflow (AC-2),
test_the_pre_repair_walker_excused_the_whole_page (AC-2),
test_the_probe_has_one_definition (AC-4),
test_only_the_scroller_scrolls_sideways (AC-5),
test_the_palette_equals_the_checked_in_brief (AC-6),
test_the_lifted_colours_reach_the_floor (AC-7),
test_the_light_palette_is_derived_not_inverted (AC-8),
test_contrast_holds_on_every_rendered_page (AC-10, headless Chrome),
test_focus_is_visible_on_every_interactive_element (AC-11, Chrome),
test_the_shell_does_not_scroll (AC-12, Chrome),
test_the_twelve_numbers (AC-18, Chrome),
test_type_scales_with_the_root_font_size (AC-19, Chrome),
test_the_danger_button_arms_with_its_checkbox (AC-21, Chrome),
test_only_layout_html_changed (AC-1),
test_the_load_bearing_class_names_survive (AC-16),
test_no_colour_outside_the_token_blocks (AC-17)

**Re-pointed** — the requirement is unchanged, the selector or the
mechanism moved. Each is named with what it was protecting:

- **`test_web_layout.py:127`
  `test_css_defines_dark_counterpart_for_every_token`** protects spec
  0015 FR-8: a token defined in one scheme only is unreadable in the
  other. Re-pointed because FR-8 inverts which block is the default —
  and strengthened; see below.
- **`test_web_layout.py:142` `test_fonts_are_vendored_with_their_licences`**
  protects spec 0015 FR-7's real requirement: the faces are in the
  repository with their licences, not fetched. Two filenames change
  (FR-17); the assertion shape does not.
- **`test_web_layout.py:517` `test_fonts_served_with_woff2_content_type`**
  protects that cabin serves them itself with the right type. Same two
  filenames.
- **`test_web_layout.py:654` `test_rail_stays_in_view_on_a_long_page`**
  and **`test_transfer.py:452`
  `test_rail_stays_in_view_with_sixteen_entries`** protect spec 0015
  FR-1's actual requirement — the rail is the only way off a page and
  may not scroll away with the logout button — and, in their second
  half, protect that the criterion cannot pass on a viewport the rail
  merely fit into. The window no longer scrolls, so the scroll target
  becomes `#main`; the second half is kept **verbatim** (FR-23).
- **`test_ca_issuer_pages.py:682` `_HEIGHT_PROBE`**, used by
  `test_per_intermediate_growth_stays_bounded`, protects spec 0026
  FR-15: an intermediate costs a table row, not a section. Re-pointed
  from `document.body` to `#main`, without which it would measure the
  viewport height twice and pass on any build (AC-14).
- **`test_web_layout.py:696` and `test_ca_names_and_actions.py:1531`
  `test_no_horizontal_overflow`** protect spec 0015 AC-1/AC-2. Both
  import the repaired probe from `tests/probes.py`; their page lists
  and fixtures are unchanged. Both gain AC-3's second scheme.
- **`test_web_layout.py:49` `test_layout_has_rail_and_main`** protects
  that the two chrome elements exist and that the rail is conditional
  on a user. Gains one assertion for `.shell` and one for `id="main"`;
  the three it has are unchanged.

**Strengthened** — the requirement grows. Each is named with what it
was protecting and what it could not catch:

- **`test_css_defines_dark_counterpart_for_every_token`** — see
  FR-13. It was protecting completeness across the two schemes, and it
  could not catch three things: a token whose value is `rgba()` rather
  than a hex (it filtered on `startswith("#")`, so the two dividers the
  design leans on everywhere were never in the set), an override with
  no default, and an override that repeats its default — the last being
  precisely the defect it was written to prevent, since copying a value
  across satisfies "a counterpart exists" and leaves the other scheme
  unreadable. A counter-check is added so the third clause is proven to
  bite (AC-9).
- **`test_ca_names_and_actions.py:1265`
  `test_stylesheet_and_templates_agree_in_both_directions`** protects
  spec 0024 AC-12: no class without a rule, no rule without a class, no
  `<details>` anywhere. It was looking at 7 of 19 pages and its reverse
  direction was three string checks. Widened to all 19 and to a real
  `defined - used` assertion (FR-20, AC-15). It is what finds
  `.tile-label` and `.warning`.
- **`test_ca_issuer_pages.py:662` `_DANGER_PROBE`**, used by
  `test_section_and_danger_probes_cover_all_three_pages`, protects spec
  0024 AC-11: the confirmation treatment repeats over every dangerous
  button. It gains the armed/disarmed colour assertion (FR-24, AC-21),
  which is the half that says the treatment is visible and not merely
  present in the DOM.
- **`test_ca_issuer_pages.py:641` `_SECTION_PROBE`** protects that
  every `.section` has a non-empty first child — the empty left column
  spec 0024 FR-8 removed. Its page list is extended from three pages to
  every page that has a `.section`, now that `.section`'s geometry
  changes under it.

**Deleted: none.** The one candidate is the Public Sans half of the two
font tests, and it is not a requirement. Spec 0015 FR-7's requirement is
"vendored under `static/fonts/`, SIL OFL, licence alongside, nothing
from a CDN"; the filename was the old look. It is edited, and AC-20
additionally asserts the retired file and its licence are gone and
unreferenced, which is a requirement the old test did not carry at all.

## Out of Scope

**No content template's markup** (FR-18). Not one table, not one form,
not one heading. The design's tables, grouped lists, preview panels,
segmented controls, filter pills, toggles and flash message arrive in
specs 0028, 0029 and 0030, with the classes they need. A stylesheet
rule written here for a component nothing renders would fail AC-15's
reverse direction, and rightly.

**No wording.** Every sentence on every page is left exactly as it is,
which is what keeps several hundred text assertions from being touched.
The rail's fourth group label (`Transfer` → `Export`, the rail in the
design being the newer artefact) is a named exception for the whole
redesign and is **not** taken here, because it would edit
`layout.html`'s nav and `test_nav_current_marked_once_per_page`'s
expectations in the same spec that is trying to prove the chrome
changed and nothing else did.

**No new route, guard, handler, column or migration.** Nothing under
`src/cabin/` changes except `static/`, `templates/layout.html` and the
static-asset wiring for the retired font.

**No version bump.** This stays 0.2.0 and PR #17 stays open. The change
is UI-visible and gets its entry under `[Unreleased]` in
`CHANGELOG.md`, which is the project's workflow rather than a
requirement of this spec.

**No htmx.** It has been vendored and loaded since the beginning and
still has no user. Spec 0029 gives it one, under the rule that every
htmx target is a URL that also works as a page.

**No icon set.** The prototype uses none; its only glyphs are the text
characters `←` `→` `↑` `↓` `✓` `✕` `├` `└` `·`. No icon font, no SVG
sprite, no dependency.

**Non-text contrast beyond the focus ring.** WCAG 1.4.11 also covers
the visual boundary of a control, and several of the design's hairlines
— the disarmed danger border `#3a2b30`, the control border `#3f424d`
against `--surface` — do not reach 3:1. Raising them all would be a
redesign of the design rather than a lift of three values, and the
borders are never the only indicator: every control carries a label and
the focus ring is solved separately (FR-15). Recorded here so that
"contrast is asserted" is not read as a claim it does not make.

**The tree glyph.** `#5d5294` on `--bg` is 2.60:1, and the design uses
it for the `├`/`└` characters in the grouped list. Nothing renders a
grouped list in 0027. It is 0028's to settle, and the honest answer
there is likely that the glyph is decoration — the indentation and the
Kind column carry the information — rather than that the colour needs
lifting.

**No screenshot review here.** The 76 images (19 screens × two
viewports × two schemes) are taken once the pages have moved, because
19 screens wearing new chrome around old content are not what anyone is
reviewing for.
