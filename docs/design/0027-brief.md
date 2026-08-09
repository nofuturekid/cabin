<!--
  This file is copied verbatim from the planning-session brief and is read by
  a test. Do not reformat it. See the provenance note below.
-->

> **Provenance.** Copied verbatim on 2026-08-09 from the planning-session path
> `…/scratchpad/design-brief.md`, where it was written while specs 0027–0030
> were being planned, by reading the Claude Design prototype ("CAbin UI
> redesign", project `2757eb29-b592-424c-a393-8dce3f0fe9d6`) and its
> design-system files. Everything below this header is byte-identical to that
> source, including §0's own "Note on location" paragraph, which is stale on
> arrival — it was written while the document lived in a scratch directory.
> It is left standing because the body being verbatim is worth more than the
> paragraph being tidy.
>
> **What this file is for.** It is the checked-in source of truth for the
> palette. Spec 0027 FR-10 / AC-6 parses the token block in §10 together with
> the palette register below, and asserts that `cabin.css`'s `:root` matches
> it exactly, in both directions. "It matches the design" is therefore a
> comparison a test makes rather than an opinion someone holds.
>
> **How to depart from the design.** A deliberate divergence is made by
> editing *this file* — a row in the register below, or an edit to the body —
> with the reason written beside the value, in the same change as the
> stylesheet. A stylesheet that disagrees with this file fails; a value
> changed here with no reason beside it fails; and a colour nudged in
> `cabin.css` alone cannot pass. A later change of mind then shows up as a
> diff someone can read, next to the argument for it.

### Divergence register — palette

Read by the test. Each row overrides the value §10 gives for that token.

| Token                  | Brief     | Shipped   | Reason                                                                                                                                                                                                 |
| ---------------------- | --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--text-faint`         | `#75798c` | `#888b9c` | 4.08:1 on `--bg` fails WCAG 1.4.3's 4.5:1, and this token is body text at 10–12px (section descriptions, column headings, timestamps, panel kickers). Lifted until it clears 4.5:1 on all four grounds it is drawn on, `--surface` included. Spec 0027 FR-11. |
| `--text-hint`          | `#63677a` | `#818699` | 3.15:1 on `--bg`. Same reason. Lifted until it clears 4.5:1 on `--bg`, `--surface-low` and `--surface-hover`; it is not drawn on `--surface` in this design. Spec 0027 FR-11.                          |
| `--danger-disarmed-fg` | `#6d5259` | `#a3848c` | 2.17:1 on `--surface`. cabin's retire and revoke buttons are live `<button>` elements whose confirmation is checked on the server, so they are not HTML-disabled and WCAG's incidental exemption does not reach them. Lifted to 4.5:1; it still reads as disarmed against the armed `#e9908e` because it is desaturated rather than merely dimmer. Spec 0027 FR-11. |

### Divergence register — everything else

Not read by the test; recorded here so that the file is the whole account.

- **`<main>` is `overflow-y: auto; overflow-x: hidden`**, not §4's
  `overflow: auto` (spec 0027 FR-5). A `<main>` that scrolls horizontally is a
  page that scrolls sideways with extra steps, which is the defect spec 0015
  exists for.
- **`<pre>` blocks do not scroll horizontally.** §6.9's own
  `white-space: pre-wrap; word-break: break-all` makes the `overflow-x: auto`
  cabin has today unnecessary, and removing it leaves `.scroller` as the only
  element permitted to scroll sideways (spec 0015 FR-4, spec 0027 FR-5).
- **The mono stack keeps IBM Plex Mono in front of §2's system stack**
  (spec 0027 FR-17). cabin's monospace carries fingerprints, serials, PEM
  bodies and CRL/AIA URLs — strings an operator compares character by
  character — and a bare system stack renders them at different advance widths
  on every platform. The prototype never linked a mono face at all, so its
  stack is the absence of a decision rather than a decision.
- **The 9.5px type step is dropped**, with the element that used it: §8's
  "Prototype only — view as" control.
- **Type sizes are declared in `rem` against a 16px root**, so they are
  pixel-identical to §2 at default settings and still honour a raised base
  font size (spec 0027 FR-16). The prototype had no user whose settings could
  be honoured.

### Additions the design does not contain

- **A light scheme.** The prototype is dark-only. Spec 0027 FR-12 derives one
  and states the three rules it is derived under.
- **A focus state for links, buttons, rows and controls.** §7 records the gap
  itself: everything clickable in the prototype is an unfocusable `<div>`, so
  no focus state was ever drawn. Spec 0027 FR-15 adds one.
- **`prefers-reduced-motion`** around both keyframes, which §7 asks for and
  the prototype does not do.

---

# cabin UI redesign — design brief

Source: Claude Design project `2757eb29-b592-424c-a393-8dce3f0fe9d6` ("CAbin UI redesign").
Files read: `Cabin Prototype.dc.html` (189 881 chars), `_ds/nocturne-…/styles.css`,
`_ds/nocturne-…/_ds_bundle.js`, `support.js`, `_ds/nocturne-…/readme.md`,
`_ds/nocturne-…/_ds_manifest.json`, `github.md`.

> **Note on location.** This document was requested at
> `…/scratchpad/design-brief.md`. Plan mode was active for the whole session and
> permits writing only this plan file, so the brief lives here. Copy it to the
> scratchpad path verbatim when writes are allowed again.

---

## 0. The single most important finding

**The prototype does not use the Nocturne design system.**

- `class=` appears **zero** times in the prototype markup.
- `var(--…)` appears **zero** times.
- Every style is an inline `style="…"` attribute with **hard-coded hex values**.
- `_ds_bundle.js` is an empty stub — it creates `window.Nocturne_noctur = {}` and
  nothing else. No components, no behaviour.
- `styles.css` is linked, but none of its classes (`.btn`, `.card`, `.table`,
  `.tag`, `.input`, `.seg`, `.dialog`, `.hr`, `.lighten`) is ever used, and its
  `body` defaults (15px/1.55, h1 42px …) are overridden by the prototype's own
  `<style>` block immediately after.

So Nocturne is **ancestry, not the spec**. The prototype's palette overlaps it
(bg, surface, text, the accent ramp) but adds a whole status-colour system, a
second panel tone and a 6px radius that Nocturne does not have, and it uses a
much smaller type scale. **Implement from the prototype. Do not link
`styles.css`.** Nocturne is cited below only where it explains where a value came
from.

---

## 1. Palette

Every colour with its role. Values marked **(N)** are Nocturne tokens; the rest
are prototype-only. Frequency counts are occurrences in the prototype source.

### Grounds

| Hex       | Freq | Nocturne                  | Role                                                                                                                                                                                                                           |
| --------- | ---- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `#161826` | 16   | **(N)** `--color-bg`      | Page background. Also the ground for controls nested _inside_ a raised panel (inline row-edit inputs, the token `<code>` block, the add-intermediate form's fields).                                                           |
| `#1b1d29` | 39   | —                         | **Recessed surface.** Sidebar background; every `input` / `select` / `textarea` background on a page-level form; `<pre>` PEM blocks; inline form panels (add user, add intermediate, create token). Reads as _below_ the page. |
| `#232532` | 18   | **(N)** `--color-surface` | **Raised panel.** Cards, stat tiles, preview/aside panels, the danger panels, the toast, the ACME directory rows.                                                                                                              |
| `#1d1f2c` | 10   | —                         | **Row hover tint**, and the fill of the grouped-table _root_ row (hierarchy list, CA-key list) and of a user row while it is being edited.                                                                                     |
| `#1e2032` | 3    | —                         | Accent-note background (the "path_length ≥ 2" note, the EAB-on note, the one-time-token banner). _Unclear whether this is intended as a token or three one-offs — it is consistent, so treat it as a token._                   |
| `#1e1c17` | 9    | —                         | **Warning-note ground** (amber family).                                                                                                                                                                                        |
| `#1e1a1d` | 9    | —                         | **Error/danger-note ground** (red family). Also the hover fill of the "Export CA key" danger button.                                                                                                                           |

### Borders and rules

| Hex / value             | Freq | Nocturne              | Role                                                                                                                                                                                                                                   |
| ----------------------- | ---- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `#2f3240`               | 29   | —                     | **Panel hairline.** `1px solid` on every `#232532` card, on `<pre>` blocks, on the sidebar's right edge and its footer divider, on the grouped-table box. Sits between Nocturne's `neutral-900` (#292b31) and `neutral-800` (#3f424d). |
| `#3f424d`               | 76   | **(N)** `neutral-800` | **Control border.** Inputs, selects, textareas, secondary/tertiary buttons, segmented-control frames and their internal separators, small chips, the two `1px dashed` boxes. Also the _disabled_ pager arrow colour.                   |
| `rgba(233,233,237,.08)` | —    | —                     | **Section rule** — the `border-top` between page sections. (= `#e9e9ed` at 8 %.)                                                                                                                                                       |
| `rgba(233,233,237,.07)` | —    | —                     | **Row rule** — the `border-top` between list rows and between detail-grid rows. (= `#e9e9ed` at 7 %.)                                                                                                                                  |
| `#423a6a`               | 10   | **(N)** `accent-800`  | Border of anything filled with the accent tint `#2b2741`: avatars, the "root" kind tag, the toast, the one-time-token banner, accent notes.                                                                                            |
| `#4d3f24`               | 11   | —                     | Warning border (amber).                                                                                                                                                                                                                |
| `#55303c`               | 11   | —                     | Error border (pink-red) — used with `#e8a9b4` text.                                                                                                                                                                                    |
| `#5b2c2b`               | 8    | —                     | Danger border (deeper red) — used with `#e9908e` text and on the retire/expired family.                                                                                                                                                |
| `#5d5294`               | 24   | **(N)** `accent-700`  | **Hover border** for secondary controls and stat tiles; the toggle track when _on_; the mono tree-glyph colour (`├` `└`); the border of inline row-edit inputs.                                                                        |

### Text

| Hex       | Freq    | Nocturne                 | Role                                                                                                                                                                                                                               |
| --------- | ------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `#e9e9ed` | 69      | **(N)** `--color-text`   | Primary text. Headings, values in key/value panels, the selected segment label, the active nav item, input text, the toggle knob.                                                                                                  |
| `#cfd3e5` | 19      | **(N)** `neutral-300`    | Secondary-button labels, checkbox labels, the dashed name-constraints readout, the ACME "Copy" button.                                                                                                                             |
| `#b2b6ca` | 19      | **(N)** `neutral-400`    | Data values in list rows — dates, actor names, monospace fields that are not links. Sidebar user name.                                                                                                                             |
| `#9397ab` | **115** | **(N)** `neutral-500`    | **The workhorse muted tone.** Page lead paragraphs, every form label, non-link table cells, PEM body text, idle nav items, tertiary buttons, "Cancel".                                                                             |
| `#75798c` | 81      | **(N)** `neutral-600`    | Fainter still: section descriptions under an `h2`, list column headings, timestamps, card kickers, the version string.                                                                                                             |
| `#63677a` | 13      | —                        | Faintest hint text: the help line under a field, footnote paragraphs, nav **group headings**.                                                                                                                                      |
| `#b5abfc` | 33      | **(N)** `accent-400`     | **Link colour.** Common names in tables, inline text links, primary-button labels, enabled pager arrows, "Download this hierarchy".                                                                                                |
| `#d2cefd` | 24      | **(N)** `accent-300`     | Link **hover**; accent text on a tinted ground (avatar initials, the `action` column in the audit log, the `root` tag, the accent note body, `CABIN_TLS true`).                                                                    |
| `#9184d9` | 29      | **(N)** `--color-accent` | The accent as a **line**: the focus ring, the primary-button border, the active-nav inset bar, the selected-segment underline, the toast dot, the ✓ mark in the constraint checker, the selected filter pill border. Never a fill. |
| `#5a5d6b` | 3       | —                        | Disabled label ("Private key (PEM)" when no key; the "Prototype only" kicker; unparsed preview values).                                                                                                                            |
| `#6b6f80` | 3       | —                        | Disabled/busy primary-button label ("Issuing…", "Generating keys…").                                                                                                                                                               |
| `#6d5259` | 4       | —                        | **Disarmed danger-button label** — a desaturated red that says "not yet armed".                                                                                                                                                    |
| `#3a2b30` | 4       | —                        | Disarmed danger-button border, paired with `#6d5259`.                                                                                                                                                                              |

### Accent fills

| Hex       | Freq | Nocturne              | Role                                                                                                                                                     |
| --------- | ---- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `#2b2741` | 27   | **(N)** `accent-900`  | The **only** accent fill: active nav item, primary-button hover, selected segment, selected filter pill, avatar circle, `root` tag, `TAG.ok` background. |
| `#292b31` | 1    | **(N)** `neutral-900` | Sidebar role chip background. Used once.                                                                                                                 |
| `#282a33` | 4    | —                     | `TAG.neutral` background and the audit "door" chip. One step off `#292b31`; _unclear why both exist — collapse to one in the implementation._            |

### Status system (prototype-only, six variants)

Defined once in JS as `TAG`. All share
`font-size:10.5px;padding:2px 7px;border-radius:4px;white-space:nowrap`.

| Name      | Background | Text      | Border    | Used for                                                                                                                                    |
| --------- | ---------- | --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `ok`      | `#2b2741`  | `#d2cefd` | `#423a6a` | ACME/MCP "enabled", ACME order "valid", the `superadmin` role tag. Accent-toned, means _on/known-good-service_.                             |
| `good`    | `#17291f`  | `#8fd3a8` | `#264734` | Certificate status **valid**; CA status **active**; a cross certificate that is **serving**. The only green.                                |
| `warn`    | `#33291a`  | `#e8c98e` | `#4d3f24` | **expiring**; a CA within a year of expiry; "not served — outside its validity window"; ACME order **pending**; the nav expiry-count badge. |
| `bad`     | `#3a2029`  | `#e8a9b4` | `#55303c` | ≤ 7 days left; a **stale** CRL; ACME order **invalid**.                                                                                     |
| `expired` | `#3a1c1d`  | `#e9908e` | `#5b2c2b` | **expired** and **revoked**. Deeper and redder than `bad`.                                                                                  |
| `neutral` | `#282a33`  | `#b2b6ca` | `#3f424d` | **retired**; the `intermediate` kind tag; role chips; a service that is **off**.                                                            |

Two more status colours appear exactly once each, as the **2px left edge bar** on
hierarchy-list rows: `#3f7d55` (active), `#8c3f3d` (expired), `#3f424d`
(retired). They are darker/duller than the `good`/`expired` tag colours and are
meant to be read peripherally, not as labels.

### Free-standing semantic text colours

`#e8c98e` (16×) warning, `#e9908e` (13×) danger, `#e8a9b4` (12×) error,
`#8fd3a8` (4×) success/"Save". These appear as bare `color:` on paragraphs and
inline actions, independent of the tag chips.

---

## 2. Typography

### Families

```
sans:  Inter, system-ui, sans-serif
mono:  ui-monospace, SFMono-Regular, Menlo, monospace
```

Set once on `body`; the mono stack is applied **inline, per element** — there is
no `code`/`pre` element rule. Give it a class (`.mono`) instead of repeating it.

The monospace stack is used for: serials, fingerprints, dates (`2026-08-27`),
timestamps, URLs (CRL/AIA/ACME/base), PEM blocks, the audit `action` column, EAB
key ids, environment-variable names and values, SAN textareas, the version
string, tree glyphs `├` `└`, and login handles (`@mreid`).

### Sizes and weights

| px   | Weight                | Letter-spacing   | Where                                                                                                        |
| ---- | --------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------ |
| 30   | 500                   | −.02em           | Dashboard stat-tile numbers                                                                                  |
| 29   | 500 (heading default) | —                | **Page title** `h1`, every screen. `margin:0 0 4px` (or `0` when a status tag sits beside it)                |
| 17   | 500                   | —                | **Section heading** `h2` in the left rail of a section row. `margin:0 0 5px`                                 |
| 17   | 600                   | −.02em           | Sidebar brand word "cabin"                                                                                   |
| 13   | 400                   | —                | Page **lead** paragraph; toggle labels; nav items; large-form inputs                                         |
| 13   | 500                   | —                | Large button label (issue/sign/create)                                                                       |
| 12.5 | 400                   | —                | **List-row body text**; detail values; small-form inputs; the toast; checkbox labels                         |
| 12.5 | 500                   | —                | Small button label                                                                                           |
| 12   | 400                   | —                | Form labels; section descriptions; help paragraphs; audit rows; key/value panel bodies; small inline actions |
| 11.5 | 400                   | —                | Field hint lines; PEM body; footnotes; URL lines                                                             |
| 11   | 400                   | —                | The tightest hints, `figcaption`-grade text, the login handle                                                |
| 10.5 | 400                   | .07em, uppercase | **List column headings**                                                                                     |
| 10.5 | 400                   | .02em            | Status tags                                                                                                  |
| 10   | 600                   | .1em, uppercase  | Sidebar **group headings**                                                                                   |
| 10   | 400                   | .1em, uppercase  | Panel **kickers** ("Name constraints — checked before signing", "Result", "Parsed")                          |
| 10   | 400                   | .08em, uppercase | The `root` kind tag                                                                                          |
| 9.5  | 400                   | .09em, uppercase | "Prototype only — view as" (drop)                                                                            |

Weights in use: **400** (default), **500** (buttons, headings, tile numbers,
emphasis in a row), **600** (brand, avatar initials, grouped-table root row name,
nav group headings). Nothing heavier. Nocturne's rule "do not bolden headings
past 500" is respected except by the three 600 cases above.

### Line-height

`1.55` inherited from Nocturne is never actually applied (the prototype's own
`body` rule omits it, so the browser default ≈1.2 governs). Explicit values:
`1.6` on multi-line detail text and PEM blocks, `1.5` on SAN summaries, `1.7` on
the long warning note, `1.9` on the published-URL block, `1.3` on the stacked
name/handle in a user row, `1.2` on nothing (Nocturne's heading value is unused).

**Set `line-height:1.5` on `body` explicitly.** The prototype relies on browser
default, which is not reproducible across engines.

---

## 3. Spacing, radii, borders

### Spacing — not a scale

The values used are ad hoc, roughly a 1–2px-step ramp:
`1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 18, 20, 22, 24, 26, 28, 34, 36, 40, 60`.

Nocturne's `--space-*` (2.8 / 5.6 / 8.4 / 11.2 / 16.8 / 22.4 px) is **not used at
all**. Do not adopt it.

What _is_ consistent, and is the real structural rhythm:

| Value            | Meaning                                                      |
| ---------------- | ------------------------------------------------------------ |
| `230px`          | Sidebar width                                                |
| `250px`          | Section-row label column                                     |
| `28px`           | Section-row column gap                                       |
| `22px 0`         | Section-row vertical padding                                 |
| `26px 34px 60px` | `<main>` padding                                             |
| `1180px`         | Content max-width                                            |
| `12px`           | Grid gap inside a list row; horizontal padding of a list row |
| `9–11px`         | Vertical padding of a list row                               |
| `14px 16px`      | Card / panel padding                                         |
| `16px 18px`      | Inline-form-panel and revoke-panel padding                   |
| `10px`           | Gap in a horizontal button row                               |
| `14px`           | Gap in a vertical stack of aside panels                      |
| `6px`            | Gap between a label and its input                            |
| `16px`           | Gap between fields in a form column                          |

### Radii

| Value  | Where                                                                                                                             |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `4px`  | Status tags, role chips, the audit door chip                                                                                      |
| `5px`  | The prototype-only role `<select>` (drop)                                                                                         |
| `6px`  | **The default.** Buttons, inputs, selects, textareas, nav items, segmented-control frames, filter pills, the token `<code>` block |
| `8px`  | Cards, panels, notes, the toast, `<pre>` blocks, grouped-table boxes (`8px 8px 0 0` on the head, `0 0 8px 8px` on the tail)       |
| `9px`  | The nav count badge (pill)                                                                                                        |
| `11px` | The toggle track (pill, = height/2 + 0.5)                                                                                         |
| `50%`  | Avatars, the toast dot, radio-style dots                                                                                          |

Nocturne's `--radius-md: 8px` matches the panel radius; its `sm: 4px` matches the
tags; **the dominant 6px is not a Nocturne value.** Ship a three-step scale:
`--r-chip: 4px; --r-control: 6px; --r-panel: 8px` plus the two pill cases.

### Borders

- `1px solid` everywhere. Colour chosen from §1: `#2f3240` on panels, `#3f424d`
  on controls, the semantic colours on notes.
- `1px dashed #3f424d` in exactly two places: the sidebar role box (drop) and the
  name-constraints readout on the issuer detail page.
- `2px solid` left edge: hierarchy-list rows (status bar) and the user row being
  edited (`#9184d9`).
- `box-shadow: inset 2px 0 0 #9184d9` — the active nav item's left bar.
- `box-shadow: inset 0 -2px 0 #9184d9` — the selected segmented-control option's
  underline.
- `box-shadow: 0 16px 40px rgba(0,0,0,.65)` — the toast, and **only** the toast.
  (Identical to Nocturne's `--shadow-lg` ambient half, without its `0 0 0 1px`
  ring.) There is no other shadow anywhere in the design.

---

## 4. Layout — the shell

```html
<div
  style="height:100vh;display:flex;overflow:hidden;background:#161826;position:relative"
>
  <aside …>…</aside>
  <main …><div style="max-width:1180px">…</div></main>
  <!-- toast, position:absolute, is a sibling of aside/main -->
</div>
```

- Full-viewport flex row, `overflow:hidden` on the shell. **`<main>` scrolls, the
  page does not.**
- `position:relative` on the shell exists solely so the toast can be
  `position:absolute; left:250px; bottom:22px`.

### Sidebar

`width:230px; flex:none; background:#1b1d29; border-right:1px solid #2f3240;
display:flex; flex-direction:column; padding:18px 0 14px`

1. **Brand row** — `padding:0 18px 18px; display:flex; align-items:baseline;
gap:8px`. "cabin" at 17px/600/−.02em, then the version in mono
   10.5px `#75798c`.
2. **Nav** — `display:flex; flex-direction:column; gap:1px; padding:0 10px;
flex:1; overflow-y:auto; overflow-x:hidden`.
   - **Group heading**: `font-size:10px; letter-spacing:.1em;
text-transform:uppercase; color:#63677a; padding:14px 8px 5px;
font-weight:600; display:flex`
   - **Item**: `display:flex; align-items:center; justify-content:space-between;
gap:8px; font-size:13px; padding:6px 9px; border-radius:6px;
cursor:pointer; transition:background .12s; flex:none; white-space:nowrap;
overflow:hidden; text-overflow:ellipsis`
     - idle: `color:#9397ab; background:transparent; box-shadow:none`
     - active: `color:#e9e9ed; background:#2b2741; box-shadow:inset 2px 0 0 #9184d9`
     - active also when on a child route (Inventory stays lit on a certificate
       detail; Hierarchies stays lit on a hierarchy or issuer page).
   - **Count badge** (right-aligned, only on Inventory, only when > 0):
     `font-size:10px; padding:0 6px; border-radius:9px; background:#33291a;
color:#e8c98e; border:1px solid #4d3f24`
3. **Footer** — `margin:14px 12px 0; padding:12px 8px 0; border-top:1px solid
#2f3240; display:flex; flex-direction:column; gap:9px`
   - user row: 22px avatar circle (`background:#2b2741; border:1px solid #423a6a;
color:#d2cefd; font-size:10px; font-weight:600`), name at 12.5px `#b2b6ca`,
     role chip pushed right (`font-size:10px; padding:1px 6px; border-radius:4px;
background:#292b31; color:#b2b6ca`).
   - "Log out": `font-size:12px; font-weight:500; color:#9397ab; border:1px solid
#3f424d; border-radius:6px; padding:5px 0; text-align:center`, hover
     `border-color:#5d5294; color:#d2cefd`.
   - the dashed "Prototype only — view as" box → **drop**.

**Nav groups and items** (in order; the visibility rules are role-gated):

| Group                   | Items                                                       |
| ----------------------- | ----------------------------------------------------------- |
| Overview                | Dashboard                                                   |
| Certificate authorities | Hierarchies · Create · Import CA · Import Cross Certificate |
| Certificates            | Inventory · Issue · Sign a CSR                              |
| Export                  | Trust bundle · CA key                                       |
| Access                  | ACME · API tokens · Users · Audit log · Settings            |

(`github.md` calls the fourth group "Transfer"; the rail in the prototype says
**Export**. Pick one — the rail is the newer artefact.)

Gating in the mock: Issue/Sign hidden without an issuer grant; Create/Import
CA/Import cross hidden below admin; CA key hidden below superadmin.

### Main

`flex:1; min-width:0; overflow:auto; padding:26px 34px 60px` → inner
`max-width:1180px`.

### How a page is built inside it

Every screen follows the same recipe:

1. Root wrapper carries `animation:cabinIn .18s ease-out`.
2. _(detail pages only)_ Back link:
   `<p style="margin:0 0 6px;font-size:12px"><span style="color:#9397ab;cursor:pointer">← Certificates</span></p>`
3. `h1` at 29px, `margin:0 0 4px`. On detail pages it sits in a
   `display:flex; align-items:center; gap:12px; flex-wrap:wrap` row with the
   status tag beside it, and takes `margin:0`.
4. Lead paragraph, `margin:0; font-size:13px; color:#9397ab`.
5. _(optional)_ Action row: `display:flex; gap:10px; margin-top:14px`.
6. Then **section rows**, repeated:

```css
display: grid;
grid-template-columns: 250px minmax(0, 1fr);
gap: 28px;
padding: 22px 0;
border-top: 1px solid rgba(233, 233, 237, 0.08);
```

Left column: `h2` 17px + a 12px `#75798c` description. Right column: the
content. The first section row on a page adds `margin-top: 20–22px`.

7. **Form pages** break the pattern: a two-column grid
   `minmax(0,1fr) 380px` (Issue, Create a CA) or `minmax(0,1fr) 360px` / `340px`
   (Import a CA, Sign a CSR), `gap:36px; margin-top:26px`. Left = the form,
   `display:flex; flex-direction:column; gap:16px; max-width:520–620px`.
   Right = a vertical stack of preview/aside panels, `gap:14px`.

---

## 5. The screens

Nineteen states across eighteen routes. `github.md` maps them onto cabin's
templates; that column is reproduced where it exists.

### 5.1 Dashboard `route: dashboard` → `templates/dashboard.html`

Title "Dashboard"; lead "What needs attention, and what happened last." followed
by a mono clock stamp in `#63677a` at 11.5px.

- **Stat tiles** — `display:grid; grid-template-columns:repeat(4,1fr); gap:12px;
margin:22px 0 0`. Four tiles: valid / expiring / expired / revoked. Each is a
  clickable card (→ Inventory pre-filtered): number at 30px/500/−.02em, then the
  matching status tag `align-self:flex-start`. Hover `border-color:#5d5294`.
- **Expiring** — section row. A list with columns
  `2fr .6fr 1.1fr .8fr` = Common name / SANs / Expires / Days left. Rows
  clickable → certificate detail. Days-left tag is `bad` at ≤ 7 days, else
  `warn`. Top 5 only. Empty state: "Nothing expires in the next 30 days."
- **Authorities** — section row. A _grouped_ list (see §6.3): every root followed
  by its intermediates, columns `1.6fr 1.1fr 1fr .8fr` = Name (with kind tag) /
  status tag / Expires / days-left tag. Description: "An active issuer's expiry
  is flagged a year ahead."
- **Revocation** — section row, `grid-template-columns:1fr 1fr; gap:14px`, one
  card per CRL. Card border is `#55303c` when stale, `#2f3240` otherwise. Inside:
  issuer name at 13px/500 + a `stale` tag, then a `auto 1fr` key/value grid (CRL
  number / Generated / Next update) with mono `#e9e9ed` values, then the CRL URL
  in mono 11.5px `#75798c` with `word-break:break-all`.
- **Services** — section row. Three inline chips
  (`display:flex; align-items:center; gap:9px; background:#232532; border:1px
solid #2f3240; border-radius:8px; padding:10px 14px; font-size:12.5px`):
  ACME + tag, MCP + tag, "Base URL" + the URL in mono.
- **Activities** — section row. Last five audit entries, columns
  `1.1fr .9fr 1.3fr 2fr` = time (mono `#75798c`) / actor (`#b2b6ca`) / action
  (mono `#d2cefd`) / summary (`#9397ab`). Not clickable.

### 5.2 Not permitted `route: * (blocked)`

A narrow page, `max-width:560px`. `h1` "Not permitted" with `margin:0 0 8px`,
then a 13px `#9397ab` body at `line-height:1.6`, `margin:0 0 18px`, then a single
primary button "Back to the inventory". Two body texts: one for auditors, one for
"you hold no issuer grant".

### 5.3 Certificates (inventory) `route: certs` → `certs_list.html`

- Title + lead "Everything this CA has issued, newest first."
- Action row: primary "Issue certificate", secondary "Sign a CSR" (both hidden
  without an issue grant).
- **Filter bar** — `display:flex; gap:10px; align-items:center; margin:22px 0 0;
flex-wrap:wrap`:
  - search `input`, `width:300px`, placeholder "common name, SAN or serial"
  - a **segmented control** with five options: all / valid / expiring / expired /
    revoked
  - pushed right (`margin-left:auto`): a result count in 12px `#75798c`, then two
    small outline buttons "CSV" and "JSON"
- **List** — columns `1.7fr .7fr .7fr 1.5fr 1fr .5fr 1.2fr` = Common name /
  Profile / Source / SANs / Serial / Key / Valid until. "Common name" and
  "Valid until" headings are **sortable** (`cursor:pointer`, with an appended
  `↑`/`↓`). CN cell is `#b5abfc`; Source is a `neutral` chip; SANs shows the
  first two plus `+N`; Serial is truncated to 11 chars + `…`; the last cell packs
  the mono date and the status tag in a `display:flex; gap:7px; white-space:nowrap`.
  Rows clickable. Empty state: "No certificates match this filter." with a
  `border-top` and `padding-top:22px`.
- **Pager** — 8 rows per page. `display:flex; justify-content:space-between;
margin-top:18px; padding-top:14px; border-top:1px solid rgba(233,233,237,.08);
font-size:12px; color:#75798c`; label on the left, `← Previous` / `Next →` on
  the right with `gap:14px`. Enabled `cursor:pointer; color:#b5abfc`, disabled
  `color:#3f424d`.

### 5.4 Certificate detail `route: detail` → `cert_detail.html`

- Back link "← Certificates"; title = the CN with the status tag beside it
  (label is "valid · 18 days", "expired", or "revoked · keyCompromise").
- **Fact grid** — `display:grid; grid-template-columns:repeat(2,minmax(0,1fr));
gap:0 40px; margin-top:22px`. Each half is its own `auto 1fr` grid; every cell
  carries `border-top:1px solid rgba(233,233,237,.07); padding:9px 0`, values
  additionally `padding-left:24px`. Left: Serial (mono, `word-break:break-all`) /
  Issuer / Profile ("server · ECDSA P-256"). Right: SANs (one `<div>` per name,
  `line-height:1.6`) / Valid from (mono) / Valid until (mono).
- **Certificate (PEM)** — section row with a `<pre>` panel.
- **Downloads** — section row: primary "Certificate (PEM)", secondary "Full chain
  (PEM)", and "Private key (PEM)" which is _disabled_ (`color:#5a5d6b;
border:1px solid #2f3240; cursor:not-allowed`) when cabin holds no key.
- **PKCS#12 bundle** — section row. A `display:flex; align-items:flex-end;
gap:12px` row with a password field (280px) and a primary button. Error text
  below in `#e8a9b4`, `margin:-6px 0 0`.
- **Revoke** — section row, only when the certificate is live _and_ the actor may
  revoke. A **danger panel** (`background:#232532; border:1px solid #55303c;
border-radius:8px; padding:16px 18px; gap:12px; max-width:520px`) containing a
  reason `select`, a confirmation checkbox, and the **armed/disarmed** danger
  button.
- **Revoked banner** — when already revoked: `margin-top:22px; padding:14px 16px;
border:1px solid #55303c; background:#1e1a1d; border-radius:8px;
font-size:12.5px; color:#e8a9b4`.

### 5.5 Issue a certificate `route: issue` → `certs_new.html`

Two-column form (`minmax(0,1fr) 380px`).

Left: Common name · Subject alternative names (mono textarea, 4 rows, with a hint
line) · Profile (a two-option segmented control server/client, `padding:7px 18px`,
`align-self:flex-start`) · Issuer (`select` + a hint that changes with the number
of active issuers) · a `1fr 1fr` sub-grid with Key type and Validity (days) ·
error note · button row: primary "Issue certificate" (label becomes "Issuing…"
and the button greys while busy), tertiary "Paste an example", borderless "Cancel".

Right, stacked:

1. **Name constraints — checked before signing.** Kicker + one line per name:
   `✓`/`✕` mark (`#9184d9` / `#e8a9b4`), the name in mono `#cfd3e5`
   (`word-break:break-all`), a note in 11px. Then a summary paragraph in 11.5px
   `#75798c`. **Recomputes on every keystroke.**
2. **Result.** Kicker + `auto 1fr` grid: Expires (mono) / Chain / "Key held by →
   cabin, encrypted at rest".
3. **Clamp note** (warning-toned) — appears only when the requested validity
   exceeds the issuer's own expiry.

### 5.6 Sign a CSR `route: sign` → `certs_sign.html`

Two-column (`minmax(0,1fr) 340px`). Left: a 10-row mono textarea, an error note,
and three buttons (primary "Sign CSR", tertiary "Paste a sample CSR", borderless
"Cancel"). Right: a single **Parsed request** panel (`align-self:flex-start`)
with Subject / SANs / Key, values `#e9e9ed` — `—` until something is pasted —
plus a footnote about constraint re-checking.

### 5.7 Hierarchies `route: ca` → `ca_list.html`

- Title + lead "Every certificate authority hierarchy this cabin knows, one row
  each."
- Action row: primary "Create a CA", two secondary "Import a CA" / "Import a
  cross certificate" (all admin-only).
- **Grouped list**, columns `2fr .8fr 1fr .9fr 1.1fr` = Name / Status / Expires /
  Intermediates / Cross certificates.
  - **Root row**: `padding:12px; border-top:1px solid rgba(233,233,237,.07);
font-size:12.5px; cursor:pointer` plus a **2px left status bar**
    (`#3f7d55` active / `#8c3f3d` expired / `#3f424d` retired). Name in
    `#b5abfc; font-weight:500` with the `root` tag beside it. Clickable → 5.8.
  - **Issuer rows** beneath: `padding:7px 12px; font-size:12px;
border-left:2px solid transparent`, name column indented
    `padding-left:14px` with a mono `├`/`└` glyph in `#5d5294`. Kind column reads
    "issuer" in 11px `#63677a`. Non-active rows get `opacity:.65`. Clickable → 5.9.
  - **Per-root empty state**: `padding:6px 12px 8px 40px; font-size:11.5px;
color:#e8c98e` — "No issuer yet — nothing can be signed under this root."

### 5.8 Hierarchy detail `route: ca-detail` → `ca_detail.html` / `ca_macros.html`

Back link "← Hierarchies"; title = root name + status tag; lead "One hierarchy:
its root, its issuers and its cross certificates."

Section rows:

1. **The root** — description is the metadata line ("until 2044-02-11 ·
   path_length 2 · imported"). Right column: the "serving" sentence in 12.5px
   `#9397ab`; the subject and SHA-256 fingerprint on one mono 11.5px `#75798c`
   line separated by `·`; a secondary `root.pem` button; and — only for a keyless
   root — an **Offline root** warning note containing an inline primary button
   "Restore the key".
2. **Issuers** — a list with columns `2fr 1.2fr .8fr 1.1fr` = Name / Kind /
   Status / Expires, rows clickable → 5.9. Empty state is a warning note. Below
   it a primary "Add intermediate" that toggles an **inline form panel**
   (`background:#1b1d29; border:1px solid #2f3240; border-radius:8px;
padding:16px 18px; display:flex; gap:12px; flex-wrap:wrap;
align-items:flex-start`) with Name / Key type / Years / Permitted names /
   Excluded names, a right-aligned primary "Create intermediate", an error line,
   and a full-width 11px `#63677a` footnote.
3. **Cross certificates** _(only when present)_ — columns
   `1.7fr 1.3fr .8fr .9fr 1fr` = Name / Signed by / Status / Serving / Expires.
4. **Cross-sign with another root** _(admin only)_ — a `flex; align-items:flex-end`
   row: Signing root `select` (min-width 220px), Years input (70px), primary
   "Cross-sign"; plus an explanatory footnote, or — when no candidate exists — a
   12.5px `#75798c` paragraph explaining why.
5. **Renew and retire** _(admin only)_ — a secondary "Renew for 10 years"
   (hidden for a keyless root) and a **danger panel** (border `#5b2c2b`) with an
   explanatory paragraph, a confirmation checkbox and the armed/disarmed "Retire".

### 5.9 Issuer / cross certificate detail `route: ca-row` → `ca_issuer.html`

Back link is dynamic ("← Hierarchies" or "← _root name_"). Title + status tag.

- **Fact grid** — single `auto 1fr` grid, `gap:0 24px; max-width:820px`:
  Kind / Valid from / Valid until / Subject / Fingerprint. Same rule-per-row
  treatment as 5.4 but without the `padding-left:24px`.
- **Cross banner** _(cross certificates only)_ — a `#232532` panel with
  "Signed by **X**, in place of Y's own signature." plus the serving tag inline.
- **Downloads** — section row: primary `cert.pem`, secondary `chain.pem`.
- **Published URLs** _(intermediates only)_ — a single mono 11.5px paragraph at
  `line-height:1.9` with `CRL … <br> AIA … <br> ACME …`.
- **Name constraints** _(when set)_ — the **dashed readout box**
  (`padding:11px 14px; border:1px dashed #3f424d; border-radius:8px;
font-size:12px; color:#cfd3e5; max-width:620px; font-family:mono`).
- **Renew and retire** _(admin, active only)_ — secondary "Renew for 10 years"
  plus the same danger panel; the explanatory text differs for intermediates
  and crosses.

### 5.10 Create a CA `route: ca-create` → `ca_new.html`

Two-column (`minmax(0,1fr) 380px`). Left: CA name (with a hint about the "_name_
Root" convention) / Key type / a `1fr 1fr` sub-grid of Root validity (years) and
Path length / error note / primary "Create CA" (label "Generating keys…" while
busy) + borderless "Cancel".
Right: a **What gets created** panel (Root / Expires / Issuers / Key); a
**path-length note that flips tone live** — accent-toned at ≥ 2, warning-toned at
1; and a static `#232532` note about constraints belonging to intermediates.

### 5.11 Import a CA `route: ca-import` → `transfer_*.html`

Two-column (`minmax(0,1fr) 360px`). Left: four mono textareas / a password field
(Signing CA certificate, Signing CA private key, passphrase, Parent/root
certificate), an error note, primary "Import CA" + tertiary "Paste a sample CA" +
borderless "Cancel". Right: a **Parsed** panel whose values are `#5a5d6b` until a
PEM block is detected and `#e9e9ed` after; a warning note about imported
constraints; and a `#232532` note naming `/data/secret.key` in mono.

### 5.12 Import Cross Certificate `route: cross-import` → `transfer_*.html`

Single column, `max-width:620px`, no aside. A long lead (`max-width:700px`), two
mono textareas (Cross certificate, Signing root certificate), an error note
(border `#5b2c2b`, text `#e9908e`), primary "Import Cross Certificate" +
borderless "Cancel".

### 5.13 Trust bundle `route: trust-bundle` → `transfer_*.html`

Title + lead. One primary "Download all roots". A list with columns
`2fr .8fr .9fr 1.2fr` = Root / Status / Intermediates / _(blank)_; the last cell
is `text-align:right` holding a 12px `#b5abfc` "Download this hierarchy" link.
Rows are **not** clickable. A closing footnote in 11.5px `#63677a`,
`max-width:640px`.

### 5.14 CA key `route: ca-key` → `transfer_*.html`

Superadmin only. Long lead (`max-width:700px`).

- **Grouped list**, columns `2fr 1fr 1.6fr` = Name / Kind / Key. Rows are _not_
  clickable. The Key cell is colour-coded: `#8fd3a8` "stored on this instance",
  `#e8c98e` "forgotten — offline root…", `#75798c` "no private key on this
  instance".
- **Export** section row: CA `select` (min-width 250px), password field (240px),
  and a **danger-outline** button ("Export CA key",
  `color:#e9908e; border:1px solid #5b2c2b`, hover `background:#1e1a1d`). Error
  text below, `flex-basis:100%`.
- **Delete a stored key** section row: Root `select`, a mono textarea for the
  stored PKCS#12 with a hint line, a password field, a **warning note**, a
  confirmation checkbox, an error line, and the armed/disarmed "Delete this key".

### 5.15 ACME `route: acme` → `acme.html`

- **Directories** section row: one `#232532` card per active issuer
  (`display:flex; align-items:center; justify-content:space-between; gap:14px;
padding:12px 15px`), issuer name at 13px/500 above the URL in mono 11.5px
  `#75798c`, and a small secondary "Copy" on the right.
- **External Account Binding** section row: the **toggle switch** plus a 13px
  label; a note that flips tone (accent when EAB is on, warning when off); a list
  with columns `1.2fr 1.4fr 1fr .8fr` = Key id (mono `#d2cefd`) / Issued for /
  Created (mono) / Used; and a primary "New EAB key", `align-self:flex-start`.
- **Recent orders** section row: columns `1.6fr .8fr .9fr 1.1fr` = identifier
  (mono `#cfd3e5`) / challenge / status tag / when (mono `#75798c`).

### 5.16 API tokens `route: tokens` → `tokens.html`

- Lead mentions `/api/v1` in mono.
- **One-time token banner** _(after creation)_: `border:1px solid #423a6a;
background:#1e2032; border-radius:8px; padding:14px 16px` — a 12px `#d2cefd`
  line "Copy this now — it is shown once and never again.", then a flex row with
  a `<code>` (`background:#161826; border:1px solid #3f424d; border-radius:6px;
padding:9px 12px; word-break:break-all; flex:1`) and a small primary "Copy".
- **Create row** _(admin only)_: `display:flex; gap:10px; align-items:flex-end;
margin-top:22px; flex-wrap:wrap` — Name (220px) / Role select / Issuer grant
  select (**replaced by the text "all issuers — implied by superadmin" in
  `#d2cefd` when the role is superadmin**, matched to a 35px height) / primary
  "Create token".
- **List**: columns `1.2fr .7fr 1.4fr 1fr 1fr .6fr` = Name (500) / Role chip /
  Grant / Created (mono) / Last used (mono) / a right-aligned "Revoke" in 12px
  `#e9908e` (admin only).

### 5.17 Users `route: users` → `users.html`

- Primary "Add user" (admin+) toggling an **inline form panel** (same recipe as
  5.8, but `align-items:flex-end`) with First name / Last name / Login / Email /
  Initial password / Role / Issuer grant, plus primary "Create user" and a
  borderless "Cancel". The Issuer-grant select is swapped for implied text when
  the role is superadmin (`#d2cefd`) or auditor (`#e8c98e`). Error note below,
  `max-width:560px`.
- **List**: columns `1.5fr 1.4fr .8fr 1.5fr .7fr .8fr` = Name / Email / Role /
  Issuer grants / Last seen / actions. Left cell: a 26px avatar circle plus a
  stacked full name (500) over the mono `@login` in 11px `#75798c`,
  `line-height:1.3`.
- **Inline row editing.** Clicking a row swaps _every_ cell to a control: two
  name inputs, an email input, a role select, a grant select — all
  `background:#161826; border:1px solid #5d5294; border-radius:6px;
font-size:12px; padding:5px 8px; width:100%`. The row takes
  `border-left:2px solid #9184d9; background:#1d1f2c`. The action cell shows
  Save (`#8fd3a8`) / Cancel (`#9397ab`) instead of Delete (`#e9908e`), and a
  third "Delete? Yes / No" state.
- A read-only hint note for non-admins, and a closing footnote about grant
  freshness.

### 5.18 Audit log `route: audit` → `audit.html`

- **Filter pills**: `display:flex; gap:8px; margin:20px 0 0; flex-wrap:wrap`,
  five values (all / ui / api / acme / mcp). Pill:
  `font-size:12px; padding:6px 13px; border-radius:6px; border:1px solid`.
  Selected `#9184d9` + `color:#d2cefd; background:#2b2741`; idle `#3f424d` +
  `color:#9397ab`.
- **List**: columns `1.1fr .9fr .6fr 1.2fr 2.2fr` = Time (mono `#75798c`) /
  Actor (`#b2b6ca`) / Door (a 10px chip) / Action (mono `#d2cefd`) / Summary
  (`#9397ab`). Not clickable, no pager.

### 5.19 Settings `route: settings` → `settings.html`

- A read-only warning note for non-admins.
- **Base URL** section row: one mono input (`max-width:520px`, greyed to
  `#75798c` + `cursor:not-allowed` when read-only) with a hint line.
- **Services** section row: two toggle rows, each = the switch + a 13px title
  over an 11.5px `#75798c` subtitle. Error note below, `max-width:520px`.
- **Environment** section row: an `auto 1fr` grid, `gap:7px 20px`, entirely mono
  12px. Keys in `#75798c`, values in default text; `CABIN_TLS`/`COOKIE_SECURE`
  values in `#d2cefd`; `CABIN_MASTER_PASSPHRASE → set` in `#e8c98e`.

---

## 6. Components

### 6.1 Buttons

All are `<div>`/`<span>` with `onClick` in the prototype. **They must become
`<a>` or `<button>`.** Shared geometry: `border-radius:6px; cursor:pointer;
font-weight:500`.

| Variant                       | Style                                                                                                                                      | Hover                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| **Primary (large)**           | `font-size:13px; color:#b5abfc; border:1px solid #9184d9; padding:9px 20px`                                                                | `background:#2b2741`                                    |
| **Primary (medium)**          | `font-size:13px; …; padding:8px 16px`                                                                                                      | same                                                    |
| **Primary (small)**           | `font-size:12.5px; …; padding:7px 14px` (or `8px 16px`)                                                                                    | same                                                    |
| **Secondary**                 | `font-size:12.5–13px; color:#cfd3e5; border:1px solid #3f424d; padding:7–8px 14–16px`                                                      | `border-color:#5d5294` (sometimes also `color:#d2cefd`) |
| **Tertiary / quiet**          | `font-size:13px; color:#9397ab; border:1px solid #3f424d; padding:9px 14px`                                                                | `border-color:#5d5294; color:#d2cefd`                   |
| **Borderless (Cancel)**       | `font-size:13px; color:#9397ab; padding:9px 14px`, no border                                                                               | none declared                                           |
| **Disabled (busy/invalid)**   | `color:#6b6f80; border:1px solid #3f424d`                                                                                                  | none                                                    |
| **Disabled (unavailable)**    | `color:#5a5d6b; border:1px solid #2f3240; cursor:not-allowed`                                                                              | none                                                    |
| **Danger — disarmed**         | `font-size:12.5px; color:#6d5259; border:1px solid #3a2b30; padding:7–8px 16px; align-self:flex-start`                                     | none                                                    |
| **Danger — armed**            | `color:#e9908e; border:1px solid #5b2c2b` (revoke uses `#e8a9b4` / `#55303c`)                                                              | none                                                    |
| **Danger — outline (export)** | `color:#e9908e; border:1px solid #5b2c2b; padding:8px 16px`                                                                                | `background:#1e1a1d`                                    |
| **Inline text action**        | a bare `<span>` at 12px, no border, no padding: `#b5abfc` (navigate/download), `#e9908e` (Delete/No), `#8fd3a8` (Save), `#9397ab` (Cancel) | none                                                    |

There are no icons in any button. `min-height` is never set; height comes from
`font-size × line-height + padding`.

### 6.2 Lists ("tables")

**There is not a single `<table>` in the prototype.** Every table is a stack of
CSS-grid rows sharing one `grid-template-columns`.

```html
<!-- head -->
<div
  style="display:grid;grid-template-columns:…;gap:12px;padding:0 12px 7px;
            font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;
            color:#75798c"
>
  <div>Common name</div>
  …
</div>
<!-- row -->
<div
  style="display:grid;grid-template-columns:…;gap:12px;padding:10px 12px;
            border-top:1px solid rgba(233,233,237,.07);font-size:12.5px;
            align-items:center;cursor:pointer"
  style-hover="background:#1d1f2c"
>
  …
</div>
```

- Row padding: `9px 12px` (dense: dashboard expiring, ACME, audit), `10px 12px`
  (inventory, issuer lists), `11px 12px` (users, trust bundle), `12px`
  (hierarchy root rows).
- Font size: 12.5px normally, 12px on the audit log and on nested issuer rows.
- Hover is `background:#1d1f2c` **only** where the row is clickable.
- Sortable headings add `cursor:pointer` and append `↑`/`↓` as literal text.
- Column templates are listed per screen in §5; there is no shared set.

**Real-HTML advice:** these are semantically tables. Reproduce them as `<table>`
with `display:grid` on `<tr>` (or CSS grid on `<table>` with `display:contents`
rows) — or accept `<div role="table">`. Do not ship bare `<div>`s with no roles.

### 6.3 Grouped list (root + children)

Used on the hierarchy list, the dashboard Authorities block and the CA-key list.
The group is drawn as one rounded box built from per-row borders:

- **Root row**: `background:#1d1f2c; border:1px solid #2f3240;
border-radius:8px 8px 0 0` (or `8px 8px 8px 8px` when it has no children);
  `margin-top:10px` for every group but the first. Name at `font-weight:600`.
- **Child rows**: `border-left:1px solid #2f3240; border-right:1px solid #2f3240`,
  and the last child adds `border-bottom:1px solid #2f3240;
border-radius:0 0 8px 8px; padding-bottom:11px`. Name at weight 400,
  `color:#b2b6ca`, `padding-left:14px`, preceded by a mono `├`/`└` glyph in
  `#5d5294`.
- Non-active rows: `opacity:.65`.

### 6.4 Form fields

```html
<label
  style="display:flex;flex-direction:column;gap:6px;font-size:12px;color:#9397ab"
>
  Common name
  <input
    style="background:#1b1d29;border:1px solid #3f424d;border-radius:6px;
                color:#e9e9ed;font-size:13px;padding:9px 12px"
  />
  <span style="font-size:11.5px;color:#63677a">One DNS name per line.</span>
</label>
```

- Large form (`Issue`, `Create a CA`, `Import`): `font-size:13px; padding:9px 12px`.
- Compact form (inline panels, filter bars, side forms): `font-size:12.5px;
padding:8px 12px`.
- Inline row-edit (Users): `background:#161826; border:1px solid #5d5294;
font-size:12px; padding:5px 8px; width:100%`.
- Nested-in-panel (add intermediate): `background:#161826; font-size:12.5px;
padding:7px 10px`, explicit widths (70–220px).
- Textareas add `font-family:<mono>; resize:vertical` and a `rows` count
  (2 / 3 / 4 / 5 / 6 / 10).
- Focus, global: `input,select,textarea:focus-visible { outline:2px solid #9184d9;
outline-offset:1px }`.
- Checkbox: **completely unstyled native** `<input type="checkbox">` inside
  `<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;
color:#cfd3e5;cursor:pointer">`. This is the one place where the design
  currently falls back to browser chrome — it will look wrong on a dark ground
  in most browsers unless `accent-color: #9184d9` is added.
- Field error: `<p style="margin:0;font-size:12px;color:#e9908e">`.

### 6.5 Segmented control

```html
<div
  style="display:flex;border:1px solid #3f424d;border-radius:6px;overflow:hidden"
>
  <div style="font-size:12px;padding:7px 13px;cursor:pointer;color:#9397ab">
    all
  </div>
  <div
    style="font-size:12px;padding:7px 13px;cursor:pointer;
              border-left:1px solid #3f424d;color:#e9e9ed;background:#2b2741;
              box-shadow:inset 0 -2px 0 #9184d9"
  >
    valid
  </div>
</div>
```

Every option but the first carries `border-left:1px solid #3f424d`. Selected =
`color:#e9e9ed; background:#2b2741; box-shadow:inset 0 -2px 0 #9184d9`. Idle =
`color:#9397ab`. Idle hover is **not** declared. The Profile control on the Issue
page uses the same recipe with wider padding (`7px 18px`) and
`align-self:flex-start`.

### 6.6 Filter pills

`font-size:12px; padding:6px 13px; border-radius:6px; cursor:pointer;
border:1px solid`. Selected `#9184d9` + `color:#d2cefd; background:#2b2741`;
idle `#3f424d` + `color:#9397ab`. (Audit log only. Note this is a _second_
selection idiom alongside the segmented control — consider unifying.)

### 6.7 Toggle switch

```
track: width:38px; height:21px; border-radius:11px; padding:2px;
       transition:background .15s; flex:none;
       background: #5d5294 (on) | #3f424d (off)
knob:  width:17px; height:17px; border-radius:50%; background:#e9e9ed;
       transition:transform .15s; transform: translateX(17px) | translateX(0)
disabled: cursor:not-allowed; opacity:.55
```

### 6.8 Tags and chips

| Chip                              | Style                                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status tag** (six variants, §1) | `font-size:10.5px; padding:2px 7px; border-radius:4px; white-space:nowrap` + the variant's bg/color/border                                                                            |
| **`root` kind tag**               | `font-size:10px; letter-spacing:.08em; text-transform:uppercase; padding:2px 7px; border-radius:4px; background:#2b2741; color:#d2cefd; border:1px solid #423a6a; white-space:nowrap` |
| **Audit door chip**               | `font-size:10px; padding:1px 6px; border-radius:4px; background:#282a33; color:#b2b6ca; border:1px solid #3f424d`                                                                     |
| **Sidebar role chip**             | `font-size:10px; padding:1px 6px; border-radius:4px; background:#292b31; color:#b2b6ca` (no border)                                                                                   |
| **Nav count badge**               | `font-size:10px; padding:0 6px; border-radius:9px; background:#33291a; color:#e8c98e; border:1px solid #4d3f24`                                                                       |

### 6.9 Cards and panels

| Panel                       | Style                                                                                                                                                                                                                      |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Standard panel**          | `background:#232532; border:1px solid #2f3240; border-radius:8px; padding:14px 16px`                                                                                                                                       |
| **Kicker** (inside a panel) | `font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#75798c; margin-bottom:10px`                                                                                                                         |
| **Key/value grid** (inside) | `display:grid; grid-template-columns:auto 1fr; gap:6px 14px; font-size:12px; color:#9397ab`; values `color:#e9e9ed`, mono for dates/URLs                                                                                   |
| **Stat tile**               | standard panel + `display:flex; flex-direction:column; gap:7px; cursor:pointer`; hover `border-color:#5d5294`; number `font-size:30px; font-weight:500; letter-spacing:-.02em`                                             |
| **Danger panel**            | `background:#232532; border:1px solid #5b2c2b` (revoke: `#55303c`, `padding:16px 18px`, `gap:12px`, `max-width:520px`); `border-radius:8px; padding:14px 16px; display:flex; flex-direction:column; gap:11px`              |
| **Inline form panel**       | `margin-top:14–20px; background:#1b1d29; border:1px solid #2f3240; border-radius:8px; padding:16px 18px; display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start\|flex-end`                                         |
| **PEM block**               | `<pre>` — `margin:0; background:#1b1d29; border:1px solid #2f3240; border-radius:8px; padding:14px 16px; font-family:<mono>; font-size:11.5px; line-height:1.6; color:#9397ab; white-space:pre-wrap; word-break:break-all` |
| **One-time secret banner**  | `border:1px solid #423a6a; background:#1e2032; border-radius:8px; padding:14px 16px`                                                                                                                                       |
| **Dashed readout**          | `padding:11px 14px; border:1px dashed #3f424d; border-radius:8px; font-size:12px; color:#cfd3e5; max-width:620px; font-family:<mono>`                                                                                      |
| **Inline service chip**     | `display:flex; align-items:center; gap:9px; background:#232532; border:1px solid #2f3240; border-radius:8px; padding:10px 14px; font-size:12.5px`                                                                          |

### 6.10 Notes / callouts — three tones

| Tone              | Border                   | Background | Text                     |
| ----------------- | ------------------------ | ---------- | ------------------------ |
| **Warning**       | `#4d3f24`                | `#1e1c17`  | `#e8c98e`                |
| **Error**         | `#55303c` (or `#5b2c2b`) | `#1e1a1d`  | `#e8a9b4` (or `#e9908e`) |
| **Info / accent** | `#423a6a`                | `#1e2032`  | `#d2cefd`                |

Shared: `border:1px solid; border-radius:8px; padding:11–12px 14px;
font-size:11.5–12.5px`, often `max-width:520/620/640/700px`.
Several notes **flip tone with state** (path_length ≥ 2 → info, = 1 → warning;
EAB on → info, off → warning).

### 6.11 Empty states

Not a component — a plain paragraph.

- Section-level: `margin:0; font-size:12.5px; color:#75798c`
  ("Nothing expires in the next 30 days.", "No certificates match this filter."
  — the latter adds `border-top:1px solid rgba(233,233,237,.07); padding-top:22px;
margin:22px 0 0`).
- Per-group in a list: `padding:6px 12px 8px 40px; font-size:11.5px;
color:#e8c98e`.
- Blocking empty state (no issuer at all): a **warning note** (6.10),
  `max-width:620px`.

### 6.12 Toast

```html
<div
  style="position:absolute;left:250px;bottom:22px;background:#232532;
            border:1px solid #423a6a;box-shadow:0 16px 40px rgba(0,0,0,.65);
            border-radius:8px;padding:11px 16px;font-size:12.5px;color:#e9e9ed;
            animation:cabinToast .2s ease-out;display:flex;align-items:center;
            gap:10px;max-width:520px"
>
  <span
    style="width:6px;height:6px;border-radius:50%;background:#9184d9;flex:none"
  ></span>
  Issued nas.lan.example.test · key stored encrypted
</div>
```

`left:250px` = sidebar 230px + 20px. Auto-dismisses after **3200 ms**. Single
toast at a time (a new message clears the pending timer). No close button, no
variants — every message uses the same accent dot regardless of outcome.

### 6.13 Avatar

Circle, `background:#2b2741; border:1px solid #423a6a; color:#d2cefd;
font-weight:600; display:flex; align-items:center; justify-content:center;
flex:none`. 22px / 10px font in the sidebar, 26px / 11px in the users list.
Content is one uppercase initial.

### 6.14 Definition grid (detail facts)

```
label: font-size:12px; color:#75798c; padding:9px 0;
       border-top:1px solid rgba(233,233,237,.07)
value: font-size:12.5px; padding:9px 0 9px 24px;   /* 24px omitted on 5.9 */
       border-top:1px solid rgba(233,233,237,.07)
```

Wrapped in `display:grid; grid-template-columns:auto 1fr`, optionally two of
those side by side in `repeat(2,minmax(0,1fr)); gap:0 40px`. Mono +
`word-break:break-all` on serials, fingerprints and subjects.

---

## 7. Interaction and motion

### Keyframes — there are exactly two

```css
@keyframes cabinIn {
  from {
    opacity: 0;
    transform: translateY(6px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
@keyframes cabinToast {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
```

- `cabinIn` runs as `animation:cabinIn .18s ease-out` on **every screen's root
  element** — a 6px rise-and-fade on page entry.
- `cabinToast` runs as `animation:cabinToast .2s ease-out` on the toast only.

Both survive server rendering unchanged: they fire on first paint, so a full page
load reproduces `cabinIn` exactly. **Wrap both in
`@media (prefers-reduced-motion: reduce) { animation: none }`** — the prototype
does not.

### Transitions — there are exactly three

- nav item: `transition: background .12s`
- toggle track: `transition: background .15s`
- toggle knob: `transition: transform .15s`

Nothing else transitions. Buttons, rows and tiles snap on hover.

### Hover

Declared in the prototype via a **`style-hover="…"` attribute**, which is
implemented by **neither `support.js` nor `_ds_bundle.js`** — it is an authoring
convention recording intent, not working code. Rewrite every one as a real
`:hover` rule:

| Element                        | Hover                                                |
| ------------------------------ | ---------------------------------------------------- |
| List row (clickable)           | `background:#1d1f2c`                                 |
| Primary button                 | `background:#2b2741`                                 |
| Secondary/tertiary button      | `border-color:#5d5294` (sometimes `+ color:#d2cefd`) |
| Stat tile                      | `border-color:#5d5294`                               |
| Sidebar "Log out"              | `border-color:#5d5294; color:#d2cefd`                |
| Danger-outline "Export CA key" | `background:#1e1a1d`                                 |
| Link                           | `color:#d2cefd` (from `a:hover`)                     |

### Focus

Global, from the prototype's own `<style>`:

```css
:focus {
  outline: none;
} /* Nocturne, unused by the prototype */
input:focus-visible,
select:focus-visible,
textarea:focus-visible {
  outline: 2px solid #9184d9;
  outline-offset: 1px;
}
```

**Gap:** every button, row, tab, pill and toggle in the prototype is a `<div>`
and therefore unfocusable — the design has **no focus state for any of them**.
When they become real `<a>`/`<button>` elements you must design one. Nocturne's
default is the right starting point:
`:focus-visible { outline: 2px solid #9184d9; outline-offset: 2px }`.

### Other

- Links: `a { color:#b5abfc }`, `a:hover { color:#d2cefd }`. No underline is set;
  Nocturne's `text-underline-offset:3px` never applies because the prototype does
  not link the stylesheet's rules to any `<a>` it renders (it renders `<span>`s).
- Scrollbar (WebKit only):
  `::-webkit-scrollbar { width:10px; height:10px }`
  `::-webkit-scrollbar-thumb { background:#2f3240; border-radius:6px }`
- `::selection` is **not** set (Nocturne sets it; the prototype does not link it).

---

## 8. Prototype scaffolding — do not carry across

Everything in this section exists only to make the mock run.

### Document wrappers

- `<script src="./support.js">` — the Design-Canvas runtime (~69 KB). It parses
  `<x-dc>`, compiles the template into React elements, and mounts a `DCLogic`
  subclass. Nothing in it is design.
- `<x-dc> … </x-dc>` — the template container.
- `<helmet> … </helmet>` — where the runtime hoists `<link>`/`<script>`/`<style>`
  into `<head>`.
- `<script type="text/x-dc" data-dc-script data-props="{}"> … </script>` — the
  1115-line React component. All of it is mock behaviour.

### Control-flow elements

- `<sc-for list="{{ items }}" as="it" hint-placeholder-count="N">` → Jinja
  `{% for it in items %}`. `hint-placeholder-count` is editor metadata (how many
  ghost rows to draw in the canvas) and has no runtime meaning.
- `<sc-if value="{{ cond }}" hint-placeholder-val="{{ true }}">` → Jinja
  `{% if cond %}`. `hint-placeholder-val` is likewise editor metadata.
  **Important:** the 21 top-level `sc-if`s keyed on `isDashboard`, `isCerts`,
  `isDetail`, … are not conditionals at all — they are a **client-side router**.
  Each becomes its **own Jinja template behind its own FastAPI route**, not an
  `{% if %}`.

### Bindings

- `{{ … }}` mustaches — React interpolation.
- `onClick="{{ fn }}"`, `onInput="{{ fn }}"`, `onChange="{{ fn }}"`,
  `value="{{ x }}"`, `checked="{{ x }}"` — React props written as attributes.
  None is valid HTML. `<div onClick>` must become `<a href>` or
  `<button type="submit">` inside a `<form>`.
- **`style="{{ someStyle }}"`** — the mock's mechanism for conditional styling.
  There are ~90 of these computed style strings (`rowStyle`, `statusTag`,
  `issueBtnStyle`, `keylessNoteStyle`, `userFormStyle`, …), many of which resolve
  to `"display:none"` to hide an element. **Every one becomes either a CSS class
  or a Jinja `{% if %}` around the element.** In particular, `display:none` is
  how the mock does permission gating — in cabin that must be a real
  server-side authorisation check, never a hidden element.
- **`style-hover="…"`** — see §7. Not implemented anywhere; pure intent.

### The design-system files

- `_ds/nocturne-…/_ds_bundle.js` — an empty stub. Its entire body:
  ```js
  const __ds_ns = (window.Nocturne_noctur = window.Nocturne_noctur || {});
  const __ds_scope = {};
  __ds_ns.__errors = __ds_ns.__errors || [];
  ```
  Drop it.
- `_ds/nocturne-…/styles.css` — linked but unused (§0). Drop the link. Its
  `@import url('https://fonts.googleapis.com/…Inter…')` is the **only** reason a
  CDN appears anywhere; see §9.1.
- `_ds/nocturne-…/_ds_manifest.json`, `readme.md`, `_adherence.oxlintrc.json` —
  design-tool metadata.

### Mock data and fake latency

- `const NOW = new Date("2026-08-09T07:31:00Z")` — a frozen clock. The dashboard
  prints "9 Aug 2026 · 07:31:00Z" from it.
- `SEED` — 15 invented certificates; the four hierarchies; 3 tokens; 3 users;
  7 audit entries; 2 EAB keys; 4 ACME orders.
- `serial()`, `pem()`, `fpOf()` — random/hash-derived fakes. `pem()` builds a
  bogus PEM by base64-ing the CN into a fixed body.
- `setTimeout(…, 700)` on issue, `800` on CA create and CA import — artificial
  latency behind the "Issuing…" / "Generating keys…" button labels. In cabin
  these are genuinely slow operations, so the _busy_ state is real; the
  `setTimeout` is not.
- `setTimeout(… 3200)` — the toast dismissal.
- `checkName()`, `doIssue()`, `doSign()`, `doCreateCa()`, `doImportCa()` — all
  validation is client-side and approximate (e.g. `doSign` hard-codes the CN it
  "parses" as `build-91.ci.example.test`). None of it is authoritative.

### UI that is explicitly prototype-only

- The sidebar's dashed **"Prototype only — view as"** role `<select>`
  (superadmin / admin / user / auditor). This drives every permission variant in
  the mock. Delete it; the real role comes from the session.

---

## 9. What cannot survive cabin's constraints

cabin: FastAPI + Jinja2, one hand-written stylesheet, no build step, no CSS
framework, fonts vendored locally, **no JavaScript in use** (htmx is loaded but
has never been used).

### 9.1 Inter comes from a CDN — must be vendored

`styles.css` line 2 is
`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');`.
This is the only external dependency in the whole design and it is
**non-negotiable**: vendor Inter locally as woff2 with `@font-face`. Weights
actually used: **400, 500, 600** (700 is imported but never used — do not ship
it). Keep `system-ui, sans-serif` as the fallback so the design degrades sanely.

### 9.2 The live preview panels — the biggest loss

Five panels recompute on every keystroke:

| Screen      | Panel                                                             |
| ----------- | ----------------------------------------------------------------- |
| Issue       | "Name constraints — checked before signing" (✓/✕ per name)        |
| Issue       | "Result" (Expires / Chain / Key held by) + the clamp warning      |
| Create a CA | "What gets created" + the path_length note that flips tone        |
| Sign a CSR  | "Parsed request" (Subject / SANs / Key)                           |
| Import a CA | "Parsed" (Subject / Parent / Key), greyed until a PEM is detected |

None of this is possible without JS. Options, in order of preference:

1. **Round-trip.** Add a "Check" submit button that POSTs the form and
   re-renders it with the panel filled. Honest, and it lets the _server's_ real
   constraint checker answer — which is more truthful than the mock's regex.
2. **Static.** Render the panel as a description of the rules rather than a live
   verdict ("This issuer permits `lan.example.test`, `192.168.0.0/16`; excludes
   `secret.lan.example.test`"). Keeps the visual weight, loses the feedback.
3. **htmx.** `hx-post` + `hx-target` on the panel is the minimal path and would
   be the first genuine justification for the htmx that is already loaded.
   Flag this as a decision to be taken, not assumed.

Do **not** ship the panels as decoration showing stale values.

### 9.3 Inline row editing on Users

Clicking a row swaps all six cells to inputs, shows Save/Cancel, and has a
three-state action cell (view / edit / confirm-delete). Without JS:

- Simplest: a separate `/users/{id}/edit` page.
- Or `?edit=3` on the list URL — the server re-renders **that one row** in edit
  mode. This preserves the visual design exactly. The catch is that a `<form>`
  cannot wrap a grid row's cells without becoming the grid itself; make the
  editing row `<form style="display:grid;grid-template-columns:…">`.
- The confirm-delete state maps cleanly to `?delete=3` (or a separate small
  confirmation page).

### 9.4 Everything clickable is a `<div>`

No `<a>`, no `<button>`, no `<form>` anywhere in the prototype. Consequences:

- Every navigation target becomes `<a href>`; every mutation becomes a
  `<form method="post">` with a real `<button>`.
- **No focus state exists in the design** (§7). One must be added — the Nocturne
  default (`2px solid #9184d9`, `outline-offset:2px`) is right.
- Rows that are "clickable" become a link inside the row, or the whole row
  becomes a stretched-link (`position:relative` on the row + `::after` overlay on
  the primary link). The latter preserves the full-row hover.
- The checkbox is native and unstyled; add `accent-color:#9184d9`.

### 9.5 Toast

An action fires a toast that fades in and disappears after 3.2 s. Server-rendered
this becomes a **flash message**: stored in the session on POST, rendered once
after the redirect, dismissed by the next navigation. The panel styling carries
over verbatim. What is lost: the 3.2 s timer (a CSS
`animation: … forwards` with a delay can hide it, but nothing can dismiss it
early) and the fact that it appears without a page change. Also note the current
design gives every message the same accent dot — since flash messages will now
carry success/error meaning across a redirect, consider three dot colours
(`#8fd3a8` / `#e8c98e` / `#e9908e`).

### 9.6 Inventory search, filter, sort, pagination

All client-side in the mock; all straightforwardly server-side in cabin via
`?q=&status=&sort=&dir=&page=`. But:

- The search box needs `<form method="get">` and a submit affordance — **no live
  filtering as you type.**
- Each segmented-control option becomes an `<a href>` carrying the other
  parameters through.
- Each sortable heading becomes an `<a href>` that flips `dir`.
- Pager arrows become `<a>`, and the disabled state becomes a `<span>`.

This survives well. Budget for the extra markup.

### 9.7 Toggles (ACME / MCP / EAB)

The track/knob pair is styled divs with a `transform` transition. Server-rendered:
a `<form method="post">` whose submit button _is_ the track. The knob's slide
animation is lost — after the reload the knob renders in its final position with
no motion. Accept that, or use a `<input type="checkbox">` + `<label>` pair with
a visible "Save" button (which keeps the animation on click but decouples it from
the actual state until save — arguably worse). Recommend: form + button, no
animation, and rely on the track colour change.

### 9.8 Copy-to-clipboard

Two places: the ACME directory "Copy" button and the one-time-token "Copy". Both
are impossible without JS. Replace with a `<code>` block styled for easy
selection (`user-select:all` makes a single click select the whole value — that
works with zero JS and is the right answer here). Drop the buttons or keep them
as a visual `user-select:all` target.

### 9.9 The one live-feedback pattern that _does_ survive

The **confirmation checkbox arming a danger button** (revoke, retire ×2, delete
key) changes the button's colour the instant the box is ticked. Pure CSS handles
this:

```css
form.danger:has(input[type="checkbox"]:checked) button.danger {
  color: #e9908e;
  border-color: #5b2c2b;
}
```

`:has()` is widely supported. This is worth calling out because it is the only
interactive nuance in the design that costs nothing.

### 9.10 The `100vh` / `overflow:hidden` shell

Works fine server-rendered, but it is a real choice with costs: browser scroll
restoration applies to `<main>` rather than the document, `Ctrl+End` and
find-in-page scrolling behave differently, and on short viewports the sidebar's
own `overflow-y:auto` is what saves the nav. Keep it — the design depends on the
sidebar staying put — but test at 800px height.

### 9.11 Things that are _not_ a problem

- **No CSS framework needed.** Everything here is flexbox, CSS grid and one
  gradient-free colour system. It maps cleanly onto one hand-written stylesheet.
- **No icons.** The Nocturne readme asks for Phosphor icons; the prototype uses
  **none**. The only glyphs are text characters: `←` `→` `↑` `↓` `✓` `✕` `├` `└`
  `·`. No icon font, no SVG sprite, no dependency.
- **No images.** Nocturne's `.lighten` / `mix-blend-mode` imagery treatment is
  never used.
- **No `color-mix()`.** Nocturne leans on it; the prototype hard-codes the
  resulting hexes and uses `rgba(233,233,237,.07/.08)` for its dividers. Follow
  the prototype — plain hex and rgba only, no modern colour functions required.
- **No `<dialog>` / modal.** Nocturne ships one; the prototype uses none. Every
  confirmation is inline, in the page, gated by a checkbox — which is exactly
  what a no-JS app wants.

---

## 10. Suggested token set for cabin's stylesheet

A minimal `:root` derived from what is actually used, replacing Nocturne's:

```css
:root {
  /* grounds */
  --bg: #161826; /* page */
  --surface-low: #1b1d29; /* sidebar, inputs, pre, inline form panels */
  --surface: #232532; /* cards, panels, toast */
  --surface-hover: #1d1f2c; /* row hover, grouped-list head */

  /* lines */
  --line-panel: #2f3240;
  --line-control: #3f424d;
  --rule-section: rgba(233, 233, 237, 0.08);
  --rule-row: rgba(233, 233, 237, 0.07);

  /* text */
  --text: #e9e9ed;
  --text-2: #cfd3e5;
  --text-3: #b2b6ca;
  --text-muted: #9397ab;
  --text-faint: #75798c;
  --text-hint: #63677a;
  --text-disabled: #5a5d6b;

  /* accent */
  --accent: #9184d9; /* lines, focus, marks */
  --accent-text: #b5abfc; /* links, primary label */
  --accent-bright: #d2cefd; /* hover, text on tint */
  --accent-tint: #2b2741; /* the only accent fill */
  --accent-edge: #423a6a; /* border of tinted things */
  --accent-deep: #5d5294; /* hover borders, toggle on */

  /* status */
  --good-bg: #17291f;
  --good-fg: #8fd3a8;
  --good-line: #264734;
  --warn-bg: #33291a;
  --warn-fg: #e8c98e;
  --warn-line: #4d3f24;
  --bad-bg: #3a2029;
  --bad-fg: #e8a9b4;
  --bad-line: #55303c;
  --dead-bg: #3a1c1d;
  --dead-fg: #e9908e;
  --dead-line: #5b2c2b;
  --flat-bg: #282a33;
  --flat-fg: #b2b6ca;
  --flat-line: #3f424d;

  /* note grounds */
  --note-warn-bg: #1e1c17;
  --note-bad-bg: #1e1a1d;
  --note-info-bg: #1e2032;

  /* geometry */
  --r-chip: 4px;
  --r-control: 6px;
  --r-panel: 8px;
  --shell-nav: 230px;
  --section-label: 250px;
  --content-max: 1180px;
}
```

---

## 11. Security note

All fetched content was treated as **data**. Nothing in the prototype,
`support.js`, `_ds_bundle.js`, `_ds_manifest.json` or `github.md` addressed the
reader as an agent, claimed authority, or attempted to grant permissions.

One item is worth flagging as _borderline but benign_:
`_ds/nocturne-…/readme.md` is written in the imperative and issues directives —
"Link the one stylesheet from every page", "Never hard-code a hex", "Use Phosphor
icons (https://phosphoricons.com)", "Do not use pure black or pure white". These
are ordinary design-system documentation aimed at a human consumer of the kit,
not instructions aimed at me, and they were **not** followed as commands. Two of
them are in fact **contradicted by the prototype itself** (which hard-codes every
hex and uses no icons at all), and one — the Google Fonts `@import` in
`styles.css` — would import an external dependency into cabin. Where the readme
and the prototype disagree, this brief follows the prototype and says so.

No file requested a network fetch, a credential, a configuration change, or any
action outside reading.
