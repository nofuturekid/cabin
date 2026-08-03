# Spec 0015 — UI Layout

## Context

The UI grew one page at a time from spec 0003 onwards, and its stylesheet grew
with it. The result has four structural defects, all reproducible with real
data at a normal desktop width:

1. **Three competing content widths.** `main` is 60rem, `.card` is 24rem,
   `.card-wide` is 48rem. Dashboard, settings, login and setup render at half
   the width of every table page, and the 60rem of `main` is never used.
2. **Tables have no overflow container.** `table { width: 100% }` without a
   fixed layout grows past its card as soon as the columns need more room —
   with the seven columns of `/certs` the last columns are painted outside the
   card and cut off at the viewport edge.
3. **No wrapping rule for unbreakable strings.** Serials, EAB key ids, ACME
   account ids, base URLs and ISO timestamps have no break opportunity, so a
   long common name is drawn across the card border and a timestamp breaks
   across four lines.
4. **Nothing is responsive.** The header nav does not wrap, the filter rows do
   not wrap, and there is no media query anywhere. Below roughly 60rem the
   page scrolls sideways.

Two further problems come from the same stylesheet: `form { display: flex;
flex-direction: column }` stretches every button to the full card width, and
because settings and the ACME page are one `<form>` each, their headings and
prose are flex items that get the same 0.5rem gap as the input fields — so
those pages have no visual hierarchy.

Rather than patch the widths, this spec replaces the page chrome with one
layout: a grouped navigation rail, a single content column that uses the
window, and a small set of layout primitives (`.scroller`, `.section`,
`.field`, `.tag`) that every page composes from. The aesthetic direction is
"instrument": neutral surfaces, one amber accent, monospace reserved for
things that identify something (serials, key ids, tags, URLs).

Nothing about behaviour, routing, wording, authorisation or data changes. This
is a template-and-stylesheet spec; the only Python that changes is the static
asset wiring for the two vendored fonts.

## User Stories

- As an operator, every page uses the same content width, so moving between
  the inventory and the settings does not resize the page under me.
- As an operator with real hostnames and serials, no text is drawn outside its
  container and nothing is cut off at the viewport edge.
- As an operator on a laptop or a phone, the page never scrolls sideways; a
  table too wide for the screen scrolls inside its own container.
- As an operator with eleven navigation entries, they are grouped by what they
  do, not listed as one undifferentiated row.
- As an operator, cabin looks the same offline as online — no asset is fetched
  from a third party at runtime.

## Functional Requirements

- FR-1: `layout.html` renders a two-column grid: a navigation rail
  (`<aside class="rail">`) and `<main>`. The rail holds the brand with the
  version, the nav grouped under "Overview" / "Certificates" / "Access", and
  a footer with the current user, their role and the logout form. Entries are
  gated by the same `nav.*` flags as today — no route gains or loses
  visibility.
- FR-2: The current page's rail entry carries `aria-current="page"`. Templates
  set it by declaring `{% set nav_current = "certs" %}`; the rail compares
  against that name. Every content template sets exactly one.
- FR-3: One content width. `main` fills the space next to the rail with a
  fluid padding of `clamp(1rem, 3vw, 2.5rem)`; no page sets its own width.
  `.card` and `.card-wide` are removed from the stylesheet and from every
  template. Login and setup — the two pages rendered without a rail — use
  `.card-narrow` (24rem, centred) instead.
- FR-4: Every `<table>` is wrapped in `<div class="scroller">`, which is the
  only element allowed to scroll horizontally. `body` never does: it carries
  `overflow-wrap: break-word`, and the grid uses `minmax(0, 1fr)` so the
  content column can shrink below its content's intrinsic width.
- FR-5: Cells opt into their treatment: `.mono` for identifiers (serial, key
  id, account id), `.nowrap` for dates and short enumerations, `.sans-list`
  for the SAN column (one name per line, capped at 20rem). `.badge-*` becomes
  `.tag`, keeping the value in the class name — `tag-valid`, `tag-revoked`,
  `tag-source-acme` — so a value can still be styled and asserted on
  individually. The stylesheet maps those values onto three roles (ok / warn /
  bad); a value with no rule stays neutral, which is what "where did this come
  from" and "which role" should be.
- FR-6: Forms stop being the layout. `form` is no longer a flex column;
  labelled inputs are wrapped in `.field` (a grid of label + control, max
  34rem) and buttons sit in `.actions`, so a button is sized by its text.
  Settings and the ACME page are laid out as `.section` blocks — a heading
  and its explanation in the left column, the controls in the right — instead
  of one flat form.
- FR-7: Two fonts are vendored under `src/cabin/web/static/fonts/`: Public
  Sans (variable, ~27 KB) for text and IBM Plex Mono (variable, ~15 KB) for
  identifiers, both SIL OFL 1.1, both served from cabin with the licence text
  alongside them. `@font-face` declarations live in `cabin.css` with
  `font-display: swap` and a system fallback in every stack. No stylesheet,
  script or font is fetched from a CDN.
- FR-8: Both colour schemes are complete. The palette is defined as custom
  properties on `:root` and overridden in `@media (prefers-color-scheme:
dark)`; every token used in light mode has a dark counterpart.
- FR-9: Below 60rem the rail becomes a horizontal, wrapping nav strip above
  the content, `.section` collapses to one column, and the filter rows wrap.
  Interactive controls keep a visible `:focus-visible` outline in both
  schemes.

## Acceptance Criteria

- AC-1: Rendered at 1440×1150 with a 60-character common name, five SANs and a
  full audit log, no page has `document.scrollingElement.scrollWidth >
clientWidth`, and no element's right edge extends past its container's.
  Measured with headless Chrome over all ten authenticated pages.
- AC-2: The same measurement passes at 390×900.
- AC-3: `/certs` at 1440 shows all seven columns inside the content column;
  narrowed to 900 the `.scroller` scrolls and the page does not.
- AC-4: Every template that renders a `<table>` wraps it in `.scroller`; no
  template references `card`, `card-wide` or `badge-`; every content template
  sets exactly one `nav_current`.
- AC-5: The rail marks exactly one entry with `aria-current="page"` per page,
  and it is the page being viewed. A viewer sees the same rail minus the
  entries their role never had.
- AC-6: `/static/fonts/PublicSans.woff2` and `/static/fonts/IBMPlexMono.woff2`
  return 200 with `font/woff2`; `cabin.css` references only those two and no
  absolute URL to another host appears anywhere in the templates or the
  stylesheet.
- AC-7: Auth, authorisation, CSRF and redirect behaviour are unchanged: the
  spec 0003–0014 test suite passes untouched.

## Test list

test_layout_has_rail_and_main, test_nav_current_marked_once_per_page,
test_nav_entries_still_role_gated, test_every_table_is_wrapped_in_scroller,
test_no_template_uses_card_or_badge_classes,
test_every_content_template_sets_nav_current, test_login_and_setup_use_narrow,
test_fonts_served_with_woff2_content_type,
test_fonts_are_vendored_with_their_licences, test_css_has_no_external_urls,
test_css_defines_dark_counterpart_for_every_token,
test_no_horizontal_overflow[1440-1150] and [390-900] (headless Chrome, all
ten pages, skipped where Chrome is absent)

The existing suite carries the rest: the badge assertions in
`test_web_certs_inventory`, `test_web_acme_ui` and `test_mcp` are renamed to
the `tag-*` classes, and `test_list_page_absurd_page_is_empty_not_an_error`
keeps the pager outside the empty-state branch.

## Out of Scope

Wording, page copy and field labels. New pages, new columns, new filters or
sorting. Any change to routes, permissions, CSRF or data. Client-side
interactivity beyond the htmx already in use. A dark/light toggle — the
scheme follows the operating system. Swagger UI's own stylesheet, which is
vendored upstream and left alone.
