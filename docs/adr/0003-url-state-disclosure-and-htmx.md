# 0003. Every htmx target is a URL that also works as a page

- Status: accepted
- Date: 2026-08-09
- Deciders: maintainer

## Context and Problem Statement

htmx has been vendored and loaded in `layout.html` since spec 0015 and this
repository contains no `hx-` attribute at all: the library is 47 KB of
capability nobody has used. Spec 0029 is the first change that wants it. The
redesign's brief calls the five live preview panels "the biggest loss" of
server-rendering (`docs/design/0027-brief.md` §9.2) and offers three ways to
recover them — a round-trip submit button, a static description of the rules,
or htmx — with the explicit instruction to treat the choice as "a decision to
be taken, not assumed". The design also draws two disclosures on the hierarchy
page, which spec 0024 FR-8 removed as `<details>` elements with an argument
that still stands.

So the question is not "may spec 0029 use htmx". It is what rule htmx enters
this project under, because the first client-side interactivity in an
application is the one that decides what the tenth looks like. Without a rule,
each later page has a local reason to add one more fragment endpoint, and the
end state — a set of URLs that render nothing an operator can navigate to,
reachable only by JavaScript — is arrived at by increments none of which was
the decision.

## Decision Drivers

- cabin runs without JavaScript today, on every page. That is a property
  worth keeping deliberately rather than losing accidentally: it is what makes
  the application scriptable, testable with an HTTP client, and usable in the
  places an internal CA gets used from.
- A preview panel that disagrees with the signer is worse than no panel. The
  answer has to come from the server, because the server is what signs.
- Spec 0024 removed `<details>` for reasons that have nothing to do with
  JavaScript: the state lived only in the browser, it could not be linked to,
  and an error re-render arrived inside a collapsed element.
- Every route in this project is guarded, CSRF-protected and audited under
  rules written down in specs 0003, 0008 and 0018. A new class of endpoint
  that is "just a fragment" is a new class of endpoint those rules have to be
  remembered for.
- The test suite is the project's memory. A rule that no test can check is a
  comment.

## Considered Options

- **Every htmx target is a URL that also works as a page**, with the preview
  endpoints as a named exception that still answers a page
- No htmx: a round-trip `Check` button that POSTs and re-renders the page
  (the brief's option 1)
- Static panels describing the issuer's rules instead of judging the request
  (the brief's option 2)
- htmx with ordinary fragment-only endpoints (the idiomatic htmx approach)
- `<details>` for the two disclosures, keeping the previews server-rendered
- A small hand-written JavaScript module doing the checks client-side, as the
  prototype does
- `hx-boost` on `<body>`, turning every link and form in cabin into a fragment
  swap

## Decision Outcome

Chosen option: **every htmx target is a URL that also works as a page**.

Concretely: an `hx-get` or `hx-post` may only name a URL that answers a
complete page — shell, rail, `<main>` — when the same request arrives without
the `HX-Request` header. htmx's job is to fetch that page and take one named
region out of it with `hx-select`, so the region an operator sees swapped in
is the same markup they would have seen after a navigation. Disclosure state
that used to live in the browser lives in the query string instead:
`GET /ca/{id}?add=intermediate` renders the page with that panel open, the
trigger is a real `<a href>` pointing at exactly that URL, and with
JavaScript off the anchor is followed and the operator gets the same panel one
navigation later.

The four preview endpoints are the one exception, and they are an exception to
how the response is packaged rather than to whether the URL answers a page.
Each returns a fragment when `HX-Request` is present and the full form page
with the panel filled when it is not, from **one** Jinja macro rendered by
both. The exception is bounded by three things: they are the only endpoints
spec 0029 adds; each is guarded exactly like the mutation it previews, with
the same dependencies in the same order; and the no-JavaScript path through
them is not a fallback anybody has to remember to test, because a round-trip
`Check` button uses it in ordinary operation.

**Why not "no htmx" (the round-trip button alone).** This was the strongest
alternative and it is the one the chosen option contains: the `Check` button
ships, works, and is what the no-JavaScript operator uses. What it does not
do is recompute as names are typed, and the panel it feeds is the one place in
cabin where feedback while typing is worth something — a name-constraints
verdict is most useful before the request is submitted, and an operator who
must submit to find out will simply submit and read the 400. Choosing it alone
would also have left htmx loaded and unused for a fourth spec running, which
is its own small dishonesty: a dependency shipped to every browser on every
page with no user.

**Why not static panels.** They keep the design's visual weight and answer a
different question from the one asked. "This issuer permits `lan.example.test`
and excludes `secret.lan.example.test`" is a description of the rule; the
operator wants to know about the four names in their textarea, and working
that out from the description by hand is exactly the arithmetic the panel
exists to do. The brief itself ranks this option below the round-trip.

**Why not fragment-only endpoints.** This is the ordinary htmx idiom and it
is the option this ADR exists to refuse. A URL that answers only a fragment
is a URL with no no-JavaScript story, and once one exists the marginal cost of
the second is zero — the mechanism that makes an application JavaScript-only
is not a decision to require JavaScript, it is twenty local decisions that
each seemed to require nothing. It also silently doubles the guard surface:
a fragment endpoint is trivially easy to write without `verify_csrf` because
nothing visible breaks, and no test in a suite that always sends the header
would notice. The chosen rule makes both failures loud: a walker over the
templates fetches every `hx-` target with no header and requires a full page
back, which a fragment-only endpoint fails on the first run.

**Why not `<details>`.** Spec 0024 FR-8 removed it and the argument survives
this ADR unchanged. `<details>` state cannot be linked to, cannot be restored
after an error re-render without the server writing `open` into the markup
(which spec 0023 AC-3 had to require), and appears nowhere else in cabin. URL
state answers all three, and the heading and help line of the section stay
visible in both states, which is what spec 0024 was actually defending.

**Why not hand-written JavaScript.** It would put a second implementation of
the name-constraint rules in the browser, and the rule that matters most —
that the common name is checked only when the SAN list carries no DNS entry —
is precisely the one a re-implementation gets wrong. The prototype's own
`checkName()` is an approximate regex, and the brief says so. cabin's checker
is `check_name_constraints`, the function `_build_leaf` calls immediately
before signing; the only way for the panel to agree with the signer is to be
the signer's own call.

**Why not `hx-boost`.** It is the single change that would make this rule
meaningless: with `hx-boost` on the body, every link and every form in the
application becomes a fragment swap, and "which of these targets is an htmx
target" stops having an answer. It is banned by name in spec 0029 FR-2's
attribute allowlist rather than left to judgement.

### Consequences

- Good, because cabin still works with JavaScript disabled, on every page,
  and that is now a checked property rather than an accident of never having
  written any: a test walks the templates, fetches every `hx-` target without
  the `HX-Request` header, and requires a full page back.
- Good, because htmx adds no endpoint except the four previews. The
  disclosure needed a query parameter on a route that already existed, and
  spec 0030's two remaining uses — the Users row edit and the inventory
  filters — need none at all.
- Good, because the preview panels answer with the server's own checker and
  the server's own clamp, so the panel and the certificate cannot disagree.
  That is a stronger property than the prototype had, not a weaker one.
- Good, because a preview URL is guarded exactly like the mutation it
  previews, which is a rule with an obvious right answer rather than a new
  judgement per endpoint.
- Bad, because a swap costs a whole page render on the server: `hx-select`
  throws most of the response away. For a disclosure clicked occasionally
  this is irrelevant; it is the reason the previews are allowed to answer a
  fragment, since those fire on a keystroke debounce.
- Bad, because disclosure state in the query string is state in a URL that
  can be bookmarked, shared and pasted into a chat window. For
  `?add=intermediate` that is harmless and mildly useful. It would not be
  harmless for state that names a secret or a target, and this ADR does not
  license that.
- Bad, because "one macro, two envelopes" is a discipline, not a mechanism:
  nothing in Jinja stops someone writing a second template for the fragment.
  Spec 0029 AC-7 holds it in place by asserting that the fragment's body
  appears verbatim inside the full page.
- Neutral, because this does not settle whether cabin ever ships JavaScript
  of its own. It settles that htmx is not how that would happen: the
  attribute allowlist excludes `hx-on*` and every template is asserted to
  contain no `<script>`.

## More Information

- Spec 0029 FR-2 states the rule and its four clauses, FR-3 the preview
  exception, FR-13 the URL-state disclosure; AC-1 and AC-2 check them.
- `docs/design/0027-brief.md` §9.2 (the five panels and the three options),
  §9.3 and §9.6 (the same idiom for Users and the inventory), §9.9 (the one
  live-feedback pattern that already survives, with no JavaScript at all).
- Spec 0024 FR-8 removed `<details>`; spec 0026 FR-16 banned htmx as a scope
  boundary for a layout spec; spec 0029 supersedes the second and narrows the
  first for two forms.
- `docs/adr/0000-template.md` for the headings; ADR 0002 for the precedent
  that a deviation is recorded with the test the next request should be held
  to.
