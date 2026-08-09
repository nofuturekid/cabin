# Spec 0029 — The Form Pages and the Live Previews

## Context

Spec 0027 put the design's shell and token layer around every page and
spec 0028 moved the detail and list pages into the design's arrangement.
This spec takes the five form pages — issue a certificate, sign a CSR,
create a CA, import a CA, import a cross certificate — and with them the
one thing the redesign has been deferring since it started: **the first
client-side interactivity in this project**.

htmx has been vendored and loaded since spec 0015 (`layout.html:8-9`,
htmx 2.0.10, no CDN) and this repository contains **zero `hx-`
attributes**. The design's most-used feature is five panels that
recompute as the operator types, and the brief calls them "the biggest
loss" (§9.2). It offers three ways out — a round-trip submit button,
a static description of the rules, or htmx — and asks that the choice be
"a decision to be taken, not assumed". Thomas took it: wire up htmx.

This spec is separate from 0028 because it is the only spec in the
redesign that adds routes and the only one that touches crypto-adjacent
Python. The constraint checker's reuse deserves acceptance criteria of
its own rather than arriving as a footnote to a template change.

### The one rule everything else rests on

**Every htmx target is a URL that also works as a page.** htmx adds no
endpoint except the four previews: it fetches a URL that already renders
a page and swaps a named region out of it with `hx-select`. The
hierarchy page's `Add intermediate` disclosure becomes URL state
(FR-13) — `GET /ca/{id}?add=intermediate` renders the page with the
panel open, and htmx pulls that one region out of the same response.
With JavaScript off, the anchor is followed and the operator sees the
same panel one navigation later.

The previews are the exception, and they are an exception to *how* the
response is packaged, not to whether the URL answers a page: each
returns a fragment when `HX-Request` is present and **the full page with
the panel filled** when it is not, from one Jinja macro rendered by
both (FR-3). One code path, two envelopes, which is what makes the
no-JavaScript story free rather than a second implementation.

This is what keeps spec 0024's `<details>` ban intact while giving the
design its behaviour, and it is what stops this project becoming a
single-page application by increments. Because that is a project-level
decision rather than a page-level one, it is also recorded as
`docs/adr/0003-url-state-disclosure-and-htmx.md` (FR-2), following the
two ADRs already in `docs/adr/`.

### The panel that must not disagree with the signer

The constraint preview calls **the real checker** —
`leaf.check_name_constraints`, the same call `_build_leaf` makes
immediately before `builder.sign(...)` (`leaf.py:678`). It calls it
twice: once per name for the ✓/✕ marks, and once over the whole set
exactly as issuance calls it, for the verdict.

Both, because of one rule inside that function
(`leaf.py:608-615`): the common name is checked as a dNSName **only when
the SAN list carries no DNS entry at all** — which is what OpenSSL's
`NAME_CONSTRAINTS_check_CN` does, and agreeing with the validator is the
whole point of spec 0020 FR-7. A per-name loop cannot reproduce that
rule: it never sees the set, so it never knows whether a DNS entry
exists. A panel built only from the loop marks every name ✓ for a
request whose CN is excluded and whose SANs are all IPs, and then
signing refuses it. A panel that disagrees with the signer is worse than
no panel; FR-4 and AC-3 are about exactly this case.

### What this spec overturns, and where

Every entry is argued in the requirement named beside it. Nothing else
in specs 0023–0028 changes.

| #   | Overturned                                        | By            | In one line                                                                                                             |
| --- | ------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 1   | 0026 FR-16, second half ("and no htmx")           | FR-2          | Thomas's decision; the ban was a scope boundary for a layout spec, and the rule replacing it is narrower than "no htmx" |
| 2   | 0026 FR-16, first half (`<details>`)              | **nothing**   | re-asserted, not overturned — recorded so that no reader infers it from row 1                                          |
| 3   | 0024 FR-8's corollary, for two forms              | FR-13         | the heading stays visible; only the fields move behind a real link that has its own URL, which `<details>` never had    |
| 4   | 0024 FR-8's removal of `_detail_page(open_form=)` | FR-13, IC     | there is something to open again, and it is read from the URL rather than threaded through each caller as a boolean     |
| 5   | 0023 FR-8's second half and AC-3                  | FR-13         | **restored**, not overturned: 0024 retired it because nothing could be closed, and something can be closed again        |
| 6   | 0028 AC-11's second clause (six reserved names)   | FR-15         | this spec renders `.kicker`; the reserved-and-undefined list becomes five                                              |
| 7   | 0028 AC-14's `[aria-hidden="true"]` census        | FR-15         | the ✓/✕ marks are the second user of that attribute, and the census gains them by name rather than being widened        |

Rows 4, 6 and 7 are not in the plan's list. They are consequences of it
that surface when the plan is checked against 0024's and 0028's own
criteria, and a spec that shipped them silently would leave three
criteria failing with no argument beside them.

## User Stories

- As an operator on the issue form, I can see before I sign anything
  whether the names I typed are inside what the chosen issuer permits —
  and the answer is the signer's own answer, not a second opinion.
- As an operator whose browser runs no JavaScript, every panel still
  fills: I press one more button and get the same page with the same
  panel in it. Nothing on these pages silently does nothing.
- As an operator issuing a certificate, the expiry the panel states is
  the expiry the certificate gets.
- As an operator importing a CA, pasting the private key and its
  passphrase sends them nowhere until I press `Import CA`.
- As an operator adding an intermediate, the open form has an address: I
  can link to it, bookmark it, and land back on it when the form comes
  back with an error.
- As an operator who reads every sentence on these pages today, every
  one of them still says exactly what it said.

## Functional Requirements

- FR-1: **The boundary.** This spec changes
  `src/cabin/web/templates/certs_new.html`, `certs_sign.html`,
  `ca_new.html`, `transfer_ca_import.html`,
  `transfer_cross_import.html` and `ca_detail.html`; adds
  `src/cabin/web/templates/form_macros.html`; changes
  `src/cabin/web/certs_ui.py`, `ca_ui.py`, `transfer_ui.py`,
  `src/cabin/ca/leaf.py` and `src/cabin/web/static/cabin.css`; and adds
  `docs/adr/0003-url-state-disclosure-and-htmx.md`. It appends one entry
  to the "everything else" divergence register of
  `docs/design/0027-brief.md` (FR-10) — the brief's own instruction for
  a deliberate departure.

  Four routes are added, all POST, all previews (FR-3). One optional
  query parameter is added to `GET /ca/{ca_id:int}` (FR-13). **No
  existing route changes** in path, method, guard, CSRF rule, form
  field, status code or redirect target. No schema change, no migration,
  no audit action, no API, MCP or ACME change. Wording is unchanged
  except for the strings FR-14 enumerates.

  **`ca_detail.html` and `ca_ui.py` are in the boundary although the
  plan's file list for this spec does not name them.** The plan names
  them in its htmx section instead, and requires this spec to supersede
  spec 0024's corollary for two forms; a supersession without the change
  it licenses is a sentence, not a requirement. The alternative — the
  rule shipping in the same spec as nothing but its own exception —
  would establish htmx in this project by its exception alone, which is
  the reverse of what the rule is for.

- FR-2: **Every htmx target is a URL that also works as a page**, and
  the ADR that records it. _Supersedes spec 0026 FR-16's second half
  ("no new page carries an `hx-` attribute")._ That clause was a scope
  boundary: 0026 was a layout spec, and its own Out of Scope says htmx
  "would be the first client-side interactivity in cabin, introduced as
  a side effect of a layout change". It is not introduced as a side
  effect here; it is this spec's subject, and it arrives with a rule
  narrower than the ban it replaces. **0026 FR-16's first half — the
  `<details>` ban — stands and is re-asserted** (FR-13).

  The rule, in four clauses:
  1. every URL named by an `hx-get` or `hx-post` attribute in any
     template answers a **full page** for the same method with no
     `HX-Request` header — status 200 (or the status that request would
     have had anyway), inside the shell, with the rail;
  2. the only endpoints this spec adds are the four previews of FR-3.
     Every other `hx-` target is a URL that exists for the
     no-JavaScript path first and is fetched by htmx second, with
     `hx-select` naming the region to take out of it;
  3. the attribute set is closed. Exactly `hx-get`, `hx-post`,
     `hx-target`, `hx-select`, `hx-swap`, `hx-trigger`, `hx-include`
     and `hx-push-url` may appear. `hx-boost`, `hx-swap-oob`,
     `hx-vals`, `hx-ext`, `hx-headers`, `hx-history` and every `hx-on*`
     attribute may not: the first turns ordinary navigation into
     fragment swapping across the whole application, and the last is
     inline JavaScript by another name;
  4. no second script is added. `htmx.min.js` stays the only JavaScript
     file cabin serves, and no template gains a `<script>` element.

  The decision is recorded in `docs/adr/0003-url-state-disclosure-and-htmx.md`,
  written to `docs/adr/0000-template.md`'s headings and addressing at
  minimum: no htmx at all (the brief's round-trip option), static
  description panels (the brief's option 2), htmx with fragment-only
  endpoints (the ordinary htmx idiom), `<details>` for the disclosure,
  and hand-written JavaScript doing the checks client-side as the
  prototype does. AC-2 checks that it exists and follows the template.

- FR-3: **The four preview endpoints: one shape, two envelopes.**

  | Path                    | Previews                     | Guard                      | Panels                                          |
  | ----------------------- | ---------------------------- | -------------------------- | ------------------------------------------------- |
  | `POST /certs/issue/preview`  | `POST /certs/issue`     | `require_admin` + `verify_csrf` | `Name constraints — checked before signing`, `Result`, the clamp note |
  | `POST /certs/sign/preview`   | `POST /certs/sign`      | `require_admin` + `verify_csrf` | `Parsed request`                             |
  | `POST /ca/create/preview`    | `POST /ca/create`       | `require_admin` + `verify_csrf` | `What gets created`, the path-length note    |
  | `POST /ca/import/preview`    | `POST /ca/import`       | `require_admin` + `verify_csrf` | `Parsed`                                     |

  Each is **guarded exactly like the mutation it previews** — the same
  dependencies, in the same order, so an anonymous request is redirected
  to `/login`, a non-admin gets 403, a missing or wrong `csrf_token`
  gets 403, and (on the two `/certs` previews) an issuer this principal
  is not granted is refused the same way `issue_and_store` refuses it. A
  preview is a read of privileged state — which names an issuer permits,
  what a pasted CA certificate says — and a preview endpoint that is
  easier to reach than its mutation is an information leak with a
  friendly name.

  Each **writes nothing**: no row, no audit event, no session state, no
  file. Each **unseals no private key**: the issuer's certificate is
  read from `ca_certificates.cert_pem`, and `ca_service.signing_credentials`
  — the one function that decrypts a CA key — is never called on a
  preview path (AC-5).

  Each returns the same panel content in two envelopes:
  - **`HX-Request` present** → `text/html` fragment: the panel stack
    alone, no `<html>`, no rail;
  - **absent** → the form page itself, rendered through its existing
    page renderer, with the panel filled and **every submitted value
    re-filled into the form**, status 200.

  Both envelopes render **one Jinja macro** per page, defined in
  `form_macros.html` and called from the page template with
  `{{ macro(preview) }}` and from the fragment path through the
  template environment's own module access. The macro takes exactly one
  argument — the preview dictionary the handler built — and reads
  nothing from the surrounding template context, which is what makes
  "one code path" a fact rather than a resemblance: AC-7 asserts the
  fragment body appears **verbatim** inside the full page.

- FR-4: **The constraint panel calls the real checker, twice.** For a
  request with resolved names `n₁…nₖ` (FR-5), an issuer certificate
  `C` and a common name `cn`, `certs_ui` calls
  `leaf.check_name_constraints`:
  - **once per name**, as `check_name_constraints(C, None, [nᵢ])`, for
    the ✓/✕ mark beside that name. `subject_cn` is `None` so that the
    common-name rule cannot fire inside a single-name call, where it
    would mark a name for a reason that is not about that name;
  - **once over the whole set**, as
    `check_name_constraints(C, cn, [n₁…nₖ])` — byte for byte the call
    `_build_leaf` makes — for the panel's verdict line.

  **The verdict is the whole-set call's, always, and is never derived
  from the marks.** When the whole-set call raises, the panel says the
  request would be refused and shows the exception's own message; when
  it returns, the panel says every name is inside what the issuer
  permits. A build that computes the verdict as "all marks are ✓" is
  wrong in exactly the case this requirement exists for: SANs
  `IP:10.0.0.5` with `subject_cn = secret.lan.example.test` under an
  issuer excluding `secret.lan.example.test` marks its one name ✓, and
  the whole-set call appends `DNS:secret.lan.example.test` — because no
  DNS SAN exists — and refuses. AC-3 is that fixture, in both
  directions.

  No part of the check is re-implemented in the web layer: no regex, no
  suffix comparison, no `in` test against `constraints_of`'s lists. The
  panel may *display* `leaf.constraints_of(C)`'s entries as context
  (which is what the design's summary paragraph shows), but no mark and
  no verdict may be computed from them.

- FR-5: **The names the panel checks are the names the signer would
  check.** `leaf._resolve_sans` becomes public as
  `leaf.resolve_sans`, with **no change to its body**, and the preview
  calls it with exactly what `issue_certificate` passes:
  `resolve_sans([_normalized SAN lines_], [], cn)`.

  This is a rename, not a second extraction, and it is required because
  the alternative is a panel that checks a different name set from the
  signer. Two of the ladder's rungs matter here and neither can be
  approximated: an empty SAN box falls back to the common name, and the
  fallback is `IP:` for a CN that parses as an IP address and `DNS:` for
  one that does not (`_san_from_cn`, `leaf.py:228-236`). Passing the
  empty list to `check_name_constraints` instead does **not** give the
  same answer: with an IP common name the checker's own fallback appends
  `DNS:10.0.0.5` — `_HOSTNAME_RE` matches a dotted-quad — and evaluates
  it against the permitted **DNS** subtrees, while issuance evaluates
  `IP:10.0.0.5` against the permitted **IP** subtrees. Those are
  different questions with different answers, and the panel must ask the
  one the signer asks.

  When resolution itself raises `IssueError` — an unparsable SAN line, a
  CN that is neither hostname nor IP with an empty SAN box, more than
  `MAX_SANS` entries — the panel shows that message in place of the
  marks. It is the message the POST would show, from the same call.

  > **Confirmed (test-authoring):** the disagreement this requirement
  > argues from is constructible, and it is in the suite as
  > `test_the_panel_resolves_an_ip_common_name_the_way_the_signer_does`.
  > It needs a hierarchy of its own — call it **ipnet** — whose
  > intermediate permits `192.168.0.0/16` and carries **no dNSName
  > subtree at all**. With `subject_cn = 10.0.0.5` and an empty SAN box:
  > `resolve_sans` returns `["IP:10.0.0.5"]`, the checker evaluates it
  > against the permitted IP subtrees, which do not cover it, and the
  > request is **refused** — `POST /certs/issue` with the same inputs
  > answers 400 carrying that message. The shortcut this requirement
  > forbids, passing the empty list, makes the checker's own fallback
  > append `DNS:10.0.0.5` and evaluate it against the permitted DNS
  > subtrees, of which there are none, so nothing constrains it:
  > **permitted**.
  >
  > **The two can only disagree in one direction, and it is the
  > dangerous one.** For an IP common name the signer's name set is a
  > superset of the shortcut's — `{IP:cn, DNS:cn}` against `{DNS:cn}` —
  > so wherever they differ, the shortcut permits what the signer
  > refuses. A panel built on it tells the operator to go ahead and the
  > button then refuses, which is the failure FR-4 opens by calling
  > worse than no panel. There is no fixture in which the shortcut is
  > the stricter of the two, so nothing about this is a matter of which
  > answer one prefers.
  >
  > The alpha fixture cannot show it: alpha permits `lan.example.test`,
  > so `DNS:10.0.0.5` fails there as well and both paths refuse — the
  > same verdict for different reasons, which is precisely the shape
  > that hides a defect. Hence a fixture of its own.

- FR-6: **The validity clamp is extracted, and it is the only
  extraction.** The five lines at `leaf.py:665-671` become

  ```python
  def clamp_validity(
      issuer_cert: x509.Certificate, days: int, now: datetime
  ) -> tuple[datetime, datetime | None]: ...
  ```

  returning `(not_after, capped_from)` and raising
  `IssueError("the signing CA certificate has expired")` unchanged.
  `_build_leaf` keeps its own signature and its own
  `now = datetime.now(UTC)` — it needs that `now` for
  `not_valid_before` as well — and passes it in. `now` is a **required**
  parameter with no default: a helper that reads its own clock is a
  helper the panel and the signer can disagree through, and a test
  cannot pin.

  Nothing else moves out of `_build_leaf`. In particular the
  `check_name_constraints` call stays exactly where it is, inside the
  one function both flows converge on, for the reason its own comment
  gives (`leaf.py:673-677`): there is nothing a caller can forget to
  pass and no door that can add itself later without the check coming
  with it.

  AC-4 measures this against **a certificate actually issued from the
  same inputs**, never against `clamp_validity` a second time. A
  criterion that calls the helper to check the helper cannot fail for
  the defect it exists to catch — that both call sites are wrong in the
  same way is precisely the failure mode of an extraction.

- FR-7: **The issue page's two panels and its note.**
  `certs_new.html` keeps its `.section`, its heading, its help line and
  its form exactly as they are; the section's value column becomes the
  two-column split of FR-15, with the form left and
  `<aside class="preview" id="preview">` right.

  1. **`Name constraints — checked before signing`** — one line per
     resolved name: the mark, the name in mono with
     `word-break: break-all`, and, for a refused name, the checker's own
     message. Then the verdict line (FR-4). When the issuer carries no
     `NameConstraints` extension, every name is marked ✓ and the verdict
     line says so (FR-14).
  2. **`Result`** — a key/value grid: `Expires` (from
     `clamp_validity`, mono), `Chain` (the issuer's chain to its root by
     name, from `ca_service.chain_for`), `Key held by` → `cabin,
     encrypted at rest`.
  3. **The clamp note**, warning-toned, rendered **only when
     `capped_from` is not `None`** — the same condition
     `cert_detail.html:14` uses for the sentence it is lifted from.

  With nothing typed yet — the first `GET /certs/new` — every value is
  the design's `—` and the constraints panel names the issuer's own
  permitted and excluded entries instead of marks. The panel is never
  blank and never shows a stale value from a previous request: it is a
  pure function of the request that produced it.

- FR-8: **The sign page's `Parsed request` panel.** `certs_sign.html`
  takes the same split. The panel shows `Subject`, `SANs` and `Key`,
  parsed from the pasted PEM with `x509.load_pem_x509_csr` and
  `leaf.san_strings`, and `—` in each until something parses. A CSR that
  does not parse shows the parse failure in the panel; it does not
  raise, does not 400, and does not touch the form's own error box,
  which belongs to `POST /certs/sign`.

  The panel carries **no verdict**. The design's §5.6 gives it a
  footnote about constraints being re-checked at signing instead, and
  that is what ships: the effective SAN set for a CSR depends on
  `sans_override` and on the resolution ladder's second rung, and a
  verdict computed from one of the two would be the disagreement FR-4
  exists to prevent. Recorded in Out of Scope rather than approximated.

- FR-9: **The create-a-CA page's `What gets created` panel and its
  flipping note.** `ca_new.html` takes the same split. The panel shows
  `Root` (the name as typed), `Expires` (now plus `root_years`, mono),
  `Issuers` and `Key` (the selected key type). `Issuers` says that a
  root is created on its own and an issuer is added on the hierarchy's
  own page — which is spec 0024 FR-3's behaviour stated where the
  operator is about to rely on it.

  The path-length note **flips tone with the value**: info-toned at
  `path_length >= 2`, warning-toned at `1`, using the existing
  `.callout` and `.callout.warning` rules and no new class. Both tones
  carry the same sentence — `ca_new.html:45`'s hint, moved into the
  panel column, byte for byte (FR-14).

  The design's CA-name hint about a "*name* Root" convention is **not**
  adopted: spec 0024 FR-1 abolished that convention, and printing a hint
  describing behaviour cabin deliberately removed is worse than printing
  none.

- FR-10: **The import page's `Parsed` panel.** `transfer_ca_import.html`
  takes the same split. The panel shows `Subject`, `Parent` and `Key`,
  read from the two certificate textareas, and each value is dim until
  its PEM parses and full-strength after.

  **The dim state is `--text-muted`, not the design's `#5a5d6b`.** That
  hex is 2.4:1 on `--surface` and would be reported by spec 0027's
  contrast probe (FR-14 there), which walks every element carrying its
  own text node; the values are not disabled controls, so WCAG's
  incidental exemption does not reach them and `aria-hidden` would be a
  lie about text an operator is meant to read. One step less faint still
  distinguishes the two states, and no new token is added — so the
  palette register stays pinned at three rows (0028 AC-12) and this
  divergence is recorded in the brief's "everything else" register,
  which no test reads and which exists for exactly this.

- FR-11: **The import preview names its textarea explicitly, and its
  endpoint has no parameter for a secret.** This form carries a CA
  private key and its passphrase, and a handler that debounces on
  keystrokes must ship neither to an endpoint that echoes what it
  parses. Three clauses, all three checkable:
  1. **The trigger.** The `hx-trigger` on `transfer_ca_import.html`'s
     aside names its sources: `keyup changed delay:400ms from:#cert_pem`
     and `keyup changed delay:400ms from:#chain_pem`. Neither
     `#key_pem` nor `#key_passphrase` is a trigger source, so typing a
     passphrase fires no request at all.
  2. **The payload.** `hx-include` names exactly
     `#csrf-ca-import, #cert_pem, #chain_pem` — three ids, written
     literally. `hx-include="closest form"` is **forbidden on this
     page**, and so is any selector that resolves to the form, to
     `[name=key_pem]` or to `[name=key_passphrase]`. The hidden CSRF
     input gains `id="csrf-ca-import"` so that the token can be included
     by name rather than by including the form that holds it.
  3. **The endpoint.** `POST /ca/import/preview` declares exactly
     `cert_pem` and `chain_pem` as `Form(...)` parameters (plus the
     `csrf_token` `verify_csrf` reads). There is no `key_pem` and no
     `key_passphrase` parameter, so no code path exists that could echo
     one, and a hand-built request carrying them is answered by a page
     that contains neither string.

  Clause 3 is what makes the no-JavaScript path safe as well. The
  round-trip button of FR-12 is a `<button formaction>` inside the form,
  so the browser posts **every** field including the key and its
  passphrase — one deliberate submit, to the same origin the mutation
  posts to, where they land in no parameter, are read by nothing, are
  written to no log and appear in no response. That is a real cost of
  the round-trip envelope and it is recorded rather than glossed: what
  the requirement forbids is a keystroke stream carrying a passphrase,
  and clause 1 is what forbids it.

- FR-12: **What each page does with JavaScript disabled, per panel.**
  Every form gains one tertiary `<button type="submit">` reading
  `Check`, inside the form it previews, carrying
  `formaction="<that page's preview URL>"` and `formmethod="post"`. The
  form's own `action` and `method` are unchanged and its primary button
  is unchanged. So:

  | Page                      | JavaScript off                                                                            |
  | ------------------------- | ------------------------------------------------------------------------------------------- |
  | `/certs/new`              | `Check` posts the form to `/certs/issue/preview` → the same page, panels filled, fields kept |
  | `/certs/sign`             | `Check` posts to `/certs/sign/preview` → the same page, `Parsed request` filled            |
  | `/ca/new`                 | `Check` posts to `/ca/create/preview` → the same page, `What gets created` filled           |
  | `/transfer/ca-import`     | `Check` posts to `/ca/import/preview` → the same page, `Parsed` filled                      |
  | `/transfer/cross-import`  | nothing to do: no panel, no htmx (FR-16)                                                    |
  | `/ca/{id}` disclosure     | the anchor is followed to `?add=intermediate`, which renders the panel open (FR-13)         |

  **`POST /certs/issue` and `POST /certs/sign` are untouched and never
  run through htmx**: no `hx-` attribute appears on either form element
  or on either primary button, and neither preview URL is either form's
  `action`. There is therefore no state in which the issue form silently
  does nothing — the failure this requirement exists to make impossible.
  AC-8 asserts it per page, by posting each preview URL with no
  `HX-Request` header and by asserting the primary path still works with
  no htmx involved at all.

- FR-13: **The disclosure becomes URL state.** _Supersedes spec 0024
  FR-8's corollary for two forms_ — `Add intermediate` and `Cross-sign
  with another root` on `ca_detail.html` — and _restores spec 0023 FR-8's
  second half and AC-3_ in the shape URL state gives them.

  `GET /ca/{ca_id}` gains one optional query parameter, `add`, whose
  recognised values are `intermediate` and `cross-sign`. Any other value
  renders the page with both panels closed and status 200 — an unknown
  parameter is a typo, not an error, which is the rule
  `certs_list`'s own `?status=` already follows
  (`certs_ui.py:292-293`).
  - **Closed** — the section keeps its `<h2>`, its `.help` line and its
    `id`; its value column holds one `<a>` whose `href` is
    `/ca/{id}?add=intermediate#add-intermediate` and which carries
    `hx-get` on the same URL, `hx-select` and `hx-target` on
    `#add-intermediate`, `hx-swap="outerHTML"` and `hx-push-url="true"`.
  - **Open** — the same section, same `id`, with the form that stands
    there today, unchanged in fields, action, method and CSRF.
  - `#add-intermediate` and the cross-sign section's `id` are stable
    across both states, so the empty state
    (`ca_detail.html:61`) still has something to point at. Its href
    gains the query — `/ca/{id}?add=intermediate#add-intermediate` — so
    that following it *opens* the form rather than scrolling to a
    closed one. Its text is unchanged.
  - Every re-render that carries a form error opens that form's own
    panel: `POST /ca/{root_id}/intermediate` failing `_name_error` or
    `_years_error` re-renders at 400 with `add=intermediate` open and
    the submitted values in the fields, which is spec 0023 AC-3's
    requirement in its new form.

  **Why this is better and not merely different.** 0024's objection was
  to `<details>`: an element used nowhere else in the project, whose
  state lived only in the browser, that could not be linked to, and that
  swallowed a re-filled form so completely that 0023 had to force
  `open` on it. URL state answers all four. What 0024 was actually
  defending — that an action on this page is a heading an operator can
  see without opening anything — is preserved exactly: the `<h2>` and
  the `.help` line are always rendered, in the left column, in the
  section order 0028 FR-4 fixed. Only the fields move behind a real
  link, and the design draws the same disclosure (brief §5.8: "a
  primary 'Add intermediate' that toggles an inline form panel").

  **`_detail_page` regains `open_form`** (Interface Contract), and this
  overturns 0024 FR-8's third clause and its own contract line. The
  parameter that was removed took a boolean each caller had to
  remember; the one that returns takes the value the URL already
  carries, and the GET handler reads it from the query string rather
  than deciding it.

  **The dashboard's notice does not change.** `#ca-no-issuer` keeps its
  fragment-free `/ca/{root_id}` href, which spec 0026 FR-17 pins and
  three assertions in `test_ca_names_and_actions.py` measure by exact
  membership.

- FR-14: **Wording is unchanged, and the exceptions are named here.**
  Every sentence, label, heading, help line and hint that exists on the
  six templates today is byte-identical afterwards. New copy exists —
  panels the project has never had cannot have existing copy — and it is
  enumerated, string by string, so that "new copy" cannot later mean
  "an edit to something that was already there":

  | String                                                                                                                              | Where                    | Source                                                            |
  | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------- |
  | `Check`                                                                                                                             | four forms               | new; the round-trip button of FR-12                                |
  | `Name constraints — checked before signing`                                                                                         | issue aside              | brief §5.5, verbatim                                               |
  | `Result`, `Expires`, `Chain`, `Key held by`, `cabin, encrypted at rest`                                                             | issue aside              | brief §5.5/§9.2, verbatim                                          |
  | `Parsed request`, `Subject`, `SANs`, `Key`                                                                                          | sign aside               | brief §5.6, verbatim                                               |
  | `What gets created`, `Root`, `Issuers`                                                                                              | create aside             | brief §5.10, verbatim                                              |
  | `Parsed`, `Parent`                                                                                                                  | import aside             | brief §5.11, verbatim                                              |
  | `Every name is inside what this issuer permits.`                                                                                    | issue aside              | new; the permitted verdict                                         |
  | `This issuer sets no name constraints, so any name it is asked for is permitted.`                                                    | issue aside              | new; the unconstrained verdict                                     |
  | `Requested N days; the issuing CA's own expiry is sooner, so this certificate would be valid only until X.`                          | issue aside              | `cert_detail.html:15-17`, with `is` → `would be`                   |
  | `Add an intermediate`, `Cross-sign with another root`                                                                               | `ca_detail.html` triggers | the existing empty-state link text and the existing `<h2>`         |
  | the sign page's constraint footnote                                                                                                 | sign aside               | brief §5.6                                                         |

  The refusal verdict is **not** in this table: it is
  `NameConstraintError`'s own message, rendered unchanged, which is both
  the sentence `POST /certs/issue` already shows for the same request
  and the only string guaranteed to agree with it.

  `ca_new.html:45`'s path-length hint moves into the panel column
  unchanged (FR-9); moving a sentence is not editing it, and AC-14
  compares multisets of text nodes, not positions.

- FR-15: **Every class this spec renders is defined here, and nothing
  else is.** Spec 0027 FR-18 and spec 0028 FR-10 settled the rule: a
  class is defined by the spec that first renders one, because
  `test_stylesheet_and_templates_agree_in_both_directions` fails in its
  reverse direction on a rule with no user. The seven this spec defines:

  | Class                     | First user                                                    |
  | ------------------------- | --------------------------------------------------------------- |
  | `.form-split`             | the value column of the four preview pages' `.section`         |
  | `.preview`                | the `<aside>` in that column                                    |
  | `.kicker`                 | every panel heading (0027 reserved it; this spec renders it)   |
  | `.kv`                     | the `auto minmax(0,1fr)` key/value grid inside a panel (§6.9)  |
  | `.checks`                 | the per-name list in the constraints panel                     |
  | `.mark-ok`, `.mark-bad`   | the ✓ and ✕ marks (brief §5.5)                                 |

  `.panel` (0028 FR-10), `.callout`, `.callout.warning`, `.note`,
  `.field`, `.hint`, `.actions`, `.mono` and `.scroller` are reused and
  not redefined. No new token: `.mark-ok` is `--accent`, which is
  4.71:1 on `--surface`, and `.mark-bad` is `--bad-fg`.

  _Supersedes spec 0028 AC-11's second clause_, which asserts that each
  of six reserved names has no rule in `cabin.css`. `.kicker` gets one
  here; the list becomes `.nav-count`, `.seg`, `.pill`, `.toggle`,
  `.flash` — five, and AC-13 asserts the five, so the clause keeps doing
  its job of stopping a later spec's components being defined "while we
  are in the file".

  **Status-like classes are written literally, never interpolated**
  (0028 FR-10, same reason): the mark is
  `{% if entry.ok %}mark-ok{% else %}mark-bad{% endif %}`, not a
  prefix glued to a value, or `.mark-bad` would be a rule with no
  literal user and the agreement test's reverse direction would fail.

  _Supersedes spec 0028 AC-14's census clause._ That criterion asserts
  that across the probe's page list the set of elements matching
  `[aria-hidden="true"]` is **exactly** the tree glyphs on `/ca`. The
  ✓/✕ marks carry the same attribute for the same reason — the verdict
  is in the words beside them and a screen reader announcing "check
  mark" adds nothing — so the census becomes "exactly the tree glyphs on
  `/ca` and the constraint marks on `/certs/new`". It is widened by
  naming a second user, not by dropping the count: the guard exists so
  that a third user has to be argued for in the spec that adds it.

- FR-16: **The cross-import page gets the split and no panel.** The
  design's §5.12 is a single column, `max-width: 620px`, with no aside —
  the only one of the five form pages drawn that way, because a cross
  certificate is checked against a root cabin already holds and the
  check is the import. `transfer_cross_import.html` therefore gains no
  `hx-` attribute, no `Check` button and no fifth endpoint. It is in
  this spec's boundary for its lead paragraph's width and nothing else.

- FR-17: **The new column is re-proved at both widths, in both
  schemes.** An aside beside a form is a second column on four pages
  that had one, which is the change that has broken the geometry before.
  The overflow probe (spec 0027 FR-3, repaired) runs over `/certs/new`,
  `/certs/sign`, `/ca/new`, `/transfer/ca-import`,
  `/transfer/cross-import` and `/ca/{root}?add=intermediate` at
  1440×1150 and 390×900, in the dark and the light stylesheet, with
  `bad == []` and `examined >= 20` per run — **with the panels filled**,
  not on a first GET, since a panel showing `—` is not the panel that
  can push a page sideways. A 200-character SAN and a full PEM subject
  are what the fixture feeds it.

  Below the split's breakpoint the aside stacks **after** the form, in
  source order: on a phone the operator meets the fields first and the
  verdict below them, and the tab order is the same order.

- FR-18: **Templates, the stylesheet and this spec's markdown are
  edited by a script through Bash, never with Edit/Write, and
  `git diff` is read after every change.** The PostToolUse formatter
  breaks Jinja tags apart — it has turned `{% if x == "y" %}` into
  `{% if x="" ="y" %}` — and it reflows markdown far outside the
  edited region, once turning a parenthetical containing a digit into a
  list marker. This has cost the project a debugging session seven times
  (0021 FR-13, 0023 FR-11, 0024 FR-10, 0025 FR-15, 0026 FR-18, 0027
  FR-25, 0028 FR-18). This spec rewrites six templates, writes a seventh,
  edits the stylesheet, and edits two markdown files under `docs/`.

## Interface Contract

### Routes

| Method | Path                     | Auth              | Change                                                       |
| ------ | ------------------------ | ----------------- | -------------------------------------------------------------- |
| POST   | `/certs/issue/preview`   | admin + CSRF      | **new**; previews `POST /certs/issue`; writes nothing         |
| POST   | `/certs/sign/preview`    | admin + CSRF      | **new**; previews `POST /certs/sign`; writes nothing          |
| POST   | `/ca/create/preview`     | admin + CSRF      | **new**; previews `POST /ca/create`; writes nothing           |
| POST   | `/ca/import/preview`     | admin + CSRF      | **new**; previews `POST /ca/import`; writes nothing           |
| GET    | `/ca/{ca_id:int}`        | session           | one optional query parameter, `add` (FR-13); same data        |

Every other route in specs 0023–0028's contracts is unchanged in path,
method, guard, CSRF rule, form fields, status codes and redirect target
— `POST /certs/issue`, `POST /certs/sign`, `POST /ca/create`,
`POST /ca/import`, `POST /ca/cross-import`,
`POST /ca/{root_id}/intermediate`, `POST /ca/{ca_id}/cross-sign`,
`/api/v1`, MCP, ACME and the CRL routes included.

Each preview's response body is a fragment with `HX-Request`, the page
without it (FR-3). Each returns 200 in both envelopes, including when
the input does not parse: a preview reports what it found, and reporting
"this is not a PEM block" is a successful preview of an unsuccessful
paste. The 4xx belongs to the mutation.

### `cabin.ca.leaf`

```python
def clamp_validity(
    issuer_cert: x509.Certificate, days: int, now: datetime
) -> tuple[datetime, datetime | None]: ...


def resolve_sans(
    explicit: Sequence[str], csr_sans: Sequence[str], subject_cn: str | None
) -> list[str]: ...
```

- **`clamp_validity` is new** (FR-6). It returns `(not_after,
  capped_from)`: `not_after` is `min(now + days, issuer_cert.not_valid_after_utc)`
  and `capped_from` is the requested `not_after` when it was not
  granted, else `None`. It raises `IssueError("the signing CA
  certificate has expired")` when `not_after <= now`. `now` is
  required and positional; the function reads no clock of its own.
- **`resolve_sans` is `_resolve_sans` renamed** (FR-5), body byte-for-byte
  unchanged, and **no alias is left behind** — a private name kept
  alongside the public one is two ways to call one function, which is
  how two callers end up on different sides of a later change. Its two
  existing call sites (`issue_certificate`, `sign_csr`) take the new
  name.
- **`_build_leaf` keeps its signature and its behaviour.** It computes
  `now`, calls `clamp_validity(issuer_cert, days, now)`, and continues
  exactly as it does today — the `check_name_constraints` call in
  particular stays inside it, in place (FR-6).
- `check_name_constraints`, `parse_san_lines`, `san_strings`,
  `constraints_of`, `issue_certificate`, `sign_csr` and every other
  public name are unchanged in signature and in body.

### `cabin.web.certs_ui`

```python
def _issue_preview(
    db: Session, principal: Principal, *, subject_cn: str, sans: str, issuer_id: int | None, days: int
) -> dict[str, object]: ...


def _sign_preview(csr_pem: str) -> dict[str, object]: ...
```

- **`_issue_preview` returns exactly seven keys and no others**:
  `issuer` (the issuer's name, or `None` when none resolved), `names`,
  `verdict`, `refused`, `expires`, `capped_from`, `chain`. `names` is a
  list of dictionaries with **exactly three keys** — `name`, `ok`,
  `note` — one per resolved SAN, in resolution order. `refused` is the
  whole-set call's outcome as a boolean and `verdict` the sentence
  beside it (FR-4). `expires` and `capped_from` are ISO-8601 strings or
  `None`, from `clamp_validity`. `chain` is the issuer's chain by name.
  A key is enumerated rather than summarised because spec 0024's
  contract once wrote "gains one flag … no other key changes" and that
  sentence was implemented faithfully into a defect that survived a
  green suite.
- **`_sign_preview` returns exactly four keys**: `subject`, `sans`,
  `key`, `error`. It parses and nothing else — no database, no issuer,
  no constraint check (FR-8).
- **`_form_page`, `_new_page`, `_sign_page`, `_no_issuer_message`,
  `_issuer_options`, `_cert_row`, `certs_issue`, `certs_sign`,
  `cert_detail`, `cert_revoke` and every other existing function are
  unchanged**, in signature and in body. The two new handlers reach the
  page envelope through `_new_page`/`_sign_page` with `values` filled,
  which is why the no-JavaScript envelope re-fills the form for free.
- `_pending_capped` is not touched. A preview computes `capped_from`
  and shows it; it never writes it into the hand-off dictionary the
  issuance route uses, which is keyed by a certificate id a preview does
  not have.

### `cabin.web.ca_ui`

```python
def _detail_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    status_code: int = 200,
    open_form: str | None = None,
) -> Response: ...


def _create_preview(*, name: str, key_type: str, root_years: int, path_length: int) -> dict[str, object]: ...
```

- **`_detail_page` regains `open_form`** (FR-13), keyword-only, default
  `None`, recognised values `"intermediate"` and `"cross-sign"`; it
  becomes the context key of the same name. Spec 0024 FR-8's contract
  line "`_detail_page` loses `open_form`" is the sentence this
  overturns. Nothing else about the function changes: same rows, same
  `_group`, same `values`, same status code.
- `ca_detail` (the GET) gains `add: str = ""` and passes it through
  after mapping an unrecognised value to `None` (FR-13).
  `ca_create_intermediate` and `ca_cross_sign` pass
  `open_form="intermediate"` / `open_form="cross-sign"` on their error
  re-renders, and are otherwise unchanged — same guards, same fields,
  same 400, same redirect on success.
- **`_create_preview` returns exactly five keys**: `root`, `expires`,
  `issuers`, `key`, `path_length`. It touches no database.
- `_child_view`, `_overview`, `_group`, `_row_view`, `_page_of`,
  `_name_error`, `_years_error`, `_new_page`, `ca_page`, `ca_create`
  and every other function are unchanged.

### `cabin.web.transfer_ui`

```python
def _import_preview(cert_pem: str, chain_pem: str) -> dict[str, object]: ...
```

- **Exactly four keys**: `subject`, `parent`, `key`, `error`. Two
  parameters, and **no parameter for a private key or a passphrase**
  anywhere on the preview path — the handler's own signature carries
  the same two names plus `csrf_token` (FR-11).
- `ca_import`, `ca_cross_import`, `_ca_import_page`,
  `_cross_import_page`, the trust-bundle, CA-key and inventory handlers
  are unchanged.

### `cabin.web.templates`

| File                        | Change                                                                                             |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| `form_macros.html`          | **new**; four macros, one per previewed page; extends nothing, defines no content block             |
| `certs_new.html`            | `.form-split` in the section's value column, the aside, the `Check` button                          |
| `certs_sign.html`           | the same, with the `Parsed request` panel                                                           |
| `ca_new.html`               | the same, with `What gets created` and the path-length note moved into the aside                    |
| `transfer_ca_import.html`   | the same, plus the explicit `hx-include`/`hx-trigger` of FR-11 and `id="csrf-ca-import"`            |
| `transfer_cross_import.html`| lead width only; no aside, no `hx-` attribute (FR-16)                                               |
| `ca_detail.html`            | the two action sections gain a closed state with a trigger anchor; ids unchanged (FR-13)            |

No template gains a `<details>`, a `<summary>` or a `<script>`. No
template's `nav_current` changes. `form_macros.html` is a macro library
in the sense `ca_macros.html` already is, and joins it in
`test_web_layout.NOT_PAGES` under the same checked exemption.

### `cabin.web.static/cabin.css`

The seven classes of FR-15, plus the `@media` rule that collapses
`.form-split` to one column. **No token is added and no colour literal
is written outside the two `:root` blocks** (spec 0027 FR-21). No
existing class is renamed: the eleven load-bearing names spec 0027 AC-16
pins survive untouched.

### Schema, services, API, MCP, ACME

Unchanged. No migration, no column, no enum value, no change to
`ca/service.py`, `ca/certs.py`, `api/`, `mcp/` or `acme/`. No audit
action: a preview is a read.

## Acceptance Criteria

Every criterion is anchored to the element, the computed value or the
call it is about — a parsed element, a computed style, a spy's call
list — never to a substring appearing somewhere in a page. Where a state
is meant to differ, both halves are in one criterion, so that a build
rendering nothing and a build rendering everything each fail.

The fixture, unless stated otherwise: hierarchy **alpha** — a root and
one intermediate whose `NameConstraints` permit `lan.example.test` and
`10.0.0.0/8` and exclude `secret.lan.example.test` — and hierarchy
**beta** with an unconstrained intermediate, so that both branches of
FR-4's verdict have a fixture.

- AC-1: **Every `hx-` target answers a full page without the header.**
  A test walks every file in `src/cabin/web/templates/`, parses out
  every `hx-get` and `hx-post` value, and for each one issues that
  method against that URL **with no `HX-Request` header** as an admin
  with a valid CSRF token: the response is 200, its body contains
  `<html`, the rail (`<aside class="rail">`) and `<main id="main">`, and
  it is at least ten times the length of the same request made **with**
  the header. The set of URLs found is asserted non-empty and its size
  asserted equal to the number this spec introduces, so that a build
  that renders no `hx-` attribute at all cannot pass by finding nothing.
  _Goes red if_: an endpoint is written fragment-only. **Nothing else in
  the suite would notice**: every other test that touches a preview
  sends the header or asserts on the fragment, and a fragment-only
  endpoint renders perfectly in a browser with JavaScript on.

  > **Correction (test-authoring):** the tenfold clause applies to the
  > **four previews only** and cannot apply to the two `hx-get` targets
  > FR-13 adds. FR-2 clause 2 makes those URLs pages that htmx narrows
  > client-side with `hx-select`, and FR-3 says the previews are the
  > only endpoints this spec adds — so `GET /ca/{id}?add=intermediate`
  > answers the same bytes with the header and without it. Requiring a
  > size difference there would force exactly the fragment-aware
  > disclosure endpoint FR-2 forbids two requirements up, in the
  > criterion written to protect that rule.
  >
  > The `hx-get` targets are held to the stronger statement of clause 2
  > instead: the response with `HX-Request` and the response without it
  > are **byte-identical**. Everything else in this criterion is
  > unchanged and applies to all six URLs — 200, `<html`, the rail,
  > `<main id="main">`, and the set of targets being exactly the six
  > this spec introduces.

- AC-2: **The attribute set is closed and the ADR exists.** Across all
  templates, the set of `hx-*` attribute names used is a subset of the
  eight FR-2 allows, and contains no `hx-on` prefix; no template
  contains `<script`; `src/cabin/web/static/` contains exactly one
  `.js` file that any template links, `htmx.min.js`. In the same test,
  `docs/adr/0003-url-state-disclosure-and-htmx.md` exists, carries the
  `Status`/`Date`/`Deciders` header lines and every `##` heading of
  `docs/adr/0000-template.md`, and names each of the five rejected
  options FR-2 lists.
  _Goes red if_: `hx-boost` is added to the layout "to make navigation
  feel faster", which would turn every link in cabin into a fragment
  swap and is the single change that would make this rule meaningless.

  > **Correction (test-authoring), two clauses of this criterion:**
  >
  > **"no template contains `<script`" is false today and must stay
  > false.** `layout.html:9` has loaded htmx from a `<script>` element
  > since spec 0015 — the very lines this spec's own Context cites as
  > `layout.html:8-9`. No build can satisfy the clause as written. FR-2
  > clause 4's wording is the satisfiable one and is what is asserted:
  > no template *gains* a `<script>` element. Pinned rather than
  > counted, because a count alone would pass on a build that moved it —
  > exactly one `<script>` across all templates, in `layout.html`, with
  > `src="/static/htmx.min.js"`.
  >
  > **"contains exactly one `.js` file" is false read literally.**
  > `src/cabin/web/static/` also holds `swagger-ui-bundle.js`, vendored
  > for `api/v1.py`'s docs page. The qualifier "that any template links"
  > is what makes the clause true, and it is the whole of the clause:
  > the set of `/static/*.js` paths any template references is exactly
  > `{htmx.min.js}`. Written out here rather than left for the reader to
  > notice, because the literal reading sends an implementer looking for
  > a vendored file to delete.

- AC-3: **The panel agrees with the signer where a per-name loop
  cannot.** Both halves, one test, against alpha's constrained issuer:
  1. `subject_cn = "secret.lan.example.test"`, SANs `10.0.0.5` only.
     `POST /certs/issue/preview` marks its one name **✓** (the IP is
     permitted), and the panel's verdict says the request would be
     **refused**, carrying `NameConstraintError`'s own message. The same
     inputs to `POST /certs/issue` return 400 with that same message,
     and `select count(*) from certificates` is unchanged.
  2. `subject_cn = "secret.lan.example.test"`, SANs `nas.lan.example.test`.
     The preview marks the name ✓ and the verdict says **permitted** —
     because a DNS SAN exists, the excluded CN is not checked — and
     `POST /certs/issue` with the same inputs returns 303 and writes a
     row.

  In the same test, `leaf.check_name_constraints` is wrapped in a
  recording spy: the preview calls it exactly `len(names) + 1` times,
  the last call's arguments are `(issuer_cert, subject_cn, resolved)`
  with `resolved` equal to `leaf.resolve_sans`'s output for those
  inputs, and each earlier call's second argument is `None`.
  _Goes red if_: the verdict is computed from the marks (clause 1 says
  permitted while issuance refuses — the defect this spec exists to
  prevent), or if the panel refuses whenever the CN is excluded
  regardless of the SAN list (clause 2 says refused while issuance
  succeeds), or if the check is re-implemented in the web layer (the
  spy sees no calls at all).

- AC-4: **The stated expiry is the granted expiry, measured against a
  certificate that was actually issued.** Two halves, one test:
  1. **Clamped.** Against an issuer whose own `not_valid_after` is
     nearer than the request, `POST /certs/issue/preview` with
     `days = 3650` states an expiry, and `POST /certs/issue` with the
     same inputs produces a certificate whose `not_valid_after_utc`
     equals that stated expiry **exactly**; the preview renders the
     clamp note and the response to a preview one day inside the
     issuer's window does not.
  2. **Not clamped.** With `days = 30` against a long-lived issuer, the
     stated expiry and the issued certificate's `not_valid_after_utc`
     agree to within five seconds — the wall time between two HTTP
     requests — and no clamp note is rendered.

  Neither half calls `clamp_validity`. The comparison is between a
  rendered panel and a stored certificate.

  **Both halves compare a moment, not a day.** `Expires` is rendered
  from the `expires` key, which the Interface Contract makes an ISO-8601
  string; "equals that stated expiry **exactly**" and "agree to within
  five seconds" are both unachievable at date granularity. This is the
  one place on these pages where the `str(datetime)` and date-only
  formatting every other cabin page uses is the wrong reach, and it is
  said here because here is where an implementer will be looking.
  _Goes red if_: the panel reads its own clock differently, forgets the
  issuer's own expiry, or renders the requested rather than the granted
  date. A criterion that compared the panel with `clamp_validity` a
  second time would pass on every one of those.

- AC-5: **A preview writes nothing and unseals nothing.** With
  `ca_service.signing_credentials`, `audit.record` and
  `cabin.ca.certs._store` wrapped in counting spies, one POST to each of
  the four preview URLs calls each spy **zero** times; the row counts of
  `certificates`, `ca_certificates` and `audit_events` are unchanged
  across all four; and in the same test each of the four responses is
  200 and its panel contains a value that is not `—`, so a build that
  does no work cannot pass by doing nothing.
  _Goes red if_: the issue preview reaches for `signing_credentials` to
  get the issuer's certificate — the panel would look identical and
  every keystroke would decrypt a CA private key.

- AC-6: **Each preview is guarded exactly like its mutation.** For each
  of the four preview URLs and its mutation, four requests, asserted
  pairwise equal in status: anonymous (redirect to `/login`), a
  `viewer`-role session (403), an admin with no `csrf_token` (403), an
  admin with a wrong one (403). Then, on `/certs/issue/preview` only:
  an admin granted no issuer, and an admin naming an issuer they are not
  granted, get the same status the corresponding `POST /certs/issue`
  gives (403), and the response body contains no issuer name they are
  not granted.
  _Goes red if_: a preview is registered without `verify_csrf`, or with
  `get_current_user` in place of `require_admin` — either is invisible
  to every other test here, all of which run as an admin.

- AC-7: **One macro, two envelopes, proved by comparison.** For each of
  the four previews, the same POST is made twice, with and without
  `HX-Request: true`. The fragment response: 200, `text/html`, contains
  no `<html`, no `<aside class="rail">`, and its stripped body appears
  **verbatim** inside the full response's body. The full response: 200,
  is the form page (its `<form>` with the mutation's own action is
  present), and every field the request submitted is re-filled with what
  was submitted.
  _Goes red if_: the fragment is rendered by a second template that
  drifts from the page's — the substring assertion is what makes "one
  code path" a measurement rather than a claim.

- AC-8: **No page silently does nothing with JavaScript off.** For each
  of `/certs/new`, `/certs/sign`, `/ca/new` and `/transfer/ca-import`:
  the page contains exactly one `<button type="submit">` whose
  `formaction` is that page's preview URL and whose `formmethod` is
  `post`; the form element itself carries no `hx-` attribute and its
  `action` is the mutation's URL; and the primary button carries no
  `formaction`. Then, with no `HX-Request` header anywhere in the test,
  the `Check` button's POST is replayed and the returned page's panel
  carries real content. Finally `POST /certs/issue` is exercised in the
  same test with the same values and returns 303 with a row written.
  _Goes red if_: the primary button is repointed at a preview URL, or
  the panel is only reachable through htmx — in which case the
  no-JavaScript operator sees a page whose only feedback never arrives.

- AC-9: **The import preview ships no secret.** Three clauses, one test:
  1. **Parsed from the template.** `transfer_ca_import.html`'s `hx-include`
     value is exactly `#csrf-ca-import, #cert_pem, #chain_pem`; its
     `hx-trigger` value names `#cert_pem` and `#chain_pem` and neither
     `key_pem` nor `key_passphrase`; the string `closest form` does not
     appear anywhere in the file.
  2. **Read off the signature.** `inspect.signature` of the
     `POST /ca/import/preview` handler has no parameter named
     `key_pem` or `key_passphrase`.
  3. **Measured as effect.** A preview POST carrying a real encrypted
     private key PEM and the passphrase `hunter2` as extra form fields
     returns 200, and neither the passphrase nor any line of the key PEM
     appears in the response body; `audit_events` gains no row.
  _Goes red if_: `hx-include` is later widened to `closest form`
  "so the panel can show the key type too" — clause 1 catches it, and
  clauses 2 and 3 are what stop the endpoint growing a parameter that
  would make the widening tempting.

- AC-10: **The sign panel parses, and says so when it cannot.** On
  `POST /certs/sign/preview` with a real CSR, the panel's `Subject`
  contains the CSR's CN and its `SANs` contains one element per entry of
  `leaf.san_strings` over the CSR's SAN extension. With `csr_pem="not a
  csr"`, the response is **200**, the panel names the failure, and the
  page's own error box (the one `POST /certs/sign` fills) is absent.
  With `csr_pem=""` all three values are `—`.
  _Goes red if_: an unparsable paste 400s or raises — a preview that
  fails on bad input fails on every keystroke of a half-typed one.

- AC-11: **The create panel and its two tones.** `POST /ca/create/preview`
  with `path_length=2` renders a note whose element carries `callout`
  and not `warning`; with `path_length=1`, one carrying both. Both
  responses' `What gets created` panel names the submitted name, a key
  type equal to the submitted one, and an expiry whose year is the
  current year plus `root_years`. Both halves in one criterion, because
  a build that renders one tone always would otherwise pass.
  _Goes red if_: the tone is decided in the stylesheet from a value the
  template interpolates — which would also make `.warning` a rule with
  no literal user and fail AC-13.

- AC-12: **The disclosure is URL state, in both directions.** On
  `GET /ca/{alpha_root}` as an admin: the element with
  `id="add-intermediate"` exists, contains an `<h2>` reading
  `Add intermediate`, contains **no** `<form>`, and contains exactly one
  `<a>` whose `href` is `/ca/{alpha_root}?add=intermediate#add-intermediate`
  and which carries `hx-get`, `hx-select="#add-intermediate"` and
  `hx-target="#add-intermediate"`. On
  `GET /ca/{alpha_root}?add=intermediate`: the same element exists with
  the same id, contains the `<form>` whose action is
  `/ca/{alpha_root}/intermediate` with every field it carries today, and
  the cross-sign section is still closed. `GET /ca/{alpha_root}?add=banana`
  returns 200 with both closed. Then `POST /ca/{alpha_root}/intermediate`
  with `name="   "` returns 400 and its body has the panel **open** with
  the submitted `key_type` and `years` still in the fields — spec 0023
  AC-3's requirement, restored. In the same test the page contains zero
  `<details>` and zero `<summary>` elements.
  _Goes red if_: the trigger is a `<button>` or a `#`-only anchor (no
  URL, nothing to follow without JavaScript), if the id moves with the
  state (the empty state's link and the swap target both break), or if
  the error re-render lands on the closed page, which is the defect
  0023 AC-3 was written for.

- AC-13: **The stylesheet and the templates agree, in both directions.**
  `test_stylesheet_and_templates_agree_in_both_directions` passes over
  the full page list with no addition to its `tag-*` exemption list.
  In the same test, `.kicker` has a rule and a literal user, and each of
  `.nav-count`, `.seg`, `.pill`, `.toggle` and `.flash` still has **no**
  rule in `cabin.css`.
  _Goes red if_: a mark class is written as `mark-{{ … }}`, or spec
  0030's components are defined here.

- AC-14: **Not one existing sentence changed.** For each of the six
  templates' pages, the multiset of non-empty visible text nodes is
  compared against the same page rendered through the templates as they
  stood at this spec's base commit, on one instance with one database.
  Nothing is lost: every text node present before is present after with
  the same multiplicity, with **no** permitted removals. Every addition
  is named, per page, from FR-14's table plus the fixture's own values
  (names, dates, subjects) — an addition not in the list fails.
  _Goes red if_: a heading is "improved" while the markup around it is
  rewritten, which fails both halves at once. This is the change that
  costs several hundred text assertions and that no other criterion here
  would see.

  > **Correction (test-authoring):** "no permitted removals" holds for
  > five of the six pages and cannot hold for `ca_detail`. FR-13 is a
  > disclosure: on `/ca/{id}` with no `add=`, the intermediate form's
  > five labels, its two hints and its button are deliberately not
  > rendered, so a text node present at the base commit is absent from
  > that URL by construction. That is the requirement working, not a
  > wording change, and no build can have both.
  >
  > What FR-14 protects is that no sentence on this page was edited or
  > dropped — and the page is now three URLs. So for `ca_detail` the
  > multiset compared against the base commit is the **union** of the
  > closed render, `?add=intermediate` and `?add=cross-sign`, taking the
  > larger multiplicity of each. Nothing is weakened by it: a sentence
  > absent from all three still fails, and every addition is still
  > named. The other five pages are one URL each and are compared
  > exactly as written above.

- AC-15: **Nothing scrolls sideways and everything is readable, with
  the panels filled.** The overflow probe over the five form pages and
  `/ca/{root}?add=intermediate`, at 1440×1150 and 390×900, in both
  stylesheets, `bad == []` and `examined >= 20` per run, with each
  preview filled by a preceding POST rather than left at `—`. The
  contrast probe over the same pages in both schemes reports
  `bad == []`, which covers the ✓ and ✕ marks on `--surface` and the
  dim unparsed values of FR-10. At 390 the aside's `offsetTop` is
  greater than the form's, and at 1440 it is not.
  _Goes red if_: a long SAN or a PEM subject in a fixed-width aside
  pushes the page out — the one thing a two-column form adds — or if the
  design's `#5a5d6b` is shipped for the dim values after all.

- AC-16: **The design's numbers and the palette are untouched.**
  `test_the_twelve_numbers`, `test_the_palette_equals_the_checked_in_brief`
  and `test_no_colour_outside_the_token_blocks` pass unmodified, and the
  palette divergence register still has **exactly three rows**. The
  entry FR-10 adds goes to the "everything else" register, which the
  test does not read.
  _Goes red if_: a colour is written into a new rule instead of taken
  from a token, or the palette register is widened to launder one.

- AC-17: **Focus is visible on everything this spec adds.** Spec 0027
  AC-11's probe over the five form pages: every focusable element has a
  computed outline whose style is not `none` and whose width is at least
  2px, including the four `Check` buttons and the two disclosure
  anchors, and `cabin.css` contains no `outline: none` and no
  `outline: 0`.

- AC-18: **Everything that was not this spec's subject still works.**
  The 0003–0028 suite passes: every route, guard, CSRF rule, form field,
  redirect and audit event is unchanged; every page still renders 200;
  the API, MCP, ACME, the CRL and cabin's own TLS are untouched. In
  particular `test_ca_leaf.py`'s clamp and constraint tests pass
  unmodified against the extracted `clamp_validity` and the renamed
  `resolve_sans`. The only test changes are the ones the Test list
  names.

## Test list

**New**, in `tests/test_web_form_previews.py` unless noted:

test_every_hx_target_answers_a_full_page (AC-1),
test_the_htmx_attribute_set_is_closed_and_the_adr_exists (AC-2, in
`tests/test_web_design_shell.py`),
test_the_constraint_panel_agrees_with_the_signer (AC-3),
test_the_panel_expiry_is_the_issued_expiry (AC-4),
test_a_preview_writes_nothing_and_unseals_nothing (AC-5),
test_each_preview_is_guarded_like_its_mutation (AC-6),
test_one_macro_two_envelopes (AC-7),
test_the_forms_work_with_javascript_off (AC-8),
test_the_import_preview_ships_no_secret (AC-9),
test_the_sign_panel_parses_and_says_when_it_cannot (AC-10),
test_the_create_panel_flips_tone_with_path_length (AC-11),
test_the_disclosure_is_url_state (AC-12, in
`tests/test_ca_issuer_pages.py`),
test_the_reserved_classes_are_still_reserved (AC-13, extended in
`tests/test_web_design_shell.py`),
test_no_sentence_changed_on_the_form_pages (AC-14),
test_the_form_pages_do_not_scroll_sideways (AC-15, headless Chrome),
test_clamp_validity_matches_what_build_leaf_did (in
`tests/test_ca_leaf.py`, against a signed certificate, not against the
helper),
test_the_panel_resolves_an_ip_common_name_the_way_the_signer_does (FR-5)

That last one has no acceptance criterion of its own and is listed
anyway. FR-5 is the only requirement in this spec argued entirely from a
case no criterion exercises — AC-3's two halves both run against alpha,
where the shortcut and the signer agree — so without it the rename is
the one change here whose reason nothing measures. It is the fixture the
correction under FR-5 describes.

**AC-2's ADR half is green before any implementation, and this records
it.** `docs/adr/0003-url-state-disclosure-and-htmx.md` was committed
alongside this spec, so its existence, its `Status`/`Date`/`Deciders`
lines, every `##` heading of `docs/adr/0000-template.md` and all five
rejected options already pass at the base commit; only the attribute
allowlist and the `<script>` clause of that test go red. A criterion
that passes at the moment it is written is worth saying so about: it is
measuring the record rather than the work, and nothing an implementer
does can make it fail. It stays in the test because the record can be
edited later, which is the only thing it can still catch.

**Re-pointed** — the requirement is unchanged, the selector or the page
it is read from moved:

- **`tests/test_web_layout.py:36` `NOT_PAGES`** protects that every
  content template names itself to the rail. It gains
  `form_macros.html`, and the checked exemption below it — which today
  names `ca_macros.html` literally — becomes a loop over both, asserting
  of each that it extends nothing and defines no content block. The
  exemption stays as narrow as spec 0026 AC-18 made it: a real page
  smuggled into the set is still the only way it can do harm, and it is
  still checked rather than trusted.
- **`tests/test_ca_issuer_pages.py:1200`** protects that the empty state
  points at the section that fixes it. Its assertion that
  `"#add-intermediate" in admin_note.anchor_hrefs` becomes: exactly one
  href, ending in `#add-intermediate` and containing `add=intermediate`
  (FR-13). The requirement is unchanged and tightened: the link must now
  *open* the form, which the fragment alone did not.
- **`tests/test_ca_issuer_pages.py:1095, 1202-1204`** protect that the
  target of that link exists and sits below the empty state. Unchanged
  in substance; re-verified against both the closed and the open state,
  since the id is now rendered by two branches instead of one.
- **`tests/test_ca_names_and_actions.py`'s detail-page assertions**
  about the intermediate and cross-sign forms protect spec 0024 FR-8.
  Each is re-pointed at `GET /ca/{id}?add=intermediate` (or
  `?add=cross-sign`) — the URL at which that form now stands open. What
  each asserts about the form is unchanged. The `<details>`/`<summary>`
  absence assertions at `:1079` and `:1237` are **not** re-pointed and
  must pass on both states.

**Strengthened** — the requirement grows:

- **`tests/probes.py`, `CONTRAST_PROBE`** protects spec 0027 FR-14. Its
  `[aria-hidden="true"]` skip now has a second user, and AC-15's census
  (0028 AC-14, widened by FR-15) names it. It could not previously catch
  a mark rendered in an unreadable colour, because no mark existed.
- **`tests/probes.py` gains `STACK_PROBE`.** AC-15's last clause — the
  aside's `offsetTop` above the form's at 390 and not at 1440 — is
  geometry no existing probe reports, and the overflow and contrast
  walkers cannot answer it: both are blind to source order. It follows
  the rule FR-4 of spec 0027 set for every probe in that file and
  reports `examined` alongside its pairs, so a page carrying no
  `.form-split` at all is distinguishable from one that stacks
  correctly. `tests/probes.py` is where it goes because a second copy of
  a browser probe is what spec 0027 FR-2 exists to prevent.
- **`tests/test_ca_issuer_pages.py`'s `_baseline_templates` gains a
  `ref` parameter**, defaulted to the constant it reads today, so
  AC-14's comparison uses that instrument against this spec's base
  commit instead of a second copy of it. Spec 0028's own criterion is
  unaffected — it passes no argument and gets the same commit it always
  did.
- **`tests/test_ca_leaf.py`'s clamp tests** protect spec 0017 FR-5/FR-7:
  a leaf never outlives its issuer, and `capped_from` is not
  re-derivable from the certificate. They now also exercise
  `clamp_validity` directly with a pinned `now`, which the old tests
  could not do at all — `_build_leaf` read the clock itself.

**Deleted: none.**

## Out of Scope

**No version bump.** Everything stays 0.2.0 and PR #17 stays open. The
change is UI-visible and gets its entry under `[Unreleased]` in
`CHANGELOG.md`, which is the project's workflow rather than a
requirement of this spec.

**No schema change, no migration, no API, MCP or ACME change.** A
preview is a read of state that already exists, through guards that
already exist.

**No verdict on the sign page** (FR-8). The design draws a footnote
there, not a checker, and a verdict computed from a CSR's own SANs while
`sans_override` may replace them would disagree with the signer — the
one thing FR-4 exists to prevent. If it is wanted later it is a small
spec of its own, and its acceptance criterion is AC-3's shape.

**No segmented control for `Profile`** (brief §5.5), and `.seg` stays
reserved. The `<select>` renders `list(Profile)`, so a two-option
control would hard-code an enum's cardinality into markup, and the
change buys nothing an operator can act on.

**No "Paste an example" / "Paste a sample CSR" buttons** (brief §5.5,
§5.6). They need example data to exist server-side and a decision about
what a good example CN is on somebody else's network. Declined, not
forgotten.

**No busy state on the primary buttons** ("Issuing…", "Generating
keys…", brief §5.5/§5.10). The label change is a client-side mutation of
a form being submitted, which is JavaScript this spec's rule has no
route-shaped answer for, and the operations really are slow — so a
disabled-looking button that is not disabled would be the worst of the
options.

**No htmx anywhere else.** The Users inline row edit and the inventory's
filters are the same idiom (brief §9.3, §9.6) and belong to spec 0030,
which reuses this spec's rule and this spec's ADR without restating
either.

**No `<details>`, ever** (0026 FR-16's first half, 0024 FR-8). The
disclosure this spec adds is a URL, an anchor and a server-rendered
branch; nothing about it is a browser-held open state.

**No second JavaScript file, no inline `<script>`, no `hx-on`.** The
attribute allowlist of FR-2 is the whole surface, and widening it is a
spec with an ADR of its own.
