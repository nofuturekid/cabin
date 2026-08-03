# Spec 0016 — Dashboard

## Context

`GET /` has been a stub since spec 0003, which called it that in as many
words. It shows the signed-in user's name and role, the cabin version, and —
when no CA exists yet — a link to `/ca`. Spec 0015 moved the name, the role
and the version into the navigation rail, so the page's entire remaining
content is a warning that is only true in the first five minutes after
installation.

Meanwhile the question an internal CA actually gets asked is not on any page:
**what is about to stop working?** The inventory can answer it, but only if
someone thinks to filter by `status=expiring`. Nothing at all surfaces the two
expiries that take real work to fix — the intermediate's and the root's — and
nothing says whether the published CRL is still inside its validity window,
which is the difference between clients seeing revocations and clients
silently trusting a revoked certificate.

This spec makes `/` the page an operator opens first: what expires soon, what
the CA's own clock looks like, whether revocation is being published, which
services are on, and what happened last. It adds no new capability — every
number is something the operator could already have found by hand.

## User Stories

- As an operator, I open cabin and see immediately which certificates expire
  in the next 30 days, without constructing a filter.
- As an operator, I am warned about my intermediate and root expiring long
  before it becomes an emergency, because replacing them is not a five-minute
  job.
- As an operator, I can tell at a glance whether the CRL clients fetch is
  still current, or whether it went stale and revocations are not reaching
  anyone.
- As an operator, I see whether ACME and MCP are on, and whether the base URL
  they depend on is actually set.
- As a viewer, I see the same page minus the parts my role cannot see
  elsewhere — the dashboard must not become a way around authorisation.

## Functional Requirements

- FR-1: `GET /` renders a dashboard for any authenticated user. It is composed
  of the spec 0015 primitives; it introduces no new layout of its own beyond a
  `.tiles` grid for the summary counts.
- FR-2: **Expiring soon.** A table of certificates whose status is `expiring`
  (`not_after` within 30 days and not yet past, the existing
  `certificate_status` definition, revoked ones excluded), soonest first, at
  most 10 rows, each linking to its detail page and showing CN, SANs count,
  and the days remaining. Below it, a link to `/certs?status=expiring` when
  more exist than are shown. When none do, the section says so plainly rather
  than rendering an empty table.
- FR-3: **Inventory summary.** Four counts — valid, expiring, expired, revoked
  — each linking to the inventory pre-filtered to that status. Backed by a new
  `cabin.ca.certs.status_counts(db, now) -> dict[str, int]` that reuses the
  same `_filters` the inventory uses, so a count and the list it links to can
  never disagree.
- FR-4: **The CA's own expiry.** Intermediate and root with their
  `not_after` and the days remaining, warning-tagged at 365 days or fewer and
  danger-tagged once expired. When no CA is configured the whole dashboard is
  replaced by the existing "set up your CA" prompt, as today.
- FR-5: **Revocation.** The stored CRL's number, when it was generated and its
  `next_update`. Danger-tagged when `next_update` is in the past — the CRL
  clients hold is then stale and revocations are not reaching them. Also shows
  the distribution URL, or says that none is published because no base URL is
  set. When no CRL has been generated yet, says that instead.
- FR-6: **Services.** Whether ACME and MCP are enabled and whether a base URL
  is set, with an explicit warning for the combination "enabled but no base
  URL", which is the one that silently does not work. **This section is
  rendered only for roles that may see `/settings`** — the same
  `nav.settings` flag the rail uses. A viewer must not learn the
  configuration from the dashboard that they are refused on the settings page.
- FR-7: **Recent activity.** The five newest audit events (actor, action,
  summary, time) via the existing `audit.list_events(db, page=1, per_page=5)`,
  linking to `/audit`. Shown to any authenticated user, because `/audit` is
  open to any authenticated user.
- FR-8: Every figure is derived at request time from one clock passed through
  the whole view, so counts, badges and "days remaining" on one render cannot
  straddle a tick — the same rule spec 0006 established for the inventory.
- FR-9: No new dependency, no new table, no background job. The dashboard is a
  read-only projection of what the database already holds.

## Acceptance Criteria

- AC-1: With certificates at +5d, +20d, +90d, one expired and one revoked, the
  dashboard lists exactly the two expiring ones, soonest first, and the counts
  read valid=1, expiring=2, expired=1, revoked=1.
- AC-2: Each of the four counts links to `/certs?status=<that status>`, and
  following the link yields exactly that many rows.
- AC-3: With 12 expiring certificates, 10 are listed and a link to
  `/certs?status=expiring` is shown; with none, the section says so and no
  table is rendered.
- AC-4: An intermediate expiring in 300 days is warning-tagged; one expiring
  in 400 days is not; an expired one is danger-tagged.
- AC-5: A CRL generated 8 days ago (validity is 7) is danger-tagged as stale;
  one generated an hour ago is not. With no CRL row, the section says none has
  been generated.
- AC-6: A viewer's dashboard contains no services section — not the ACME
  state, not the MCP state, not the base URL — while an admin's does. A viewer
  still sees expiring certificates, the counts, the CA expiry and recent
  activity.
- AC-7: With ACME enabled and no base URL, the services section warns; with
  both set, it does not.
- AC-8: With no CA configured, `/` shows the setup prompt and none of the
  sections, and does not raise.
- AC-9: `status_counts` agrees with `list_certificates` for every status at
  the same instant, including at the exact 30-day boundary.

## Test list

test_dashboard_lists_expiring_soonest_first,
test_dashboard_counts_match_inventory, test_status_counts_boundary_30d,
test_status_counts_agree_with_list_certificates,
test_dashboard_caps_expiring_list_at_ten,
test_dashboard_empty_expiring_says_so, test_dashboard_ca_expiry_warning,
test_dashboard_ca_expired_is_danger, test_dashboard_crl_stale_is_danger,
test_dashboard_crl_absent_says_so, test_dashboard_hides_services_from_viewer,
test_dashboard_warns_acme_enabled_without_base_url,
test_dashboard_without_ca_shows_setup_prompt,
test_dashboard_recent_activity_lists_five

## Out of Scope

Charts and graphs. Any write action from the dashboard. Notifications, email
or webhooks on expiry — this spec surfaces the state, it does not act on it.
Auto-renewal. A per-user configurable layout. Changing the 30-day `expiring`
definition, which spec 0006 set and the inventory shares. OCSP, which cabin
does not have.
