# Spec 0019 — ACME per Issuer

## Context

Spec 0017 gave cabin several hierarchies. Spec 0018 gave every identity a
set of issuers it may sign with — and exempted ACME from it, in writing, at
the top of that document and twice more. The reason was not laziness:
`acme/api_finalize.py:238` issues on behalf of an ACME account, and an ACME
account is a key thumbprint. There is no `users.id`, no `api_tokens.id` and
nothing else to look a grant up by, so `issuer_grants.ACME_PRINCIPAL` was
introduced as an unrestricted principal with a name rather than a missing
argument.

The consequence 0018 wrote down and accepted: **on an instance with ACME
switched on, an admin holding no grant at all can obtain a certificate** by
registering an ACME account and running an ordinary order, from whichever
issuer 0017's default rule happens to pick. Its Out of Scope section says
this is 0019's to close. This is that document.

**Two mechanisms, deliberately separate.** The URL selects the issuer; the
EAB key authorises it. A directory per issuer is what makes "which CA do I
want a certificate from" a thing a client can express at all — every ACME
client already takes exactly one directory URL and nothing else. The EAB
key is what makes it a thing an operator decided. Either alone is
insufficient: a URL is public and anybody can type it, and an EAB key with
no URL to spend it at would be a credential naming a CA that the protocol
gives it no way to reach. Both, together, produce a chain that starts at a
grant and ends at a certificate.

**Only two paths gain an issuer segment.** All ACME paths are constants in
`acme/http.py:44-62`, and they fall into two groups. The five protocol
entry points — `directory`, `new-nonce`, `new-account`, `new-order`,
`key-change`, `revoke-cert` — are fixed URLs a client is told about. The
five resource prefixes — `ACCOUNT_PREFIX`, `ORDER_PREFIX`, `AUTHZ_PREFIX`,
`CHALLENGE_PREFIX`, `CERT_PREFIX` — are opaque object URLs, an unguessable
random id appended to a prefix (`service.new_id`, 128 bits). **The claim
that those already know their issuer was checked against the code and
holds**, by following each one to the row it authorises against:

- `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/chal/{id}` all end at
  `owned_order` (`http.py:253-260`), which compares `order.account_id`
  against the account the JWS resolved. The account is the issuer's holder
  under FR-5, so the order's issuer is the account's.
- `/acme/account/{id}` and `/acme/account/{id}/orders` are the account
  itself (`own_account_or_403`, `http.py:263-265`).
- `/acme/cert/{id}` resolves through `order_for_certificate`
  (`api_finalize.py:316`) to the same account, and the chain it serves is
  built from `row.issuer_id` on the certificate itself
  (`api_finalize.py:339`) — a column 0017 already added, so this path was
  per-issuer before this spec started.

`new-order`, `key-change` and `revoke-cert` are POSTs in `kid` mode: the
JWS names the account and `jws.verify_request` resolves it before the route
body runs (`jws.py:419-422`). They know the issuer for the same reason.
`new-nonce` has no issuer and needs none — a nonce is a token against
replay, not a capability.

That leaves exactly two paths where the issuer is genuinely not derivable
from anything the request already carries: the **directory**, which is read
before any account exists, and **new-account**, which is the request that
creates one. Those two get the segment. Nothing else does, and the smaller
change is not a compromise — it is the correct one.

**There is no backward compatibility to preserve.** Migrations `0008` and
`0009` are rewritten in place rather than added to, and `/acme/directory`
disappears with no alias. cabin has no deployed instances and `~/cabin-data`
has been deleted; a v0.1.0 database cannot be brought forward by any of the
0.2.0 specs, and this one adds nothing to that cost.

**What this spec cannot close, stated up front** so it is not discovered as
a surprise in FR-12. An ACME account is anonymous by construction, and
`acme_require_eab` is a switch an operator can leave off. With it off,
anybody who can reach the port can register an account at any issuer's
directory and order from it — no EAB key, no operator decision, no grant.
0019 makes the grant chain real and it makes it enforceable; it does not
make it unavoidable. FR-12 says exactly what holds under each setting, and
the release notes have to repeat it.

## User Stories

- As an operator running an internal hierarchy and a lab hierarchy, I hand
  the lab's build host a directory URL and an EAB key that work for the lab
  intermediate and for nothing else, and pointing the same host at the
  internal directory gets it refused rather than a certificate.
- As an operator, I create an EAB key only for a hierarchy I was granted, so
  the certificates that come out of ACME are the ones I could have signed by
  hand — and 0018's grants stop being a claim ACME quietly undoes.
- As a host with certbot already configured, my nightly renewal keeps
  working: re-registration with an account key I have used for months
  answers with my account exactly as it did before.
- As a host whose account key somebody copied to a machine on the other
  hierarchy, that machine gets an error at the other directory, and my
  account is still bound to the issuer it always was.
- As an operator retiring an intermediate, its ACME clients stop being able
  to order and are told why, while everything they were already issued keeps
  downloading and keeps being revocable.
- As an operator, the certbot command the ACME page offers me for a key I
  just created already names that key's own directory, so I cannot pair the
  right key with the wrong CA by copying the wrong line.

## Functional Requirements

- FR-1: **Schema — `0008` and `0009` rewritten in place.** Neither gains a
  successor and no `0011` appears: `0008` keeps `revision = "0008"`,
  `down_revision = "0007"`, `0009` keeps `"0009"` / `"0008"`, and 0018's
  `0010` continues to follow them untouched.
  - `acme_accounts` gains `issuer_id` (Integer, NOT NULL, FK
    `ca_certificates.id`), plus `ix_acme_accounts_issuer_id`. NOT NULL and
    no server default: an account that does not name an issuer is not a
    state this spec has an answer for, and a default would be cabin
    choosing an issuer for somebody — the exact thing FR-9 exists to stop.
  - `acme_eab_keys` gains `ca_certificate_id` (Integer, NOT NULL, FK
    `ca_certificates.id`). Named for the column it references rather than
    `issuer_id`, matching 0018's join tables (`user_issuers`,
    `token_issuers`), because a key names a CA row and only FR-8 decides
    whether that row is a usable issuer.

  Neither foreign key declares `ondelete`, for the same reason 0018 FR-1
  gives: nothing in cabin deletes a `ca_certificates` row — retirement is a
  status change (`ca/service.py:409`) — so the FK is a backstop that would
  make a future deletion loud rather than a cleanup rule anyone relies on.

  **Why rewritten and not appended.** A NOT NULL column with no default
  cannot be added to a table that already has rows, and the only backfill
  available would be "pick an issuer for every
  existing account", which is a policy decision made by a migration script
  at 3 a.m. against a database nobody is looking at. The project's standing
  answer (plan, "Migrations are being rewritten, not appended to") already
  applies to `0008` and `0009` by name. The cost is stated in the CHANGELOG
  with the other four: a v0.1.0 database cannot be brought up, and the
  repair path is an empty `/data`.

- FR-2: **Two paths gain an issuer segment, and no others.**

  | Path                                                                                | Shape after 0019 |
  | ----------------------------------------------------------------------------------- | ---------------- |
  | `/acme/ca/{issuer_id}/directory`                                                    | new              |
  | `/acme/ca/{issuer_id}/new-account`                                                  | new              |
  | `/acme/new-nonce`                                                                   | unchanged        |
  | `/acme/new-order`                                                                   | unchanged        |
  | `/acme/key-change`                                                                  | unchanged        |
  | `/acme/revoke-cert`                                                                 | unchanged        |
  | `/acme/account/…`, `/acme/order/…`, `/acme/authz/…`, `/acme/chal/…`, `/acme/cert/…` | unchanged        |

  `DIRECTORY_PATH` and `NEW_ACCOUNT_PATH` (`http.py:45,47`) stop being
  constants and become `directory_path(issuer_id)` and
  `new_account_path(issuer_id)`; every other constant in that block is
  untouched. The Context above records the check that the unchanged ones
  really do know their issuer already.

  Both new routes declare the segment with Starlette's integer converter —
  `"/ca/{issuer_id:int}/directory"` — so a non-numeric segment does not
  match the route at all and falls through to the catch-all
  (`api.py:140-146`), which answers `not_found("ACME resource")` as a
  proper problem document. Declaring it as `issuer_id: int` alone would
  hand a browser a FastAPI 422 validation body in the middle of an ACME
  conversation. `/acme/ca/{issuer_id:int}/new-account` is added to
  `_POST_ONLY_PATHS` (`api.py:95-107`) so a GET of it is the same 405 every
  other POST-only resource gives.

  A non-canonical spelling of the id — `/acme/ca/01/directory`, which the
  `int` converter accepts — needs no special handling and gets none: the
  directory it returns names `new-account` in the canonical form cabin
  builds from the integer, and a client that signs the non-canonical URL
  instead is refused by `jws.verify_request`'s `url` comparison
  (`jws.py:410-414`). The URL binding RFC 8555 6.4 already requires is what
  makes one resource have one name here.

- FR-3: **`/acme/directory` is dropped, with no alias and no redirect.** The
  route is deleted from `api.py:51`; the catch-all then answers it with the
  same 404 problem document as any other unknown path, so nothing new is
  written to produce that. No `Link`, no 301 to "the" directory — there is
  no longer a single directory, and inventing one would reintroduce the
  default-issuer rule this spec exists to remove.

- FR-4: **The directory of one issuer.** `GET /acme/ca/{issuer_id}/directory`
  resolves `issuer_id` against `ca_certificates`:
  - unknown row, or a row that is not `kind == "intermediate"` → 404, the
    `not_found("ACME resource")` problem document. A root signs no leaf, so
    its directory would be a URL that could never produce a certificate.
  - an intermediate, **active or retired** → the directory is served.

  Serving a retired issuer's directory is deliberate and mirrors 0017 FR-9's
  treatment of its CRL: retirement stops issuance and stops nothing else.
  The accounts bound to that issuer still exist, their clients still poll,
  and a 404 at the directory would tell them cabin is gone rather than that
  the CA was stood down. What they are refused instead is precise and
  reaches them where it matters — new-account (FR-5) and new-order (FR-9).

  The body keeps its current shape (`api.py:62-71`), with `newAccount`
  pointing at `new_account_path(issuer_id)` and `newNonce`, `newOrder`,
  `revokeCert` and `keyChange` at the unchanged global paths. `meta` keeps
  `externalAccountRequired` from the instance-wide `acme_require_eab` flag
  and `website` from the base URL. No cabin-specific field naming the
  issuer is added: RFC 8555 9.7.6 registers the `meta` members, and an
  operator asking "which CA is this" is answered by the `/ca` page (FR-13),
  not by a non-standard key that some client will one day validate against.

- FR-5: **newAccount binds the account to the issuer in the path.** A POST to
  the per-issuer new-account path resolves the issuer exactly as FR-4 does
  (404 for unknown or non-intermediate), verifies the JWS against
  `url(db, new_account_path(issuer_id))`, and stores the resolved id in
  `acme_accounts.issuer_id` for every account it creates.

  **An account belongs to exactly one issuer, for its whole life.** Nothing
  changes it afterwards. `key-change` (`api_account.py:229`) rotates the
  key on the row and leaves `issuer_id` alone — a rollover proves possession
  of a new key, which is a statement about the client and not about the CA.

  So **obtaining certificates from two hierarchies needs two account keys.**
  This is not a limitation nobody chose: it is the same shape a step-ca
  provisioner has, and it is the only shape the schema can express, because
  `acme_accounts.jwk_thumbprint` is unique across the whole table
  (`models.py:71`, migration `0008`) and always has been. One key is one
  account is one issuer. It is worth stating in the operator documentation
  (FR-13) precisely because a client author will otherwise read the
  refusal in FR-6 as a bug.

  Creating a **new** account at a retired issuer's directory is refused —
  `urn:ietf:params:acme:error:unauthorized`, message naming the retirement.
  The check sits on the creation path only (after the existing-account
  return of FR-6), so a client whose account is already there still gets its
  account back and then a comprehensible refusal at new-order.

- FR-6: **The re-registration trap.** `new_account` returns an existing
  account **without checking EAB at all** (`api_account.py:134-140`), and
  that is deliberate: `_external_account`'s docstring
  (`api_account.py:55-67`) records why — certbot re-registers on every run,
  and demanding a credential it was handed months ago and no longer stores
  would break every renewal on the instance. `_external_account` is only
  reached for a registration that will actually create an account.

  Left as it is, that early return is a **silent cross-issuer escalation**.
  A client registers at issuer A's directory, gets an account bound to A,
  and later posts new-account at issuer B's directory with the same account
  key. The lookup is by thumbprint and knows nothing about paths, so it
  finds the A-bound account and returns it with `Location` pointing at it —
  200, no EAB check, no error. The client then places orders under an
  account that is still bound to A. Two readings of that outcome exist and
  both are wrong: if the account's issuer wins, the client silently gets A's
  certificates from B's directory, and B's EAB key was never asked for; if
  the path's issuer won instead — the "obvious" fix — a bare account key
  would rebind itself across hierarchies by visiting a URL, which is worse.

  **Therefore: the found account's `issuer_id` must equal the issuer in the
  path, or the request is refused** with
  `urn:ietf:params:acme:error:unauthorized` and a message saying the account
  key is registered against another issuer's directory. The check runs
  immediately after `_reject_unusable` (`api_account.py:136`) and therefore
  **before** the 200 return, before the `onlyReturnExisting` branch
  (`:141`) and before `_external_account` (`:144`). No account row is
  created, no EAB key is consulted and none is spent.

  Order of the two refusals — deactivated first, wrong issuer second — is
  arbitrary and both are `unauthorized`; it is fixed here only so a test can
  assert one of them rather than either.

  What the refusal does **not** break: re-registration at the account's
  **own** directory is untouched and still answers 200 with the account and
  its `Location`, with no EAB demanded. That is the behaviour the early
  return exists for, and AC-4 asserts both halves in one test, because a
  spec that only asserted the refusal would be satisfied by an
  implementation that refused everything.

  The refusal is logged at WARNING with the thumbprint, the issuer the
  account is bound to and the issuer that was asked for. It is **not**
  audited: the request only needs a valid signature by the account key and a
  fresh nonce, so an audit event here would be a row a client can write in a
  loop, and the one event that mattered would be buried under the ones that
  did not — the same argument 0018 FR-15 makes for its per-tick events.

- FR-7: **An EAB key belongs to one issuer, and a key presented at the wrong
  directory is refused.** `eab.verify` gains the expected issuer and
  compares it against `row.ca_certificate_id`; a mismatch raises the same
  `unauthorized` with the same `_REFUSED` wording every other binding
  failure uses (`eab.py:128`), because a client that is not entitled to
  register learns that it is not entitled and nothing about which of the
  operator's keys exist for which CA.

  **The check has to be on the stored row, and the URL binding is not a
  substitute for it.** This is the trap in this requirement, and it is worth
  spelling out because the code makes the wrong answer look right.
  `jws.parse_external_binding` already refuses a binding whose inner JWS
  `url` is not the new-account URL cabin published (`jws.py:514-518`), and
  after FR-2 that URL contains the issuer id. It is tempting to conclude
  that a key for A therefore cannot be presented at B. It can. The inner JWS
  is built by the client and MACed with the shared secret **the client
  holds**: a client with A's key id and HMAC secret can sign a fresh binding
  over B's new-account URL, and it will parse and it will verify. The `url`
  check stops a third party replaying a binding document someone else built;
  it stops nothing about the key holder. Only the `ca_certificate_id` on the
  row does that, and AC-3 is written so that an implementation relying on
  the URL alone fails.

  A key whose issuer does not match is **not spent**: `bound_account_id`
  stays NULL and the key still works at its own directory afterwards.
  Refusal happens in `verify`, before `_spend_binding`
  (`api_account.py:153`) is reached at all.

  The `is_usable` rule (`eab.py:73-75`) and the one-key-one-account unique
  index (`0009`) are unchanged. A key is still spent by exactly one account,
  and that account's issuer is now, by construction, the key's.

- FR-8: **Where the grant is checked, and why it is there rather than at
  issuance.** An ACME account is not a cabin user; a principal has to come
  from somewhere, and the EAB key is the only thing in the whole flow that
  ties a certificate to an operator's decision. So the grant is checked at
  the moment that decision is made: **creating an EAB key.**

  `POST /acme/admin/eab-keys` (`web/acme_ui.py:191`) gains a required
  `issuer_id` form field and a `principal` from
  `Depends(current_principal)` (`web/deps.py:183`), and resolves it through
  `issuer_grants.resolve_granted_issuer(db, principal, issuer_id)` before
  `eab.create_key` is called. `IssuerForbiddenError` and
  `NoGrantedIssuerError` re-render the page with the message at **403**, the
  status 0018 FR-14 fixed for an authorization failure; 0017's
  `UnknownIssuerError` / `IssuerRetiredError` re-render at 400. No key row
  is written on any of them.

  The issuer select on the page is populated from
  `granted_issuers(db, principal)`, and — as in 0018 FR-11 — that is
  convenience, not enforcement: AC-6 posts an ungranted id directly and
  requires a 403. With an empty granted set the form still renders, with a
  banner saying no issuer is granted, and the POST is still refused.

  **The issuance-time exemption is narrowed, not removed, and the reason is
  not squeamishness.** Three ways to remove it were considered:
  - _Look the grant up at issuance from the user who created the EAB key_
    (a `created_by_user_id` column). 0018 FR-9 requires grants to be read
    fresh on every decision, so an unattended host's renewal would start
    failing because an unrelated person was demoted or deleted — days or
    weeks later, with nothing connecting cause to symptom. This is the
    failure 0018 FR-7 and 0022 FR-17 both refuse for cabin's own
    certificate, and it is worse for somebody else's.
  - _Give the ACME account a principal of its own._ There is nothing to
    build one from. `PrincipalKind.acme` exists precisely because the
    account is a thumbprint (`issuer_grants.py:83`, 0018 FR-2).
  - _Require an EAB key on every order, not just at registration._ RFC 8555
    binds EAB to new-account and nowhere else; a client would have to keep a
    single-use credential forever, and `eab.bind` spends it once by design.

  So `ACME_PRINCIPAL` stays, and stays unrestricted. What changes is that it
  no longer **chooses** anything: FR-9 removes ACME from 0017's default
  rule, so the exemption's whole remaining effect is "do not look for a
  grant row against an identity that has none", applied to an issuer that
  the URL selected and the EAB key authorised.

- FR-9: **Issuance uses the account's issuer, explicitly.** `_issue`
  (`api_finalize.py:215`) passes `issuer_id=account.issuer_id` to
  `sign_csr_and_store` alongside the unchanged
  `principal=issuer_grants.ACME_PRINCIPAL`, and its docstring's paragraph
  about riding the default rule (`api_finalize.py:225-229`) is replaced by
  what it now does. `finalize_order` already holds the account
  (`api_finalize.py:119`) and passes it in; `_issue` gains the parameter
  rather than re-reading the order's account, so there is one place the
  issuer comes from.

  **This is the substance of closing 0018's gap.** Today, with two active
  issuers, an ACME finalize raises `IssuerRequiredError` and with one it
  takes whatever that one is. After this requirement, the certificate comes
  from the issuer the account registered against and from no other, whatever
  else exists on the instance.

  Two exceptions become reachable at that call for the first time and must
  be handled where the others already are (`api_finalize.py:265-272`):
  `UnknownIssuerError` and `IssuerRetiredError` join the `isinstance` tuple,
  so they become an ACME problem document with the claim released. Without
  that, a retired issuer turns a finalize into a bare 500 with no problem
  document and no `Replay-Nonce` — which strands a client that has already
  spent one. `IssuerRequiredError` stays in the tuple although it is now
  unreachable from this path; removing it would be a second change with no
  test behind it.

  **The refusal is moved earlier for the case an operator can act on.**
  `new_order` (`api_order.py:57-67`) today refuses when
  `ca_service.active_issuers(db)` is empty. That question is now the wrong
  one: an instance can have four active issuers and this account's may still
  be retired. It is replaced by a check on the account's own issuer — active
  intermediate or refuse — with a `server_internal` problem document naming
  the issuer and the retirement. `server_internal` rather than a client
  error because nothing about the request was wrong, which is the same
  reading the existing branch takes.

- FR-10: **Revocation is unchanged, and that is a decision.**
  `revoke_cert` (`api_finalize.py:461`) keeps
  `principal=issuer_grants.ACME_PRINCIPAL` and gains nothing. RFC 8555 7.6's
  two doors already answer the issuer question without knowing about it: in
  `kid` mode the signer must be the account that placed the order that
  produced the certificate (`api_finalize.py:438-445`), and that account's
  issuer is the certificate's issuer by construction under FR-9, so an
  account on hierarchy A cannot reach a certificate of hierarchy B at all.
  In `jwk` mode there is no account — authority is possession of the
  certificate's own private key (`api_finalize.py:450-457`), which is a
  claim about that certificate and not about any CA.

  Adding an issuer check on top would therefore refuse nothing that is not
  already refused, while making revocation — the operation you least want to
  be harder than it has to be — depend on one more thing being right.
  `crl.revoke_certificate` continues to find the issuer on the certificate
  row (0017 FR-9), so a certificate signed by a since-retired issuer stays
  revocable over ACME exactly as it does through the UI.

- FR-11: **The `index` link names a directory only when the request names an
  issuer.** `acme_response_headers` (`http.py:185`) appends
  `<origin+/acme/directory>;rel="index"` to **every** ACME response today.
  That URL no longer exists (FR-3), and there is no single URL to put in its
  place.

  `require_acme_enabled` — which already runs on every ACME request and
  already stashes `acme_origin` on the request (`http.py:116-117`) — sets
  `request.state.acme_directory_path` when the path carries an issuer
  segment, and the middleware appends the header only when that attribute is
  present. So the two per-issuer routes carry an `index` link to their own
  directory, and the global routes carry none.

  RFC 8555 7.1 describes the `index` relation as present on resources other
  than the directory; this is a deliberate partial deviation, and the
  alternatives are worse. Naming an arbitrary issuer's directory would point
  a client at a CA it may hold no key for. Deriving it from the account
  instead of the path would cover more routes but means threading the
  request through `http.verified` and its eleven call sites for a header no
  client in the interop gate reads. The gate itself is the evidence that
  this costs nothing: certbot and acme.sh must complete a full issuance with
  the header present on the directory and new-account responses only, and
  absent from the other eight of the ten responses they receive (AC-13).

- FR-12: **What is protected afterwards, and what is not.** Written as a
  requirement rather than as prose at the end, because the release notes
  have to be able to quote it and because AC-7 measures both halves.

  **With `acme_require_eab` on**, the chain is complete and every link is
  enforced: an EAB key for issuer X can only be created by an identity
  0018 granted X (FR-8); registering at X's directory requires such a key
  (FR-7); an account so registered is bound to X for life (FR-5, FR-6); and
  every certificate it obtains is signed by X (FR-9). An admin holding no
  grant obtains no certificate over ACME — which is the sentence 0018 could
  not write.

  **With `acme_require_eab` off**, grants do not bind ACME. Anyone who can
  reach the port registers at any issuer's directory and orders from it.
  What 0019 still buys in that state is real but smaller: an account is
  confined to one issuer, so nothing crosses hierarchies, and the issuer
  is the one named in a URL the operator published rather than one cabin
  picked. It is not access control.

  cabin says so where the switch is: the `/acme` page shows a warning
  whenever `acme_enabled` is on and `acme_require_eab` is off, stating that
  issuer grants do not restrict ACME in this configuration and naming the
  checkbox that changes it. Not an error and not a refusal — an internal CA
  where any host on the LAN may ask for a certificate is a legitimate and
  common way to run one, and 0022 FR-11's precedent for overriding an
  operator does not apply here, because there is no deployment in which
  cabin knows better than they do what their network is.

  Forcing EAB on is **not** done; see Out of Scope for why.

- FR-13: **Everything that showed "the" directory URL now shows one per
  issuer.** `directory_url(db)` (`http.py:68-74`) becomes
  `directory_url(db, issuer_id)`, still `None` while no base URL is set, and
  its four callers change:
  - `/ca` (`web/ca_ui.py:215`): the installation-level
    `acme_directory_url` context key is removed, and `_row_view`
    (`web/ca_ui.py:144`) gains `acme_directory_url` next to the `crl_url`
    and `ca_url` it already computes for an intermediate (0022 FR-16) —
    `None` when ACME is off. `ca_list.html:14-21`'s single note becomes a
    per-row value, so the page that lists hierarchies is the page that
    answers "which URL is which CA".
  - `/settings` (`web/settings_ui.py:117`, `settings.html:110-112`): the
    directory line is replaced by a pointer to `/acme`. There is no single
    URL to print here any more, and a settings page is not where a list of
    them belongs.
  - `/acme` (`web/acme_ui.py:102`): the "Directory URL" section becomes one
    row per intermediate, active ones first, each naming the hierarchy. The
    EAB key table gains an **Issuer** column, the create form gains the
    issuer select of FR-8, and `snippet_directory` — the certbot and acme.sh
    commands an operator copies — uses the directory of the **key that was
    just created** rather than an instance-wide value. That last one is the
    cheapest defence this spec has against the mistake it is about: an
    operator who copies the offered line cannot pair a key with a directory
    it will be refused at.
  - MCP (`mcp/server.py:370`): `McpCAInfo.acme_directory_url: str | None` is
    replaced by `acme_directory_urls: list[McpAcmeDirectory]`, each entry an
    `issuer_id` and a `url`, empty while ACME is off or no base URL is set.
    A scalar field cannot answer the question any more, and leaving it as
    the first issuer's URL would be the default rule reappearing in a place
    nobody would look for it. The shared `CAInfo` (`api/models.py:90`) is
    **not** touched: the REST API does not report ACME today and this spec
    is not the reason to start.

  `README.md:23` names `/acme/directory` as cabin's ACME endpoint and is
  corrected to the per-issuer form, together with a sentence stating FR-5's
  one-key-one-issuer rule and FR-12's boundary.

- FR-14: **Audit.** No new `AuditAction`. Two existing details grow the one
  field that is now missing from them:
  `acme_account_created` (`api_account.py:155-164`) carries `issuer_id`
  alongside the thumbprint, and `acme_eab_key_created`
  (`web/acme_ui.py:206-215`) carries `issuer_id` alongside the key id and
  label. Without those, the audit log records that an account exists and
  that a credential was minted while omitting the only property that decides
  what either of them can do. `acme_certificate_issued` needs nothing: it
  already records the certificate row, which has carried its issuer since
  0017 FR-9.

## Interface Contract

What the changed things are called, take and return, so that the modules on
either side of a seam cannot be built against two different guesses.

### `cabin.acme.http` — paths

```python
ACME_PREFIX = "/acme"
#: The per-issuer segment. FR-2: the only place an issuer appears in a URL.
CA_PREFIX = f"{ACME_PREFIX}/ca/"


def directory_path(issuer_id: int) -> str: ...
def new_account_path(issuer_id: int) -> str: ...


def directory_url(db: Session, issuer_id: int) -> str | None: ...
def issuer_in_path(path: str) -> int | None: ...
```

`DIRECTORY_PATH` and `NEW_ACCOUNT_PATH` are removed; `NEW_NONCE_PATH`,
`NEW_ORDER_PATH`, `KEY_CHANGE_PATH`, `REVOKE_CERT_PATH` and the five
resource prefixes are unchanged. `issuer_in_path` returns the id when a path
is under `CA_PREFIX` and `None` otherwise; it is called once, by
`require_acme_enabled`, and exists so FR-11's middleware never parses a URL
itself.

`origin`, `url`, `verified`, `require_jose_content_type`, `acme_body`,
`json_response`, `owned_order`, `own_account_or_403` and every `*_json`
serializer keep their signatures.

### `cabin.acme.models`

- `AcmeAccount.issuer_id: Mapped[int]` — NOT NULL, FK `ca_certificates.id`
  (FR-1). Set once, at creation, and never written again.

### `cabin.acme.service`

- `get_or_create_account(db, key, *, issuer_id: int, contacts, tos_agreed, now=None) -> tuple[AcmeAccount, bool]`
  — `issuer_id` is keyword-only with no default, for the reason 0018 FR-5
  gives about `principal`: an entry point that forgets it must not compile.
- `account_issuer(db, account) -> CACertificate` — the account's issuer row,
  raising `ca.service.UnknownIssuerError` if it is gone. One lookup, used by
  FR-9's new-order check and available to the routes, so "which issuer is
  this account's" is not spelled three ways.

`find_account_by_key` is **unchanged** and stays a lookup by thumbprint
alone, across every issuer — the uniqueness it relies on is global
(`models.py:71`), and narrowing it by issuer would let two accounts share a
key, which the schema forbids and FR-6 depends on it forbidding.

### `cabin.acme.eab`

```python
class AcmeEabKey(Base):
    ca_certificate_id: Mapped[int]  # FK ca_certificates.id, NOT NULL


def create_key(
    db: Session,
    secrets: SecretStore,
    *,
    label: str,
    ca_certificate_id: int,
    now: datetime | None = None,
) -> tuple[AcmeEabKey, str]: ...


def verify(
    db: Session,
    secrets: SecretStore,
    binding: object,
    *,
    new_account_url: str,
    account_jwk: dict[str, Any],
    issuer_id: int,
) -> AcmeEabKey: ...
```

`issuer_id` on `verify` is keyword-only and has no default: FR-7's check is
the authorisation half of this spec, and a parameter that can be omitted is
a check that can be skipped. It compares `row.ca_certificate_id` against
`issuer_id`, and its refusal is `refused()` — the same object every other
binding failure raises. `bind`, `get_key`, `list_keys`, `revoke_key`,
`is_usable` and `refused` are unchanged.

### `cabin.acme.api_account`

- `new_account(issuer_id: int, request, body, db) -> Response` — route
  `POST /ca/{issuer_id:int}/new-account`.
- `_external_account(db, request, verification, payload, issuer_id: int)` —
  passes `issuer_id` straight to `eab.verify`.

The order of checks inside `new_account` is part of the contract, because
FR-6 is a statement about where one line goes:

1. resolve the issuer from the path (404 unknown / not an intermediate);
2. `verified(db, body, new_account_path(issuer_id), KeyMode.jwk)`;
3. `find_account_by_key` → if found: `_reject_unusable`, then **the issuer
   comparison of FR-6**, then the 200 with `Location`;
4. `onlyReturnExisting`;
5. refuse if the issuer is retired (FR-5 — creation only);
6. `_external_account` → `eab.verify(..., issuer_id=issuer_id)`;
7. `get_or_create_account(..., issuer_id=issuer_id)`;
8. `_spend_binding`.

### `cabin.acme.api_finalize`

- `_issue(request, db, account: AcmeAccount, order: AcmeOrder, der: bytes) -> Issued`
  — passes `issuer_id=account.issuer_id` and the unchanged
  `principal=issuer_grants.ACME_PRINCIPAL`.
- The `isinstance` tuple at `api_finalize.py:265-272` gains
  `UnknownIssuerError` and `IssuerRetiredError`.

`revoke_cert`, `chain_pem`, `_certificate_of`, `_authorize_revocation` and
`_certificate_id` are unchanged (FR-10).

### `cabin.web.acme_ui`

| Method | Path                               | Auth                                     | Response                 |
| ------ | ---------------------------------- | ---------------------------------------- | ------------------------ |
| POST   | `/acme/admin/eab-keys`             | admin + CSRF + **granted issuer** (FR-8) | 200 page with the secret |
| POST   | `/acme/admin/eab-keys/{id}/revoke` | admin + CSRF                             | 303 `/acme/admin`        |

`POST /acme/admin/eab-keys` gains a required `issuer_id: int = Form(...)`.
403 for an issuer this principal is not granted, 400 for one that is
unknown, retired or not an intermediate; no key row is written on either.
Revocation is unchanged: a key already exists, and taking it out of service
is not a new use of an issuer.

### `cabin.mcp.server`

```python
class McpAcmeDirectory(BaseModel):
    issuer_id: int
    url: str


class McpCAInfo(CAInfo):
    acme_directory_urls: list[McpAcmeDirectory] = []
```

### Routes, before and after

| Method | Path                                   | Change                  |
| ------ | -------------------------------------- | ----------------------- |
| GET    | `/acme/directory`                      | **removed**, 404 (FR-3) |
| GET    | `/acme/ca/{issuer_id:int}/directory`   | new (FR-4)              |
| POST   | `/acme/ca/{issuer_id:int}/new-account` | new (FR-5); GET → 405   |
| POST   | `/acme/new-account`                    | **removed**, 404        |

Every other ACME route keeps its path, its method and its auth. What changes
is which of them succeed.

## Acceptance Criteria

Every criterion below is written so that something specific has to break for
it to go red, and the mutation each one exists to catch is named. This
project has three times shipped tests that passed while the feature was
broken, so "returned 200", "returned 403" and "contains the string" do not
satisfy anything here on their own: a criterion that says **refused** means
the client's own refusal **and** no state change — no `acme_accounts` row,
no `certificates` row, no `bound_account_id` written.

Unless stated otherwise, each criterion runs against one instance with **two
active intermediates A and B** under different roots, because a single-issuer
instance cannot distinguish "used the right issuer" from "used the only one".

- AC-1: **The URL selects the issuer, end to end.** An account registered at
  A's directory places an order, answers a challenge and finalizes: the
  resulting `certificates` row has `issuer_id == A`, and the chain served at
  its `/acme/cert/{id}` ends at **A's** root, parsed — not compared as a
  string. The same flow through B's directory, in the same test against the
  same database, yields `issuer_id == B` and B's root. Both certificates
  verify with `openssl verify -CAfile` against their own chain and **fail**
  against the other's.
  _Goes red if_: `_issue` passes no `issuer_id` (with two active issuers it
  raises `IssuerRequiredError` and neither finalize completes), or passes a
  constant. The counter-check against the wrong chain is what stops a test
  from passing because both hierarchies happen to be trusted by the same
  store.
- AC-2: **The default rule no longer reaches ACME.** With an account bound
  to A and A **retired** while B is active and is the instance's only active
  issuer, `new-order` for that account is refused with a problem document
  naming the retirement, no `acme_orders` row is created, and
  `select count(*) from certificates` is unchanged. Forcing a finalize on an
  order placed before the retirement is likewise refused, as a problem
  document with a `Replay-Nonce` header present — not a bare 500 — and the
  order's claim is released so the same order can be finalized again after
  A is un-retired.
  _Goes red if_: any implementation still resolves the issuer by 0017's
  default rule (it would issue from B, silently, which is precisely the
  escalation this spec closes), or if `IssuerRetiredError` is left out of
  `_issue`'s `isinstance` tuple (the response loses its problem document and
  its nonce).
- AC-3: **An EAB key is refused at the wrong directory, and the check is not
  the URL.** An EAB key K is created for issuer A. A registration is
  attempted at **B's** new-account URL with an `externalAccountBinding`
  whose inner JWS is signed over **B's** new-account URL and MACed with K's
  own secret — i.e. a binding that is structurally perfect and that
  `jws.parse_external_binding` accepts. The registration is refused with
  `urn:ietf:params:acme:error:unauthorized`; **no** `acme_accounts` row
  exists for that key afterwards; and K's `bound_account_id` is **still
  NULL**. The same K is then used at A's directory in the same test and
  registers successfully.
  _Goes red if_: the implementation relies on the inner JWS's `url` binding
  instead of on `ca_certificate_id` — the binding in this criterion is
  signed over the right URL for the wrong CA, so the URL check passes and
  only the row check can refuse. Also red if the key is spent by the failed
  attempt: the final half would then find K unusable at A.
- AC-4: **Re-registration: the same key at its own directory works, at
  another directory is refused, and the account never moves.** One account
  key:
  1. registers at A's directory (201, `issuer_id == A`);
  2. re-registers at **A's** directory with no `externalAccountBinding` at
     all → 200, the same `Location`, the same row id, no new row. This is
     the certbot path and it must not regress;
  3. posts new-account at **B's** directory, both with a valid EAB key for
     B and without any binding → refused `unauthorized` both times;
  4. after all of it: exactly one `acme_accounts` row for that thumbprint,
     its `issuer_id` is still **A**, and an order placed under it still
     finalizes from A.

  _Goes red if_: the early return is left as it is (step 3 answers 200 —
  the silent escalation); if the found account is rebound to the path's
  issuer (step 4's `issuer_id` becomes B); or if the issuer check is placed
  after `_external_account` so that step 3's no-binding attempt slips
  through. Step 2 is what stops the whole criterion from being satisfied by
  refusing every re-registration.

- AC-5: **`onlyReturnExisting` obeys the same boundary.** A new-account with
  `onlyReturnExisting: true` at the account's own directory returns it;
  the identical request at the other issuer's directory is refused
  `unauthorized`, **not** `accountDoesNotExist` — asserted on the problem
  type, because the two say different things and only one of them is true.
  No row is created either way.
- AC-6: **Creating an EAB key needs a grant on that issuer.** An admin
  granted A only: `POST /acme/admin/eab-keys` with `issuer_id=A` succeeds
  and the row's `ca_certificate_id` is A; with `issuer_id=B` — a value the
  rendered select never offers — returns **403** and the row count of
  `acme_eab_keys` is unchanged. A superadmin holding no grant row succeeds
  for both (0018 FR-3's implicit rule). A **viewer** holding a grant row on
  both is refused with the role refusal, not the grant one.
  _Goes red if_: the implementation filters the select and passes the posted
  id through; asserting that the page renders only A satisfies nothing here.
- AC-7: **The boundary of FR-12, measured in both directions, in one test
  against one database.** With `acme_require_eab` **on**, zero rows in
  `user_issuers` and `token_issuers`, and an admin who is not a superadmin:
  the admin cannot create an EAB key for A (403), and a registration at A's
  directory without a binding is refused `externalAccountRequired` — so no
  certificate is obtainable over ACME by an ungranted identity. With
  `acme_require_eab` **off**, the same registration at A's directory
  **succeeds** and an order finalizes.
  The second half asserts a documented hole on purpose, exactly as 0018 AC-7
  did: the boundary cannot move in either direction without someone updating
  this criterion. Additionally, the `/acme` page renders FR-12's warning
  while ACME is on and EAB is off, and does not render it when EAB is on —
  asserted on the presence of the element in the parsed DOM, in both states.
- AC-8: **A retired issuer serves its directory and refuses new
  registrations.** With A retired: `GET /acme/ca/{A}/directory` returns 200
  and a body whose `newAccount` names A's new-account URL; a **new** account
  key registering there is refused `unauthorized` with a message naming the
  retirement and no row is created; an account **already** bound to A
  re-registers successfully (200) and can still fetch its existing
  certificates from `/acme/cert/{id}`, chain parsed. The directory path of a
  **root** id and of `999999` are both 404 with an ACME
  problem document — not a FastAPI validation body — and so is
  `/acme/ca/abc/directory`.
- AC-9: **`/acme/directory` is gone and nothing replaces it.**
  `GET /acme/directory` is 404 with an ACME problem document, carries no
  `Location` header, and `POST /acme/new-account` is 404 as well — a 405
  would prove the route still exists. Asserted with ACME switched **on**, so
  that the gate's own 404 is not what is being measured.
- AC-10: **A key rollover does not move the account.** An account bound to A
  performs a `key-change` to a new key: the row's `issuer_id` is still A,
  the new key resolves to the same account id, and an order under the new
  key finalizes from A. Then a `key-change` to a key that is already an
  account elsewhere is still the 409 of RFC 8555 7.3.5 step 9, whichever
  issuer that other account belongs to — `find_account_by_key` must stay
  global.
- AC-11: **Revocation still works across the retirement, and does not cross
  hierarchies.** (a) A certificate issued from A is revoked over ACME by its
  own account after A is retired: it succeeds, and A's CRL gains the serial,
  parsed with `openssl crl`. (b) An account bound to B, presented with a
  certificate of A in `kid` mode, is refused `unauthorized`, and that
  certificate's `revoked_at` is still NULL and A's `crl_number` unchanged.
  (c) `jwk`-mode revocation with the certificate's own key succeeds
  regardless of which issuer signed it — FR-10's deliberate unchanged
  behaviour.
- AC-12: **Schema.** A fresh database migrated to head has
  `acme_accounts.issuer_id` NOT NULL with a foreign key to
  `ca_certificates.id` and an index on it, and `acme_eab_keys` has
  `ca_certificate_id` NOT NULL with the same foreign key — asserted against
  the schema cabin actually migrates to, not against the migrations' source
  text. Inserting an `acme_accounts` row with a NULL or unknown `issuer_id`
  fails at the database. `0008` still has `down_revision = "0007"`, `0009`
  still `"0008"`, `0010` still `"0009"`, and there is no `0011`.
- AC-13: **The interop gate, on a live instance, natively.** certbot and
  acme.sh run against a running cabin — not `TestClient`, not a container —
  with two hierarchies configured and `acme_require_eab` on:
  1. certbot registers with an EAB key for A at **A's** directory URL and
     obtains a certificate; `openssl verify` against A's chain passes and
     against B's fails.
  2. acme.sh does the same at **B's** directory with a key for B.
  3. certbot is re-run for the same account against A — the renewal path,
     which re-registers — and succeeds.
  4. certbot is pointed at **B's** directory with the EAB key for A: it
     fails with the server's `unauthorized`, visibly and promptly, not with
     a hang or a client-side crash. Its account for A is unaffected and step
     3 still works afterwards.
  5. certbot is pointed at **B's** directory with the account key already
     registered for A: refused, FR-6, and the account is still A's.

  Both clients must complete steps 1 and 2 with FR-11's `index` link present
  only on the directory and new-account responses — the two per-issuer
  paths — and absent from the other eight of the ten responses each client
  receives; that split, not a stricter absence, is what FR-11 accepts, and
  it is the evidence the deviation costs nothing. The deviation itself
  exists because RFC 8555 7.1 asks for the link on every response and FR-3
  removes the one shared directory URL that used to fill it, so a client
  the gate did not cover would otherwise be the first to notice the header
  is narrower than the RFC describes.

- AC-14: **Every surface shows the right URL for the right issuer.** For
  each of A and B: `/ca` renders that issuer's directory URL as visible text
  in that issuer's own row, and the value equals
  `acme_http.directory_url(db, issuer_id)`; the `/acme` page lists both, one
  per intermediate; the MCP `get_ca_info` tool returns two
  `acme_directory_urls` entries whose `issuer_id`s are A and B and whose
  URLs match the same function; `/settings` renders **no** directory URL at
  all. With ACME off, all of these are absent or empty. With no base URL
  configured, all are absent.
  _Goes red if_: a page recomputes or hardcodes a URL rather than calling
  `directory_url`, or if a scalar "the directory" survives anywhere.
- AC-15: **The offered command matches the key.** After creating an EAB key
  for B, the `/acme` page's certbot and acme.sh snippets name **B's**
  directory URL and that key's id — parsed out of the rendered snippet and
  compared against `directory_url(db, B)` and the row's id, not matched as a
  substring. A snippet still naming A's directory, or an instance-wide one,
  fails.
- AC-16: **Audit.** `acme_account_created`'s detail carries `issuer_id`
  equal to the directory the account registered at, and
  `acme_eab_key_created`'s carries the `issuer_id` the key was created for.
  A refused cross-issuer re-registration (AC-4 step 3) adds **no** audit
  event at all — asserted on the event count before and after, since FR-6
  makes that a deliberate choice and not an omission.
- AC-17: **The exemption is exactly as wide as FR-8 says.** By source
  inspection: `issuer_grants.ACME_PRINCIPAL` appears at exactly the two call
  sites 0018 FR-7 names (`acme/api_finalize.py`, in `_issue` and in
  `revoke_cert`) and nowhere else, and `_issue`'s call to
  `sign_csr_and_store` passes an `issuer_id` keyword. By effect, in the same
  test: an ungranted admin is refused at `POST /certs/issue` while an ACME
  order bound to A finalizes — so an implementation that checks grants
  nowhere fails the first half and one that checks them inside `ca/certs.py`
  unconditionally fails the second. This is 0018 AC-7 re-run under 0019's
  rules, and it must keep passing.

## Test list

test*directory_per_issuer_lists_that_issuers_new_account,
test_directory_of_unknown_issuer_is_a_problem_document_404,
test_directory_of_a_root_is_404, test_directory_of_a_non_numeric_id_is_404,
test_legacy_directory_path_is_gone, test_legacy_new_account_path_is_gone,
test_new_account_binds_the_account_to_the_path_issuer,
test_two_directories_issue_from_their_own_issuer (AC-1, both chains parsed
and cross-verified), test_certificate_chain_ends_at_its_own_root,
test_finalize_never_uses_the_default_rule (two active issuers),
test_new_order_refused_when_the_accounts_issuer_is_retired,
test_finalize_on_a_retired_issuer_is_a_problem_document_with_a_nonce,
test_eab_key_refused_at_another_issuers_directory (inner JWS signed over the
\_wrong* directory's URL — the AC-3 mutation),
test_refused_eab_key_is_not_spent_and_still_works_at_its_own_directory,
test_eab_key_accepted_at_its_own_directory,
test_reregistration_at_the_same_directory_still_returns_the_account,
test_reregistration_at_another_directory_is_refused,
test_refused_reregistration_leaves_the_accounts_issuer_alone,
test_reregistration_without_a_binding_at_another_directory_is_refused,
test_only_return_existing_at_another_directory_is_unauthorized_not_account_does_not_exist,
test_new_account_at_a_retired_issuer_is_refused,
test_existing_account_may_still_reregister_at_a_retired_issuer,
test_retired_issuer_still_serves_its_directory,
test_eab_key_creation_requires_a_grant_on_that_issuer,
test_eab_key_creation_ungranted_issuer_posted_directly_is_403,
test_eab_key_creation_superadmin_needs_no_grant,
test_eab_key_creation_refused_for_a_viewer,
test_eab_key_issuer_select_lists_only_granted_issuers,
test_ungranted_admin_obtains_no_certificate_over_acme_with_eab_required,
test_ungranted_admin_obtains_one_with_eab_not_required (the documented
hole, asserted as such), test_acme_page_warns_when_eab_is_not_required,
test_key_change_keeps_the_issuer,
test_key_change_conflict_is_global_across_issuers,
test_acme_revocation_across_the_retirement (openssl crl),
test_acme_revocation_cannot_reach_another_issuers_certificate,
test_jwk_mode_revocation_unchanged,
test_index_link_present_on_per_issuer_paths,
test_index_link_absent_on_global_paths,
test_schema_acme_accounts_issuer_id_not_null,
test_schema_acme_eab_keys_ca_certificate_id_not_null,
test_migration_chain_unchanged_through_0010,
test_ca_page_shows_a_directory_url_per_issuer,
test_settings_page_shows_no_directory_url,
test_acme_page_lists_a_directory_url_per_issuer,
test_mcp_ca_info_reports_one_directory_per_issuer,
test_snippet_names_the_new_keys_own_directory,
test_audit_account_created_records_the_issuer,
test_audit_eab_key_created_records_the_issuer,
test_refused_cross_issuer_registration_writes_no_audit_event,
test_acme_principal_call_sites_are_exactly_the_expected_ones,
test_acme_issues_while_an_ungranted_admin_is_refused (0018 AC-7, re-run)

Four notes for whoever writes these.

- **The existing 0010–0012 ACME tests all move.** Every one of them builds a
  URL from `/acme/directory` or `/acme/new-account`
  (`tests/test_acme_api.py:135` and following,
  `tests/test_acme_client_interop.py:37`). They are updated to the
  per-issuer paths, not given a compatibility shim — FR-3 is the point.
  Where a test has one hierarchy, the change is mechanical; where it asserts
  something about issuance, check whether it should now assert the issuer.
- **The AC-3 mutation is the one to get right.** A test that presents an
  EAB binding whose inner JWS names issuer A's new-account URL to issuer B's
  endpoint is testing `jws.parse_external_binding`, not FR-7, and it will
  pass against an implementation with no issuer check on the key at all.
  The binding must be re-signed for the URL it is actually sent to. That is
  what a client holding the secret can trivially do, which is why it is the
  case that matters.
- **A single-issuer fixture proves almost nothing in this spec.** With one
  active issuer, "used the account's issuer" and "used the default rule"
  give the same answer everywhere. Two hierarchies is the default fixture
  here, and criteria that say so mean it.
- **The interop gate is out-of-band**, on the maintainer's machine, against
  a live instance with certbot and acme.sh installed natively — AC-13.
  Its result counts; a report that it was run does not.

## Out of Scope

**Forcing `acme_require_eab` on.** FR-12 makes the consequence of leaving it
off explicit and warns about it in the UI, and stops there. An internal CA
on which any host on the LAN may ask for a certificate for a name it
controls is a legitimate and common way to run one — it is most of the
reason ACME is in cabin at all — and turning that into a configuration error
would be this spec deciding what somebody's network is. Anyone who wants the
grant chain to hold absolutely switches EAB on, which is one checkbox, and
FR-12's warning is the thing that tells them so.

**A per-issuer `acme_require_eab`.** The flag stays instance-wide. Per-issuer
would be the more expressive design and it is not needed by anything here:
an operator who wants one hierarchy locked down and one open has, after
0017, the option of not publishing the second directory URL, and a second
axis of configuration whose only consumer is a hypothetical deployment is
exactly the speculative abstraction Rule 2 refuses.

**Moving an account between issuers.** There is no endpoint, no admin action
and no migration path. An account is bound at registration and stays bound
(FR-5); a client that needs the other hierarchy generates another account
key, which is one command in every ACME client. Offering a rebind would be
offering the exact operation FR-6 exists to prevent, with a nicer name.

**Deriving an issuance-time grant from whoever created the EAB key.**
Considered and rejected in FR-8, with reasons — an unattended renewal that
starts failing because an unrelated person was demoted is a worse failure
than the one it would prevent, and it is the same argument 0018 FR-7 and
0022 FR-17 make about cabin's own certificate. The `ACME_PRINCIPAL`
exemption is narrowed by FR-9 rather than removed, and FR-12 states what
that leaves.

**An issuer segment on the account, order, authorization, challenge or
certificate URLs.** They are opaque object URLs that already resolve their
issuer through the account or through `certificates.issuer_id`; the Context
records the check. Adding a segment would put a second, redundant statement
of the issuer in every URL, and a URL that says one thing while the row says
another is a bug waiting for someone to trust the wrong one.

**Naming the issuer in the directory's `meta`.** RFC 8555 9.7.6 registers
those members and cabin does not get to add one. The `/ca` page (FR-13)
answers "which URL is which CA" for the audience that asks it.

**Per-issuer ACME enablement, per-issuer nonce pools, per-issuer rate
limits.** `acme_enabled` stays one switch, `acme_nonces` stays one table
(a nonce is an anti-replay token and is not a capability for anything), and
cabin has no rate limiting to make per-issuer.

**Anything about which names an issuer may sign for.** That is spec 0020's
name constraints, and it applies to ACME through `ca/leaf.py` like every
other door — deliberately, so the check cannot be missing on the one path
where names arrive from outside.

**`Link rel="alternate"` and alternative chains.** Spec 0021's, unchanged by
this one: cabin still publishes one chain per certificate, built from that
certificate's own issuer.
