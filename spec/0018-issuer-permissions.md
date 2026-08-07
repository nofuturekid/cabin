# Spec 0018 — Issuer Permissions

## Context

Spec 0017 made several hierarchies possible; it deliberately left every
admin able to use all of them. `resolve_issuer` (`ca/service.py:173`) asks
only whether a row exists, is an intermediate and is active — never who is
asking. On a single-CA instance that was the whole truth. On an instance
that runs an internal hierarchy next to a lab hierarchy it is not: the
reason to have two is that not everyone should be signing from both.

Nothing in cabin can express that today. `require_admin`
(`web/deps.py:169`) and `require_api_write` (`web/api_deps.py:68`) draw one
line — may this identity change anything at all — and the seven issuance
entry points draw no second line after it. This spec adds the second line:
**which issuers** this identity may sign and revoke with.

Three facts about cabin's identity model shape the design.

- **API tokens have no owning user.** `ApiToken` (`api_tokens.py:43-55`)
  carries a label, a hash, a role and four timestamps — there is no
  `user_id` and no `created_by`. That is deliberate (spec 0008): a token is
  a credential for a script, not a proxy for a person. So a token cannot
  inherit a user's grants; it has to carry its own. Hence two join tables
  rather than one.
- **MCP authenticates with those same tokens.** `CabinTokenVerifier`
  (`mcp/auth.py:58-81`) verifies the bearer against `api_tokens` and
  `current_token` (`mcp/auth.py:84-97`) re-reads the row inside the tool. So
  MCP inherits token grants for free, and gets no permission model of its
  own.
- **ACME has no cabin identity at all.** `acme/api_finalize.py:215` issues
  on behalf of an ACME account, which is a key thumbprint — `acme_actor`
  (`audit.py:138`) exists precisely because there is no user row and no
  integer id to point at. There is nothing to look a grant up by. FR-7
  makes that exemption explicit rather than leaving it to be discovered.

**Visibility does not change, and that is a decision, not an omission** —
see FR-13.

## User Stories

- As an operator running an internal hierarchy and a lab hierarchy, I give
  the lab's admin a grant on the lab intermediate only, and their attempt to
  sign an internal name is refused at every door, not just at the one they
  happened to try.
- As the superadmin, I never lock myself out of a CA I just built: my access
  to every issuer is implicit, and the hierarchy I create is granted to me
  the moment it exists — so demoting myself later does not take my own CA
  away.
- As an admin who was given the lab issuer, I go on issuing without naming
  it, exactly as on a single-CA instance, because one granted issuer is as
  unambiguous as one active issuer.
- As an operator, I hand a build script a token that can sign for the lab
  hierarchy and nothing else, and the same token gives the same answer
  whether the script talks REST or MCP.
- As the superadmin, I take a grant away and it is gone on that identity's
  very next request — no logout, no token rotation, no restart.
- As anyone with a login, I still see every certificate, every hierarchy and
  every audit event, because knowing what the instance holds is not the same
  as being allowed to change it.

## Functional Requirements

- FR-1: **Schema — a new migration `0010`, appended.** Unlike 0017 nothing
  here is rewritten: `0010` follows `0009` (`revision = "0010"`,
  `down_revision = "0009"`) and creates two tables and nothing else.
  - `user_issuers`: `user_id` (Integer, NOT NULL, FK `users.id`),
    `ca_certificate_id` (Integer, NOT NULL, FK `ca_certificates.id`),
    primary key over both columns.
  - `token_issuers`: `api_token_id` (Integer, NOT NULL, FK
    `api_tokens.id`), `ca_certificate_id` (Integer, NOT NULL, FK
    `ca_certificates.id`), primary key over both columns.

  The composite primary key is what makes a grant idempotent at the
  database: re-granting the same pair is an integrity error, not a second
  row, so no counting logic anywhere has to be right about duplicates. No
  surrogate id, no `granted_at`, no `granted_by` — who changed a grant and
  when is what the audit log is for (FR-12), and a second record of it in
  the join table would be a second thing to keep true.

  There is no CHECK constraining `ca_certificate_id` to an intermediate:
  that is a property of a row in another table, which neither SQLite nor
  PostgreSQL can express here. FR-10 enforces it in the one function that
  writes these rows.

- FR-2: **A principal is what a permission is checked against.** New module
  `cabin/issuer_grants.py`, top-level next to `users.py` and
  `api_tokens.py`, holding both ORM models, the principal type and every
  rule below.

  ```
  class PrincipalKind(StrEnum): user, token, acme
  @dataclass(frozen=True) class Principal: kind, id, role
  ```

  Built by three things and nothing else: `user_principal(user)`,
  `token_principal(token)`, and the module constant `ACME_PRINCIPAL`
  (`kind=acme`, `id=None`, `role=None`). A principal is derived from an
  identity that has **already** been authenticated and role-checked; it
  never authenticates anything itself. `Principal.unrestricted` is true for
  a superadmin user, a superadmin token and `ACME_PRINCIPAL`.

  `cabin/issuer_grants.py` imports `cabin.users`, `cabin.api_tokens` and
  `cabin.ca.service`, and is imported by `cabin.ca.certs` and
  `cabin.ca.crl`. That direction is checked and holds: `cabin.ca.service`
  imports only `cabin.ca.x509`, `cabin.secrets` and `cabin.store`
  (`ca/service.py:19-21`), so nothing under `cabin.ca` reaches back into
  the identity modules and there is no cycle.

- FR-3: **The grant rules.** Four functions, and the entire policy lives in
  them:
  - `granted_issuers(db, principal) -> list[CACertificate]` — the **active**
    intermediates this principal may sign with, ordered by id. For an
    unrestricted principal this is exactly `active_issuers(db)`
    (`ca/service.py:161`); for anyone else it is `active_issuers(db)`
    intersected with that identity's grant rows. A grant on a retired issuer
    therefore never appears here — a retired issuer is not offered to
    anyone, granted or not.
  - `may_use_issuer(db, principal, ca_certificate_id) -> bool` — whether the
    grant exists, **status-blind**. True for every unrestricted principal.
    This, not `granted_issuers`, is what revocation asks (FR-6), because a
    certificate signed by a since-retired issuer must still be revocable by
    the same people who were allowed to issue it.
  - `set_issuers(db, principal_target, issuer_ids) -> Change` — replace one
    identity's grant set, returning what was added and removed (FR-12 logs
    it, FR-11 posts it).
  - `resolve_granted_issuer(db, principal, issuer_id) -> CACertificate` —
    FR-4.

  **`superadmin` is implicit for users and for tokens alike**, with no grant
  rows required. Without that, a superadmin who creates the first hierarchy
  and forgets to grant it to themselves has an instance nobody can issue
  from and no way in — the same class of lockout `users.py:75-79` guards
  against for the last superadmin.

- FR-4: **"Exactly one active issuer" becomes "exactly one granted
  issuer".** `resolve_granted_issuer` replaces `resolve_issuer` at the two
  places `ca/certs.py` calls it (`ca/certs.py:218`, `:268`) and keeps
  0017 FR-6's shape:

  | granted active issuers  | `issuer_id` omitted                   | `issuer_id` given                          |
  | ----------------------- | ------------------------------------- | ------------------------------------------ |
  | 0, none active anywhere | `CANotConfiguredError`                | `UnknownIssuerError`                       |
  | 0, but some are active  | `NoGrantedIssuerError`                | 0017's checks, then `IssuerForbiddenError` |
  | exactly 1               | **that one**, however many are active | 0017's checks, then the grant              |
  | 2 or more               | `IssuerRequiredError`                 | 0017's checks, then the grant              |

  The third row is the substance of this requirement. An admin granted one
  of three active issuers has no ambiguity to resolve, so they issue without
  naming it — a single-CA experience on a multi-CA instance. A superadmin on
  the same instance gets `IssuerRequiredError`, because their granted set is
  all three; the rule is one rule, applied to a set that differs per
  principal.

  With an explicit `issuer_id` the checks run in this order: existence,
  then kind and status (both by delegating to 0017's `resolve_issuer`
  unchanged), then the grant. So a retired issuer answers
  `IssuerRetiredError` whether or not it was granted — the retirement is the
  operative fact and the message has to say so, or an operator will spend
  the afternoon editing grants. The order does not leak anything: FR-13
  keeps every issuer visible to every logged-in user anyway, so there is no
  existence to conceal and no 404-versus-403 dance to invent.

  `CANotConfiguredError` and `NoGrantedIssuerError` stay distinct because
  the UI says different things: `_NO_CA` (`web/certs_ui.py:69`) tells the
  operator to create a hierarchy, which is exactly the wrong advice for
  someone who is merely not granted one that already exists.

- FR-5: **Issuing is enforced in one place, and that place cannot be
  skipped.** `issue_and_store` (`ca/certs.py:184`) and `sign_csr_and_store`
  (`ca/certs.py:243`) gain a **required, keyword-only** `principal:
Principal` parameter with no default, and pass it to
  `resolve_granted_issuer`.

  This is the whole enforcement mechanism, and the reason it is here rather
  than in a FastAPI dependency is worth stating: the issuer to check against
  arrives in the request _body_, and when it is omitted it can only be
  derived from the database and the principal together — a dependency that
  runs before the body is bound cannot decide it. A guard per entry point
  would also have to be written seven times and would be right seven times
  only by discipline. One required parameter on the two functions every door
  already goes through is right by construction: the eighth entry point
  someone adds in 2027 does not compile until it says who is asking. This is
  the same device 0017 used for `_store(..., *, issuer_id: int)`.

  The seven call sites pass a principal: `web/certs_ui.py:308` and `:368`
  (`user_principal`), `api/v1.py:262` and `:312` (`token_principal`),
  `mcp/server.py:463` and `:531` (`token_principal` on the token
  `_writer` at `mcp/server.py:300` already returned), and
  `acme/api_finalize.py:238` (`ACME_PRINCIPAL`, FR-7).

  `web/deps.py` gains `current_principal(user: User = Depends(require_admin))
-> Principal` and `web/api_deps.py` gains `api_write_principal(token:
ApiToken = Depends(require_api_write)) -> Principal`: conveniences that
  put the role gate and the principal in one dependency for the routes that
  want it. They are the "new guards alongside `require_admin` /
  `require_api_write`" — but they are ergonomics, not the enforcement, and
  no acceptance criterion is satisfied by their presence.

- FR-6: **Revoking follows the issuing grant**, because a revocation
  rewrites that issuer's CRL and every relying party sees the result.
  `revoke_certificate` (`ca/crl.py:192`) gains the same required
  keyword-only `principal: Principal` and calls `may_use_issuer(db,
principal, row.issuer_id)` on the row it is already loading — 0017 FR-9
  kept the issuer on the row for exactly this kind of reason. Refusal is
  `IssuerForbiddenError`, raised **before** anything is written, so a
  refused revocation leaves `revoked_at`, `crl_number` and the stored CRL
  bytes untouched.

  `may_use_issuer`, not `granted_issuers`: revoking through a **retired**
  issuer works and republishes its CRL (0017 FR-9), so the check must not
  filter on status. An operator who retires a compromised intermediate and
  then cannot revoke what it signed has the problem backwards.

  All four call sites pass one: `web/certs_ui.py:495`, `api/v1.py:383`,
  `mcp/server.py:584`, `acme/api_finalize.py:484` (`ACME_PRINCIPAL`).

- FR-7: **ACME is exempt in this spec, explicitly and by name.** There is no
  cabin user and no API token behind an ACME finalize or an ACME
  revoke-cert; the account is a key thumbprint. `ACME_PRINCIPAL` is
  unrestricted, so `acme/api_finalize.py:238` and `:484` behave exactly as
  they do under 0017 — `_issue`'s docstring (`api_finalize.py:225-229`)
  already explains that ACME rides the default rule until spec 0019.

  It is a named constant rather than `principal=None` on purpose. `None`
  meaning "skip the check" would make every forgotten call site a silent
  bypass instead of a type error, which is precisely the failure FR-5 is
  shaped to prevent. `ACME_PRINCIPAL` is greppable, appears at two call
  sites, and a third occurrence is a review question.

  What this costs is stated in Out of Scope: until 0019 binds an ACME
  account to an issuer, an admin with no grant who can register an ACME
  account can still obtain a certificate. That is a real hole, it is
  accepted here, and it is 0019's to close.

- FR-8: **Whoever creates a hierarchy is granted it.** `POST /ca/create`
  (`web/ca_ui.py:173`), `POST /ca/import` (`:224`) and
  `POST /ca/{root_id}/intermediate` (`:265`) write a `user_issuers` row for
  the acting user and the **new intermediate** in the same request, before
  the redirect. Without this an admin can build a CA and immediately not be
  allowed to use it, which is absurd on its face and would be diagnosed as a
  bug every time.

  The row is written even when the creator is a superadmin, where it is
  redundant today. That is deliberate: a superadmin later demoted to admin
  keeps the hierarchy they built, instead of losing it to a role change
  nobody connected to it.

  The grant is recorded as part of the existing CA event rather than as an
  event of its own — `ca_created` / `ca_imported` (`web/ca_ui.py:204`,
  `:252`, `:293`) gain `granted_to` in their detail, naming the user id.

- FR-9: **Grants are read fresh on every authorization decision.** Nothing
  memoizes them: no `functools.cache` or `lru_cache` on any of FR-3's four
  functions, no grant set on the session row, and no scope list in
  `AccessToken.claims` (`mcp/auth.py:78`), which FastMCP holds for the life
  of the transport and which would keep a withdrawn grant working. The
  claims dict keeps carrying the token id and nothing else; `current_token`
  (`mcp/auth.py:84-97`) already re-reads the row per call for the same
  reason and the grant lookup follows it. A permission that survives its own
  withdrawal is not a permission.
- FR-10: **Grant lifecycle.**
  - Only an intermediate can be granted. `set_issuers` rejects a
    `ca_certificate_id` whose row is not `kind == "intermediate"` with a
    `ValueError` naming "intermediate". A root signs no leaf and no CRL, so
    a grant on one could only ever be dead data that reads like permission.
  - **Deleting a user deletes their grants.** `users.delete_user`
    (`users.py:154-160`) removes the identity's `user_issuers` rows in the
    same transaction, the way `delete_sessions_for_user` is called for its
    sessions (`web/ui.py:507`). This is not tidiness. cabin enables no
    `PRAGMA foreign_keys` anywhere (`store/__init__.py:26-30` sets only
    `check_same_thread`), so SQLite does not enforce the FK and the rows
    would simply stay; and `users.id` is a plain `INTEGER PRIMARY KEY`,
    whose value SQLite reuses for the next insert after the highest row is
    deleted. A deleted admin's grants would then be inherited by the next
    user created. AC-12 measures exactly that.
  - Tokens are revoked, never deleted (`api_tokens.py:146-158`), so
    `token_issuers` has no equivalent hole. A revoked or expired token fails
    `verify_token` before any grant is consulted; its rows stay and are shown
    on the page as history.
  - Retiring an issuer does not touch its grants. It stops appearing in
    `granted_issuers` (FR-3) and stays usable for revocation (FR-6); if it
    is ever un-retired, the grants that were there are still there.
- FR-11: **UI.**
  - `/users` (`web/ui.py:374`, `users.html`) shows each user's granted
    issuers and, for a non-superadmin row, a checkbox per active
    intermediate. `POST /users/{user_id}/issuers` takes repeated `issuer_id`
    form fields (an empty post means "no issuers"), superadmin + CSRF, 303
    to `/users`. A superadmin row shows "all issuers" and no control,
    because there is nothing to edit. A viewer row shows the control with a
    note that it grants nothing until the role changes — a grant survives a
    role change (FR-10), so pre-granting someone about to be promoted is
    legitimate, and AC-3 asserts the role gate still comes first.
  - `/tokens` (`web/tokens_ui.py`, `tokens.html`) does the same per token:
    `POST /tokens/{token_id}/issuers`, superadmin + CSRF. `POST /tokens`
    gains the same optional repeated `issuer_id` field so a token can be
    born with its grants; a token created without any is an admin token that
    can do nothing until granted, which is the correct default. A token
    whose `token_status` is not `active` shows its grants read-only.
  - `/certs/new` and `/certs/sign`: `_issuer_options` (`web/certs_ui.py:88`)
    returns `granted_issuers(db, principal)` instead of
    `active_issuers(db)`. 0017 FR-14's "rendered only when there is more
    than one" now counts granted issuers, so the admin of FR-4's third row
    sees no select at all. When the granted set is empty the form still
    renders, with a banner saying no issuer is granted — and the POST is
    still refused server-side. The select is a convenience; AC-2 exists to
    prove nothing rests on it.
- FR-12: **Audit.** Two new `AuditAction` members (`audit.py:67-102`):
  `user_issuers_changed` with `target_type="user"`, and
  `token_issuers_changed` with `target_type="api_token"`. The detail carries
  `added` and `removed` as lists of issuer ids plus the resulting `issuers`
  list. Re-posting a set that is already in place records nothing — the same
  no-op rule `update_role_route` (`web/ui.py:433`), the settings route and
  both revocation routes already follow. Both appear in `/audit`'s filter,
  which is generated from the enum (`audit.py:106`) and so cannot drift.
- FR-13: **Visibility is deliberately unchanged, and this is a decision.**
  The inventory (`/certs`, `GET /api/v1/certificates`, the MCP
  `list_certificates` tool), the CA list (`/ca`, `GET /api/v1/ca`,
  `get_ca_info`), the dashboard (`web/ui.py:226-238`) and the audit log go
  on showing everything to every logged-in user and every live token,
  exactly as they do today. Grants govern **issuing and revoking only**.

  The reason: the inventory is a shared operational view. It answers "what
  is deployed on this network and when does it expire", and that question
  does not become someone else's business because a second hierarchy exists.
  A filtered inventory would also be a filtered expiry warning, and an
  admin who cannot see a certificate about to expire cannot tell anyone it
  is about to expire. The audit log is worse still: a log that shows each
  reader only their own actions is not an audit log.

  Written down here, and again in Out of Scope, so that it is not later
  "fixed" by adding filtering. Filtering the inventory is a different spec
  with a different argument, and it would have to answer what happens to the
  dashboard.

- FR-14: **Error mapping at the four front doors.** Two new exceptions,
  defined in `cabin/issuer_grants.py` and imported from there by everything
  else:

  | Exception              | When                                                                     |
  | ---------------------- | ------------------------------------------------------------------------ |
  | `IssuerForbiddenError` | This principal has no grant on the issuer it named (or the row's issuer) |
  | `NoGrantedIssuerError` | No `issuer_id` was given and this principal has no granted active issuer |

  They live in `issuer_grants` rather than in `cabin.ca.service`, where 0017
  put its four: `ca.service` has no concept of a principal and must not
  acquire one — it is the module `cabin/issuer_grants.py` imports, not the
  other way round. Each is defined exactly once.
  - UI (`web/certs_ui.py`): the form re-rendered with the message and the
    submitted values intact, status **403** — the same status
    `require_role` returns (`web/deps.py:162`), because this is an
    authorization failure and not the bad input 0017's issuer errors are.
  - REST: `_domain_errors` (`api/v1.py:97`) gains a branch mapping both to
    **403** with the usual `ErrorDetail` body, alongside the existing
    `_FORBIDDEN` 403 (`web/api_deps.py:31`). Explicitly not the 400 that
    `UnknownIssuerError` and friends get.
  - MCP: `_readable_errors` (`mcp/server.py:231`) gains both, relayed as a
    `ToolError` whose message says the issuer is not permitted — wording
    distinguishable from "no such issuer", since an MCP client has no status
    line to read.
  - ACME: not reachable (FR-7).

## Interface Contract

What the changed things are called, take and return, so that the modules on
either side of a seam cannot be built against two different guesses.

### `cabin.issuer_grants` — the whole policy, one module

```python
class UserIssuer(Base):  # __tablename__ = "user_issuers"
    user_id: Mapped[int]  # PK, FK users.id
    ca_certificate_id: Mapped[int]  # PK, FK ca_certificates.id


class TokenIssuer(Base):  # __tablename__ = "token_issuers"
    api_token_id: Mapped[int]  # PK, FK api_tokens.id
    ca_certificate_id: Mapped[int]  # PK, FK ca_certificates.id


class PrincipalKind(StrEnum):
    user = "user"
    token = "token"
    acme = "acme"


@dataclass(frozen=True)
class Principal:
    kind: PrincipalKind
    id: int | None
    role: Role | None

    @property
    def unrestricted(self) -> bool: ...


def user_principal(user: User) -> Principal: ...
def token_principal(token: ApiToken) -> Principal: ...


ACME_PRINCIPAL: Principal


def granted_issuers(db: Session, principal: Principal) -> list[CACertificate]: ...
def may_use_issuer(db: Session, principal: Principal, ca_certificate_id: int) -> bool: ...
def resolve_granted_issuer(
    db: Session, principal: Principal, issuer_id: int | None
) -> CACertificate: ...


@dataclass(frozen=True)
class Change:
    added: list[int]
    removed: list[int]
    issuers: list[int]

    @property
    def changed(self) -> bool: ...


def issuers_of(db: Session, principal: Principal) -> list[int]: ...
def set_issuers(db: Session, principal: Principal, issuer_ids: Sequence[int]) -> Change: ...
def grant(db: Session, principal: Principal, ca_certificate_id: int) -> bool: ...


class IssuerForbiddenError(Exception): ...


class NoGrantedIssuerError(Exception): ...
```

`set_issuers` and `grant` take the **target** identity as a `Principal`,
not a raw id, so that a caller cannot pass a user id where a token id was
meant — the two tables are otherwise structurally identical and a
transposed argument would grant the wrong identity in silence. Both raise
`ValueError` for an id that is not an active-or-retired intermediate row
(FR-10) and for `ACME_PRINCIPAL`, which has nothing to store a grant
against. `grant` returns whether a row was actually written, so FR-8's
creation path can be idempotent without counting.

### `cabin.ca.certs` — changed signatures

- `issue_and_store(db, secrets, *, principal: Principal, profile, subject_cn, sans, days=DEFAULT_DAYS, key_type="ecdsa-p256", issuer_id=None, source=CertSource.ui) -> Issued`
- `sign_csr_and_store(db, secrets, *, principal: Principal, csr_pem, profile, days=DEFAULT_DAYS, sans_override=None, subject_cn_fallback=None, allow_empty_subject=False, issuer_id=None, source=CertSource.ui) -> Issued`

`principal` is keyword-only with **no default**. Both call
`resolve_granted_issuer(db, principal, issuer_id)` where 0017 called
`resolve_issuer(db, issuer_id)` (`ca/certs.py:218`, `:268`); nothing else
about them changes.

### `cabin.ca.crl` — changed signature

- `revoke_certificate(db, secrets, cert_id, reason=RevocationReason.unspecified, *, principal: Principal, now=None) -> Certificate`

Keyword-only and without a default, for the same reason. `reason` stays
positional-or-keyword so the four existing call sites keep their shape.
`regenerate_crl`, `stored_crl` and `current_crl` are **unchanged**: serving
and refreshing a CRL is a public, unauthenticated read (0017 FR-10) and has
no principal to check.

### `cabin.web.deps` / `cabin.web.api_deps`

- `current_principal(user: User = Depends(require_admin)) -> Principal`
- `api_write_principal(token: ApiToken = Depends(require_api_write)) -> Principal`

Both are one line over FR-2's constructors. `require_admin`,
`require_api_read`, `require_api_write` and `ADMIN_ROLES` are untouched:
grants are checked **after** the role, never instead of it.

### Routes

| Method | Path                         | Module             | Auth              | Response      |
| ------ | ---------------------------- | ------------------ | ----------------- | ------------- |
| POST   | `/users/{user_id}/issuers`   | `web/ui.py`        | superadmin + CSRF | 303 `/users`  |
| POST   | `/tokens/{token_id}/issuers` | `web/tokens_ui.py` | superadmin + CSRF | 303 `/tokens` |

Both take repeated `issuer_id` form fields; no field at all means the empty
set, which is how a grant is taken away. An unknown user or token id is a
404; an `issuer_id` that is not an intermediate is a 400 with the page
re-rendered and no row written. `POST /tokens` gains the same optional
repeated `issuer_id` field.

No existing route gains or loses a path, a method or an auth dependency.
`/certs/issue`, `/certs/sign`, `POST /api/v1/certificates`,
`/api/v1/certificates/sign` and the three revocation routes keep their
shapes; what changes is which of them succeed.

### New status codes, in one list

| Situation                                           | UI  | REST | MCP         |
| --------------------------------------------------- | --- | ---- | ----------- |
| Named an issuer this identity has no grant on       | 403 | 403  | `ToolError` |
| Named none, and this identity has no granted issuer | 403 | 403  | `ToolError` |
| Named none, several granted (`IssuerRequiredError`) | 400 | 400  | `ToolError` |
| Named a retired issuer (`IssuerRetiredError`)       | 400 | 400  | `ToolError` |
| Role may not write at all                           | 403 | 403  | `ToolError` |

## Acceptance Criteria

A permissions spec is carried by its negative cases, and a negative case at
one door proves nothing about the other six. Every criterion below that
says "refused" means: the front door's own refusal **and** no state change —
no `certificates` row, no `revoked_at`, no changed `crl_number`. A test that
asserts only a status code passes an implementation that does the thing and
then reports an error.

- AC-1: **All seven issuance entry points refuse an ungranted admin.** With
  one active issuer and an admin (resp. an admin token) holding no grant,
  each of `web/certs_ui.py:308`, `:368`, `api/v1.py:262`, `:312`,
  `mcp/server.py:463`, `:531` — driven through its real front door, not by
  calling the service function — refuses, and `select count(*) from
certificates` is identical before and after all six. The seventh,
  `acme/api_finalize.py:238`, is AC-7's. Granting the issuer and repeating
  all six produces six rows whose `issuer_id` is the granted one. A test
  parameterized over fewer than six does not satisfy this criterion.
- AC-2: **Enforcement is not the select box.** Two active issuers, admin
  granted only A. `POST /certs/issue` with `issuer_id=B` in the body — a
  value the rendered form never offers — returns 403 and writes no row;
  `POST /api/v1/certificates` with `issuer_id=B` returns 403 and writes no
  row; the MCP `issue_certificate` tool with `issuer_id=B` raises and writes
  no row. Asserting that `/certs/new` renders only A satisfies **nothing**
  here: an implementation that filters the select and passes the posted id
  straight through must fail this criterion.
- AC-3: **Superadmin is implicit; viewers are not.** A superadmin holding no
  grant row issues successfully from every active issuer at all six
  non-ACME points. A **viewer** holding a grant row on every active issuer
  is refused at all six issuance points and all three non-ACME revocation
  points, with the role refusal (`forbidden for this role` /
  `_FORBIDDEN` / `_ROLE_REFUSED`), and no row changes. This measures that
  the grant check was added _after_ the role gate rather than in place of
  it: an implementation that returns True from `may_use_issuer` whenever a
  grant row exists must still fail the viewer half.
- AC-4: **The one-granted-issuer default.** With three active issuers and an
  admin granted exactly one, issuing with `issuer_id` omitted succeeds and
  the stored `issuer_id` equals the granted one — not `IssuerRequiredError`.
  Granting a second and repeating the identical call raises
  `IssuerRequiredError` and writes no row. A superadmin making the same call
  against the same three issuers gets `IssuerRequiredError`, because their
  granted set is all three. With one active issuer granted to the admin, the
  omitted-`issuer_id` call still works, so 0017's single-CA ergonomics
  survive.
- AC-5: **A grant on a retired issuer.** Admin granted issuer I; I is then
  retired. (a) I is absent from `granted_issuers`, absent from the rendered
  select, and issuing with `issuer_id=I` raises `IssuerRetiredError` — not
  `IssuerForbiddenError`, asserted on the exception type, because the
  message has to name retirement. (b) Revoking a certificate I signed
  **succeeds** for that admin at all three non-ACME revocation points, and
  I's CRL gains the serial (parsed with `openssl crl`, not merely
  byte-compared). (c) A second admin without the grant is refused revoking
  the same certificate, and I's stored CRL bytes and `crl_number` are
  unchanged after the refusal.
- AC-6: **Revocation follows the issuing grant, at all four points.** Admin
  granted A only, certificate signed by B: refused at `web/certs_ui.py:495`,
  `api/v1.py:383` and `mcp/server.py:584`; after each refusal the
  certificate's `revoked_at` is still NULL and B's `crl_state` row —
  `crl_number` and `crl_der` — is byte-identical to before. Granting B and
  repeating one of the three revokes it and changes both. The fourth,
  `acme/api_finalize.py:484`, is AC-7's.
- AC-7: **ACME issues and revokes with no cabin identity present.** With
  ACME enabled, one active issuer, and **zero rows in `user_issuers` and
  `token_issuers`**, a full ACME order finalizes into a certificate and an
  ACME `revoke-cert` for it succeeds. In the same test and against the same
  database, an ungranted admin is refused at `POST /certs/issue`. The pair
  is the point: an implementation that checks grants unconditionally inside
  `ca/certs.py` fails the first half, and one that checks them nowhere fails
  the second.
- AC-8: **The choke point cannot be forgotten.** By `inspect.signature`,
  `issue_and_store`, `sign_csr_and_store` and `revoke_certificate` each
  declare `principal` as `KEYWORD_ONLY` with `Parameter.empty` as its
  default, and calling each without it raises `TypeError`. Rationale
  asserted, not merely written: a default of `None` meaning "unrestricted"
  would let a future eighth entry point bypass AC-1 through AC-6 in silence.
- AC-9: **Nothing caches a grant.** A logged-in admin issues successfully;
  the superadmin then posts a grant set without that issuer to
  `/users/{id}/issuers`; the **next** request on the same session cookie is
  refused — no logout, no restart. The same for an API token over REST and
  for the same token secret over MCP, on the connection that already
  succeeded. The reverse holds too: adding a grant takes effect on the next
  request. Additionally, the claims dict `CabinTokenVerifier` builds
  (`mcp/auth.py:78`) has exactly the key `TOKEN_ID_CLAIM` and no issuer or
  scope list.
- AC-10: **Creating grants the creator.** An admin posts `/ca/create`: a
  `user_issuers` row exists for that admin and the new **intermediate**, no
  row exists for the new root, and that admin immediately issues with
  `issuer_id` omitted. The same for `/ca/import` and
  `/ca/{root_id}/intermediate`. A superadmin who creates a hierarchy also
  gets the row: demote them to admin and they can still issue from it, while
  a different admin who did not create it cannot. That demotion step is what
  distinguishes "the row was written" from "superadmin was implicit anyway".
- AC-11: **Only intermediates can be granted.** `set_issuers` with a root's
  id raises `ValueError` whose message names "intermediate";
  `POST /users/{id}/issuers` carrying a root's id is a 400 with no row
  written in either table; `set_issuers` with `ACME_PRINCIPAL` raises. The
  row counts before and after are equal.
- AC-12: **A deleted user's grants do not outlive them.** A user granted an
  issuer is deleted; no `user_issuers` row with that `user_id` remains. A
  new user is then created carrying that same id (constructed explicitly
  rather than relying on SQLite's rowid reuse, so the test is deterministic
  on both backends), and is refused at all six non-ACME issuance points.
  This criterion goes red the moment `users.delete_user` forgets the
  cleanup, which is the failure mode FR-10 exists for — cabin enforces no
  foreign keys on SQLite, so nothing else would notice.
- AC-13: **Editing grants is superadmin-only.** `POST /users/{id}/issuers`
  and `POST /tokens/{id}/issuers` return 403 for an admin, 403 for a viewer,
  and 403 for a superadmin without a CSRF token; after each, the row counts
  in `user_issuers` and `token_issuers` are unchanged. An unknown user or
  token id is a 404.
- AC-14: **Audit.** A grant change records `user_issuers_changed` with
  `target_type="user"` and the user id, resp. `token_issuers_changed` with
  `target_type="api_token"`, and the detail names the `added` and `removed`
  ids. Posting the identical set again adds **no** event — asserted on the
  event count, not on the absence of a string. Both actions appear as
  selectable options in `/audit`'s rendered filter. `ca_created` and
  `ca_imported` carry `granted_to` with the creating user's id.
- AC-15: **Visibility is unchanged.** With certificates issued from two
  hierarchies, an admin granted **no** issuer sees the same counts as a
  superadmin against the same database in: `/certs`, `GET
/api/v1/certificates`, the MCP `list_certificates` tool, `/ca`,
  `GET /api/v1/ca`, `get_ca_info`, the dashboard's CA list, and `/audit`.
  Equality against the superadmin's view, not a hard-coded number, so the
  criterion goes red for any filtering anyone adds later for any reason.
- AC-16: **A token's grants are its own, and MCP sees the same ones.** An
  admin token granted issuer A issues from A and is refused from B over
  REST; the identical secret used over MCP gives the identical two answers
  in the same test against the same database. Adding a grant on B through
  `/tokens/{id}/issuers` flips the MCP answer as well. The token's grants
  are unaffected by any grant held by the superadmin who created it —
  `api_tokens` has no owner column and none is added.
- AC-17: **Schema.** A fresh database migrated to head has `user_issuers`
  and `token_issuers`, each with a composite primary key over both of its
  columns and both columns NOT NULL. Inserting the same pair twice fails at
  the database, not only in Python. Migration `0010` has
  `down_revision = "0009"`, and `downgrade()` drops both tables.

## Test list

test_ungranted_admin_refused_at_every_issuance_entry_point (parameterized
over all six non-ACME doors), test_granted_admin_issues_at_every_entry_point,
test_ungranted_issuer_posted_directly_is_refused (UI, REST and MCP),
test_issuer_select_lists_only_granted_issuers,
test_superadmin_needs_no_grant, test_granted_viewer_still_refused,
test_single_granted_issuer_is_the_default,
test_two_granted_issuers_require_explicit_choice,
test_superadmin_with_several_active_issuers_must_choose,
test_retired_granted_issuer_reports_retirement_not_forbidden,
test_revoke_through_retired_granted_issuer_succeeds (openssl crl, both
directions), test_revocation_requires_the_issuing_grant (all three non-ACME
doors, CRL byte-compared), test_refused_revocation_changes_nothing,
test_acme_issues_with_no_grants_in_the_database,
test_acme_revoke_cert_with_no_grants_in_the_database,
test_principal_is_required_keyword_only (signature inspection plus
TypeError), test_grant_change_takes_effect_on_the_next_request (session,
token, MCP), test_mcp_access_token_claims_carry_no_scopes,
test_ca_create_grants_the_creator, test_ca_import_grants_the_creator,
test_ca_intermediate_grants_the_creator,
test_superadmin_creator_keeps_its_hierarchy_after_demotion,
test_grant_on_a_root_is_refused, test_grant_on_acme_principal_is_refused,
test_deleted_user_leaves_no_grants,
test_recreated_user_id_inherits_no_grants,
test_grant_routes_are_superadmin_and_csrf_only,
test_audit_records_grant_changes, test_unchanged_grant_set_records_nothing,
test_grant_actions_selectable_in_audit_filter,
test_visibility_unchanged_for_ungranted_admin (all eight surfaces),
test_token_grants_are_independent_of_users,
test_token_grants_identical_over_rest_and_mcp,
test_token_created_with_issuers, test_schema_join_tables_composite_pk

Two notes for whoever writes these.

- **The existing 0005–0017 issuance tests are affected.** Any test that
  builds a hierarchy through `ca_service` directly and then issues as an
  admin now has an admin with no grant, because FR-8's auto-grant only fires
  on the `/ca` routes. Those tests are updated by granting explicitly (or by
  acting as a superadmin, which is what most of them already do), not by
  weakening the rule. Where a test issues through the route it exercises,
  nothing changes.
- **A mutation to watch for.** Replacing `may_use_issuer` in FR-6 with
  `granted_issuers` passes every criterion here except AC-5(b) — issuing is
  unaffected, and revocation only breaks once the issuer is retired. AC-5(b)
  is the only thing standing between that mutation and a green suite.

## Out of Scope

**Visibility filtering** — stated as a decision in FR-13 and repeated here
so it cannot be read as an oversight. The inventory, the CA list, the
dashboard and the audit log show everything to every logged-in identity.
Anyone proposing to filter them has to answer what happens to the expiry
warnings, and to an audit log that shows each reader only their own actions.

**ACME per-issuer authorization (spec 0019).** FR-7 exempts ACME because
there is no cabin identity behind it. The consequence is a real gap and is
named rather than buried: an admin with no grant who can register an ACME
account against an instance with ACME switched on can still obtain a
certificate, from whichever issuer the 0017 default rule picks. Closing it
means binding an account to an issuer through the directory URL and the EAB
key, which is exactly what 0019 does — including the EAB key's own
`ca_certificate_id`. Until then, ACME plus grants is a combination whose
weaker half is ACME.

Also out: grants on roots (FR-10 — nothing signs with one). Grant groups,
roles or inheritance; the model is a flat pair of join tables and an
instance with enough identities to want groups has outgrown more than this.
An owner column on `api_tokens` — spec 0008 left tokens ownerless on
purpose, and FR-1's second table is the consequence, not a workaround to be
tidied away later. Per-profile, per-name or per-SAN permissions: what an
issuer may be used _for_ is name constraints, spec 0020. Turning on
`PRAGMA foreign_keys` for SQLite — a global change affecting every table in
cabin, and FR-10's explicit cleanup is the narrow fix this spec needs.
Revoking or re-issuing certificates when a grant is withdrawn: a
certificate already issued stays valid, because the grant governed the act
of issuing and not the certificate's life. Any change to who may _create_ a
hierarchy — that stays `require_admin`, as in 0017.
