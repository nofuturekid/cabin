# Spec 0020 — Name Constraints

## Context

Spec 0017 gave cabin several hierarchies, 0018 decided who may sign with
which of them, and 0019 decided which one an ACME account reaches. All three
answer questions about **who**. This one answers the only question left:
**what** an issuer is allowed to sign for.

Without it, delegation in cabin is all-or-nothing. An operator who wants a
lab intermediate that cannot mint `login.corp.example` has exactly one tool —
not creating it — because every active intermediate on the instance may sign
every name any of the others can. Name constraints are what turns "this
hierarchy is for the lab" from a naming convention into a property of the
certificate.

**The extension is the easy half.** When an intermediate is created the
operator may name permitted and excluded subtrees, and they go into the
certificate as a critical `NameConstraints` extension (RFC 5280 4.2.1.10),
built next to the `BasicConstraints` and `KeyUsage` that
`ca/x509.py:146-185` already writes. DNS suffixes and IP networks are the
whole vocabulary; email and directory names stay out (Out of Scope says why).

**The half that matters is that cabin enforces its own constraints before it
signs.** Writing the extension and trusting the relying party to check it
would mean cabin cheerfully issues a certificate that every validator then
rejects — and the operator finds out when a service stops answering, days
later, with nothing connecting the outage to the CA that produced it. A CA
that signs something it has published a promise not to sign has not enforced
a policy; it has manufactured an outage with a signature on it.

So the check sits in `ca/leaf.py:297-367`, in `_build_leaf`, immediately
before `builder.sign(...)` at `:366`, beside the SAN validation that is
already there (`_normalize_san` at `:131-159`, `_resolve_sans` at
`:228-247`). That is the one place both issuance flows converge:
`issue_certificate` (`:370`) and `sign_csr` (`:452`) each call it, and every
front door — the two UI forms, the two REST endpoints, the two MCP tools,
ACME's finalize, and cabin's own TLS certificate — reaches one of those two.
Putting the check anywhere else means naming the doors, and naming the doors
means one day forgetting one. The one that would be forgotten is **ACME**,
where nobody is watching, where the names arrive from outside, and where the
failure surfaces as a renewal that quietly stopped working.

**The constraints live in the issuer's certificate, not in a column.** They
are read back off `ca_certificates.cert_pem` at check time. A denormalised
copy would raise the question of which one is authoritative the first time
the two drift, and there is no answer to that question that a relying party
would agree with: the relying party only ever sees the certificate. No new
column, no new migration, nothing to keep in sync.

That has a consequence worth stating rather than discovering: **constraints
are fixed when the intermediate is created.** Changing them means creating a
new intermediate — which, after 0017, is one action on the `/ca` page and the
same thing a rotation already is. And a renewal must carry them over
**unchanged**: `renew_in_place` re-signs the same row for the same key
(`ca/service.py:438-476`), and if that rebuild dropped the extension, a
routine "extend this CA by five years" would silently widen what the CA may
sign. `ca/x509.py:renew_certificate` rebuilds from a fixed list of extensions
today (`:221-223` reads SKI, BasicConstraints and KeyUsage and nothing else),
so this is not a hypothetical.

**Matching rules are where implementations get this wrong**, and the wrong
answers are all plausible-looking:

- an empty `permitted` set means **everything is allowed**, not nothing —
  RFC 5280 constrains only what it names;
- DNS matching is by **label boundary**, so `example.com` covers
  `a.example.com` and does **not** cover `badexample.com`;
- IP constraints are a **network and a mask**, not a prefix string;
- `excluded` beats `permitted`, always;
- and restrictions apply **per name form**: a certificate carrying no name of
  a constrained form is acceptable, which is why a DNS-only permitted set
  does not stop an IP address literal.

FR-5 states each of these as a rule and the Acceptance Criteria measure each
of them separately, because every one of them is a one-line mistake that
leaves the feature looking like it works.

**One warning about how any of this is verified.** This project has a
recorded finding that `openssl verify -CAfile` does **not** check the
self-signature of the certificates it is handed — it treats them as trust
anchors, trusted by assumption. It was found by a mutation harness, not by
review: a deliberately broken `renew_in_place` that generated a fresh key
passed every test in spec 0017, including the one written to prove renewal
without rekey is safe, because all of them were chain-shaped. A chain check
therefore proves almost nothing about what a CA certificate **contains**.
Every criterion below that depends on the issuer's certificate — that the
extension is present, that it is critical, that its subtrees are the ones
asked for, that a renewal did not drop it — is verified directly with
`cryptography` against the parsed `cert_pem`, and says so in the criterion,
because the next person will reach for `openssl verify` by reflex. Where a
chain check **is** the point (AC-15), the intermediate goes in `-untrusted`
and only the root in `-CAfile`, for the same reason.

## User Stories

- As an operator running a lab hierarchy next to the internal one, I create
  the lab intermediate restricted to `*.lab.internal` and `10.42.0.0/16`, and
  a request for `login.corp.example` from that intermediate is refused by
  cabin — at the form, in the API, and in ACME — rather than issued and
  rejected later by whatever tries to use it.
- As an operator, I hand a colleague an ACME EAB key for the lab issuer
  without also handing them the ability to mint a certificate for the payroll
  server, and I do not have to trust their client to check the extension.
- As an operator who was delegated a subtree by the company CA, I import that
  intermediate into cabin and cabin honours the constraints the company CA
  put on it, without me configuring anything, because they are in the
  certificate.
- As an operator renewing an intermediate for another five years, what it may
  sign for is exactly what it could sign for yesterday — a renewal is a date
  change, never a policy change.
- As an operator looking at `/ca`, I can see for every issuer what it is
  allowed to sign, read off its own certificate, so the page and the
  certificate cannot tell me different things.
- As an operator who got the constraint wrong, I am told so by the create
  form before anything is written, and I fix it by creating another
  intermediate — not by editing a certificate that has already been handed
  out.

## Functional Requirements

- FR-1: **Constraints are chosen when an intermediate is created — on both
  creation paths.** There are two, and naming only one of them would leave
  the intermediate that most instances actually use unconstrained:
  - `create_hierarchy` (`ca/service.py:220-280`) builds the root **and** the
    first intermediate of a new hierarchy. This is the one the setup wizard
    and the "create hierarchy" form on `/ca` use, so it is the one that
    matters most.
  - `create_intermediate_under` (`ca/service.py:342-389`) is 0017's rotation
    path and the only way to add a further intermediate.

  Both gain `constraints: NameConstraintSpec | None = None` and forward it to
  `ca/x509.py:create_intermediate`. `None` and an empty spec both mean "no
  constraints", and an intermediate created without them carries **no**
  `NameConstraints` extension at all — not an empty one (FR-2), and not one
  that permits everything. Every certificate created before this spec, and
  every hierarchy an operator does not constrain, behaves exactly as it does
  today.

  **Roots get none.** `create_root` (`ca/x509.py:115-143`) is unchanged and
  takes no constraint argument. A root does not sign leaves in cabin
  (`resolve_issuer` refuses any row whose `kind` is not `intermediate`,
  `ca/service.py:185-186`), so constraints on it would only ever be evaluated
  by somebody else's validator, against intermediates whose own constraints
  cabin would then have to intersect with them to stay honest. That is a
  validator's job, not an issuer's. Out of Scope records the one
  configuration in which this is visible, and FR-9 makes it visible on the
  page.

- FR-2: **The extension.** One `NameConstraints` extension, **critical**, on
  the intermediate's certificate:
  - `permittedSubtrees` from the permitted entries, `excludedSubtrees` from
    the excluded ones, each carrying `dNSName` (`x509.DNSName`) and
    `iPAddress` (`x509.IPAddress` holding an `IPv4Network`/`IPv6Network`)
    general names and nothing else. An `x509.IPAddress` in a name-constraint
    subtree must hold a **network**, never a bare address: the DER form is
    address plus mask, and a bare address encodes to half the required
    length.
  - A side with no entries is `None`, not `[]`. `cryptography` raises
    `ValueError("permitted_subtrees must be a non-empty list or None")` for
    the empty list, and RFC 5280 4.2.1.10 forbids an extension with both
    sides absent — which is also why an intermediate with no constraints at
    all gets no extension rather than an empty one.
  - Critical, as RFC 5280 requires ("this extension MUST be critical"). The
    cost is real and accepted: a relying party that does not implement name
    constraints must reject the certificate rather than ignore the promise on
    it. That is the correct failure direction for a CA that is issuing on the
    strength of that promise. Every validator cabin's interop gate uses
    (OpenSSL 3, Go, NSS, Windows) implements them.
  - `minimum`/`maximum` on a `GeneralSubtree` are not emitted. RFC 5280
    requires `minimum` to be zero and `maximum` to be absent, and
    `cryptography` does not offer them.

- FR-3: **Operator input is parsed in exactly one place.**
  `leaf.parse_name_constraints(permitted_text, excluded_text)` takes the two
  form fields — one entry per line, blank lines ignored — and returns a
  `NameConstraintSpec`, raising `NameConstraintError` (FR-8) with a message
  naming the offending line. The rules, all of which exist to keep an entry
  from meaning something other than what the operator read into it:
  - An entry that parses as an IP network or an IP address is an
    **iPAddress** subtree; a bare address is that address's `/32` or `/128`.
    An address with host bits set (`10.1.2.3/8`) is **refused**, not silently
    widened to `10.0.0.0/8` — `ipaddress.ip_network(..., strict=False)`
    accepts it and produces a constraint an order of magnitude wider than
    what was typed.
  - Anything else is a **dNSName** subtree, validated by the same hostname
    rule the SAN policy uses (`ca/leaf.py:87-88`), lower-cased, with one
    leading dot stripped (`.example.com` and `example.com` are the same
    constraint; the leading-dot spelling is common in OpenSSL configuration
    and is accepted rather than silently taken as a hostname with an empty
    first label).
  - A **wildcard is refused**. `*.example.com` is not a name-constraint
    syntax; RFC 5280's subtree already means "this name and everything below
    it", and accepting the star would let an operator write a constraint that
    means one thing to them and another to every validator.
  - An **empty entry is refused**. An empty `dNSName` constraint matches
    every name, so a stray blank-but-not-whitespace line would turn a
    restriction into its opposite.
  - At most 50 entries per side, the same kind of sanity cap `MAX_SANS`
    (`ca/leaf.py:75`) is, so one form post cannot mint a multi-megabyte CA
    certificate.

  Parsing happens in the route, **before** anything is written.
  `create_hierarchy` inserts the root and flushes before it builds the
  intermediate (`ca/service.py:261-269`); a constraint error discovered
  inside the service layer would leave a root behind for an operation the
  operator will read as having failed.

- FR-4: **Enforcement lives in `_build_leaf`, and reads the constraints off
  the issuer's certificate.** `ca/leaf.py:_build_leaf` calls
  `check_name_constraints(issuer_cert, subject_cn, sans)` after the validity
  clamp and before `builder.sign(...)` (`:366`). It **takes no new
  parameter**: `issuer_cert` is already there, and `sans` is already the
  resolved, canonical list. That is deliberate and is the whole
  anti-regression design of this requirement — there is no argument a caller
  can forget to pass, no keyword a new entry point can omit, and no door that
  can be added later without the check coming with it. `issue_certificate`,
  `sign_csr` and both `ca/certs.py` functions keep their signatures
  unchanged.

  An issuer certificate with no `NameConstraints` extension permits
  everything, and the check returns immediately — the cost on the
  unconstrained path is one `get_extension_for_class` and an
  `ExtensionNotFound`.

  `self_signed_server_certificate` (`ca/leaf.py:407`) is not affected: it has
  no issuer, so there is nothing to constrain it against.

- FR-5: **The matching rules, stated so that no two of them have to be
  guessed at.** Let the issuer's constraints be read back as sets of
  dNSName suffixes and iPAddress networks, and let the checked names be
  FR-5's name set (below).
  1. **Excluded beats permitted.** A name matching any excluded subtree is
     refused, whatever the permitted set says. Excluded is evaluated first.
  2. **An empty permitted set for a name form permits every name of that
     form.** Not "permits nothing". An issuer with only excluded entries is a
     blocklist and nothing else.
  3. **Restrictions apply per name form** (RFC 5280 4.2.1.10: "restrictions
     apply only when the specified name form is present"). DNS constraints
     are evaluated against DNS names only, IP constraints against IP
     addresses only. A certificate carrying only IP SANs is unaffected by a
     DNS-only permitted set — which is exactly what OpenSSL, Go and NSS do,
     and therefore what cabin must do (FR-7). An operator who wants an issuer
     that may sign no IP addresses at all excludes `0.0.0.0/0` and `::/0`;
     the `/ca` page (FR-9) is where they see whether they did.
  4. **DNS matching is by label boundary, case-insensitively.** A name `n`
     matches a constraint `c` when `n == c` or `n` ends with `"." + c`. Both
     sides are compared lower-cased. `example.com` therefore covers
     `example.com`, `a.example.com` and `a.b.example.com`, and covers none of
     `badexample.com`, `notexample.com`, `example.como` or
     `example.com.evil.net`.
  5. **A wildcard label is an ordinary label.** `*.example.com` is inside
     `example.com` and outside `other.com`; it is never treated as matching
     more than its own position, and it never widens a match. `*.com` is
     outside `example.com`, because `*.com` does not end at a label boundary
     of it.
  6. **IP matching is containment in a network, and iPAddress is one name
     form covering both families.** An address matches a constraint when it
     is inside that network. An IPv6 address is never inside an IPv4 network
     and vice versa — so a permitted set listing only IPv4 networks does
     permit no IPv6 address at all, because the iPAddress form **is**
     present in the constraints and the address matches none of its subtrees.
     This is not the same statement as rule 3 and the two are easy to
     conflate.
  7. **The name set.** The resolved SAN list's DNS and IP entries, plus the
     subject CN as a dNSName **only when the SAN list contains no DNS entry
     at all**. That condition is not an arbitrary simplification: it is
     precisely what OpenSSL's `NAME_CONSTRAINTS_check_CN` does, and matching
     the validator in both directions is this spec's whole point (FR-7).
     Checking the CN unconditionally would refuse certificates every
     validator accepts; not checking it at all would issue a certificate with
     only an IP SAN and an out-of-subtree hostname in the CN, which OpenSSL
     rejects. A certificate issued with no subject at all
     (`allow_empty_subject`, `ca/leaf.py:452-519`) contributes no CN.
  8. **A name form cabin cannot evaluate is refused, not ignored.** If the
     issuer's constraints carry subtrees of a form this spec does not
     implement — `rfc822Name`, `directoryName`, `uniformResourceIdentifier`,
     `otherName`, all of which an **imported** intermediate may legitimately
     carry — then a leaf carrying a SAN of that same form is refused with a
     message saying cabin cannot evaluate it. Refusing to sign a name it
     cannot judge is the conservative direction, and the alternative is
     issuing a certificate whose acceptance cabin has no opinion about. In
     practice this is the email SAN of an imported, email-constrained CA;
     cabin emits no other constrainable form.
  9. **A refusal names what was refused.** The message carries the offending
     name and the constraint it violated (`"nas.other.lan is not permitted by
this CA's name constraints (permitted DNS: example.com)"`), because the
     operator's next action is either to fix the name or to use a different
     issuer, and neither is possible from "refused".

  A certificate with **no subject alternative names at all** cannot be issued
  by cabin — `_resolve_sans` refuses it at `ca/leaf.py:242` — so the case
  does not arise at issuance. The matcher still answers it, and it answers
  "allowed", by rule 3: constraints restrict the names that are present.

- FR-6: **A renewal carries the constraints over, unchanged.**
  `ca/x509.py:renew_certificate` copies the issuer's `NameConstraints`
  extension — value and criticality — onto the renewed certificate when the
  original carried one, and writes none when it did not, exactly as it
  already does for `BasicConstraints`, `KeyUsage` and the SKI (`:221-223`,
  `:239-241`). `renew_in_place` (`ca/service.py:438-476`) and
  `POST /ca/{ca_id}/renew` gain nothing at all: renewal takes `years` and
  only `years`.

  The reason this is a requirement of its own rather than a line in FR-2:
  a renewal that dropped the extension would take an intermediate that was
  restricted to one subtree and turn it into one that may sign anything, on
  an operator action whose entire visible effect is a later expiry date, with
  no error and no audit difference. And it would pass every chain-shaped
  test, for the reason the Context gives. AC-8 compares the extension's DER
  bytes across the renewal.

- FR-7: **cabin's check and the extension cabin writes say the same thing.**
  This is a requirement and not a nice property, because it is the only thing
  that makes both halves of the feature worth having:
  - if cabin's check is **laxer** than the extension, cabin issues
    certificates that relying parties reject — the failure this spec exists
    to prevent, arriving later and further from its cause;
  - if cabin's check is **stricter**, cabin refuses certificates that every
    relying party would have accepted, and the operator's only diagnosis is
    that cabin disagrees with the standard.

  Rules 3, 6 and 7 of FR-5 are each the _less obvious_ answer, chosen for
  this reason. The single exception, deliberately in the strict direction, is
  FR-5 rule 8, where cabin has no implementation to be equal to. AC-15
  measures the equality in both directions against a real validator.

- FR-8: **One error type, a subclass, so no door can miss it.**
  `NameConstraintError` subclasses `leaf.IssueError` and lives beside it in
  `ca/leaf.py`. Because it is a subclass, every front door already handles
  it, with no change and no possibility of one being forgotten:
  `web/certs_ui.py:354` and `:417` re-render the form at 400,
  `api/v1.py:117` answers 400, `mcp/server.py:260` raises `ToolError`,
  `tls.py:493-527` logs and audits and keeps the current material, and
  `acme/api_finalize.py:283-296` turns it into an ACME problem document.

  ACME gets the one change: that block currently maps every issuance failure
  to `ErrorType.server_internal` (`api_finalize.py:294`). A name constraint
  refusal is **not** a server error — the client asked for a name this CA may
  not sign, and telling it the server is broken invites it to retry forever.
  `NameConstraintError` is matched **before** the existing tuple and answered
  with `ErrorType.rejected_identifier`
  (`urn:ietf:params:acme:error:rejectedIdentifier`, 400 —
  `acme/errors.py:31,68`), which is the type `acme/service.py:106` already
  uses for an identifier cabin will not accept. Everything else in that
  handler is unchanged: the claim still comes off the order, the order is
  still not marked `invalid`, and the response still carries a
  `Replay-Nonce`.

- FR-9: **UI.** Two form fields and one read-back, all of them reading the
  certificate rather than a remembered value.
  - `POST /ca/create` (`web/ca_ui.py:237-300`) gains
    `permitted_names: str = Form("")` and `excluded_names: str = Form("")`,
    rendered as two textareas in **both** copies of the create form —
    `templates/ca_setup.html:28-57` (the first-run wizard) and
    `templates/ca_list.html:47-76` (every later hierarchy). Both, because
    they are two copies of one form and constraining only the second would
    mean the very first intermediate on an instance is the one that cannot be
    restricted.
  - `POST /ca/{root_id}/intermediate` (`web/ca_ui.py:353-400`) gains the same
    two fields. The current control is a single inline form on the root's row
    (`templates/ca_list.html:19`) that shares one `years` input between
    Renew and +Intermediate and has no room for two textareas; it becomes a
    `<details>` block of its own per root row, with its own `name`,
    `key_type`, `years`, `permitted_names` and `excluded_names`, while Renew
    and Retire stay in the inline form they are in now.
  - `POST /ca/import` gains **nothing**. An imported certificate is already
    signed; its constraints were decided by whoever signed it, and a field
    that appeared to change them would be a field that changes nothing.
  - `/ca` shows, for **every** row that carries them — intermediate or root —
    the permitted and excluded entries, obtained by `constraints_of` from
    that row's own `cert_pem` in `_row_view` (`web/ca_ui.py:144-175`),
    alongside the `crl_url`, `ca_url` and `acme_directory_url` it already
    computes. A row with no constraints renders no such block. Roots are
    included because an imported root may carry constraints cabin does not
    evaluate at issuance (Out of Scope), and the page is where an operator
    finds out that it does.

  A form error re-renders the page at 400 with the message, the way
  `_years_error` and `_path_length_error` already do (`web/ca_ui.py:250-259`)
  — and, per FR-3, before any row is written.

  **Templates are edited through a script, never with Edit/Write**: the
  PostToolUse formatter breaks Jinja tags apart (`{% if x == "y" %}` becomes
  `{% if x="" ="y" %}`). This has cost this project a debugging session
  before and it will again.

- FR-10: **Audit.** No new `AuditAction`. The `ca_created` detail written by
  both creation routes (`web/ca_ui.py:276-289` and `:390-398`) gains
  `permitted` and `excluded`, as lists of the canonical entry strings, read
  back from the certificate that was actually produced rather than echoed
  from the form. Present and empty when there are none, so the log
  distinguishes "this CA was created unconstrained" from "this cabin version
  did not record it". `ca_renewed` gains nothing: FR-6 makes a renewal a
  no-op for constraints, and a field that is always identical to the previous
  one is noise.

- FR-11: **cabin's own certificate is not exempt.** `tls.py:558` issues
  cabin's own TLS certificate through the ordinary `issue_and_store` path,
  and it passes through `_build_leaf` like everything else, so an issuer
  whose constraints exclude cabin's own hostname will refuse it. That is
  correct and is not softened with an exemption: an issuer that may not sign
  `ca.example.lan` may not sign it for cabin either, and a certificate cabin
  issued to itself in violation of its own published promise would be
  rejected by every browser it was served to.

  The failure path already exists and is the right one: `ensure_current`
  catches `IssueError` (`tls.py:493-505`), logs a warning, keeps the current
  material rather than dropping the listener, writes one
  `tls_certificate_failed` audit event on the transition into failure and not
  one per tick (`tls.py:514-527`), and returns `False`. Nothing is added to
  it. What this requirement fixes is that it must not be **discovered**: an
  operator constraining the issuer that cabin's own TLS binding points at
  gets a certificate that stops renewing 30 to 90 days later. AC-13 asserts
  the behaviour; the remedy is 0017's — create another intermediate that
  permits the name and rebind — because constraints are fixed (FR-6).

## Interface Contract

What the changed things are called, take and return, so that the modules on
either side of a seam cannot be built against two different guesses.

### Where this code lives, and why not in `cabin.ca.x509`

The spec type, its parser, the extension builder, the reader and the matcher
all live in **`cabin.ca.leaf`**, and `cabin.ca.x509` takes a finished
`x509.NameConstraints` object.

Two reasons. The mechanical one: `NameConstraintError` must subclass
`leaf.IssueError` so FR-8 holds, and `ca/x509.py` cannot import `ca/leaf.py`
— `leaf` already imports `x509` (`ca/leaf.py:24-29`) and the reverse would be
a cycle. The substantive one is the same argument 0017 FR-12 made when it put
`public_http_origin` in `ca/leaf.py`: the vocabulary of a constraint — what a
DNS suffix means, what an IP network means, how a name is normalised before
comparison — has to be **one** implementation shared by the code that writes
the extension and the code that checks against it, or the two drift and FR-7
stops holding. Putting it next to `_normalize_san` and `_is_hostname`, which
it reuses, is what makes "cabin's check matches the extension cabin writes"
structurally true instead of a coincidence maintained by hand.

`cabin.ca.service` imports both and does the wiring; it gains no logic.

### `cabin.ca.leaf`

```python
class NameConstraintError(IssueError):
    """A name is outside the issuer's name constraints, or a constraint
    entry is not one cabin can express. A subclass of IssueError so every
    existing door refuses it; distinguished only so ACME can answer
    rejectedIdentifier instead of serverInternal (FR-8)."""


@dataclass(frozen=True)
class NameConstraintSpec:
    permitted_dns: tuple[str, ...] = ()
    permitted_ip: tuple[IPv4Network | IPv6Network, ...] = ()
    excluded_dns: tuple[str, ...] = ()
    excluded_ip: tuple[IPv4Network | IPv6Network, ...] = ()

    def is_empty(self) -> bool: ...


MAX_NAME_CONSTRAINTS = 50


def parse_name_constraints(permitted: str, excluded: str) -> NameConstraintSpec: ...
def name_constraints_extension(spec: NameConstraintSpec) -> x509.NameConstraints | None: ...
def constraints_of(cert: x509.Certificate) -> NameConstraintSpec: ...
def check_name_constraints(
    issuer_cert: x509.Certificate, subject_cn: str | None, sans: Sequence[str]
) -> None: ...
```

- Frozen, with tuples rather than lists, so a spec cannot be mutated between
  the moment it is validated and the moment it is signed into a certificate.
- `parse_name_constraints` raises `NameConstraintError` (FR-3). It is the
  only place operator text becomes a constraint.
- `name_constraints_extension` returns `None` for an empty spec — the caller
  then adds no extension (FR-2). It never returns an extension with an empty
  subtree list.
- `constraints_of` is the one reader, used by `check_name_constraints`, by
  `renew_certificate`'s carry-over check and by `/ca`'s row view, so the page
  cannot describe an issuer differently from the way the check evaluates it.
  It returns only the forms this spec implements; the forms it does not are
  reported separately for FR-5 rule 8 (an implementation detail of the
  matcher, not a public shape).
- `check_name_constraints` returns `None` and raises `NameConstraintError`.
  It is called from `_build_leaf` and takes no `db`, no settings and no
  issuer id — it is a pure function of a certificate and a list of names, and
  `tests/test_ca_leaf.py`, which never opens a database, is where most of
  FR-5 is measured.

`issue_certificate`, `sign_csr`, `_build_leaf`, `_normalize_san`,
`parse_san_lines`, `san_strings`, `_resolve_sans`, `public_http_origin` and
`self_signed_server_certificate` all keep their current signatures.

### `cabin.ca.x509`

```python
def create_intermediate(
    root_cert: x509.Certificate,
    root_key: CertificateIssuerPrivateKeyTypes,
    subject_cn: str,
    key_type: str,
    years: int = 10,
    name_constraints: x509.NameConstraints | None = None,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]: ...
```

Adds the extension as **critical** when the argument is not `None`, and adds
nothing when it is. The parameter follows `years`, so every existing
positional and keyword call is unaffected.

`renew_certificate(cert, parent_cert, parent_key, years)` keeps its signature
and gains one carried-over extension (FR-6): `NameConstraints`, with its
criticality preserved, present in the output exactly when it was present in
the input. `create_root` and `load_import` are unchanged.

### `cabin.ca.service`

```python
def create_hierarchy(
    db,
    secrets,
    name,
    key_type="ecdsa-p256",
    root_years=20,
    intermediate_years=10,
    path_length=1,
    constraints: NameConstraintSpec | None = None,
) -> CAHierarchy: ...


def create_intermediate_under(
    db,
    secrets,
    root_id,
    name,
    key_type="ecdsa-p256",
    years=10,
    constraints: NameConstraintSpec | None = None,
) -> CACertificate: ...
```

Both forward `leaf.name_constraints_extension(constraints)` to
`create_intermediate` and do nothing else with it. `import_hierarchy`,
`renew_in_place`, `retire`, `resolve_issuer`, `signing_credentials`,
`get_ca`, `chain_for`, `list_cas` and `active_issuers` are unchanged, and no
new exception type is added to this module — a constraint failure is a
`leaf.NameConstraintError` wherever it happens.

### `cabin.ca.certs`

Unchanged. `issue_and_store` and `sign_csr_and_store` keep their signatures,
gain no parameter and gain no check: FR-4 is enforced one layer below them,
which is what makes it reach ACME and cabin's own TLS certificate without
either of them knowing about it.

### Schema

**No migration.** `ca_certificates` gains no column, `certificates` gains no
column, and no new table appears. AC-9 asserts this against the schema cabin
migrates to, because "we did not add a column" is exactly the kind of claim
that quietly stops being true.

### Routes

| Method | Path                         | Change                                                |
| ------ | ---------------------------- | ----------------------------------------------------- |
| POST   | `/ca/create`                 | + `permitted_names`, `excluded_names` (both `""`)     |
| POST   | `/ca/{root_id}/intermediate` | + `permitted_names`, `excluded_names` (both `""`)     |
| POST   | `/ca/import`                 | unchanged — an imported certificate is already signed |
| POST   | `/ca/{ca_id}/renew`          | unchanged — `years` only (FR-6)                       |
| GET    | `/ca`                        | renders each row's constraints (FR-9)                 |

No route is added and none is removed. Auth on all of them is unchanged:
admin + CSRF for the POSTs, session for the page.

## Acceptance Criteria

Every criterion names the mutation it exists to catch. "Refused" means the
door's own refusal **and** no state change: `select count(*) from
certificates` unchanged, and for a creation route no `ca_certificates` row
written either. A criterion that only asserts a status code or a substring
satisfies nothing here.

Unless stated otherwise, the fixture is one instance with an intermediate
**A** constrained to permitted DNS `example.com` and an unconstrained
intermediate **B**, both active, under different roots — so that "refused
because of the constraint" cannot be confused with "refused because
something else was wrong", and so the default-issuer rule of 0017 FR-6 is
never what is being measured.

- AC-1: **The extension is written, is critical, and says what was asked —
  verified with `cryptography`.** A's certificate, parsed from its stored
  `cert_pem`, has a `NameConstraints` extension with `critical is True`,
  `permitted_subtrees == [DNSName("example.com")]` and
  `excluded_subtrees is None`. B's certificate raises `ExtensionNotFound` for
  the same class — asserted as an absence, not as an empty extension. The
  same holds for an intermediate created through
  `POST /ca/{root_id}/intermediate` as for one created through
  `POST /ca/create`.
  Asserted against the parsed certificate and **not** through
  `openssl verify`: a certificate handed to `-CAfile` is a trust anchor and
  its contents are never examined, so a chain check cannot see any part of
  this criterion.
  _Goes red if_: the extension is non-critical, is written on the root
  instead of the intermediate, is written only on one of the two creation
  paths, or is written as an empty extension for an unconstrained CA.
- AC-2: **The check runs at every door, including ACME, in one test against
  one database.** For `nas.other.lan` from issuer A: `POST /certs/issue`,
  `POST /certs/sign`, `POST /api/v1/certificates`,
  `POST /api/v1/certificates/sign`, both MCP tools, and a full ACME order +
  challenge + finalize bound to A are each refused, and the total
  `certificates` row count is unchanged from before the first of them to
  after the last. The same seven doors then issue `nas.example.com` from A
  successfully, and all seven issue `nas.other.lan` from **B**.
  _Goes red if_: the check is placed in `web/certs_ui.py` (the four non-UI
  doors pass), in `ca/certs.py`'s two functions (a future door bypasses it,
  and the ACME half of this criterion is what makes that visible today), or
  if a refusal still writes a row.
- AC-3: **DNS matching is by label boundary.** From A: `example.com`,
  `a.example.com`, `a.b.example.com`, `EXAMPLE.COM` and `*.example.com` are
  all issued. `badexample.com`, `notexample.com`, `example.como`,
  `example.com.evil.net`, `*.com` and `com` are all refused, each writing no
  row.
  _Goes red if_: the match is `name.endswith(constraint)` (`badexample.com`
  is issued), is case-sensitive (`EXAMPLE.COM` is refused), or treats the
  wildcard as widening (`*.com` is issued).
- AC-4: **An empty permitted set permits everything, and constraints apply
  per name form.** Issuer C carries only `excluded` DNS `lab.internal`:
  `anything.at.all.test` is issued, `lab.internal` and `x.lab.internal` are
  refused. From A — permitted DNS only, no IP entries — a certificate whose
  only SAN is `IP:10.9.9.9` is **issued**, because the iPAddress form is not
  constrained. Issuer D, permitted DNS `example.com` plus excluded
  `0.0.0.0/0` and `::/0`, refuses the same IP request and still issues
  `www.example.com`.
  _Goes red if_: an empty permitted set is read as "deny all" (C issues
  nothing and A's IP request is refused), or if DNS constraints are applied
  to IP names (A's IP request is refused, which is also cabin being stricter
  than every validator — FR-7).
- AC-5: **Excluded beats permitted.** Issuer E: permitted `example.com`,
  excluded `secret.example.com`. `www.example.com` is issued;
  `secret.example.com` and `a.secret.example.com` are refused, with a message
  naming the excluded subtree rather than the permitted one.
  _Goes red if_: permitted is evaluated first and short-circuits, which is
  the natural way to write the loop.
- AC-6: **IP constraints are networks, and the family matters.** Issuer F:
  permitted `10.0.0.0/8` and `2001:db8::/32`. `IP:10.5.5.5` and
  `IP:2001:db8::1` are issued; `IP:192.168.1.1` and `IP:2001:db9::1` are
  refused. Issuer G, permitted `10.0.0.0/8` only: `IP:2001:db8::1` is
  **refused** — the iPAddress form is present in the constraints and no IPv4
  network contains an IPv6 address. Creating an issuer with `10.1.2.3/8` in
  the form is a 400 with no row written (FR-3's host-bits rule), and the
  message names the line.
  _Goes red if_: matching compares address strings by prefix (`10.5.5.5` and
  `10.99.0.1` would both "match" `10.0.0.0/8` for the wrong reason, and
  `192.168.1.1` against a `192.168.0.0/24` constraint would pass), or if
  `strict=False` silently widens `10.1.2.3/8`.
- AC-7: **The CN is checked exactly when a validator would check it.** From
  A: (a) a request with CN `evil.other.lan` and the single SAN `IP:10.0.0.1`
  is **refused** — no DNS SAN is present, so OpenSSL applies the dNSName
  constraint to the CN; (b) a request with CN `evil.other.lan` and the SAN
  `DNS:www.example.com` is **issued**, and the stored row's `subject_cn` is
  `evil.other.lan`. Case (b) is additionally verified against
  `openssl verify` per AC-15's method and must pass there too.
  _Goes red if_: the CN is checked unconditionally (b is refused — cabin
  stricter than every validator), or never (a is issued — cabin laxer than
  OpenSSL, and the certificate is rejected in the field).
- AC-8: **A renewal carries the constraints over, byte for byte.** A is
  renewed with `POST /ca/{A}/renew`, `years=5`. Its parsed certificate
  afterwards has a `NameConstraints` extension whose value's DER encoding is
  **identical** to the one before the renewal and whose `critical` is still
  `True`, while the serial number has changed and `not_after` has moved —
  all four asserted with `cryptography` against the stored `cert_pem`. Then,
  by effect: `nas.other.lan` from A is still refused, through the UI **and**
  through ACME, and `nas.example.com` is still issued.
  This criterion must not be written as a chain check. A `renew_certificate`
  that dropped the extension produces a certificate that verifies perfectly
  in every chain-shaped test — that is the recorded `-CAfile` blind spot that
  let a broken 0017 renewal pass its whole test suite.
  _Goes red if_: `renew_certificate` rebuilds from its fixed extension list
  and does not copy `NameConstraints`, or copies it as non-critical.
- AC-9: **Nothing is stored outside the certificate.** Against the schema a
  fresh database migrates to — not against the migrations' source text —
  `ca_certificates` has exactly the columns 0017 FR-1 gave it and no
  constraint column of any name, `certificates` is likewise unchanged, and
  the migration chain still ends at `0010` with no `0011`. `POST
/ca/{A}/renew` with `permitted_names` and `excluded_names` posted as extra
  form fields leaves A's extension bytes unchanged (FR-6), and no route
  anywhere accepts a constraint change on an existing row.
- AC-10: **An imported intermediate is enforced from its own certificate.** A
  CA certificate carrying permitted DNS `partner.example` is imported through
  `POST /ca/import`: the import form renders **no** constraint field
  (asserted on the parsed DOM, as an absent control), issuing
  `www.partner.example` from it succeeds, issuing `www.other.example` is
  refused at all doors, and `/ca` shows the constraint on that row. An
  imported intermediate additionally carrying an `rfc822Name` subtree refuses
  a leaf with an `EMAIL:` SAN (FR-5 rule 8) while still issuing a DNS name
  inside its permitted set.
  _Goes red if_: enforcement reads a cabin-side value rather than the
  certificate — an imported CA has no cabin-side value, so it would be
  unconstrained.
- AC-11: **Bad constraint input is refused before anything is written.**
  `POST /ca/create` with `permitted_names` containing `*.example.com`, or
  `10.1.2.3/8`, or `not a hostname`, or 51 entries: each returns 400 with the
  offending line named in the re-rendered page, and the `ca_certificates` row
  count is unchanged — **including the root**, which `create_hierarchy`
  inserts and flushes before it reaches the intermediate. The same inputs at
  `POST /ca/{root_id}/intermediate` are 400 with no row. Empty
  `permitted_names` and `excluded_names` are valid and produce an
  unconstrained intermediate (AC-1).
  _Goes red if_: parsing happens inside `create_hierarchy` — the root is then
  left behind by an operation the operator was told had failed.
- AC-12: **`/ca` shows what each certificate carries.** A's row renders
  `example.com` as visible text in a constraints block, and the rendered
  values equal `leaf.constraints_of(<A's parsed cert>)`; B's row renders no
  such block at all (asserted as an absent element, not an empty string). A
  root imported with constraints renders them on the **root** row.
  _Goes red if_: the page echoes the creation form's input instead of reading
  the certificate — which would be right until the first import and wrong
  forever after.
- AC-13: **cabin's own certificate is not exempt.** With TLS on and cabin's
  TLS binding pointing at an issuer whose constraints exclude the base URL's
  hostname: `ensure_current` returns `False`, cabin keeps serving the
  material it already has (the listener does not drop), exactly one
  `tls_certificate_failed` audit event is written across three consecutive
  ticks, and no `certificates` row with `source="system"` is added. Creating
  a second intermediate that permits the hostname and rebinding
  `TLS_ISSUER_ID` then makes the next `ensure_current` succeed and write the
  row.
  _Goes red if_: `SYSTEM_PRINCIPAL` or `tls.py` is given an exemption from
  the check, or if the failure takes the listener down, or if the event is
  written once per tick.
- AC-14: **ACME says `rejectedIdentifier`, and the order survives.** An order
  bound to A for `nas.other.lan` passes its challenge and is finalized: the
  response is `urn:ietf:params:acme:error:rejectedIdentifier` at 400, not
  `serverInternal` and not a bare 500; the problem detail names
  `nas.other.lan`; a `Replay-Nonce` header is present; the order's claim is
  released so the same order can be finalized again; and no `certificates`
  row is written. An order for `nas.example.com` under the same account
  finalizes normally in the same test.
  _Goes red if_: `NameConstraintError` is matched by the existing
  `IssueError` arm first and answered `serverInternal` — which is a 500-class
  problem type telling a correctly-behaving client to keep retrying a request
  that can never succeed.
- AC-15: **cabin and a real validator agree, in both directions.** Using
  A's hierarchy, with the **root** as `-CAfile` and the **intermediate** as
  `-untrusted`:
  1. a leaf cabin issued for `www.example.com` verifies, exit 0;
  2. a leaf for `nas.other.lan`, built by signing directly with A's key and
     bypassing `_build_leaf`'s check, **fails** verification with a permitted
     subtree violation;
  3. the same two, with the excluded-subtree fixture of AC-5, give the same
     two outcomes for `secret.example.com`.

  The intermediate goes in `-untrusted` and **only** the root in `-CAfile`,
  deliberately: `openssl verify` treats everything in the CAfile as a trust
  anchor and never examines it, so a chain with the intermediate in the
  CAfile would be measuring something else. Swapping the two files must flip
  no outcome in step 1 and must not turn step 2 green.
  _Goes red if_: cabin's matcher is stricter or laxer than the extension it
  wrote (FR-7). This is the criterion that catches the rules of FR-5 being
  right in cabin and wrong in the certificate, or the reverse.

- AC-16: **Audit.** `ca_created` from both creation routes carries
  `permitted` and `excluded` in its detail, equal to what
  `constraints_of` reads back from the certificate that was produced, and
  both present as empty lists for an unconstrained creation. A refused
  issuance writes **no** `certificate_issued` event — asserted on the event
  count before and after — because nothing was issued.

## Test list

test_intermediate_carries_a_critical_name_constraints_extension (AC-1,
parsed with `cryptography`), test_unconstrained_intermediate_carries_no_such
\_extension, test_create_hierarchy_applies_constraints_to_the_intermediate,
test_create_intermediate_under_applies_constraints,
test_root_never_carries_name_constraints,
test_empty_spec_writes_no_extension_rather_than_an_empty_one,
test_permitted_subtrees_is_none_not_empty_list,
test_dns_constraint_covers_the_name_itself,
test_dns_constraint_covers_subdomains,
test_dns_constraint_does_not_cover_a_longer_label (`badexample.com`,
`notexample.com`, `example.como` — the label-boundary mutation),
test_dns_constraint_does_not_cover_a_name_it_is_a_prefix_of,
test_dns_matching_is_case_insensitive,
test_wildcard_san_is_inside_its_own_subtree,
test_wildcard_san_does_not_widen_the_match (`*.com` under `example.com`),
test_empty_permitted_set_allows_everything,
test_excluded_only_issuer_is_a_blocklist,
test_dns_constraints_do_not_apply_to_ip_sans,
test_excluding_the_whole_address_space_stops_ip_sans,
test_excluded_beats_permitted, test_excluded_subtree_named_in_the_message,
test_ip_constraint_matches_inside_the_network,
test_ip_constraint_refuses_outside_the_network,
test_ipv6_address_is_not_inside_an_ipv4_network,
test_ip_constraint_with_host_bits_is_refused,
test_cn_is_checked_when_no_dns_san_is_present,
test_cn_is_not_checked_when_a_dns_san_is_present,
test_empty_subject_contributes_no_name,
test_unevaluable_constraint_form_refuses_that_san_form (imported
`rfc822Name`), test_wildcard_constraint_entry_is_refused,
test_empty_constraint_entry_is_refused,
test_leading_dot_constraint_equals_the_bare_name,
test_too_many_constraint_entries_is_refused,
test_constraint_error_is_an_issue_error_subclass,
test_refused_at_the_ui_issue_form, test_refused_at_the_ui_sign_form,
test_refused_at_the_rest_issue_endpoint,
test_refused_at_the_rest_sign_endpoint, test_refused_at_the_mcp_tools,
test_refused_at_acme_finalize (AC-2's ACME half, a real order),
test_no_certificate_row_is_written_by_any_refusal,
test_unconstrained_issuer_still_signs_everything,
test_renewal_keeps_the_extension_bytes_identical (AC-8, DER compared, not a
chain check), test_renewal_keeps_the_extension_critical,
test_renewal_still_refuses_the_same_name_through_acme,
test_renewal_of_an_unconstrained_issuer_adds_no_extension,
test_no_constraint_column_exists_in_the_migrated_schema,
test_renew_route_ignores_posted_constraint_fields,
test_imported_intermediate_is_enforced_from_its_certificate,
test_import_form_offers_no_constraint_field,
test_create_form_rejects_a_wildcard_and_writes_no_root (AC-11's partial-state
half), test_create_intermediate_form_rejects_bad_input,
test_ca_page_shows_constraints_per_row,
test_ca_page_shows_no_block_for_an_unconstrained_row,
test_ca_page_shows_an_imported_roots_constraints,
test_tls_certificate_is_not_exempt_from_the_check,
test_tls_failure_writes_one_event_across_three_ticks,
test_acme_refusal_is_rejected_identifier_not_server_internal,
test_acme_refusal_carries_a_nonce_and_releases_the_claim,
test_openssl_agrees_with_an_issued_name (AC-15, root in `-CAfile`,
intermediate in `-untrusted`),
test_openssl_rejects_a_smuggled_name (the same, counter-direction),
test_audit_ca_created_records_the_constraints,
test_audit_records_empty_lists_for_an_unconstrained_ca,
test_refused_issuance_writes_no_certificate_issued_event

Five notes for whoever writes these.

- **Most of FR-5 belongs in `tests/test_ca_leaf.py`**, which never opens a
  database. `check_name_constraints` is a pure function of a certificate and
  a list of names; a matching bug found through a route is a matching bug
  found expensively.
- **The two-issuer fixture is not optional.** With one constrained issuer on
  the instance, "refused by the constraint" and "refused by something else"
  produce the same red, and a check that refuses everything passes half of
  these tests. Every criterion that says "and B issues it" is there for that
  reason and must not be dropped as redundant.
- **`openssl verify` proves nothing about a CA certificate's contents.** Use
  `cryptography` for every assertion about the extension itself
  (AC-1, AC-8, AC-9, AC-12). Where a chain check is the point (AC-15), the
  intermediate goes in `-untrusted` and only the root in `-CAfile`. This is a
  recorded finding of this project, not a style preference: a broken
  `renew_in_place` in spec 0017 passed its entire chain-shaped test suite.
- **Templates are written by a script through Bash, never with Edit/Write.**
  The PostToolUse formatter breaks Jinja tags apart. FR-9 touches
  `ca_setup.html` and `ca_list.html`, and `ca_list.html:19` is a dense inline
  form that has to be restructured; check `git diff` after every template
  change.
- **The existing 0004–0019 tests should keep passing untouched.** An
  intermediate created without constraint arguments must be byte-for-byte the
  same shape it is today, minus nothing and plus nothing. If any existing
  test needs a change, the change is a bug in this spec's default, not in the
  test.

## Out of Scope

**Email and directory name constraints.** `rfc822Name`, `directoryName`,
`uniformResourceIdentifier` and `otherName` are not offered in the form and
are not emitted. cabin's certificates are internal TLS certificates: their
names are hostnames and addresses, and a subtree vocabulary nobody would type
is a form field that only produces mistakes. The consequence is stated rather
than hidden: an intermediate constrained to `example.com` may still sign a
certificate carrying `EMAIL:someone@elsewhere.invalid`, because no
`rfc822Name` constraint is present and RFC 5280 restricts only the forms it
names — which is also what every validator will conclude. An operator who
needs email locked out needs a constraint form this spec does not build.
FR-5 rule 8 is the other half of this: cabin **reads** those forms on an
imported certificate and refuses what it cannot evaluate, rather than
pretending they are not there.

**Constraints on roots, and constraints inherited from an ancestor.** cabin
evaluates the constraints carried by the certificate that is actually
signing. For a hierarchy cabin generates, no ancestor ever carries any
(FR-1). For an **imported** hierarchy, the parent certificate stored by
`import_hierarchy` (`ca/service.py:320-326`) may carry constraints that the
imported intermediate does not, and in that configuration a relying party
applies the parent's constraints to cabin's leaves while cabin does not —
cabin is laxer. This is left as it is, deliberately: closing it means either
threading the whole chain into the pure leaf layer (a parameter that can be
omitted is a check that can be skipped — FR-4's entire design is that there
is nothing to omit) or intersecting the subtrees at creation time, which is
validator logic in an issuer. What is done instead is that FR-9 renders a
root's constraints on the root's row, so the configuration is visible on the
page rather than being a surprise, and this paragraph exists so that the next
person reading the enforcement code knows it was a decision.

**Editing an existing intermediate's constraints.** There is no route, no
form and no service function. The constraints are in a certificate that has
been handed out; a certificate cannot be edited, and a cabin-side edit would
mean the row and the certificate say different things — the exact drift this
spec avoided by not adding a column. Changing them is creating a new
intermediate, which after 0017 is one action and is the same operation a
rotation already is.

**A pre-check at ACME's newOrder.** The account's issuer is known at
`new-order` (0019 FR-9), so cabin could refuse an out-of-subtree identifier
before the client does any challenge work, and the client would learn sooner.
It is not done: it would be a second enforcement site with its own copy of
FR-5's rules, and two sites drift — including legitimately, when an issuer is
retired or the order is finalized against different material than it was
placed against. One choke point, in the layer every door passes through, is
worth more than an earlier error. What is fixed instead is the error's shape:
FR-8 makes the finalize refusal `rejectedIdentifier` with the offending name
in it, rather than an invitation to retry forever.

**A policy requiring every intermediate to be constrained.** Creating an
unconstrained intermediate stays allowed and stays the default. An internal
CA that may sign any name on its own network is the normal way to run one —
it is what every existing cabin instance is — and turning that into a
configuration error would be this spec deciding what somebody's network is.

**Reporting constraints over REST and MCP.** `GET /api/v1/ca`'s `IssuerInfo`
and the MCP `get_ca_info` tool are unchanged. `/ca` answers "what may this
issuer sign for" for the audience that asks it, nothing today consumes the
answer programmatically, and a field with no consumer is the speculative
addition Rule 2 refuses. It is a field to add when something needs it.

**Showing an issuer's constraints on the issuance forms.** `/certs/new` and
`/certs/sign` do not preview which names the selected issuer would accept.
Useful, and a separate piece of work: it needs the issuer select's change
event, and the refusal it would prevent is already precise, immediate and
harmless (FR-5 rule 9).

**Name constraints on cross certificates.** Spec 0021's. A cross certificate
is a second certificate over an existing root's subject and public key, and
what constraints it should carry — the signing root's, none, or a narrowing
set — is a question about cross-signing, answered there. Nothing in this spec
prevents that answer, because nothing in this spec stores a constraint
anywhere but in the certificate that carries it.
