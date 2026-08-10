# Spec 0021 — Cross-Signing

## Context

Spec 0017 made rotation ordinary. A hierarchy that is running out is
replaced by a second one next to it, the old issuer is retired, and
everything already deployed keeps validating against the chain it was
issued with. For almost every instance that is the whole answer, and this
spec should not be read as an improvement on it: **running two hierarchies
side by side is the better transition, and cross-signing is the most
error-prone mechanism in the whole of PKI.** It is in scope for exactly one
situation, and the situation is real: an operator with devices on the
network whose trust store cannot be reached — an appliance with no import
path, a printer, a piece of lab equipment older than the CA — and which
will outlive a root generation. Those devices trust the old root and will
never trust anything else. Parallel operation does not help them, because
parallel operation asks every relying party to learn a new anchor.

A **cross certificate** is another certificate for a CA that already
exists: the same subject, the same public key, a new serial, and a
signature from a _different_ root. It creates no new CA and no new key. Its
only effect is that a relying party which trusts the old root can now build
a path to a certificate issued under the new one, because the new root's
public key is vouched for by the old root as well as by itself.

**The model.** A cross certificate is one more row in `ca_certificates`,
with `kind = "cross"`. Its `parent_id` names the root that signed it, so
`chain_for`'s existing walk up `parent_id` (`ca/service.py:151-159`) reaches
the old root without knowing anything new. A second column, `cross_of_id`,
names the self-signed row it duplicates, so that "these two certificates are
the same logical CA" is a fact in the schema rather than something inferred
by comparing public keys at every use. It holds no private key: the key is
the subject root's and is already sealed on that row.

**Two ways in.** A root already in cabin signs another root — the normal
case here, and the one that works even when the _signed_ root's key is not
in cabin, because signing needs only its public key. Or a cross certificate
produced elsewhere is imported, which is the case when the old root belongs
to somebody else. The import path carries the check the whole feature stands
on: **the imported certificate's subject and public key must match the
existing root exactly.** Without it an operator can staple an unrelated CA
certificate into their own served chain and cabin will hand it to every
client — and the failure would look like nothing at all, because a chain
containing a certificate nobody validates against is still a chain that
parses.

**Serving alternate chains is the actual work.** A leaf under the new root
now has two valid paths: the short one, up through the self-signed root, and
the long one, up through the cross certificate to the old root. Only one can
go in a response body, so the default has to be whichever satisfies the most
relying parties — the long one, because the population this feature exists
for is exactly the population that only knows the old anchor — and the other
has to be offered alongside rather than hidden. Every place cabin assembles
a chain is affected: `web/certs_download_ui.py:70-79` (and the PKCS#12
bundle at `:166`), `api/views.py:114-122`, `acme/api_finalize.py:361-376`,
`web/ca_ui.py:545`, and two the plan did not name — `tls.py:577`, where
cabin builds the chain it serves for its own TLS certificate, and
`web/ui.py:118`, where the dashboard decides which root to offer for import.
ACME has a mechanism for alternates in RFC 8555 §7.4.2 that cabin does not
emit today and says so in a comment (`acme/api_finalize.py:398-400`).

**The failure that must not be repeated.** On 30 September 2021 DST Root CA
X3 expired. Large numbers of clients broke, and not one of them broke
because something had been signed wrongly: every certificate involved was
correct, and a valid path existed the whole time. They broke because path
building preferred the expired route while the valid one sat beside it. The
lesson for this spec is not "warn about expiry". It is that **an expired
cross certificate must stop being served automatically** — computed at the
moment the chain is assembled, on every request, not on an operator's next
visit to a page, not by a nightly job, and not by a status column somebody
has to remember to update. FR-7 puts that check in the single function every
serving surface goes through, and the Acceptance Criteria measure it as an
effect on the bytes that come back.

**One warning about how any of this is verified, and it matters more here
than anywhere else in this project.** There is a recorded finding that
`openssl verify -CAfile` does **not** check the self-signature of the
certificates it is handed: everything in the CAfile is a trust anchor,
trusted by assumption and never examined. It was found by a mutation
harness, not by review — a deliberately broken `renew_in_place` that
generated a fresh key passed every test in spec 0017, including the one
written to prove renewal without rekey is safe, because all of them were
chain-shaped. Nearly every assertion in _this_ spec is chain-shaped, so
nearly every one inherits that blind spot, and the shapes it hides are
precisely the ones a cross certificate can get wrong: a wrong public key, a
wrong SubjectKeyIdentifier, a signature from the wrong root. Every criterion
below that is about what a certificate _contains_, or about _who signed it_,
is therefore verified directly with `cryptography` — `Name.public_bytes()`,
`SubjectPublicKeyInfo` DER, `verify_directly_issued_by` — and says so in the
criterion. Where a chain check is the point, the criterion states exactly
which file goes in `-CAfile` and which in `-untrusted`, because putting the
cross certificate in the CAfile turns the test into one that passes even if
cabin signed it with an unrelated key. A criterion that only runs
`openssl verify` may prove nothing at all.

## User Stories

- As an operator with a controller on the shop floor whose trust store I
  cannot reach and whose firmware I cannot replace, I cross-sign my new root
  with the old one, and that controller keeps accepting certificates from
  the new hierarchy without anything being installed on it.
- As an operator, I am told plainly on the page and in this document that
  cross-signing is the second-best answer, and that two hierarchies side by
  side is what I want unless I have devices I cannot reach.
- As an operator whose old root was signed by a company CA I do not run, I
  import the cross certificate they produced for my root, and cabin refuses
  it if it is not actually a certificate for _my_ root — so a mistyped paste
  cannot put a stranger's CA into the chain my services hand out.
- As a relying party that only knows the old root, the certificate my server
  presents comes with the chain that reaches it, because that is what cabin
  serves by default.
- As a relying party that already trusts the new root, I can ask for the
  short chain — through ACME's `alternate` link, or the second download on
  the page — and get exactly two CA certificates instead of three.
- As an operator on the day the cross certificate expires, nothing breaks
  and nobody has to do anything: cabin stops serving that path on the first
  request after the expiry instant, the short chain takes over, and my
  dashboard warned me a year in advance.
- As an operator who cross-signed the wrong root, I retire the cross
  certificate and it is out of every chain cabin serves on the next request
  — and I am told, in as many words, that this is not a revocation.

## Functional Requirements

- FR-1: **Schema — migration `0003` edited in place, no `0011`.**
  - `ca_certificates`'s CHECK constraint becomes
    `kind IN ('root', 'intermediate', 'cross')`
    (`store/migrations/versions/0003_ca_certificates.py:46`).
  - New column `cross_of_id` (Integer, FK `ca_certificates.id`, nullable):
    the self-signed row this certificate duplicates. NULL for every row that
    is not a `cross` row, which is why the column is nullable even though a
    cross row must always have one.

  Edited in place rather than added as a new revision, for the reason 0019
  FR-1 already gave for `0008`/`0009`: nothing in this release cycle has
  shipped, there is no upgrade path from a 0.1.x database anyway, and spec
  0020 AC-9 asserts that the migration chain still ends at `0010` with no
  `0011`. Adding a revision here would break a criterion of the spec
  immediately before this one in exchange for nothing.

  Three invariants hold for a `cross` row and are asserted by tests rather
  than by the database, because none of them is expressible as a single-row
  CHECK:
  - `parent_id` names the root that **signed** it and `cross_of_id` names
    the root it **duplicates**; the two are never the same row.
  - No row anywhere ever has a `cross` row as its `parent_id`. A cross
    certificate is a second path to an existing CA, never a place to hang a
    new one, and this is what keeps `chain_for`'s walk from ever producing a
    path that goes through two cross certificates.
  - `key_sealed` is always NULL. The private key is the subject root's and
    is already sealed on that row; a second copy would be a second copy of a
    secret, kept in sync by nothing.

  `certificates.issuer_id` can never name a cross row, and this needs no new
  check: `resolve_issuer` refuses any row whose `kind` is not
  `intermediate` (`ca/service.py:186-187`), which is the one place an
  issuer is chosen for a leaf. AC-13 asserts it there rather than assuming
  it.

- FR-2: **What a cross certificate contains, and what it must not invent.**
  A new pure function `ca/x509.py:cross_sign(subject_cert, issuer_cert,
issuer_key, years)` builds it. The certificate is, field by field:
  - **subject**: `subject_cert.subject`, unchanged. Not rebuilt from a
    string — a `Name` that renders identically can encode differently, and
    to a path builder a differently encoded name is a different CA.
  - **public key**: `subject_cert.public_key()`. This is the entire point of
    the operation and there is no code path in which it is a fresh key.
  - **SubjectKeyIdentifier**: copied from `subject_cert`, byte for byte. The
    intermediates under that root carry an AuthorityKeyIdentifier derived
    from it (`ca/x509.py:168, 187`), so a re-derived or altered SKI produces
    a certificate that is perfectly valid and that nothing chains through.
  - **BasicConstraints** and **KeyUsage**: copied from `subject_cert`,
    critical, `path_length` included (FR-3).
  - **NameConstraints**: copied when `subject_cert` carries one, value and
    criticality both; absent when it does not (FR-12).
  - **AuthorityKeyIdentifier**: derived from the _signing_ root through the
    existing `authority_key_identifier(issuer_cert, issuer_key)`
    (`ca/x509.py:76-92`), which copies the signing root's SKI rather than
    recomputing it. Non-critical.
  - **issuer**: `issuer_cert.subject`. **serial**: a new random one.
    **not_before**: `now - _BACKDATE`. **not_after**:
    `min(now + 365 * years, issuer_cert.not_valid_after_utc)` — clamped, the
    same way `create_intermediate` clamps against its root
    (`ca/x509.py:173`), because a cross certificate outliving the root that
    signed it would look like a path and never be one.
  - **No CRL distribution point and no AIA.** cabin publishes neither for a
    root: `/crl/{id}` is 404 for anything that is not an intermediate
    (`web/crl_ui.py:35-45`), so a CDP on a cross certificate would point at
    a document that does not exist. FR-10 says what follows from that.

  **This is deliberately not `renew_certificate`**, which is otherwise the
  same shape. That function adds an AuthorityKeyIdentifier only when the
  input already carried one (`ca/x509.py:240-244`), and a self-signed root
  carries none (`create_root`, `:130-141`) — so reusing it would produce a
  cross certificate with **no AKI**, which is exactly the hint a path
  builder uses to tell the two certificates of that root apart. That is the
  DST X3 pathology in miniature, so the two functions stay separate and this
  paragraph is why.

- FR-3: **What `path_length` on the signing root has to permit.** The cross
  path is one certificate longer than any path cabin builds today:
  `A → cross(B) → intermediate(B) → leaf`. RFC 5280 4.2.1.9 counts the
  non-self-issued intermediate certificates that follow a certificate in the
  path and excludes the last one, so:
  - the **signing root** A needs `pathLenConstraint` absent or **≥ 2** (the
    cross certificate and B's intermediate both count; the leaf does not);
  - the **cross certificate** needs `pathLenConstraint` absent or **≥ 1**,
    and since it is copied from the subject root (FR-2) this holds for every
    root cabin created — the form bounds `path_length` to 1..4 (0017 FR-13)
    — and can fail only for an imported root built elsewhere with 0.

  Both are checked **before anything is signed or written**, and the refusal
  names `path_length` and the value the root actually carries. This is not a
  formality: a root's `path_length` cannot be changed afterwards by any
  operation cabin has — `renew_certificate` carries BasicConstraints over
  unchanged (`ca/x509.py:238, 259`) — so the only remedy is a different
  root, which for an old root is no remedy at all.

  The consequence has to be stated rather than discovered: **a root created
  with cabin's default `path_length = 1` cannot cross-sign anything.** That
  default does not change here; widening every root by default for a feature
  most instances never use would be the wrong trade, and 0017 AC-11 asserts
  the default is 1. What changes is that the hint under the field
  (`templates/ca_list.html:75-77` and `templates/ca_setup.html:52-54`) says
  a root that may ever have to cross-sign another needs at least 2. This is
  what 0017 FR-13 meant by "cross-signing needs room in it", and it means
  cross-signing has to be planned one root generation before it is needed.
  An operator who did not plan it has 0017's parallel operation and nothing
  else, which is the honest answer and is why the Context leads with it.

- FR-4: **Cabin signs one: `cross_sign_root`.**
  `ca/service.py:cross_sign_root(db, secrets, ca_id, signing_root_id, years)`
  writes one row with `kind="cross"`, `parent_id=signing_root_id`,
  `cross_of_id=ca_id`, `status="active"`, `key_sealed=None`, and `name` the
  subject CN of the certificate it produced — which is the same name the
  subject root's row carries, exactly as 0017's naming rule intends for two
  certificates of one logical CA.
  - `ca_id` must name a `kind == "root"` row; anything else is a `ValueError`
    naming "root", the same way `create_intermediate_under` treats it
    (`ca/service.py:384-385`), because the UI only offers the action on
    roots.
  - `signing_root_id` must name a different `kind == "root"` row whose
    `key_sealed` is not NULL; a root with no stored key — every imported
    hierarchy's root (`ca/service.py:334-339`) — raises `CANotConfiguredError`
    naming the missing key.
  - The **subject** root's key is not needed and is not touched. Cabin can
    therefore cross-sign an imported root, which is worth stating because it
    is the one CA operation in cabin that works without the subject's
    private key.
  - `CrossSignError` (new, in `ca/service.py`) for the two refusals that are
    neither of the above: FR-3's `path_length`, and an attempt to cross-sign
    a root that this same signing root has already cross-signed and whose
    cross certificate is still `active` — a second identical path serves
    nobody and makes FR-6's default rule depend on a coin toss. Renewing the
    existing one (FR-11) is what extending it means.
  - Cross-signing a root with itself is refused by the "different row" rule
    above; the result would be a re-issued self-signed root, which is what
    `renew_in_place` is for.

- FR-5: **Or one is imported: `import_cross`.** The operator submits two
  PEMs — the cross certificate, and the certificate of the root that signed
  it — and nothing else. There is no private key to submit, which is why
  this does **not** go through `x509.load_import`: that function requires a
  key and refuses to proceed without one (`ca/x509.py:299-307`), and nobody
  holds the private key of a certificate somebody else produced. A new pure
  function `ca/x509.py:load_cross(cross_pem, subject_cert, issuer_cert)`
  raises `CAImportError`, with a message naming the reason, unless all of
  the following hold:
  1. `cross_pem` parses as a certificate;
  2. **`cross.subject.public_bytes()` equals `subject_cert.subject
.public_bytes()`** — compared as DER, not as an RFC 4514 string. Two
     `Name` objects that compare equal in Python can still encode
     differently (`PrintableString` against `UTF8String`), and a validator
     matching issuer to subject compares the encoding;
  3. **the SubjectPublicKeyInfo DER of the two is identical**, through the
     module's existing `_public_key_der` (`ca/x509.py:109-112`). This is the
     check the import path exists for. Without it, any CA certificate whose
     subject CN happens to read `CN=cabin Root CA` — a string that is not
     unique and that cabin itself generates from an operator's label — can
     be stapled into the chain cabin serves to every client;
  4. `cross.verify_directly_issued_by(issuer_cert)` does not raise, so the
     submitted signing root really did sign it. `ca/x509.py:340` already
     uses this for the ordinary import;
  5. its SubjectKeyIdentifier equals the subject root's. Equal public keys
     do not force equal SKIs — the signer chooses the derivation — and a
     cross certificate whose SKI differs from the one every intermediate's
     AuthorityKeyIdentifier names is a certificate no client can chain
     through (FR-2);
  6. `BasicConstraints(ca=True)` and `KeyUsage(keyCertSign)` are present,
     the same two checks the ordinary import makes (`ca/x509.py:309-321`);
  7. it is neither expired nor not-yet-valid, mirroring `ca/x509.py:323-327`
     — importing a certificate that is already past is importing a path that
     FR-7 will drop on the first request;
  8. FR-3's `path_length` rule holds for the cross certificate and for the
     submitted signing root;
  9. FR-12's NameConstraints rule holds.

  `ca/service.py:import_cross(db, cross_pem, issuer_pem)` then:
  - resolves the **subject** root by looking for the `ca_certificates` row
    whose subject DER and SubjectPublicKeyInfo both equal the cross
    certificate's. Exactly one must match; none is "this is not a
    certificate for any CA on this instance", and more than one is a
    duplicate-root state cabin cannot resolve and refuses;
  - reuses an existing row for the **signing** root when one matches it by
    the same two comparisons, and otherwise inserts it as a `kind="root"`
    row with `key_sealed=None` — the same shape `import_hierarchy` already
    stores an imported parent in (`ca/service.py:334-340`). Reused rather
    than duplicated so that two cross certificates from one old root do not
    produce two rows for it and two entries on `/ca`;
  - writes the cross row, and takes no `name` argument: 0017's naming rule
    says the row's name is the subject CN of its own certificate.

  Nothing here needs a private key, and nothing here is granted to anybody
  (FR-14).

- FR-6: **Chain assembly, in one function, with the default decided there.**
  `ca/service.py` gains:
  - `Chain` — one complete path: the rows nearest-issuer-first with the
    trust anchor last, plus the id of the cross certificate it goes through
    (`None` for the self-signed path).
  - `ChainSet` — the `default` path and the `alternates`, in that order.
  - `chains_for(db, ca_id, now=None) -> ChainSet`.

  How it is built:
  1. The **base path** is today's walk up `parent_id` from `ca_id`
     (`ca/service.py:151-159`), which for any intermediate ends at its own
     self-signed root. No cross row can appear in it (FR-1's second
     invariant).
  2. Let `top` be that path's last row. Each active cross row with
     `cross_of_id == top.id`, taken in id order, yields one **alternate
     path**: the base path with `top` replaced by that cross row, followed
     by the `parent_id` walk from the cross row upwards — which ends at the
     signing root.
  3. **One hop only.** A cross certificate whose signing root is itself
     cross-signed produces no third path. The set of paths would otherwise
     grow with every generation, and cabin would be publishing paths nobody
     asked for.
  4. FR-7 removes any alternate path that is not valid at `now`.
  5. **The default is the first surviving alternate**, i.e. the one whose
     cross row has the lowest id — the earliest cross certificate, which is
     the one signed by the oldest root generation and therefore the one in
     the most trust stores. When none survives, the default is the base
     path.
  6. `alternates` is everything else: the base path first, then the
     remaining cross paths in id order. The base path is **always** present
     in the set, whatever its own dates — if the self-signed root has
     expired there is nothing better to serve, and returning no chain at all
     would turn a bad state into a 500 on every download.

  A path is identified by the id of its **topmost row** — B's root for the
  short path, the signing root for a long one — and every one of those ids
  is distinct within a `ChainSet`. That id is what the URLs in FR-8 and FR-9
  take. It is deliberately not an ordinal: an ordinal shifts when a cross
  certificate expires, so a client that remembered "alternate 1" would
  quietly start fetching a different chain, which is the class of bug this
  whole spec is about.

  **`chain_for(db, ca_id)` keeps its exact signature** and returns
  `list(chains_for(db, ca_id).default.rows)`. That is the whole
  anti-regression design of this requirement, and it is the same argument
  0020 FR-4 made for putting the constraint check inside `_build_leaf`:
  every existing chain-assembling call site serves the default without being
  told to, there is no argument a new one can forget to pass, and no door
  can be added later without the behaviour coming with it. The doors it
  reaches without any change of their own are
  `web/certs_download_ui.py:76`, `api/views.py:122`,
  `acme/api_finalize.py:371`, `web/ca_ui.py:545` and `tls.py:577`.

- FR-7: **An expired cross certificate leaves the served chain by itself.**
  The check lives in `chains_for` and nowhere else. It is:
  - **evaluated on every call**, against `now` (defaulting to
    `datetime.now(UTC)`), with no cached value, no column, no background job
    and no dependency on any page having been visited;
  - applied to **every row on an alternate path** — the cross certificate
    _and_ the signing root above it — not only to the cross certificate. A
    path whose anchor has expired is exactly as unbuildable as one whose
    cross certificate has, and cabin's clamp in FR-2 does not cover an
    imported cross certificate whose signing root cabin does not control;
  - `not_valid_before_utc <= now <= not_valid_after_utc`, read off the
    parsed `cert_pem`;
  - **purely a read.** The cross row's `status` stays `active`, its
    `cert_pem` is untouched, and no audit event is written. Expiry is not an
    operator decision and must not be recorded as one — and a filter
    implemented as "mark it retired the next time somebody looks" is exactly
    the implementation this requirement exists to forbid.

  Removing the path removes it from the default chain, from `alternates`,
  from FR-9's `Link` headers and from FR-8's downloads in the same instant,
  because all five read the same `ChainSet`.

  This is the DST Root CA X3 requirement. Nothing broke in September 2021
  because a signature was wrong; things broke because a path builder
  preferred an expired route while a valid one sat beside it. cabin cannot
  fix anybody's path builder, but it can decline to hand one the expired
  route in the first place. AC-7, AC-8 and AC-9 measure it as an effect on
  the bytes that come back, on the first request after the expiry instant.

- FR-8: **Serving the two chains.** The default goes in the body everywhere,
  because of FR-6's `chain_for`. The alternates are offered:
  - `GET /certs/{cert_id}/download/chain.pem` gains an optional
    `anchor: int | None` query parameter naming a path by its topmost row
    (FR-6). Omitted, it serves the default. An `anchor` that names no path
    in that leaf's `ChainSet` — including one that was valid a minute ago —
    is a **404**, not a silent fallback to the default: a client that asked
    for a specific anchor and got a different one has been misinformed about
    the one thing it asked about.
  - `GET /ca/{issuer_id}/chain.pem` (`web/ca_ui.py:538-549`) gains the same
    parameter with the same rules.
  - `POST /certs/{cert_id}/download/bundle.p12` gains **nothing** and
    bundles the default chain (`web/certs_download_ui.py:166`). One bundle,
    one path; an operator who needs the other downloads `chain.pem`.
  - `web/ui.py:114-119` changes: the dashboard's `root_cer_url` is built
    from `chains_for(...).self_signed`, i.e. the last row of the **base**
    path, not from `chain_for`'s new default. The banner's job is to tell an
    operator which root to install so this instance keeps being trusted, and
    the right answer is the root that will outlive the cross certificate,
    not the old one the cross certificate is a bridge to. It is the one call
    site whose correct answer changed when the default did, which is why it
    is named here instead of inheriting FR-6.
  - `tls.py:577` inherits the default with no change, and that is correct: a
    browser reaching cabin's own UI is a relying party like any other.

- FR-9: **ACME alternates, RFC 8555 §7.4.2.**
  - `certificate_resource` (`acme/api_finalize.py:379-401`) keeps serving
    the default chain and gains one
    `Link: <url>;rel="alternate"` header per alternate path. **Appended,
    never assigned** — the response middleware appends a `rel="index"` link
    of its own (`acme/http.py:246-252`), and several alternates each need
    their own header line.
  - New route `POST /acme/cert/{cert_id}/{anchor_id}`, POST-as-GET, the same
    JWS verification and the same ownership check as the route it sits
    beside, serving that path's chain with the same
    `PEM_CHAIN_CONTENT_TYPE`. The URL passed to `verified` is
    `f"{CERT_PREFIX}{cert_id}/{anchor_id}"`, built by the same helper that
    builds the `Link` header, because the JWS `url` header is compared
    against exactly what cabin publishes (`acme/http.py:136-137`).
  - `anchor_id` is parsed by the **existing** `_certificate_id`
    (`acme/api_finalize.py:315-337`), not by a second copy of the same idea.
    That helper exists because `str.isdigit()` is true of `'²'` and of `'01'`
    and of a number no id column can hold, and each of those escapes as a
    bare 500 with no problem document and — worse — no `Replay-Nonce`,
    stranding a client whose nonce the request already spent. The new route
    has the same three problems and gets the same answer.
  - An `anchor_id` naming no path in the current `ChainSet` is
    `not_found("certificate chain")` — a 404 problem document with a nonce.
    A cross certificate that expired between the `Link` header being read
    and the URL being fetched lands here, and that is the correct outcome.
  - `order_json`'s `certificate` field (`acme/http.py:405`) is unchanged and
    names the default chain, as RFC 8555 7.1.3 requires.
  - The comment at `acme/api_finalize.py:398-400` saying cabin publishes one
    chain is deleted rather than left to rot.

  What this buys in practice: `certbot --preferred-chain` selects on the
  issuer common name of the topmost certificate, so an operator can pin
  either path from the client side without cabin having to guess for them.

- FR-10: **Retiring, and the fact that cabin cannot revoke.**
  - `retire(db, cross_id)` works unchanged and is the operator's kill
    switch. A cross row is not an intermediate, so `active_issuers` never
    counts it (`ca/service.py:162-171`) and `RetireError` can never fire for
    retiring one. The path is out of every chain on the next request,
    because FR-6 selects only `status == "active"` cross rows.
  - Retiring the **signing** root cascades onto it for free:
    `retire_targets` returns every row whose `parent_id` is that root
    (`ca/service.py:414-428`), which now includes the cross certificates it
    signed. That is right — a root that must not be used is not one whose
    cross certificates may keep vouching for anything — and AC-11 asserts it
    so that a future narrowing of `retire_targets` to intermediates goes
    red.
  - Retiring the **subject** root does **not** retire the cross
    certificates of it: their `parent_id` names the signing root, so they
    are outside that cascade. Deliberate. A retired root's intermediates
    stop issuing, but everything they already issued keeps being served with
    a working chain, and the cross path is one of those chains.
  - `ca_retired` (0017 FR-15) covers all of this with no new audit action.
  - **Revocation of a cross certificate is not something cabin can do**, and
    this is stated rather than papered over. A cross certificate is signed
    by a root, cabin publishes no CRL for a root — `regenerate_crl` selects
    leaf rows by `issuer_id` from the `certificates` table (0017 FR-9) and
    `/crl/{id}` is a 404 for anything that is not an intermediate
    (`web/crl_ui.py:35-45`) — so there is no document its serial could go
    into. Retiring is **not** revoking: it stops cabin serving the path, and
    it says nothing at all to a relying party that has already cached the
    cross certificate from a previous handshake. For a cross certificate
    cabin signed, an operator who needs real revocation needs a CRL for the
    signing root, which Out of Scope explains cabin does not publish. For an
    imported one, revocation always belonged to whoever signed it. The UI
    says this next to the Retire button rather than leaving an operator to
    infer it.

- FR-11: **A cross certificate can be renewed, through `renew_in_place`,
  with one guard moved.** This is the maintenance path, and it matters:
  letting a cross certificate lapse is survivable (FR-7) but it is a
  capability lost, and re-signing is cheaper than explaining to a fleet of
  unreachable devices why they stopped working.
  - `renew_in_place` (`ca/service.py:460-498`) already does the right thing
    for a cross row in every respect but one. `kind != "root"` takes the
    parent branch, which loads the row `parent_id` names — the signing root
    — signs with **its** key, and clamps the term to its `not_valid_after`
    through `_years_until` (`:485-495`). `renew_certificate` carries the
    subject, the public key, the SKI, BasicConstraints, KeyUsage and
    NameConstraints across (`ca/x509.py:237-269`), and adds the AKI because
    the input carried one — the same `needs_aki` branch that made it the
    wrong function for _creating_ a cross certificate (FR-2) is what makes
    it the right one for renewing it.
  - **The one blocker is real**: `:477-478` refuses when `row.key_sealed is
None`, and a cross row never has a key of its own (FR-1). The check
    moves inside the `kind == "root"` branch, where it is the check actually
    needed — a root self-signs, so its own key is the signing key. The
    non-root branch keeps its existing parent-key check (`:487-490`), which
    is what really guards the signature. Nothing changes for any
    intermediate that exists today: `create_hierarchy`,
    `create_intermediate_under` and `import_hierarchy` all seal a key on
    every intermediate row they write, so no intermediate has ever reached
    that line with a NULL. AC-12 asserts both directions — a cross
    certificate renews, an imported root still refuses with
    `CANotConfiguredError` naming the missing key (0017 AC-13).
  - **A renewal can never push a cross certificate past its signing root.**
    `_years_until` returns `min(years, remaining_days // 365)`, which is 0 or
    negative once the signing root is inside its own last year
    (`ca/service.py:501-517`), and `renew_certificate` then writes a
    certificate that is already expired. That wart is older than this spec
    and applies to intermediates too, so it is not fixed here; what is
    required is that the **consequence** is harmless and measured: the row
    is written, FR-7 drops it from every chain on the very next request, the
    short chain is served, and nothing breaks. AC-12 measures exactly that,
    because "we assumed the fallback works" is how the DST X3 outage was
    survivable in theory.

- FR-12: **Name constraints on a cross certificate — 0020's deferred
  question, answered.** A cross certificate carries **exactly** the
  `NameConstraints` extension of the certificate it duplicates: copied,
  value and criticality both, when the subject root has one; absent when it
  does not. cabin offers no field, on any form, to add or narrow
  constraints on a cross certificate, and `load_cross` **refuses** an
  imported cross certificate whose `NameConstraints` extension is not
  byte-identical to the subject root's (both absent counts as identical).

  Two reasons, and the first is the one that matters:
  1. cabin enforces constraints in `_build_leaf` by reading them off the
     **issuer's** certificate (0020 FR-4), and a leaf's issuer is an
     intermediate, never a root. A constraint that existed only on the cross
     certificate would therefore be enforced by every relying party that
     took the long path and by nobody else — cabin would be issuing
     certificates that one of its own two served chains rejects. That is
     precisely the laxness 0020 FR-7 exists to prevent, arriving by a route
     0020 could not see.
  2. The same CA would be allowed different things depending on which path a
     validator happened to build, and which one it builds is not something
     cabin controls or can predict.

  Out of Scope records that a narrowing cross certificate is a real and
  legitimate PKI practice, and what supporting it would take.

- FR-13: **UI.** Everything here reads `chains_for`; nothing recomputes a
  path in a template.
  - **Cross rows are rendered.** They are invisible today:
    `_groups` collects children only for `kind == "intermediate"`
    (`web/ca_ui.py:217`) and builds a group only for `kind == "root"`
    (`:232`), so a cross row would be a certificate cabin serves to every
    client and shows on no page. Each cross row is rendered under the root
    it **duplicates** (`cross_of_id`) — that is where an operator looks for
    "what paths does this hierarchy have" — labelled with the name of the
    root that **signed** it, its validity window and its status, plus a
    `cross` tag beside the existing `root`/`intermediate` ones.
  - **The served paths are named on the page.** For each hierarchy, which
    chain is served by default and which is offered as an alternate, read
    from `chains_for` so the page cannot describe a chain cabin does not
    serve. A cross certificate that FR-7 has dropped is shown as such, on
    its row, with its expiry date — the page is where an operator finds out
    _why_ the default went back to the short chain.
  - **Actions.** A `<details>` block on each root row, modelled on the
    "Add intermediate" one (`templates/ca_list.html:21`): a select of the
    roots that could sign this one — `kind == "root"`, a stored key, FR-3's
    `path_length`, not this row itself — and a years field. Roots that
    cannot sign are not offered rather than offered and refused. A second
    block imports a cross certificate: two PEM textareas, no key field, no
    name field. Each cross row gets Renew and Retire, in the same inline
    form an intermediate row has (`templates/ca_list.html:28`), with the
    sentence from FR-10 next to Retire saying it is not a revocation.
  - **The `path_length` hint** on both create forms gains FR-3's sentence.
    The current wording — "How many further intermediates may sign under the
    root" (`templates/ca_list.html:77`, `templates/ca_setup.html:54`) — is
    not wrong and is not enough.
  - **A form error re-renders at 400** with the message, before any row is
    written, the way `_years_error` and `_path_length_error` already do
    (`web/ca_ui.py:282-294`).
  - **The dashboard needs no change at all**, and AC-16 asserts that rather
    than leaving it to luck. `_ca_expiry` (`web/ui.py:269-295`) already
    walks one entry per `ca_certificates` row and already tags an active row
    `tag-warn` at `CA_WARN_DAYS = 365`, so a cross certificate gets a year's
    notice before it expires. That warning is the human half of FR-7 and it
    is the half that was missing in 2021.
  - **Templates are written by a script through Bash, never with
    Edit/Write.** The PostToolUse formatter breaks Jinja tags apart
    (`{% if x == "y" %}` becomes `{% if x="" ="y" %}`). This has cost this
    project a debugging session before. Check `git diff` after every
    template change.

- FR-14: **Audit, and what the API reports.**
  - Two new `AuditAction` members, `ca_cross_signed` and
    `ca_cross_imported`, both with `target_type="ca_certificate"` and the
    new row's id, following 0017 FR-15. Not folded into `ca_created` /
    `ca_imported`: extending what an existing root vouches for is a
    materially different act from creating a hierarchy, and a log that
    cannot tell them apart cannot answer the one question anybody will ask
    it afterwards. The audit filter is generated from `AuditAction`, so both
    appear there with no further change (0017 AC-14).
  - Details: for a signing, the signing root's id, the subject root's id,
    the requested `years` and the `not_after` actually granted after FR-2's
    clamp — the clamp is silent otherwise, and a certificate that came out
    five years shorter than asked for is worth one field. For an import, the
    two row ids plus the SHA-256 fingerprints of the cross certificate and
    of the signing root.
  - **No grant is written.** `grant()` attaches an identity to an issuer,
    and every existing call site passes an intermediate's id
    (`web/ca_ui.py:309, 378, 434`). A cross certificate is not an issuer and
    can never sign a leaf (FR-1), so there is nothing for a grant to
    authorise. Stated because its absence beside three routes that do write
    one would otherwise read as an oversight.
  - `IssuerInfo.kind` (`api/models.py:56`) gains `"cross"` to its `Literal`,
    and the model gains `cross_of_id: int | None`, omitted from the JSON
    when `None` through the route's existing `response_model_exclude_none`
    — unlike `parent_id`, which is kept present by the model serializer
    (`api/models.py:74-87`) because it is how a caller tells a root from an
    intermediate. `cross_of_id` needs no such treatment: `kind` already
    answers that question, and a field present only where it means something
    is the smaller change.
  - The MCP `get_ca_info` tool names each field rather than splatting
    (0017's rule), so it gains the same two and AC-17 asserts REST and MCP
    agree against one database.

## Interface Contract

What the changed things are called, take and return, so the modules on
either side of a seam cannot be built against two different guesses.

### Where this code lives

The certificate builder and the import validator go in **`cabin.ca.x509`**,
next to `create_intermediate` and `load_import`, which they are the
siblings of: both are pure functions over `cryptography` objects with no
session, no ORM and no settings. Path assembly goes in
**`cabin.ca.service`**, because a path is a walk over `ca_certificates` rows
and that is what `chain_for` already is. Nothing goes in `cabin.ca.leaf`:
this spec never touches a leaf.

### `cabin.ca.x509`

```python
def cross_sign(
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    years: int = 10,
) -> x509.Certificate: ...


def load_cross(
    cross_pem: bytes,
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> x509.Certificate: ...


def cross_path_length_error(
    subject_cert: x509.Certificate, issuer_cert: x509.Certificate
) -> str | None: ...
```

- `cross_sign` returns a certificate and never a key — there is no key to
  return, which is the difference between this and `create_intermediate`. It
  raises `ValueError` when `subject_cert` carries no SubjectKeyIdentifier;
  a CA certificate without one cannot be cross-signed usefully and cabin
  writes one on every CA it creates (`:140`, `:185`).
- `load_cross` returns the parsed cross certificate and raises
  `CAImportError` — the existing type, not a new one, because the operator
  is doing the same thing they do at `/ca/import` and the message is what
  distinguishes the reasons.
- `cross_path_length_error` is FR-3's rule, returning a message or `None`.
  It is a separate function because both `cross_sign`'s caller and
  `load_cross` need it and the two must not have separate copies of the
  arithmetic; the UI also needs it to decide which roots to offer in the
  select (FR-13).

`create_root`, `create_intermediate`, `renew_certificate`, `load_import`,
`authority_key_identifier` and `describe_certificate` are unchanged.

### `cabin.ca.service`

```python
class CrossSignError(Exception):
    """A cross certificate cannot be produced for these two roots: the
    signing root's path_length cannot carry the subtree (spec 0021 FR-3),
    or an active cross certificate for this pair already exists (FR-4)."""


@dataclass(frozen=True)
class Chain:
    rows: tuple[CACertificate, ...]
    via_cross_id: int | None

    @property
    def anchor_id(self) -> int: ...


@dataclass(frozen=True)
class ChainSet:
    default: Chain
    alternates: tuple[Chain, ...]

    @property
    def self_signed(self) -> Chain: ...

    def by_anchor(self, anchor_id: int) -> Chain | None: ...


def chains_for(db: Session, ca_id: int, now: datetime | None = None) -> ChainSet: ...


def cross_sign_root(
    db: Session,
    secrets: SecretStore,
    ca_id: int,
    signing_root_id: int,
    years: int = 10,
) -> CACertificate: ...


def import_cross(db: Session, cross_pem: str, issuer_pem: str) -> CACertificate: ...
```

- `Chain.rows` is nearest-issuer-first with the anchor last, the order every
  existing consumer already assumes. `anchor_id` is `rows[-1].id`.
- `ChainSet.self_signed` is the path whose `via_cross_id` is `None`. It is
  always in `[default, *alternates]` (FR-6 rule 6), so the property is total
  and `web/ui.py` can rely on it.
- `by_anchor` returns `None` for an id naming no path, which is what FR-8's
  and FR-9's 404s are built on. It never falls back to the default.
- `chains_for` takes `now` so a test can name the instant rather than
  monkeypatching a clock, and so FR-7's boundary is measurable from both
  sides. Production callers omit it.
- `chain_for(db, ca_id) -> list[CACertificate]` keeps its signature and
  becomes `list(chains_for(db, ca_id).default.rows)`.
- `cross_sign_root` raises `UnknownIssuerError`, `ValueError` (not a root),
  `CANotConfiguredError` (signing root has no key) and `CrossSignError`
  (FR-3, FR-4). `import_cross` raises `CAImportError` for everything
  `load_cross` refuses and for "no row on this instance is that root" /
  "more than one is".
- `get_ca`, `list_cas`, `active_issuers`, `resolve_issuer`,
  `signing_credentials`, `create_hierarchy`, `import_hierarchy`,
  `create_intermediate_under`, `retire` and `retire_targets` are unchanged.
  `renew_in_place` keeps its signature and moves one guard (FR-11).

### Schema

`ca_certificates` gains `cross_of_id` and one value in its `kind` CHECK,
both by editing migration `0003` in place (FR-1). The chain still ends at
`0010`. `certificates`, `crl_state` and every other table are untouched, and
no new table appears. AC-18 asserts this against the schema a fresh database
migrates to, not against the migrations' source text.

### Routes

| Method | Path                                   | Auth         | Change                                          |
| ------ | -------------------------------------- | ------------ | ----------------------------------------------- |
| POST   | `/ca/{ca_id}/cross-sign`               | admin + CSRF | new — form `signing_root_id`, `years`           |
| POST   | `/ca/cross-import`                     | admin + CSRF | new — form `cross_pem`, `issuer_pem`            |
| GET    | `/ca/{issuer_id}/chain.pem`            | session      | + optional `?anchor={ca_id}`                    |
| GET    | `/certs/{cert_id}/download/chain.pem`  | session      | + optional `?anchor={ca_id}`                    |
| POST   | `/certs/{cert_id}/download/bundle.p12` | admin + CSRF | unchanged — the default chain (FR-8)            |
| POST   | `/acme/cert/{cert_id}`                 | ACME JWS     | + one `Link ...;rel="alternate"` per alternate  |
| POST   | `/acme/cert/{cert_id}/{anchor_id}`     | ACME JWS     | new — that path's chain, 404 when it is gone    |
| GET    | `/ca`                                  | session      | renders cross rows and the served paths (FR-13) |

`/ca/{ca_id}/cross-sign` names the root being **signed** in the path — the
row the operator is looking at when they decide it needs a second path — and
the root doing the signing in the form. No route is removed and no route
changes its auth.

**Neither new path can be shadowed, and this is checked rather than
assumed.** `/ca/{ca_id}/cross-sign` has three segments and its last one is
a literal, which is what already separates `/ca/{ca_id}/renew`,
`/ca/{ca_id}/retire` and `/ca/{root_id}/intermediate` from each other.
`/ca/cross-import` has two, so the only routes it could ever be confused
with are the other two-segment ones — `/ca/create` and `/ca/import`, both
literal and both different, and `/ca/{ca_id}.pem` and `/ca/{ca_id}.cer`,
which Starlette compiles to `^/ca/(?P<ca_id>[^/]+)\.pem$` and `\.cer$` and
which therefore cannot match a path with no suffix. There is no
registration-order dependency in either case, which is the point: 0017's
route table had to reason about a pair that did depend on it, and this pair
does not. AC-15 asserts that `POST /ca/cross-import` reaches the import
handler rather than being read as `ca_id="cross-import"`, because "we
reasoned it cannot collide" is what the `/crl/7.pem` 422 in 0017 also
started as.

## Acceptance Criteria

Every criterion names the mutation it exists to catch. "Refused" means the
door's own refusal **and** no state change: the `ca_certificates` row count
is unchanged and no chain any door serves is different afterwards. A
criterion that only asserts a status code or a substring satisfies nothing
here.

The fixture, unless stated otherwise: hierarchy **OLD** (root `A`, created
with `path_length=2`, plus an intermediate) and hierarchy **NEW** (root `B`,
default `path_length`, intermediate `I`), both active; a leaf `L` issued by
`I`; and one cross certificate `X` — `B`'s subject and public key, signed by
`A`. Two hierarchies, because with one, "served the cross chain" and
"served the only chain there was" produce the same bytes.

- AC-1: **The cross certificate is another certificate for the same CA —
  asserted with `cryptography`, never through a chain check.** Parsed from
  `X`'s stored `cert_pem`: `X.subject.public_bytes()` equals
  `B.subject.public_bytes()`; `X`'s SubjectPublicKeyInfo DER equals `B`'s;
  `X`'s SubjectKeyIdentifier bytes equal `B`'s; `X.issuer` equals
  `A.subject`; `X.serial_number != B.serial_number`; `X`'s BasicConstraints
  and KeyUsage equal `B`'s including `path_length`; `X` carries an
  `AuthorityKeyIdentifier` whose `key_identifier` equals `A`'s
  SubjectKeyIdentifier; `X` carries **no** CRLDistributionPoints and **no**
  AuthorityInformationAccess; `X.not_valid_after_utc <= A.not_valid_after_utc`.
  Not one of these is visible to `openssl verify`: a certificate handed to
  `-CAfile` is a trust anchor and its contents are never examined, and one
  handed in `-untrusted` is examined only for whether it links two names.
  _Goes red if_: `cross_sign` generates a fresh key, rebuilds the subject
  from a string, re-derives the SKI instead of copying it, or (the
  `renew_certificate` reuse mutation) omits the AuthorityKeyIdentifier
  because the input carried none.
- AC-2: **`A` really signed it, checked directly and then in a chain.**
  1. `X.verify_directly_issued_by(A_cert)` returns without raising, and
     raises for a forged cross certificate built over `B`'s subject and
     public key with an unrelated key. This is the assertion that does not
     depend on where a file was placed.
  2. `openssl verify -CAfile A.pem -untrusted "X.pem + I.pem" L.pem` exits 0.
  3. The same command with `X` **omitted** from `-untrusted` exits non-zero
     with an "unable to get local issuer certificate" error — which is what
     proves step 2 went through the cross certificate rather than round it.
  4. The same command with the forged cross certificate in place of `X`
     exits non-zero. Putting that forged certificate in `-CAfile` instead
     makes the command exit 0, and the test asserts that too, as the
     executable form of the warning: a criterion that had verified the long
     chain with `X` in the CAfile would pass against a cross certificate
     cabin signed with the wrong key entirely.
- AC-3: **Both paths validate, and the long one is what is served.**
  `openssl verify -CAfile B.pem -untrusted I.pem L.pem` exits 0, so `L` has
  two paths. With `X` active, the bytes returned by
  `GET /certs/{L}/download/chain.pem`, `GET /api/v1/certificates/{L}`'s
  `chain_pem`, `GET /ca/{I}/chain.pem`, the ACME certificate resource for
  `L`'s order, and the CA list inside the PKCS#12 bundle each contain
  **three** CA certificates whose last one is `A` — asserted by parsing the
  PEMs and comparing subject DER, not by counting `BEGIN CERTIFICATE`
  markers. The dashboard's `root_cer_url`, in the same instance, points at
  **`B`**'s row id and not at `A`'s (FR-8).
  _Goes red if_: the default is the short chain, if any one door was left on
  its own idea of a chain, or if `web/ui.py` was allowed to inherit the new
  default.
- AC-4: **`path_length` is checked before anything is signed, and OpenSSL
  agrees with the check.** Cross-signing `B` with a root created at
  `path_length=1` is refused with a message naming `path_length` and that
  value, and writes no row. A cross certificate built for that pair by
  calling `cross_sign` directly — bypassing the check — is accepted by
  neither: `openssl verify -CAfile A1.pem -untrusted "X1.pem + I.pem" L.pem`
  exits non-zero with a path-length error. With `path_length=2` the same two
  operations succeed. A subject root whose own BasicConstraints carries
  `path_length=0` (imported) is refused for the other half of FR-3.
  _Goes red if_: the bound is off by one in either direction — at `≥ 1` on
  the signing root cabin issues a cross certificate every validator rejects;
  at `≥ 3` it refuses one every validator accepts.
- AC-5: **The import compares the public key, and the subject, as bytes.**
  Importing `X` produces one cross row and leaves the served chains
  identical to AC-3's. Each of these is refused with **no** row written and
  the served chains byte-identical before and after: a CA certificate with
  the subject `CN=cabin Root CA` — the same string cabin generates — over a
  **different** key; a certificate over `B`'s key with a different subject; a
  certificate whose subject renders identically but encodes its common name
  differently. The negative cases are asserted on the served chain, not only
  on the response code, because "the import was refused" and "the import was
  refused and nothing was written" are different claims.
  _Goes red if_: the key comparison is skipped or replaced by a fingerprint
  of the subject, or if the subject is compared as an RFC 4514 string.
- AC-6: **The import's other checks.** A cross certificate is refused, with
  no row written, when: its signature is not `A`'s (a valid certificate
  signed by a third root); its SubjectKeyIdentifier differs from `B`'s
  although the public key matches; it carries `BasicConstraints(ca=False)`
  or a KeyUsage without `keyCertSign`; it is already expired; the submitted
  signing root did not sign it. Importing a cross certificate whose signing
  root is **already** a row in cabin reuses that row rather than inserting a
  second one — asserted on the `ca_certificates` row count — and importing
  one whose signing root is unknown inserts exactly one new `kind="root"`
  row with `key_sealed IS NULL`.
- AC-7: **An expired cross certificate leaves every served chain by itself,
  with nothing written.** This is the criterion this spec exists for. With
  `X`'s `not_after` in the past — a cross certificate genuinely built with
  past validity and stored, not a mocked clock — and **without any request
  to `/ca` and without restarting the application**, the first request to
  each of the five surfaces in AC-3 returns a chain of **two** CA
  certificates ending at `B`. In the same test, afterwards:
  `select count(*) from ca_certificates` is unchanged, `X`'s `status` is
  still `active`, `X`'s `cert_pem` is unchanged, and no audit event was
  written.
  _Goes red if_: the filter is implemented as a status update on page view
  (the row's `status` changes, or the first chain served is still the long
  one), if it lives in one door instead of in `chains_for` (the other four
  still serve three certificates), or if it is cached for the process
  lifetime.
- AC-8: **The whole alternate path is checked, not only the cross
  certificate.** With `X` valid but its signing root `A` expired, the same
  five surfaces serve the short chain. With both valid, all five serve the
  long one.
  _Goes red if_: the check reads only the cross row's dates — the case that
  cannot arise for a cabin-signed cross certificate, because FR-2 clamps it,
  and does arise for every imported one.
- AC-9: **The boundary, from both sides.**
  `chains_for(db, I, now=X.not_valid_after_utc - 1s).default.via_cross_id`
  is `X`'s id; at `+ 1s` it is `None`. The same pair around
  `X.not_valid_before_utc` for a cross certificate whose validity starts in
  the future.
  _Goes red if_: the comparison is inverted, is `<` where it should be `<=`
  in a way that changes the served chain at the boundary instant, or ignores
  `not_valid_before` entirely.
- AC-10: **ACME publishes the alternate and it works.** For `L`'s order:
  the certificate resource's body is the long chain; the response carries
  exactly one `Link` header with `rel="alternate"`, and its URL ends in
  `/{B's row id}`; a POST-as-GET to that URL by the owning account returns
  the short chain with `Content-Type: application/pem-certificate-chain`; a
  POST-as-GET to it by a **different** account is `unauthorized`; a nonce is
  present on all of them. `/acme/cert/{L}/999999` is a 404 problem document
  **with** a `Replay-Nonce`, and so are `/acme/cert/{L}/01` and
  `/acme/cert/{L}/²`. After `X` expires, the certificate resource carries no
  `alternate` link at all and the alternate URL that worked a moment ago is
  a 404. The order's own `certificate` field is unchanged throughout.
  _Goes red if_: the alternate is indexed by an ordinal (the URL a client
  cached now names a different chain), if `Link` is assigned rather than
  appended (the middleware's `index` link disappears), or if the id parsing
  is re-derived instead of reusing `_certificate_id` (`'²'` becomes a 500
  with no nonce).
- AC-11: **Retiring is the kill switch, and the cascade goes one way.**
  `POST /ca/{X}/retire` succeeds — it never raises `RetireError`, whatever
  else is on the instance — and the five surfaces serve the short chain on
  the next request. Retiring the **signing root** `A` retires `X` with it
  (`retire_targets` includes it) and the short chain is served. Retiring the
  **subject root** `B` leaves `X` `active`, and `L`'s chain is still the
  long one. `active_issuers` never contains a cross row, before or after any
  of this.
  _Goes red if_: `retire_targets` is narrowed to intermediates, if a cross
  row is counted as an active issuer (retiring the last real intermediate
  would then be allowed), or if retiring `B` cascades to `X` and takes a
  working path away from certificates that still need one.
- AC-12: **Renewal.** `POST /ca/{X}/renew` with `years=5` succeeds. `X`'s
  parsed certificate afterwards has the same subject DER, the same
  SubjectPublicKeyInfo, the same SubjectKeyIdentifier and the same
  AuthorityKeyIdentifier as before, a new serial, a later `not_after`, and
  `X.verify_directly_issued_by(A_cert)` still passes — all asserted with
  `cryptography`, because a renewal that regenerated the key would verify
  perfectly in every chain-shaped test. `L`, issued before the renewal,
  still verifies by AC-2's method afterwards. Renewing an imported root
  still raises `CANotConfiguredError` naming the missing key, and renewing
  an intermediate behaves exactly as it did before this spec. Finally: with
  `A` inside its own last year, renewing `X` writes a certificate that is
  already expired, and the very next request to each of the five surfaces
  serves the short chain — no exception, no 500, no three-certificate chain.
  _Goes red if_: the `key_sealed` guard is left where it is (`X` cannot be
  renewed at all) or removed outright (an imported root renews and silently
  produces nothing usable).
- AC-13: **A cross certificate never issues anything.** `issue_and_store`
  and `sign_csr_and_store` with `issuer_id` = `X`'s id raise
  `UnknownIssuerError` and write no `certificates` row; `active_issuers`
  does not contain it, so it appears in no issuer select, in no ACME
  directory and in no grant form; `GET /crl/{X}` is a 404; `GET /ca/{X}.cer`
  is a 200 with `X`'s DER, because a relying party repairing a chain may
  legitimately need it.
- AC-14: **Name constraints are copied, never invented.** A root carrying a
  `NameConstraints` extension (imported) is cross-signed: the cross
  certificate's extension DER and criticality are **identical** to the
  subject root's, asserted with `cryptography`. A root carrying none
  produces a cross certificate carrying none — asserted as an
  `ExtensionNotFound`, not as an empty extension. An imported cross
  certificate that carries constraints its subject root does not, or omits
  ones it does, is refused with no row written.
- AC-15: **UI.** `/ca` renders `X` under `B`'s group with a `cross` tag, the
  name of the signing root, its validity window and its status — asserted on
  the parsed DOM. The page names the default and alternate chains for that
  hierarchy, and the values equal what `chains_for` returns for `I`. A root
  with `path_length=1` is **not** in the cross-sign select (asserted as an
  absent option, not an absent string), and posting its id anyway is a 400
  with no row. Both new POSTs are 403 for a viewer and 403 without CSRF for
  an admin. `POST /ca/cross-import` reaches the import handler and is not
  read as `ca_id="cross-import"`. After `X` expires, its row is shown as
  not served, with its expiry date.
- AC-16: **The dashboard warns a year out, unchanged.** With `X` expiring in
  300 days, the dashboard lists it among the CA certificates with the
  `tag-warn` tag and its own name; at 400 days it carries no tag; once
  expired it is `tag-bad`. Asserted because FR-13 claims this needs no code
  change, and an untested claim of "this already works" is how the human
  half of the DST X3 warning gets lost.
- AC-17: **Audit and the API surface.** `ca_cross_signed` and
  `ca_cross_imported` appear in the log with `target_type="ca_certificate"`
  and the new row's id, are selectable in the audit filter, and carry the
  ids and the granted `not_after` FR-14 names. No `issuer_grants` row is
  written by either route — asserted on the table's row count.
  `GET /api/v1/ca` reports `X` with `kind: "cross"` and
  `cross_of_id: {B's id}`, reports `crl_url` as absent for it, and the MCP
  `get_ca_info` tool returns the same ids, kinds and `cross_of_id` values
  against the same database.
- AC-18: **Schema.** Against the schema a fresh database migrates to — not
  against the migrations' source text — `ca_certificates` has a
  `cross_of_id` column with a foreign key to itself, its `kind` CHECK admits
  exactly `root`, `intermediate` and `cross`, the migration chain still ends
  at `0010` with no `0011`, and no other table changed. Inserting a
  `ca_certificates` row with `kind='bogus'` fails at the database, not only
  in Python. Every cross row cabin writes has `key_sealed IS NULL`, a
  non-NULL `parent_id` and a non-NULL `cross_of_id`, and no row anywhere has
  a cross row as its `parent_id`.

## Test list

test_cross_certificate_has_the_same_subject_bytes,
test_cross_certificate_has_the_same_public_key,
test_cross_certificate_copies_the_subject_key_identifier,
test_cross_certificate_has_an_aki_naming_the_signing_root (the
`renew_certificate` reuse mutation),
test_cross_certificate_copies_basic_constraints_and_key_usage,
test_cross_certificate_carries_no_cdp_and_no_aia,
test_cross_certificate_is_clamped_to_the_signing_roots_expiry,
test_cross_certificate_serial_is_new,
test_cross_sign_verifies_directly_issued_by_the_signing_root,
test_forged_cross_certificate_fails_direct_verification,
test_openssl_builds_the_long_path (A alone in `-CAfile`, X and I in
`-untrusted`), test_openssl_fails_without_the_cross_certificate,
test_openssl_fails_with_a_forged_cross_certificate,
test_openssl_passes_a_forged_cross_certificate_in_cafile (the blind spot,
asserted so it cannot be relied on by accident),
test_openssl_builds_the_short_path,
test_default_chain_is_the_long_one_at_every_door (five surfaces, one
database), test_dashboard_root_link_points_at_the_self_signed_root,
test_path_length_one_signing_root_is_refused,
test_path_length_error_names_the_value,
test_smuggled_cross_certificate_fails_path_length_in_openssl,
test_path_length_two_signing_root_is_accepted,
test_subject_root_with_path_length_zero_is_refused,
test_import_refuses_a_matching_subject_with_a_different_key (the staple
attack), test_import_refuses_a_matching_key_with_a_different_subject,
test_import_refuses_a_differently_encoded_subject,
test_import_refuses_a_signature_from_a_third_root,
test_import_refuses_a_mismatched_subject_key_identifier,
test_import_refuses_a_non_ca_certificate,
test_import_refuses_an_expired_certificate,
test_import_reuses_an_existing_signing_root_row,
test_import_inserts_an_unknown_signing_root_without_a_key,
test_import_refuses_when_no_row_matches_the_subject,
test_refused_import_changes_no_served_chain,
test_expired_cross_certificate_drops_out_at_every_door (AC-7, no page visit,
no restart), test_expired_cross_certificate_writes_nothing,
test_expired_signing_root_drops_the_path,
test_validity_boundary_one_second_either_side,
test_not_yet_valid_cross_certificate_is_not_served,
test_self_signed_path_is_served_even_when_expired,
test_only_one_cross_hop_is_followed,
test_two_cross_certificates_default_to_the_lowest_id,
test_chain_anchor_ids_are_unique_within_a_chainset,
test_anchor_query_selects_the_short_chain,
test_unknown_anchor_is_404_not_the_default,
test_bundle_p12_carries_the_default_chain,
test_acme_certificate_carries_one_alternate_link,
test_acme_alternate_url_serves_the_short_chain,
test_acme_alternate_url_rejects_another_account,
test_acme_alternate_link_disappears_when_the_cross_expires,
test_acme_alternate_404_carries_a_nonce,
test_acme_alternate_id_parsing_reuses_the_certificate_id_rules,
test_acme_order_certificate_field_is_unchanged,
test_retire_cross_certificate_serves_the_short_chain,
test_retire_cross_certificate_never_raises_retire_error,
test_retiring_the_signing_root_retires_the_cross_certificate,
test_retiring_the_subject_root_does_not,
test_cross_row_is_never_an_active_issuer,
test_renew_cross_certificate_keeps_key_ski_and_aki,
test_renew_cross_certificate_still_verifies_against_the_signing_root,
test_leaf_issued_before_the_renewal_still_validates,
test_renew_imported_root_still_refuses,
test_renew_intermediate_is_unchanged,
test_renewal_past_the_signing_root_falls_back_to_the_short_chain,
test_cross_certificate_cannot_issue_a_leaf,
test_crl_route_404_for_a_cross_row, test_ca_cer_route_serves_a_cross_row,
test_name_constraints_are_copied_byte_for_byte,
test_unconstrained_root_produces_an_unconstrained_cross_certificate,
test_import_refuses_a_narrowing_cross_certificate,
test_ca_page_shows_the_cross_row_under_the_subject_root,
test_ca_page_names_the_default_and_alternate_chains,
test_ca_page_omits_roots_that_cannot_sign,
test_cross_routes_require_admin_and_csrf,
test_cross_import_path_is_not_read_as_a_ca_id,
test_ca_page_marks_an_expired_cross_certificate_as_not_served,
test_dashboard_warns_a_year_before_a_cross_certificate_expires,
test_audit_cross_signed_and_cross_imported,
test_cross_signing_writes_no_grant, test_api_ca_reports_kind_cross,
test_mcp_ca_info_matches_rest_for_cross_rows,
test_schema_admits_kind_cross_and_has_cross_of_id,
test_migration_chain_still_ends_at_0010

Five notes for whoever writes these.

- **The two-hierarchy fixture is not optional.** With one hierarchy on the
  instance, "served the cross chain" and "served the only chain there was"
  are the same bytes, and an implementation that ignores cross rows entirely
  passes half of this list.
- **`openssl verify` proves almost nothing here.** Everything about what a
  cross certificate _contains_ (AC-1, AC-12, AC-14) and about _who signed
  it_ (AC-2) is asserted with `cryptography` — `Name.public_bytes()`,
  SubjectPublicKeyInfo DER, `verify_directly_issued_by`. Where a chain check
  is the point, only the trust anchor goes in `-CAfile` and everything else
  in `-untrusted`. `test_openssl_passes_a_forged_cross_certificate_in_cafile`
  exists to keep that from being forgotten: it asserts the blind spot, so
  the next person who reaches for the convenient invocation sees it.
- **Count certificates by parsing, not by counting markers.** "Three PEM
  blocks" and "the chain ends at A" are different assertions, and only the
  second one fails when the chain is assembled in the wrong order.
- **Build the expired cross certificate for real.** AC-7 asks for a stored
  certificate with past validity, not a patched clock, because a patched
  clock is a mutation-proof test of a mocked function. `chains_for`'s `now`
  parameter is for AC-9's boundary, where naming the instant is the point.
- **Templates are written by a script through Bash, never with Edit/Write**
  — the PostToolUse formatter breaks Jinja tags apart. FR-13 restructures
  `ca_list.html`, which is already dense; check `git diff` after every
  change.

## Out of Scope

**A CRL for a root, and therefore revocation of a cross certificate.**
cabin's CRLs are per intermediate over the `certificates` table (0017 FR-9),
and a cross certificate is neither a leaf nor signed by an intermediate.
Publishing one would need a second CRL shape, a table for revoked CA
certificates, a public route for it, and a `cRLDistributionPoints` extension
on every cross certificate pointing at it — and it would still only reach
relying parties that fetch CRLs for CA certificates, which most do not.
FR-10 offers `retire` instead and says plainly that it is not the same
thing. An operator whose cross certificate must be repudiated to third
parties has a problem cabin cannot solve for them, and being told so is
better than being handed a button that looks like it did.

**A narrowing cross certificate.** Constraining a CA more tightly on one
path than on another is a real and common PKI practice — it is how a company
CA delegates a subtree to a partner. cabin does not do it, for FR-12's first
reason: cabin's own enforcement reads constraints off the issuing
intermediate (0020 FR-4), so a constraint present only on a cross
certificate would be enforced by relying parties taking the long path and by
nobody else, and cabin would be issuing certificates one of its own served
chains rejects. Supporting it means enforcing over the whole served path
rather than over the issuer's certificate, which 0020's Out of Scope already
declined for the ancestor case and declined for the same reason: it means
putting validator logic in an issuer, and threading a chain into the pure
leaf layer where FR-4's "no argument a caller can forget" design lives.

**Cross-signing an intermediate.** Only roots are cross-signed here. The
mechanism works identically for an intermediate, and there is a real use for
it, but every part of this spec that reasons about `path_length`, about the
retire cascade and about where a row is rendered would need a second answer,
and the devices this spec exists for trust roots.

**Chains through more than one cross certificate.** FR-6 follows one hop.
Two generations of cross certificates would produce a set of paths that
grows with each one, and a default rule that has to choose between them on
grounds cabin does not have.

**Letting the operator choose the default chain.** The default is FR-6's
rule and there is no setting. A per-hierarchy preference is a plausible next
step and is cheap to add on top of `ChainSet`; what it is not is something
anybody has asked for, and a setting whose wrong value silently breaks path
building on unreachable devices is a setting worth waiting for a reason to
add.

**Alternate chains over REST and MCP.** `CertificatePem.chain_pem` is the
default chain and gains no sibling field, and no REST route takes an
`anchor`. The two surfaces that actually have consumers for an alternate —
ACME clients with `--preferred-chain`, and an operator clicking a link —
have one. A second field with no consumer is the speculative addition Rule 2
refuses; it is a field to add when something needs it.

**Automatic renewal of a cross certificate.** FR-11 makes renewal possible
and FR-13 makes its expiry visible a year out. cabin still has no scheduler
beyond the CRL's lazy refresh (0017 Out of Scope), and a CA operation that
happened by itself would be one an operator did not decide.

**Backfilling 0015/0016 into `spec/README.md:8-23`**, where they are still
missing — noted by 0017 and 0020 before this, and still not part of this
work.
