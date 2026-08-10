# Spec 0022 — HTTPS for cabin itself

## Context

cabin accepts a password on `/login`, a bearer token on every `/api/v1`
call, an EAB key on ACME registration and a master passphrase in its
environment — and today it speaks nothing but plaintext HTTP
(`cli.py:19`). The standing answer, "put a reverse proxy in front", stays
supported and stays the **default**: TLS is opt-in, and an instance that
does not turn it on behaves exactly as it does now. But for an all-in-one
product that already owns a CA, "generate your own certificate elsewhere"
is a thin answer to a problem cabin is uniquely equipped to solve.

**The chicken and the egg.** TLS needs a certificate; a certificate needs a
CA; the CA is created through the web UI that is supposed to be behind TLS.
This spec resolves it in three stages: a self-signed certificate at first
start, a certificate from cabin's own CA the moment one exists — swapped in
**without a restart** — and, once the operator has installed the root, no
warning at all. The warning in stage 1 is unavoidable and expected; it is
said out loud in the setup copy rather than glossed over (FR-14).

**Why the way cabin starts has to change.** The hot-swap in stage 2 was not
assumed, it was measured: a spike ran a real uvicorn server over TLS and
called `ssl.SSLContext.load_cert_chain()` on the live context, and every
connection opened afterwards presented the new certificate, with the same
process, the same socket and the same context object
(`id()` identical before and after). The mechanism is not uvicorn-specific:
`asyncio.sslproto.SSLProtocol` stores a _reference_ to the `SSLContext` and
calls `wrap_bio()` on it fresh per handshake, and uvicorn passes
`config.ssl` straight into `loop.create_server(...)`
(`uvicorn/server.py:145,152,173-177`).

The catch is that `uvicorn.run()` — what `cli.py:19` calls — builds its own
`Config` and `Server` internally and never returns either
(`uvicorn/main.py:494+`). There is no handle to the `SSLContext` at all.
So cabin must construct `uvicorn.Config` and `uvicorn.Server` itself and
keep the `Config` around. **That is the reason this spec restructures
process startup**, and it is worth stating plainly, because a diff that
replaces a one-line `uvicorn.run()` with a small server module otherwise
reads as churn for its own sake. It is the whole mechanism.

Two further spike findings are requirements here, not footnotes:

- `config.ssl` does not exist until the server runs. `Config.load()` builds
  the `SSLContext`, and it is called inside `Server._serve()`
  (`uvicorn/server.py:87-88`), not at `Config()` construction time. Anything
  that swaps a certificate has to cope with being called before that
  (FR-7).
- **Multi-worker mode would break the swap silently.** Separate worker
  processes each build their own `Config` and their own `SSLContext`;
  mutating one does nothing for the others, and the result is an instance
  where some connections get the new certificate and some keep the old, with
  no error anywhere. cabin passes no `workers=` today, so this is a
  guardrail rather than a fix — but a silent partial success is worse than a
  refusal, so cabin refuses (FR-8).

**The second listener.** Spec 0017 FR-12 forces every CDP and AIA URL to
`http://` (`ca/leaf.py:32-49`), because a relying party validating a cabin
certificate would otherwise need a CRL it can only fetch over TLS, for which
it would need to validate a certificate. Turning on TLS therefore cannot
simply move every route to HTTPS. When TLS is on, cabin binds a second,
plaintext listener that serves **only** the three public PKI routes
(`web/crl_ui.py:64-100`) and answers 404 to everything else — no redirect,
ever, so that no credential can be sent in the clear because there is
nothing there that would accept one (FR-10).

**A cost the plan did not price in.** `base_url` is not a required setting.
It is a database key that starts empty (`settings.py:17-19`), and first-run
setup collects only a username and a password (`web/ui.py:103-140`) — so at
the very first start with TLS on there is no configured hostname to issue
for. FR-5 gives that case a fallback and re-issues as soon as `base_url`
appears. Related: `public_http_origin` keeps whatever port `base_url`
carries, which with TLS on is the _TLS_ port — so a `base_url` naming an
explicit port would put an unreachable CDP into every certificate cabin
issues, and would do it silently. FR-13 closes that.

**No conflict with ACME.** `http-01` and `tls-alpn-01` are validations cabin
performs **outbound**, against the applicant's host — cabin connects out, it
does not serve them. Nothing about which ports cabin listens on, or with
which certificate, touches them. Stated here so nobody has to derive it
again from the challenge code.

**This spec breaks the five-environment-variable rule.** cabin has exactly
five (`README.md:71-75`); TLS needs two more, and that deviation is
recorded as an ADR rather than allowed to happen quietly (FR-12).

## User Stories

- As an operator starting cabin for the first time with TLS on, I get an
  HTTPS listener immediately, click through one browser warning I was told
  to expect, and complete the first-run wizard without my password crossing
  the network in the clear.
- As an operator who has just created a CA, cabin issues itself a
  certificate from it and starts serving it straight away — I do not restart
  the container and I do not lose the request I am in the middle of.
- As an operator who has installed cabin's root in my trust store, I get no
  warning at all, and `curl` without `--cacert` still fails — which is how I
  know the trust is real and not a disabled check.
- As a relying party, I fetch a CRL and a CA certificate over plain HTTP
  from the URLs written into the certificate, because validating the
  certificate is exactly what I am trying to do.
- As a security reviewer, I point a browser at the plaintext port and find
  no login form, no redirect to one, and no session cookie — only signed,
  public PKI documents.
- As an operator who prefers a reverse proxy, I change nothing and notice
  nothing.

## Functional Requirements

- FR-1: **cabin starts its own uvicorn server.** A new module
  `cabin/server.py` owns process startup; `cli.py` keeps its job of turning
  a `ConfigError` into one sentence and a non-zero exit
  (`cli.py:11-18`) and then calls `server.run(config)`.
  `run` builds `uvicorn.Config(app, host="0.0.0.0", port=config.port, ...)`
  and `uvicorn.Server(config)` and drives them inside one `asyncio` event
  loop, keeping the `uvicorn.Config` reachable so FR-6 has an `SSLContext`
  to mutate. `uvicorn.run()` is not called anywhere.

  **With TLS off, this changes nothing observable**: exactly one server,
  plaintext, on `config.port`, serving the whole application, no second
  listener, and no files under `DATA_DIR/tls`. That is the acceptance
  criterion for the restructure (AC-4's counter-check), not a hope.

- FR-2: **Shutdown covers both listeners.** `uvicorn.Server.serve()`
  installs process-wide signal handlers with `signal.signal`
  (`uvicorn/server.py:323-341`), and uvicorn 0.52 offers no way to opt out.
  Two servers in one process therefore fight over `SIGTERM`: whichever
  entered `capture_signals()` last wins, sets `should_exit` on **itself**,
  and the other keeps running until the container's grace period expires and
  Docker sends `SIGKILL`.

  `run` therefore supervises: it awaits the server tasks with
  `asyncio.wait(..., return_when=FIRST_COMPLETED)`, and when the first one
  finishes it sets `should_exit = True` on every other server and awaits
  them. Public attributes only, and correct whichever server the signal
  reached.

- FR-3: **TLS material at rest: the certificate in the clear, the key
  sealed — never a plaintext key on disk.** `DATA_DIR/tls/` is created mode
  `0700` and holds two files:
  - `cabin.crt` — the leaf, followed by the issuing chain when there is one,
    PEM. A certificate is a public document; it is stored as one.
  - `cabin.key.sealed` — the private key sealed with the same AES-GCM
    `SecretStore` that protects every CA key and every server-generated leaf
    key (`secrets.py:65-71`). Byte-for-byte the same treatment as
    `ca_certificates.key_sealed`, in a file rather than a column only
    because there is no table a stage-1 certificate could live in (FR-4).

  Both are written to a temporary file in the same directory, chmod'ed
  `0600`, and moved into place with `os.replace`, so a crash mid-write
  cannot leave a half-written file.

  cabin's stated posture is that no private key exists in plaintext at rest,
  and the key protecting the operator's login is the last one that should
  get an exception carved out for it. So it does not get one.

  **The key reaches OpenSSL without ever touching a filesystem.**
  `ssl.SSLContext.load_cert_chain()` takes paths, not bytes — there is no
  in-memory overload. The gap is closed with an anonymous in-memory file:

  ```
  fd = os.memfd_create("cabin-tls-key", os.MFD_CLOEXEC)
  os.write(fd, secrets.unseal(sealed))          # plaintext key, RAM only
  ctx.load_cert_chain(cert_path, f"/proc/self/fd/{fd}")
  os.close(fd)                                  # in a finally
  ```

  `memfd_create` returns a file living only in anonymous memory: it has no
  name in any filesystem, not even a tmpfs one, it is unlinked by
  construction, `MFD_CLOEXEC` keeps it out of any child process, and closing
  the descriptor frees the pages. `/proc/self/fd/N` is a path OpenSSL's
  `BIO_new_file` can open, and it resolves to that descriptor and nothing
  else. The unsealed key exists as process memory for the duration of one
  call and is never reachable from the filesystem at any point.

  **This was measured, not reasoned about.** A probe against cabin's own
  interpreter (`.venv`, CPython 3.13.14) loaded a certificate and key
  through `/proc/self/fd/N` memfd paths with `MFD_CLOEXEC` set, then
  completed a real TLS handshake against the resulting context and read the
  served certificate back off the wire — the CN came back as expected, so
  the context genuinely held usable key material rather than merely not
  having raised. Two alternatives were probed and also pass, and are
  recorded because they are the fallbacks: a `/dev/shm` tmpfs file
  (persistent-storage-free but nameable by anything in the container while
  it exists) and a regular file unlinked immediately after the load — which
  proves that `load_cert_chain` reads eagerly and the context survives its
  files disappearing.

  Fallback, and only this one: if `os.memfd_create` raises — an ancient
  kernel, a seccomp profile that blocks it, `/proc` not mounted — cabin
  falls back to a `0600` file inside `DATA_DIR/tls/` that is unlinked
  immediately after `load_cert_chain` returns, and logs one line saying it
  did. That narrows a permanent exposure to a window of microseconds, and
  it is the difference between degraded TLS and no TLS at all. There is no
  third path and no configuration knob.

  **A pair that does not load is discarded, not fatal.** If unsealing fails
  or `load_cert_chain` rejects the result (a mismatched pair from a crash
  between the two `os.replace` calls, a truncated file, a key sealed under a
  master key that has since changed), cabin logs what it discarded and
  issues fresh material rather than refusing to start. An instance that
  cannot boot because of its own certificate cannot be repaired through its
  own UI. One consequence worth naming: a wrong `CABIN_MASTER_PASSPHRASE`
  makes the sealed TLS key unreadable, and cabin will silently reissue —
  which is the correct outcome, because the same wrong passphrase has
  already made every CA key unreadable and that failure surfaces loudly on
  its own.

- FR-4: **Stage 1 — self-signed at first start.** With TLS on and no active
  issuer, cabin generates a self-signed server certificate before the
  listener accepts anything, and serves it. A new pure helper
  `ca/leaf.self_signed_server_certificate(subject_cn, sans, key_type, days)`
  builds it next to `issue_certificate` (`ca/leaf.py:370`), reusing that
  module's SAN normalisation and the `server` profile's KeyUsage/EKU
  (`ca/leaf.py:93-108`), with `basicConstraints CA:FALSE`.

  It is **not** written to the `certificates` table. It has no issuer, and
  `certificates.issuer_id` is NOT NULL with no default and no meaning for a
  row nothing signed (`ca/certs.py:69-71`). Stage 1 material exists only as
  the two files from FR-3.

- FR-5: **What name the certificate covers.** `tls.wanted_names(db)` returns
  the subject CN and the SAN list:
  - `base_url` configured → its host, port stripped (a port is a property of
    the listener, not of a name). If the host is an IP literal it becomes an
    IP SAN, which `ca/leaf.py`'s SAN handling already distinguishes.
  - `base_url` empty → the fallback: `socket.gethostname()`, `localhost`,
    `127.0.0.1` and `::1`. This is stage-1-only material for an instance that
    has not been configured yet, and it exists because `base_url` genuinely
    is empty at first start (see Context) — not as a preference.

  Whenever the names cabin's current certificate covers differ from
  `wanted_names`, it is re-issued and swapped in. That is what makes the
  fallback safe: the moment the operator saves a `base_url`, the certificate
  follows.

- FR-6: **Stage 2 — a certificate from cabin's own CA, swapped in live.**
  `tls.ensure_current(db, secrets) -> bool` is the single entry point for
  everything above and returns whether the material changed. It:
  1. reads the current certificate from disk (or notes that there is none);
  2. decides the target state — CA-issued when FR-17 resolves a bound
     issuer, self-signed otherwise — and the names from FR-5;
  3. re-issues when the target differs from what is on disk, when the names
     differ, or when FR-9's renewal window is open **and** FR-17's
     no-shorter-certificate rule allows it; otherwise returns `False` and
     touches nothing;
  4. writes `cabin.crt` and the sealed `cabin.key.sealed` per FR-3, then
     calls `tls.load_into(config.ssl, cert_path, key_pem)` — FR-3's memfd
     load — on the live `uvicorn.Config` from FR-1. The unsealed key is
     passed from step 4 in memory; it is never written anywhere.

  The CA-issued certificate is produced through the ordinary
  `certs.issue_and_store(...)` path with a new `CertSource.system`, so it is
  a normal row in the inventory with a real `issuer_id`, a sealed key, a CDP
  and an AIA, and so it is visible, revocable and counted like any other
  certificate. `cabin.crt` contains that leaf followed by
  `chain_for(db, issuer_id)`, so a client holding only the root can still
  build the chain.

  `ensure_current` is called from four places, all of which pass through
  this one function: at startup (FR-9), from the hourly check (FR-9), after
  `POST /ca/create` and `POST /ca/import` succeed, and after `POST /settings`
  changes `base_url`. In the two request paths a failure is logged and
  audited but never turned into a 5xx: the CA _was_ created, and losing that
  outcome because a certificate could not be swapped would be the worse
  error. The hourly check makes a missed hook a delay of at most an hour
  rather than a permanent wrong state.

  A `threading.Lock` guards the write-and-load sequence — the request paths
  run in Starlette's threadpool while handshakes run on the event loop, and
  two concurrent triggers must not interleave two writes to the same two
  files, nor two overlapping unsealed keys in memory.

- FR-7: **The swap must survive `config.ssl` not existing yet.**
  `Config.load()` runs inside `Server._serve()` (`uvicorn/server.py:87-88`),
  so between process start and the server actually serving there is a window
  in which `config.ssl` is absent. `ensure_current` writes the files
  unconditionally and calls `load_cert_chain` only when the context exists;
  when it does not, the files are what the server will pick up when it
  loads. Nothing is lost and nothing raises. `run` waits for
  `server.started` before starting the plaintext listener and before the
  first post-startup check, which is also what guarantees the main app's
  lifespan has populated `app.state` (`app.py:35-47`) for FR-10.

- FR-8: **cabin runs exactly one worker process, and says so.** `run` starts
  one `uvicorn.Server` for the application listener and never a worker pool.
  If a worker count greater than one is requested — today only through the
  conventional `WEB_CONCURRENCY`, which cabin now no longer inherits from
  `uvicorn.run()` — and TLS is on, cabin exits non-zero **before binding
  anything**, with a message naming the certificate swap as the reason.
  Refusal rather than a warning: the failure mode is that half the
  connections keep the stale certificate with nothing in any log, and that
  is not something an operator can be expected to notice.

- FR-9: **Renewal: at startup and on an hourly check.** cabin's own
  certificate is issued for 90 days and renewed once fewer than 30 days
  remain. `ensure_current` is called once during startup, **before the
  listener accepts its first connection**, and thereafter by one background
  task on an hourly interval.

  **Why this is a timer and not the CRL's lazy pattern.** The plan asked for
  "lazy on access plus a startup check, the way the CRL does it". Two things
  are wrong with that, and both matter enough to write down, because this is
  the requirement someone will later try to simplify back.

  First, the CRL has no startup check to copy. `current_crl`
  (`ca/crl.py:166`) is lazy on access and nothing else, and it has exactly
  one caller (`web/crl_ui.py:51`).

  Second, and decisive: **lazy-on-access is structurally impossible here.**
  The CRL's refresh works because the access and the document are the same
  event — a request arrives for a CRL, and cabin can freshen it before
  answering, inside the handler, while the client waits. cabin's own
  certificate is presented during the **TLS handshake**, which completes
  entirely inside OpenSSL and asyncio before a single byte of ASGI request
  reaches any cabin code. There is no handler that runs "on access" to a
  certificate. By the time the earliest possible hook — a request — could
  fire, the handshake is already over and the client has already been shown
  the expired certificate and, if it is a browser, has already refused to
  continue or thrown an interstitial. The only request that could trigger a
  lazy renewal is one that the expired certificate has already prevented.

  So renewal has to be driven by a clock, not by traffic: one call during
  startup before the listener accepts anything, and one background task on
  an hourly interval. This is cabin's first background scheduler, and spec
  0017's Out of Scope names the lazy CRL refresh as cabin's only one — this
  is a deliberate, argued exception to that line, not an oversight in it.

  **The loop is a seam, so it can be tested without waiting an hour.**
  `tls.renewal_loop(interval, tick, stop)` is the whole of the scheduler:
  it calls `tick` every `interval` until `stop` is set, and `run` supplies
  `CHECK_INTERVAL`, a `tick` that opens a session and calls
  `ensure_current`, and the same stop signal FR-2 uses. A test drives it
  with a millisecond interval and a fake `tick`; nothing in the suite sleeps
  for an hour.

  **A failing tick must not kill the loop.** `renewal_loop` catches every
  exception `tick` raises, logs it, and continues to the next interval. A
  transient database error, a locked SQLite file or an issuer that is
  briefly unusable must cost one cycle, not the scheduler — a loop that dies
  silently after one bad tick is worse than no loop at all, because the
  certificate then expires with the process looking perfectly healthy.
  AC-22 asserts the cycle _after_ a raising one still runs.

- FR-10: **The plaintext PKI listener.** With TLS on, `run` starts a second
  `uvicorn.Server` on `config.http_port`, bound to `0.0.0.0`, serving a
  separate ASGI application built by `server.create_public_app(main_app)`.
  That application contains `crl_router` (`web/crl_ui.py`) and **nothing
  else**: no other router, no static mount, no `/healthz`, no session
  middleware, no exception handler that could produce a redirect. Every
  path it does not know is a 404 from Starlette's default handler.

  It has no lifespan and opens no database or secret store of its own. It
  reaches the main application's state through FastAPI dependency
  overrides: `get_db` (`web/deps.py:90-96`) is overridden with a generator
  over `main_app.state.db`, and a new `web/deps.get_secrets(request)` — which
  `crl_ui` uses in place of reading `request.app.state.secrets` directly
  (`web/crl_ui.py:51`) — is overridden with `main_app.state.secrets`. The
  closures read `main_app.state` per request, by which time FR-7's
  `server.started` wait has guaranteed it exists.

  **This is a security property, not a routing detail.** No route that
  accepts a credential is mounted on this listener, and no response from it
  ever carries a `Location` header or a `Set-Cookie`. A redirect from `/` to
  the HTTPS origin looks helpful and would mean a browser that reached the
  plaintext port first can be walked to a login form; a client that follows
  it having already typed a password sends it in the clear. AC-11 is written
  so that adding one turns the suite red.

  With TLS off there is no second listener; the PKI routes stay on the one
  plaintext port they are on today.

- FR-11: **`COOKIE_SECURE` becomes automatic.** With TLS on,
  `Config.cookie_secure` is `True` regardless of the environment, so
  `set_session_cookie` (`web/deps.py:35-45`) marks the session cookie
  `Secure`. An explicit `COOKIE_SECURE=false` alongside TLS is overridden,
  with one log line naming the override — cabin is the TLS terminator, so
  there is no deployment in which the operator is right and cabin is wrong.

- FR-12: **Two new environment variables, and an ADR for them.**
  `cabin.config.Config` gains `tls: bool` and `http_port: int`:

  | Variable          | Default | Meaning                                                                  |
  | ----------------- | ------- | ------------------------------------------------------------------------ |
  | `CABIN_TLS`       | `false` | Terminate TLS in cabin. Parsed like `COOKIE_SECURE` (`config.py:77-80`). |
  | `CABIN_HTTP_PORT` | `8081`  | Port of the plaintext PKI listener. Only used when `CABIN_TLS` is on.    |

  `PORT` keeps its meaning — the port the UI, API, ACME and MCP are served
  on — and speaks HTTPS instead of HTTP when TLS is on. `CABIN_HTTP_PORT` is
  range-checked by the existing `_parse_port` (`config.py:42-49`); equal to
  `PORT` it is a `ConfigError` naming both. Set without `CABIN_TLS` it is
  ignored, with one log line saying so.

  cabin has deliberately had exactly five environment variables
  (`README.md:71-75`); this makes seven. **`docs/adr/0002-tls-environment-variables.md`**
  records the deviation in the shape of `docs/adr/0000-template.md`, and
  must cover why the alternatives were rejected: a single combined variable
  (the plaintext port genuinely varies per deployment, and a fixed one would
  collide); deriving the plaintext port as `PORT + 1` (an implicit binding
  is worse than an explicit one, and it can collide with something already
  there); and putting "TLS on" in the `settings` table next to
  `acme_enabled` (`settings.py:28-30`) — the strongest-looking option, and
  rejected because a setting that can make the UI unreachable must be
  changeable _without_ the UI. An operator whose certificate covers the
  wrong name needs to be able to turn TLS off from the outside.

- FR-13: **A base URL with an explicit port is refused while TLS is on.**
  `public_http_origin` (`ca/leaf.py:32-49`) forces the scheme to `http` and
  drops an explicit `:443`, but keeps any other port — spec 0017 AC-9 pins
  that. With TLS on, that port is the _TLS_ port, so
  `base_url = https://ca.example.lan:8443` would write
  `http://ca.example.lan:8443/crl/{id}` into every certificate: a CDP
  pointing at an HTTPS listener, unreachable, and silent until some relying
  party actually enforces revocation.

  `POST /settings` therefore rejects a `base_url` with an explicit port
  other than `443` when `config.tls` is on, with a 400 and a message naming
  the reason; the check lives in the route (`web/settings_ui.py:185-195`),
  which has the config, not in the pure `validate_base_url`
  (`settings.py:139-176`), which does not. A value already stored from
  before TLS was turned on is **not** a startup failure — cabin comes up,
  logs a warning and shows the dashboard banner from FR-14, because an
  instance that refuses to start cannot be fixed through its own settings
  page.

  The consequence for deployment, which follows and must be documented
  (FR-15): the plaintext listener has to be published on port **80** of the
  host named in `base_url`. That is where every certificate cabin issues
  says its CRL and CA certificate are.

- FR-14: **What the operator is told.** The first-run browser warning is
  expected, and cabin says so before and after it happens:
  - `setup.html` and `ca_setup.html` carry a short note, rendered only while
    the TLS mode is self-signed, explaining that the warning is expected and
    what ends it.
  - The dashboard (`web/ui.py:255-320`) carries a banner whose content
    depends on the mode: while self-signed, "cabin is using a self-signed
    certificate — create or import a CA to replace it"; once CA-issued,
    "install this root in your trust store to remove the warning", linking
    to the public `GET /ca/{root id}.cer` (`web/crl_ui.py:85`). The banner is
    absent entirely when TLS is off.
  - A new `AuditAction.tls_certificate_issued`, recorded with
    `audit.SYSTEM_ACTOR` (`audit.py:120-121`), `target_type="certificate"`,
    and a detail naming the mode, the names covered and the new `not_after`
    — for both the self-signed and the CA-issued case, so the certificate
    the instance presents always has a written history.

- FR-15: **Deployment.** The container currently probes `/healthz` over
  plain HTTP on `$PORT` (`Dockerfile:78-79`), which fails the moment that
  port speaks TLS. The `HEALTHCHECK` becomes scheme-aware: `https` with
  certificate verification disabled when `CABIN_TLS` is on, `http`
  otherwise. Verification is off because at stage 1 the certificate is
  self-signed _by definition_, and this is a liveness probe against
  `127.0.0.1`, not a trust decision.

  `docker-compose.yml` gains the second published port and the two new
  variables, commented out like the existing optional ones, plus the note
  that the plaintext port belongs on host port 80 (FR-13).
  `deploy/unraid/cabin.xml` gains `Config` entries for both variables and a
  second port mapping. `README.md`'s configuration table (`:71-75`) grows
  the two rows, and its security note (`:86-90`) — which today says only
  "put a reverse proxy in front and set `COOKIE_SECURE=true`" — gains the
  TLS-on path: the expected first-run warning, the three stages, the
  port-80 requirement from FR-13, and the statement that cabin's own TLS key
  is sealed at rest like every other key it holds (FR-3), so that the
  security note says the same thing about `DATA_DIR/tls/` that it already
  says about the database.

- FR-16: **The CDP and AIA URLs are shown to the operator, exactly as they
  are embedded.** FR-13 stops the worst `base_url` mistake, but it cannot
  catch the other half: an operator who publishes the plaintext listener on
  the wrong host port ends up with certificates whose CRL and CA URLs are
  dead, and nothing in cabin ever says so. The failure is invisible until
  some relying party enforces revocation, which may be years later and will
  not look like a cabin problem when it happens.

  `/ca` therefore shows, per issuer, the **exact** CDP and AIA URLs that go
  into certificates that issuer signs, as visible and clickable text — the
  way `/acme` already presents the directory URL for exactly this reason
  (`templates/acme.html:50-51`). Today `/ca` renders `crl_url` only as an
  unlabelled `crl` link with the URL invisible (`templates/ca_list.html:38`)
  and has no AIA URL at all; `_row_view` (`web/ca_ui.py:94-113`) gains
  `ca_url` from `crl.ca_issuers_url(db, row.id)` alongside the `crl_url` it
  already computes.

  The values rendered must be the values `crl.distribution_url` and
  `crl.ca_issuers_url` return — the same two functions issuance itself calls
  (`ca/certs.py:228-229` and `:277-278`), not a URL recomputed for display.
  AC-20
  pins that by comparing the rendered hrefs against the URLs parsed out of a
  certificate that issuer actually signed, so the page cannot drift from
  what is in the certificates.

  An operator who can see the URL and click it finds a broken deployment in
  seconds. That is the entire justification, and it is cheap.

- FR-17: **Which issuer signs cabin's own certificate is a stored,
  deliberate choice.** Spec 0017 FR-6 requires an explicit `issuer_id` as
  soon as more than one issuer is active and raises `IssuerRequiredError`
  otherwise. `ensure_current` calling `issue_and_store` without one would
  therefore fail to issue **and fail to renew** on exactly the multi-issuer
  installations 0017 exists to enable. That is a functional defect, not a
  corner case, and the fix is not to pick a default silently: whichever
  issuer signs cabin's own certificate decides the chain an operator has
  installed in their browser and their trust stores, so a rotation that
  moved cabin onto a different issuer without anyone deciding would break
  trust across a fleet with no decision recorded anywhere.

  A new setting `TLS_ISSUER_ID = "tls_issuer_id"` (`settings.py`) holds the
  chosen `ca_certificates.id` as text. `tls.resolve_tls_issuer(db)` decides,
  in the shape 0017 FR-6 already established:
  - set, and it names an **active intermediate** → that issuer.
  - unset, and exactly **one** active issuer exists → that one, **and it is
    persisted immediately**, before the certificate is issued. Writing the
    decision down at the moment it is unambiguous is what stops a second
    issuer created later from changing the answer retroactively.
  - unset, and **several** active issuers exist → no CA-issued certificate.
    cabin keeps serving what it has (self-signed at stage 1), logs it,
    and shows the operator a banner asking them to choose. It does **not**
    raise: the multi-issuer instance must stay reachable, and being
    reachable behind a self-signed certificate beats not starting.
  - set, but the row is unknown or retired → the same: keep the current
    material, warn, do not silently rebind. Falling back to another issuer
    here would be precisely the silent chain change this requirement exists
    to prevent.

  `/settings` gains an issuer select, populated from `active_issuers(db)`
  and rendered only when TLS is on — mirroring how the issue form renders
  its selector only when there is a choice to make (0017 FR-14). Changing it
  triggers `ensure_current`, so the new chain is served immediately rather
  than at the next renewal.

  **Retiring the bound issuer is refused while TLS is on.** Retiring it
  would leave `resolve_tls_issuer` unable to renew, and cabin's certificate
  would then expire 30 to 90 days later — the maximum possible distance
  between cause and symptom, long after the operator has forgotten the
  retirement. The refusal is the same shape as 0017 FR-4's
  `RetireError` and the last-superadmin invariant (`users.py:75-79`), and
  its message names the fix: rebind under Settings first, then retire. The
  check must cover the **cascade**: retiring a root also retires its
  intermediates (`ca/service.py:409-417`), so it tests the whole set that
  would be stood down, not just the named row. A new
  `ca/service.retire_targets(db, ca_id) -> set[int]` returns that set and is
  used by `retire` itself, so there is one definition of what a retire
  touches rather than two that can drift.

  Like FR-13, the check lives in the route (`web/ca_ui.py`'s retire POST),
  which has `request.app.state.config`, and not in `ca/service.retire`,
  which does not and must not. With TLS off there is no refusal at all — the
  binding is inert and an operator not using cabin's TLS must not be
  obstructed by it.

  **An expiring bound issuer is warned about, never worked around.** cabin
  cannot choose a different issuer on its own, so it does the two things it
  can:
  - The dashboard's per-issuer expiry warning (`web/ui.py:55`,
    `CA_WARN_DAYS`) says additionally, for the bound issuer, that this is
    the issuer signing cabin's own certificate — so the warning names a
    consequence and not just a date.
  - 0017 FR-7 already reports a clamped validity as `capped_from`. When
    cabin's own renewal comes back clamped, that is the first hard evidence
    the bound issuer is running out; it is logged and audited with the
    renewal, not discarded.

  **No renewal storm as the issuer runs out.** Once the bound issuer has
  less time left than `RENEW_BEFORE`, every certificate cabin issues itself
  is clamped to the issuer's `not_after` and is therefore _immediately_
  inside the renewal window again. A naive implementation would re-issue on
  every hourly tick and add 8,760 rows a year to the inventory. So
  `ensure_current` re-issues only when the replacement would be **at least
  one day longer-lived** than what is already loaded; otherwise it logs and
  returns `False`. AC-24 measures this.

  **cabin never downgrades itself from CA-issued to self-signed.** If the
  bound issuer becomes unusable, the existing certificate keeps being
  served — even once expired — and the failure is logged, audited and shown.
  Replacing a certificate whose root the operator has installed with a
  self-signed one would turn a working, trusted deployment into a browser
  warning automatically and unattended, and would look enough like a fix to
  take the pressure off repairing the real problem. A self-signed
  certificate is what an instance starts with, not something it falls back
  to.

## Interface Contract

What the Functional Requirements change, named exactly, so that the modules
on either side of a seam cannot be built against two different guesses.

### `cabin.config`

- `Config` gains `tls: bool = False` and `http_port: int = DEFAULT_HTTP_PORT`
  (`8081`). `Config.load` reads `CABIN_TLS` and `CABIN_HTTP_PORT`, and
  forces `cookie_secure=True` when `tls` is true (FR-11). `ConfigError` when
  `http_port == port` and TLS is on.

### `cabin.server` — new

- `run(config: Config) -> None` — builds the TLS manager, passes it to
  `create_app`, builds the uvicorn `Config`/`Server` objects, and blocks
  until every server has stopped. The only caller is `cli.main`.
- `create_public_app(main_app: FastAPI) -> FastAPI` — FR-10. Contains
  `crl_router` and nothing else, with `dependency_overrides` for `get_db`
  and `get_secrets` pointing at `main_app.state`.

### `cabin.app` — where `app.state.tls` comes from

`create_app` gains one optional parameter:
`create_app(config: Config, tls: TlsManager | None = None) -> FastAPI`, and
its lifespan sets `app.state.tls = tls` on the line after
`app.state.config = config` (`app.py:39`). `run` is what passes a manager;
every other caller passes nothing and gets `None`.

**This is specified rather than left to the implementer because
`app.state` is a trap here.** `set_session_cookie` reads
`request.app.state.config` unguarded (`web/deps.py:41`) and works only
because the lifespan sets it — so anything reading `app.state.tls` the same
way would raise `AttributeError` in every one of the ~36 places that build
an app through `create_app` without going through `server.run`, which is all
of the test suite. Establishing it in the lifespan alongside `config`,
defaulting to `None`, means no existing call site changes and `None` is a
supported value with a defined meaning: TLS is off, and FR-14's banner is
absent. Nothing may read `app.state.tls` without handling `None`.

### `cabin.tls` — new

Top-level, next to `secrets.py` and `settings.py`: it needs `ca`,
`settings`, `secrets`, `audit` and `config`, and nothing under `ca/` may
import it back.

- `TlsMode` (`StrEnum`): `self_signed`, `ca_issued`.
- `CERT_DAYS = 90`, `RENEW_BEFORE = timedelta(days=30)`,
  `CHECK_INTERVAL = timedelta(hours=1)`, `MIN_RENEWAL_GAIN = timedelta(days=1)`
  (FR-17's no-shorter-certificate rule).
- `TlsManager(data_dir: Path)`:
  - `mode: TlsMode | None` — what is currently loaded; `None` before the
    first `ensure_current`. Read by FR-14's templates via `app.state.tls`.
  - `attach(uvicorn_config: uvicorn.Config) -> None` — hands over the
    `Config` whose `.ssl` will be mutated.
  - `ensure_current(db: Session, secrets: SecretStore) -> bool` — FR-6.
    Returns whether the material changed. Never raises for a recoverable
    condition; logs and returns `False`.
  - `wanted_names(db: Session) -> tuple[str, list[str]]` — FR-5, as
    `(subject_cn, sans)`.
- `resolve_tls_issuer(db: Session) -> CACertificate | None` — FR-17.
  `None` means "no CA-issued certificate right now", never an exception:
  every ambiguous or broken binding keeps the instance serving what it has.
  Persists the sole-active-issuer decision as a side effect, which is the
  one case where it writes.
- `renewal_loop(interval: timedelta, tick: Callable[[], None], stop: asyncio.Event) -> None`
  — FR-9's scheduler and the seam AC-22 drives. Calls `tick` every
  `interval` until `stop` is set; catches, logs and swallows **every**
  exception `tick` raises. Takes the interval as an argument precisely so a
  test can pass milliseconds.
- `cert_path(data_dir)` / `sealed_key_path(data_dir)` —
  `data_dir / "tls" / "cabin.crt"` and `.../"cabin.key.sealed"`. There is no
  `key_path`: no plaintext key file exists to have a path (FR-3).
- `load_into(ctx: ssl.SSLContext, cert_path: Path, key_pem: bytes) -> None`
  — FR-3's memfd load, and the **only** function in cabin that ever holds an
  unsealed TLS key. Takes the key as bytes rather than a path so no caller
  can pass it a filename; closes the descriptor in a `finally`; falls back
  to an immediately-unlinked `0600` file only when `os.memfd_create` raises,
  and logs when it does.

### `cabin.ca.leaf` — pure crypto, no database

- `self_signed_server_certificate(subject_cn: str, sans: Sequence[str], key_type: str = "ecdsa-p256", days: int = 90) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]`
  — FR-4. Self-signed, `CA:FALSE`, the `server` profile's KeyUsage and EKU,
  the same `_BACKDATE` and SAN normalisation as `issue_certificate`, and no
  CDP or AIA (there is no CRL that would cover it).

### `cabin.ca.certs`

- `CertSource` gains `system = "system"` (FR-6). The column is
  `String(16)` with no CHECK constraint (`ca/certs.py:92-97`), so this needs
  no migration.

### `cabin.ca.service`

- `retire_targets(db: Session, ca_id: int) -> set[int]` — the ids `retire`
  would stand down: the row itself, plus its intermediates when it is a root
  (`ca/service.py:409-417`). Extracted so `retire` and FR-17's route check
  share one definition instead of each having their own.

### `cabin.settings`

- `TLS_ISSUER_ID = "tls_issuer_id"` (FR-17) — the chosen
  `ca_certificates.id` as text, empty meaning unchosen. Read and written
  through the existing `get_setting`/`set_setting`; no new storage
  mechanism.

### `cabin.audit`

- `AuditAction` gains `tls_certificate_issued` (FR-14). The audit filter is
  generated from the enum, so it appears there for free — and AC-18 asserts
  on the rendered option, not on the enum.

### `cabin.web.deps`

- `get_secrets(request: Request) -> SecretStore` — returns
  `request.app.state.secrets`. Introduced so the plaintext app can override
  it (FR-10); `crl_ui` is the only caller that changes.

### Routes on the plaintext listener

| Method | Path                       | Response                      |
| ------ | -------------------------- | ----------------------------- |
| GET    | `/crl/{issuer_id:int}`     | `application/pkix-crl` (DER)  |
| GET    | `/crl/{issuer_id:int}.pem` | `application/x-pem-file`      |
| GET    | `/ca/{ca_id:int}.cer`      | `application/pkix-cert` (DER) |

Everything else: 404, no `Location`, no `Set-Cookie`. The set is exactly
these three and AC-11 compares it as a set.

## Acceptance Criteria

Every criterion below is written so that something specific has to break for
it to go red; where a check could pass against a broken implementation, the
counter-check is named. This project has shipped two tests that passed while
the feature was visibly broken, and a mutation harness recently found a
third where a chain check could not detect a cryptographically invalid root.
"Returned 200" and "contains the string" are not acceptance here.

- AC-1: **The swap happens on a live server.** With TLS on and no CA, an
  instance is started through `server.run`. A raw TLS connection reads the
  peer certificate with `getpeercert(binary_form=True)` and parses it: its
  issuer equals its subject (self-signed). A CA is then created through the
  running instance over HTTPS. A **new** connection reads a certificate
  whose issuer is the intermediate's subject and whose serial differs.
  Throughout, the process id is unchanged and the listening socket was never
  rebound.
  _Goes red if_: the swap does not happen; a restart happened (pid check);
  the test asserted only that no exception was raised. The first
  connection's self-signed assertion is what stops a test from passing
  against an implementation that only ever issues from the CA.
- AC-2: **The swap does not break connections in flight.** A keep-alive
  connection opened before the swap serves a further request after it, and
  still reports the _old_ certificate. This is inherent to TLS — the
  certificate is fixed at handshake — and is asserted so that nobody later
  "fixes" it with a mid-connection renegotiation.
- AC-3: **Stage 3, both directions.** With the root exported and passed as
  `--cacert`, `curl https://<host>:<port>/healthz` exits 0 and returns the
  health JSON. The identical call **without** `--cacert` exits non-zero with
  a verification error. A test that runs only the first half proves nothing
  about trust.
- AC-4: **Stage 1 material.** Empty data dir, TLS on, no CA:
  `DATA_DIR/tls/` exists mode `0700`, `cabin.key.sealed` mode `0600`, and
  the certificate parses as self-signed and covers FR-5's fallback names.
  Counter-check: with `CABIN_TLS` unset, `DATA_DIR/tls` does not exist, the
  port speaks plain HTTP, and exactly one uvicorn `Server` was constructed.
- AC-5: **The name follows `base_url`.** With `base_url` empty, the
  certificate's SANs are the fallback set. After `POST /settings` stores
  `https://ca.example.lan`, a new connection presents a certificate whose
  SANs contain `ca.example.lan` and **not** the OS hostname, with a
  different serial — and no restart occurred.
- AC-6: **Renewal is conditional.** A certificate whose `not_after` is
  inside `RENEW_BEFORE` is replaced by one call to `ensure_current`: new
  serial, later `not_after`, and a new connection presents it. Counter-check:
  a certificate outside the window is left byte-for-byte alone and
  `ensure_current` returns `False`. Without the second half the test would
  also pass an implementation that re-issues on every tick.
- AC-7: **The startup check runs before the first connection.** Starting
  with an expired certificate on disk, the **very first** TLS connection
  after startup already presents the renewed one. Goes red if the check is
  only on the hourly task or runs after the server starts serving.
- AC-8: **A swap before the server has loaded its context is not lost.**
  `ensure_current` is called with `config.ssl` absent: it raises nothing,
  writes both files, and the first connection after the server starts
  presents exactly that certificate. Goes red on an unguarded dereference of
  `config.ssl`, and on an implementation that mutates the context but skips
  the files.
- AC-9: **Multi-worker is refused, loudly.** A worker count greater than one
  with TLS on exits non-zero before any socket is bound, and the message
  names the certificate swap. Counter-check: the same request with TLS off
  starts normally. Plus: `server.run` constructs exactly one application
  `Server`, asserted on the constructed objects, so introducing a worker
  pool later fails here rather than in production.
- AC-10: **The plaintext listener serves real PKI documents.**
  `GET http://<host>:<http_port>/crl/{intermediate id}` returns
  `application/pkix-crl` whose DER parses with `x509.load_der_x509_crl` into
  a CRL whose issuer equals that intermediate's subject;
  `/ca/{root id}.cer` returns DER that parses into a certificate whose
  subject equals that root's. Status codes alone do not satisfy this.
- AC-11: **The plaintext listener serves nothing else — the negative case.**
  For each of `/`, `/login`, `/setup`, `/healthz`, `/certs`, `/ca`,
  `/api/v1/ca`, `/acme/ca/1/directory` and `/static/app.css`, the response
  status is **404**; no response carries a `Location` header; no response
  carries a `Set-Cookie`. `POST /login` is also 404 — a 405 would prove the
  route exists. And the public application's route set equals exactly the
  three paths in the Interface Contract, compared as a set.
  _Goes red if_: someone adds an HTTP→HTTPS redirect (the `Location`
  assertion); someone mounts the full app or a single extra convenience
  route (the set comparison and the 404s); someone attaches the session
  middleware (the `Set-Cookie` assertion).
- AC-12: **`Secure` is on the wire.** With TLS on, a successful login's
  `Set-Cookie` for `cabin_session` carries the `Secure` attribute — both
  with `COOKIE_SECURE` unset and with `COOKIE_SECURE=false`. With TLS off
  and `COOKIE_SECURE` unset it does not. Asserted on the response header,
  not on `config.cookie_secure`, because the header is what a browser obeys.
- AC-13: **Configuration.** `Config.load` maps both variables and their
  defaults; `CABIN_HTTP_PORT` equal to `PORT` with TLS on raises
  `ConfigError` naming both values; an out-of-range value is rejected the
  way `PORT` already is. `docs/adr/0002-tls-environment-variables.md` exists
  and carries the template's headings including "Considered Options" with
  the three rejected alternatives from FR-12. (The deliverable here _is_ a
  document, which is the one case where asserting its presence is the point.)
- AC-14: **CDP and AIA stay reachable.** With TLS on,
  `POST /settings` with `base_url=https://ca.example.lan:8443` returns 400
  and leaves the stored value unchanged; `https://ca.example.lan` is
  accepted, and a leaf issued afterwards carries
  `http://ca.example.lan/crl/{issuer id}` as its CDP and
  `http://ca.example.lan/ca/{issuer id}.cer` as its AIA — read off the
  parsed certificate. Counter-check: with TLS **off**,
  `https://ca.example.lan:8443` is still accepted and the port still
  survives into the URLs (spec 0017 AC-9 is unchanged by this spec).
- AC-15: **The setup copy exists and changes state.** While the mode is
  self-signed, the dashboard renders the banner element; after a CA is
  created and the swap has happened, the same element's link `href` resolves
  to `/ca/{root id}.cer`, and a request to that URL returns 200 and DER that
  parses into that root. With TLS off the element is absent from the parsed
  DOM. The assertion is on the element and its resolved link target, not on
  a substring of prose.
- AC-16: **Both listeners stop on `SIGTERM`.** A TLS-enabled instance
  receives `SIGTERM` and the process exits within the grace period;
  afterwards a connection to each of the two ports is refused. Goes red if
  FR-2's supervision is dropped and the second server outlives the first.
- AC-17: **Broken material on disk is survivable.** A mismatched
  certificate/sealed-key pair (a certificate for one key, the sealed key of
  another) is discarded at startup, cabin comes up, and the certificate it
  then serves is one that a client can complete a handshake with. The same
  holds for a `cabin.key.sealed` that cannot be unsealed at all. Goes red if
  either exception is allowed to escape and kill the process.
- AC-18: **Inventory and audit tell the truth.** After stage 2, the
  inventory holds exactly one row with `source == "system"`, whose
  certificate is the one the TLS listener presents (compared by serial), and
  an audit event `tls_certificate_issued` exists with the system actor and a
  detail naming the mode; the audit filter's rendered options include the
  new action. Counter-check for stage 1: with a self-signed certificate in
  place and no CA, the `certificates` table has **no** row at all — asserted
  as an absence, because a row with a fabricated `issuer_id` is exactly the
  shortcut this forbids.
- AC-19: **No plaintext private key is ever reachable on disk.** Three
  assertions, and the third is the one that matters:
  1. After a full startup, a stage-2 swap and a renewal, every regular file
     under `DATA_DIR` is read and none of them parses as a private key:
     `serialization.load_pem_private_key` fails on all of them, and none
     contains a `PRIVATE KEY` PEM header. `cabin.key.sealed` in particular
     is not loadable as a key but **is** loadable through
     `SecretStore.unseal` — so the test proves it is sealed, not merely that
     it is some opaque bytes.
  2. `DATA_DIR/tls/` contains exactly `cabin.crt` and `cabin.key.sealed`,
     compared as a set, so a stray temporary file left behind by a failed
     write is a failure rather than an unnoticed leak.
  3. **A watcher running concurrently with the load sees nothing.** While
     `ensure_current` runs, a second thread polls the contents of
     `DATA_DIR/tls/` continuously and records every filename it ever sees;
     afterwards, none of the recorded names is a plaintext key file. That is
     what distinguishes the required implementation from a
     write-load-unlink one, which the first two assertions would pass.
     _Goes red if_: someone "simplifies" the memfd load into a temporary
     file, or leaves the fallback path active by default.
- AC-20: **The displayed URLs are the embedded URLs.** For an issuer,
  `/ca` renders its CDP and AIA as visible, clickable text. A leaf is then
  issued from that issuer, and its `cRLDistributionPoints` and its AIA
  `caIssuers` URI are parsed off the certificate: both equal the `href`
  values on the page, string for string. Then, over the plaintext listener,
  a `GET` of each of those two URLs' paths returns the CRL and the CA
  certificate respectively, parsed, not merely 200.
  _Goes red if_: the page prettifies, recomputes or hardcodes a URL instead
  of calling `crl.distribution_url` / `crl.ca_issuers_url`; if the AIA link
  is missing; or if the URL is rendered but not as a link. With no base URL
  configured, both are absent from the page and the existing "no base URL is
  set" note (`templates/ca_list.html:39`) is what appears instead.
- AC-21: **cabin issues its own certificate on a multi-issuer instance.**
  This is the defect FR-17 exists to fix, so it is measured end to end.
  With **two** active issuers and `tls_issuer_id` unset, `ensure_current`
  does not raise, writes no CA-issued material, leaves the self-signed
  certificate being served, and the banner asks for a choice. After
  `POST /settings` selects the second issuer, a new TLS connection presents
  a certificate whose issuer is **that** issuer's subject — not the first
  one's, which is what a test using the "sole active issuer" default would
  wrongly accept. Counter-check on persistence: with exactly **one** active
  issuer and the setting unset, `ensure_current` issues **and** stores the
  id; creating a second issuer afterwards leaves the served certificate's
  issuer unchanged, proving the decision was written down rather than
  re-derived each time.
  _Goes red if_: `issue_and_store` is called without an `issuer_id` (it
  raises `IssuerRequiredError` and the connection fails); if the binding is
  not persisted; or if a second issuer silently changes the chain.
- AC-22: **The renewal loop runs, survives failure, and stops.** Driven
  through `renewal_loop` with a millisecond interval, never a real hour:
  1. A `tick` that renews an about-to-expire certificate is called
     repeatedly, and the material is actually replaced — asserted on the
     certificate served over a new connection, not on a call count.
  2. A `tick` that raises on its first call is still called again on the
     next interval, and the loop is still running afterwards. This is the
     one that matters: a scheduler that dies silently after a transient
     database error leaves the process looking healthy while the
     certificate expires underneath it.
  3. Setting the stop event ends the loop, and it does not delay FR-2's
     shutdown — AC-16's `SIGTERM` timing holds with the loop running.
- AC-23: **Retiring the bound issuer is refused, cascade included.** With
  TLS on and cabin's certificate bound to intermediate I1 (a second active
  issuer I2 existing, so 0017's own `RetireError` is not what fires), the
  retire POST for I1 returns an error naming the rebind as the fix and I1's
  `status` is **still** `active`. Retiring the **root** above I1 is refused
  for the same reason, which is what proves `retire_targets` is consulted
  rather than the named row alone. After rebinding to I2, retiring I1
  succeeds. Counter-check: with TLS **off**, retiring I1 succeeds
  immediately — the binding must not obstruct an instance not using it.
- AC-24: **No renewal storm as the bound issuer runs out.** With the bound
  issuer three days from expiry, cabin's own certificate is clamped to the
  issuer's `not_after` (0017 FR-7) and is therefore already inside the
  renewal window. Ten consecutive `ensure_current` calls after the first
  produce **no** new certificate row and return `False`, and the audit log
  gains no further `tls_certificate_issued` events. Counter-check: with a
  fresh issuer, a certificate inside the renewal window **is** replaced
  exactly once. Without both halves the test cannot tell "correctly declined"
  from "renewal is broken".

## Test list

test_run_without_tls_starts_one_plaintext_server,
test_run_without_tls_creates_no_tls_directory,
test_self_signed_certificate_at_first_start,
test_self_signed_certificate_is_not_stored_in_inventory,
test_wanted_names_fallback_without_base_url,
test_wanted_names_from_base_url_drops_port,
test_certificate_swapped_after_ca_created (live server, raw TLS peer-cert
read, both before and after),
test_swap_does_not_restart_process, test_keepalive_connection_keeps_old_cert,
test_certificate_reissued_after_base_url_change,
test_curl_trusts_ca_issued_cert_with_root_and_fails_without (both
directions), test_renewal_inside_window_replaces_material,
test_renewal_outside_window_changes_nothing,
test_startup_check_runs_before_first_connection,
test_ensure_current_before_ssl_context_exists,
test_multi_worker_with_tls_refuses_to_start,
test_multi_worker_without_tls_starts,
test_public_listener_serves_crl_and_ca_cer (parsed CRL/certificate, not
status codes), test_public_listener_404s_authenticated_routes,
test_public_listener_never_redirects,
test_public_listener_sets_no_cookie,
test_public_listener_route_set_is_exactly_three,
test_session_cookie_secure_with_tls,
test_session_cookie_secure_override_logged,
test_config_reads_tls_env_vars, test_config_rejects_http_port_equal_to_port,
test_adr_0002_exists_and_follows_template,
test_settings_rejects_ported_base_url_with_tls,
test_settings_accepts_ported_base_url_without_tls,
test_cdp_and_aia_have_no_port_with_tls,
test_dashboard_banner_self_signed, test_dashboard_banner_ca_issued_links_root,
test_dashboard_banner_absent_without_tls,
test_sigterm_stops_both_listeners,
test_mismatched_material_is_discarded_and_reissued,
test_tls_certificate_row_has_system_source,
test_audit_tls_certificate_issued,
test_no_plaintext_private_key_anywhere_under_data_dir,
test_sealed_tls_key_unseals_but_does_not_parse_as_a_key,
test_tls_dir_contains_exactly_cert_and_sealed_key,
test_concurrent_watcher_never_sees_a_plaintext_key_file,
test_memfd_load_serves_a_working_certificate,
test_load_falls_back_when_memfd_unavailable (with `os.memfd_create` patched
to raise, asserting both that TLS still works and that the fallback was
logged), test_unsealable_tls_key_is_discarded_and_reissued,
test_ca_page_shows_cdp_and_aia_urls,
test_displayed_urls_match_issued_certificate (the AC-20 comparison against a
parsed leaf), test_ca_page_urls_absent_without_base_url,
test_tls_issuer_persisted_when_exactly_one_active,
test_second_issuer_does_not_change_persisted_binding,
test_multi_issuer_without_binding_stays_self_signed,
test_multi_issuer_serves_selected_issuers_chain,
test_unknown_or_retired_binding_keeps_current_material,
test_settings_issuer_select_rendered_only_with_tls,
test_retire_bound_issuer_refused_with_tls,
test_retire_root_above_bound_issuer_refused,
test_retire_bound_issuer_allowed_without_tls,
test_retire_after_rebinding_succeeds,
test_renewal_loop_replaces_expiring_certificate,
test_renewal_loop_survives_a_raising_tick,
test_renewal_loop_stops_on_event,
test_no_reissue_when_gain_below_minimum,
test_reissue_when_gain_above_minimum,
test_capped_renewal_is_logged_and_audited,
test_never_downgrades_from_ca_issued_to_self_signed,
test_create_app_without_tls_manager_has_none_state (the `app.state.tls`
guard — every existing `create_app(config)` call site keeps working)

The live-server tests need a real `uvicorn.Server`, not `TestClient`:
`TestClient` never builds an `SSLContext`, so every criterion about the swap
would be vacuous against it. They start cabin on an ephemeral port in a
thread or subprocess and read the peer certificate off the socket, the way
the spike did.

Out-of-band, on the maintainer's machine, per the plan's verification list:
the three stages end to end against a browser and `curl`, and one certbot
run against a TLS-enabled instance to confirm in practice what the Context
argues from the code — that outbound `http-01` validation is untouched.

## Out of Scope

**Any HTTP→HTTPS redirect, anywhere.** Not on the plaintext listener, not as
an option, not "just for `/`". It is the one addition that would undo FR-10's
security property, and it is named here so that a later reader finds a
decision rather than an omission.

**Multi-worker mode.** cabin runs one process; FR-8 refuses more rather than
supporting them. Making the swap work across workers needs a broadcast
mechanism (IPC, or a full restart on change) and belongs to whatever spec
first has a reason to want workers at all.

**Defending the key inside process memory.** FR-3 keeps the unsealed TLS key
off every filesystem, and that is the whole of the claim. It is in process
RAM for the duration of one `load_cert_chain` call, and after that OpenSSL
holds it for as long as the context lives — which is the entire point of the
context. A core dump, a swap file, `ptrace` or `/proc/<pid>/mem` still reach
it, exactly as they reach every unsealed CA key `signing_credentials` hands
out. `mlock`, guarded allocators and zeroing after use are not in scope, and
claiming otherwise would be the more dangerous statement.

**Verifying that the published CDP and AIA URLs actually answer.** FR-16
shows the operator what went into the certificates; it does not fetch them.
cabin probing its own public URLs would be an outbound request that
frequently cannot succeed from inside the container even when the deployment
is correct — split-horizon DNS, a host-only port mapping — so a red cross
there would be wrong more often than right. Showing the URL and letting a
human click it is the check that works.

**Automatically rebinding to another issuer.** When the bound issuer becomes
unusable, cabin warns and keeps serving; it never picks a replacement.
Choosing an issuer changes the chain a fleet has been told to trust, and
that is an operator's decision (FR-17). Nothing here schedules cabin's own
certificate to follow a rotation on its own.

**Bring-your-own certificate.** cabin issues its own; there is no
`CABIN_TLS_CERTFILE`. An operator with a certificate from elsewhere already
has the supported path: a reverse proxy.

**Revoking cabin's superseded certificates.** Each renewal issues a new row
and the old one is left to expire. Revoking it would put an entry in a CRL
for a certificate nobody holds.

**Anything about the TLS layer beyond the certificate**: protocol versions,
cipher suites, HSTS, OCSP stapling, session tickets and client certificates
are Python's `ssl` defaults, unchanged. HTTP/2 is not a choice being made —
uvicorn ships no HTTP/2 implementation at all, so everything here is
HTTP/1.1.

**Obtaining cabin's own certificate over ACME**, from its own server or a
public one. Direct issuance is one function call and needs no challenge.

**Requiring `https://` in `base_url`.** `validate_base_url`
(`settings.py:139-176`) is unchanged; spec 0017 FR-12 continues to rewrite
only what goes into a certificate.

**Making the plaintext listener bind port 80 itself.** The image runs as a
nonroot uid and cannot; publishing the container's port on host port 80 is a
deployment step, documented under FR-15 and not automated.
