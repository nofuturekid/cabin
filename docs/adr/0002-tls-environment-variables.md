# 0002. Two new environment variables for native TLS

- Status: accepted
- Date: 2026-08-08
- Deciders: maintainer

## Context and Problem Statement

Since spec 0014, cabin has kept exactly five environment variables (`PORT`,
`DATA_DIR`, `CABIN_DB_URL`, `COOKIE_SECURE`, `CABIN_MASTER_PASSPHRASE`,
`README.md:69-75`). Everything else an operator can change after first start
lives in the `settings` table and is edited through the UI. The module
docstring of `cabin/settings.py` states the line plainly: settings are what
"an operator configures in the UI and cabin stores in the database", as
opposed to `cabin.config`, "the handful of process-level knobs that come
from flags and environment variables."

Spec 0022 gives cabin native HTTPS termination and needs two more runtime
values: whether TLS is on, and which port the plaintext PKI listener (the
CRL/CA-certificate routes that must stay reachable without TLS, spec 0022
FR-10) binds to. This breaks the five-variable line — it becomes seven. This
ADR records that the break is a deliberate, argued choice, not something that
happened by not noticing, and it says what would make the next such request
acceptable or not.

## Decision Drivers

- A setting that can make the user interface unreachable must be changeable
  from somewhere that does not depend on that interface being reachable. An
  operator who has locked themselves out with a broken TLS configuration
  needs a way in that does not run through the thing TLS is blocking.
- As supporting evidence, not the foundation: today, both values also have
  to be known before `cabin.server.run` can construct
  `uvicorn.Config`/`uvicorn.Server` and decide how many listeners to bind and
  on which ports — a decision made before the FastAPI `lifespan` has run, and
  therefore before the database session factory or the migrated schema exist
  (`app.py:35-41`: `run_migrations` and `create_session_factory` are both
  inside `lifespan`, which uvicorn calls only after `Server._serve()`
  starts). This is real today, but it is an artefact of the current startup
  sequence — a future refactor could open the database earlier — so it
  cannot carry the decision on its own.
- The five-variable constraint holds because everything behind it is a
  genuine operator preference that can safely wait for the app to be up —
  not because environment variables are cheap. It should not erode for
  convenience.
- The plaintext port must stay independently configurable: it can collide
  with whatever else a given host already has bound.

## Considered Options

- `CABIN_TLS` (bool) and `CABIN_HTTP_PORT` (int) as two new environment
  variables
- A `tls_enabled` (and port) row in the `settings` table, read once at
  startup before the listener binds — "database plus bootstrap read"
- A single combined environment variable, with a fixed, non-configurable
  plaintext port
- Deriving the plaintext port implicitly as `PORT + 1`
- A config file for just these two settings
- Command-line flags only, no environment variables

## Decision Outcome

Chosen option: **`CABIN_TLS` and `CABIN_HTTP_PORT` as two environment
variables**, because an operator recovering from a bad TLS setup needs a
lever that exists outside the thing TLS broke, and the environment block a
container is started with is exactly that: it is read before cabin runs at
all, and editing it does not depend on cabin serving anything.

**Why the database, even with a bootstrap read, does not work.** This is the
option a reader will most likely propose instead, so it gets the fullest
treatment. The decisive reason is recoverability, not timing: a `settings`
row is edited through the UI, or, failing that, by opening `cabin.db` with a
raw SQLite client while the container is stopped — both heavier, and both
still routed through the same instance whose TLS is broken, than editing a
compose file's environment block, which is the mechanism `COOKIE_SECURE` and
every other environment-set knob already gives an operator. A setting that
can make the UI unreachable has to be changeable from a place that does not
depend on the UI being reachable, and the database it lives in — reachable
only through cabin's own code, whether the UI, a maintenance script, or a
raw client working around cabin entirely — does not offer that independence
the way a file the container orchestrator reads directly does.

That alone is enough to reject it. Startup ordering adds a second, narrower
objection specific to _how_ cabin boots today: `run_migrations` and
`create_session_factory` both live inside the ASGI `lifespan`, which uvicorn
invokes only once `Server._serve()` starts — after `uvicorn.Config` is
already built with a fixed `ssl=` argument and a fixed set of ports. A
"bootstrap read" would mean opening a second, separate database connection
before that point, on a schema the `settings` table migration may not even
have applied yet, reading two keys, closing it, and then letting the
ordinary `lifespan` open the database again moments later through the normal
path — a second, parallel, unmigrated data-access code path whose only job
is answering two questions before the schema it depends on is guaranteed to
exist. This cost is real today and would have to be paid, but it is an
implementation detail of the current startup sequence, not the reason the
option is wrong: a maintainer who reordered startup to open the database
first would remove this objection without touching the lockout one.

**Why the smaller alternatives were also rejected.** A single variable that
combines the two concerns by giving up a separately configurable port (e.g.
`CABIN_TLS` alone, with a hardcoded plaintext port) does not actually save
anything: the plaintext port genuinely varies by deployment — whatever else
is already bound on the host's port 8081 collides — so a fixed value only
moves the problem to whoever hits the collision, silently. Deriving the port
implicitly as `PORT + 1` has the same collision risk plus a second cost: an
implicit binding an operator has to know about from documentation is worse
than one they can read directly out of their own environment block. A config
file introduces a new mechanism cabin has never had — a new format to parse,
a new precedence to define relative to flags and env, a new path to mount
into the container — to hold exactly two values, which is a disproportionate
amount of new surface for what it buys over an environment variable that
already has a defined precedence. Flags-only was rejected for the same
reason `PORT`/`DATA_DIR` already are not flag-only (spec 0001 FR-2): cabin
runs as a container with a fixed entrypoint, and setting a flag means
rebuilding or overriding the entrypoint rather than editing the environment
block every other deployment-time value already lives in.

### Consequences

- Good, because recovery from a broken TLS configuration is the same
  mechanism an operator already uses for `COOKIE_SECURE`: edit the
  environment, restart the container — a lever that does not depend on
  cabin, or its UI, being reachable at all.
- Good, because both values also happen to be available at the exact moment
  they are needed under the current startup sequence — before sockets are
  bound — with no new data-access path and no schema dependency added to
  startup. Supporting, not load-bearing: see the Decision Outcome.
- Good, because the deviation stays as narrow as it can be: the TLS
  hostname does **not** become a third environment variable. It is read from
  the existing `base_url` setting (spec 0022 FR-5), which already lives in
  the database and does not need to exist before the first listener binds —
  stage 1 serves a self-signed fallback certificate until it does.
- Bad, because the environment surface is now seven variables, not five, and
  the number is no longer a clean statement the README can make without a
  footnote.
- Bad, because this is a precedent, and precedents get cited. The next
  feature that wants an environment variable "for consistency with TLS" is
  not automatically justified by this ADR. The test this decision applies —
  and the one any future request should be held to — is recoverability, not
  convenience: would a wrong value, once set, leave the operator unable to
  reach the interface that could otherwise fix it? "Operators would rather
  not click into settings" is not that test. "This value is wrong and now
  the settings page is exactly what it broke" is.
- Neutral, because this does not reopen `COOKIE_SECURE`'s or
  `CABIN_MASTER_PASSPHRASE`'s presence in the environment — both already
  satisfy the same test (a cookie flag decided at request-handling setup
  time; a passphrase that unwraps the key the database's own secrets depend
  on) and are unaffected by this decision either way.

## More Information

- Spec 0022 FR-12 requires this ADR and names the three alternatives above
  that had to be addressed; AC-13 checks that it exists and follows
  `docs/adr/0000-template.md`.
- The original constraint: `cabin/settings.py` module docstring; spec 0001
  FR-2/FR-3 (`flag > env > default`, and the `settings` table as "the seed
  for UI-managed configuration"); spec 0014 FR-7 (README's configuration
  table as "the five env vars + what lives in the UI").
- `README.md:69-75` gains the two new rows as part of spec 0022 FR-15.
