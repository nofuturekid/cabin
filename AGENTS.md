# AGENTS.md — how to work on cabin

cabin is built **Spec-Driven (SDD) + Test-Driven (TDD)**. This file is the
authoritative workflow; `CLAUDE.md` is a summary of it.

## Golden rules

1. **Spec first.** Work the specs in `spec/NNNN-*.md` in numeric order. If the
   next piece of work has no spec, write the spec first (same format: Context,
   User Stories, Functional Requirements, Data Model/Routes/UI, Acceptance
   Criteria as Given/When/Then, Test list, Out of Scope).
2. **Test first.** Red → green → refactor. Every functional requirement and
   acceptance criterion maps to at least one test.
3. **Small PRs.** 1 spec = 1 branch (`type/short-kebab`) = 1 PR against `main`.
   No merge without approval.
4. **ADRs.** Every non-trivial architecture decision gets a MADR record in
   `docs/adr/` (copy `0000-template.md`). Revisions supersede explicitly —
   never rewrite history. Only reserve an ADR number if you write it now.
5. **Conventional Commits**, minimalistic: `type(scope): imperative summary`,
   lowercase, ≤72 chars. Changelog entry under `[Unreleased]` per spec.
6. **SemVer pre-1.0**: bump the version only at releases.

## Architecture guardrails

- **No GPL code.** django-ca and acme2certifier (both GPLv3) may be consulted
  as _behavioral_ references for ACME only. Never copy or translate their code.
  Interop truth comes from RFC 8555/8737/7807 and real clients (certbot,
  acme.sh, Pebble's observable behavior).
- **Secrets never in plaintext.** Private keys and other secrets go through
  the secrets layer (AES-256-GCM, master key in `DATA_DIR/secret.key`,
  optional `CABIN_MASTER_PASSPHRASE` KEK).
- **Config precedence** flag > env > default, and only a handful of env vars
  (PORT, DATA_DIR, COOKIE_SECURE, CABIN_DB_URL, CABIN_MASTER_PASSPHRASE) —
  everything else is configured in the UI and stored in the DB.
- **No business logic in templates.** UI is Jinja2 + htmx partials,
  server-rendered; no Node toolchain, no SPA.
- **DB via SQLAlchemy 2.x (sync) + Alembic.** Migrations are applied
  programmatically at startup. SQLite is the default and must always work;
  PostgreSQL is optional and must not leak into SQLite-only code paths.
- **Mock ≠ real** (lesson from step-ui-ng ADR-0018): protocol behavior must be
  verified against real clients/instances before a spec is called done — for
  ACME that means certbot and acme.sh, not just unit tests.

## Verify before committing

```bash
make check   # ruff format --check + ruff check + mypy + pytest
```

CI (`.github/workflows/ci.yml`) runs the same checks; green CI on GitHub is
the acceptance bar, not a local run ("parsed ≠ accepted").
