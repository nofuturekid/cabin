# Spec 0001 — Foundation

## Context

Everything later (CA, ACME, UI) needs a booting app with configuration, a
database with migrations, a health endpoint, and CI. This spec delivers the
smallest runnable cabin: `uv run cabin` starts a server whose `/healthz`
answers, with the SQLite database created and migrated in `DATA_DIR`.

## User Stories

- As the operator, I start cabin with zero configuration and get a working
  instance with sensible defaults (port 8080, `./data`).
- As the operator, I override port/data dir via CLI flag or environment.
- As a developer, `make check` and CI tell me reliably whether the tree is
  healthy.

## Functional Requirements

- FR-1: `cabin` console script starts uvicorn serving the FastAPI app.
- FR-2: Configuration resolves **flag > env > default**:
  `--port` / `PORT` / 8080; `--data-dir` / `DATA_DIR` / `./data`.
  Invalid port values fail loudly at startup.
- FR-3: On startup, `DATA_DIR` is created (0700 if new) and Alembic migrations
  are applied programmatically to `DATA_DIR/cabin.db` (SQLite). A later
  `CABIN_DB_URL` (Postgres) must be able to reuse the same mechanism, but only
  SQLite is exercised in this spec.
- FR-4: `GET /healthz` returns 200 `{"status": "ok", "version": "<version>"}`
  without touching auth (none exists yet).
- FR-5: Version comes from package metadata (single source: pyproject).
- FR-6: CI runs ruff (format check + lint), mypy (strict), pytest on every PR
  and push to main.

## Data Model

Alembic revision 0001: table `schema_info` is _not_ needed (Alembic keeps its
own version table `alembic_version`). First real revision creates `settings`
(key TEXT PK, value TEXT NOT NULL) as the seed for UI-managed configuration.

## Routes

- `GET /healthz` → 200 JSON (FR-4)

## Acceptance Criteria

- AC-1: Given no env/flags, when the app factory runs, then config is
  port=8080, data_dir=./data.
- AC-2: Given `PORT=9000` env and flag `--port 9001`, when config resolves,
  then port=9001 (flag wins); given only env, port=9000.
- AC-3: Given an empty temp dir as DATA_DIR, when the app starts, then
  `cabin.db` exists and `alembic_version` + `settings` tables exist.
- AC-4: Given a running app, when `GET /healthz`, then 200 with status "ok"
  and the installed package version.
- AC-5: Given a second startup on the same DATA_DIR, then startup succeeds
  (migrations idempotent).
- AC-6: `make check` passes; the GitHub Actions `ci` workflow passes on the
  repository (platform-accepted, not just locally parsed).

## Test list

- test_config_defaults (AC-1)
- test_config_precedence_flag_over_env_over_default (AC-2)
- test_config_invalid_port_rejected (FR-2)
- test_startup_creates_and_migrates_db (AC-3)
- test_startup_idempotent (AC-5)
- test_healthz_ok (AC-4)

## Out of Scope

Auth, UI pages, CA logic, Postgres wiring (only the URL seam), Docker,
release workflows (spec 0014).
