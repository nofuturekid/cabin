# Repository Guidelines (for Claude Code & other agents)

Authoritative workflow lives in [`AGENTS.md`](AGENTS.md). Summary:

## Project

**cabin** — all-in-one internal CA in Python: FastAPI + Jinja2/htmx UI,
REST API, own ACME v2 server (http-01/dns-01/tls-alpn-01, EAB), direct
issuance + CSR signing, CRL, MCP server. pyca/cryptography for X.509,
SQLAlchemy 2 (sync) + Alembic, SQLite default / Postgres optional,
secrets encrypted at rest. One container, `/data` volume.

## Verify before committing

- `make check` (ruff format --check, ruff check, mypy, pytest)

## Working conventions (IMPORTANT)

- **Conventional Commits** (minimalistic), single subject line.
- **One branch + PR per spec**, based on `main`; **no merge without approval**.
- **SemVer (pre-1.0)**: version bump only at releases; per spec add a
  `CHANGELOG.md` entry under `[Unreleased]`.
- **SDD/TDD**: spec → failing test → implement → refactor. See `spec/` and
  `docs/adr/`.
- **No GPL code** — django-ca/acme2certifier are behavioral references only.
