# cabin

**All-in-one internal CA** — a single container that provides a web UI, a REST
API, an ACME server (RFC 8555), direct certificate issuance, and CSR signing.

> **Status: pre-alpha.** Built spec-driven (see [`spec/`](spec/)) and
> test-first; architecture decisions live in [`docs/adr/`](docs/adr/).

## What this is

- **One process, one volume**: FastAPI app serving the UI (Jinja2 + htmx,
  server-rendered, no Node), the REST API (`/api/v1`, OpenAPI), the ACME v2
  endpoints (`/acme`), the CRL (`/crl`), and an MCP server (`/mcp`).
- **CA core** on [pyca/cryptography]: create a root + intermediate on first
  run, or import an existing CA. Sign CSRs and issue certificates directly
  from the UI/API — not just via ACME.
- **ACME server** (own implementation, no GPL code): `http-01`, `dns-01`,
  `tls-alpn-01`, External Account Binding.
- **SQLite by default** (single file in `/data`), PostgreSQL optional.
- Private keys encrypted at rest (AES-256-GCM); optional passphrase KEK via
  environment.
- Small image: `python:3.13-slim`, multi-stage, multi-arch (amd64/arm64),
  published to `ghcr.io/nofuturekid/cabin`.

[pyca/cryptography]: https://cryptography.io/

## Quick start (development)

```bash
uv sync            # install deps (incl. dev group)
uv run cabin       # start on http://localhost:8080, data in ./data
make check         # ruff + mypy + pytest
```

## For the implementing agent

Read [`AGENTS.md`](AGENTS.md) first. Work the specs in `spec/` in order,
test-first, one focused PR per spec.
