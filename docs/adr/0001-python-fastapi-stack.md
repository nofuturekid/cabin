# 0001. Build cabin in Python on FastAPI, with an own ACME server

- Status: accepted
- Date: 2026-08-01
- Deciders: maintainer

## Context and Problem Statement

cabin is an all-in-one internal CA: one container providing web UI, REST API,
ACME v2 server, direct issuance and CSR signing. The predecessor setup
(step-ca + step-ui-ng, two containers, Go) is being replaced. The main
architectural fork was language/engine: Go with the embeddable
smallstep/certificates library versus Python with a self-built ACME layer.

## Decision Drivers

- Maintainer preference for the Python ecosystem (FastAPI, FastMCP).
- License hygiene: no GPL code in an MIT project.
- Small image, one container, SQLite-first, Unraid-friendly.
- ACME interop with real clients (certbot, acme.sh, Traefik, Caddy) is a
  hard requirement.

## Considered Options

- Go + smallstep/certificates embedded (Caddy's acme_server pattern)
- Go with a fully self-built RFC 8555 layer
- Python: FastAPI + Jinja2/htmx + pyca/cryptography + self-built ACME server

## Decision Outcome

Chosen option: **Python/FastAPI**, accepting the trade-off knowingly: research
(2026-08) found no production-grade, license-clean, framework-neutral ACME
_server_ library in Python — django-ca and acme2certifier are GPLv3 and
architecturally coupled — so the RFC 8555 state machine (JWS/nonces, accounts,
orders, authorizations, the three challenge validators, EAB) is built in-house
on josepy (JWS/JWK) and pyca/cryptography. The X.509 side (issuance, CSR, CRL)
is fully covered by pyca/cryptography and is _easier_ than in Go.

Stack details:

- **FastAPI + Jinja2 + htmx** for UI and API in one framework. FastHTML was
  rejected: it is a complete ASGI framework itself; running it next to FastAPI
  duplicates routing layers.
- **FastMCP (PrefectHQ, 3.x)** mounted at `/mcp` (ASGI sub-app).
- **SQLAlchemy 2.x sync + Alembic**, SQLite default, PostgreSQL optional.
- **Image**: `python:3.13-slim` multi-stage via uv (not Alpine — musl breaks
  prebuilt `cryptography` wheels), target ≤150 MB, amd64/arm64, GHCR.

### Consequences

- Good, because the CA/X.509/CRL core rides on the mature pyca/cryptography.
- Good, because UI, API, ACME, MCP live in one framework and one process.
- Bad, because the ACME server is the largest self-built, security-critical
  component (est. 4–8 person-weeks) with ongoing client-interop maintenance —
  mitigated by a hard interop gate (certbot + acme.sh over all three
  challenge types) before v1.
- Bad, because the image is ~10× a comparable Go binary (~100–150 MB vs
  ~10–15 MB) — accepted for an internal infra tool.
- Neutral: GPLv3 projects (django-ca, acme2certifier) serve as behavioral
  references only; code must never be copied or translated.

## More Information

- Research: plan file `ich-haette-gern-eine-sleepy-island.md` (2026-08-01),
  workflow wf_7c8cdaa7-f60.
- Process/deployment patterns are inherited from step-ui-ng (SDD/TDD, MADR,
  CI/release lanes, Unraid template); see its `docs/adr/` for the originals.
