# cabin

**All-in-one internal CA** — one small container that gives a homelab or a
small company its own certificate authority: a web UI, a REST API, an ACME v2
server, an MCP server, direct issuance, CSR signing, revocation and a CRL.

> **Status: pre-alpha.** Built spec-driven (see [`spec/`](spec/)) and
> test-first; architecture decisions live in [`docs/adr/`](docs/adr/).

## Features

- **Web UI** — server-rendered Jinja2 + htmx, no Node toolchain, no SPA. A
  first-run wizard creates the superadmin, then walks you through creating a
  root + intermediate CA (ECDSA P-256/P-384, RSA-4096 or Ed25519) or
  importing an existing one. Roles: superadmin, admin, viewer.
- **Certificates** — issue `server`/`client` leaves with a server-generated
  key or by signing a pasted CSR, browse and search the inventory, download
  the leaf, the chain, the private key or a password-protected **PKCS#12**
  bundle.
- **REST API** — `/api/v1`, bearer-token authentication, OpenAPI docs at
  [`/api/v1/docs`](http://localhost:8080/api/v1/docs).
- **ACME v2 server** (RFC 8555, own implementation) — directory at
  `/acme/directory`, all three challenge types (`http-01`, `dns-01`,
  `tls-alpn-01`) and External Account Binding. Verified against certbot and
  acme.sh, not just unit tests.
- **MCP server** — `/mcp` (streamable HTTP), six tools so an AI assistant can
  look at the CA and issue, sign or revoke certificates under an API token's
  role.
- **Revocation and CRL** — reason codes, a monotonic CRL number and a public
  `/crl` (DER) / `/crl.pem` that regenerates itself when stale.
- **Audit log** — who did what, from which front door (UI, API, ACME, MCP).
- **Secrets encrypted at rest** — AES-256-GCM, master key in
  `/data/secret.key`, optionally wrapped with a passphrase-derived KEK.
- **One container, one volume** — SQLite by default, `linux/amd64`
  (~216 MB uncompressed) and `linux/arm64` (~243 MB), running as a nonroot
  user with no capabilities.

## Quick start

### docker compose

```bash
curl -O https://raw.githubusercontent.com/nofuturekid/cabin/main/docker-compose.yml
mkdir -p data && sudo chown 65532:65532 data
docker compose up -d
```

The image runs as the nonroot uid 65532, so the bind-mounted `./data` has to
belong to it — otherwise docker creates the directory as root and cabin
cannot write its database. Then open <http://localhost:8080/> and complete the
first-run wizard.

### Unraid

Add this repository as a template source, or drop
[`deploy/unraid/cabin.xml`](deploy/unraid/cabin.xml) into
`/boot/config/plugins/dockerMan/templates-user/`. The template maps
`/mnt/user/appdata/cabin` to `/data` and runs the container as `99:100`
(`nobody:users`, the owner of appdata) via `--user 99:100`. Click the icon,
open the WebUI, complete the wizard.

## Configuration

Five environment variables, all optional. Everything else — CA, profiles,
base URL, ACME, MCP, users, tokens — is configured in the UI and stored in
the database. Flags (`--port`, `--data-dir`) beat environment variables,
which beat the defaults.

| Variable                  | Default                        | What it does                                                                                           |
| ------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `PORT`                    | `8080`                         | Listen port. One port serves the UI, the API, ACME, MCP and the CRL.                                   |
| `DATA_DIR`                | `data` (`/data` in the image)  | Holds `cabin.db` and `secret.key`.                                                                     |
| `CABIN_DB_URL`            | `sqlite:///$DATA_DIR/cabin.db` | SQLAlchemy URL. SQLite is the tested default; PostgreSQL needs a driver the image does not bundle yet. |
| `COOKIE_SECURE`           | `false`                        | Send session cookies only over HTTPS. Turn on behind a TLS proxy.                                      |
| `CABIN_MASTER_PASSPHRASE` | unset                          | Wraps the master key in `secret.key` with a scrypt-derived KEK. Set it **before** the first start.     |

The version cabin reports at `/healthz` and in the UI footer is the version of
the installed wheel: the release build stamps the git tag into it
(`docker build --build-arg VERSION=…`), and a plain source build reports what
`pyproject.toml` declares.

## Security notes

- **Back up `/data`.** `secret.key` encrypts every private key in the
  database. Lose it and the CA is gone; leak it and so is your CA.
- **`CABIN_MASTER_PASSPHRASE`** adds a passphrase-derived KEK around the
  master key, so a stolen `secret.key` alone is not enough. It cannot be
  added or changed after the first start without discarding the sealed keys.
- **Put TLS in front.** cabin speaks plain HTTP; terminate TLS in a reverse
  proxy and set `COOKIE_SECURE=true`. ACME `http-01` validation is outbound,
  so it works either way.
- **Do not expose it to the internet.** An internal CA is trusted by every
  machine that installs its root; treat the admin UI accordingly.

## Development

```bash
uv sync              # install deps (incl. dev group)
uv run cabin         # start on http://localhost:8080, data in ./data
make check           # ruff format --check, ruff check, mypy, pytest
make docker-smoke    # build the image and check it serves /healthz
```

Read [`AGENTS.md`](AGENTS.md) first if you are adding to cabin: the specs in
[`spec/`](spec/) are worked in order, test-first, one focused PR per spec.
Architecture decisions are recorded in [`docs/adr/`](docs/adr/).
