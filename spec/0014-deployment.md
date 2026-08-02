# Spec 0014 — Deployment

## Context

cabin is feature-complete (specs 0001–0013) but only runs from a source
checkout. This spec makes it shippable: a small multi-arch container image, a
compose file, an Unraid template, and the GitHub Actions lanes that build and
publish to GHCR.

## User Stories

- As an Unraid user, I install cabin from a template, map one appdata folder,
  open the WebUI and complete the first-run wizard.
- As a docker-compose user, I copy the compose file, `docker compose up -d`,
  and have a CA.
- As the maintainer, pushing a tag produces a release with checksummed
  binaries-free artifacts and a multi-arch image; pushing to main refreshes a
  `:main` tag.

## Functional Requirements

- FR-1: `Dockerfile`, multi-stage:
  - builder: `python:3.13-slim` + `uv`, `uv sync --frozen --no-dev` into
    `/app/.venv`, then `uv build --wheel` and install the wheel into that venv
    (so no source tree ships)
  - runtime: `python:3.13-slim` pinned **by digest**, no build tools, no uv;
    copy only the venv; `USER 65532:65532` (nonroot, created in the image);
    `VOLUME /data`; `ENV DATA_DIR=/data PORT=8080`; `EXPOSE 8080`;
    `HEALTHCHECK` hitting `/healthz` with python's stdlib (no curl/wget
    dependency); `ENTRYPOINT ["cabin"]`.
  - `.dockerignore` excluding tests, docs, .git, caches.
  - Target: ≤ 250 MB uncompressed for the amd64 image; measure and record the
    actual size in the PR/changelog.
- FR-2: `docker-compose.yml` at the repo root: image
  `ghcr.io/nofuturekid/cabin:latest`, `./data:/data`, `8080:8080`, restart
  unless-stopped, the optional env vars commented (COOKIE_SECURE,
  CABIN_MASTER_PASSPHRASE, CABIN_DB_URL), plus a commented-out Postgres
  service showing the alternative.
- FR-3: `deploy/unraid/cabin.xml` following the step-ui-ng template shape:
  Name/Repository/Registry/Support/Project/Overview/Category
  (`Network:Management Security:`), `WebUI http://[IP]:[PORT:8080]/`,
  TemplateURL + Icon raw.githubusercontent URLs, `ExtraParams --user 99:100`
  (Unraid appdata ownership) with the explanatory comment, Config entries for
  the port, `/data` (with a BACK THIS UP warning naming secret.key), and the
  optional env vars (COOKIE_SECURE, CABIN_MASTER_PASSPHRASE masked).
- FR-4: `.github/workflows/release.yml`: on published release (and
  workflow_dispatch) build and push multi-arch (linux/amd64, linux/arm64)
  via buildx + QEMU to `ghcr.io/nofuturekid/cabin`, tagged with the release
  tag, plus `:latest` for stable releases and `:beta` for prereleases.
  `permissions: packages: write, contents: read`. Use the GITHUB_TOKEN, no
  external secrets.
- FR-5: `.github/workflows/main.yml`: on push to main (paths-ignore for docs)
  and workflow_dispatch, build and push the moving `:main` tag,
  `concurrency: group: main-build, cancel-in-progress: true`.
- FR-6: Version stamping: the image and the running app report the release
  version. `cabin.__version__` currently comes from package metadata, so pass
  the tag into the build (`--build-arg VERSION=`) and have the build write it
  into the wheel's version (or set an env var the app prefers) — pick ONE
  mechanism, keep `/healthz` and the UI footer consistent, and document it.
- FR-7: README rewrite: what cabin is, feature list (UI, REST, ACME with all
  three challenge types + EAB, MCP, CRL), quick start (docker compose and
  Unraid), configuration table (the five env vars + what lives in the UI),
  a security note (back up /data, protect secret.key, use a passphrase, put
  TLS in front), and a link to `spec/` + `docs/adr/`.
- FR-8: A smoke test that the built image actually works: a Make target
  (`make docker-smoke`) that builds the image, runs it with an empty data
  dir, waits for `/healthz` to return ok, checks the version matches, and
  stops it. Run it manually before merging (CI building images on PRs is out
  of scope).

## Acceptance Criteria

- AC-1: `docker build .` succeeds; the resulting image runs as uid 65532,
  has no `uv`/compiler in it, and `docker run --rm <img> --help` works.
- AC-2: Starting with an empty mounted `/data` creates the DB + secret.key
  with the right permissions and `/healthz` returns `{"status":"ok",...}`;
  restarting keeps the data.
- AC-3: The image size is recorded and under the target.
- AC-4: `docker compose up -d` from the repo root yields a reachable UI at
  :8080 with the first-run wizard.
- AC-5: The Unraid XML parses as XML and every Config entry has
  Name/Target/Default/Type; the `--user 99:100` scenario works (run the image
  with that uid/gid against a 99:100-owned host dir).
- AC-6: `make docker-smoke` passes end-to-end.
- AC-7: The workflows are accepted by GitHub (a real run is green — "parsed ≠
  accepted"): the main lane pushes `:main`, and a prerelease tag pushes
  `:beta` (verify at least the main lane for real).
- AC-8: README instructions are followed verbatim by the smoke test where
  they overlap (compose file path, env var names).

## Test list

Mostly out-of-band (docker/CI), so the pytest suite gains only:
test_healthz_reports_version (already exists — extend to assert the version
mechanism from FR-6), test_dockerfile_and_compose_reference_the_same_image,
test_unraid_template_is_valid_xml_and_complete.
The rest are the Make target and the CI runs.

## Out of Scope

Helm charts, Kubernetes manifests, systemd units, SBOM/signing (cosign),
automated image scanning, CI-built images on pull requests, Postgres
integration testing in CI, ARM32.
