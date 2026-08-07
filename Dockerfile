# syntax=docker/dockerfile:1

# Spec 0014 FR-1. Two stages: the builder has uv and the source tree, the
# runtime has neither -- only the virtualenv the builder produced.
#
# The base is pinned by digest (python:3.13-slim = 3.13.14-slim-trixie) so a
# rebuild of the same commit resolves to the same bytes. It is a multi-arch
# index digest, so the same pin works for linux/amd64 and linux/arm64.
ARG PYTHON_IMAGE=python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

FROM ${PYTHON_IMAGE} AS builder

# uv comes from its own published image rather than pip, pinned by digest to
# the same version this repo's uv_build backend is locked to (0.12.1).
COPY --from=ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded /uv /usr/local/bin/uv

ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /src

# Spec 0014 FR-6: the release version is stamped into the wheel's metadata,
# because that is where cabin.__version__ (and therefore /healthz and the UI
# footer) reads it from -- importlib.metadata.version("cabin"). Empty means
# "plain source build", which keeps the version declared in pyproject.toml.
ARG VERSION=""

# Dependencies before source: this layer only changes when the lockfile does.
# --no-install-project keeps cabin itself out of the venv for now; it goes in
# as a built wheel below, so no source tree ships in the final image.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN if [ -n "${VERSION}" ]; then uv version --frozen "${VERSION}"; fi \
    && uv build --wheel --out-dir /tmp/dist \
    && uv pip install --python /app/.venv --no-deps /tmp/dist/*.whl


FROM ${PYTHON_IMAGE} AS runtime

ARG VERSION=""
LABEL org.opencontainers.image.title="cabin" \
      org.opencontainers.image.description="All-in-one internal CA: web UI, REST API, ACME server, MCP" \
      org.opencontainers.image.source="https://github.com/nofuturekid/cabin" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# A fixed nonroot uid/gid, so a bind-mounted host directory can be chowned to
# a known number. Unraid ignores this and runs the image as 99:100 instead
# (see deploy/unraid/cabin.xml) -- which works because nothing outside /data
# is written at runtime.
RUN groupadd --system --gid 65532 nonroot \
    && useradd --system --uid 65532 --gid 65532 --home-dir /home/nonroot \
       --create-home --shell /usr/sbin/nologin nonroot \
    && mkdir -p /data \
    && chown 65532:65532 /data

# Root-owned and world-readable on purpose: the runtime user only ever needs
# to read and execute it. A site-packages the app itself can write to would
# hand any code execution bug durable persistence -- in a container that
# holds the CA's private keys.
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    PORT=8080

VOLUME /data
EXPOSE 8080
USER 65532:65532

# stdlib only -- the image has no curl and no wget, and adding one just for
# the healthcheck would grow it for nothing.
#
# Spec 0022 FR-15: $PORT speaks TLS once CABIN_TLS is on, so the probe has to
# pick its scheme from the same flag cabin itself reads, with verification
# off -- stage 1 is self-signed by definition and this is a liveness check
# against 127.0.0.1, not a trust decision.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os,ssl,urllib.request,sys; tls=os.environ.get('CABIN_TLS','').strip().lower() in ('true','1'); scheme='https' if tls else 'http'; ctx=ssl._create_unverified_context() if tls else None; sys.exit(0 if urllib.request.urlopen('%s://127.0.0.1:%s/healthz' % (scheme, os.environ.get('PORT','8080')), timeout=3, context=ctx).status == 200 else 1)"]

ENTRYPOINT ["cabin"]
