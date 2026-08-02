#!/usr/bin/env sh
# Spec 0014 FR-8: prove the built image actually serves cabin.
#
# Builds the image, starts it on an empty data directory, waits for /healthz,
# checks that the reported version is the one the build stamped in, and that
# the data directory came out with a database and a 0600 secret.key. Leaves
# nothing behind, including when it fails.
#
#   scripts/docker-smoke.sh
#   IMAGE=cabin:dev PORT=18080 VERSION=9.9.9 scripts/docker-smoke.sh
set -eu

IMAGE="${IMAGE:-cabin:smoke}"
PORT="${PORT:-18080}"
TIMEOUT="${TIMEOUT:-60}"

cd "$(dirname "$0")/.."

# FR-6: the version the build stamps into the wheel is the version the
# running app reports. The default carries a local segment pyproject.toml
# does not have, so the check below fails if the stamping ever silently
# becomes a no-op instead of passing on the version they share.
VERSION="${VERSION:-$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')+smoke}"

name="cabin-smoke-$$"
data_dir=""

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    if [ -n "$data_dir" ]; then
        rm -rf "$data_dir"
    fi
}
trap cleanup EXIT INT TERM

echo "==> building $IMAGE (VERSION=$VERSION)"
docker build --build-arg "VERSION=$VERSION" -t "$IMAGE" .

data_dir="$(mktemp -d)"
echo "==> starting $name on :$PORT with an empty $data_dir"
# As the invoking user rather than the image's 65532, both because a
# bind-mounted host directory belongs to that user and because it is the same
# "run me as some other uid" case Unraid creates with --user 99:100.
docker run -d --name "$name" \
    --user "$(id -u):$(id -g)" \
    -p "127.0.0.1:$PORT:8080" \
    -v "$data_dir:/data" \
    "$IMAGE" >/dev/null

echo "==> waiting for /healthz (up to ${TIMEOUT}s)"
i=0
while :; do
    rc=0
    python3 - "$PORT" "$VERSION" <<'PY' || rc=$?
import json
import sys
import urllib.request

port, expected = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as resp:
        body = json.load(resp)
except OSError:
    sys.exit(1)
if body != {"status": "ok", "version": expected}:
    print(f"unexpected /healthz payload: {body}", file=sys.stderr)
    sys.exit(2)
print(f"healthz: {body}")
PY
    if [ "$rc" -eq 0 ]; then
        break
    fi
    if [ "$rc" -ne 1 ]; then
        exit 1
    fi
    if [ -z "$(docker ps -q --filter "name=^${name}$")" ]; then
        echo "container exited before serving /healthz:" >&2
        docker logs "$name" >&2 || true
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -ge "$TIMEOUT" ]; then
        echo "timed out waiting for /healthz" >&2
        docker logs "$name" >&2 || true
        exit 1
    fi
    sleep 1
done

echo "==> checking the data directory"
[ -s "$data_dir/cabin.db" ] || { echo "no cabin.db in $data_dir" >&2; exit 1; }
mode="$(stat -c '%a' "$data_dir/secret.key" 2>/dev/null || stat -f '%Lp' "$data_dir/secret.key")"
[ "$mode" = "600" ] || { echo "secret.key has mode $mode, expected 600" >&2; exit 1; }

echo "==> ok"
