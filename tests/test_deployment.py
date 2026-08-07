"""Spec 0014: the deployment artefacts have to stay in step with each other.

Everything else about the image is verified out of band (`make docker-smoke`
and the release lanes). What is worth a unit test is the part that silently
rots: a compose file pointing at one image while the Unraid template and the
workflows point at another, a template Unraid refuses to import, or a release
build that stops stamping the version into the wheel.
"""

import ipaddress
import os
import re
import ssl
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/nofuturekid/cabin"

DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
UNRAID_TEMPLATE = REPO_ROOT / "deploy" / "unraid" / "cabin.xml"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def test_dockerfile_and_compose_reference_the_same_image() -> None:
    """FR-1/2/3/4/5: one image name, and one digest-pinned base to build it."""
    dockerfile = DOCKERFILE.read_text()
    base = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", dockerfile, re.MULTILINE)
    assert base is not None, "the base image must be a single ARG both stages share"
    assert re.fullmatch(r"python:3\.13-slim@sha256:[0-9a-f]{64}", base.group(1)), (
        f"the runtime base must be pinned by digest, got {base.group(1)!r}"
    )
    assert re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE) == [
        "${PYTHON_IMAGE}",
        "${PYTHON_IMAGE}",
    ], "builder and runtime must be the same pinned base"

    compose = COMPOSE_FILE.read_text()
    images = re.findall(r"^\s+image:\s*(\S+)\s*$", compose, re.MULTILINE)
    assert images == [f"{IMAGE}:latest"]

    unraid = ET.parse(UNRAID_TEMPLATE).getroot()
    assert unraid.findtext("Repository") == f"{IMAGE}:latest"

    for workflow in ("main.yml", "release.yml"):
        assert f"IMAGE: {IMAGE}\n" in (WORKFLOWS / workflow).read_text(), workflow


def test_unraid_template_is_valid_xml_and_complete() -> None:
    """FR-3/AC-5: Unraid only imports a template it can read completely."""
    root = ET.parse(UNRAID_TEMPLATE).getroot()
    assert root.tag == "Container"

    required = {
        "Name": "cabin",
        "Category": "Network:Management Security:",
        "WebUI": "http://[IP]:[PORT:8080]/",
        # Unraid appdata belongs to nobody:users, and cabin needs no
        # capability beyond writing there.
        "ExtraParams": "--user 99:100 --security-opt no-new-privileges:true --cap-drop ALL",
    }
    for tag, expected in required.items():
        assert root.findtext(tag) == expected, tag
    for tag in ("Registry", "Support", "Project", "Overview"):
        assert (root.findtext(tag) or "").strip(), tag
    for tag in ("TemplateURL", "Icon"):
        url = root.findtext(tag) or ""
        assert url.startswith("https://raw.githubusercontent.com/nofuturekid/cabin/"), tag

    configs = root.findall("Config")
    for config in configs:
        for attribute in ("Name", "Target", "Default", "Type"):
            assert attribute in config.attrib, f"{config.get('Name')} misses {attribute}"

    by_target = {config.get("Target"): config for config in configs}
    assert by_target["8080"].get("Type") == "Port"
    data = by_target["/data"]
    assert data.get("Type") == "Path"
    # The one thing a user cannot recover from a backup they never took.
    assert "secret.key" in (data.get("Description") or "")
    # Optional, so Unraid must not block the install on them -- and the
    # passphrase must not be readable over someone's shoulder.
    assert by_target["COOKIE_SECURE"].get("Required") == "false"
    assert by_target["CABIN_MASTER_PASSPHRASE"].get("Mask") == "true"


def test_release_build_stamps_the_version_into_the_wheel() -> None:
    """FR-6: the release version reaches the app as package metadata.

    cabin.__version__ is importlib.metadata.version("cabin") and nothing
    else, so the only way the image can report a release version is for the
    build to write it into the wheel it installs. Drop either half and every
    published image would quietly report the pyproject version instead.
    """
    dockerfile = DOCKERFILE.read_text()
    assert re.search(r"^ARG VERSION=\"\"$", dockerfile, re.MULTILINE)

    # The whole chain, in order: rewrite the project version, build a wheel
    # from it, and install that same wheel into the environment the runtime
    # stage copies. Lose the last step and the venv keeps whatever `uv sync`
    # left there, so the stamp would never reach the image.
    chain = re.search(
        r'uv version --frozen "\$\{VERSION\}".*'
        r"uv build --wheel --out-dir (?P<dist>\S+).*"
        r"uv pip install --python (?P<venv>\S+) --no-deps (?P=dist)/\*\.whl",
        dockerfile,
        re.DOTALL,
    )
    assert chain is not None, "the version must reach the wheel the runtime installs"
    venv = chain.group("venv")
    assert f"UV_PROJECT_ENVIRONMENT={venv}" in dockerfile
    assert f"COPY --from=builder {venv} {venv}" in dockerfile
    # ... and cabin must not already be in that venv from the dependency
    # sync, or the wheel would only ever be a second opinion.
    assert "--no-install-project" in dockerfile

    for workflow in ("main.yml", "release.yml"):
        text = (WORKFLOWS / workflow).read_text()
        assert "VERSION=${{ steps.meta.outputs.version }}" in text, workflow


# --- Spec 0022 FR-12/AC-13: the ADR the deviation requires ------------------

ADR_TEMPLATE = REPO_ROOT / "docs" / "adr" / "0000-template.md"
ADR_0002 = REPO_ROOT / "docs" / "adr" / "0002-tls-environment-variables.md"


def test_adr_0002_exists_and_follows_template() -> None:
    """AC-13: the deliverable here *is* the document, which is the one case
    where asserting its presence is the point. It must carry the template's
    headings, and its "Considered Options" must name the three alternatives
    FR-12 requires be addressed: a single combined variable, deriving the
    plaintext port as PORT + 1, and a settings-table row."""
    assert ADR_0002.is_file(), "spec 0022 FR-12 requires this ADR to exist"
    text = ADR_0002.read_text()

    template_headings = re.findall(r"^#{2,3} (.+)$", ADR_TEMPLATE.read_text(), re.MULTILINE)
    adr_headings = re.findall(r"^#{2,3} (.+)$", text, re.MULTILINE)
    for heading in template_headings:
        assert heading in adr_headings, heading

    considered = re.search(r"## Considered Options\n(.*?)\n##", text, re.DOTALL)
    assert considered is not None
    options = considered.group(1)
    assert re.search(r"combined environment variable", options, re.IGNORECASE), (
        "must record why a single combined environment variable was rejected"
    )
    assert re.search(r"PORT \+ 1", options), "must record why deriving PORT + 1 was rejected"
    assert re.search(r"settings.*table", options, re.IGNORECASE), (
        "must record why a settings-table row was rejected"
    )


# --- Spec 0022 FR-15: the HEALTHCHECK follows CABIN_TLS ---------------------
#
# The image is built only at release time (this suite runs natively), so
# these tests do not build it. What they do instead: pull the exact
# `python -c` one-liner the Dockerfile ships as its HEALTHCHECK and execute
# it -- unmodified -- against a real /healthz listener, plain and TLS, on an
# ephemeral loopback port. That is the difference between "the string
# 'https' appears in the Dockerfile" and "the probe cabin ships actually
# reaches a TLS listener", which is the property FR-15 asks for.


class _HealthzHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b'{"status": "ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence: a test's output is the assertion, not the access log."""


def _self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """A throwaway self-signed cert for 127.0.0.1 -- exactly the shape of
    cabin's own stage-1 material, which is why FR-15 disables verification
    for the probe rather than pinning a root."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "healthz-cert.pem"
    key_file = tmp_path / "healthz-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@contextmanager
def _healthz_server(*, tls_files: tuple[Path, Path] | None) -> Iterator[int]:
    """A real /healthz listener on an ephemeral loopback port -- plain HTTP,
    or TLS when `tls_files` is given."""
    server = HTTPServer(("127.0.0.1", 0), _HealthzHandler)
    if tls_files is not None:
        cert_file, key_file = tls_files
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _healthcheck_code() -> str:
    """The exact `python -c` one-liner the image runs as its HEALTHCHECK,
    pulled straight from the Dockerfile -- so a test that executes it can
    never drift from what actually ships."""
    match = re.search(r'CMD \["python", "-c", "(?P<code>.*)"\]', DOCKERFILE.read_text())
    assert match is not None, "HEALTHCHECK must run a `python -c` one-liner"
    return match.group("code")


def _run_healthcheck(port: int, *, tls: bool) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.pop("CABIN_TLS", None)
    env["PORT"] = str(port)
    if tls:
        env["CABIN_TLS"] = "true"
    return subprocess.run(
        [sys.executable, "-c", _healthcheck_code()],
        env=env,
        capture_output=True,
        timeout=10,
    )


def test_healthcheck_probe_succeeds_over_plain_http_without_tls() -> None:
    """FR-15 counter-check: with CABIN_TLS unset the probe still works
    exactly as it does today."""
    with _healthz_server(tls_files=None) as port:
        result = _run_healthcheck(port, tls=False)
    assert result.returncode == 0, result.stderr


def test_healthcheck_probe_succeeds_over_https_with_tls(tmp_path: Path) -> None:
    """FR-15: `$PORT` speaks TLS once CABIN_TLS is on, so the probe must
    speak HTTPS with certificate verification disabled -- stage 1 is
    self-signed by definition and this is a liveness check against
    127.0.0.1, not a trust decision."""
    with _healthz_server(tls_files=_self_signed_cert(tmp_path)) as port:
        result = _run_healthcheck(port, tls=True)
    assert result.returncode == 0, result.stderr


def test_healthcheck_probe_fails_when_tls_flag_does_not_match_the_listener() -> None:
    """Counter-check: CABIN_TLS=true against a plaintext listener must fail
    -- proving the probe actually switches scheme when CABIN_TLS is on
    rather than ignoring it and always speaking the same protocol, which
    would make the two tests above pass for the wrong reason."""
    with _healthz_server(tls_files=None) as port:
        result = _run_healthcheck(port, tls=True)
    assert result.returncode != 0
