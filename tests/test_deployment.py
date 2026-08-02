"""Spec 0014: the deployment artefacts have to stay in step with each other.

Everything else about the image is verified out of band (`make docker-smoke`
and the release lanes). What is worth a unit test is the part that silently
rots: a compose file pointing at one image while the Unraid template and the
workflows point at another, a template Unraid refuses to import, or a release
build that stops stamping the version into the wheel.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

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
