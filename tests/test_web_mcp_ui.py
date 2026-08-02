"""Spec 0013 FR-4/FR-6: the operator's side of the MCP server -- the switch
on /settings, the endpoint address, and the command they paste into their
client."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cabin.app import create_app
from cabin.config import Config
from cabin.mcp import MCP_PATH
from cabin.sessions import get_session
from cabin.settings import MCP_ENABLED, get_flag
from cabin.store import create_session_factory

BASE = "https://ca.example.org"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _csrf(client: TestClient, cfg: Config) -> str:
    db = create_session_factory(cfg.db_url)()
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup(client: TestClient, cfg: Config) -> str:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )
    return _csrf(client, cfg)


def test_settings_page_toggles_mcp_and_shows_the_snippet(client: TestClient, cfg: Config) -> None:
    """FR-4/FR-6: the switch, the endpoint URL, and a ready-to-paste
    ``claude mcp add`` line that names the token requirement."""
    csrf = _setup(client, cfg)

    page = client.get("/settings")
    assert "mcp_enabled" in page.text
    assert client.post(MCP_PATH, json={}).status_code == 404

    resp = client.post(
        "/settings",
        data={"base_url": BASE, "mcp_enabled": "on", "csrf_token": csrf},
    )
    assert resp.status_code == 303, resp.text

    db = create_session_factory(cfg.db_url)()
    try:
        assert get_flag(db, MCP_ENABLED) is True
    finally:
        db.close()

    page = client.get("/settings")
    assert f"{BASE}{MCP_PATH}" in page.text
    assert "claude mcp add --transport http cabin" in page.text
    assert "Authorization: Bearer" in page.text
    assert "/tokens" in page.text


def test_settings_refuses_to_enable_mcp_without_a_base_url(client: TestClient, cfg: Config) -> None:
    """FR-4: MCP publishes its own address, so it needs one -- the same
    reason ACME does, and the same answer."""
    csrf = _setup(client, cfg)

    resp = client.post(
        "/settings",
        data={"base_url": "", "mcp_enabled": "on", "csrf_token": csrf},
    )

    assert resp.status_code == 400, resp.text
    assert "base URL" in resp.text
    db = create_session_factory(cfg.db_url)()
    try:
        assert get_flag(db, MCP_ENABLED) is False
    finally:
        db.close()
    assert client.post(MCP_PATH, json={}).status_code == 404


def test_settings_page_says_mcp_is_off(client: TestClient, cfg: Config) -> None:
    """While it is off the page still explains what the switch is for, but it
    hands out no address -- there is nothing listening at one."""
    _setup(client, cfg)
    page = client.get("/settings")
    assert "MCP" in page.text
    assert "claude mcp add" not in page.text
