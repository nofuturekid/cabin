import sqlite3
import stat
import tomllib
from importlib.metadata import version
from pathlib import Path

from fastapi.testclient import TestClient

from cabin.app import create_app
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.web import templates


def make_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


def test_startup_creates_and_migrates_db(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    with TestClient(create_app(cfg)):
        pass

    assert stat.S_IMODE(cfg.data_dir.stat().st_mode) == 0o700
    db_file = cfg.data_dir / "cabin.db"
    assert db_file.exists()
    con = sqlite3.connect(db_file)
    try:
        rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    finally:
        con.close()
    tables = {name for (name,) in rows}
    assert {"alembic_version", "settings"} <= tables


def test_startup_idempotent(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    for _ in range(2):
        with TestClient(create_app(cfg)):
            pass


def test_healthz_ok(tmp_path: Path) -> None:
    """Spec 0014 FR-6: one version, and it comes from package metadata.

    The container build stamps the release version into the wheel it installs
    (`ARG VERSION` -> `uv version`), so `importlib.metadata` is the single
    source of truth -- there is no environment override that could let
    /healthz and the UI drift apart, and a plain source checkout
    reports what pyproject.toml declares.
    """
    declared = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    expected = declared["project"]["version"]

    with TestClient(create_app(make_config(tmp_path))) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": version("cabin")}
    assert resp.json()["version"] == expected
    assert templates.env.globals["version"] == expected


def test_app_state_has_secret_store(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    app = create_app(cfg)
    with TestClient(app):
        store = app.state.secrets
        assert isinstance(store, SecretStore)
        assert store.unseal(store.seal(b"hello")) == b"hello"
