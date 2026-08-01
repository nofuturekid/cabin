import sqlite3
import stat
from importlib.metadata import version
from pathlib import Path

from fastapi.testclient import TestClient

from cabin.app import create_app
from cabin.config import Config


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
    with TestClient(create_app(make_config(tmp_path))) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": version("cabin")}
