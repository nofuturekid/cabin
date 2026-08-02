import os
from pathlib import Path

import pytest

from cabin.config import Config, ConfigError, ensure_data_dir_writable


def test_config_defaults() -> None:
    cfg = Config.load(argv=[], env={})
    assert cfg.port == 8080
    assert cfg.data_dir == Path("data")
    assert cfg.db_url == "sqlite:///data/cabin.db"


def test_config_env_overrides_default() -> None:
    cfg = Config.load(argv=[], env={"PORT": "9000", "DATA_DIR": "/tmp/cabin-x"})
    assert cfg.port == 9000
    assert cfg.data_dir == Path("/tmp/cabin-x")
    assert cfg.db_url == "sqlite:////tmp/cabin-x/cabin.db"


def test_config_flag_overrides_env() -> None:
    cfg = Config.load(
        argv=["--port", "9001", "--data-dir", "/tmp/cabin-y"],
        env={"PORT": "9000", "DATA_DIR": "/tmp/cabin-x"},
    )
    assert cfg.port == 9001
    assert cfg.data_dir == Path("/tmp/cabin-y")


def test_config_db_url_env_wins_over_derived_sqlite_path() -> None:
    cfg = Config.load(argv=[], env={"CABIN_DB_URL": "postgresql+psycopg://u@h/db"})
    assert cfg.db_url == "postgresql+psycopg://u@h/db"


@pytest.mark.parametrize(
    ("argv", "env"),
    [
        ([], {"PORT": "not-a-number"}),
        ([], {"PORT": "0"}),
        (["--port", "70000"], {}),
    ],
)
def test_config_invalid_port_rejected(argv: list[str], env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Config.load(argv=argv, env=env)


def test_config_repr_hides_passphrase() -> None:
    cfg = Config.load(argv=[], env={"CABIN_MASTER_PASSPHRASE": "s3cr3t"})
    assert "s3cr3t" not in repr(cfg)


def test_config_cookie_secure_defaults_false() -> None:
    cfg = Config.load(argv=[], env={})
    assert cfg.cookie_secure is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("false", False),
        ("0", False),
        ("", False),
    ],
)
def test_config_cookie_secure_env_parsing(value: str, expected: bool) -> None:
    cfg = Config.load(argv=[], env={"COOKIE_SECURE": value})
    assert cfg.cookie_secure is expected


def test_ensure_data_dir_writable_creates_a_missing_directory(tmp_path: Path) -> None:
    data_dir = tmp_path / "nested" / "data"
    ensure_data_dir_writable(data_dir)
    assert data_dir.is_dir()


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes regardless of the mode bits")
def test_ensure_data_dir_writable_says_what_to_fix(tmp_path: Path) -> None:
    """The message has to carry the whole fix: an operator who mounted the
    wrong-owner volume sees this line and nothing else."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o500)

    with pytest.raises(ConfigError) as excinfo:
        ensure_data_dir_writable(data_dir)

    message = str(excinfo.value)
    assert str(data_dir) in message
    assert f"uid {os.geteuid()}:{os.getegid()}" in message
    assert f"chown -R {os.geteuid()}:{os.getegid()}" in message
