from pathlib import Path

import pytest

from cabin.config import Config, ConfigError


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
