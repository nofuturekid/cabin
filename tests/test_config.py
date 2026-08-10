import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cabin.app import create_app
from cabin.config import Config, ConfigError, ensure_data_dir_writable
from cabin.sessions import get_session
from cabin.settings import BASE_URL, get_setting
from cabin.store import create_session_factory


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


# --- Spec 0022 FR-12/AC-13: the two new environment variables ---------------
#
# Precedence for both is env-over-default, like every existing knob in this
# module -- neither gets a CLI flag (the Interface Contract defines none),
# so there is no flag-over-env case to pin down here, only env-over-default
# and loud rejection of a bad value.


def test_config_defaults_tls_off() -> None:
    cfg = Config.load(argv=[], env={})
    assert cfg.tls is False
    assert cfg.http_port == 8081


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
def test_config_tls_env_parsing(value: str, expected: bool) -> None:
    cfg = Config.load(argv=[], env={"CABIN_TLS": value})
    assert cfg.tls is expected


def test_config_http_port_env_override() -> None:
    cfg = Config.load(argv=[], env={"CABIN_HTTP_PORT": "9091"})
    assert cfg.http_port == 9091


@pytest.mark.parametrize(
    ("env",),
    [
        ({"CABIN_HTTP_PORT": "not-a-number"},),
        ({"CABIN_HTTP_PORT": "0"},),
        ({"CABIN_HTTP_PORT": "70000"},),
    ],
)
def test_config_invalid_http_port_rejected(env: dict[str, str]) -> None:
    """AC-13: CABIN_HTTP_PORT is rejected the way PORT already is -- a value
    out of range must not silently fall back to the default, or an operator
    ends up serving a CRL nobody can fetch on a port nobody configured."""
    with pytest.raises(ConfigError):
        Config.load(argv=[], env=env)


def test_config_http_port_equal_to_port_allowed_without_tls() -> None:
    """Interface Contract: the equal-ports refusal only fires when TLS is
    on. CABIN_HTTP_PORT is otherwise unused (FR-12), so an accidental
    collision with PORT must not break an instance that never turns TLS
    on."""
    cfg = Config.load(argv=[], env={"PORT": "9443", "CABIN_HTTP_PORT": "9443"})
    assert cfg.port == cfg.http_port == 9443


def test_config_rejects_http_port_equal_to_port_with_tls() -> None:
    """AC-13: with TLS on, CABIN_HTTP_PORT == PORT is a ConfigError naming
    both -- the two listeners would otherwise be indistinguishable, which is
    exactly how an operator ends up serving a CRL nobody can fetch."""
    with pytest.raises(ConfigError) as excinfo:
        Config.load(argv=[], env={"CABIN_TLS": "true", "PORT": "9443", "CABIN_HTTP_PORT": "9443"})
    message = str(excinfo.value)
    assert "PORT" in message
    assert "CABIN_HTTP_PORT" in message
    assert "9443" in message


# --- Spec 0022 FR-11/AC-12: cookie security follows TLS ---------------------


def _setup_superadmin(
    client: TestClient, username: str = "alice", password: str = "correcthorse1"
) -> str:
    """Complete first-run setup, which logs the new superadmin in
    immediately -- returns the raw `Set-Cookie` header from that response,
    which is what AC-12 has to be measured against, not `config.cookie_secure`."""
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303
    return resp.headers["set-cookie"]


def test_session_cookie_secure_on_response_with_tls(tmp_path: Path) -> None:
    """FR-11/AC-12: with TLS on, the session cookie carries `Secure` on the
    wire. Built through `Config.load`, not a direct `Config(tls=True, ...)`
    call -- the forcing happens inside `Config.load` (Interface Contract:
    "forces cookie_secure=True when tls is true"), and `Config` is a frozen
    dataclass with no `__post_init__`, so a hand-built Config would silently
    skip the forcing and this test would pass for the wrong reason."""
    data_dir = tmp_path / "data"
    cfg = Config.load(argv=[], env={"CABIN_TLS": "true", "DATA_DIR": str(data_dir)})
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        set_cookie = _setup_superadmin(client)
    assert "secure" in set_cookie.lower()


@pytest.mark.parametrize("cookie_secure_env", ["false", "0", ""])
def test_session_cookie_secure_override_with_tls(tmp_path: Path, cookie_secure_env: str) -> None:
    """FR-11: an explicit COOKIE_SECURE=false does not win over TLS -- cabin
    is the TLS terminator, so there is no deployment in which the operator
    is right and cabin is wrong."""
    data_dir = tmp_path / "data"
    cfg = Config.load(
        argv=[],
        env={"CABIN_TLS": "true", "COOKIE_SECURE": cookie_secure_env, "DATA_DIR": str(data_dir)},
    )
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        set_cookie = _setup_superadmin(client)
    assert "secure" in set_cookie.lower()


def test_session_cookie_not_secure_without_tls(tmp_path: Path) -> None:
    """Counter-check: without TLS the cookie is left unmarked. Without this
    half, the two assertions above would only prove that `Secure` is always
    set, regardless of TLS -- which is not what FR-11 claims."""
    data_dir = tmp_path / "data"
    cfg = Config.load(argv=[], env={"DATA_DIR": str(data_dir)})
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        set_cookie = _setup_superadmin(client)
    assert "secure" not in set_cookie.lower()


# --- Spec 0022 FR-13/AC-14: a ported base URL is refused while TLS is on ----


def _csrf_for(cfg: Config, client: TestClient) -> str:
    db = create_session_factory(cfg.db_url)()
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _stored_base_url(cfg: Config) -> str | None:
    db = create_session_factory(cfg.db_url)()
    try:
        return get_setting(db, BASE_URL)
    finally:
        db.close()


def test_settings_rejects_ported_base_url_with_tls(tmp_path: Path) -> None:
    """FR-13/AC-14: `public_http_origin` keeps any explicit port other than
    `:443` (spec 0017 AC-9), and with TLS on that port is the *TLS* port --
    so `base_url=https://ca.example.lan:8443` would bake
    `http://ca.example.lan:8443/crl/...` into every certificate: a
    plaintext URL pointing at the TLS listener, unfetchable. The route must
    refuse it with a 400 and leave the stored value untouched.

    Also checks that the same client, in the same session, accepts the same
    host *without* a port -- proving the 400 is about the port and not a
    blanket refusal of everything while TLS is on."""
    data_dir = tmp_path / "data"
    cfg = Config(
        port=8080,
        data_dir=data_dir,
        db_url=f"sqlite:///{data_dir}/cabin.db",
        tls=True,
        http_port=8081,
    )
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        _setup_superadmin(client)

        resp = client.post(
            "/settings",
            data={"base_url": "https://ca.example.lan:8443", "csrf_token": _csrf_for(cfg, client)},
        )
        assert resp.status_code == 400
        assert _stored_base_url(cfg) in (None, "")

        resp = client.post(
            "/settings",
            data={"base_url": "https://ca.example.lan", "csrf_token": _csrf_for(cfg, client)},
        )
        assert resp.status_code == 303
    assert _stored_base_url(cfg) == "https://ca.example.lan"


def test_settings_accepts_ported_base_url_without_tls(tmp_path: Path) -> None:
    """Counter-check for FR-13: with TLS off, the port survives into the
    stored value unchanged (spec 0017 AC-9 is unaffected by spec 0022).
    Without this half, the test above would prove nothing about the TLS
    condition -- it could just as well be that a ported base URL is always
    rejected."""
    data_dir = tmp_path / "data"
    cfg = Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=False)
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        _setup_superadmin(client)
        resp = client.post(
            "/settings",
            data={"base_url": "https://ca.example.lan:8443", "csrf_token": _csrf_for(cfg, client)},
        )
        assert resp.status_code == 303
    assert _stored_base_url(cfg) == "https://ca.example.lan:8443"
