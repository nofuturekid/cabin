"""Live-process tests for `cabin.server` (spec 0022 FR-1, FR-2, FR-7): the
process cabin starts on its own, without `uvicorn.run`.

`TestClient` never opens a socket, so none of what belongs here can be
asserted against it: whether `SIGTERM` actually reaches and stops *two*
listeners in one process (FR-2), whether the plaintext listener only starts
once the main application's lifespan has populated `app.state` (FR-7), and
whether TLS off still means exactly one plaintext server and no
`DATA_DIR/tls` (FR-1's own stated acceptance criterion). These need a real
`cabin` process on a real socket -- `tests/live_server.py` is that harness;
see its module docstring for why subprocess, not a thread.

**Two tests below cannot pass yet, and that is expected.**
`cabin.tls.TlsManager` is still the Phase-0 skeleton: `ensure_current` does
nothing and loads no certificate, so a `CABIN_TLS=true` child never
completes a TLS handshake and `live_cabin` never reports it ready -- every
TLS-on test here times out at `live_server._READY_TIMEOUT` (15s), not at
the assertion it exists to make. Verified directly: starting `cabin` by
hand with `CABIN_TLS=true` and attempting a handshake against it today
raises `ssl.SSLEOFError`, because the live `SSLContext` `_build_servers`
attaches has no certificate loaded into it yet. This is a statement about
`cabin.tls` (FR-3/FR-4/FR-6, out of this file's scope), not about `run`'s
own supervision or startup ordering, which is what each such test's
docstring says explicitly.
"""

import asyncio
import os
import re
import signal
from pathlib import Path

import pytest
from live_server import LiveClient, live_cabin, plain_get

import cabin.server as server_mod
from cabin.app import create_app
from cabin.config import Config
from cabin.server import _build_servers
from cabin.tls import TlsManager

#: Fixed port numbers for the unit tests below: `_build_servers` only
#: constructs `uvicorn.Config`/`uvicorn.Server` objects and never binds a
#: socket, so there is nothing here for a parallel test run to collide on.
_UNIT_PORT = 18080
_UNIT_HTTP_PORT = 18081


def test_build_servers_without_tls_constructs_exactly_one_server(tmp_path: Path) -> None:
    """AC-4's counter-check / AC-9's "exactly one application Server",
    asserted directly on the constructed objects rather than inferred from
    a live process -- so a worker pool added later fails here first, not
    only in the slower live test below."""
    data_dir = tmp_path / "data"
    cfg = Config(port=_UNIT_PORT, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")
    app = create_app(cfg)

    servers = _build_servers(cfg, app, None)

    assert len(servers) == 1
    assert servers[0].config.port == _UNIT_PORT


def test_build_servers_with_tls_constructs_two_servers(tmp_path: Path) -> None:
    """FR-10: with TLS on, a second `uvicorn.Server` exists for
    `config.http_port`, alongside the primary one on `config.port` -- fast
    and socket-free, ahead of the live proof that it is actually served."""
    data_dir = tmp_path / "data"
    cfg = Config(
        port=_UNIT_PORT,
        http_port=_UNIT_HTTP_PORT,
        tls=True,
        data_dir=data_dir,
        db_url=f"sqlite:///{data_dir}/cabin.db",
    )
    tls = TlsManager(cfg.data_dir)
    app = create_app(cfg, tls=tls)

    servers = _build_servers(cfg, app, tls)

    assert len(servers) == 2
    assert {server.config.port for server in servers} == {_UNIT_PORT, _UNIT_HTTP_PORT}


def test_run_without_tls_starts_one_plaintext_server(tmp_path: Path) -> None:
    """FR-1's own stated acceptance criterion: with TLS off, this changes
    nothing observable -- one plaintext server on `config.port`, and no
    second listener at all."""
    with live_cabin(data_dir=tmp_path / "instance") as handle:
        resp = plain_get("127.0.0.1", handle.port, "/healthz")
        assert resp.status == 200

        # The negative half: nothing was ever asked to listen on the
        # second port, so a connection to it must simply be refused.
        try:
            plain_get("127.0.0.1", handle.http_port, "/healthz", timeout=1.0)
        except OSError:
            pass
        else:
            raise AssertionError("a second listener answered with TLS off")


def test_run_without_tls_creates_no_tls_directory(tmp_path: Path) -> None:
    """FR-1's counter-check: no `DATA_DIR/tls` at all when TLS is off."""
    data_dir = tmp_path / "instance"
    with live_cabin(data_dir=data_dir) as handle:
        assert plain_get("127.0.0.1", handle.port, "/healthz").status == 200
        assert not (data_dir / "tls").exists()


def test_plaintext_listener_reaches_working_database_immediately(tmp_path: Path) -> None:
    """FR-7: the plaintext listener has no lifespan of its own and cannot
    reach the database until the main app's lifespan has run; `run` waits
    for `server.started` before starting the plaintext listener at all.
    Proved on the very first request after startup, against a real socket:
    a clean, business-logic 404 for an id nothing has created yet -- not a
    500 from a database or secret store the second listener never got a
    working handle to, which is what an unguarded ordering bug looks like.
    A listener that binds but answers 500 because its dependencies are
    missing is worse than one that does not exist at all.

    Blocked today (module docstring): `live_cabin(tls=True)` never reports
    ready because `TlsManager` loads no certificate yet.
    """
    with live_cabin(data_dir=tmp_path / "instance", tls=True) as handle:
        # Positive control: the main application is genuinely serving.
        with LiveClient("127.0.0.1", handle.port) as main:
            assert main.get("/healthz").status_code == 200

        resp = plain_get("127.0.0.1", handle.http_port, "/crl/999999")
        assert resp.status == 404
        assert resp.header("location") is None


def test_sigterm_stops_both_listeners(tmp_path: Path) -> None:
    """AC-16: one `SIGTERM`, sent to the real process, stops the TLS
    listener *and* the plaintext one -- within a bound tight enough that
    "one of them was merely killed later by the container's `SIGKILL`"
    would fail it. `uvicorn.Server.serve()` installs its own `SIGTERM`
    handler with `signal.signal` and offers no opt-out in this uvicorn
    version, so whichever of the two servers registers last would
    otherwise win the signal and leave the other running until the
    container's grace period expires -- FR-2 exists to stop that, and
    sending a real signal to a real process is the only way to measure it.

    Blocked today (module docstring): `live_cabin(tls=True)` never reports
    ready because `TlsManager` loads no certificate yet.
    """
    with live_cabin(data_dir=tmp_path / "instance", tls=True) as handle:
        # Positive control: both listeners are actually up before the signal.
        with LiveClient("127.0.0.1", handle.port) as main:
            assert main.get("/healthz").status_code == 200
        assert plain_get("127.0.0.1", handle.http_port, "/crl/1").status == 404

        os.kill(handle.pid, signal.SIGTERM)
        # Raises subprocess.TimeoutExpired -- a correct test failure -- if
        # either server was left running for the other to outlive.
        handle.proc.wait(timeout=8.0)

        for port in (handle.port, handle.http_port):
            try:
                plain_get("127.0.0.1", port, "/healthz", timeout=1.0)
            except OSError:
                continue
            raise AssertionError(f"port {port} still answers after SIGTERM")


class _StubServer:
    """A bare stand-in for `uvicorn.Server`: no socket, no ASGI lifespan, no
    signal handling of its own -- only the two attributes `cabin.server._serve`
    itself reads and writes (`started`, `should_exit`) and a `serve()` coroutine
    shaped like uvicorn's own main loop (poll `should_exit` until told to stop,
    or -- for the one standing in for "a signal reached this server" -- return
    immediately). Used to drive `_serve` with uvicorn's own SIGTERM handling and
    `capture_signals()` relay completely out of the picture, so what remains
    under test is only `_serve`'s own cross-wiring.
    """

    def __init__(self, *, finish_immediately: bool) -> None:
        self.started = True
        self.should_exit = False
        self._finish_immediately = finish_immediately

    async def serve(self) -> None:
        if self._finish_immediately:
            return
        while not self.should_exit:
            await asyncio.sleep(0.005)


def test_serve_sets_should_exit_on_other_servers_when_one_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unit-level proof of `_serve`'s own cross-wiring (module docstring,
    trap 1): when any one server's `serve()` returns, `_serve` itself must
    set `should_exit = True` on every OTHER server, rather than relying on
    uvicorn's SIGTERM handling to relay the signal on its own.

    `test_sigterm_stops_both_listeners` above cannot tell this mechanism
    apart from its absence: `uvicorn.Server.capture_signals()` restores the
    previous SIGTERM handler and re-raises the captured signal once
    `serve()` returns, so the signal reaches the *process* again and stops
    the other listener too -- true whether or not `cabin.server` does
    anything at all. That test is still worth having (it is the only proof
    a real SIGTERM actually reaches a real process running both listeners),
    but it stays green even if `_serve`'s own `for server in servers:
    server.should_exit = True` / `should_exit.set()` sequence is deleted
    outright, because uvicorn's relay alone is enough to stop both.

    This test removes that relay from the picture entirely: `_build_servers`
    is monkeypatched to return two `_StubServer`s instead of real
    `uvicorn.Server` instances, so nothing here ever installs a signal
    handler, and the only thing that can stop `stub_b` is `_serve` itself
    setting `stub_b.should_exit = True`. `stub_a` stands in for "a server
    whose `serve()` returned for any reason" (a caught signal, among
    others) by simply returning right away. If `_serve`'s cross-wiring were
    deleted, `stub_b` would poll `should_exit` forever, the final
    `asyncio.wait(tasks)` inside `_serve` would never resolve, and
    `asyncio.wait_for` below would raise `TimeoutError` -- a real failure,
    not a false negative -- rather than this test staying green either way.
    """
    stub_a = _StubServer(finish_immediately=True)
    stub_b = _StubServer(finish_immediately=False)
    monkeypatch.setattr(server_mod, "_build_servers", lambda config, app, tls: [stub_a, stub_b])

    data_dir = tmp_path / "data"
    cfg = Config(port=_UNIT_PORT, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")

    asyncio.run(asyncio.wait_for(server_mod._serve(cfg), timeout=5))

    assert stub_b.should_exit is True


def test_multi_worker_with_tls_refuses_to_start(tmp_path: Path) -> None:
    """FR-8/AC-9: a real child started with `WEB_CONCURRENCY=2` and TLS on
    must never reach a listening socket at all -- this is the actual defect
    FR-8 exists to prevent, so the test drives a real subprocess rather than
    calling a validation function directly.

    `live_server._wait_ready` checks `proc.poll()` on every iteration
    *before* attempting a connection, so a child that exits during startup
    surfaces as a `TimeoutError` naming its exit code and its captured
    stdout/stderr (`live_cabin`'s child runs with stderr merged into
    stdout) -- that message is the evidence this test inspects: a non-zero
    exit, reached quickly rather than at the 15s readiness timeout, whose
    text names the certificate swap as the reason. A plausible wrong
    implementation -- one that merely logs a warning and starts anyway, or
    validates `WEB_CONCURRENCY` without checking `config.tls` -- would
    leave the child answering `/healthz`, and `live_cabin` would return a
    working handle instead of raising, which is exactly what the final
    `pytest.raises` block below is there to catch.
    """
    with (
        pytest.raises(TimeoutError) as exc_info,
        live_cabin(data_dir=tmp_path / "instance", tls=True, env={"WEB_CONCURRENCY": "2"}),
    ):
        pass  # pragma: no cover -- reaching this body is itself a failure

    message = str(exc_info.value)
    assert "exited during startup" in message
    match = re.search(r"\(code (-?\d+)\)", message)
    assert match is not None, message
    assert int(match.group(1)) != 0
    assert "certificate" in message.lower()
    assert "WEB_CONCURRENCY" in message


def test_multi_worker_without_tls_starts(tmp_path: Path) -> None:
    """FR-8's counter-check (AC-9): the identical `WEB_CONCURRENCY=2` does
    not stop cabin from starting when TLS is off -- `run` never hands a
    worker count to anything that would spawn a second process either way,
    so there is nothing for FR-8 to refuse, and an operator not using
    cabin's TLS must not be obstructed by a guard that exists for it."""
    with live_cabin(
        data_dir=tmp_path / "instance", tls=False, env={"WEB_CONCURRENCY": "2"}
    ) as handle:
        assert plain_get("127.0.0.1", handle.port, "/healthz").status == 200
