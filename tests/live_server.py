"""Real `cabin` processes on real sockets -- the harness spec 0022 is
tested through.

Every test in this project so far drives `create_app(cfg)` in process
through Starlette's `TestClient`: no socket is ever opened, no `SSLContext`
is ever built, and `cabin.cli`/`cli.main`/`uvicorn.run` have zero call sites
anywhere under `tests/`. None of that can exercise a TLS handshake, a
process exit code, or `SIGTERM` -- those need a real OS process.

**Subprocess, not thread. This is not a style preference.**
`uvicorn.Server.capture_signals` is a documented no-op off the main thread
(`uvicorn/server.py:323-327` in the installed 0.52.0):

    def capture_signals(self):
        if threading.current_thread() is not threading.main_thread():
            yield
            return

A thread-based harness would therefore silently skip the exact mechanism
`cabin.server`'s FR-2 supervision exists to test, and a SIGTERM test would
go green without proving anything. This module offers subprocess mode only;
not offering the wrong tool is the mitigation.

**The child's SQLite file is never opened from here, and must never be.**
`cabin.store` sets no journal mode, so a reader opening the file while the
child holds a write lock intermittently gets "database is locked" --
under load, on CI only, and never on a laptop. Every state change a test
needs must go through the child's own HTTP surface (see `LiveClient`);
every assertion is read off the wire or off `DATA_DIR/tls/` (see
`plant_tls_material`).

This module is a helper library, not a test file: it asserts nothing
itself. Its own self-test lives in `tests/test_live_server.py`.
"""

import atexit
import contextlib
import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx2
import pytest
from cryptography import x509

from cabin.secrets import SecretStore
from cabin.tls import cert_path, sealed_key_path

_READY_POLL_INTERVAL = 0.025
_READY_TIMEOUT = 15.0
_SHUTDOWN_TIMEOUT = 10.0

#: Every child this process has started, so the `atexit` hook below can
#: clean up what a `finally` never got to run -- pytest itself being
#: killed, or a fixture raising during its own teardown.
_LIVE_CHILDREN: "list[subprocess.Popen[bytes]]" = []


def free_port() -> int:
    """An ephemeral port nothing is listening on right now.

    Same shape as `challenge_servers.closed_port()`, which honestly
    documents its own bind-then-release race. 0022 needs two ports per
    instance across roughly a dozen instances in a run, so the race is
    correspondingly more likely -- but it is `_wait_ready` below, not this
    function, that is actually responsible for telling "still starting"
    apart from "the port was taken by someone else in the meantime".
    """
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


@dataclass
class LiveCabin:
    """A running cabin child process."""

    port: int
    http_port: int
    data_dir: Path
    pid: int
    proc: "subprocess.Popen[bytes]"
    log: list[str] = field(default_factory=list)


def _resolve_cabin_argv() -> list[str]:
    """The installed console script if there is one (the same way an
    operator actually runs cabin), else the module form."""
    venv_bin = Path(sys.executable).parent / "cabin"
    if venv_bin.exists():
        return [str(venv_bin)]
    return [sys.executable, "-m", "cabin.cli"]


def _drain(proc: "subprocess.Popen[bytes]", log: list[str]) -> None:
    """Daemon reader thread. Not a nicety: an undrained pipe deadlocks the
    child once its stdout buffer fills, and uvicorn logs on every request.
    This is also what a failing test needs to show -- the startup message,
    FR-11's override line, FR-3's memfd-fallback line."""
    assert proc.stdout is not None
    for raw in proc.stdout:
        log.append(raw.decode("utf-8", errors="replace").rstrip("\n"))


def _tcp_connect_ok(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _tls_handshake_ok(port: int, timeout: float = 1.0) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname="127.0.0.1"),
        ):
            return True
    except OSError:
        return False


def _wait_ready(handle: LiveCabin, *, tls: bool) -> None:
    """Poll, never sleep. Three checks, in order:

    (a) the process is still alive -- if not, fail *immediately* with the
        captured log, otherwise every startup bug in this spec presents as
        an indistinguishable timeout;
    (b) with TLS on, a handshake to `port` completes (off, a plain TCP
        connect to `port`);
    (c) with TLS on, a TCP connect to `http_port` also succeeds.

    `cabin.server._serve` starts the plaintext listener only after the main
    server's lifespan has populated `app.state` and only calls it "started"
    once its socket is bound (spec 0022 FR-7), so (b)+(c) together are a
    sound readiness signal that needs no test-only hook in production code.
    """
    deadline = time.monotonic() + _READY_TIMEOUT
    while time.monotonic() < deadline:
        if handle.proc.poll() is not None:
            raise TimeoutError(
                f"cabin (pid {handle.pid}) exited during startup "
                f"(code {handle.proc.returncode}):\n" + "\n".join(handle.log)
            )
        primary_up = _tls_handshake_ok(handle.port) if tls else _tcp_connect_ok(handle.port)
        if primary_up and (not tls or _tcp_connect_ok(handle.http_port)):
            return
        time.sleep(_READY_POLL_INTERVAL)
    raise TimeoutError(
        f"cabin (pid {handle.pid}) did not become ready within {_READY_TIMEOUT}s:\n"
        + "\n".join(handle.log)
    )


def _terminate(proc: "subprocess.Popen[bytes]") -> None:
    """`terminate()`, wait, then `kill()` -- never just one or the other."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=_SHUTDOWN_TIMEOUT)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    proc.wait(timeout=_SHUTDOWN_TIMEOUT)


@atexit.register
def _reap_all() -> None:
    """Backstop for the `live_cabin` `finally`: it does not run if pytest
    itself is killed mid-test."""
    for proc in list(_LIVE_CHILDREN):
        _terminate(proc)


@contextlib.contextmanager
def live_cabin(
    *,
    data_dir: Path,
    tls: bool = False,
    env: Mapping[str, str] | None = None,
) -> Iterator[LiveCabin]:
    """Start a real `cabin` process on fresh ephemeral ports and yield a
    handle to it. Subprocess mode only -- see the module docstring.

    The child's environment is built from scratch, not inherited: `PORT`,
    `CABIN_HTTP_PORT`, `CABIN_TLS`, `DATA_DIR` and `PATH` only, plus
    whatever `env` overrides or adds. In particular `CABIN_MASTER_PASSPHRASE`
    is never set here -- a test that needs one asks for it explicitly, so
    that every other live test isn't paying scrypt's cost on every boot for
    nothing.

    Teardown is unconditional and happens even if the caller never actually
    used the handle: `terminate()`, wait, then `kill()`, so a failed
    assertion inside the `with` block can never leave the child or its
    ports behind for the next test.
    """
    port = free_port()
    http_port = free_port()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    child_env = {
        "PORT": str(port),
        "CABIN_HTTP_PORT": str(http_port),
        "CABIN_TLS": "true" if tls else "false",
        "DATA_DIR": str(data_dir),
        "PATH": os.environ.get("PATH", ""),
    }
    if env:
        child_env.update(env)

    proc = subprocess.Popen(
        _resolve_cabin_argv(),
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        # A killed child must not leave a grandchild holding a port open.
        start_new_session=True,
    )
    _LIVE_CHILDREN.append(proc)
    log: list[str] = []
    reader = threading.Thread(target=_drain, args=(proc, log), daemon=True)
    reader.start()
    handle = LiveCabin(
        port=port, http_port=http_port, data_dir=data_dir, pid=proc.pid, proc=proc, log=log
    )
    try:
        _wait_ready(handle, tls=tls)
        yield handle
    finally:
        _terminate(proc)
        reader.join(timeout=5)
        if proc in _LIVE_CHILDREN:
            _LIVE_CHILDREN.remove(proc)


def tls_peer_certificate(host: str, port: int, *, timeout: float = 5.0) -> x509.Certificate:
    """Read the certificate a fresh TLS connection to `host:port` actually
    presents. The primitive AC-1, AC-5, AC-6 and AC-7 all read their
    evidence from -- `getpeercert(binary_form=True)`, parsed, never
    inferred from the absence of an exception. `CERT_NONE`: these tests
    establish identity for themselves, they do not delegate trust to the
    client.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    assert der is not None
    return x509.load_der_x509_certificate(der)


@dataclass
class TlsKeepalive:
    """One TLS connection held open across a certificate swap (AC-2): the
    certificate it reports is fixed at the handshake that already
    happened, by construction."""

    sock: ssl.SSLSocket
    certificate: x509.Certificate

    def request(self, path: str = "/healthz", host: str = "127.0.0.1") -> bytes:
        """A further HTTP/1.1 request on the same, already-open connection
        -- what AC-2 uses to prove the swap did not break it."""
        self.sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
        )
        return self.sock.recv(65536)


@contextlib.contextmanager
def tls_keepalive(host: str, port: int, *, timeout: float = 5.0) -> Iterator[TlsKeepalive]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    tls = context.wrap_socket(raw, server_hostname=host)
    try:
        der = tls.getpeercert(binary_form=True)
        assert der is not None
        yield TlsKeepalive(sock=tls, certificate=x509.load_der_x509_certificate(der))
    finally:
        tls.close()


@dataclass
class PlainResponse:
    """A response read off a bare `http.client` connection -- no redirect
    ever followed, every raw header visible."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


def plain_request(
    host: str, port: int, path: str, *, method: str = "GET", timeout: float = 5.0
) -> PlainResponse:
    """A bare `http.client` request to the plaintext PKI listener. AC-11's
    `Location` assertion must not depend on a higher-level client's
    `follow_redirects` default, so this never follows one."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        body = resp.read()
        return PlainResponse(status=resp.status, headers=resp.getheaders(), body=body)
    finally:
        conn.close()


def plain_get(host: str, port: int, path: str, *, timeout: float = 5.0) -> PlainResponse:
    return plain_request(host, port, path, method="GET", timeout=timeout)


def curl(*args: str, timeout: float = 10.0) -> "subprocess.CompletedProcess[bytes]":
    """Run `curl` with `args`, skipping the test if it is not installed.
    AC-3 names `curl` specifically; the skip guard is for a developer
    machine that lacks it, not for this one or ubuntu-latest, which both
    have it.
    """

    binary = shutil.which("curl")
    if binary is None:
        pytest.skip("curl is not installed")
    return subprocess.run([binary, *args], capture_output=True, timeout=timeout)


def plant_tls_material(
    data_dir: Path, secrets: SecretStore, cert_pem: bytes, key_pem: bytes
) -> None:
    """Write `cabin.crt` / `cabin.key.sealed` exactly as FR-3 would, before
    a child starts.

    This is the one helper that makes the renewal criteria testable without
    any clock machinery: "is this certificate inside the renewal window" is
    answered by planting material with a chosen `not_after` -- 10 days out,
    60 days out, already expired -- never by faking the clock. No frozen
    time, no monkeypatched `datetime`, and it works identically whether the
    check runs in process or across the subprocess boundary.
    """
    tls_dir = cert_path(data_dir).parent
    tls_dir.mkdir(mode=0o700, exist_ok=True, parents=True)
    cert_path(data_dir).write_bytes(cert_pem)
    cert_path(data_dir).chmod(0o600)
    sealed_key_path(data_dir).write_text(secrets.seal(key_pem))
    sealed_key_path(data_dir).chmod(0o600)


_CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]*)"')


class LiveClient:
    """An HTTPS driver for a running instance's own UI: first-run setup,
    login, and CSRF-guarded POSTs, all over the real TLS listener.

    `httpx2` (already a dependency), matching the rest of the project.
    `verify=False`: these tests establish the certificate's identity for
    themselves via `tls_peer_certificate`, they do not delegate trust to
    this client. Cookies persist across requests on the underlying
    `httpx2.Client`, the way a browser's would.
    """

    def __init__(self, host: str, port: int, *, timeout: float = 10.0) -> None:
        self._client = httpx2.Client(
            base_url=f"https://{host}:{port}", verify=False, timeout=timeout
        )

    def __enter__(self) -> "LiveClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get(self, path: str) -> httpx2.Response:
        return self._client.get(path)

    def post(self, path: str, data: dict[str, str]) -> httpx2.Response:
        return self._client.post(path, data=data)

    def csrf_token(self, path: str = "/") -> str:
        """Scrape `csrf_token` out of a rendered form. Never read off the
        child's database -- see the module docstring."""
        match = _CSRF_RE.search(self.get(path).text)
        if match is None:
            raise AssertionError(f"no csrf_token form field found on {path!r}")
        return match.group(1)

    def setup(self, username: str, password: str) -> httpx2.Response:
        """First-run setup: no CSRF token exists yet, because there is no
        session yet."""
        return self.post("/setup", {"username": username, "password": password})

    def login(self, username: str, password: str) -> httpx2.Response:
        return self.post("/login", {"username": username, "password": password})
