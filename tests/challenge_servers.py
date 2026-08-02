"""Real local servers for the spec-0011 validation tests.

Not a fixture module and not collected by pytest -- imported by
``test_acme_validation.py``, ``test_acme_challenges_api.py`` and
``test_acme_client_interop.py``.

The validators are network code, and mocking the network would only prove
that our idea of an HTTP client agrees with our idea of an HTTP server. So
these tests speak to a real ``http.server`` and a real TLS socket on an
ephemeral loopback port, and the one thing that *is* replaced is
:func:`cabin.acme.validation.targets.resolve` -- the single function that
turns an identifier into an address. That seam does two jobs at once: it
maps ``nas.lan`` onto the port a test server happens to have got, and it is
also what lets a test reach loopback at all, which the address policy of
FR-9 otherwise refuses.

Nothing here reaches outside 127.0.0.1.
"""

import datetime
import hashlib
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cabin.acme.validation import targets

#: What a route returns: HTTP status, body, extra headers.
Route = tuple[int, bytes, dict[str, str]]
#: A test's server-side logic: path -> response.
Router = Callable[[str], Route]

ACME_IDENTIFIER_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")


@dataclass
class HttpServer:
    port: int
    #: (path, Host header) of every request that arrived, in order -- what a
    #: test asserts the validator actually asked for.
    requests: list[tuple[str, str]] = field(default_factory=list)


def _handler_class(server: HttpServer, router: Router) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            server.requests.append((self.path, self.headers.get("Host", "")))
            status, body, headers = router(self.path)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            try:
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                # The validator hung up mid-body -- which is the *point* of
                # the oversized-response test, and not something a test
                # server should print a traceback about.
                return

        def log_message(self, fmt: str, *args: Any) -> None:
            """Silence: a test's output is the assertion, not the access log."""

    return Handler


@contextmanager
def http_server(router: Router) -> Iterator[HttpServer]:
    """A real HTTP server on an ephemeral loopback port."""
    server = HttpServer(port=0)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler_class(server, router))
    server.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def serves(body: bytes, *, path: str | None = None) -> Router:
    """The common case: one path with one body, 404 everywhere else."""

    def router(requested: str) -> Route:
        if path is None or requested == path:
            return 200, body, {}
        return 404, b"not found", {}

    return router


def closed_port() -> int:
    """A port nothing is listening on: bound to learn its number, then
    released. Racy in principle, reliable on a loopback interface in a test
    run -- and the alternative (a hard-coded port) is worse."""
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


def point_at(
    monkeypatch: pytest.MonkeyPatch,
    port: int,
    *,
    address: str = "127.0.0.1",
    only: str | None = None,
) -> None:
    """Aim an identifier at a local test server (see the module docstring).

    Replaces the one function the validators use to turn a name into an
    address, so the HTTP/TLS code under test is exercised unchanged --
    including the ``Host``/SNI it sends, which stays the identifier.

    ``only`` narrows the substitution to a single name and lets every other
    host through to the *real* :func:`targets.resolve`. That is what makes
    the redirect tests meaningful: the first hop reaches the test server,
    and a hop to any other name meets the actual address policy.
    """
    real = targets.resolve

    def fake_resolve(host: str, port_wanted: int, allow_private: bool) -> targets.Endpoint:
        if only is not None and host != only:
            return real(host, port_wanted, allow_private)
        return targets.Endpoint(host=host, address=address, port=port)

    monkeypatch.setattr(targets, "resolve", fake_resolve)


@contextmanager
def dripping_http_server(*, delay: float = 0.25, length: int = 4096) -> Iterator[HttpServer]:
    """A server that answers 200 and then dribbles the body out one byte at
    a time, forever as far as the client is concerned.

    The shape of a slow-loris: every individual read succeeds, so a per-read
    timeout never fires and only a budget for the whole attempt ends it.
    """
    server = HttpServer(port=0)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            server.requests.append((self.path, self.headers.get("Host", "")))
            self.send_response(200)
            self.send_header("Content-Length", str(length))
            self.end_headers()
            try:
                for _ in range(length):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(delay)
            except OSError:  # the validator gave up and closed the socket
                return

        def log_message(self, fmt: str, *args: Any) -> None:
            """Silence: a test's output is the assertion, not the access log."""

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@contextmanager
def silent_tls_listener() -> Iterator[int]:
    """A socket that accepts a connection and then never says anything.

    The TLS equivalent of the dripping server: the connect succeeds, the
    handshake never completes, and without a deadline the validator would
    wait for as long as the peer feels like.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port: int = listener.getsockname()[1]
    accepted: list[socket.socket] = []

    def serve() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            # Held, not closed: closing would give the client an answer.
            accepted.append(connection)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        for connection in accepted:
            connection.close()
        thread.join(timeout=5)


def acme_identifier_certificate(
    *,
    names: tuple[str, ...] = ("nas.lan",),
    key_authorization: str | None = None,
    critical: bool = True,
    with_extension: bool = True,
    tmp_path: Path,
) -> tuple[Path, Path]:
    """A self-signed tls-alpn-01 certificate (RFC 8737 3), written to disk
    because :meth:`ssl.SSLContext.load_cert_chain` reads files.

    The knobs are the failure modes AC-4 asks for: no extension, a
    non-critical one, the wrong digest (pass a different key authorization),
    and a certificate for the wrong name.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
    )
    if with_extension:
        digest = hashlib.sha256((key_authorization or "").encode("utf-8")).digest()
        builder = builder.add_extension(
            # RFC 8737 3: the extension value is a DER OCTET STRING wrapping
            # the digest -- 0x04, length 0x20, then the 32 bytes.
            x509.UnrecognizedExtension(ACME_IDENTIFIER_OID, b"\x04\x20" + digest),
            critical=critical,
        )
    certificate = builder.sign(key, hashes.SHA256())
    cert_file = tmp_path / f"{names[0]}-cert.pem"
    key_file = tmp_path / f"{names[0]}-key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@contextmanager
def tls_server(
    cert_file: Path,
    key_file: Path,
    *,
    alpn: tuple[str, ...] = ("acme-tls/1",),
) -> Iterator[int]:
    """A TLS listener on an ephemeral loopback port, offering ``alpn``.

    ``alpn=()`` is AC-4's "no ALPN negotiation": the handshake succeeds and
    the protocol does not, which is exactly the case a validator must not
    mistake for success.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    if alpn:
        context.set_alpn_protocols(list(alpn))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port: int = listener.getsockname()[1]
    stopping = threading.Event()

    def serve() -> None:
        while not stopping.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:  # the listener was closed underneath us
                return
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    # The client only wants the certificate; reading once
                    # keeps the handshake from being torn down too early.
                    tls.settimeout(2)
                    tls.recv(1)
            except OSError:
                pass
            finally:
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stopping.set()
        listener.close()
        thread.join(timeout=5)
