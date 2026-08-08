"""cabin's own TLS material, and the live `uvicorn.Config` it is loaded into
(spec 0022).

Three stages, one entry point (`TlsManager.ensure_current`): self-signed
before any CA exists (FR-4), a certificate from cabin's own CA the moment
one does (FR-6), swapped onto the live `uvicorn.Config.ssl` context without
a restart (the spike this spec is built on: `asyncio.sslproto.SSLProtocol`
holds a *reference* to the `SSLContext` and calls `wrap_bio()` on it fresh
per handshake, so mutating the context in place is picked up by every
connection opened afterwards).

**The key never touches a filesystem in the clear.** `cabin.crt` is a public
document, stored as PEM; `cabin.key.sealed` is the private key sealed with
the same AES-GCM `SecretStore` that protects every CA key (FR-3). The one
place the unsealed key exists as bytes is a `memfd_create` anonymous file
that OpenSSL reads through `/proc/self/fd/N` and that is closed the moment
`load_cert_chain` returns -- `load_into` is the only function in cabin that
ever holds one.

Nothing under `cabin/ca/` imports this module: it is a leaf that depends on
`ca`, `settings`, `secrets` and `audit`, never the other way around.
"""

import asyncio
import contextlib
import ipaddress
import logging
import os
import socket
import ssl
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from cabin import audit, issuer_grants
from cabin.audit import AuditAction
from cabin.ca import leaf
from cabin.ca.certs import Certificate, CertSource, issue_and_store
from cabin.ca.leaf import IssueError, Profile
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    UnknownIssuerError,
    active_issuers,
    chain_for,
)
from cabin.secrets import SecretsError, SecretStore
from cabin.settings import BASE_URL, TLS_ISSUER_ID, get_setting, set_setting

logger = logging.getLogger(__name__)

#: Spec 0022 Interface Contract: FR-9's issuance/renewal validity.
CERT_DAYS = 90
#: FR-9: renew once fewer than this many days remain.
RENEW_BEFORE = timedelta(days=30)
#: FR-9: the hourly background check's period. `run` passes this to
#: `renewal_loop`; a test passes milliseconds instead.
CHECK_INTERVAL = timedelta(hours=1)
#: FR-17's no-shorter-certificate rule: a renewal is only worth the row and
#: the sealed key it costs when it actually buys at least this much more
#: validity than what is already loaded. Without this, a bound issuer
#: running out clamps every reissue straight back inside the renewal
#: window, and an hourly loop adds thousands of rows and keys a year.
MIN_RENEWAL_GAIN = timedelta(days=1)

#: memfd_create's name -- cosmetic only, since the descriptor has no path
#: in any filesystem; it shows up in /proc/self/fd listings for debugging.
_MEMFD_NAME = "cabin-tls-key"


class TlsMode(StrEnum):
    """Which kind of certificate `TlsManager` currently has loaded."""

    self_signed = "self_signed"
    ca_issued = "ca_issued"


def cert_path(data_dir: Path) -> Path:
    """FR-3: the certificate, in the clear -- a public document."""
    return data_dir / "tls" / "cabin.crt"


def sealed_key_path(data_dir: Path) -> Path:
    """FR-3: the private key, sealed. There is no ``key_path``: no
    plaintext key file exists to have one."""
    return data_dir / "tls" / "cabin.key.sealed"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _spki(public_key: PublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _subject_cn(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names:
        return ""
    value = names[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to a temp name in ``path``'s own directory, chmod
    0600, then `os.replace` into place (FR-3) -- a crash mid-write cannot
    leave a half-written ``cabin.crt``/``cabin.key.sealed``. On any failure
    the temp file is removed rather than left behind, so a failed write
    never grows the directory to more than the two files FR-3 names.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.chmod(0o600)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_into(ctx: ssl.SSLContext, cert_path: Path, key_pem: bytes) -> None:
    """FR-3's memfd load -- the only function in cabin that ever holds an
    unsealed TLS key. ``key_pem`` is bytes rather than a path so no caller
    can pass this a filename to begin with.

    `os.memfd_create` returns a file that lives only in anonymous memory:
    no name in any filesystem, not even a tmpfs one, unlinked by
    construction. `MFD_CLOEXEC` keeps it out of any child process, and
    `/proc/self/fd/N` is a path `ssl.SSLContext.load_cert_chain`'s
    `BIO_new_file` can open that resolves to that descriptor and nothing
    else. The descriptor is closed in a `finally`, which frees the pages;
    OpenSSL has already read what it needs by the time `load_cert_chain`
    returns.

    Falls back to a `0600` file inside ``cert_path``'s directory, unlinked
    immediately after `load_cert_chain` returns, only when `memfd_create`
    itself raises (an old kernel, a seccomp profile, `/proc` not mounted) --
    logged, because that narrows a permanent exposure to a window of
    microseconds and an operator should know it happened.
    """
    try:
        fd = os.memfd_create(_MEMFD_NAME, os.MFD_CLOEXEC)
    except OSError:
        logger.info(
            "os.memfd_create is unavailable; falling back to an immediately-"
            "unlinked file for cabin's TLS key (spec 0022 FR-3)"
        )
        _load_via_unlinked_file(ctx, cert_path, key_pem)
        return
    try:
        os.write(fd, key_pem)
        ctx.load_cert_chain(str(cert_path), f"/proc/self/fd/{fd}")
    finally:
        os.close(fd)


def _load_via_unlinked_file(ctx: ssl.SSLContext, cert_path: Path, key_pem: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=cert_path.parent, prefix=".cabin-tls-key-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        os.write(fd, key_pem)
        os.close(fd)
        tmp_path.chmod(0o600)
        ctx.load_cert_chain(str(cert_path), str(tmp_path))
    finally:
        tmp_path.unlink(missing_ok=True)


def resolve_tls_issuer(db: Session) -> "CACertificate | None":
    """FR-17: which issuer signs cabin's own certificate, decided once and
    written down rather than re-derived on every call.

    ``None`` means "no CA-issued certificate right now", never an
    exception -- every ambiguous or broken binding keeps the instance
    serving what it already has (`TlsManager.ensure_current` is what acts
    on that, not this function).
    """
    bound = get_setting(db, TLS_ISSUER_ID)
    if bound:
        try:
            bound_id = int(bound)
        except ValueError:
            return None
        row = db.get(CACertificate, bound_id)
        if row is not None and row.kind == "intermediate" and row.status == "active":
            return row
        return None
    issuers = active_issuers(db)
    if len(issuers) == 1:
        # Persisted immediately, at the moment the answer is unambiguous --
        # so a second issuer created later cannot change it retroactively.
        set_setting(db, TLS_ISSUER_ID, str(issuers[0].id))
        return issuers[0]
    return None


async def renewal_loop(interval: timedelta, tick: Callable[[], None], stop: asyncio.Event) -> None:
    """FR-9's scheduler: call ``tick`` every ``interval`` until ``stop`` is
    set. Every exception ``tick`` raises is caught, logged and swallowed --
    a transient database error or a briefly-unusable issuer must cost one
    cycle, not the scheduler, because a loop that dies silently after one
    bad tick leaves the certificate expiring underneath a process that
    still looks healthy.

    Sleeps on ``stop.wait()`` rather than a bare `asyncio.sleep`, so setting
    ``stop`` wakes the loop immediately instead of waiting out whatever is
    left of the current interval -- FR-2's shutdown must not be delayed by
    this loop.
    """
    while not stop.is_set():
        try:
            tick()
        except Exception:
            logger.exception("cabin's TLS renewal tick failed; will retry next interval")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval.total_seconds())


@dataclass(frozen=True)
class _CurrentMaterial:
    """What `TlsManager._load_current` found on disk -- parsed, verified to
    be a matching cert/key pair, and never the raw bytes."""

    cert: x509.Certificate
    key_pem: bytes
    mode: TlsMode
    subject_cn: str
    sans: list[str]
    not_after: datetime


class TlsManager:
    """Owns cabin's own TLS material and the `uvicorn.Config` it is loaded
    into. The full surface is spec 0022's Interface Contract.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        #: What is currently loaded; `None` before the first
        #: `ensure_current`. Read by FR-14's templates via `app.state.tls`.
        self.mode: TlsMode | None = None
        #: Spec 0018 FR-15: the message of the last swallowed issuance
        #: failure, `None` at construction and after any `ensure_current`
        #: that returned `True`. Read, not raised -- the renewal loop's
        #: behaviour does not change; this only makes a terminal failure
        #: visible to `_tls_banner` and the audit log instead of scrolling
        #: away in a log line.
        self.last_error: str | None = None
        self._uvicorn_config: uvicorn.Config | None = None
        #: FR-6: request paths run in Starlette's threadpool while
        #: handshakes run on the event loop, and two concurrent triggers
        #: must not interleave two writes to the same two files, nor two
        #: overlapping unsealed keys in memory.
        self._lock = threading.Lock()

    def attach(self, uvicorn_config: uvicorn.Config) -> None:
        """Hand over the `Config` whose `.ssl` `ensure_current` will
        mutate. `Config.ssl` does not exist until `Server._serve()` calls
        `Config.load()` (FR-7); `ensure_current` copes with that by reading
        the attribute with `getattr`, never by assuming it is there."""
        self._uvicorn_config = uvicorn_config

    def wanted_names(self, db: Session) -> tuple[str, list[str]]:
        """FR-5: the subject CN and SAN list cabin's own certificate should
        cover right now.

        `base_url` configured -> its host, with the port stripped (a port
        is a property of the listener, not of a name); an IP literal host
        becomes an IP SAN. `base_url` empty -> the fallback cabin starts
        with before it has been configured at all: the OS hostname,
        ``localhost``, ``127.0.0.1`` and ``::1``.
        """
        base_url = get_setting(db, BASE_URL) or ""
        if base_url:
            host = urlsplit(base_url).hostname or ""
            if _is_ip_literal(host):
                return host, [f"IP:{host}"]
            return host, [f"DNS:{host}"]
        hostname = socket.gethostname()
        sans = [f"DNS:{hostname}", "DNS:localhost", "IP:127.0.0.1", "IP:::1"]
        return hostname, list(dict.fromkeys(sans))

    def _load_current(self, secrets: SecretStore) -> "_CurrentMaterial | None":
        """The certificate and key currently on disk, or `None` when there
        is nothing there, it doesn't parse, it doesn't unseal, or the two
        halves don't match (AC-17: discarded and reissued, never fatal --
        a mismatched pair from a crash between the two `os.replace` calls,
        a truncated file, or a key sealed under a master key that has since
        changed all land here rather than killing the process).
        """
        crt_path = cert_path(self.data_dir)
        key_path = sealed_key_path(self.data_dir)
        if not crt_path.exists() or not key_path.exists():
            return None
        try:
            cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
        except ValueError:
            logger.warning("cabin.crt does not parse; discarding and reissuing")
            return None
        try:
            key_pem = secrets.unseal(key_path.read_text())
        except SecretsError:
            logger.warning("cabin.key.sealed could not be unsealed; discarding and reissuing")
            return None
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError):
            logger.warning(
                "cabin.key.sealed does not unseal to a private key; discarding and reissuing"
            )
            return None
        if not hasattr(key, "public_key") or _spki(key.public_key()) != _spki(cert.public_key()):
            logger.warning(
                "cabin.crt and cabin.key.sealed are a mismatched pair; discarding and reissuing"
            )
            return None
        mode = TlsMode.self_signed if cert.issuer == cert.subject else TlsMode.ca_issued
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans = leaf.san_strings(san_ext)
        except x509.ExtensionNotFound:
            sans = []
        return _CurrentMaterial(
            cert=cert,
            key_pem=key_pem,
            mode=mode,
            subject_cn=_subject_cn(cert),
            sans=sans,
            not_after=cert.not_valid_after_utc,
        )

    def _write_and_load(self, cert_bytes: bytes, secrets: SecretStore, key_pem: bytes) -> None:
        tls_dir = cert_path(self.data_dir).parent
        tls_dir.mkdir(mode=0o700, exist_ok=True, parents=True)
        _atomic_write(cert_path(self.data_dir), cert_bytes)
        _atomic_write(sealed_key_path(self.data_dir), secrets.seal(key_pem).encode("ascii"))
        self._load_into_live_context(key_pem)

    def _load_into_live_context(self, key_pem: bytes) -> None:
        """Mutate the attached `uvicorn.Config`'s live `SSLContext`, if one
        is attached and has actually loaded one (FR-7: `Config.ssl` does not
        exist until `Server._serve()` calls `Config.load()`, so this is a
        no-op until then and the files on disk are what that load will pick
        up)."""
        ssl_ctx: ssl.SSLContext | None = None
        if self._uvicorn_config is not None:
            ssl_ctx = getattr(self._uvicorn_config, "ssl", None)
        if ssl_ctx is not None:
            load_into(ssl_ctx, cert_path(self.data_dir), key_pem)

    def _record_issued(
        self,
        db: Session,
        mode: TlsMode,
        subject_cn: str,
        sans: Sequence[str],
        cert: x509.Certificate,
        cert_row: "Certificate | None",
        capped_from: datetime | None,
    ) -> None:
        detail: dict[str, object] = {
            "mode": str(mode),
            "subject_cn": subject_cn,
            "sans": list(sans),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
        if capped_from is not None:
            detail["capped_from"] = capped_from.isoformat()
        audit.record(
            db,
            audit.SYSTEM_ACTOR,
            AuditAction.tls_certificate_issued,
            summary=f"issued a {mode} TLS certificate for cabin itself ({subject_cn!r})",
            target_type="certificate",
            target_id=cert_row.id if cert_row is not None else None,
            detail=detail,
        )

    def ensure_current(self, db: Session, secrets: SecretStore) -> bool:
        """FR-6: the single entry point for cabin's own TLS material.
        Returns whether it changed. Never raises for a recoverable
        condition -- logs and returns `False`.
        """
        with self._lock:
            return self._ensure_current_locked(db, secrets)

    def _ensure_current_locked(self, db: Session, secrets: SecretStore) -> bool:
        current = self._load_current(secrets)
        if current is not None and self.mode is None:
            # A fresh process attaches an empty `SSLContext` (FR-1's
            # `_bare_ssl_context_factory`) even when valid material already
            # sits on disk from a previous run -- nothing else ever loads it
            # in. Adopt what is there before deciding whether it also needs
            # replacing, so the very first connection after a restart is
            # never handed a context with nothing loaded (AC-7/FR-9's
            # startup check, and stage 3's "still served after a restart").
            self._load_into_live_context(current.key_pem)
            self.mode = current.mode
        subject_cn, sans = self.wanted_names(db)
        issuer = resolve_tls_issuer(db)

        if issuer is not None:
            target_mode = TlsMode.ca_issued
        elif current is not None and current.mode is TlsMode.ca_issued:
            # FR-17: never downgrade a working CA-issued certificate to
            # self-signed just because the bound issuer became unusable --
            # a self-signed certificate is what an instance starts with,
            # not something it falls back to.
            target_mode = TlsMode.ca_issued
        else:
            target_mode = TlsMode.self_signed

        if target_mode is TlsMode.ca_issued and issuer is None:
            logger.warning(
                "cabin's bound TLS issuer is unset, unknown, retired, or ambiguous; "
                "keeping the certificate already being served"
            )
            self.mode = current.mode if current is not None else None
            return False

        issuer_cert: x509.Certificate | None = None
        if target_mode is TlsMode.ca_issued:
            assert issuer is not None
            issuer_cert = x509.load_pem_x509_certificate(issuer.cert_pem.encode("utf-8"))

        names_changed = (
            current is None or current.subject_cn != subject_cn or set(current.sans) != set(sans)
        )
        mode_changed = current is None or current.mode is not target_mode
        if not mode_changed and target_mode is TlsMode.ca_issued and current is not None:
            assert issuer_cert is not None
            try:
                current.cert.verify_directly_issued_by(issuer_cert)
            except Exception:
                # Currently-loaded material was signed by a *different*
                # issuer than the one now resolved (a rebind) -- treated
                # exactly like a mode change: reissue unconditionally.
                mode_changed = True

        if not mode_changed and not names_changed:
            assert current is not None
            now = datetime.now(UTC)
            if now < current.not_after - RENEW_BEFORE:
                self.mode = current.mode
                return False
            if target_mode is TlsMode.ca_issued:
                assert issuer_cert is not None
                candidate_not_after = min(
                    now + timedelta(days=CERT_DAYS), issuer_cert.not_valid_after_utc
                )
                if candidate_not_after - current.not_after < MIN_RENEWAL_GAIN:
                    logger.info(
                        "declining to renew cabin's TLS certificate: the bound issuer's "
                        "remaining validity would not gain at least %s (spec 0022 FR-17)",
                        MIN_RENEWAL_GAIN,
                    )
                    self.mode = current.mode
                    return False

        try:
            cert, cert_bytes, key_pem, cert_row, capped_from = self._issue(
                db, secrets, target_mode, issuer, subject_cn, sans
            )
        except (
            CANotConfiguredError,
            IssuerRequiredError,
            IssuerRetiredError,
            UnknownIssuerError,
            IssueError,
        ) as exc:
            # Deliberately not extended with IssuerForbiddenError or
            # NoGrantedIssuerError (spec 0018 FR-15/AC-19): the system
            # principal below is unrestricted, so neither can be raised by
            # the call this wraps. Catching them "defensively" would hide a
            # future regression instead of failing where a test can see it.
            message = str(exc)
            logger.warning(
                "could not issue cabin's own TLS certificate (%s); keeping current material", exc
            )
            self.mode = current.mode if current is not None else None
            if self.last_error != message:
                # Only on the transition into failure (spec 0018 FR-15): a
                # tick that repeats the same failure must not write a second
                # event, or an unattended instance logs one every hour.
                audit.record(
                    db,
                    audit.SYSTEM_ACTOR,
                    AuditAction.tls_certificate_failed,
                    summary=f"cabin could not issue its own TLS certificate ({message})",
                    detail={
                        "reason": message,
                        "mode": str(self.mode) if self.mode is not None else None,
                    },
                )
            self.last_error = message
            return False

        self._write_and_load(cert_bytes, secrets, key_pem)
        self.mode = target_mode
        self.last_error = None
        self._record_issued(db, target_mode, subject_cn, sans, cert, cert_row, capped_from)
        return True

    def _issue(
        self,
        db: Session,
        secrets: SecretStore,
        target_mode: TlsMode,
        issuer: "CACertificate | None",
        subject_cn: str,
        sans: Sequence[str],
    ) -> tuple[x509.Certificate, bytes, bytes, "Certificate | None", datetime | None]:
        """Build the next certificate/key pair -- self-signed (FR-4) or
        CA-issued through the ordinary `issue_and_store` path (FR-6) -- and
        the exact bytes `cabin.crt` should hold. Raises the same exceptions
        `issue_and_store`/`leaf` do; the caller decides what "recoverable"
        means.
        """
        if target_mode is TlsMode.self_signed:
            cert, key = leaf.self_signed_server_certificate(subject_cn, sans, days=CERT_DAYS)
            key_pem = _key_pem(key)
            cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
            return cert, cert_bytes, key_pem, None, None

        assert issuer is not None
        issued = issue_and_store(
            db,
            secrets,
            # Spec 0018 FR-7: cabin issuing its own certificate acts for
            # nobody -- there is no session, no bearer token and (from the
            # renewal tick) no request at all, so this rides the named
            # system exemption rather than any operator's grants.
            principal=issuer_grants.SYSTEM_PRINCIPAL,
            profile=Profile.server,
            subject_cn=subject_cn,
            sans=sans,
            days=CERT_DAYS,
            issuer_id=issuer.id,
            source=CertSource.system,
        )
        cert_row = issued.row
        cert = x509.load_pem_x509_certificate(cert_row.cert_pem.encode("ascii"))
        assert cert_row.key_sealed is not None  # issue_and_store always seals one
        key_pem = secrets.unseal(cert_row.key_sealed)
        chain_pem = b"".join(row.cert_pem.encode("ascii") for row in chain_for(db, issuer.id))
        cert_bytes = cert_row.cert_pem.encode("ascii") + chain_pem
        return cert, cert_bytes, key_pem, cert_row, issued.capped_from
