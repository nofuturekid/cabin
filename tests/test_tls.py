"""Tests for cabin.tls: the TLS key material and certificate lifecycle
(spec 0022).

This file is written against the module's full Interface Contract (spec
0022, "cabin.tls -- new"), not against the Phase-0 skeleton that exists on
disk today -- `TlsMode`/`cert_path`/`sealed_key_path`/`TlsManager.mode`/
`.attach`/`.ensure_current` exist; `TlsManager.wanted_names`,
`resolve_tls_issuer`, `renewal_loop`, `load_into` and the module's four
constants do not yet. Those five are therefore accessed through `tls_mod.*`
(a plain `import cabin.tls as tls_mod`) rather than imported by name, and
`CertSource.system` / `AuditAction.tls_certificate_issued` / a settings-table
key by the same reasoning are used as the literal strings the spec's
Interface Contract fixes them to -- mirroring the same technique
`tests/test_web_tls_ui.py` already uses in this branch. Importing any of
them by name would turn every one of this file's tests into a single
collection error instead of the individual, informative red pytest already
gives per test: "the thing does not exist yet", not "this test is broken".

Scope, deliberately narrow: this file's job is the four acceptance criteria
that are testable at the `cabin.tls` level without a full request/route
stack -- AC-19 (the key is never reachable on disk, including the
concurrent-watcher half that a write-load-unlink implementation would
still pass), AC-21 (FR-17's issuer binding, written so that "default to the
sole/first active issuer" silently fails it), AC-22 (the renewal scheduler
survives a raising tick) and AC-24 (no renewal storm once the bound issuer
is running out). FR-3's memfd load is tested here too, because AC-19's
decisive claim rests on it actually running rather than merely not
raising. AC-1/AC-4/AC-6/AC-8/AC-17/AC-18 belong to other test files in this
spec's split and are intentionally not duplicated here, except where a
helper needs to pass through a self-signed or CA-issued stage to set up
state for one of the four ACs this file owns.

Every certificate identity check that matters uses `cryptography` directly
(`verify_directly_issued_by`, SubjectPublicKeyInfo comparison) rather than
an external chain check -- this project has already shipped a chain check
that could not tell a cryptographically invalid root from a valid one, and
`openssl verify -CAfile` trusts whatever it is handed.
"""

import asyncio
import contextlib
import logging
import os
import socket
import ssl
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import ca_fixtures
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import NameOID
from live_server import LiveClient, live_cabin, plant_tls_material, tls_peer_certificate
from sqlalchemy.orm import Session

from cabin import tls as tls_mod
from cabin.audit import AuditEvent
from cabin.ca.certs import Certificate
from cabin.ca.leaf import Profile, issue_certificate
from cabin.ca.service import CACertificate, signing_credentials
from cabin.ca.x509 import create_root, generate_key, signing_algorithm
from cabin.secrets import SecretStore
from cabin.settings import get_setting, set_setting
from cabin.store import create_session_factory, run_migrations
from cabin.tls import TlsManager, TlsMode, cert_path, sealed_key_path

#: Spec 0022 Interface Contract: ``TLS_ISSUER_ID_KEY = "tls_issuer_id"``. Used as
#: a literal for the same reason as `tls_mod.*` above -- it is Crypto's own
#: Phase-2 addition to ``cabin.settings`` and does not exist on this branch
#: yet; importing it by name would break collection of this whole file.
TLS_ISSUER_ID_KEY = "tls_issuer_id"

#: Spec 0022 Interface Contract: ``CertSource`` gains ``system = "system"``
#: and ``AuditAction`` gains ``tls_certificate_issued``. Same reasoning,
#: same fix: the literal values the contract fixes, not the enum members.
CERT_SOURCE_SYSTEM = "system"
AUDIT_ACTION_TLS_CERTIFICATE_ISSUED = "tls_certificate_issued"

# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def secrets(tmp_path: Path) -> SecretStore:
    return SecretStore.open(tmp_path, None)


# --- crypto helpers ------------------------------------------------------


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _spki(public_key: CertificatePublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _self_signed_cert(
    cn: str, *, not_after: datetime | None = None
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """A throwaway self-signed leaf for planting on disk (never through
    `TlsManager`) -- what "the current material" looks like before a test
    calls `ensure_current` against it."""
    key = generate_key("ecdsa-p256")
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after or (now + timedelta(days=tls_mod.CERT_DAYS)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=signing_algorithm(key))
    )
    return cert, key


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _hierarchy_with_intermediate_expiry(
    db: Session, secrets: SecretStore, not_after: datetime, name: str
) -> "ca_fixtures.CAHierarchy":
    """A real, signing-capable root+intermediate whose intermediate expires
    at exactly `not_after` -- `ca.x509.create_intermediate` only takes whole
    years, which cannot express AC-24's "three days from expiry"."""
    root_cert, root_key = create_root(f"{name} Root CA", "ecdsa-p256", years=20)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    intermediate_key = generate_key("ecdsa-p256")
    now = datetime.now(UTC)
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Intermediate CA")])
        )
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False
        )
        .sign(root_key, algorithm=signing_algorithm(root_key))
    )
    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_sealed=secrets.seal(_key_pem(root_key)),
    )
    db.add(root_row)
    db.flush()
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status="active",
        cert_pem=intermediate_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_sealed=secrets.seal(_key_pem(intermediate_key)),
    )
    db.add(intermediate_row)
    db.commit()
    return ca_fixtures.CAHierarchy(root=root_row, intermediate=intermediate_row)


# --- a real TLS handshake against a mutated SSLContext ------------------------
#
# `load_into` and `ensure_current` mutate an `ssl.SSLContext` in place --
# exactly the object `uvicorn.Config.ssl` will be at runtime (spec 0022's
# spike: "every connection opened afterwards presented the new certificate,
# ... id() identical before and after"). This is the primitive that lets a
# test read what a client actually sees off that context, the same way
# `live_server.tls_peer_certificate` does it against a real socket, but
# without paying for a subprocess boot for every one of this file's tests.


def _served_certificate(ctx: ssl.SSLContext, *, timeout: float = 5.0) -> x509.Certificate:
    """One real TLS handshake against `ctx` over loopback. Never inferred
    from the absence of an exception -- the served certificate is parsed
    back off the wire, the same primitive AC-1/AC-5/AC-6/AC-7 use via
    `live_server.tls_peer_certificate`."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(timeout)
    port = listener.getsockname()[1]
    errors: list[BaseException] = []

    def accept_once() -> None:
        try:
            connection, _ = listener.accept()
            with ctx.wrap_socket(connection, server_side=True) as tls_conn:
                tls_conn.settimeout(timeout)
                with contextlib.suppress(OSError):
                    tls_conn.recv(1)
        except BaseException as exc:
            errors.append(exc)

    server_thread = threading.Thread(target=accept_once, daemon=True)
    server_thread.start()
    try:
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw,
            client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls_conn,
        ):
            der = tls_conn.getpeercert(binary_form=True)
    finally:
        listener.close()
        server_thread.join(timeout=timeout)
    if errors:
        raise errors[0]
    assert der is not None
    return x509.load_der_x509_certificate(der)


async def _noop_asgi_app(scope: object, receive: object, send: object) -> None:  # pragma: no cover
    raise AssertionError("the dummy ASGI app must never actually be invoked in these tests")


def _attach_live_context(manager: TlsManager) -> uvicorn.Config:
    """A real `uvicorn.Config` with `.ssl` already populated -- simulating
    the post-startup state FR-6 writes into (`config.ssl` only exists after
    `Server._serve()` calls `Config.load()`; here it is built directly so
    `ensure_current`'s `load_into` call actually has something to mutate)."""
    cfg = uvicorn.Config(app=_noop_asgi_app)
    cfg.ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    manager.attach(cfg)
    return cfg


def _through_stage_two(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> tuple[TlsManager, "ca_fixtures.CAHierarchy"]:
    """Stage 1 (self-signed, no CA) then stage 2 (a hierarchy appears and
    the swap happens) -- the shared setup AC-19's "after a full startup and
    a stage-2 swap" needs, with a live context attached throughout so the
    memfd load actually runs both times."""
    manager = TlsManager(tmp_path)
    _attach_live_context(manager)
    assert manager.ensure_current(db, secrets) is True, "stage 1 did not write anything"
    assert manager.mode is TlsMode.self_signed
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Lifecycle")
    assert manager.ensure_current(db, secrets) is True, "stage 2 did not swap"
    assert manager.mode is TlsMode.ca_issued
    return manager, hierarchy


def _plant_near_expiry_renewal(
    db: Session,
    secrets: SecretStore,
    tmp_path: Path,
    manager: TlsManager,
    hierarchy: "ca_fixtures.CAHierarchy",
    *,
    days: int = 10,
) -> x509.Certificate:
    """Overwrite the on-disk material with a CA-issued leaf from the SAME
    issuer and the SAME names, `days` from expiry -- so the next
    `ensure_current` call is a genuine *renewal* (same mode, same names,
    inside `RENEW_BEFORE`), not a mode swap. This is work-split section
    2.4(a)'s technique: plant the certificate, never fake the clock."""
    subject_cn, sans = manager.wanted_names(db)
    issuer_cert, issuer_key = signing_credentials(db, secrets, hierarchy.intermediate.id)
    stale, stale_key, _capped = issue_certificate(
        issuer_cert, issuer_key, Profile.server, subject_cn, sans, days=days
    )
    plant_tls_material(
        tmp_path, secrets, stale.public_bytes(serialization.Encoding.PEM), _key_pem(stale_key)
    )
    return stale


# ==============================================================================
# AC-19 -- no plaintext private key is ever reachable on disk.
# ==============================================================================


def test_no_plaintext_private_key_anywhere_under_data_dir(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-19.1: after a full startup, a stage-2 swap and a renewal, every
    regular file under DATA_DIR is read and none of them parses as a
    private key."""
    manager, hierarchy = _through_stage_two(db, secrets, tmp_path)
    _plant_near_expiry_renewal(db, secrets, tmp_path, manager, hierarchy)
    assert manager.ensure_current(db, secrets) is True, "the renewal did not happen"

    checked = 0
    for path in tmp_path.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        checked += 1
        assert b"PRIVATE KEY" not in data, f"{path} carries a PEM private-key header"
        with pytest.raises((ValueError, TypeError)):
            serialization.load_pem_private_key(data, password=None)
    assert checked > 0, "the walk found nothing under DATA_DIR -- the test proved nothing"


def test_sealed_tls_key_unseals_but_does_not_parse_as_a_key(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-19.1's decisive half: `cabin.key.sealed` is not loadable as a key,
    but it *is* loadable through `SecretStore.unseal` -- proving it is
    sealed, not merely opaque -- and the unsealed key is the one the served
    certificate actually carries."""
    manager, hierarchy = _through_stage_two(db, secrets, tmp_path)
    _plant_near_expiry_renewal(db, secrets, tmp_path, manager, hierarchy)
    assert manager.ensure_current(db, secrets) is True

    sealed = sealed_key_path(tmp_path).read_text()
    with pytest.raises((ValueError, TypeError)):
        serialization.load_pem_private_key(sealed.encode("ascii"), password=None)

    unsealed = secrets.unseal(sealed)
    key = serialization.load_pem_private_key(unsealed, password=None)
    served_cert = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert _spki(key.public_key()) == _spki(served_cert.public_key())


def test_tls_dir_contains_exactly_cert_and_sealed_key(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-19.2, compared as a set: a stray temporary file left behind by a
    failed write is a failure, not an unnoticed leak."""
    manager, hierarchy = _through_stage_two(db, secrets, tmp_path)
    _plant_near_expiry_renewal(db, secrets, tmp_path, manager, hierarchy)
    assert manager.ensure_current(db, secrets) is True

    names = {entry.name for entry in cert_path(tmp_path).parent.iterdir()}
    assert names == {"cabin.crt", "cabin.key.sealed"}


def test_failed_write_leaves_no_temporary_file(
    db: Session, secrets: SecretStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-19.2's crash case: both files are written to a temp name and
    `os.replace`d into place (FR-3). If the second `os.replace` in one
    `ensure_current` call fails, no partial file may be left behind."""
    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True  # stage 1, unpatched
    ca_fixtures.make_hierarchy(db, secrets, "Flaky")  # forces a re-issue attempt next call

    real_replace = os.replace
    calls = {"n": 0}

    def _flaky_replace(src: object, dst: object, *args: object, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated crash mid-write")
        real_replace(src, dst, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", _flaky_replace)
    with contextlib.suppress(Exception):
        manager.ensure_current(db, secrets)
    monkeypatch.undo()

    tls_dir = cert_path(tmp_path).parent
    leftover = {entry.name for entry in tls_dir.iterdir()} - {"cabin.crt", "cabin.key.sealed"}
    assert leftover == set(), f"a stray temp file was left behind: {leftover}"


def _watch_tls_dir(
    tls_dir: Path, stop: threading.Event, seen: list[str], violations: list[str]
) -> None:
    """Poll `tls_dir` continuously (no sleep -- this is the whole point:
    the tighter the loop, the better the odds of catching a write-load-
    unlink implementation's transient plaintext file) and record every
    filename ever observed. Anything readable at the moment it is seen is
    checked *then*, not after the fact -- a temp file may be renamed or
    removed a microsecond later."""
    while not stop.is_set():
        try:
            entries = list(tls_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen.append(entry.name)
            try:
                data = entry.read_bytes()
            except OSError:
                continue  # renamed/removed between listing and reading: fine
            if b"PRIVATE KEY" in data:
                with contextlib.suppress(ValueError, TypeError):
                    serialization.load_pem_private_key(data, password=None)
                    violations.append(entry.name)


def test_concurrent_watcher_never_sees_a_plaintext_key_file(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-19.3 -- the one that matters. A second thread polls
    `DATA_DIR/tls/` throughout a real renewal (fresh key, seal, write,
    memfd load) and records every filename it ever sees. None of them may
    be a plaintext key file. This is what a "simplify the memfd load into a
    temporary file" implementation fails and the first three AC-19
    assertions would not catch."""
    manager, hierarchy = _through_stage_two(db, secrets, tmp_path)
    _plant_near_expiry_renewal(db, secrets, tmp_path, manager, hierarchy)

    tls_dir = cert_path(tmp_path).parent
    stop = threading.Event()
    seen: list[str] = []
    violations: list[str] = []
    watcher = threading.Thread(
        target=_watch_tls_dir, args=(tls_dir, stop, seen, violations), daemon=True
    )
    watcher.start()
    try:
        changed = manager.ensure_current(db, secrets)
    finally:
        stop.set()
        watcher.join(timeout=5)

    assert changed is True, "no renewal happened -- the watcher observed nothing meaningful"
    assert seen, "the watcher never observed the directory at all -- it did not run concurrently"
    assert violations == [], f"a plaintext private key was visible on disk: {violations}"


# ==============================================================================
# FR-3 -- the memfd load itself, which AC-19's decisive claim rests on.
# ==============================================================================


def test_memfd_load_serves_a_working_certificate(tmp_path: Path) -> None:
    """FR-3: a real TLS handshake against the resulting context, with the
    served certificate read back off the wire -- not "no exception raised"."""
    cert, key = _self_signed_cert("memfd.example")
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    crt = tls_dir / "cabin.crt"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_mod.load_into(ctx, crt, _key_pem(key))

    served = _served_certificate(ctx)
    assert served.serial_number == cert.serial_number
    assert served.subject == cert.subject
    assert _spki(served.public_key()) == _spki(key.public_key())


def test_load_falls_back_when_memfd_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """FR-3's one fallback: `os.memfd_create` raising still ends in a
    working context, and cabin logs that it took the fallback. The
    unlinked-file half is also checked here: nothing but `cabin.crt`
    survives in the directory the fallback would have written into."""
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    cert, key = _self_signed_cert("fallback.example")
    crt = tls_dir / "cabin.crt"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _raise(*_args: object, **_kwargs: object) -> int:
        raise OSError("memfd_create is not permitted in this test")

    monkeypatch.setattr(os, "memfd_create", _raise)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with caplog.at_level(logging.INFO):
        tls_mod.load_into(ctx, crt, _key_pem(key))

    served = _served_certificate(ctx)
    assert served.serial_number == cert.serial_number
    assert "memfd" in caplog.text.lower(), "the fallback must be logged (FR-3)"
    leftover = {entry.name for entry in tls_dir.iterdir()}
    assert leftover == {"cabin.crt"}, f"the fallback file was not cleaned up: {leftover}"


# ==============================================================================
# AC-21 -- FR-17's issuer binding: a stored, deliberate choice.
# ==============================================================================


def test_resolve_tls_issuer_persists_when_exactly_one_active(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Sole")
    assert get_setting(db, TLS_ISSUER_ID_KEY) is None
    resolved = tls_mod.resolve_tls_issuer(db)
    assert resolved is not None
    assert resolved.id == hierarchy.intermediate.id
    # Persisted immediately, not just returned -- so a second issuer created
    # later cannot change the answer retroactively.
    assert get_setting(db, TLS_ISSUER_ID_KEY) == str(hierarchy.intermediate.id)


def test_resolve_tls_issuer_stays_ambiguous_with_two_active_and_no_binding(
    db: Session, secrets: SecretStore
) -> None:
    ca_fixtures.make_hierarchy(db, secrets, "First")
    ca_fixtures.make_hierarchy(db, secrets, "Second")
    assert tls_mod.resolve_tls_issuer(db) is None
    assert get_setting(db, TLS_ISSUER_ID_KEY) is None, "an ambiguous state must not be persisted"


def test_resolve_tls_issuer_honors_explicit_binding(db: Session, secrets: SecretStore) -> None:
    hierarchy_a = ca_fixtures.make_hierarchy(db, secrets, "First")
    hierarchy_b = ca_fixtures.make_hierarchy(db, secrets, "Second")
    set_setting(db, TLS_ISSUER_ID_KEY, str(hierarchy_b.intermediate.id))
    resolved = tls_mod.resolve_tls_issuer(db)
    assert resolved is not None
    assert resolved.id == hierarchy_b.intermediate.id
    assert resolved.id != hierarchy_a.intermediate.id


def test_resolve_tls_issuer_ignores_unknown_or_retired_binding(
    db: Session, secrets: SecretStore
) -> None:
    set_setting(db, TLS_ISSUER_ID_KEY, "999999")
    assert tls_mod.resolve_tls_issuer(db) is None

    retired_id = ca_fixtures.retired_issuer(db)
    set_setting(db, TLS_ISSUER_ID_KEY, str(retired_id))
    assert tls_mod.resolve_tls_issuer(db) is None


def test_multi_issuer_without_binding_stays_self_signed(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-21 main scenario, first half: two active issuers, nothing bound
    yet -- cabin must not raise, must not issue anything CA-signed, and
    must keep serving self-signed material."""
    ca_fixtures.make_hierarchy(db, secrets, "First")
    ca_fixtures.make_hierarchy(db, secrets, "Second")
    manager = TlsManager(tmp_path)
    changed = manager.ensure_current(db, secrets)

    assert changed is True  # first-ever material, written for the first time
    assert manager.mode is TlsMode.self_signed
    served = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert served.issuer == served.subject
    assert db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).count() == 0
    assert get_setting(db, TLS_ISSUER_ID_KEY) is None


def test_ensure_current_binds_to_the_explicitly_selected_second_issuer_durably(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-21 main scenario, second half, and the mutation catcher: bind to
    the SECOND of two active issuers deliberately, so an implementation
    that silently defaults to "the sole/first active issuer" gets this
    wrong. Identity is proved with `verify_directly_issued_by` -- signature
    verification, not a subject-string comparison -- against BOTH
    candidate issuers, so a chain check that trusts whatever it is handed
    cannot pass here by accident. Then a further issuer is created and the
    served chain must not move, proving the decision was written down.
    """
    hierarchy_a = ca_fixtures.make_hierarchy(db, secrets, "First")
    hierarchy_b = ca_fixtures.make_hierarchy(db, secrets, "Second")
    set_setting(db, TLS_ISSUER_ID_KEY, str(hierarchy_b.intermediate.id))

    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True
    assert manager.mode is TlsMode.ca_issued

    leaf = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    issuer_a_cert = x509.load_pem_x509_certificate(hierarchy_a.intermediate.cert_pem.encode())
    issuer_b_cert = x509.load_pem_x509_certificate(hierarchy_b.intermediate.cert_pem.encode())
    leaf.verify_directly_issued_by(issuer_b_cert)  # the chosen issuer signed this
    with pytest.raises(Exception):  # noqa: B017 - cryptography raises several types here
        leaf.verify_directly_issued_by(issuer_a_cert)  # the OTHER one did not

    row = db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).one()
    assert row.issuer_id == hierarchy_b.intermediate.id
    served_serial = leaf.serial_number

    # Durability: a third issuer appears; the bound chain must not move.
    ca_fixtures.make_hierarchy(db, secrets, "Third")
    changed = manager.ensure_current(db, secrets)
    assert changed is False
    still_served = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert still_served.serial_number == served_serial
    still_served.verify_directly_issued_by(issuer_b_cert)


def test_second_issuer_does_not_change_the_persisted_sole_issuer_binding(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-21's persistence counter-check: with exactly one active issuer,
    `ensure_current` issues *and* stores the id; a second issuer created
    afterwards leaves the served certificate's issuer unchanged."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Sole")
    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True
    assert get_setting(db, TLS_ISSUER_ID_KEY) == str(hierarchy.intermediate.id)
    first_leaf = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())

    ca_fixtures.make_hierarchy(db, secrets, "Later")
    changed = manager.ensure_current(db, secrets)
    assert changed is False

    second_leaf = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert second_leaf.serial_number == first_leaf.serial_number
    issuer_cert = x509.load_pem_x509_certificate(hierarchy.intermediate.cert_pem.encode())
    second_leaf.verify_directly_issued_by(issuer_cert)


def test_unknown_or_retired_binding_keeps_current_material(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True  # stage 1: self-signed
    before = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())

    set_setting(db, TLS_ISSUER_ID_KEY, "999999")
    assert manager.ensure_current(db, secrets) is False
    after = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert after.serial_number == before.serial_number

    retired_id = ca_fixtures.retired_issuer(db)
    set_setting(db, TLS_ISSUER_ID_KEY, str(retired_id))
    assert manager.ensure_current(db, secrets) is False
    still = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert still.serial_number == before.serial_number


# ==============================================================================
# AC-22 -- the renewal loop runs, survives a raising tick, and stops.
# ==============================================================================


def test_renewal_loop_replaces_expiring_certificate(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-22.1: driven through `renewal_loop` with a millisecond interval,
    never a real hour. The material is actually replaced -- asserted on the
    certificate served over a real handshake against the mutated context,
    not on a call count."""
    manager = TlsManager(tmp_path)
    cfg = _attach_live_context(manager)
    stale, _stale_key = _self_signed_cert(
        "loop.example", not_after=datetime.now(UTC) + timedelta(days=10)
    )
    plant_tls_material(
        tmp_path, secrets, stale.public_bytes(serialization.Encoding.PEM), _key_pem(_stale_key)
    )

    async def run() -> None:
        stop = asyncio.Event()
        done = asyncio.Event()

        def tick() -> None:
            manager.ensure_current(db, secrets)
            done.set()

        task = asyncio.create_task(tls_mod.renewal_loop(timedelta(milliseconds=1), tick, stop))
        await asyncio.wait_for(done.wait(), timeout=5)
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(run())

    renewed = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert renewed.serial_number != stale.serial_number
    assert renewed.not_valid_after_utc > stale.not_valid_after_utc
    served = _served_certificate(cfg.ssl)
    assert served.serial_number == renewed.serial_number


def test_renewal_loop_survives_a_raising_tick(db: Session, secrets: SecretStore) -> None:
    """AC-22.2 -- the one that matters. A `tick` that raises on its first
    call is still called again on the next interval, and the loop is still
    running afterwards. A scheduler that dies silently after one transient
    error leaves the process looking healthy while the certificate expires
    underneath it."""
    calls: list[int] = []

    def flaky_tick() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("simulated transient database error")

    async def run() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(
            tls_mod.renewal_loop(timedelta(milliseconds=1), flaky_tick, stop)
        )
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5
        while len(calls) < 2 and loop.time() < deadline:
            await asyncio.sleep(0.001)
        assert len(calls) >= 2, "the tick was never called a second time after it raised"
        assert not task.done(), "the loop died after the raising tick instead of continuing"
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(run())


def test_renewal_loop_stops_on_event(db: Session, secrets: SecretStore) -> None:
    """AC-22.3: setting `stop` ends the loop, and it actually stops ticking
    -- not just that the task object completed, which a loop ignoring
    `stop` for an unrelated reason could also produce."""
    calls: list[int] = []

    def tick() -> None:
        calls.append(1)

    async def run() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(tls_mod.renewal_loop(timedelta(milliseconds=1), tick, stop))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5
        while len(calls) < 3 and loop.time() < deadline:
            await asyncio.sleep(0.001)
        assert len(calls) >= 3
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        assert task.done()
        seen_at_stop = len(calls)
        await asyncio.sleep(0.05)
        assert len(calls) == seen_at_stop, "the loop kept ticking after stop was set"

    asyncio.run(run())


# ==============================================================================
# AC-24 -- no renewal storm as the bound issuer runs out.
# ==============================================================================


def test_no_renewal_storm_as_bound_issuer_runs_out(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """The half that catches a naive "re-issue whenever inside the window"
    implementation: once the bound issuer has less life left than
    RENEW_BEFORE, every certificate cabin issues itself is clamped straight
    back inside the window (0017 FR-7). Ten consecutive `ensure_current`
    calls after the first must add no inventory row and no audit event, and
    must keep returning False."""
    assert timedelta(days=3) < tls_mod.RENEW_BEFORE, (
        "the scenario needs an issuer inside the window"
    )
    near_expiry = datetime.now(UTC) + timedelta(days=3)
    hierarchy = _hierarchy_with_intermediate_expiry(db, secrets, near_expiry, "Storm")
    set_setting(db, TLS_ISSUER_ID_KEY, str(hierarchy.intermediate.id))

    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True  # the one certificate it can ever get
    first = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert first.not_valid_after_utc <= near_expiry + timedelta(seconds=5)

    rows_before = db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).count()
    audits_before = (
        db.query(AuditEvent).filter_by(action=AUDIT_ACTION_TLS_CERTIFICATE_ISSUED).count()
    )

    results = [manager.ensure_current(db, secrets) for _ in range(10)]
    assert results == [False] * 10, "a naive implementation re-issued on a later tick"

    rows_after = db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).count()
    audits_after = (
        db.query(AuditEvent).filter_by(action=AUDIT_ACTION_TLS_CERTIFICATE_ISSUED).count()
    )
    assert rows_after == rows_before, "the clamp did not stop new inventory rows from piling up"
    assert audits_after == audits_before, "the clamp did not stop new audit events from piling up"

    still_served = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes())
    assert still_served.serial_number == first.serial_number


def test_renewal_replaces_exactly_once_with_healthy_issuer(
    db: Session, secrets: SecretStore, tmp_path: Path
) -> None:
    """AC-24's counter-check: an ordinary certificate inside the renewal
    window, signed by an issuer that is nowhere near expiry, IS replaced --
    exactly once, not on every subsequent tick either. Without this half,
    the storm test above cannot distinguish "correctly declined" from
    "renewal is broken"."""
    hierarchy = ca_fixtures.make_hierarchy(db, secrets, "Healthy")
    set_setting(db, TLS_ISSUER_ID_KEY, str(hierarchy.intermediate.id))
    manager = TlsManager(tmp_path)
    assert manager.ensure_current(db, secrets) is True  # a fresh, ~90-day certificate

    _plant_near_expiry_renewal(db, secrets, tmp_path, manager, hierarchy, days=10)
    rows_before = db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).count()

    results = [manager.ensure_current(db, secrets) for _ in range(10)]
    assert results == [True] + [False] * 9

    rows_after = db.query(Certificate).filter_by(source=CERT_SOURCE_SYSTEM).count()
    assert rows_after == rows_before + 1


# ==============================================================================
# The three stages, read off the wire through a real cabin process.
# ==============================================================================


def _create_ca_via_live_client(client: LiveClient, *, name: str = "cabin") -> None:
    token = client.csrf_token("/")
    resp = client.post(
        "/ca/create",
        {
            "name": name,
            "key_type": "ecdsa-p256",
            "root_years": "20",
            "intermediate_years": "10",
            "csrf_token": token,
        },
    )
    assert resp.status_code in (200, 303), resp.text


def test_stage_transitions_confirmed_over_a_live_server(tmp_path: Path) -> None:
    """The three stages end to end, against a real subprocess, reading
    every certificate off the wire rather than off disk -- what a client
    actually sees is the only thing that matters here. This exercises the
    whole stack (server.py, web/ca_ui.py's post-create hook, tls.py), not
    only this module, and stays red until every phase of spec 0022 lands,
    not just Crypto's."""
    data_dir = tmp_path / "instance"
    with live_cabin(data_dir=data_dir, tls=True) as handle:
        pre_ca = tls_peer_certificate("127.0.0.1", handle.port)
        assert pre_ca.issuer == pre_ca.subject  # stage 1: self-signed

        with LiveClient("127.0.0.1", handle.port) as client:
            setup_resp = client.setup("admin", "correct horse battery staple 42")
            assert setup_resp.status_code in (200, 303), setup_resp.text
            _create_ca_via_live_client(client)

        post_ca = tls_peer_certificate("127.0.0.1", handle.port)
        assert post_ca.issuer != post_ca.subject  # stage 2: CA-issued
        assert post_ca.serial_number != pre_ca.serial_number
        first_pid = handle.pid  # the swap, not a restart, produced this

    with live_cabin(data_dir=data_dir, tls=True) as handle2:
        assert handle2.pid != first_pid  # this really is a fresh process
        restarted = tls_peer_certificate("127.0.0.1", handle2.port)
        assert restarted.issuer == post_ca.issuer
        assert restarted.serial_number == post_ca.serial_number  # stage 3: still CA-issued
