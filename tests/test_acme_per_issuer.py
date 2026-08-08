"""Spec 0019 -- ACME per issuer: the cross-issuer suite.

This file carries the weight of the spec (AC-1, AC-3, AC-4, AC-5, AC-7,
AC-10) and is deliberately written by someone who implements none of the
three checks it measures: FR-6's re-registration comparison, FR-7's EAB
issuer check and FR-9's issuance issuer. An author who had just written any
one of those checks is the worst possible author of the test that has to
tell it apart from something that only looks like it.

Every test below builds **two** active hierarchies (:data:`TwoIssuers`,
built straight from :func:`ca_fixtures.make_hierarchy` -- not the shared
``ca_fixtures.two_hierarchies`` helper, so this file depends on nothing that
is not already real) and names A or B explicitly in every assertion. A
single-issuer instance cannot tell "used the account's issuer" from "used
the only one", and the spec's own Test list note 3 says exactly that.

Three traps this file exists to avoid, spelled out once here rather than
scattered across comments nobody reads together:

1. **The EAB URL check is not the issuer check.**
   ``jws.parse_external_binding`` already refuses a binding whose inner JWS
   ``url`` is not the new-account URL cabin published, and after FR-2 that
   URL names an issuer. It is tempting to conclude a key minted for A
   therefore cannot be presented at B. It can: the inner JWS is built and
   MACed by the *client*, with the secret the client holds, so a client
   holding A's key id and secret simply signs a fresh binding over B's URL
   instead of A's. See the comment on
   :func:`test_eab_key_refused_at_another_issuers_directory` -- that test
   signs over the URL it is actually sent to, which is the only way to make
   the refusal come from ``ca_certificate_id`` rather than from the URL
   check.
2. **A default issuer in the test client would hide five criteria.** If
   ``Acme.__init__`` grew a default ``issuer_id``, "used the account's
   issuer" and "fell back to a default" would become indistinguishable on a
   one-hierarchy fixture. Every test here builds two hierarchies and names
   one explicitly at every call site.
3. **Re-registration is a silent escalation, not a refusal-shaped bug.**
   The found account's ``issuer_id`` must equal the path's issuer or the
   request is refused -- but re-registration at the account's *own*
   directory must keep working with no binding demanded, or the whole
   criterion is satisfied by an implementation that refuses everything
   (certbot's nightly renewal). Both halves are asserted, in the same test,
   for every re-registration criterion below.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import ca_fixtures
import pytest
from acme_client import Acme, ec_key, external_account_binding, flattened, rsa_key
from acme_orders import BASE, Flow, assert_problem, csr_der
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cabin.acme import eab
from cabin.acme import service as acme_service
from cabin.acme.eab import AcmeEabKey
from cabin.acme.models import AcmeAccount, AcmeOrder
from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import (
    ACME_ENABLED,
    ACME_REQUIRE_EAB,
    BASE_URL,
    FALSE,
    TRUE,
    set_setting,
)
from cabin.store import create_session_factory

EAB_KEYS_PATH = "/acme/admin/eab-keys"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _mac_key(secret: str) -> bytes:
    """The raw HMAC key behind ``eab.create_key``'s base64url secret."""
    return base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))


def _csrf_token(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


@dataclass(frozen=True)
class TwoIssuers:
    """Two independent, active hierarchies with sealed signing keys -- the
    default fixture in this file (spec 0019 Test list note 3). Built from
    :func:`ca_fixtures.make_hierarchy` directly rather than through a shared
    ``two_hierarchies`` helper, so this file has no dependency beyond what
    already exists in ``tests/ca_fixtures.py`` today.
    """

    cfg: Config
    client: TestClient
    hierarchy_a: ca_fixtures.CAHierarchy
    hierarchy_b: ca_fixtures.CAHierarchy

    @property
    def a(self) -> int:
        return self.hierarchy_a.intermediate.id

    @property
    def b(self) -> int:
        return self.hierarchy_b.intermediate.id


@pytest.fixture
def two_issuers(cfg: Config, client: TestClient) -> TwoIssuers:
    secrets = _secrets(cfg)
    db = _db(cfg)
    try:
        set_setting(db, BASE_URL, BASE)
        set_setting(db, ACME_ENABLED, TRUE)
        hierarchy_a = ca_fixtures.make_hierarchy(db, secrets, "alpha")
        hierarchy_b = ca_fixtures.make_hierarchy(db, secrets, "beta")
    finally:
        db.close()
    return TwoIssuers(cfg=cfg, client=client, hierarchy_a=hierarchy_a, hierarchy_b=hierarchy_b)


def acme_for(two_issuers: TwoIssuers, issuer_id: int) -> Acme:
    return Acme(two_issuers.client, issuer_id=issuer_id)


def _openssl_verify(tmp_path: Path, label: str, leaf_pem: str, chain_pem: str) -> bool:
    """Shell out to the real ``openssl`` CLI, the same technique
    ``tests/test_ca_multi.py`` uses for this repo's other cross-hierarchy
    checks -- a PEM-string comparison cannot tell "signed by the right root"
    from "signed by a root that merely looks similar"."""
    d = tmp_path / "verify" / label
    d.mkdir(parents=True)
    leaf_path = d / "leaf.pem"
    chain_path = d / "chain.pem"
    leaf_path.write_text(leaf_pem)
    chain_path.write_text(chain_pem)
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(chain_path), str(leaf_path)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


# === FR-5: the account binds to the path's issuer ==============================


def test_new_account_binds_the_account_to_the_path_issuer(two_issuers: TwoIssuers) -> None:
    """FR-5: registering at A's directory gives ``issuer_id == A``, at B's
    gives B -- both in one test, against one database, so a constant or a
    swapped comparison shows up as a wrong id rather than as "some id"."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)

    reg_a = acme_a.post(acme_a.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert reg_a.status_code == 201, reg_a.text
    reg_b = acme_b.post(acme_b.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert reg_b.status_code == 201, reg_b.text

    account_id_a = reg_a.headers["location"].rsplit("/", 1)[1]
    account_id_b = reg_b.headers["location"].rsplit("/", 1)[1]
    db = _db(two_issuers.cfg)
    try:
        account_a = db.get(AcmeAccount, account_id_a)
        account_b = db.get(AcmeAccount, account_id_b)
        assert account_a is not None
        assert account_b is not None
        assert account_a.issuer_id == two_issuers.a
        assert account_b.issuer_id == two_issuers.b
    finally:
        db.close()


def test_new_account_at_a_root_id_is_404(two_issuers: TwoIssuers) -> None:
    """FR-5 resolves the path's issuer exactly as FR-4 does: 404 for a root
    and for an unknown id. Proven against a live comparison in the same
    test, not against the 404 alone -- today, before this route exists at
    all, *every* path under ``/acme/ca/`` falls through to the catch-all and
    answers the same 404, matching id or not (``api.py``'s
    ``unknown_resource``). The passing registration at the real intermediate
    id, right next to the two refusals, is what stops this test from being
    satisfied by a route that simply is not there yet.
    """
    acme_a = acme_for(two_issuers, two_issuers.a)

    ok = acme_a.post(acme_a.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert ok.status_code == 201, ok.text

    at_root = acme_a.post(
        f"/acme/ca/{two_issuers.hierarchy_a.root.id}/new-account",
        rsa_key(),
        {"termsOfServiceAgreed": True},
    )
    assert_problem(at_root, "malformed", 404)

    at_unknown = acme_a.post(
        "/acme/ca/999999/new-account", rsa_key(), {"termsOfServiceAgreed": True}
    )
    assert_problem(at_unknown, "malformed", 404)


# === AC-1: the URL selects the issuer, end to end ===============================


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_two_directories_issue_from_their_own_issuer(
    two_issuers: TwoIssuers, tmp_path: Path
) -> None:
    """AC-1, the spine of this spec. Two accounts, two directories, two
    finalizes, in one test against one database: the resulting
    ``certificates`` rows carry ``issuer_id == A`` and ``== B``
    respectively, and the chain served at each account's own
    ``/acme/cert/{id}`` -- parsed, not compared as a string -- verifies
    against its own root and *fails* against the other's.

    _Goes red if_: ``_issue`` passes no ``issuer_id`` -- with two **active**
    issuers that raises ``IssuerRequiredError`` and neither finalize
    completes at all, which is exactly what happens today, since nothing
    yet passes ``issuer_id=account.issuer_id`` -- or passes a constant,
    which the cross-verify below catches even if both hierarchies happened
    to share a trust store.
    """
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)

    flow_a = Flow(acme_a, two_issuers.cfg, "svc-a.lan")
    flow_a.make_ready()
    flow_a.finalize_ok(csr_der("svc-a.lan"))
    cert_resp_a = flow_a.certificate()
    assert cert_resp_a.status_code == 200, cert_resp_a.text

    flow_b = Flow(acme_b, two_issuers.cfg, "svc-b.lan")
    flow_b.make_ready()
    flow_b.finalize_ok(csr_der("svc-b.lan"))
    cert_resp_b = flow_b.certificate()
    assert cert_resp_b.status_code == 200, cert_resp_b.text

    cert_id_a = int(flow_a.certificate_url.rsplit("/", 1)[1])
    cert_id_b = int(flow_b.certificate_url.rsplit("/", 1)[1])
    db = _db(two_issuers.cfg)
    try:
        row_a = certs_service.get_certificate(db, cert_id_a)
        row_b = certs_service.get_certificate(db, cert_id_b)
        assert row_a is not None and row_a.issuer_id == two_issuers.a
        assert row_b is not None and row_b.issuer_id == two_issuers.b
    finally:
        db.close()

    chain_a = x509.load_pem_x509_certificates(cert_resp_a.text.encode("ascii"))
    chain_b = x509.load_pem_x509_certificates(cert_resp_b.text.encode("ascii"))
    leaf_pem_a = chain_a[0].public_bytes(serialization.Encoding.PEM).decode("ascii")
    leaf_pem_b = chain_b[0].public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_chain_pem_a = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in chain_a[1:]
    )
    ca_chain_pem_b = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in chain_b[1:]
    )
    # Parsed, not compared as a string: the last certificate in each served
    # chain is that hierarchy's own root.
    assert chain_a[-1].public_bytes(serialization.Encoding.DER) == x509.load_pem_x509_certificate(
        two_issuers.hierarchy_a.root.cert_pem.encode("ascii")
    ).public_bytes(serialization.Encoding.DER)
    assert chain_b[-1].public_bytes(serialization.Encoding.DER) == x509.load_pem_x509_certificate(
        two_issuers.hierarchy_b.root.cert_pem.encode("ascii")
    ).public_bytes(serialization.Encoding.DER)

    assert _openssl_verify(tmp_path, "a-own", leaf_pem_a, ca_chain_pem_a)
    assert _openssl_verify(tmp_path, "b-own", leaf_pem_b, ca_chain_pem_b)
    # The counter-check: without this half, a build that hands out the same
    # trust store for both hierarchies would still pass.
    assert not _openssl_verify(tmp_path, "a-wrong", leaf_pem_a, ca_chain_pem_b)
    assert not _openssl_verify(tmp_path, "b-wrong", leaf_pem_b, ca_chain_pem_a)


def test_new_order_refused_when_the_accounts_issuer_is_retired(two_issuers: TwoIssuers) -> None:
    """'Also pin down' in this file's brief: an account whose issuer has
    been retired is refused at new-order, comprehensibly, rather than
    allowed to place an order it can never finalize. FR-9 replaces "does
    *any* active issuer exist" (0017's rule) with "is *this account's*
    issuer active" -- B stays active throughout, so a build still running
    the old rule would let this order through.
    """
    acme_a = acme_for(two_issuers, two_issuers.a)
    key = rsa_key()
    registered = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert registered.status_code == 201, registered.text
    kid = registered.headers["location"]

    db = _db(two_issuers.cfg)
    try:
        ca_service.retire(db, two_issuers.a)
    finally:
        db.close()

    placed = acme_a.post(
        "/acme/new-order",
        key,
        {"identifiers": [{"type": "dns", "value": "gone.lan"}]},
        kid=kid,
    )
    assert_problem(placed, "serverInternal", 500)
    assert "retire" in placed.text.lower(), placed.text

    db = _db(two_issuers.cfg)
    try:
        assert db.scalar(select(func.count()).select_from(AcmeOrder)) == 0
    finally:
        db.close()


def test_new_account_at_a_retired_issuer_is_refused(two_issuers: TwoIssuers) -> None:
    """FR-5: a *new* account at a retired issuer's directory is refused,
    naming the retirement, with no row created."""
    db = _db(two_issuers.cfg)
    try:
        ca_service.retire(db, two_issuers.a)
    finally:
        db.close()

    acme_a = acme_for(two_issuers, two_issuers.a)
    key = rsa_key()
    resp = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert_problem(resp, "unauthorized", 403)
    assert "retire" in resp.text.lower(), resp.text

    db = _db(two_issuers.cfg)
    try:
        assert acme_service.find_account_by_key(db, key.thumbprint()) is None
    finally:
        db.close()


def test_existing_account_may_still_reregister_at_a_retired_issuer(
    two_issuers: TwoIssuers,
) -> None:
    """FR-5's refusal sits on the creation path only: an account already
    bound to A keeps re-registering there after A is retired, and can still
    fetch what it was issued -- chain parsed, not just a 200."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    flow = Flow(acme_a, two_issuers.cfg, "svc.lan")
    flow.make_ready()
    cert_url = flow.finalize_ok(csr_der("svc.lan"))

    db = _db(two_issuers.cfg)
    try:
        ca_service.retire(db, two_issuers.a)
    finally:
        db.close()

    again = acme_a.post(acme_a.new_account_path, flow.key, {"termsOfServiceAgreed": True})
    assert again.status_code == 200, again.text
    assert again.headers["location"] == flow.kid

    fetched = flow.certificate(cert_url)
    assert fetched.status_code == 200, fetched.text
    chain = x509.load_pem_x509_certificates(fetched.text.encode("ascii"))
    assert len(chain) >= 2


# === AC-3: an EAB key is refused at the wrong directory, and not by the URL check =====


def test_eab_key_refused_at_another_issuers_directory(two_issuers: TwoIssuers) -> None:
    """AC-3, and the trap the whole file's docstring warns about.

    ``jws.parse_external_binding`` already refuses a binding whose inner
    JWS ``url`` is not the new-account URL cabin published, and after FR-2
    that URL contains the issuer id. It is tempting to conclude that a key
    minted for A therefore cannot be presented at B's directory. It can:
    the inner JWS is built and MACed by the client, with the secret the
    client holds -- so a client holding K's id and secret simply signs a
    fresh binding over **B's** URL instead of A's. That binding is
    structurally perfect (it parses, the ``url`` check passes, the MAC
    verifies), so it passes against an implementation with *no* issuer
    check on the EAB key at all. Only a comparison against the stored
    ``ca_certificate_id`` refuses it -- which is why the binding below is
    signed over B's URL, not A's.
    """
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)

    db = _db(two_issuers.cfg)
    try:
        key_row, secret = eab.create_key(
            db, _secrets(two_issuers.cfg), label="for-a", ca_certificate_id=two_issuers.a
        )
        key_id = key_row.id
    finally:
        db.close()
    mac_key = _mac_key(secret)

    account_key = rsa_key()
    binding_for_b = external_account_binding(
        kid=key_id,
        mac_key=mac_key,
        url=acme_b.url(acme_b.new_account_path),  # B's URL -- the trap
        jwk=account_key.jwk,
    )
    refused = acme_b.post(
        acme_b.new_account_path,
        account_key,
        {"termsOfServiceAgreed": True, "externalAccountBinding": binding_for_b},
    )
    assert_problem(refused, "unauthorized", 403)

    db = _db(two_issuers.cfg)
    try:
        assert acme_service.find_account_by_key(db, account_key.thumbprint()) is None
        row = eab.get_key(db, key_id)
        assert row is not None and row.bound_account_id is None
    finally:
        db.close()

    # Positive control, in the same test: K still works at A's own
    # directory. Without this half, "every binding is refused" would also
    # satisfy the assertions above.
    binding_for_a = external_account_binding(
        kid=key_id,
        mac_key=mac_key,
        url=acme_a.url(acme_a.new_account_path),
        jwk=account_key.jwk,
    )
    ok = acme_a.post(
        acme_a.new_account_path,
        account_key,
        {"termsOfServiceAgreed": True, "externalAccountBinding": binding_for_a},
    )
    assert ok.status_code == 201, ok.text
    db = _db(two_issuers.cfg)
    try:
        row = eab.get_key(db, key_id)
        assert row is not None and row.bound_account_id is not None
    finally:
        db.close()


# === AC-4: re-registration keeps the account where it was ======================


def test_reregistration_at_the_same_directory_still_returns_the_account(
    two_issuers: TwoIssuers,
) -> None:
    """AC-4 step 2 -- the certbot path. Without this half, the whole
    criterion is satisfiable by an implementation that refuses every
    re-registration."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    key = rsa_key()
    first = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert first.status_code == 201, first.text
    location = first.headers["location"]

    again = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert again.status_code == 200, again.text
    assert again.headers["location"] == location

    db = _db(two_issuers.cfg)
    try:
        count = db.scalar(
            select(func.count())
            .select_from(AcmeAccount)
            .where(AcmeAccount.jwk_thumbprint == key.thumbprint())
        )
        assert count == 1
    finally:
        db.close()


def test_reregistration_at_another_directory_is_refused(two_issuers: TwoIssuers) -> None:
    """AC-4 step 3, with a valid EAB key for B presented: the found
    account's issuer is A, the path's issuer is B, and the comparison
    refuses before the binding is even consulted."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    key = rsa_key()
    first = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert first.status_code == 201, first.text

    db = _db(two_issuers.cfg)
    try:
        key_row, secret = eab.create_key(
            db, _secrets(two_issuers.cfg), label="for-b", ca_certificate_id=two_issuers.b
        )
        key_id = key_row.id
    finally:
        db.close()
    binding = external_account_binding(
        kid=key_id,
        mac_key=_mac_key(secret),
        url=acme_b.url(acme_b.new_account_path),
        jwk=key.jwk,
    )
    again = acme_b.post(
        acme_b.new_account_path,
        key,
        {"termsOfServiceAgreed": True, "externalAccountBinding": binding},
    )
    assert_problem(again, "unauthorized", 403)


def test_reregistration_without_a_binding_at_another_directory_is_refused(
    two_issuers: TwoIssuers,
) -> None:
    """AC-4 step 3, without any binding: the half that goes red if FR-6's
    comparison sits *after* ``_external_account`` instead of before it --
    misplaced, a binding-less request at B would slip through exactly
    because no binding is required to reach the found-account branch.
    """
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    key = rsa_key()
    first = acme_a.post(acme_a.new_account_path, key, {"termsOfServiceAgreed": True})
    assert first.status_code == 201, first.text

    again = acme_b.post(acme_b.new_account_path, key, {"termsOfServiceAgreed": True})
    assert_problem(again, "unauthorized", 403)


def test_refused_reregistration_leaves_the_accounts_issuer_alone(
    two_issuers: TwoIssuers,
) -> None:
    """AC-4 step 4: after a refused cross-issuer re-registration, exactly
    one row for that thumbprint exists, its ``issuer_id`` is still A, and an
    order placed under it still finalizes from A -- proving the row was
    never touched rather than merely that the response looked like a
    refusal."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    flow = Flow(acme_a, two_issuers.cfg, "svc.lan")

    refused = acme_b.post(acme_b.new_account_path, flow.key, {"termsOfServiceAgreed": True})
    assert_problem(refused, "unauthorized", 403)

    db = _db(two_issuers.cfg)
    try:
        rows = db.scalars(
            select(AcmeAccount).where(AcmeAccount.jwk_thumbprint == flow.key.thumbprint())
        ).all()
        assert len(rows) == 1
        assert rows[0].issuer_id == two_issuers.a
    finally:
        db.close()

    flow.make_ready()
    cert_url = flow.finalize_ok(csr_der("svc.lan"))
    db = _db(two_issuers.cfg)
    try:
        row = certs_service.get_certificate(db, int(cert_url.rsplit("/", 1)[1]))
        assert row is not None and row.issuer_id == two_issuers.a
    finally:
        db.close()


def test_only_return_existing_at_another_directory_is_unauthorized_not_account_does_not_exist(
    two_issuers: TwoIssuers,
) -> None:
    """AC-5: ``onlyReturnExisting`` obeys the same boundary. Asserted on the
    problem *type*, because ``unauthorized`` and ``accountDoesNotExist`` say
    different things and only one of them is true here -- the account
    exists, just not at this directory."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    flow = Flow(acme_a, two_issuers.cfg, "svc.lan")

    own = acme_a.post(acme_a.new_account_path, flow.key, {"onlyReturnExisting": True})
    assert own.status_code == 200, own.text
    assert own.headers["location"] == flow.kid

    other = acme_b.post(acme_b.new_account_path, flow.key, {"onlyReturnExisting": True})
    assert_problem(other, "unauthorized", 403)

    db = _db(two_issuers.cfg)
    try:
        assert db.scalar(select(func.count()).select_from(AcmeAccount)) == 1
    finally:
        db.close()


# === AC-10: a key rollover does not move the account ============================


def test_key_change_keeps_the_issuer(two_issuers: TwoIssuers) -> None:
    """AC-10: after a ``key-change``, the row's ``issuer_id`` is still A,
    the new key resolves to the same account, and an order under the new
    key still finalizes from A."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    flow = Flow(acme_a, two_issuers.cfg, "svc.lan")
    new_key = ec_key("ES256")
    kc_url = acme_a.url("/acme/key-change")

    def inner(signer: object, jwk: dict[str, object], payload: dict[str, object]) -> dict:
        return flattened(signer, {"alg": signer.alg, "url": kc_url, "jwk": jwk}, payload)  # type: ignore[attr-defined]

    rolled = acme_a.post(
        "/acme/key-change",
        flow.key,
        inner(new_key, new_key.jwk, {"account": flow.kid, "oldKey": flow.key.jwk}),
        kid=flow.kid,
    )
    assert rolled.status_code == 200, rolled.text
    flow.key = new_key

    account_id = flow.kid.rsplit("/", 1)[1]
    db = _db(two_issuers.cfg)
    try:
        account = db.get(AcmeAccount, account_id)
        assert account is not None
        assert account.issuer_id == two_issuers.a
    finally:
        db.close()

    same = acme_a.post(acme_a.new_account_path, new_key, {"onlyReturnExisting": True})
    assert same.status_code == 200, same.text
    assert same.headers["location"] == flow.kid

    flow.make_ready()
    cert_url = flow.finalize_ok(csr_der("svc.lan"))
    db = _db(two_issuers.cfg)
    try:
        row = certs_service.get_certificate(db, int(cert_url.rsplit("/", 1)[1]))
        assert row is not None and row.issuer_id == two_issuers.a
    finally:
        db.close()


def test_key_change_conflict_is_global_across_issuers(two_issuers: TwoIssuers) -> None:
    """AC-10's second half, and the detector for the obvious-looking fix to
    FR-6: narrowing ``find_account_by_key`` by issuer would make this
    conflict invisible (each account "lives" only in its own issuer's
    view), turning the 409 RFC 8555 7.3.5 step 9 requires into a 500 when
    the account is later re-created with a thumbprint the unique index
    already holds. ``find_account_by_key`` must stay global, so a key
    already bound to an account at **B** still conflicts when named from a
    key-change signed at **A**."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    flow_a = Flow(acme_a, two_issuers.cfg, "one.lan")
    flow_b = Flow(acme_b, two_issuers.cfg, "two.lan")
    kc_url = acme_a.url("/acme/key-change")

    def inner(signer: object, jwk: dict[str, object], payload: dict[str, object]) -> dict:
        return flattened(signer, {"alg": signer.alg, "url": kc_url, "jwk": jwk}, payload)  # type: ignore[attr-defined]

    conflict = acme_a.post(
        "/acme/key-change",
        flow_a.key,
        inner(flow_b.key, flow_b.key.jwk, {"account": flow_a.kid, "oldKey": flow_a.key.jwk}),
        kid=flow_a.kid,
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.headers["location"] == flow_b.kid

    db = _db(two_issuers.cfg)
    try:
        account = db.get(AcmeAccount, flow_a.kid.rsplit("/", 1)[1])
        assert account is not None
        assert account.issuer_id == two_issuers.a
    finally:
        db.close()


# === AC-7: the boundary of FR-12, in both directions ============================


def test_ungranted_admin_obtains_no_certificate_over_acme_with_eab_required(
    two_issuers: TwoIssuers,
) -> None:
    """AC-7, first half. With ``acme_require_eab`` on and zero grant rows
    anywhere, an ordinary admin (not a superadmin) can neither mint an EAB
    key for A (403, FR-8's grant check) nor register at A's directory
    without one (``externalAccountRequired``) -- so no certificate is
    obtainable over ACME by an identity 0018 granted nothing. Read together
    with the next test: this half alone would also pass a build that simply
    broke ACME outright.
    """
    cfg, client = two_issuers.cfg, two_issuers.client
    db = _db(cfg)
    try:
        set_setting(db, ACME_REQUIRE_EAB, TRUE)
    finally:
        db.close()

    assert (
        client.post("/setup", data={"username": "root", "password": "correcthorse1"}).status_code
        == 303
    )
    root_csrf = _csrf_token(client, cfg)
    created = client.post(
        "/users",
        data={
            "username": "plain-admin",
            "password": "correcthorse1",
            "role": "admin",
            "csrf_token": root_csrf,
        },
    )
    assert created.status_code == 303, created.text
    client.post("/logout", data={"csrf_token": root_csrf})
    logged_in = client.post("/login", data={"username": "plain-admin", "password": "correcthorse1"})
    assert logged_in.status_code == 303, logged_in.text
    csrf = _csrf_token(client, cfg)

    denied = client.post(
        EAB_KEYS_PATH,
        data={"label": "x", "issuer_id": str(two_issuers.a), "csrf_token": csrf},
    )
    assert denied.status_code == 403, denied.text
    db = _db(cfg)
    try:
        assert db.scalar(select(func.count()).select_from(AcmeEabKey)) == 0
    finally:
        db.close()

    acme_a = acme_for(two_issuers, two_issuers.a)
    refused = acme_a.post(acme_a.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert_problem(refused, "externalAccountRequired", 403)
    db = _db(cfg)
    try:
        assert db.scalar(select(func.count()).select_from(AcmeAccount)) == 0
    finally:
        db.close()


def test_ungranted_admin_obtains_one_with_eab_not_required(two_issuers: TwoIssuers) -> None:
    """AC-7, second half -- the documented hole, asserted as such (FR-12,
    Out of Scope: "Forcing acme_require_eab on is not done"). With the
    switch OFF, the very same registration the previous test refused now
    succeeds and an order finalizes, with zero grant rows anywhere: no
    admin identity is involved at all, because an ACME account is anonymous
    by construction. This is not a bug this file exists to catch -- FR-12
    states it in writing, and a test that only asserted the first half
    would let a reader believe the hole was already closed.
    """
    db = _db(two_issuers.cfg)
    try:
        set_setting(db, ACME_REQUIRE_EAB, FALSE)
    finally:
        db.close()

    acme_a = acme_for(two_issuers, two_issuers.a)
    flow = Flow(acme_a, two_issuers.cfg, "open.lan")
    flow.make_ready()
    cert_url = flow.finalize_ok(csr_der("open.lan"))
    assert cert_url


# === AC-16: audit ===============================================================


def test_audit_account_created_records_the_issuer(two_issuers: TwoIssuers) -> None:
    """AC-16: ``acme_account_created``'s detail carries ``issuer_id`` equal
    to the directory the account registered at."""
    acme_b = acme_for(two_issuers, two_issuers.b)
    registered = acme_b.post(acme_b.new_account_path, rsa_key(), {"termsOfServiceAgreed": True})
    assert registered.status_code == 201, registered.text

    db = _db(two_issuers.cfg)
    try:
        event = db.scalars(
            select(AuditEvent).where(AuditEvent.action == AuditAction.acme_account_created)
        ).one()
        detail = event.detail
    finally:
        db.close()
    assert detail is not None
    assert detail["issuer_id"] == two_issuers.b


def test_refused_cross_issuer_registration_writes_no_audit_event(two_issuers: TwoIssuers) -> None:
    """AC-16: FR-6's refusal is deliberately not audited -- the request only
    needs a valid signature and a fresh nonce, so an audit event here would
    be a row a client can write in a loop. Asserted on the event count
    before and after, since a silently missing event and a deliberately
    absent one look identical any other way."""
    acme_a = acme_for(two_issuers, two_issuers.a)
    acme_b = acme_for(two_issuers, two_issuers.b)
    flow = Flow(acme_a, two_issuers.cfg, "svc.lan")

    db = _db(two_issuers.cfg)
    try:
        before = db.scalar(select(func.count()).select_from(AuditEvent))
    finally:
        db.close()

    refused = acme_b.post(acme_b.new_account_path, flow.key, {"termsOfServiceAgreed": True})
    assert_problem(refused, "unauthorized", 403)

    db = _db(two_issuers.cfg)
    try:
        after = db.scalar(select(func.count()).select_from(AuditEvent))
    finally:
        db.close()
    assert after == before
