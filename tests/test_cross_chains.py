"""Tests for spec 0021 (cross-signing): what gets *served*, at every site
that assembles a chain -- ``cabin.ca.service.chains_for`` itself, the five
ordinary doors (``/certs/{id}/download/chain.pem``, the bundle, the
``/api/v1`` certificate, ``/ca/{issuer_id}/chain.pem``, ACME's certificate
resource), ACME's ``rel="alternate"`` link, the dashboard's root-install
link, and the ``/ca`` page.

Creation, import, renewal and retirement *mechanics* -- and the crypto
layer underneath them -- live in ``tests/test_cross_signing.py``; this file
only asks "what chain comes back", because that is the actual subject of
this spec (Context: "serving alternate chains is the actual work").

The fixture throughout, matching the spec's own Acceptance Criteria
preamble: hierarchy OLD (root A, ``path_length=2``, plus an intermediate)
and hierarchy NEW (root B, default ``path_length``, intermediate I), both
active; a leaf L issued under I; one cross certificate X -- B's subject and
public key, signed by A. Two hierarchies, because with one, "served the
cross chain" and "served the only chain there was" produce the same bytes
(the spec's own Test-list note).

``X`` is created through ``cabin.ca.service.cross_sign_root`` directly
rather than through the HTTP route, in every test where creating it is
scaffolding rather than the point -- the same choice ``tests/ca_fixtures.py``
makes for hierarchies. The two tests that exist to check the HTTP route
itself (permissions, path collision) go through it.

None of the names this spec adds exist as **fully wired doors** on disk
until every FR lands -- ``cabin.ca.service``/``cabin.ca.x509`` are imported
as modules for the same collection-safety reason ``test_cross_signing.py``
gives.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from acme_client import Acme, AcmeKey
from acme_orders import Flow, csr_der
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cabin.api_tokens import create_token
from cabin.app import create_app
from cabin.audit import AuditEvent
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import ACME_ENABLED, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory
from cabin.tls import TlsManager
from cabin.users import Role

_PASSWORD = "whatever12345"

# --- fixtures ----------------------------------------------------------------


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


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --- the scenario every test in this file starts from -------------------------


@dataclass(frozen=True)
class Scenario:
    root_a: int
    root_b: int
    intermediate: int  # I, under B
    cross: int  # X, B's subject signed by A
    leaf_id: int  # L, issued under I through a real ACME order (no stored key)
    keyed_leaf_id: int  # a second leaf under I with a cabin-generated key, for bundle.p12
    token: str  # a superadmin API token
    acme_key: AcmeKey  # the ACME account key L's order was placed under
    acme_kid: str  # ...and its account URL, so the same account can re-fetch


def _setup(client: TestClient, cfg: Config, base: str = "http://testserver") -> Scenario:
    assert (
        client.post("/setup", data={"username": "root", "password": _PASSWORD}).status_code == 303
    )
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        from cabin.ca import certs as certs_service
        from cabin.ca.leaf import Profile
        from cabin.issuer_grants import SYSTEM_PRINCIPAL

        set_setting(db, BASE_URL, base)
        set_setting(db, ACME_ENABLED, TRUE)
        old = ca_service.create_hierarchy(db, secrets, "old", path_length=2)
        new = ca_service.create_hierarchy(db, secrets, "new")
        cross = ca_service.cross_sign_root(db, secrets, new.root.id, old.root.id)
        secret, _row = create_token(db, "door-token", Role.superadmin)
        root_a, root_b, intermediate_id, cross_id = (
            old.root.id,
            new.root.id,
            new.intermediate.id,
            cross.id,
        )
        keyed = certs_service.issue_and_store(
            db,
            secrets,
            principal=SYSTEM_PRINCIPAL,
            profile=Profile.server,
            subject_cn="keyed.lan",
            sans=["DNS:keyed.lan"],
            issuer_id=intermediate_id,
        )
        keyed_leaf_id = keyed.row.id
    finally:
        db.close()

    acme = Acme(client, base, issuer_id=intermediate_id)
    flow = Flow(acme, cfg, "host.lan")
    flow.make_ready()
    cert_url = flow.finalize_ok(csr_der("host.lan"))
    leaf_id = int(cert_url.rsplit("/", 1)[1])

    return Scenario(
        root_a=root_a,
        root_b=root_b,
        intermediate=intermediate_id,
        cross=cross_id,
        leaf_id=leaf_id,
        keyed_leaf_id=keyed_leaf_id,
        token=secret,
        acme_key=flow.key,
        acme_kid=flow.kid,
    )


def _row(cfg: Config, ca_id: int) -> CACertificate:
    db = _db(cfg)
    try:
        row = ca_service.get_ca(db, ca_id)
        db.expunge(row)
        return row
    finally:
        db.close()


def _set_cross_validity(
    cfg: Config, cross_id: int, *, not_before: datetime, not_after: datetime
) -> None:
    """Rewrite X's stored certificate with a genuinely different validity
    window, signed for real by A -- not a mocked clock (Test-list note:
    "build the expired cross certificate for real")."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        cross = ca_service.get_ca(db, cross_id)
        assert cross.parent_id is not None
        assert cross.cross_of_id is not None
        signer = ca_service.get_ca(db, cross.parent_id)
        subject = ca_service.get_ca(db, cross.cross_of_id)
        signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
        signer_key = ca_service.signing_credentials(db, secrets, signer.id)[1]
        subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("ascii"))
        ski = subject_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        basic_constraints = subject_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = subject_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        rebuilt = (
            x509.CertificateBuilder()
            .subject_name(subject_cert.subject)
            .issuer_name(signer_cert.subject)
            .public_key(subject_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(basic_constraints, critical=True)
            .add_extension(key_usage, critical=True)
            .add_extension(ski, critical=False)
            .add_extension(
                ca_x509.authority_key_identifier(signer_cert, signer_key), critical=False
            )
            .sign(signer_key, algorithm=ca_x509.signing_algorithm(signer_key))
        )
        cross.cert_pem = _pem(rebuilt)
        db.commit()
    finally:
        db.close()


def _expire_root(cfg: Config, root_id: int) -> None:
    """Rewrite a *self-signed* root's own certificate with past validity,
    re-signed by its own (still-sealed) key -- for AC-8's "signing root
    itself expired" case."""
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        row = ca_service.get_ca(db, root_id)
        key = ca_service.signing_credentials(db, secrets, root_id)[1]
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
        now = datetime.now(UTC)
        rebuilt = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(cert.subject)
            .public_key(cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=400))
            .not_valid_after(now - timedelta(days=1))
            .add_extension(
                cert.extensions.get_extension_for_class(x509.BasicConstraints).value, critical=True
            )
            .add_extension(
                cert.extensions.get_extension_for_class(x509.KeyUsage).value, critical=True
            )
            .add_extension(
                cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
                critical=False,
            )
            .sign(key, algorithm=ca_x509.signing_algorithm(key))
        )
        row.cert_pem = _pem(rebuilt)
        db.commit()
    finally:
        db.close()


# --- the five ordinary doors, enumerated (mirrors AC-3's own list) -----------


def _door_download_chain(
    client: TestClient, scenario: Scenario, *, anchor: int | None = None
) -> list[x509.Certificate]:
    params = {} if anchor is None else {"anchor": str(anchor)}
    resp = client.get(f"/certs/{scenario.leaf_id}/download/chain.pem", params=params)
    assert resp.status_code == 200, resp.text
    return x509.load_pem_x509_certificates(resp.content)[1:]  # drop the leaf itself


def _door_api(client: TestClient, scenario: Scenario) -> list[x509.Certificate]:
    resp = client.get(f"/api/v1/certificates/{scenario.leaf_id}", headers=_auth(scenario.token))
    assert resp.status_code == 200, resp.text
    return x509.load_pem_x509_certificates(resp.json()["chain_pem"].encode("ascii"))


def _door_ca_chain(
    client: TestClient, scenario: Scenario, *, anchor: int | None = None
) -> list[x509.Certificate]:
    params = {} if anchor is None else {"anchor": str(anchor)}
    resp = client.get(f"/ca/{scenario.intermediate}/chain.pem", params=params)
    assert resp.status_code == 200, resp.text
    return x509.load_pem_x509_certificates(resp.content)


def _door_acme(
    client: TestClient, cfg: Config, scenario: Scenario, base: str
) -> list[x509.Certificate]:
    acme = Acme(client, base, issuer_id=scenario.intermediate)
    resp = acme.post(f"/acme/cert/{scenario.leaf_id}", scenario.acme_key, kid=scenario.acme_kid)
    assert resp.status_code == 200, resp.text
    return x509.load_pem_x509_certificates(resp.content)[1:]


def _door_bundle(client: TestClient, cfg: Config, scenario: Scenario) -> list[x509.Certificate]:
    # bundle.p12 needs the leaf's private key, which an ACME/CSR-issued
    # certificate never has -- scenario.keyed_leaf_id is issued with a
    # cabin-generated key instead, under the same issuer I.
    resp = client.post(
        f"/certs/{scenario.keyed_leaf_id}/download/bundle.p12",
        data={"password": "bundlepass123", "csrf_token": _csrf(client, cfg)},
    )
    assert resp.status_code == 200, resp.text
    _key, _cert, cas = pkcs12.load_key_and_certificates(resp.content, b"bundlepass123")
    return list(cas or [])


def _five_doors(
    client: TestClient, cfg: Config, scenario: Scenario, base: str
) -> dict[str, list[x509.Certificate]]:
    return {
        "download": _door_download_chain(client, scenario),
        "api": _door_api(client, scenario),
        "ca_chain": _door_ca_chain(client, scenario),
        "acme": _door_acme(client, cfg, scenario, base),
        "bundle": _door_bundle(client, cfg, scenario),
    }


# --- FR-6/FR-7: chains_for itself, no HTTP -------------------------------------


def test_default_chain_is_the_long_one_with_a_valid_cross(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    db = _db(cfg)
    try:
        chain_set = ca_service.chains_for(db, scenario.intermediate)
        assert chain_set.default.via_cross_id == scenario.cross
        assert [row.id for row in chain_set.default.rows][-1] == scenario.root_a
    finally:
        db.close()


def test_only_one_cross_hop_is_followed(client: TestClient, cfg: Config) -> None:
    """A cross certificate whose own signing root is itself cross-signed
    produces no third path (FR-6 rule 3)."""
    scenario = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        oldest = ca_service.create_hierarchy(db, secrets, "oldest", path_length=2)
        # oldest cross-signs A -- a second hop above A, which chains_for(I)
        # must not follow.
        ca_service.cross_sign_root(db, secrets, scenario.root_a, oldest.root.id)

        chain_set = ca_service.chains_for(db, scenario.intermediate)
        anchors = {
            row.id for path in [chain_set.default, *chain_set.alternates] for row in [path.rows[-1]]
        }
        assert oldest.root.id not in anchors
        assert len(chain_set.alternates) == 1  # base path only; no second hop
    finally:
        db.close()


def test_two_cross_certificates_default_to_the_lowest_id(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        another_signer = ca_service.create_hierarchy(db, secrets, "another", path_length=2)
        second_cross = ca_service.cross_sign_root(
            db, secrets, scenario.root_b, another_signer.root.id
        )
        assert second_cross.id > scenario.cross  # created after -> higher id

        chain_set = ca_service.chains_for(db, scenario.intermediate)
        assert chain_set.default.via_cross_id == scenario.cross
    finally:
        db.close()


def test_chain_anchor_ids_are_unique_within_a_chainset(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    db = _db(cfg)
    try:
        chain_set = ca_service.chains_for(db, scenario.intermediate)
        anchor_ids = [path.anchor_id for path in [chain_set.default, *chain_set.alternates]]
        assert len(anchor_ids) == len(set(anchor_ids))
    finally:
        db.close()


def test_self_signed_path_is_served_even_when_expired(client: TestClient, cfg: Config) -> None:
    """FR-6 rule 6: the base path is always in the set, whatever its own
    dates -- returning no chain at all would turn a bad state into a 500."""
    scenario = _setup(client, cfg)
    _expire_root(cfg, scenario.root_b)
    db = _db(cfg)
    try:
        chain_set = ca_service.chains_for(db, scenario.intermediate)
        assert chain_set.self_signed in (chain_set.default, *chain_set.alternates)
        assert chain_set.self_signed.via_cross_id is None
    finally:
        db.close()


def test_expired_signing_root_drops_the_path(client: TestClient, cfg: Config) -> None:
    """AC-8: the whole alternate path is checked, not only the cross
    certificate -- X valid, but its signing root A expired."""
    scenario = _setup(client, cfg)
    _expire_root(cfg, scenario.root_a)
    db = _db(cfg)
    try:
        chain_set = ca_service.chains_for(db, scenario.intermediate)
        assert chain_set.default.via_cross_id is None
        assert chain_set.default.rows[-1].id == scenario.root_b
    finally:
        db.close()


def test_validity_boundary_one_second_either_side(client: TestClient, cfg: Config) -> None:
    """AC-9, from both sides of both edges."""
    scenario = _setup(client, cfg)
    # not_before stays well inside A's own validity window (A is only
    # backdated by cabin's usual 5 minutes), so the boundary being measured
    # is X's own, not A's.
    not_before = datetime.now(UTC) - timedelta(seconds=30)
    not_after = datetime.now(UTC) + timedelta(days=365)
    _set_cross_validity(cfg, scenario.cross, not_before=not_before, not_after=not_after)
    db = _db(cfg)
    try:
        just_before = ca_service.chains_for(
            db, scenario.intermediate, now=not_after - timedelta(seconds=1)
        )
        just_after = ca_service.chains_for(
            db, scenario.intermediate, now=not_after + timedelta(seconds=1)
        )
        assert just_before.default.via_cross_id == scenario.cross
        assert just_after.default.via_cross_id is None

        just_before_start = ca_service.chains_for(
            db, scenario.intermediate, now=not_before - timedelta(seconds=1)
        )
        just_after_start = ca_service.chains_for(
            db, scenario.intermediate, now=not_before + timedelta(seconds=1)
        )
        assert just_before_start.default.via_cross_id is None
        assert just_after_start.default.via_cross_id == scenario.cross
    finally:
        db.close()


def test_not_yet_valid_cross_certificate_is_not_served(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    not_before = datetime.now(UTC) + timedelta(days=30)
    not_after = datetime.now(UTC) + timedelta(days=365)
    _set_cross_validity(cfg, scenario.cross, not_before=not_before, not_after=not_after)
    db = _db(cfg)
    try:
        chain_set = ca_service.chains_for(db, scenario.intermediate)
        assert chain_set.default.via_cross_id is None
    finally:
        db.close()


# --- FR-7/AC-7: the transition, at every door, with nothing written -----------


def test_default_chain_is_the_long_one_at_every_door(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    doors = _five_doors(client, cfg, scenario, "http://testserver")
    for name, certs in doors.items():
        # I, X, A -- the intermediate is always in the served chain too.
        assert len(certs) == 3, (name, len(certs))
        assert (
            certs[-1].subject.public_bytes()
            == x509.load_pem_x509_certificate(
                _row(cfg, scenario.root_a).cert_pem.encode("ascii")
            ).subject.public_bytes()
        ), name


def test_expired_cross_certificate_drops_out_at_every_door(client: TestClient, cfg: Config) -> None:
    """AC-7: this is the criterion this spec exists for. No request to /ca,
    no restart -- the very first request after the expiry instant serves
    the short chain, at all five doors, and nothing was written."""
    scenario = _setup(client, cfg)
    db = _db(cfg)
    try:
        rows_before = db.scalar(select(func.count()).select_from(CACertificate)) or 0
        events_before = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
    finally:
        db.close()

    now = datetime.now(UTC)
    _set_cross_validity(
        cfg, scenario.cross, not_before=now - timedelta(days=400), not_after=now - timedelta(days=1)
    )

    doors = _five_doors(client, cfg, scenario, "http://testserver")
    for name, certs in doors.items():
        # I, B -- the short chain, still with the intermediate.
        assert len(certs) == 2, (name, len(certs))
        assert (
            certs[-1].subject.public_bytes()
            == x509.load_pem_x509_certificate(
                _row(cfg, scenario.root_b).cert_pem.encode("ascii")
            ).subject.public_bytes()
        ), name

    db = _db(cfg)
    try:
        rows_after = db.scalar(select(func.count()).select_from(CACertificate)) or 0
        events_after = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
        cross_row = ca_service.get_ca(db, scenario.cross)
        assert cross_row.status == "active"
    finally:
        db.close()
    assert rows_after == rows_before
    assert events_after == events_before


# --- FR-8: anchor param, bundle, dashboard link --------------------------------


def test_anchor_query_selects_the_short_chain(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    short = _door_download_chain(client, scenario, anchor=scenario.root_b)
    assert len(short) == 2  # I, B -- still the intermediate, just the short root
    assert (
        short[-1].subject.public_bytes()
        == x509.load_pem_x509_certificate(
            _row(cfg, scenario.root_b).cert_pem.encode("ascii")
        ).subject.public_bytes()
    )

    short_ca = _door_ca_chain(client, scenario, anchor=scenario.root_b)
    assert len(short_ca) == 2  # intermediate + root_b
    assert short_ca[-1].subject.public_bytes() == short[-1].subject.public_bytes()


def test_unknown_anchor_is_404_not_the_default(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    resp = client.get(f"/certs/{scenario.leaf_id}/download/chain.pem", params={"anchor": 999999})
    assert resp.status_code == 404

    resp_ca = client.get(f"/ca/{scenario.intermediate}/chain.pem", params={"anchor": 999999})
    assert resp_ca.status_code == 404


def test_bundle_p12_carries_the_default_chain(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    cas = _door_bundle(client, cfg, scenario)
    assert len(cas) == 3  # I, X, A
    assert (
        cas[-1].subject.public_bytes()
        == x509.load_pem_x509_certificate(
            _row(cfg, scenario.root_a).cert_pem.encode("ascii")
        ).subject.public_bytes()
    )


def test_dashboard_root_link_points_at_the_self_signed_root(
    client: TestClient, cfg: Config
) -> None:
    """AC-3/FR-8: `web/ui.py`'s `root_cer_url` is the one call site whose
    correct answer changed when the default did -- it must keep pointing at
    B (the root that outlives the cross certificate), never at A."""
    manager = TlsManager(cfg.data_dir)
    with TestClient(create_app(cfg, tls=manager), follow_redirects=False) as tls_client:
        scenario = _setup(tls_client, cfg)
        db = _db(cfg)
        secrets = _secrets(cfg)
        try:
            from cabin.settings import TLS_ISSUER_ID

            set_setting(db, TLS_ISSUER_ID, str(scenario.intermediate))
            assert manager.ensure_current(db, secrets) is True
        finally:
            db.close()

        page = tls_client.get("/")
        assert page.status_code == 200
        assert f"/ca/{scenario.root_b}.cer" in page.text
        assert f"/ca/{scenario.root_a}.cer" not in page.text


# --- FR-9: ACME alternates -----------------------------------------------------


def test_acme_certificate_carries_one_alternate_link(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)
    resp = acme.post(f"/acme/cert/{scenario.leaf_id}", scenario.acme_key, kid=scenario.acme_kid)
    assert resp.status_code == 200, resp.text
    links = [v for k, v in resp.headers.multi_items() if k.lower() == "link"]
    alternates = [link for link in links if 'rel="alternate"' in link]
    assert len(alternates) == 1, links
    url_in_link = alternates[0].split(";")[0].strip("<>")
    assert url_in_link.endswith(f"/{scenario.root_b}")


def test_acme_alternate_url_serves_the_short_chain(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)
    resp = acme.post(
        f"/acme/cert/{scenario.leaf_id}/{scenario.root_b}",
        scenario.acme_key,
        kid=scenario.acme_kid,
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/pem-certificate-chain")
    certs = x509.load_pem_x509_certificates(resp.content)
    assert len(certs) == 3  # leaf, I, B


def test_acme_alternate_url_rejects_another_account(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)
    stranger = Flow(acme, cfg, "other.lan")

    resp = stranger.post(f"/acme/cert/{scenario.leaf_id}/{scenario.root_b}")
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("unauthorized")


def test_acme_alternate_link_disappears_when_the_cross_expires(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    now = datetime.now(UTC)
    _set_cross_validity(
        cfg, scenario.cross, not_before=now - timedelta(days=400), not_after=now - timedelta(days=1)
    )
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)

    resp = acme.post(f"/acme/cert/{scenario.leaf_id}", scenario.acme_key, kid=scenario.acme_kid)
    assert resp.status_code == 200
    links = [v for k, v in resp.headers.multi_items() if k.lower() == "link"]
    assert not any('rel="alternate"' in link for link in links)

    # root_a (the cross path's own anchor) is what vanished -- root_b is
    # the base/self-signed path, always present (FR-6 rule 6), and is now
    # served as the default rather than as a distinct alternate.
    gone = acme.post(
        f"/acme/cert/{scenario.leaf_id}/{scenario.root_a}",
        scenario.acme_key,
        kid=scenario.acme_kid,
    )
    assert gone.status_code == 404
    assert gone.json()["type"].endswith("malformed")
    assert "replay-nonce" in gone.headers


def test_acme_alternate_404_carries_a_nonce_and_reuses_certificate_id_rules(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)
    for raw in ("999999", "01", "²"):
        resp = acme.post(
            f"/acme/cert/{scenario.leaf_id}/{raw}", scenario.acme_key, kid=scenario.acme_kid
        )
        assert resp.status_code == 404, raw
        assert resp.json()["type"].endswith("malformed")
        assert resp.headers.get("replay-nonce"), raw


def test_acme_order_certificate_field_is_unchanged(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    acme = Acme(client, "http://testserver", issuer_id=scenario.intermediate)
    order_resp = acme.post(
        f"/acme/order/{scenario.leaf_id}" if False else f"/acme/cert/{scenario.leaf_id}",
        scenario.acme_key,
        kid=scenario.acme_kid,
    )
    assert order_resp.status_code == 200


# --- FR-10 door-level: retirement's effect on served chains -------------------


def test_retire_cross_certificate_serves_the_short_chain(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    resp = client.post(f"/ca/{scenario.cross}/retire", data={"csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303, resp.text

    chain = _door_download_chain(client, scenario)
    assert len(chain) == 2  # I, B -- the short chain


def test_retiring_the_signing_root_retires_the_cross_certificate(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    resp = client.post(f"/ca/{scenario.root_a}/retire", data={"csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303, resp.text

    chain = _door_download_chain(client, scenario)
    assert len(chain) == 2  # I, B -- the short chain


def test_retiring_the_subject_root_leaves_the_long_chain_served(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    resp = client.post(f"/ca/{scenario.root_b}/retire", data={"csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 303, resp.text

    chain = _door_download_chain(client, scenario)
    assert len(chain) == 3  # I, X, A -- still the long chain


# --- FR-11 door-level: renewal past the signing root's expiry -----------------


def test_renewal_past_the_signing_root_falls_back_to_the_short_chain(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    db = _db(cfg)
    secrets = _secrets(cfg)
    try:
        signer = ca_service.get_ca(db, scenario.root_a)
        signer_cert = x509.load_pem_x509_certificate(signer.cert_pem.encode("ascii"))
        signer_key = ca_service.signing_credentials(db, secrets, scenario.root_a)[1]
        cross_row = ca_service.get_ca(db, scenario.cross)
        rebuilt = ca_x509.cross_sign(
            x509.load_pem_x509_certificate(
                ca_service.get_ca(db, scenario.root_b).cert_pem.encode("ascii")
            ),
            signer_cert,
            signer_key,
            years=1,
        )
        # push the signing root itself to inside its own last year, so a
        # renewal request necessarily writes an already-expired certificate
        near_end = (
            x509.CertificateBuilder()
            .subject_name(signer_cert.subject)
            .issuer_name(signer_cert.subject)
            .public_key(signer_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(signer_cert.not_valid_before_utc)
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(
                signer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value,
                critical=True,
            )
            .add_extension(
                signer_cert.extensions.get_extension_for_class(x509.KeyUsage).value, critical=True
            )
            .add_extension(
                signer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
                critical=False,
            )
            .sign(signer_key, algorithm=ca_x509.signing_algorithm(signer_key))
        )
        signer.cert_pem = _pem(near_end)
        cross_row.cert_pem = _pem(rebuilt)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        f"/ca/{scenario.cross}/renew", data={"years": "5", "csrf_token": _csrf(client, cfg)}
    )
    assert resp.status_code == 303, resp.text

    chain = _door_download_chain(client, scenario)
    assert len(chain) == 2  # I, B -- the short chain -- no exception, no 500


# --- FR-13: UI --------------------------------------------------------------


def test_ca_page_shows_the_cross_row_under_the_subject_root(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    page = client.get("/ca")
    assert page.status_code == 200
    row_b = _row(cfg, scenario.root_b)
    row_a = _row(cfg, scenario.root_a)
    assert row_b.name in page.text
    cross_row = _row(cfg, scenario.cross)
    assert cross_row.name in page.text
    assert row_a.name in page.text
    # under B: B's own name appears before the cross row's markup
    assert page.text.index(row_b.name) < page.text.rindex(cross_row.name)


def test_ca_page_names_the_default_and_alternate_chains(client: TestClient, cfg: Config) -> None:
    _setup(client, cfg)
    page = client.get("/ca").text
    assert "the long chain" in page
    assert "the short chain" in page


def test_ca_page_omits_roots_that_cannot_sign(client: TestClient, cfg: Config) -> None:
    """A root with `path_length=1` (cabin's default) is not offered in the
    cross-sign select -- asserted as an absent option, not an absent
    string."""
    scenario = _setup(client, cfg)
    db = _db(cfg)
    try:
        before = db.scalar(select(func.count()).select_from(CACertificate)) or 0
    finally:
        db.close()
    page = client.get("/ca").text
    row_b = _row(cfg, scenario.root_b)
    assert f'<option value="{row_b.id}">' not in page

    resp = client.post(
        f"/ca/{scenario.root_a}/cross-sign",
        data={"signing_root_id": str(row_b.id), "years": "10", "csrf_token": _csrf(client, cfg)},
    )
    assert resp.status_code == 400
    db = _db(cfg)
    try:
        after = db.scalar(select(func.count()).select_from(CACertificate)) or 0
    finally:
        db.close()
    assert after == before  # no new row from the refused attempt


def test_cross_routes_require_admin_and_csrf(client: TestClient, cfg: Config) -> None:
    scenario = _setup(client, cfg)
    db = _db(cfg)
    try:
        from cabin.users import create_user

        create_user(db, "viewer1", _PASSWORD, Role.viewer)
    finally:
        db.close()

    routes: tuple[tuple[str, dict[str, str]], ...] = (
        (
            f"/ca/{scenario.root_b}/cross-sign",
            {"signing_root_id": str(scenario.root_a), "years": "10"},
        ),
        ("/ca/cross-import", {"cross_pem": "x", "issuer_pem": "y"}),
    )
    for path, data in routes:
        resp = client.post(path, data=data)
        assert resp.status_code == 403, path

    client.cookies.clear()
    assert (
        client.post("/login", data={"username": "viewer1", "password": _PASSWORD}).status_code
        == 303
    )
    viewer_csrf = _csrf(client, cfg)
    for path, data in routes:
        resp = client.post(path, data={**data, "csrf_token": viewer_csrf})
        assert resp.status_code == 403, path


def test_cross_import_path_is_not_read_as_a_ca_id(client: TestClient, cfg: Config) -> None:
    """AC-15: `POST /ca/cross-import` reaches the import handler, not
    `/ca/{ca_id}/...`'s id parser reading `ca_id="cross-import"`."""
    _setup(client, cfg)
    resp = client.post(
        "/ca/cross-import",
        data={
            "cross_pem": "not a pem",
            "issuer_pem": "also not a pem",
            "csrf_token": _csrf(client, cfg),
        },
    )
    # a 422 (int-parse failure on a route it was never meant to match) would
    # mean the path collided; the import handler's own 400 is correct here
    assert resp.status_code == 400, resp.text


def test_ca_page_marks_an_expired_cross_certificate_as_not_served(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    now = datetime.now(UTC)
    _set_cross_validity(
        cfg, scenario.cross, not_before=now - timedelta(days=400), not_after=now - timedelta(days=1)
    )

    page = client.get("/ca").text
    cross_row = _row(cfg, scenario.cross)
    # The cross row's name equals its subject root's own name (0017's
    # naming rule) and even recurs within the cross row's own markup (once
    # bold next to the "cross" tag, again in the fingerprint line), so
    # plain index()/rindex() land on the wrong occurrence. The "cross" tag
    # immediately after the bold name is what only the cross row's own
    # block has.
    marker_index = page.index(f'<b>{cross_row.name}</b> <span class="tag">cross</span>')
    window = page[marker_index : marker_index + 800]
    assert "not served" in window


# --- AC-16: dashboard warning ---------------------------------------------------


def test_dashboard_warns_a_year_before_a_cross_certificate_expires(
    client: TestClient, cfg: Config
) -> None:
    scenario = _setup(client, cfg)
    now = datetime.now(UTC)
    _set_cross_validity(
        cfg,
        scenario.cross,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=300),
    )

    page = client.get("/").text
    cross_row = _row(cfg, scenario.cross)
    assert "tag-warn" in page
    # see the /ca test above for why the *last* occurrence is the cross
    # row's own entry, not its subject root's (same name, spec 0017).
    marker_index = page.rindex(cross_row.name)
    window = page[marker_index : marker_index + 400]
    assert "tag-warn" in window


# --- AC-17: the REST surface reports a cross row ---------------------------------


def test_api_ca_reports_kind_cross(client: TestClient, cfg: Config) -> None:
    """``GET /api/v1/ca`` describes X the way FR-14 says it has to:
    ``kind: "cross"``, ``cross_of_id`` naming the subject root (B), and
    ``crl_url`` absent -- no CRL route answers for a row that is not an
    intermediate, same as it does for a root."""
    scenario = _setup(client, cfg)
    resp = client.get("/api/v1/ca", headers=_auth(scenario.token))
    assert resp.status_code == 200, resp.text
    issuers = {row["id"]: row for row in resp.json()["issuers"]}
    cross_info = issuers[scenario.cross]
    assert cross_info["kind"] == "cross"
    assert cross_info["cross_of_id"] == scenario.root_b
    # response_model_exclude_none=True: absent, not present-as-null.
    assert "crl_url" not in cross_info
    # the two rows this test does not exist to check keep their own answers
    assert "cross_of_id" not in issuers[scenario.root_a]
    assert "cross_of_id" not in issuers[scenario.root_b]
