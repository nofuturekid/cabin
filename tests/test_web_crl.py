"""Web-layer tests for spec 0007's public CRL endpoint and revoke form, now
rewritten for spec 0017: FR-10 (``/crl/{issuer_id}[.pem]``, ``/ca/{ca_id}.cer``,
replacing the singleton ``/crl``/``/crl.pem`` with no alias), FR-11 (AIA
``caIssuers``) and FR-12 (CDP/AIA URLs forced to ``http://``).

The scheme-forcing itself (``public_http_origin``) and the AIA extension's
shape are unit-tested against real certificates in ``test_ca_leaf.py``,
without a database. This file is the HTTP layer on top: routes, status
codes, headers, and -- because ``web/crl_ui.py`` is deliberately the one
router with no authentication dependency -- that the public routes answer
without a session and answer *identically* with an invalid one, and that
the authenticated ``/ca/{id}.pem`` route does not accidentally shadow the
public ``/ca/{id}.cer`` one (spec 0017 work split R8).
"""

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import ca_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import leaf
from cabin.ca import service as ca_service
from cabin.ca.certs import get_certificate
from cabin.ca.crl import CRLState
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory

BASE_URL = "https://ca.example.org"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    factory = create_session_factory(cfg.db_url)
    return factory()


def _secrets(cfg: Config) -> SecretStore:
    """The same store the running app uses (``SecretStore.open`` is
    idempotent: it reads back the key file the app's lifespan already
    created), so a hierarchy built directly against the ORM here is signed
    with a key the app can also unseal."""
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _create_ca(client: TestClient, cfg: Config) -> None:
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _hierarchy(cfg: Config, name: str = "cabin") -> ca_fixtures.CAHierarchy:
    """A fresh, fully-keyed root+intermediate, built directly against the
    ORM (the spec 0017 Phase 0 shared fixture module) rather than through
    ``POST /ca/create``.

    These tests exercise ``web/crl_ui.py`` (Security's), not ``web/ca_ui.py``
    (Frontend's) -- going straight to the database keeps them from failing
    for reasons that have nothing to do with the CRL/AIA endpoints, and lets
    more than one hierarchy exist, which the old singleton-CA route (still
    guarded by ``CAExistsError`` today) cannot yet do.
    """
    db = _db(cfg)
    try:
        return ca_fixtures.make_hierarchy(db, _secrets(cfg), name)
    finally:
        db.close()


def _parse_cert(row: CACertificate) -> x509.Certificate:
    return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))


def _sole_intermediate_id(cfg: Config) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(select(CACertificate).where(CACertificate.kind == "intermediate")).one()
        return row.id
    finally:
        db.close()


def _create_viewer(client: TestClient, cfg: Config) -> None:
    resp = client.post(
        "/users",
        data={
            "username": "vera",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _issue(client: TestClient, cfg: Config, cn: str = "nas.lan") -> int:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": cn,
            "profile": "server",
            "key_type": "ecdsa-p256",
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _sign_csr(client: TestClient, cfg: Config, cn: str = "csr.lan") -> int:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _set_base_url(client: TestClient, cfg: Config, value: str) -> int:
    resp = client.post(
        "/settings",
        data={"base_url": value, "csrf_token": _csrf(client, cfg)},
    )
    return resp.status_code


def _revoke(
    client: TestClient,
    cfg: Config,
    cert_id: int,
    reason: str = "key_compromise",
    confirm: bool = True,
) -> int:
    data = {"reason": reason, "csrf_token": _csrf(client, cfg)}
    if confirm:
        data["confirm"] = "on"
    return client.post(f"/certs/{cert_id}/revoke", data=data).status_code


def _cert(cfg: Config, cert_id: int) -> x509.Certificate:
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    finally:
        db.close()


def _serial(cfg: Config, cert_id: int) -> int:
    return _cert(cfg, cert_id).serial_number


def _cdp_urls(cert: x509.Certificate) -> list[str]:
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert cdp.critical is False  # a CDP is informational, never critical
    urls: list[str] = []
    for point in cdp.value:
        assert point.full_name is not None
        urls.extend(
            name.value
            for name in point.full_name
            if isinstance(name, x509.UniformResourceIdentifier)
        )
    return urls


# --- FR-10, AC-8/AC-10: the public CRL and CA-certificate endpoints -------------


def test_old_crl_routes_are_gone(client: TestClient, cfg: Config) -> None:
    """AC-10: ``/crl`` and ``/crl.pem`` are removed with no alias -- a plain
    404, not a redirect to the per-issuer route. A relying party that still
    has the old URL baked into config must fail loudly, not be silently
    carried along by a 30x that happens to work today."""
    for path in ("/crl", "/crl.pem"):
        resp = client.get(path)
        assert resp.status_code == 404, path
        assert "location" not in resp.headers, path

    _setup_superadmin(client)
    _hierarchy(cfg)
    client.cookies.clear()
    for path in ("/crl", "/crl.pem"):
        resp = client.get(path)
        assert resp.status_code == 404, path
        assert "location" not in resp.headers, path


def test_crl_endpoint_404_without_ca(client: TestClient, cfg: Config) -> None:
    """Without any CA there is no issuer id to look CRL state up against --
    and, with zero users, the first-run redirect must still not swallow a
    public route."""
    for path in ("/crl/1", "/crl/1.pem"):
        resp = client.get(path)
        assert resp.status_code == 404, path

    _setup_superadmin(client)
    client.cookies.clear()
    assert client.get("/crl/1").status_code == 404


def test_crl_route_404_for_root_and_unknown(client: TestClient, cfg: Config) -> None:
    """AC-10: a root id (not an intermediate -- it never signs a CRL) and an
    unknown id are both 404, DER and PEM alike. Interface Contract: both
    routes declare ``{issuer_id:int}``, so a non-numeric id is a 404 too --
    not the 422 a plain ``{issuer_id}`` path parameter would produce trying
    to coerce "abc" (or "7.pem", see test_crl_pem_route_is_not_swallowed_by
    _the_der_route below) into an int."""
    hierarchy = _hierarchy(cfg)
    client.cookies.clear()

    assert client.get(f"/crl/{hierarchy.root.id}").status_code == 404
    assert client.get(f"/crl/{hierarchy.root.id}.pem").status_code == 404
    assert client.get("/crl/999999").status_code == 404
    assert client.get("/crl/999999.pem").status_code == 404
    assert client.get("/crl/abc").status_code == 404
    assert client.get("/crl/abc.pem").status_code == 404
    assert client.get("/crl/7.5").status_code == 404


def test_crl_pem_route_is_not_swallowed_by_the_der_route(client: TestClient, cfg: Config) -> None:
    """Interface Contract: without the ``:int`` convertor on BOTH CRL
    routes, the plain-string DER route (``^/crl/(?P<issuer_id>[^/]+)$``)
    also matches ``/crl/{id}.pem`` -- "7.pem" is one path segment -- so
    whichever route is registered first can swallow the other and answer
    422 from the wrong handler. Checked explicitly here, not merely
    inferred from the content-type assertion in test_crl_route_per_issuer:
    a 422 there would fail on content-type too, but for a less legible
    reason than "wrong status code entirely"."""
    hierarchy = _hierarchy(cfg)
    client.cookies.clear()

    resp = client.get(f"/crl/{hierarchy.intermediate.id}.pem")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    assert resp.text.startswith("-----BEGIN X509 CRL-----")


def test_crl_route_per_issuer(client: TestClient, cfg: Config) -> None:
    """AC-10: two issuers serve two distinct CRLs, both without a session
    and both cached; an invalid session cookie changes nothing about the
    answer -- this route has no business inspecting the cookie at all."""
    h1 = _hierarchy(cfg, "Alpha")
    h2 = _hierarchy(cfg, "Beta")
    client.cookies.clear()

    resp1 = client.get(f"/crl/{h1.intermediate.id}")
    resp2 = client.get(f"/crl/{h2.intermediate.id}")

    for resp in (resp1, resp2):
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/pkix-crl")
        assert resp.headers["cache-control"] == "public, max-age=3600"

    crl1 = x509.load_der_x509_crl(resp1.content)
    crl2 = x509.load_der_x509_crl(resp2.content)
    assert crl1.issuer == _parse_cert(h1.intermediate).subject
    assert crl2.issuer == _parse_cert(h2.intermediate).subject
    # genuinely two different, independently-signed CRLs -- not one CRL
    # served twice under two different ids.
    assert crl1.issuer != crl2.issuer
    assert crl1.signature != crl2.signature

    pem1 = client.get(f"/crl/{h1.intermediate.id}.pem")
    assert pem1.status_code == 200
    assert pem1.headers["content-type"].startswith("application/x-pem-file")
    assert x509.load_pem_x509_crl(pem1.content).issuer == crl1.issuer

    client.cookies.set("cabin_session", "not-a-real-session-token")
    same = client.get(f"/crl/{h1.intermediate.id}")
    assert same.status_code == resp1.status_code == 200
    assert same.content == resp1.content
    assert same.headers["content-type"] == resp1.headers["content-type"]


def _age_stored_crl(cfg: Config, issuer_id: int, by: timedelta) -> None:
    db = _db(cfg)
    try:
        state = db.get(CRLState, issuer_id)
        assert state is not None
        state.generated_at = state.generated_at - by
        db.commit()
    finally:
        db.close()


def test_crl_lazy_regeneration_is_per_issuer(client: TestClient, cfg: Config) -> None:
    """AC-10: a stale stored CRL is rebuilt on the next access -- and doing
    so for one issuer must not touch the other issuer's ``crl_number``. Once
    the CRL state is keyed by issuer_id, two issuers no longer serialize on
    the same row (spec 0017 work split R2), so this is worth checking in
    both directions, not assumed from the single-issuer case."""
    h1 = _hierarchy(cfg, "Alpha")
    h2 = _hierarchy(cfg, "Beta")
    client.cookies.clear()
    assert client.get(f"/crl/{h1.intermediate.id}").status_code == 200
    assert client.get(f"/crl/{h2.intermediate.id}").status_code == 200

    db = _db(cfg)
    try:
        state1 = db.get(CRLState, h1.intermediate.id)
        state2 = db.get(CRLState, h2.intermediate.id)
        assert state1 is not None
        assert state2 is not None
        first_number_1 = state1.crl_number
        first_number_2 = state2.crl_number
    finally:
        db.close()

    _age_stored_crl(cfg, h1.intermediate.id, timedelta(days=8))

    resp = client.get(f"/crl/{h1.intermediate.id}")
    assert resp.status_code == 200
    regenerated = x509.load_der_x509_crl(resp.content)
    assert (
        regenerated.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        > first_number_1
    )

    db = _db(cfg)
    try:
        state2_after = db.get(CRLState, h2.intermediate.id)
        assert state2_after is not None
        assert state2_after.crl_number == first_number_2
    finally:
        db.close()


def _swap_ca_key(cfg: Config, sealed: str | None = None, *, issuer_id: int | None = None) -> str:
    """Swap the given intermediate's sealed key for one that fails GCM
    authentication (or put the original back), the way a restored backup with
    the wrong master key would. Returns the value that was there before.

    Takes an explicit issuer_id (spec 0017 work split R7) rather than
    ``.where(kind == "intermediate").one()``: with more than one
    intermediate in the database, ``.one()`` raises MultipleResultsFound --
    a failure that would show up far from here, in whichever multi-issuer
    test happened to run after this file. Defaulting to the lowest id keeps
    every existing single-hierarchy call site unchanged.
    """
    db = _db(cfg)
    try:
        if issuer_id is not None:
            row = db.get(CACertificate, issuer_id)
        else:
            row = db.scalars(
                select(CACertificate)
                .where(CACertificate.kind == "intermediate")
                .order_by(CACertificate.id)
            ).first()
        assert row is not None
        original = row.key_sealed
        assert original is not None
        row.key_sealed = sealed if sealed is not None else "A" * 40
        db.commit()
        return original
    finally:
        db.close()


def test_crl_survives_an_unusable_ca_key(client: TestClient, cfg: Config) -> None:
    """FR-5/FR-9: a CRL that cannot be re-signed is still worth serving. A
    relying party that cannot fetch one may fail closed, so the last good
    CRL beats a 500 -- but there must be no pretending when nothing was ever
    published for this issuer."""
    hierarchy = _hierarchy(cfg)
    issuer_id = hierarchy.intermediate.id
    original = _swap_ca_key(cfg, issuer_id=issuer_id)
    client.cookies.clear()

    # nothing stored yet and no key to sign with: say so, don't invent a CRL
    assert client.get(f"/crl/{issuer_id}").status_code == 500

    _swap_ca_key(cfg, original, issuer_id=issuer_id)
    first = client.get(f"/crl/{issuer_id}")
    assert first.status_code == 200
    published = x509.load_der_x509_crl(first.content)

    # now make it due for a refresh that cannot happen
    _age_stored_crl(cfg, issuer_id, timedelta(days=8))
    _swap_ca_key(cfg, issuer_id=issuer_id)
    stale = client.get(f"/crl/{issuer_id}")

    assert stale.status_code == 200
    assert x509.load_der_x509_crl(stale.content).signature == published.signature
    assert client.get(f"/crl/{issuer_id}.pem").status_code == 200


def test_ca_cer_endpoint_public_der(client: TestClient, cfg: Config) -> None:
    """AC-8: ``GET /ca/{issuer_id}.cer`` answers without a session, as DER,
    ``application/pkix-cert``, and the bytes parse into the certificate
    that actually signed a leaf issued under that issuer -- not merely some
    stored CA certificate. Also: an invalid session cookie must not change
    the answer, since this route has no business consulting it."""
    hierarchy = _hierarchy(cfg)
    db = _db(cfg)
    try:
        issuer_cert, issuer_key = ca_service.signing_credentials(
            db, _secrets(cfg), hierarchy.intermediate.id
        )
    finally:
        db.close()
    leaf_cert, _key, _capped_from = leaf.issue_certificate(
        issuer_cert, issuer_key, leaf.Profile.server, "cer.lan", ["DNS:cer.lan"]
    )

    client.cookies.clear()
    resp = client.get(f"/ca/{hierarchy.intermediate.id}.cer")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pkix-cert")
    served = x509.load_der_x509_certificate(resp.content)
    assert served.subject == leaf_cert.issuer
    assert served.subject == issuer_cert.subject
    assert served.serial_number == issuer_cert.serial_number

    client.cookies.set("cabin_session", "not-a-real-session-token")
    same = client.get(f"/ca/{hierarchy.intermediate.id}.cer")
    assert same.status_code == resp.status_code == 200
    assert same.content == resp.content
    assert same.headers["content-type"] == resp.headers["content-type"]


def test_ca_cer_endpoint_serves_a_root_certificate_too(client: TestClient, cfg: Config) -> None:
    """Interface Contract: unlike the CRL routes, ``/ca/{id}.cer`` answers
    404 only for an unknown id -- a root has no CRL route to answer for it,
    so serving its certificate over ``.cer`` is exactly what a client
    repairing a chain from a leaf may eventually need. Also: ``:int`` on
    this route too, so a non-numeric id is 404, not 422."""
    hierarchy = _hierarchy(cfg)
    client.cookies.clear()

    resp = client.get(f"/ca/{hierarchy.root.id}.cer")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pkix-cert")
    served = x509.load_der_x509_certificate(resp.content)
    root_cert = _parse_cert(hierarchy.root)
    assert served.subject == root_cert.subject
    assert served.serial_number == root_cert.serial_number

    assert client.get("/ca/999999.cer").status_code == 404
    assert client.get("/ca/abc.cer").status_code == 404


def test_public_cer_route_is_not_shadowed_by_the_authenticated_pem_route(
    client: TestClient, cfg: Config
) -> None:
    """Spec 0017 work split R8: ``/ca/{id}.cer`` (public, crl_ui.py) and
    ``/ca/{id}.pem`` (authenticated, ca_ui.py) share the ``/ca`` prefix. If
    router registration order or an over-broad path let the authenticated
    route win, every relying party following an AIA URL would get a login
    redirect instead of a certificate -- checked here in one test, with no
    session, so the two routes cannot silently drift apart."""
    _setup_superadmin(client)
    hierarchy = _hierarchy(cfg)
    client.cookies.clear()

    cer_resp = client.get(f"/ca/{hierarchy.intermediate.id}.cer")
    pem_resp = client.get(f"/ca/{hierarchy.intermediate.id}.pem")

    assert cer_resp.status_code == 200
    assert cer_resp.headers["content-type"].startswith("application/pkix-cert")
    x509.load_der_x509_certificate(cer_resp.content)  # parses cleanly
    assert pem_resp.status_code != 200


# --- FR-11/FR-12, AC-9: the CDP/AIA URLs baked into an issued certificate -------


def test_cdp_present_with_base_url(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    assert _set_base_url(client, cfg, BASE_URL) == 303
    issuer_id = _sole_intermediate_id(cfg)

    issued = _cert(cfg, _issue(client, cfg, cn="cdp.lan"))

    # FR-12: forced to http even though base_url is configured as https --
    # fetching an https CDP would need a validated certificate to do the
    # TLS handshake, which is the certificate being validated.
    forced = f"http://ca.example.org/crl/{issuer_id}"
    assert _cdp_urls(issued) == [forced]

    page = client.get("/ca")
    assert forced in page.text
    assert "https://ca.example.org/crl" not in page.text


def test_cdp_present_for_signed_csr(client: TestClient, cfg: Config) -> None:
    """FR-6/FR-12 cover every certificate cabin issues, not just the ones
    whose key it generated -- a CSR-signed leaf needs the same forced-http
    CDP."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    assert _set_base_url(client, cfg, BASE_URL) == 303
    issuer_id = _sole_intermediate_id(cfg)

    signed = _cert(cfg, _sign_csr(client, cfg))

    assert _cdp_urls(signed) == [f"http://ca.example.org/crl/{issuer_id}"]


def test_cdp_absent_without_base_url(client: TestClient, cfg: Config) -> None:
    """FR-6: no base URL means no CDP -- a broken CRL URL in a certificate
    that lives for a year is worse than none at all."""
    _setup_superadmin(client)
    _create_ca(client, cfg)

    issued = _cert(cfg, _issue(client, cfg, cn="nocdp.lan"))

    with pytest.raises(x509.ExtensionNotFound):
        issued.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    # ...and the CA page says so, so an operator can find out why
    assert "base URL" in client.get("/ca").text


def test_base_url_validation(client: TestClient, cfg: Config) -> None:
    """AC-5: only an absolute http(s) URL without a trailing slash is
    accepted; anything else re-renders the form with a 400. Pure settings
    validation, no CA needed -- unlike the CDP tests above, this does not
    depend on ``/ca/create`` or the issuance pipeline at all."""
    _setup_superadmin(client)

    for bad in (
        "ca.example.org",
        "/crl",
        "ftp://ca.example.org",
        f"{BASE_URL}/",
        "https://",
        # userinfo would be baked into every future CDP -- and into every
        # relying party's fetch of it
        "https://user:pass@ca.example.org",
        "https://user@ca.example.org",
        # a backslash is a slash to browsers but not to urlparse, so it is a
        # way to make the host read one way here and another there
        "https://ca.example.org\\@evil.example",
        "https://ca.example.org\\.evil.example",
    ):
        resp = client.post("/settings", data={"base_url": bad, "csrf_token": _csrf(client, cfg)})
        assert resp.status_code == 400, bad
        assert "base_url" in resp.text  # the form comes back, not a bare error

    assert _set_base_url(client, cfg, BASE_URL) == 303
    assert BASE_URL in client.get("/settings").text
    # a sub-path deployment behind a reverse proxy is legitimate
    assert _set_base_url(client, cfg, f"{BASE_URL}/cabin") == 303


def test_base_url_normalization(client: TestClient, cfg: Config) -> None:
    """What is stored is what goes into every future certificate (after
    FR-12's forcing), so it is stored canonically: scheme and host
    lowercased, no query or fragment."""
    _setup_superadmin(client)

    assert _set_base_url(client, cfg, "HTTPS://CA.Example.ORG:8443/Cabin") == 303
    # the path keeps its case (it is case-sensitive), the host does not
    assert "https://ca.example.org:8443/Cabin" in client.get("/settings").text

    assert _set_base_url(client, cfg, f"{BASE_URL}?ref=mail#top") == 303
    stored = client.get("/settings").text
    assert f'value="{BASE_URL}"' in stored
    assert "ref=mail" not in stored

    # CSRF is enforced like on every other mutating form
    assert client.post("/settings", data={"base_url": BASE_URL}).status_code == 403
    # ...and so is the admin role
    _create_viewer(client, cfg)
    _login(client, "vera")
    assert client.get("/settings").status_code == 403
    assert client.post("/settings", data={"base_url": BASE_URL}).status_code == 403


# --- FR-7, AC-6: the revoke form (unchanged by 0017, updated for /crl/{id}) -----


def test_ui_revoke_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    detail = client.get(f"/certs/{cert_id}")
    assert f"/certs/{cert_id}/revoke" in detail.text

    # the confirm checkbox is not decoration: without it nothing happens
    assert _revoke(client, cfg, cert_id, confirm=False) == 400
    # neither does a cross-site post
    assert client.post(f"/certs/{cert_id}/revoke", data={"reason": "superseded"}).status_code == 403
    assert _cert(cfg, cert_id) is not None
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revoked_at is None
    finally:
        db.close()

    assert _revoke(client, cfg, cert_id, reason="key_compromise") == 303

    page = client.get(f"/certs/{cert_id}")
    assert page.status_code == 200
    assert "key_compromise" in page.text
    assert "Revoked" in page.text
    # AC-6: revoking again is not offered
    assert f"/certs/{cert_id}/revoke" not in page.text
    # ...and a hand-made second post is a no-op, not a rewritten history
    assert _revoke(client, cfg, cert_id, reason="superseded") == 303
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revocation_reason == "key_compromise"
    finally:
        db.close()

    client.cookies.clear()
    issuer_id = _sole_intermediate_id(cfg)
    crl = x509.load_der_x509_crl(client.get(f"/crl/{issuer_id}").content)
    assert crl.get_revoked_certificate_by_serial_number(_serial(cfg, cert_id)) is not None


def test_ui_revoke_unknown_reason_is_refused(client: TestClient, cfg: Config) -> None:
    """A reason cabin does not know must not be quietly downgraded to
    "unspecified": the operator would be told the certificate was revoked for
    a reason that never reaches the CRL."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    assert _revoke(client, cfg, cert_id, reason="because-i-said-so") == 400

    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None and row.revoked_at is None
    finally:
        db.close()


def test_ui_revoke_requires_admin(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_viewer(client, cfg)
    cert_id = _issue(client, cfg)

    _login(client, "vera")
    page = client.get(f"/certs/{cert_id}")

    assert page.status_code == 200
    assert f"/certs/{cert_id}/revoke" not in page.text
    assert _revoke(client, cfg, cert_id) == 403
