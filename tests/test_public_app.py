"""Tests for the plaintext PKI listener's application (spec 0022 FR-10):
`cabin.server.create_public_app`.

When TLS is on, cabin binds a second, plaintext listener purely so that CRL
and CA-certificate URLs can stay `http://` -- fetching a CRL over TLS to
validate a certificate would require validating that certificate first (see
the spec's Context). That listener must therefore serve exactly three
routes and answer 404 to literally everything else: no redirect, ever
(FR-10 calls this "a security property, not a routing detail"), and no
`Set-Cookie` -- a login form reachable over plaintext is the exact outcome
this listener exists to make impossible.

Every test here drives `create_public_app` directly through Starlette's
`TestClient`, in process: `TestClient` never builds a real `SSLContext`, so
none of this says anything about a TLS handshake or about `cabin.server.run`
actually wiring this application onto `config.http_port` -- `tests/
test_server_live.py` covers that on a real socket. What belongs here is the
application's own contract, which needs no socket to prove.
"""

from collections.abc import Iterator
from pathlib import Path

import ca_fixtures
import pytest
from cryptography import x509
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from cabin.app import create_app
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.server import create_public_app
from cabin.store import create_session_factory

#: The Interface Contract's exact route table (spec 0022, "Routes on the
#: plaintext listener"). AC-11 requires the served set to equal this,
#: compared as a set -- "contains" would let an extra route hide.
_ALLOWED_PATHS = {"/crl/{issuer_id}", "/crl/{issuer_id}.pem", "/ca/{ca_id}.cer"}

#: AC-11's own list, verbatim: every kind of surface FR-10 forbids -- the
#: dashboard, login, first-run setup, the healthcheck, an authenticated
#: download, the CA UI, the REST API and the ACME protocol, plus a static
#: asset.
_AC11_FORBIDDEN_PATHS = (
    "/",
    "/login",
    "/setup",
    "/healthz",
    "/certs",
    "/ca",
    "/api/v1/ca",
    "/acme/ca/1/directory",
    "/static/app.css",
)

#: FastAPI enables these on every `FastAPI()` instance unless `docs_url`/
#: `redoc_url`/`openapi_url` are explicitly turned off. None of the three
#: are in the Interface Contract, so FR-10's "nothing else" covers them
#: too -- and unlike the AC-11 list above, the spec never spells this one
#: out, so a competent implementation that only reads the named list can
#: still ship this gap.
_AUTO_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect")


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def app(cfg: Config) -> FastAPI:
    """Kept as its own fixture, typed as `FastAPI` rather than read back off
    `TestClient.app` (typed only as the bare ASGI callable) -- both
    `create_public_app` and the `.state.db` swap below need the real type."""
    return create_app(cfg)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    """The full application, with its lifespan actually run -- `app.state`
    only exists once this has happened, which is exactly the ordering
    `create_public_app`'s dependency overrides rely on (FR-7)."""
    with TestClient(app, follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _hierarchy(cfg: Config) -> ca_fixtures.CAHierarchy:
    """A real, signed root + intermediate -- so the positive assertions
    below read genuine PKI documents rather than an empty database that
    would make every negative assertion look like a 404 for the wrong
    reason. Built directly against the ORM, after the `client` fixture's
    lifespan has already opened the secret store this reuses (the same
    pattern `test_web_crl.py` uses)."""
    db = _db(cfg)
    try:
        return ca_fixtures.make_hierarchy(db, _secrets(cfg))
    finally:
        db.close()


def test_public_app_serves_crl_and_ca_cer(cfg: Config, app: FastAPI, client: TestClient) -> None:
    """AC-10: real PKI documents, parsed -- not just a status code."""
    hierarchy = _hierarchy(cfg)
    intermediate_cert = x509.load_pem_x509_certificate(hierarchy.intermediate.cert_pem.encode())
    root_cert = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode())
    public = TestClient(create_public_app(app), follow_redirects=False)

    crl_resp = public.get(f"/crl/{hierarchy.intermediate.id}")
    assert crl_resp.status_code == 200
    assert crl_resp.headers["content-type"] == "application/pkix-crl"
    crl = x509.load_der_x509_crl(crl_resp.content)
    assert crl.issuer == intermediate_cert.subject

    pem_resp = public.get(f"/crl/{hierarchy.intermediate.id}.pem")
    assert pem_resp.status_code == 200
    assert x509.load_pem_x509_crl(pem_resp.content).issuer == intermediate_cert.subject

    cer_resp = public.get(f"/ca/{hierarchy.root.id}.cer")
    assert cer_resp.status_code == 200
    assert cer_resp.headers["content-type"] == "application/pkix-cert"
    served_root = x509.load_der_x509_certificate(cer_resp.content)
    assert served_root.subject == root_cert.subject
    assert served_root.serial_number == root_cert.serial_number

    # FR-10 is a security property on every response this listener sends,
    # successful ones included: no session cookie ever leaves this port.
    for resp in (crl_resp, pem_resp, cer_resp):
        assert "set-cookie" not in resp.headers


def test_public_app_serves_nothing_else(cfg: Config, app: FastAPI, client: TestClient) -> None:
    """AC-11, the negative case that carries all the weight: every route
    that is not one of the three above is a 404 with no `Location` and no
    `Set-Cookie` -- the assertion that stops a later, well-meaning
    HTTP->HTTPS redirect (Out of Scope, spec: "Any HTTP->HTTPS redirect,
    anywhere") from ever going green here. A login form reachable over
    plaintext is the exact outcome this listener must never produce, hence
    `/login` and `POST /login` in the list below.

    The positive half runs first, against the *same* client: a failure to
    start or to wire the database must not be able to masquerade as "the
    negative case passed".
    """
    hierarchy = _hierarchy(cfg)
    public = TestClient(create_public_app(app), follow_redirects=False)
    assert public.get(f"/crl/{hierarchy.intermediate.id}").status_code == 200

    for path in (*_AC11_FORBIDDEN_PATHS, *_AUTO_DOCS_PATHS):
        resp = public.get(path)
        assert resp.status_code == 404, f"{path} is reachable on the plaintext listener"
        assert "location" not in resp.headers, f"{path} carries a Location header"
        assert "set-cookie" not in resp.headers, f"{path} sets a cookie"

    # A 405 would prove the route exists; only a 404 proves it does not.
    login_resp = public.post("/login", data={"username": "x", "password": "y"})
    assert login_resp.status_code == 404
    assert "location" not in login_resp.headers
    assert "set-cookie" not in login_resp.headers


def test_public_app_never_redirects_trailing_slash(
    cfg: Config, app: FastAPI, client: TestClient
) -> None:
    """R2: FastAPI's router defaults to `redirect_slashes=True`, which would
    answer a trailing-slash request with a 307 and a `Location` header --
    exactly the redirect FR-10 forbids, and on paths AC-11's fixed list
    does not otherwise reach.
    """
    hierarchy = _hierarchy(cfg)
    public = TestClient(create_public_app(app), follow_redirects=False)

    # Positive control: the same routes work without the trailing slash.
    assert public.get(f"/crl/{hierarchy.intermediate.id}").status_code == 200
    assert public.get(f"/ca/{hierarchy.root.id}.cer").status_code == 200

    for path in (
        f"/crl/{hierarchy.intermediate.id}/",
        f"/crl/{hierarchy.intermediate.id}.pem/",
        f"/ca/{hierarchy.root.id}.cer/",
    ):
        resp = public.get(path)
        assert resp.status_code == 404
        assert "location" not in resp.headers, f"{path} redirects instead of 404ing"


def test_public_app_route_set_is_exactly_three(app: FastAPI) -> None:
    """AC-11's set comparison: not "contains the three" but "equals the
    three", so an extra route is caught even if it happens to 404 (or 500)
    today and only becomes reachable later."""
    public = create_public_app(app)
    assert set(public.openapi()["paths"].keys()) == _ALLOWED_PATHS


def test_public_app_disables_its_own_auto_generated_docs(
    cfg: Config, app: FastAPI, client: TestClient
) -> None:
    """FastAPI enables `/docs`, `/redoc` and `/openapi.json` on every app by
    default -- working, unauthenticated pages that are no part of the three
    routes FR-10 allows. `test_public_app_route_set_is_exactly_three` alone
    cannot catch a forgotten `docs_url=None`: FastAPI excludes its own docs
    routes from `openapi()["paths"]` by definition, so only a direct HTTP
    check proves they are actually unreachable.
    """
    hierarchy = _hierarchy(cfg)
    public = TestClient(create_public_app(app), follow_redirects=False)
    # Positive control in the same test: the listener genuinely works.
    assert public.get(f"/ca/{hierarchy.root.id}.cer").status_code == 200

    for path in _AUTO_DOCS_PATHS:
        resp = public.get(path)
        assert resp.status_code == 404, f"{path} is reachable on the plaintext listener"


def test_public_app_reaches_main_apps_database(
    cfg: Config, app: FastAPI, client: TestClient
) -> None:
    """FR-10: `create_public_app` has no lifespan and opens no database of
    its own -- it reaches the *main* application's through a dependency
    override that reads `main_app.state.db` per request. Proved by
    substituting a distinguishable-but-still-real factory on
    `app.state.db` and observing the public app actually call through it,
    rather than building a session factory of its own from `cfg.db_url`.
    """
    hierarchy = _hierarchy(cfg)
    calls = 0
    real_factory: sessionmaker[Session] = app.state.db

    def _tracking_factory() -> Session:
        nonlocal calls
        calls += 1
        return real_factory()

    app.state.db = _tracking_factory
    public = TestClient(create_public_app(app), follow_redirects=False)

    resp = public.get(f"/crl/{hierarchy.intermediate.id}")

    assert resp.status_code == 200
    assert calls > 0, "the public app did not read main_app.state.db"
