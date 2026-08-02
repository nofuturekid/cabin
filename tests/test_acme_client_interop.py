"""Spec 0010 AC-7 and spec 0011 AC-8: the interop gate.

Unit tests prove cabin does what *we* read RFC 8555 to say. These prove a
real client agrees -- the certbot ACME library (BSD-licensed, a dev
dependency only) registers an account, places an order and, from spec 0011,
answers an http-01 challenge and polls the authorization to valid.
"""

from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import josepy as jose
import pytest
import requests
from acme import client as acme_client
from acme import crypto_util, messages
from challenge_servers import http_server, point_at, serves
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store
from fastapi.testclient import TestClient
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict

from cabin.acme import eab
from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.settings import ACME_ENABLED, ACME_REQUIRE_EAB, BASE_URL, TRUE, set_setting
from cabin.store import create_session_factory

DIRECTORY_URL = "http://testserver/acme/directory"

#: Headers the transport below owns; letting the client's copies through
#: would have httpx describe a body it is not sending.
_HOP_BY_HOP = frozenset({"content-length", "connection", "transfer-encoding", "host"})


class AsgiAdapter(BaseAdapter):
    """A ``requests`` transport that hands the request to the ASGI app.

    The certbot library speaks ``requests``; cabin's tests run the app
    in-process through Starlette's TestClient. Bridging the two beats
    binding a port: no thread, no socket, no flake -- and the bytes on the
    wire are exactly the ones the client built.
    """

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def send(self, request: Any, **kwargs: Any) -> requests.Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
        raw = self.client.request(
            request.method, request.url, content=request.body, headers=headers
        )
        response = requests.Response()
        response.status_code = raw.status_code
        response.headers = CaseInsensitiveDict(dict(raw.headers))
        response.encoding = "utf-8"
        response._content = raw.content
        response.url = str(request.url)
        response.request = request
        response.reason = raw.reason_phrase
        return response

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        db = create_session_factory(cfg.db_url)()
        try:
            set_setting(db, BASE_URL, "http://testserver")
            set_setting(db, ACME_ENABLED, TRUE)
            ca_service.create_hierarchy(
                db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), "cabin test"
            )
        finally:
            db.close()
        yield c


def _csr(*names: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
        .sign(key, algorithm=hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _connect(client: TestClient) -> acme_client.ClientV2:
    account_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    net = acme_client.ClientNetwork(key=account_key, user_agent="cabin-interop-test")
    net.session.mount("http://", AsgiAdapter(client))
    directory = acme_client.ClientV2.get_directory(DIRECTORY_URL, net)
    return acme_client.ClientV2(directory, net)


def test_real_client_account_and_order(client: TestClient) -> None:
    """AC-7: account registration and order placement, driven end to end by
    the certbot ACME library -- nonces, JWS, kid handling, POST-as-GET and
    every URL in between are the client's reading of them, not ours."""
    acme = _connect(client)

    assert acme.directory["newNonce"] == "http://testserver/acme/new-nonce"

    registration = acme.new_account(
        messages.NewRegistration.from_data(email="ops@example.org", terms_of_service_agreed=True)
    )

    assert registration.uri.startswith("http://testserver/acme/account/")
    assert registration.body.status == "valid"
    assert registration.body.contact == ("mailto:ops@example.org",)

    order = acme.new_order(_csr("nas.lan", "www.nas.lan"))

    assert order.body.status == messages.STATUS_PENDING
    assert {identifier.value for identifier in order.body.identifiers} == {
        "nas.lan",
        "www.nas.lan",
    }
    assert order.uri.startswith("http://testserver/acme/order/")
    assert len(order.authorizations) == 2
    for authzr in order.authorizations:
        assert authzr.body.status == messages.STATUS_PENDING
        assert len(authzr.body.challenges) == 3
        # This certbot release dropped tls-alpn-01 from its own registry and
        # parses it as UnrecognizedChallenge, so the client's view is the two
        # it still knows -- and, importantly, an authorization it accepts
        # despite carrying a challenge type it does not.
        known = {
            challenge.typ
            for challenge in authzr.body.challenges
            if challenge.typ is not NotImplemented
        }
        assert known == {"http-01", "dns-01"}
        # the tokens are what spec 0011 will validate against, so they have
        # to survive the client's own base64url round-trip
        assert all(
            challenge.chall.token
            for challenge in authzr.body.challenges
            if challenge.typ is not NotImplemented
        )

    # the client re-finds its own account by key alone (onlyReturnExisting)
    requeried = acme.query_registration(registration)
    assert requeried.uri == registration.uri

    # ...and reads its order and one authorization back with POST-as-GET
    new_nonce_url = acme.directory["newNonce"]
    updated = acme.net.post(order.uri, None, new_nonce_url=new_nonce_url)
    assert updated.status_code == 200
    assert updated.json()["status"] == "pending"

    raw_authz = acme.net.post(
        order.body.authorizations[0], None, new_nonce_url=new_nonce_url
    ).json()
    assert {challenge["type"] for challenge in raw_authz["challenges"]} == {
        "http-01",
        "dns-01",
        "tls-alpn-01",
    }


def test_real_client_sees_problem_documents(client: TestClient) -> None:
    """A client only recovers from an error it can parse: the problem
    document has to deserialize into ``messages.Error``, with a fresh nonce
    alongside it so the next request is not stuck."""
    acme = _connect(client)
    acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))

    with pytest.raises(messages.Error) as caught:
        acme.new_order(_csr("not a hostname"))

    assert caught.value.typ == "urn:ietf:params:acme:error:rejectedIdentifier"
    # the client is still usable afterwards
    order = acme.new_order(_csr("nas.lan"))
    assert order.body.status == messages.STATUS_PENDING


def test_client_completes_http01(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Spec 0011 AC-8: trigger, validate, poll -- driven end to end by the
    certbot library against a real local web server.

    The client computes the key authorization from its own account key and
    serves it at its own idea of the well-known path; cabin has to agree with
    both, and with the ``up`` Link the client insists on when answering.
    """
    acme = _connect(client)
    acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    order = acme.new_order(_csr("nas.lan"))
    authzr = order.authorizations[0]
    challb = next(challenge for challenge in authzr.body.challenges if challenge.typ == "http-01")
    chall = challb.chall
    response, validation = chall.response_and_validation(acme.net.key)

    with http_server(serves(validation.encode(), path=chall.path)) as server:
        point_at(monkeypatch, server.port)

        answered = acme.answer_challenge(challb, response)
        assert answered.body.status in (
            messages.STATUS_PROCESSING,
            messages.STATUS_VALID,
        )

        polled, _ = acme.poll(authzr)

    assert polled.body.status == messages.STATUS_VALID
    assert server.requests == [(chall.path, "nas.lan")]
    # ...and the order the client came for is now ready to finalize (0012)
    updated = acme.net.post(order.uri, None, new_nonce_url=acme.directory["newNonce"]).json()
    assert updated["status"] == "ready"


def _answer_http01(
    acme: acme_client.ClientV2,
    order: messages.OrderResource,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Serve every http-01 challenge of ``order`` until its authorizations
    are valid -- the client's own key authorization, at the client's own
    path."""
    for authzr in order.authorizations:
        challb = next(
            challenge for challenge in authzr.body.challenges if challenge.typ == "http-01"
        )
        response, validation = challb.chall.response_and_validation(acme.net.key)
        with http_server(serves(validation.encode(), path=challb.chall.path)) as server:
            point_at(monkeypatch, server.port)
            acme.answer_challenge(challb, response)
            polled, _ = acme.poll(authzr)
        assert polled.body.status == messages.STATUS_VALID


def _root_certificate(cfg: Config) -> x509.Certificate:
    db = create_session_factory(cfg.db_url)()
    try:
        hierarchy = ca_service.get_ca(db)
        assert hierarchy is not None
        return x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))
    finally:
        db.close()


def test_client_full_flow_to_certificate(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec 0012 AC-1: account, order, http-01, finalize, download -- every
    step driven by the certbot ACME library, and the chain it gets back has
    to verify to the root cabin publishes.

    The CSR is the client's own (``acme.crypto_util.make_csr``), which
    carries no subject at all: the names live in the SAN extension, exactly
    as RFC 8555 7.4 allows.
    """
    acme = _connect(client)
    acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_pem = crypto_util.make_csr(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        ["nas.lan", "www.nas.lan"],
    )

    order = acme.new_order(csr_pem)
    _answer_http01(acme, order, monkeypatch)
    finalized = acme.finalize_order(order, datetime.now() + timedelta(seconds=30))

    assert finalized.body.status == messages.STATUS_VALID
    chain = x509.load_pem_x509_certificates(finalized.fullchain_pem.encode("ascii"))
    assert len(chain) == 3
    leaf, intermediate, root = chain
    # the leaf carries exactly the names that were ordered, and the client's
    # own public key
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(sans.get_values_for_type(x509.DNSName)) == {"nas.lan", "www.nas.lan"}
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    # ...and the chain really verifies to cabin's root -- checked by
    # pyca/cryptography's path validator rather than by comparing subjects,
    # so signatures, validity and basic constraints all have to hold
    assert root == _root_certificate(cfg)
    verifier = PolicyBuilder().store(Store([root])).build_server_verifier(x509.DNSName("nas.lan"))
    verifier.verify(leaf, [intermediate])


def test_client_full_flow_with_eab(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec 0012 AC-8: with external account binding required, the real
    client registers when it is given the key id and HMAC key -- and cannot
    get an account without them."""
    db = create_session_factory(cfg.db_url)()
    try:
        set_setting(db, ACME_REQUIRE_EAB, TRUE)
        row, secret = eab.create_key(
            db, SecretStore.open(cfg.data_dir, cfg.master_passphrase), label="certbot"
        )
        key_id = row.id
    finally:
        db.close()

    acme = _connect(client)
    assert acme.directory.meta.external_account_required is True

    with pytest.raises(messages.Error) as refused:
        acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    assert refused.value.typ == "urn:ietf:params:acme:error:externalAccountRequired"

    binding = messages.ExternalAccountBinding.from_data(
        acme.net.key.public_key(), key_id, secret, acme.directory
    )
    registration = acme.new_account(
        messages.NewRegistration.from_data(
            terms_of_service_agreed=True, external_account_binding=binding
        )
    )

    assert registration.body.status == "valid"
    db = create_session_factory(cfg.db_url)()
    try:
        bound = eab.get_key(db, key_id)
        assert bound is not None
        assert bound.bound_account_id == registration.uri.rsplit("/", 1)[1]
    finally:
        db.close()

    # ...and the bound account goes all the way to a certificate
    order = acme.new_order(_csr("nas.lan"))
    _answer_http01(acme, order, monkeypatch)
    finalized = acme.finalize_order(order, datetime.now() + timedelta(seconds=30))
    assert finalized.body.status == messages.STATUS_VALID
    assert len(x509.load_pem_x509_certificates(finalized.fullchain_pem.encode("ascii"))) == 3
