"""Scaffolding shared by the spec-0012 tests: an account with an order, a
way to put that order in ``ready`` without re-proving a challenge, and CSRs
built to order.

Not collected by pytest -- imported by ``test_acme_finalize.py``,
``test_acme_revoke.py`` and ``test_acme_eab.py``.

Getting an authorization to ``valid`` over HTTP is spec 0011's subject and
is tested there against real servers; repeating it in front of every
finalize test would buy nothing and cost a web server per case. So the
authorizations are marked valid in the database directly -- the *only*
shortcut these tests take, and one that touches nothing finalize itself
reads.
"""

import ipaddress
from typing import Any

from acme_client import Acme, AcmeKey, b64, rsa_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from httpx2 import Response
from sqlalchemy import update
from sqlalchemy.orm import Session

from cabin.acme.models import AcmeAuthorization, AuthorizationStatus
from cabin.config import Config
from cabin.store import create_session_factory

BASE = "http://testserver"
ERROR_PREFIX = "urn:ietf:params:acme:error:"

#: A CSR key type is not what these tests are about, so one shape is enough.
CsrKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


def db_session(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def path_of(url: str) -> str:
    return url.removeprefix(BASE)


def assert_problem(resp: Response, kind: str, status: int) -> None:
    __tracebackhide__ = True
    assert resp.status_code == status, resp.text
    assert resp.json()["type"] == f"{ERROR_PREFIX}{kind}", resp.text


def _general_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def csr_der(
    *names: str,
    common_name: str | None = "",
    key: CsrKey | None = None,
    tamper: bool = False,
) -> bytes:
    """A DER CSR naming ``names`` as SANs.

    ``common_name=""`` (the default) means "the first SAN"; None means a CSR
    with no subject at all, which is what the certbot library produces.
    ``tamper`` flips a bit of the signature, so the CSR still parses and
    then fails to verify -- the only way to reach that branch without
    hand-building ASN.1.
    """
    signing_key: CsrKey = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([])
    if common_name is not None:
        cn = common_name or names[0]
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_general_name(name) for name in names]),
            critical=False,
        )
    algorithm = None if isinstance(signing_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = builder.sign(signing_key, algorithm=algorithm)
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    if tamper:
        der[-1] ^= 0x01
    return bytes(der)


def rsa_signing_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


class Flow:
    """One ACME account and one order, driven over the real HTTP surface."""

    def __init__(self, acme: Acme, cfg: Config, *names: str, key: AcmeKey | None = None) -> None:
        self.acme = acme
        self.cfg = cfg
        self.key = key or rsa_key()
        registration = acme.post("/acme/new-account", self.key, {"termsOfServiceAgreed": True})
        assert registration.status_code in (200, 201), registration.text
        self.kid = registration.headers["location"]
        self.identifiers = [self._identifier(name) for name in names]
        placed = acme.post(
            "/acme/new-order", self.key, {"identifiers": self.identifiers}, kid=self.kid
        )
        assert placed.status_code == 201, placed.text
        self.order_url = placed.headers["location"]
        self.order_id = self.order_url.rsplit("/", 1)[1]
        #: Set by :meth:`finalize_ok` -- where this order's certificate lives.
        self.certificate_url = ""

    @staticmethod
    def _identifier(name: str) -> dict[str, str]:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            return {"type": "dns", "value": name}
        return {"type": "ip", "value": name}

    def post(self, url: str, payload: Any = None) -> Response:
        return self.acme.post(path_of(url), self.key, payload, kid=self.kid)

    def read(self, url: str) -> dict[str, Any]:
        response = self.post(url)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    def order(self) -> dict[str, Any]:
        return self.read(self.order_url)

    def make_ready(self) -> None:
        """Mark every authorization of this order valid -- which is what a
        completed challenge does in spec 0011."""
        db = db_session(self.cfg)
        try:
            result = db.execute(
                update(AcmeAuthorization)
                .where(AcmeAuthorization.order_id == self.order_id)
                .values(status=AuthorizationStatus.valid)
            )
            assert result.rowcount == len(self.identifiers)
            db.commit()
        finally:
            db.close()

    def finalize(self, csr: bytes) -> Response:
        return self.post(f"{self.order_url}/finalize", {"csr": b64(csr)})

    def finalize_ok(self, csr: bytes) -> str:
        response = self.finalize(csr)
        assert response.status_code == 200, response.text
        self.certificate_url = str(response.json()["certificate"])
        return self.certificate_url

    def certificate(self, url: str | None = None) -> Response:
        return self.post(url or self.certificate_url)

    def leaf(self) -> x509.Certificate:
        """The issued certificate, as the client gets it back."""
        response = self.certificate()
        assert response.status_code == 200, response.text
        return x509.load_pem_x509_certificates(response.text.encode("ascii"))[0]
