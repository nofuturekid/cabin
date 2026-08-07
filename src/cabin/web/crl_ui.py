"""The public PKI endpoints (spec 0017 FR-10): a per-issuer CRL and, for any
CA row, its certificate.

Deliberately the only router in cabin without an authentication dependency:
a CRL -- and the certificate a client needs to complete a chain via a leaf's
AIA ``caIssuers`` URL (FR-11) -- are signed, public documents, and every
relying party validating one of our certificates must be able to fetch them
without a session, and without tripping the first-run redirect (a per-route
dependency, not middleware, so it does not apply here).
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import crl as crl_service
from cabin.ca.crl import CRL_MAX_AGE
from cabin.ca.service import CACertificate, CANotConfiguredError, UnknownIssuerError, get_ca
from cabin.secrets import SecretsError, SecretStore
from cabin.web.deps import get_db, get_secrets

router = APIRouter()

#: FR-5: a CRL is public and stable for its whole validity window; an hour of
#: caching keeps a busy fleet off the database without hiding a revocation
#: for long. Taken from the same constant the refresh margin uses, so the two
#: can never drift into promising a CRL for longer than it is valid.
_CACHE_CONTROL = f"public, max-age={int(CRL_MAX_AGE.total_seconds())}"

_KEY_UNAVAILABLE = "the CA private key could not be decrypted, so no CRL can be signed"


def _intermediate_or_404(db: Session, issuer_id: int) -> CACertificate:
    """FR-10: both CRL routes are 404 for an unknown id and for a row that
    is not an intermediate -- a root never signs a CRL, so there is nothing
    to serve and nothing to say about it."""
    try:
        row = get_ca(db, issuer_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="unknown issuer") from exc
    if row.kind != "intermediate":
        raise HTTPException(status_code=404, detail="not an intermediate")
    return row


def _current_der(secrets: SecretStore, db: Session, issuer_id: int) -> bytes:
    _intermediate_or_404(db, issuer_id)
    try:
        return crl_service.current_crl(db, secrets, issuer_id).crl_der
    except (CANotConfiguredError, SecretsError) as exc:
        # The signing key is unusable -- wrong master key, a damaged sealed
        # column, or (CANotConfiguredError) no key stored for this issuer at
        # all. Serving the last good CRL -- even past its nextUpdate --
        # beats serving nothing: a relying party that cannot fetch a CRL may
        # fail closed on every certificate this issuer ever signed.
        stale = crl_service.stored_crl(db, issuer_id)
        if stale is None:
            raise HTTPException(status_code=500, detail=_KEY_UNAVAILABLE) from exc
        return stale.crl_der


@router.get("/crl/{issuer_id:int}")
def crl_der(
    issuer_id: int,
    db: Session = Depends(get_db),
    secrets: SecretStore = Depends(get_secrets),
) -> Response:
    return Response(
        content=_current_der(secrets, db, issuer_id),
        media_type="application/pkix-crl",
        headers={"Cache-Control": _CACHE_CONTROL},
    )


@router.get("/crl/{issuer_id:int}.pem")
def crl_pem(
    issuer_id: int,
    db: Session = Depends(get_db),
    secrets: SecretStore = Depends(get_secrets),
) -> Response:
    body = x509.load_der_x509_crl(_current_der(secrets, db, issuer_id)).public_bytes(
        serialization.Encoding.PEM
    )
    return Response(
        content=body,
        media_type="application/x-pem-file",
        headers={"Cache-Control": _CACHE_CONTROL},
    )


@router.get("/ca/{ca_id:int}.cer")
def ca_cer(ca_id: int, db: Session = Depends(get_db)) -> Response:
    """FR-10: one certificate, DER, for any row -- root or intermediate --
    so a relying party repairing a chain from a leaf's AIA ``caIssuers`` URL
    (FR-11) can always complete it. 404 only for an unknown id; unlike the
    CRL routes, a root has no CRL route to answer for it, but serving its
    certificate here is exactly what such a client may need."""
    try:
        row = get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="unknown CA") from exc
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    return Response(
        content=cert.public_bytes(serialization.Encoding.DER),
        media_type="application/pkix-cert",
    )
