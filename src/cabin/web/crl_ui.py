"""The public CRL endpoints (spec 0007 FR-5): ``/crl`` (DER) and
``/crl.pem``.

Deliberately the only routes in cabin without an authentication dependency:
a CRL is a signed, public document, and every relying party that validates
one of our certificates must be able to fetch it -- without a session, and
without tripping the first-run redirect (which is a per-route dependency,
not middleware, so it does not apply here).
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import crl as crl_service
from cabin.ca.crl import CRL_MAX_AGE
from cabin.ca.service import CANotConfiguredError
from cabin.secrets import SecretsError
from cabin.web.deps import get_db

router = APIRouter()

#: FR-5: a CRL is public and stable for its whole validity window; an hour of
#: caching keeps a busy fleet off the database without hiding a revocation
#: for long. Taken from the same constant the refresh margin uses, so the two
#: can never drift into promising a CRL for longer than it is valid.
_CACHE_CONTROL = f"public, max-age={int(CRL_MAX_AGE.total_seconds())}"

_KEY_UNAVAILABLE = "the CA private key could not be decrypted, so no CRL can be signed"


def _current_der(request: Request, db: Session) -> bytes:
    try:
        return crl_service.current_crl(db, request.app.state.secrets).crl_der
    except CANotConfiguredError as exc:
        # No CA means no CRL exists to be talked about -- not an error on the
        # caller's side, just nothing here (FR-5).
        raise HTTPException(status_code=404, detail="no CA configured") from exc
    except SecretsError as exc:
        # The key is unusable (wrong master key, damaged column), so the CRL
        # cannot be re-signed. Serving the last good one -- even past its
        # nextUpdate -- beats serving nothing: a relying party that cannot
        # fetch a CRL may fail closed on every certificate we ever issued.
        stale = crl_service.stored_crl(db)
        if stale is None:
            raise HTTPException(status_code=500, detail=_KEY_UNAVAILABLE) from exc
        return stale.crl_der


@router.get("/crl")
def crl_der(request: Request, db: Session = Depends(get_db)) -> Response:
    return Response(
        content=_current_der(request, db),
        media_type="application/pkix-crl",
        headers={"Cache-Control": _CACHE_CONTROL},
    )


@router.get("/crl.pem")
def crl_pem(request: Request, db: Session = Depends(get_db)) -> Response:
    body = x509.load_der_x509_crl(_current_der(request, db)).public_bytes(
        serialization.Encoding.PEM
    )
    return Response(
        content=body,
        media_type="application/x-pem-file",
        headers={"Cache-Control": _CACHE_CONTROL},
    )
