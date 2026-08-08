"""Per-certificate downloads (spec 0006 FR-4/FR-5): PEM, full chain,
private key and a password-protected PKCS#12 bundle.

Separate from :mod:`cabin.web.certs_ui` so the issuance/inventory pages and
the file-serving routes stay readable on their own; both mount under
``/certs``. Everything here is an attachment and nothing here may be
cached: two of the four routes hand out private key material.
"""

import re
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin.ca import certs as certs_service
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate
from cabin.ca.service import UnknownIssuerError
from cabin.users import User
from cabin.web.certs_ui import SERIAL_CHARS
from cabin.web.deps import (
    certificate_or_404,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/certs")

#: FR-4: a PKCS#12 bundle is only as safe as its password.
MIN_P12_PASSWORD = 8

_NO_CA = "no CA configured"
_NO_KEY = "no private key is stored for this certificate"
_P12_UNSUPPORTED = "this key type cannot be stored in a PKCS#12 bundle"
#: FR-8: an ``anchor`` that names no path in this leaf's ChainSet is a 404,
#: never a silent fallback to the default -- a client that asked for a
#: specific anchor and got a different one has been misinformed about the
#: one thing it asked about.
_UNKNOWN_ANCHOR = "no such chain for this certificate"

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(subject_cn: str) -> str:
    """CN -> filename-safe token. The result is ``[a-z0-9-]`` only, which is
    also what keeps the Content-Disposition filename below free of quotes,
    separators and non-ASCII."""
    return _NON_SLUG.sub("-", subject_cn.lower()).strip("-") or "certificate"


def _filename(row: Certificate, suffix: str) -> str:
    return f"{_slug(row.subject_cn)}-{row.serial_hex[:SERIAL_CHARS]}{suffix}"


def _attachment(body: bytes, media_type: str, filename: str) -> Response:
    """FR-4: every download is saved, never rendered, and never cached."""
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def _chain_set(db: Session, row: Certificate) -> "ca_service.ChainSet":
    """The leaf's full set of paths -- default and alternates (spec 0021
    FR-6) -- built from the leaf's own issuer (spec 0017 FR-8), not from a
    single instance-wide hierarchy: with several hierarchies side by side,
    a certificate's chain is whichever one actually signed it."""
    try:
        return ca_service.chains_for(db, row.issuer_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=_NO_CA) from exc


def _certs(chain: "ca_service.Chain") -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(ca.cert_pem.encode("ascii")) for ca in chain.rows]


def _chain(db: Session, row: Certificate) -> list[x509.Certificate]:
    """The *default* chain (spec 0021 FR-6/FR-8) -- what the PKCS#12 bundle
    always bundles, and what ``chain.pem`` serves when no ``anchor`` is
    given."""
    return _certs(_chain_set(db, row).default)


def _key_pem(request: Request, row: Certificate) -> str:
    """The unsealed private key, or a clean HTTP error (FR-4/FR-6): 404 when
    the row never had a key (CSR-signed), 409 when it exists but cannot be
    decrypted -- a broken master key is a state conflict, and explicitly not
    a 500.
    """
    pem, error = certs_service.key_material(request.app.state.secrets, row)
    if error is not None:
        raise HTTPException(status_code=409, detail=error)
    if pem is None:
        raise HTTPException(status_code=404, detail=_NO_KEY)
    return pem


@router.get("/{cert_id}/download/cert.pem")
def download_cert_pem(
    cert_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> Response:
    row = certificate_or_404(db, cert_id)
    return _attachment(
        row.cert_pem.encode("ascii"), "application/x-pem-file", _filename(row, ".pem")
    )


@router.get("/{cert_id}/download/chain.pem")
def download_chain_pem(
    cert_id: int,
    anchor: int | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> Response:
    """FR-8: ``anchor`` names a path by its topmost row's id. Omitted, this
    serves the default -- the long path, when a live cross certificate
    offers one (spec 0021 FR-6). Given, it must name a path that is
    actually in this leaf's current :class:`~cabin.ca.service.ChainSet`, or
    the request is a 404 rather than a quiet fallback to the default."""
    row = certificate_or_404(db, cert_id)
    chain_set = _chain_set(db, row)
    if anchor is None:
        chain = chain_set.default
    else:
        found = chain_set.by_anchor(anchor)
        if found is None:
            raise HTTPException(status_code=404, detail=_UNKNOWN_ANCHOR)
        chain = found
    body = row.cert_pem + "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for cert in _certs(chain)
    )
    return _attachment(body.encode("ascii"), "application/x-pem-file", _filename(row, "-chain.pem"))


@router.get("/{cert_id}/download/key.pem")
def download_key_pem(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _user: User = Depends(require_admin),
) -> Response:
    row = certificate_or_404(db, cert_id)
    return _attachment(
        _key_pem(request, row).encode("ascii"),
        "application/x-pem-file",
        _filename(row, "-key.pem"),
    )


@router.post("/{cert_id}/download/bundle.p12")
def download_bundle_p12(
    cert_id: int,
    request: Request,
    password: str = Form(""),
    db: Session = Depends(get_db),
    _user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-5: leaf + key + chain in one file for Windows/macOS import.

    ``password`` is declared optional and length-checked here so a missing
    one is the same clean 400 as a too-short one, rather than FastAPI's 422
    (AC-5).
    """
    row = certificate_or_404(db, cert_id)
    if len(password) < MIN_P12_PASSWORD:
        raise HTTPException(
            status_code=400,
            detail=f"the bundle password must be at least {MIN_P12_PASSWORD} characters",
        )
    key = serialization.load_pem_private_key(_key_pem(request, row).encode("ascii"), password=None)
    try:
        bundle = pkcs12.serialize_key_and_certificates(
            name=row.subject_cn.encode("utf-8"),
            # The PEM parser's return type is wider than what PKCS#12 can
            # carry; the except below -- not a type check -- is what turns a
            # key it cannot carry into a clean 400.
            key=cast(pkcs12.PKCS12PrivateKeyTypes, key),
            cert=x509.load_pem_x509_certificate(row.cert_pem.encode("ascii")),
            cas=_chain(db, row),
            # PBES2/AES-256, i.e. whatever the library considers current --
            # not the legacy RC2/3DES profile (FR-5).
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    except (TypeError, ValueError) as exc:
        # Every key type cabin issues today can go into a PKCS#12 bundle
        # (Ed25519 included). This is the guard for the day one cannot:
        # pyca/cryptography refuses it, and that must be a clean 400, never
        # a traceback (FR-5).
        raise HTTPException(status_code=400, detail=_P12_UNSUPPORTED) from exc
    return _attachment(bundle, "application/x-pkcs12", _filename(row, ".p12"))
