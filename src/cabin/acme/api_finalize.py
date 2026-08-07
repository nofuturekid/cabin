"""The end of an ACME order (spec 0012 FR-1, FR-2, FR-3): finalize with a
CSR, download the chain, revoke what came out.

RFC 8555 sections 7.4, 7.4.2 and 7.6. Split from :mod:`cabin.acme.api_order`
-- which is about reading order state -- because these three are the routes
that *change* something outside ACME: they mint and revoke certificates in
the same tables the UI and the API use.

Two properties hold across all three and are worth stating once:

* **Every route here verifies a JWS before it looks at a payload.** The
  spec-0010 stubs these replace verified nothing, which was safe only
  because they did nothing. A finalize that signed a CSR without checking
  the signature would hand certificates to anyone who could guess an order
  URL.
* **Ownership is checked against the order, never against the URL.** A
  certificate id is a small integer and guessable; what authorizes fetching
  or revoking one is the account that placed the order which produced it
  (or, for revocation, the certificate's own key -- RFC 8555 7.6).
"""

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import csr as csr_policy
from cabin.acme import service
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.http import (
    CERT_PREFIX,
    ORDER_PREFIX,
    PEM_CHAIN_CONTENT_TYPE,
    REVOKE_CERT_PATH,
    account_of,
    acme_body,
    json_response,
    not_found,
    order_json,
    owned_order,
    verified,
)
from cabin.acme.jws import KeyMode, VerifiedRequest, b64decode, key_mode
from cabin.acme.models import AcmeOrder, OrderStatus
from cabin.audit import AuditAction, acme_actor
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate, CertSource, Issued
from cabin.ca.leaf import DEFAULT_DAYS, MAX_CN_LENGTH, IssueError, Profile
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import CANotConfiguredError, IssuerRequiredError
from cabin.secrets import SecretsError
from cabin.web.deps import client_ip, get_db

router = APIRouter()

#: What cabin issues over ACME. Not a client's choice: ACME proves control
#: of a *name*, which is what a server certificate is for, and a client
#: certificate is an identity decision an operator makes in the UI.
ACME_PROFILE = Profile.server

#: How long a client that met a ``processing`` order is asked to wait (RFC
#: 8555 7.4's SHOULD). Signing one leaf takes milliseconds, so this is short
#: -- it exists to keep every client from picking its own interval, not to
#: throttle anything.
RETRY_AFTER_SECONDS = 3

#: RFC 5280 5.3.1 reason codes -> the reasons cabin can actually put on a
#: CRL (spec 0007 FR-2). Everything absent from this table is refused rather
#: than silently downgraded to "unspecified": a client told its certificate
#: was revoked as keyCompromise, when the CRL says otherwise, has been
#: misinformed about the one field that changes what relying parties do.
#:
#: Absent on purpose: 2 (caCompromise) -- revoking a CA is not something
#: cabin does over ACME; 6 (certificateHold) -- implies un-revocation, which
#: cabin does not offer; 8 (removeFromCRL) -- only meaningful with delta
#: CRLs, and RFC 8555 7.6 singles it out as one a server should refuse.
REVOCATION_REASONS: dict[int, RevocationReason] = {
    0: RevocationReason.unspecified,
    1: RevocationReason.key_compromise,
    3: RevocationReason.affiliation_changed,
    4: RevocationReason.superseded,
    5: RevocationReason.cessation_of_operation,
}


def _payload_of(verification: VerifiedRequest, what: str) -> dict[str, Any]:
    payload = verification.payload
    if payload is None:
        raise AcmeError(ErrorType.malformed, f"{what} needs a payload")
    return payload


# --- FR-1: finalize ------------------------------------------------------------------


@router.post("/order/{order_id}/finalize")
def finalize_order(
    order_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """RFC 8555 7.4: the CSR arrives, the certificate comes back.

    The order of operations is the whole design. The CSR is checked against
    the order *before* the order is claimed, so that a client which sent the
    wrong CSR can simply send the right one -- a rejected CSR must not cost
    it its order. The claim (a conditional UPDATE, see
    :func:`cabin.acme.service.claim_for_issuance`) is what makes two
    simultaneous finalizes produce one certificate rather than two.
    """
    verification = verified(db, body, f"{ORDER_PREFIX}{order_id}/finalize", KeyMode.kid)
    account = account_of(verification)
    order = owned_order(db, account, service.get_order(db, order_id))

    if order.certificate_id is not None:
        # AC-3: already done. Answering with the order as it stands -- rather
        # than issuing again or refusing -- is what makes a lost response
        # recoverable, and it is what RFC 8555 7.4 has the client poll for
        # anyway.
        return json_response(order_json(db, order))

    # Readiness first, and before the CSR is even looked at: RFC 8555 7.4
    # requires this exact answer for an order that is not ready yet, and the
    # certbot client keys off it to go back to polling. A client that
    # finalizes early would otherwise be told to fix its CSR, when what it
    # actually has to do is finish proving its names.
    status = service.order_status(db, order)
    if status != OrderStatus.ready:
        raise AcmeError(
            ErrorType.order_not_ready,
            f"this order is {status}; every authorization must be valid before it can be finalized",
        )

    payload = _payload_of(verification, "finalize")
    der = b64decode(payload.get("csr"), "the CSR")
    request_csr = csr_policy.load(der)
    csr_policy.check_identifiers(request_csr, service.order_identifiers(order))

    if not service.claim_for_issuance(db, order):
        # Another finalize is in flight or has just finished. Both are the
        # client's own request seen twice, so both are answered with the
        # order rather than with an error it cannot act on -- and with the
        # ``Retry-After`` RFC 8555 7.4 asks for, so that a client told to
        # poll is also told how long to wait.
        processing = json_response(order_json(db, order))
        processing.headers["Retry-After"] = str(RETRY_AFTER_SECONDS)
        return processing

    issued = _issue(request, db, order, der)
    row = issued.row
    # Two commits, and a crash between them leaves the order ``processing``
    # with a certificate nobody can reach: it exists in the inventory (where
    # an operator can see and revoke it), but the order never names it and
    # the claim above will not let the client finalize again. v1 has no
    # recovery path for that window -- reconciling orphans would need either
    # a single transaction across two modules that commit separately, or a
    # sweeper, and neither is worth it for a gap of milliseconds. An
    # operator's fix is to revoke the orphan; the client then places a new
    # order.
    service.attach_certificate(db, order, row.id)
    audit.record(
        db,
        acme_actor(account.jwk_thumbprint),
        AuditAction.acme_certificate_issued,
        summary=audit.issued_summary(row),
        target_type="certificate",
        target_id=row.id,
        # The CSR itself stays out of the log, as it does for the UI and the
        # API (spec 0009 FR-3): it is bulky, and what it asked for is already
        # described by the certificate that came out of it. Spec 0017 FR-7:
        # ACME requests no explicit validity, so DEFAULT_DAYS is what was
        # implicitly asked for when the clamp fired.
        detail={
            **audit.certificate_detail(
                row,
                days_requested=DEFAULT_DAYS if issued.capped_from is not None else None,
                validity_capped_from=issued.capped_from,
            ),
            "order": order.id,
        },
        ip=client_ip(request, db),
    )
    return json_response(order_json(db, order))


def _subject_cn(identifiers: list[dict[str, str]]) -> str | None:
    """Which of the order's names goes in the subject, if any.

    RFC 8555 7.4 lets a CSR carry its names in the SAN extension alone,
    which is what the certbot library produces; the subject then has to come
    from the order. Taking the *first* identifier is the obvious reading and
    the wrong one: a DNS identifier may be 253 characters and a common name
    may be 64 (:data:`cabin.ca.leaf.MAX_CN_LENGTH`), so an order whose first
    name is long could never be finalized -- with nothing the client could
    change about its perfectly good CSR to fix it.

    So: the first name that fits, and if none does, no subject at all. What
    a certificate is authorized for is its SAN set, which is built from the
    order either way; the common name is a courtesy copy of one of those
    names for readers who still look there.
    """
    for entry in identifiers:
        if len(entry["value"]) <= MAX_CN_LENGTH:
            return entry["value"]
    return None


def _issue(request: Request, db: Session, order: AcmeOrder, der: bytes) -> Issued:
    """Sign the CSR through the spec-0005 path, or give the order back.

    The SANs are taken from the *order*, not from the CSR: they are the
    names whose control was actually proven, and rebuilding the extension
    set from them is what keeps anything else the CSR carries out of the
    issued certificate. They are equal by the time this runs -- that is what
    :func:`cabin.acme.csr.check_identifiers` established -- so this is
    belt and braces, and cheap.

    No ``issuer_id`` is passed: spec 0017 FR-6 leaves ACME on the default
    rule (a directory per issuer is spec 0019's gap to close), so this either
    resolves the instance's one active issuer or -- with more than one --
    fails as :class:`~cabin.ca.service.IssuerRequiredError`, handled below
    like any other issuance failure.
    """
    identifiers = service.order_identifiers(order)
    sans = [
        f"{'IP' if entry['type'] == service.IP else 'DNS'}:{entry['value']}"
        for entry in identifiers
    ]
    pem = x509.load_der_x509_csr(der).public_bytes(serialization.Encoding.PEM).decode("ascii")
    try:
        return certs_service.sign_csr_and_store(
            db,
            request.app.state.secrets,
            csr_pem=pem,
            profile=ACME_PROFILE,
            sans_override=sans,
            subject_cn_fallback=_subject_cn(identifiers),
            # ...and if none of them fits, no subject at all rather than no
            # certificate; see :func:`_subject_cn`.
            allow_empty_subject=True,
            source=CertSource.acme,
        )
    except Exception as exc:
        # The claim comes off again whatever went wrong, so the client can
        # retry once an operator has fixed it. An order left ``processing``
        # by a failure nobody anticipated is one that can never be finalized
        # and never be retried, which is why this catches broadly and
        # re-raises rather than naming the failures it knows about.
        #
        # The order is deliberately not turned into an ``invalid`` one:
        # nothing about the request was wrong.
        db.rollback()
        service.release_claim(db, order)
        if isinstance(
            exc,
            IssueError | CANotConfiguredError | SecretsError | ValueError | IssuerRequiredError,
        ):
            raise AcmeError(
                ErrorType.server_internal,
                f"this certificate could not be issued: {exc}"[:400],
            ) from exc
        raise


# --- FR-2: the certificate -----------------------------------------------------------

#: The largest id a ``certificates`` row can carry: a signed 64-bit integer,
#: which is what both SQLite and PostgreSQL store one as.
MAX_CERT_ID = 2**63 - 1


def _certificate_id(raw_id: str) -> int:
    """The row id a ``/acme/cert/{id}`` URL names, or "no such certificate".

    ``raw_id.isdigit()`` is not "converts to an id this database can hold",
    and each of the three ways it is not used to escape as a bare 500 -- an
    answer with no problem document and, worse, no ``Replay-Nonce``, which
    strands a client whose nonce this request has already spent:

    * ``str.isdigit`` is true of ``'²'``, which ``int`` refuses;
    * it is true of a number far past what an id column can hold, which the
      database refuses (``OverflowError`` on SQLite, ``DataError`` on
      PostgreSQL) rather than answering "no such row";
    * and it is true of ``01``, which would otherwise be a second URL for
      certificate 1 -- one resource, two names.
    """
    if not (raw_id.isascii() and raw_id.isdigit()) or len(raw_id) > len(str(MAX_CERT_ID)):
        raise not_found("certificate")
    # Safe now: an ASCII digit string of at most 19 characters is an int, and
    # the canonical-spelling check below is what rejects "01" and "007".
    cert_id = int(raw_id)
    if str(cert_id) != raw_id or cert_id > MAX_CERT_ID:
        raise not_found("certificate")
    return cert_id


def _certificate_of(db: Session, raw_id: str, account_id: str) -> Certificate:
    """The certificate behind a ``/acme/cert/{id}`` URL, for this account.

    An id that is not a row id is "no such certificate" rather than a
    validation error: the path is public, and a 404 problem document is the
    same answer a wrong-but-well-formed id gets.
    """
    cert_id = _certificate_id(raw_id)
    order = service.order_for_certificate(db, cert_id)
    if order is None:
        # Either nothing was issued under that id, or it was issued through
        # the UI or the API -- which ACME has no claim on either way.
        raise not_found("certificate")
    if order.account_id != account_id:
        raise AcmeError(ErrorType.unauthorized, "this certificate belongs to another account")
    row = certs_service.get_certificate(db, cert_id)
    if row is None:  # pragma: no cover - the order's FK guarantees the row
        raise not_found("certificate")
    return row


def chain_pem(db: Session, row: Certificate) -> str:
    """FR-2/FR-8: leaf, then the chain of *its own* issuer, nearest first,
    root last.

    The root is included. For a public CA it would be redundant, but cabin's
    root is exactly what a client's trust store may not have yet, and an
    operator pointing a service at ``fullchain.pem`` should not have to go
    and fetch it separately.
    """
    try:
        chain = ca_service.chain_for(db, row.issuer_id)
    except ca_service.UnknownIssuerError as exc:  # pragma: no cover - FK guarantees the row
        raise AcmeError(
            ErrorType.server_internal, "no CA is configured on this cabin instance"
        ) from exc
    return row.cert_pem + "".join(ca.cert_pem for ca in chain)


@router.post("/cert/{cert_id}")
def certificate_resource(
    cert_id: str,
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """RFC 8555 7.4.2, read with POST-as-GET."""
    verification = verified(db, body, f"{CERT_PREFIX}{cert_id}", KeyMode.kid)
    account = account_of(verification)
    if verification.payload is not None:
        raise AcmeError(
            ErrorType.malformed,
            "a certificate is fetched with a POST-as-GET request, which carries no payload",
        )
    row = _certificate_of(db, cert_id, account.id)
    return Response(
        content=chain_pem(db, row),
        media_type=PEM_CHAIN_CONTENT_TYPE,
        # No Link rel="alternate": cabin publishes one chain (see the spec's
        # Out of Scope), and offering a link to nothing would be worse than
        # offering none.
    )


# --- FR-3: revocation ----------------------------------------------------------------


def _parse_reason(raw: object) -> RevocationReason:
    if raw is None:
        return RevocationReason.unspecified
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise AcmeError(ErrorType.malformed, "the revocation reason must be an RFC 5280 code")
    reason = REVOCATION_REASONS.get(raw)
    if reason is None:
        raise AcmeError(
            ErrorType.bad_revocation_reason,
            f"cabin does not revoke for reason code {raw}",
            extra={"reasons": sorted(REVOCATION_REASONS)},
        )
    return reason


def _submitted_certificate(payload: dict[str, Any]) -> x509.Certificate:
    der = b64decode(payload.get("certificate"), "the certificate")
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise AcmeError(ErrorType.malformed, "the certificate is not valid DER") from exc


def _stored_certificate(db: Session, submitted: x509.Certificate) -> Certificate:
    """The row this certificate is, or ``unauthorized``.

    Found by serial and then confirmed byte for byte. The second half is the
    one that matters: a serial is a number an attacker chooses when they
    build their own certificate, so "cabin has a row with that serial" is
    not evidence that cabin issued *this*.
    """
    row = certs_service.certificate_by_serial(db, format(submitted.serial_number, "x"))
    if row is None or row.cert_pem.encode("ascii") != submitted.public_bytes(
        serialization.Encoding.PEM
    ):
        raise AcmeError(ErrorType.unauthorized, "this certificate was not issued by this cabin")
    return row


def _authorize_revocation(
    db: Session,
    verification: VerifiedRequest,
    row: Certificate,
    submitted: x509.Certificate,
) -> str:
    """RFC 8555 7.6's two doors, and the label the audit log records.

    Either the account that placed the order which produced the certificate
    (kid mode), or possession of the certificate's own key (jwk mode). The
    second is what lets a host revoke a certificate whose account key it has
    lost -- which, when the reason is keyCompromise, is exactly the case
    that matters most.

    RFC 8555 7.6 opens a third door cabin deliberately does not: an account
    that merely holds *valid authorizations for all the identifiers* in a
    certificate may revoke it, even if another account was issued it. In an
    internal CA that is a demotion rather than a convenience -- it means any
    client that can still prove control of a name can revoke a colleague's
    certificate for it, and control of an internal name is often as cheap as
    winning a DHCP lease. Issuance stays the account's; revocation stays the
    issuing account's or the key holder's, and an operator can always revoke
    anything from the UI. Recorded in spec 0012 FR-3 as a known deviation.
    """
    if verification.account is not None:
        order = service.order_for_certificate(db, row.id)
        if order is None or order.account_id != verification.account.id:
            raise AcmeError(
                ErrorType.unauthorized,
                "this certificate was not issued to the account that signed this request",
            )
        return str(verification.account.jwk_thumbprint)
    # jwk mode: the signature was verified against the key in the header, so
    # what is left to prove is that that key is the certificate's own.
    # SubjectPublicKeyInfo on both sides -- the same key can be written as
    # several different JWKs, but only as one SPKI.
    certificate_spki = submitted.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if verification.key.public_der() != certificate_spki:
        raise AcmeError(
            ErrorType.unauthorized,
            "this request is not signed by the certificate's own key pair",
        )
    return str(verification.key.thumbprint)


@router.post("/revoke-cert")
def revoke_cert(
    request: Request,
    body: bytes = Depends(acme_body),
    db: Session = Depends(get_db),
) -> Response:
    """RFC 8555 7.6.

    The only route in cabin whose key mode is a property of the request
    rather than of the route, because the RFC gives a client two ways to
    prove it may do this. The header is read first (``key_mode``), the JWS
    is then verified in exactly that mode, and which of the two claims was
    made decides which check :func:`_authorize_revocation` runs.
    """
    verification = verified(db, body, REVOKE_CERT_PATH, key_mode(body))
    payload = _payload_of(verification, "revoke-cert")
    submitted = _submitted_certificate(payload)
    reason = _parse_reason(payload.get("reason"))
    row = _stored_certificate(db, submitted)
    thumbprint = _authorize_revocation(db, verification, row, submitted)

    if row.revoked_at is not None:
        raise AcmeError(
            ErrorType.already_revoked,
            "this certificate has already been revoked",
        )
    try:
        crl_service.revoke_certificate(db, request.app.state.secrets, row.id, reason)
    except (CANotConfiguredError, crl_service.RevocationError, SecretsError) as exc:
        raise AcmeError(
            ErrorType.server_internal,
            f"this certificate could not be revoked: {exc}"[:400],
        ) from exc
    audit.record(
        db,
        acme_actor(thumbprint),
        AuditAction.acme_certificate_revoked,
        summary=audit.revoked_summary(row, reason),
        target_type="certificate",
        target_id=row.id,
        detail=audit.revocation_detail(row, reason),
        ip=client_ip(request, db),
    )
    # RFC 8555 7.6: 200 and nothing else. The nonce a client needs next is
    # attached by the middleware, like on every other response here.
    return Response(status_code=200)
