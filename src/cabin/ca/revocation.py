"""Pure CRL construction: revocation reasons and the signed CRL itself
(spec 0007 FR-2/FR-3).

No FastAPI or database imports here -- this module only deals with
pyca/cryptography objects. Which certificates are revoked, and where the
resulting CRL is stored, is :mod:`cabin.ca.crl`'s job.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)

from cabin.ca.x509 import authority_key_identifier, signing_algorithm

#: How long a published CRL stays valid (FR-4). A relying party may cache it
#: until then, so this is also the longest a revocation can take to become
#: visible to a client that does not re-fetch early.
CRL_VALIDITY = timedelta(days=7)


class RevocationReason(StrEnum):
    """The reasons cabin offers (FR-2). Deliberately a subset of RFC 5280's
    list: ``certificateHold`` implies un-revocation, ``removeFromCRL`` only
    makes sense with delta CRLs, and the CA-compromise reasons are about
    revoking a CA, which cabin does not do (see Out of Scope)."""

    unspecified = "unspecified"
    key_compromise = "key_compromise"
    affiliation_changed = "affiliation_changed"
    superseded = "superseded"
    cessation_of_operation = "cessation_of_operation"


#: Reason -> the RFC 5280 code that goes on the wire (FR-2).
REASON_FLAGS: dict[RevocationReason, x509.ReasonFlags] = {
    RevocationReason.unspecified: x509.ReasonFlags.unspecified,
    RevocationReason.key_compromise: x509.ReasonFlags.key_compromise,
    RevocationReason.affiliation_changed: x509.ReasonFlags.affiliation_changed,
    RevocationReason.superseded: x509.ReasonFlags.superseded,
    RevocationReason.cessation_of_operation: x509.ReasonFlags.cessation_of_operation,
}


@dataclass(frozen=True)
class RevokedEntry:
    """One line of the CRL: which certificate, when, and why."""

    serial_number: int
    revoked_at: datetime
    reason: RevocationReason = RevocationReason.unspecified


def build_crl(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    revoked_entries: Sequence[RevokedEntry],
    crl_number: int,
    this_update: datetime,
    next_update: datetime,
) -> x509.CertificateRevocationList:
    """Build and sign a full CRL in ``issuer_cert``'s name (FR-3).

    Carries a CRLNumber (so relying parties can order two CRLs) and an
    AuthorityKeyIdentifier copied from the issuer's SKI (so they can find the
    key that signed it). Each entry gets a CRLReason unless its reason is
    ``unspecified`` -- which is exactly what a reason-less entry already
    means, so spelling it out would only add bytes.

    An empty ``revoked_entries`` is not an error: "nothing is revoked" is a
    statement worth signing (FR-4).
    """
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(authority_key_identifier(issuer_cert, issuer_key), critical=False)
    )
    for entry in revoked_entries:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(entry.serial_number)
            .revocation_date(entry.revoked_at)
        )
        if entry.reason is not RevocationReason.unspecified:
            revoked = revoked.add_extension(
                x509.CRLReason(REASON_FLAGS[entry.reason]), critical=False
            )
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(issuer_key, algorithm=signing_algorithm(issuer_key))
