"""Stored rows as the response models of :mod:`cabin.api.models`.

Shared by ``/api/v1`` (spec 0008) and the MCP server (spec 0013), which are
two front doors onto the same domain services. Neither of them may have its
own idea of what a certificate looks like: an operator who lists the
inventory over MCP and then over REST has to see the same fields with the
same values, and an assistant that has been told a certificate is "valid"
must mean the badge the UI would draw.

Nothing here touches the CA -- it only describes what is already stored.
"""

from datetime import datetime
from typing import Any

from cryptography import x509
from sqlalchemy.orm import Session

from cabin.api.models import (
    CAInfo,
    CertificateList,
    CertificatePem,
    CertificateSummary,
    IssuerInfo,
    RevocationInfo,
)
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.certs import PER_PAGE, Certificate, CertStatus, certificate_status
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import CACertificate, CANotConfiguredError
from cabin.ca.x509 import describe_certificate
from cabin.settings import BASE_URL, get_setting

#: What a caller is told when there is nothing to describe yet.
NO_CA = "no CA has been created or imported yet"


def issuer_info(db: Session, row: CACertificate) -> IssuerInfo:
    """One ``ca_certificates`` row, described the way ``GET /ca`` and the
    MCP ``get_ca_info`` tool both report it (spec 0017 FR-15).

    ``crl_url`` is ``None`` for a root -- no CRL route answers for one
    (FR-10) -- while ``ca_url`` is set for every row, since ``/ca/{id}.cer``
    serves both kinds.
    """
    described = describe_certificate(x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8")))
    return IssuerInfo.model_validate(
        {
            **described,
            "id": row.id,
            "name": row.name,
            "kind": row.kind,
            "status": row.status,
            "parent_id": row.parent_id,
            "crl_url": crl_service.distribution_url(db, row.id)
            if row.kind == "intermediate"
            else None,
            "ca_url": crl_service.ca_issuers_url(db, row.id),
        }
    )


def ca_info(db: Session) -> CAInfo:
    """Every CA row this instance holds, with its own URLs (spec 0017
    FR-15). Raises CANotConfiguredError while there is no CA at all."""
    rows = ca_service.list_cas(db)
    if not rows:
        raise CANotConfiguredError(NO_CA)
    return CAInfo(
        issuers=[issuer_info(db, row) for row in rows],
        base_url=get_setting(db, BASE_URL),
    )


def certificate_fields(row: Certificate, now: datetime) -> dict[str, Any]:
    """Everything every certificate response model shares, computed once.

    ``now`` is passed in rather than read here so that a page of rows is
    filtered and badged against a single instant -- a row cannot be selected
    as "expiring" and then reported as "expired" a tick later.
    """
    return {
        "id": row.id,
        "serial_hex": row.serial_hex,
        "subject_cn": row.subject_cn,
        "sans": row.sans,
        "profile": row.profile,
        "not_before": datetime.fromisoformat(row.not_before),
        "not_after": row.not_after_dt,
        "status": certificate_status(row.not_after_dt, now, row.revoked_at_dt),
        "has_key": row.key_sealed is not None,
        "revoked_at": row.revoked_at_dt,
        "revocation_reason": row.revocation_reason,
    }


def certificate_summary(row: Certificate, now: datetime) -> CertificateSummary:
    return CertificateSummary.model_validate(certificate_fields(row, now))


def certificate_list(
    rows: list[Certificate], total: int, page: int, now: datetime
) -> CertificateList:
    return CertificateList(
        items=[certificate_summary(row, now) for row in rows],
        total=total,
        page=page,
        per_page=PER_PAGE,
        pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
    )


def chain_pem_for_issuer(db: Session, issuer_id: int) -> str:
    """The issuer chain, nearest issuer first -- the same order
    /certs/{id}/download/chain.pem serves.

    Built from the *leaf's own* issuer (spec 0017 FR-8) rather than from a
    single instance-wide hierarchy: with several hierarchies side by side,
    which chain is right depends on who actually signed the certificate.
    """
    return "".join(row.cert_pem for row in ca_service.chain_for(db, issuer_id))


def certificate_pem(
    db: Session,
    row: Certificate,
    now: datetime,
    *,
    validity_capped_from: datetime | None = None,
) -> CertificatePem:
    """One certificate and its chain, with no room for a private key.

    ``validity_capped_from`` (spec 0017 FR-7) is set only by an issuance
    call site, from the ``Issued.capped_from`` it just got back -- a lookup
    never passes it, so a later ``GET`` cannot claim a clamp that has not
    just happened.
    """
    return CertificatePem.model_validate(
        {
            **certificate_fields(row, now),
            "cert_pem": row.cert_pem,
            "chain_pem": chain_pem_for_issuer(db, row.issuer_id),
            "validity_capped_from": validity_capped_from,
        }
    )


def revocation_info(db: Session, row: Certificate) -> RevocationInfo:
    """What a completed revocation reports back. ``row`` must already be
    revoked -- every caller gets it from
    :func:`cabin.ca.crl.revoke_certificate`, which either revokes or raises.
    """
    revoked_at = row.revoked_at_dt
    assert revoked_at is not None
    return RevocationInfo(
        id=row.id,
        serial_hex=row.serial_hex,
        status=CertStatus.revoked,
        revoked_at=revoked_at,
        reason=RevocationReason(row.revocation_reason or RevocationReason.unspecified),
        crl_url=crl_service.distribution_url(db, row.issuer_id),
    )
