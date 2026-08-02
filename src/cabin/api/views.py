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
    CACertificateInfo,
    CAInfo,
    CertificateList,
    CertificatePem,
    CertificateSummary,
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


def hierarchy(db: Session) -> ca_service.CAHierarchy:
    """The CA, or :class:`CANotConfiguredError` -- so that "cabin is not set
    up yet" is one sentence, raised in one place, and each front door only
    has to decide how to *report* it."""
    found = ca_service.get_ca(db)
    if found is None:
        raise CANotConfiguredError(NO_CA)
    return found


def ca_certificate_info(row: CACertificate) -> CACertificateInfo:
    described = describe_certificate(x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8")))
    return CACertificateInfo.model_validate({**described, "kind": row.kind})


def ca_info(db: Session) -> CAInfo:
    """Subjects, fingerprints, validity and the URLs this instance
    publishes. Raises CANotConfiguredError while there is no CA."""
    found = hierarchy(db)
    return CAInfo(
        root=ca_certificate_info(found.root),
        intermediate=ca_certificate_info(found.intermediate),
        base_url=get_setting(db, BASE_URL),
        crl_url=crl_service.distribution_url(db),
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


def chain_pem(db: Session) -> str:
    """The issuer chain, nearest issuer first -- the same order
    /certs/{id}/download/chain.pem serves."""
    found = hierarchy(db)
    return found.intermediate.cert_pem + found.root.cert_pem


def certificate_pem(db: Session, row: Certificate, now: datetime) -> CertificatePem:
    """One certificate and its chain, with no room for a private key."""
    return CertificatePem.model_validate(
        {
            **certificate_fields(row, now),
            "cert_pem": row.cert_pem,
            "chain_pem": chain_pem(db),
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
        crl_url=crl_service.distribution_url(db),
    )
