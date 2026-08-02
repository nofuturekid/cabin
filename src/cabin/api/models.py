"""Request and response models for /api/v1 (spec 0008 FR-5).

Two rules shape this module:

* the limits are the *same* limits the UI enforces -- they are imported from
  the domain modules, never retyped, and the two literal types below are
  pinned to their domain tuples by a test;
* ``key_pem`` is present only where it may be. The routes serialize with
  ``response_model_exclude_none=True``, so an optional field that is None is
  absent from the JSON rather than sitting there as ``null`` with a hint --
  which is what FR-5 asks for, and reads the same for ``revoked_at`` on a
  certificate that was never revoked.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cabin.audit import ActorKind, AuditAction
from cabin.ca.certs import CertStatus
from cabin.ca.leaf import (
    DEFAULT_DAYS,
    MAX_CN_LENGTH,
    MAX_DAYS,
    MAX_SANS,
    MIN_DAYS,
    Profile,
)
from cabin.ca.revocation import RevocationReason

#: Mirrors :data:`cabin.ca.x509.KEY_TYPES`; spelled out as a Literal so the
#: OpenAPI document enumerates the choices instead of saying "string".
KeyType = Literal["ecdsa-p256", "ecdsa-p384", "rsa-4096", "ed25519"]
#: Mirrors :data:`cabin.ca.certs.STATUS_FILTERS`. Unlike the UI -- which
#: treats an unknown ?status= as a typo and shows everything -- an unknown
#: value here is a 422: a script that filters on a name we do not have must
#: be told, not quietly handed the whole inventory.
StatusFilter = Literal["all", "valid", "expiring", "expired", "revoked"]


class ErrorDetail(BaseModel):
    """Every failure the API returns, from a rejected token to a rejected
    CSR (FR-3): one JSON object with one human-readable message."""

    detail: str


class CACertificateInfo(BaseModel):
    """One CA certificate as ``GET /ca`` describes it."""

    kind: Literal["root", "intermediate"]
    subject: str
    issuer: str
    serial: str
    not_valid_before: datetime
    not_valid_after: datetime
    #: SHA-256 over the DER, colon-separated hex.
    fingerprint: str
    key_type: str


class CAInfo(BaseModel):
    root: CACertificateInfo
    intermediate: CACertificateInfo
    #: The configured public origin, or absent while none is set.
    base_url: str | None = None
    #: Where this instance publishes its CRL; absent without a base URL,
    #: which is also when newly issued certificates carry no CDP.
    crl_url: str | None = None


class CertificateSummary(BaseModel):
    """One inventory row."""

    id: int
    serial_hex: str
    subject_cn: str
    sans: list[str]
    profile: Profile
    not_before: datetime
    not_after: datetime
    status: CertStatus
    #: Whether cabin holds this certificate's private key (false for
    #: everything that arrived as a CSR).
    has_key: bool
    revoked_at: datetime | None = None
    revocation_reason: RevocationReason | None = None


class CertificateDetail(CertificateSummary):
    """One certificate with its PEM material."""

    cert_pem: str
    #: The issuer chain, nearest issuer first -- intermediate then root.
    chain_pem: str
    #: Present only in the response to POST /certificates and, for an
    #: admin+ caller, on a certificate whose key cabin still holds.
    key_pem: str | None = None
    #: Set instead of ``key_pem`` when a stored key exists but cannot be
    #: decrypted: an unusable key is said out loud, not silently omitted.
    key_error: str | None = None


class CertificateList(BaseModel):
    items: list[CertificateSummary]
    #: Matches across the whole filtered set, not just this page.
    total: int
    page: int
    per_page: int
    pages: int


class RevocationInfo(BaseModel):
    """What POST /certificates/{id}/revoke reports back."""

    id: int
    serial_hex: str
    status: CertStatus
    revoked_at: datetime
    reason: RevocationReason
    #: Where the CRL now listing this serial is published, if configured.
    crl_url: str | None = None


class AuditEventInfo(BaseModel):
    """One audit entry (spec 0009 FR-7) -- the same row /audit renders."""

    id: int
    occurred_at: datetime
    actor_kind: ActorKind
    #: Absent for an actor with no row behind it: a failed login, or cabin
    #: itself.
    actor_id: int | None = None
    actor_label: str
    action: AuditAction
    target_type: str | None = None
    #: Text, because not every target is an integer id.
    target_id: str | None = None
    summary: str
    #: Identifiers, names, serials and reasons -- never key material,
    #: passwords or token secrets (FR-3).
    detail: dict[str, Any] | None = None
    ip: str | None = None


class AuditEventList(BaseModel):
    items: list[AuditEventInfo]
    #: Matches across the whole filtered set, not just this page.
    total: int
    page: int
    per_page: int
    pages: int


class IssueRequest(BaseModel):
    """POST /certificates -- issue with a server-generated key."""

    model_config = ConfigDict(extra="forbid")

    subject_cn: str = Field(min_length=1, max_length=MAX_CN_LENGTH)
    #: ``dns:``/``ip:``/``email:`` prefixes optional; empty falls back to the
    #: CN, exactly as in the UI.
    sans: list[str] = Field(default_factory=list, max_length=MAX_SANS)
    profile: Profile = Profile.server
    key_type: KeyType = "ecdsa-p256"
    days: int = Field(default=DEFAULT_DAYS, ge=MIN_DAYS, le=MAX_DAYS)


class SignRequest(BaseModel):
    """POST /certificates/sign -- sign a CSR cabin has no key for."""

    model_config = ConfigDict(extra="forbid")

    csr_pem: str = Field(min_length=1)
    profile: Profile = Profile.server
    days: int = Field(default=DEFAULT_DAYS, ge=MIN_DAYS, le=MAX_DAYS)
    #: Overrides the CSR's own SANs when given.
    sans: list[str] = Field(default_factory=list, max_length=MAX_SANS)


class RevokeRequest(BaseModel):
    """POST /certificates/{id}/revoke."""

    model_config = ConfigDict(extra="forbid")

    reason: RevocationReason = RevocationReason.unspecified
