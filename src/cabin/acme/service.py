"""ACME accounts, orders, authorizations and challenges (spec 0010 FR-3,
FR-7).

Everything here is about the database and the protocol's rules; nothing here
knows about HTTP, request URLs or FastAPI. The identifier policy is the one
place where ACME meets the rest of cabin: a name arriving over ACME is put
through exactly the SAN validation of spec 0005 (:mod:`cabin.ca.leaf`), so a
name that could not be typed into the issuance form cannot be smuggled in
through an order either.
"""

import ipaddress
import json
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.jws import AccountKey
from cabin.acme.models import (
    AccountStatus,
    AcmeAccount,
    AcmeAuthorization,
    AcmeChallenge,
    AcmeOrder,
    AuthorizationStatus,
    ChallengeStatus,
    OrderStatus,
    kid_hash,
)
from cabin.ca import leaf

#: How long an order stays placeable before a client has to start over.
ORDER_LIFETIME = timedelta(days=7)
#: How long a proof of control stays good. Same window as the order, so an
#: authorization never outlives the only order that can use it.
AUTHZ_LIFETIME = timedelta(days=7)

#: What a client may prove control of a name with (spec 0011 implements the
#: proving). A wildcard is DNS-only because there is nowhere to serve an
#: HTTP file for "*." (RFC 8555 8.4); an IP identifier is not DNS-provable
#: because it has no name to put a TXT record on (RFC 8738 4).
CHALLENGE_TYPES: tuple[str, ...] = ("http-01", "dns-01", "tls-alpn-01")
WILDCARD_CHALLENGE_TYPES: tuple[str, ...] = ("dns-01",)
IP_CHALLENGE_TYPES: tuple[str, ...] = ("http-01", "tls-alpn-01")

#: Identifier types cabin can issue for (FR-7).
DNS = "dns"
IP = "ip"

#: Bounds on one order. The identifier cap is the SAN cap of spec 0005 -- an
#: order that cannot become a certificate is not worth storing.
MAX_IDENTIFIERS = leaf.MAX_SANS
#: Bounds on an account's contacts, so a registration cannot become storage.
MAX_CONTACTS = 10
MAX_CONTACT_LENGTH = 255

#: Width of an opaque id: 128 bits, rendered as 22 base64url characters.
#: These appear verbatim in URLs, so they have to be unguessable -- a
#: resource URL is the only thing that ties an order to its account.
_ID_BYTES = 16
#: Challenge tokens get 256 bits: they are also a key-authorization input.
_TOKEN_BYTES = 32


def new_id() -> str:
    return secrets.token_urlsafe(_ID_BYTES)


def _iso(moment: datetime) -> str:
    """The shape every timestamp in this schema is stored in -- the same one
    :mod:`cabin.audit` and :mod:`cabin.ca.certs` use."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


# --- FR-7: identifier policy ---------------------------------------------------------


@dataclass(frozen=True)
class Identifier:
    """One requested name. ``value`` is what the order echoes back (so a
    wildcard keeps its star); ``base_value`` is what the authorization names,
    which for a wildcard is the domain underneath it (RFC 8555 7.1.4)."""

    type: str
    value: str
    base_value: str
    wildcard: bool

    def as_json(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


def _reject(message: str) -> AcmeError:
    """One rejection, one sentence. The caller quotes the offending value
    exactly once -- ``leaf.IssueError`` already includes it, so wrapping
    those messages with the value again read as ``"…: 'x': 'x'"``."""
    return AcmeError(ErrorType.rejected_identifier, message[:200])


def _dns_identifier(raw: str) -> Identifier:
    """A DNS name, validated by spec 0005's SAN policy and nothing weaker."""
    if not raw or any(character.isspace() for character in raw):
        raise _reject(f"not a valid hostname: {raw!r}")
    # DNS is case-insensitive, so NAS.LAN and nas.lan are one name -- folding
    # here rather than at comparison time means one authorization, one
    # challenge set, and one value in the issued certificate.
    value = raw.lower()
    if _is_ip(value):
        # 192.0.2.1 matches the hostname grammar, but an address is not a
        # name: RFC 8738 gives it its own identifier type, and issuing it as
        # a DNS SAN would put the wrong kind of name in the certificate.
        raise _reject(f"an IP address must be requested as an ip identifier: {value!r}")
    wildcard = value.startswith("*.")
    try:
        # One entry in, one entry out -- the whitespace guard above is what
        # keeps a smuggled newline from turning this into two names.
        normalized = leaf.parse_san_lines(f"dns:{value}")
    except leaf.IssueError as exc:
        raise _reject(str(exc)) from exc
    if normalized != [f"DNS:{value}"]:
        raise _reject(f"not a valid hostname: {value!r}")
    return Identifier(
        type=DNS,
        value=value,
        base_value=value[2:] if wildcard else value,
        wildcard=wildcard,
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ip_identifier(value: str) -> Identifier:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise _reject(f"not a valid IP address: {value!r}") from exc
    canonical = str(address)
    return Identifier(type=IP, value=canonical, base_value=canonical, wildcard=False)


def parse_identifiers(raw: object) -> list[Identifier]:
    """The ``identifiers`` member of a new-order payload (FR-7, AC-8).

    An unknown *type* is ``unsupportedIdentifier`` and a bad *value* is
    ``rejectedIdentifier``: the first says "cabin will never do this", the
    second "not this one" -- and a client can only act sensibly on the
    difference.
    """
    if not isinstance(raw, list) or not raw:
        raise AcmeError(ErrorType.malformed, "an order needs a non-empty identifiers array")
    if len(raw) > MAX_IDENTIFIERS:
        raise AcmeError(
            ErrorType.malformed,
            f"an order may name at most {MAX_IDENTIFIERS} identifiers",
        )
    parsed: list[Identifier] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise AcmeError(ErrorType.malformed, "each identifier must be a JSON object")
        kind, value = entry.get("type"), entry.get("value")
        if not isinstance(value, str):
            raise AcmeError(ErrorType.malformed, "each identifier needs a string value")
        if kind == DNS:
            parsed.append(_dns_identifier(value))
        elif kind == IP:
            parsed.append(_ip_identifier(value))
        else:
            raise AcmeError(
                ErrorType.unsupported_identifier,
                f"cabin issues for dns and ip identifiers only, not {kind!r}"[:200],
            )
    # A name asked for twice is one authorization, not two.
    return list(dict.fromkeys(parsed))


def challenge_types_for(identifier: Identifier) -> tuple[str, ...]:
    if identifier.wildcard:
        return WILDCARD_CHALLENGE_TYPES
    if identifier.type == IP:
        return IP_CHALLENGE_TYPES
    return CHALLENGE_TYPES


# --- accounts ------------------------------------------------------------------------


def parse_contacts(raw: object) -> list[str]:
    """RFC 8555 7.3: contacts are URLs. Validated rather than stored as
    typed, because a contact that is not reachable is worse than none -- and
    because this is the one free-text field an account can set."""
    if not isinstance(raw, list):
        raise AcmeError(ErrorType.malformed, "contact must be an array of URLs")
    if len(raw) > MAX_CONTACTS:
        raise AcmeError(ErrorType.malformed, f"at most {MAX_CONTACTS} contacts are accepted")
    contacts: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry or len(entry) > MAX_CONTACT_LENGTH:
            raise AcmeError(ErrorType.malformed, "each contact must be a non-empty URL")
        scheme, separator, rest = entry.partition(":")
        if not separator or not rest or not scheme.isascii() or not scheme.isalpha():
            raise AcmeError(ErrorType.malformed, f"contact is not a URL: {entry!r}"[:200])
        if any(character.isspace() for character in entry):
            raise AcmeError(ErrorType.malformed, "a contact URL must not contain whitespace")
        contacts.append(entry)
    return contacts


def find_account_by_key(db: Session, thumbprint: str) -> AcmeAccount | None:
    return db.scalar(select(AcmeAccount).where(AcmeAccount.jwk_thumbprint == thumbprint))


def get_or_create_account(
    db: Session,
    key: AccountKey,
    *,
    contacts: list[str] | None,
    tos_agreed: bool,
    now: datetime | None = None,
) -> tuple[AcmeAccount, bool]:
    """AC-3: new-account is idempotent on the *key*, not on the request.

    Returns ``(account, created)``. The unique index on the thumbprint is
    what decides the race between two simultaneous first registrations --
    the loser reads back the winner's row rather than failing, which is what
    a retrying client expects.
    """
    existing = find_account_by_key(db, key.thumbprint)
    if existing is not None:
        return existing, False
    moment = now or datetime.now(UTC)
    account_id = new_id()
    account = AcmeAccount(
        id=account_id,
        kid_hash=kid_hash(account_id),
        jwk_json=json.dumps(key.jwk, sort_keys=True),
        jwk_thumbprint=key.thumbprint,
        status=AccountStatus.valid,
        contacts_json=json.dumps(contacts) if contacts is not None else None,
        tos_agreed_at=_iso(moment) if tos_agreed else None,
        created_at=_iso(moment),
    )
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raced = find_account_by_key(db, key.thumbprint)
        if raced is None:  # pragma: no cover - only reachable on real corruption
            raise
        return raced, False
    return account, True


def set_contacts(db: Session, account: AcmeAccount, contacts: list[str]) -> None:
    account.contacts_json = json.dumps(contacts)
    db.commit()


def deactivate_account(db: Session, account: AcmeAccount) -> None:
    """RFC 8555 7.3.6: a one-way door. There is no reactivation path here,
    deliberately -- the client's remedy is a new account."""
    account.status = AccountStatus.deactivated
    db.commit()


def rotate_account_key(db: Session, account: AcmeAccount, key: AccountKey) -> None:
    account.jwk_json = json.dumps(key.jwk, sort_keys=True)
    account.jwk_thumbprint = key.thumbprint
    db.commit()


def account_contacts(account: AcmeAccount) -> list[str]:
    if not account.contacts_json:
        return []
    stored: list[str] = json.loads(account.contacts_json)
    return stored


# --- orders, authorizations, challenges ------------------------------------------------


def parse_timestamp(raw: object, field: str) -> str | None:
    """An optional RFC 3339 instant from an order payload.

    ``OverflowError`` is caught alongside ``ValueError`` because a timestamp
    can parse and *still* not survive being normalized: converting
    ``9999-12-31T23:59:59-14:00`` to UTC lands past ``datetime.max``, and an
    order payload is attacker-supplied.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise AcmeError(ErrorType.malformed, f"{field} must be an RFC 3339 timestamp")
    try:
        moment = datetime.fromisoformat(raw)
        if moment.tzinfo is None:
            raise AcmeError(ErrorType.malformed, f"{field} must name a time zone")
        return _iso(moment)
    except (ValueError, OverflowError) as exc:
        raise AcmeError(
            ErrorType.malformed,
            f"{field} is not a usable RFC 3339 timestamp: {raw!r}"[:200],
        ) from exc


def create_order(
    db: Session,
    account: AcmeAccount,
    identifiers: Sequence[Identifier],
    *,
    not_before: str | None = None,
    not_after: str | None = None,
    now: datetime | None = None,
) -> AcmeOrder:
    """One order, one authorization per identifier, and the challenges that
    could prove it -- written in a single transaction, so a client never sees
    an order whose authorizations are still being built."""
    moment = now or datetime.now(UTC)
    order = AcmeOrder(
        id=new_id(),
        account_id=account.id,
        status=OrderStatus.pending,
        identifiers_json=json.dumps([identifier.as_json() for identifier in identifiers]),
        not_before=not_before,
        not_after=not_after,
        expires_at=_iso(moment + ORDER_LIFETIME),
        created_at=_iso(moment),
    )
    db.add(order)
    for identifier in identifiers:
        authz = AcmeAuthorization(
            id=new_id(),
            order_id=order.id,
            identifier_type=identifier.type,
            identifier_value=identifier.base_value,
            status=AuthorizationStatus.pending,
            expires_at=_iso(moment + AUTHZ_LIFETIME),
            wildcard=identifier.wildcard,
        )
        db.add(authz)
        for challenge_type in challenge_types_for(identifier):
            db.add(
                AcmeChallenge(
                    id=new_id(),
                    authz_id=authz.id,
                    type=challenge_type,
                    # A token per challenge, never one per authorization: the
                    # key authorization is derived from it, and reusing one
                    # across challenge types would let a proof for the
                    # cheapest one stand in for the others.
                    token=secrets.token_urlsafe(_TOKEN_BYTES),
                    status=ChallengeStatus.pending,
                )
            )
    db.commit()
    return order


def order_identifiers(order: AcmeOrder) -> list[dict[str, str]]:
    stored: list[dict[str, str]] = json.loads(order.identifiers_json)
    return stored


def _has_expired(expires_at: str, now: datetime | None) -> bool:
    # Both sides are fixed-layout UTC ISO-8601, so this is a string
    # comparison in the same order as a chronological one.
    return expires_at <= _iso(now or datetime.now(UTC))


def order_status(order: AcmeOrder, now: datetime | None = None) -> str:
    """RFC 8555 7.1.3: ``expires`` is the instant after which the server
    considers the order invalid -- so past it, it is invalid, whatever the
    stored row still says.

    Computed rather than written back: a read is not a state change, and a
    lazy UPDATE on every POST-as-GET would be a write amplification for no
    gain. Spec 0011 calls this before validating a challenge, which is why it
    is one shared function and not two readings of the same column.
    """
    if order.status == OrderStatus.pending and _has_expired(order.expires_at, now):
        return OrderStatus.invalid
    return order.status


def authorization_status(authz: AcmeAuthorization, now: datetime | None = None) -> str:
    """RFC 8555 7.1.4: an authorization past its expiry reads ``expired``.

    Only a pending or valid one can expire; an invalid authorization stays
    invalid, because *why* it failed outranks *when*.
    """
    if authz.status in (
        AuthorizationStatus.pending,
        AuthorizationStatus.valid,
    ) and _has_expired(authz.expires_at, now):
        return AuthorizationStatus.expired
    return authz.status


def get_order(db: Session, order_id: str) -> AcmeOrder | None:
    return db.get(AcmeOrder, order_id)


def get_authorization(db: Session, authz_id: str) -> AcmeAuthorization | None:
    return db.get(AcmeAuthorization, authz_id)


def get_challenge(db: Session, challenge_id: str) -> AcmeChallenge | None:
    return db.get(AcmeChallenge, challenge_id)


def authorizations_of(db: Session, order: AcmeOrder) -> list[AcmeAuthorization]:
    return list(
        db.scalars(
            select(AcmeAuthorization)
            .where(AcmeAuthorization.order_id == order.id)
            .order_by(AcmeAuthorization.id)
        ).all()
    )


def challenges_of(db: Session, authz: AcmeAuthorization) -> list[AcmeChallenge]:
    return list(
        db.scalars(
            select(AcmeChallenge)
            .where(AcmeChallenge.authz_id == authz.id)
            .order_by(AcmeChallenge.id)
        ).all()
    )


def orders_of(db: Session, account: AcmeAccount) -> list[AcmeOrder]:
    return list(
        db.scalars(
            select(AcmeOrder)
            .where(AcmeOrder.account_id == account.id)
            .order_by(AcmeOrder.created_at, AcmeOrder.id)
        ).all()
    )
