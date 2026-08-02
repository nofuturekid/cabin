"""External account binding (spec 0012 FR-4, RFC 8555 7.3.4): the
operator-issued credentials a client must present before it may register.

The point of EAB is that reaching cabin's ACME endpoint is not the same as
being allowed to use it. An operator creates a key here, hands the key id
and the HMAC secret to one host, and that host -- and only that host -- can
register an account.

Three rules make that hold, and all three live in this module:

* **The secret is never stored in the clear.** It is sealed with the
  AES-256-GCM secrets layer (spec 0002) on the way in and unsealed for the
  length of one MAC check. A database dump is then not a set of live
  credentials, and neither is a backup.
* **The secret is shown exactly once**, in the response to the request that
  created it. There is no path here that returns it again -- not for the
  UI, not for the API -- because "show it to me again" and "let an attacker
  who reached the page read it" are the same request.
* **A key binds one account.** RFC 8555 does not require that, but an
  operator handing out one credential per host means one account per
  credential, and the conditional UPDATE in :func:`bind` is what makes it a
  property of the database rather than of the code that raced for it.
"""

import base64
import secrets as _secrets
from datetime import UTC, datetime
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.acme import jws
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.models import AcmeAccount
from cabin.secrets import SecretsError, SecretStore
from cabin.store import Base

#: Width of the HMAC key handed to a client. 256 bits, i.e. the full block
#: size of the SHA-256 the binding is MACed with -- there is no reason to
#: hand out less than the algorithm can use.
_SECRET_BYTES = 32
#: Width of a key identifier. It is public (it travels in the inner JWS's
#: kid header and in the client's config file), but it is still a lookup
#: key, so it is unguessable rather than sequential.
_ID_BYTES = 16
#: Cap on the operator's label, mirroring the API token page's.
MAX_LABEL_LENGTH = 100


class AcmeEabKey(Base):
    """One operator-issued binding credential.

    ``id`` is the key identifier a client puts in its configuration;
    ``hmac_sealed`` is the sealed MAC key. ``bound_account_id`` is NULL
    until the key is spent, and the unique index on it (migration 0009) is
    what stops two registrations from spending it at once.
    """

    __tablename__ = "acme_eab_keys"

    id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    hmac_sealed: Mapped[str] = mapped_column(sa.Text, nullable=False)
    label: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    bound_account_id: Mapped[str | None] = mapped_column(
        sa.String(64), sa.ForeignKey("acme_accounts.id"), nullable=True
    )
    bound_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)

    @property
    def is_usable(self) -> bool:
        return self.revoked_at is None and self.bound_account_id is None


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def _b64(data: bytes) -> str:
    """base64url without padding -- the form every ACME client's
    ``--eab-hmac-key`` flag expects."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_key(
    db: Session, secrets: SecretStore, *, label: str, now: datetime | None = None
) -> tuple[AcmeEabKey, str]:
    """Mint one credential. Returns the row and the base64url secret -- the
    only time that string exists outside the client's configuration."""
    secret = _secrets.token_bytes(_SECRET_BYTES)
    row = AcmeEabKey(
        id=_secrets.token_urlsafe(_ID_BYTES),
        hmac_sealed=secrets.seal(secret),
        label=label.strip()[:MAX_LABEL_LENGTH],
        created_at=_iso(now or datetime.now(UTC)),
    )
    db.add(row)
    db.commit()
    return row, _b64(secret)


def get_key(db: Session, key_id: str) -> AcmeEabKey | None:
    return db.get(AcmeEabKey, key_id)


def list_keys(db: Session) -> list[AcmeEabKey]:
    return list(db.scalars(select(AcmeEabKey).order_by(AcmeEabKey.created_at.desc())).all())


def revoke_key(db: Session, row: AcmeEabKey | None, now: datetime | None = None) -> bool:
    """Take a key out of service. Idempotent, and tolerant of a key that is
    already gone -- both leave the world exactly as it was, so neither is an
    error and neither is an event."""
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = _iso(now or datetime.now(UTC))
    db.commit()
    return True


#: One wording for every way a binding can fail to authorize a registration.
#: Deliberately the same for "no such key", "already used" and "revoked": a
#: client that is not entitled to register learns that it is not entitled,
#: and nothing about which of the operator's keys exist.
_REFUSED = "the external account binding does not authorize this registration"


def verify(
    db: Session,
    secrets: SecretStore,
    binding: object,
    *,
    new_account_url: str,
    account_jwk: dict[str, Any],
) -> AcmeEabKey:
    """Check one ``externalAccountBinding`` and return the key it names.

    Does not bind it -- :func:`bind` does that, once the account exists.
    """
    if not isinstance(binding, dict):
        raise AcmeError(ErrorType.malformed, "externalAccountBinding must be a JSON object")
    parsed = jws.parse_external_binding(binding, url=new_account_url)
    row = get_key(db, parsed.kid)
    if row is None or not row.is_usable:
        # The MAC is not checked in this branch, so a client cannot use the
        # timing of this answer to sort key ids into "exists" and "does not".
        # It cannot learn anything from the answer itself either -- see
        # _REFUSED above.
        raise AcmeError(ErrorType.unauthorized, _REFUSED)
    try:
        mac_key = secrets.unseal(row.hmac_sealed)
    except SecretsError as exc:
        # The master key can no longer open what the database holds. That is
        # cabin's problem, not the client's, and saying "unauthorized" would
        # send an operator looking at the wrong end of it.
        raise AcmeError(
            ErrorType.server_internal,
            "this external account key cannot be read: it was sealed with a different master key",
        ) from exc
    jws.verify_external_binding(parsed, mac_key=mac_key, account_jwk=account_jwk)
    return row


def bind(db: Session, row: AcmeEabKey, account: AcmeAccount, now: datetime | None = None) -> bool:
    """Spend the key on ``account``. Returns False if someone else got there
    first.

    One statement, not a read followed by a write: two registrations that
    both passed :func:`verify` at the same moment both saw an unbound key,
    and the WHERE clause below is what makes exactly one of them the winner.
    """
    claimed = cast(
        "CursorResult[Any]",
        db.execute(
            update(AcmeEabKey)
            .where(
                AcmeEabKey.id == row.id,
                AcmeEabKey.bound_account_id.is_(None),
                AcmeEabKey.revoked_at.is_(None),
            )
            .values(bound_account_id=account.id, bound_at=_iso(now or datetime.now(UTC)))
        ),
    )
    db.commit()
    db.refresh(row)
    return bool(claimed.rowcount == 1)


def refused() -> AcmeError:
    """The error for a client that lost the race in :func:`bind` -- same
    wording as every other refusal, for the same reason."""
    return AcmeError(ErrorType.unauthorized, _REFUSED)
