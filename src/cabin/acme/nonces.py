"""Anti-replay nonces (spec 0010 FR-3, AC-1).

RFC 8555 section 6.5: every POST carries a nonce the server issued, and the
server rejects a nonce it has already seen. Two things make that true here
rather than nearly true:

* **Consuming is a DELETE.** The nonce is the primary key, so "is it still
  unused?" and "mark it used" are one statement whose row count decides the
  answer. Two concurrent requests quoting the same nonce cannot both see it
  as unused, on SQLite and on PostgreSQL alike -- a read-then-delete would
  let them.
* **Expiry is part of the same statement.** A nonce older than
  :data:`NONCE_LIFETIME` does not match the DELETE, so it is refused without
  a second round trip and without the row having to be gone already.
"""

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from sqlalchemy.sql import Delete

from cabin.acme.models import AcmeNonce

#: How long a handed-out nonce stays usable. Long enough that a client that
#: pre-fetched one is not punished for a slow DNS update; short enough that
#: the table is bounded by a day's traffic rather than by all of it.
NONCE_LIFETIME = timedelta(hours=24)

#: 128 bits, the width RFC 8555 6.5.1 asks for. ``token_urlsafe`` renders it
#: as 22 base64url characters, which is what the ``Replay-Nonce`` header and
#: the JWS ``nonce`` field both want -- no re-encoding anywhere.
_NONCE_BYTES = 16


def _iso(moment: datetime) -> str:
    """The shape ``issued_at`` is stored in: UTC, second granularity, fixed
    layout -- so string order is time order and the expiry comparison is a
    plain string comparison both databases evaluate identically."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def issue(db: Session, *, now: datetime | None = None) -> str:
    """Hand out a fresh nonce, and clear out the expired ones while we are
    here.

    The opportunistic purge rides along with issuing rather than running on a
    schedule: cabin has no scheduler (see the CRL's lazy regeneration in spec
    0007), and every ACME response issues a nonce, so the table is swept
    exactly as often as it grows.
    """
    moment = now or datetime.now(UTC)
    purge(db, now=moment)
    nonce = secrets.token_urlsafe(_NONCE_BYTES)
    db.add(AcmeNonce(nonce=nonce, issued_at=_iso(moment)))
    db.commit()
    return nonce


def _delete(db: Session, statement: Delete) -> int:
    """Run a DELETE and commit it, returning the number of rows it removed.

    ``Session.execute`` is typed as returning a plain ``Result``; for DML it
    is a ``CursorResult``, which is where ``rowcount`` lives. One narrowing
    here beats one at every call site.
    """
    result = cast(CursorResult[Any], db.execute(statement))
    db.commit()
    return int(result.rowcount)


def consume(db: Session, nonce: str, *, now: datetime | None = None) -> bool:
    """Spend ``nonce``. True exactly once per issued nonce; False if it is
    unknown, already spent, or older than :data:`NONCE_LIFETIME`."""
    if not nonce:
        return False
    cutoff = _iso((now or datetime.now(UTC)) - NONCE_LIFETIME)
    return (
        _delete(
            db,
            sa.delete(AcmeNonce).where(AcmeNonce.nonce == nonce, AcmeNonce.issued_at >= cutoff),
        )
        == 1
    )


def purge(db: Session, *, now: datetime | None = None) -> int:
    """Drop every nonce past its lifetime; returns how many went."""
    cutoff = _iso((now or datetime.now(UTC)) - NONCE_LIFETIME)
    return _delete(db, sa.delete(AcmeNonce).where(AcmeNonce.issued_at < cutoff))
