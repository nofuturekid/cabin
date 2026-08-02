"""The audit log (spec 0009): who changed what, and when.

Three properties shape this module.

* **Append-only by construction.** There is exactly one writer,
  :func:`record`, and no update, delete or purge helper anywhere -- so "the
  app cannot rewrite its own history" is a property of the module surface,
  not of anyone's discipline. Retention and tamper-evidence are explicitly
  out of scope for this spec; not offering an edit path is the part that
  must be true from day one.
* **Actors are not users.** cabin is operated through three doors -- a
  browser session, an API token, and (from spec 0010) an ACME account --
  plus cabin itself. A log that only knew user ids could not answer "who
  issued this" for two of them, so every event carries an
  :class:`ActorKind` alongside the id, and a label that stays readable even
  after the account behind it is gone.
* **Never a secret.** ``detail_json`` holds identifiers, names, serials,
  profiles and reasons. Private keys, passwords, token secrets and CSR
  bodies do not go in, and :data:`SECRET_SETTING_KEYS` codifies that rule
  for the one place where a value of unknown shape could arrive -- a
  changed setting.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.api_tokens import ApiToken
from cabin.store import Base
from cabin.users import User

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Under TYPE_CHECKING so the log stays a leaf module at runtime: the CA
    # layer may one day want to record events itself, and that must not
    # become an import cycle.
    from cabin.ca.certs import Certificate

#: Page size of /audit and /api/v1/audit (FR-6/FR-7).
PER_PAGE = 50
#: Cap on the free-text filter, mirroring the inventory's (spec 0006 FR-2).
MAX_QUERY_LENGTH = 200
#: Cap on the requested page, so a hand-edited ?page= is an empty page rather
#: than an unbindable OFFSET -- same reasoning as the inventory's.
MAX_PAGE = 1_000_000
#: Width of ``actor_label``. Enforced in :func:`record` because one label --
#: the username of a failed login -- is attacker-supplied.
MAX_LABEL_LENGTH = 255


class ActorKind(StrEnum):
    """Which door an actor came through (FR-1). Mirrors the table's CHECK
    constraint; ``acme`` is reserved for specs 0010-0012 and unused today."""

    user = "user"
    token = "token"
    system = "system"
    acme = "acme"


class AuditAction(StrEnum):
    """Every state change cabin records (FR-2). Adding an action here without
    also recording it somewhere is harmless; recording something not in this
    list is not possible, which is the point -- the filter dropdown in the UI
    and this enum cannot drift."""

    login_success = "login_success"
    login_failed = "login_failed"
    logout = "logout"
    user_created = "user_created"
    user_role_changed = "user_role_changed"
    user_password_reset = "user_password_reset"
    user_deleted = "user_deleted"
    ca_created = "ca_created"
    ca_imported = "ca_imported"
    settings_changed = "settings_changed"
    cert_issued = "cert_issued"
    cert_signed = "cert_signed"
    cert_revoked = "cert_revoked"
    token_created = "token_created"
    token_revoked = "token_revoked"


#: Accepted ``?action=`` / ``?actor_kind=`` values; "all" means "no filter".
ACTION_FILTERS: tuple[str, ...] = ("all", *AuditAction)
ACTOR_KIND_FILTERS: tuple[str, ...] = ("all", *ActorKind)


@dataclass(frozen=True)
class Actor:
    """Whoever caused an event. ``id`` is NULL when there is no row to point
    at -- a failed login, or cabin acting on its own."""

    kind: ActorKind
    id: int | None
    label: str


#: cabin itself: first-run setup, and later anything a scheduler does.
SYSTEM_ACTOR = Actor(kind=ActorKind.system, id=None, label="system")


def user_actor(user: User) -> Actor:
    return Actor(kind=ActorKind.user, id=user.id, label=user.username)


def token_actor(token: ApiToken) -> Actor:
    return Actor(kind=ActorKind.token, id=token.id, label=token.label)


class AuditEvent(Base):
    """One recorded state change. Written once, never updated."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    actor_kind: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    actor_label: Mapped[str] = mapped_column(sa.String(MAX_LABEL_LENGTH), nullable=False)
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_type: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    summary: Mapped[str] = mapped_column(sa.Text, nullable=False)
    detail_json: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(sa.String(45), nullable=True)

    @property
    def occurred_at_dt(self) -> datetime:
        """``occurred_at`` as an aware datetime; the column keeps the
        ISO-8601 UTC form written by :func:`record`."""
        return datetime.fromisoformat(self.occurred_at)

    @property
    def detail(self) -> dict[str, Any] | None:
        """The decoded ``detail_json``, or None when the event has none."""
        if self.detail_json is None:
            return None
        decoded: dict[str, Any] = json.loads(self.detail_json)
        return decoded


#: Setting keys whose values must never reach the log. Empty today -- every
#: setting cabin has is a public knob -- but the rule is written down here so
#: that the first secret one is masked by construction rather than by whoever
#: happens to review the pull request that adds it.
SECRET_SETTING_KEYS: frozenset[str] = frozenset()
#: What a masked value reads as.
MASKED = "***"


def setting_change_detail(key: str, old: str | None, new: str | None) -> dict[str, str | None]:
    """FR-3/AC-3: the detail blob for a settings change -- the key plus what
    it was and what it became, with the values masked for a secret key."""

    def value(raw: str | None) -> str | None:
        if raw is None:
            return None
        return MASKED if key in SECRET_SETTING_KEYS else raw

    return {"key": key, "old": value(old), "new": value(new)}


def certificate_detail(row: "Certificate", *, key_type: str | None = None) -> dict[str, Any]:
    """FR-3/AC-3: everything an issuance, signing or revocation event says
    about a certificate -- and the one place to look to check that it is
    nothing else. Identifiers and metadata only: no private key, no CSR body,
    nothing that would let a reader of the log use the certificate.
    """
    detail: dict[str, Any] = {
        "serial_hex": row.serial_hex,
        "subject_cn": row.subject_cn,
        "sans": row.sans,
        "profile": row.profile,
        "not_after": row.not_after,
    }
    if key_type is not None:
        detail["key_type"] = key_type
    return detail


def revocation_detail(row: "Certificate", reason: str) -> dict[str, Any]:
    """:func:`certificate_detail` plus why the certificate was revoked."""
    return {**certificate_detail(row), "reason": str(reason)}


# The three summaries below are what the free-text filter searches, so the UI
# and the API have to phrase them identically -- an operator looking for
# "issued certificate for 'nas.lan'" must not find only half of them because
# one front door words it differently. They live here, next to the detail
# builders, for the same reason: one place decides what an event says.


def issued_summary(row: "Certificate") -> str:
    return f"issued certificate for {row.subject_cn!r}"


def signed_summary(row: "Certificate") -> str:
    return f"signed CSR for {row.subject_cn!r}"


def revoked_summary(row: "Certificate", reason: str) -> str:
    return f"revoked certificate for {row.subject_cn!r} ({reason})"


def _iso(moment: datetime) -> str:
    """A point in time in the shape ``occurred_at`` stores: UTC, second
    granularity, fixed layout -- so string order is time order."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def record(
    db: Session,
    actor: Actor,
    action: AuditAction,
    *,
    summary: str,
    target_type: str | None = None,
    target_id: int | str | None = None,
    detail: dict[str, Any] | None = None,
    ip: str | None = None,
    now: datetime | None = None,
) -> AuditEvent:
    """Append one event and commit it (FR-2).

    Callers record *after* the state change succeeded, on the same session,
    so an event never describes something that did not happen. The trade-off
    that buys is worth stating plainly, because it is not "fails safely":
    the state change has already committed, so a failing insert here surfaces
    as a 500 over a change that did happen and is now unlogged. For
    ``POST /api/v1/certificates`` that means a certificate was issued and
    stored whose private key the caller never receives, and whose retry mints
    a second one. Nothing here is wrapped in a try/except anyway -- a log
    that silently swallows its own write failures would turn that loud,
    diagnosable case into an invisible gap.

    Making the event and the change genuinely atomic would mean moving
    :func:`record` into the domain layer, so that the one commit which writes
    the certificate (or the user, or the setting) writes its event too. That
    is a larger change than spec 0009 asks for, and it is where this should
    go if the gap above ever matters more than the coupling.

    ``now`` must be timezone-aware: a naive datetime would be reinterpreted
    as local time by :func:`_iso`, and an audit log that quietly shifts its
    own timestamps by the host's UTC offset is worse than one that refuses.

    ``detail`` is JSON-encoded with sorted keys (so two events with the same
    content compare equal as text) and must contain no secret -- see FR-3 and
    :func:`setting_change_detail`.
    """
    if now is not None and now.tzinfo is None:
        raise ValueError("record() needs a timezone-aware datetime for now")
    event = AuditEvent(
        occurred_at=_iso(now or datetime.now(UTC)),
        actor_kind=str(actor.kind),
        actor_id=actor.id,
        # The one label a caller does not control is the one that matters:
        # a failed login carries the username someone typed.
        actor_label=actor.label[:MAX_LABEL_LENGTH],
        action=str(action),
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        summary=summary,
        detail_json=json.dumps(detail, sort_keys=True) if detail is not None else None,
        ip=ip,
    )
    db.add(event)
    db.commit()
    return event


def _filters(q: str, action: str, actor_kind: str) -> list[sa.ColumnElement[bool]]:
    conditions: list[sa.ColumnElement[bool]] = []
    term = q.strip()[:MAX_QUERY_LENGTH].lower()
    if term:
        # Bound parameter, never interpolated; LIKE metacharacters escaped so
        # a search for "%" finds a literal "%" instead of everything.
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        conditions.append(
            sa.or_(
                sa.func.lower(AuditEvent.actor_label).like(pattern, escape="\\"),
                sa.func.lower(AuditEvent.action).like(pattern, escape="\\"),
                sa.func.lower(AuditEvent.summary).like(pattern, escape="\\"),
            )
        )
    if action and action != "all":
        conditions.append(AuditEvent.action == action)
    if actor_kind and actor_kind != "all":
        conditions.append(AuditEvent.actor_kind == actor_kind)
    return conditions


def list_events(
    db: Session,
    *,
    q: str = "",
    action: str = "all",
    actor_kind: str = "all",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> tuple[list[AuditEvent], int]:
    """One page of the log, newest first, plus the total number of matches
    (FR-6) -- the same shape and the same clamping as the certificate
    inventory, so both pagers behave identically.

    ``q`` is a case-insensitive substring over actor label, action and
    summary; ``action`` and ``actor_kind`` are exact matches, with "all" (or
    an empty string) meaning "no filter". An unknown value simply matches
    nothing; it is the caller's job to decide whether that is a typo to
    ignore (the UI) or a 422 (the API).
    """
    conditions = _filters(q, action, actor_kind)
    page = min(max(page, 1), MAX_PAGE)
    total = db.scalar(select(sa.func.count()).select_from(AuditEvent).where(*conditions)) or 0
    rows = db.scalars(
        select(AuditEvent)
        .where(*conditions)
        # id breaks ties: two events in the same second still come back in
        # the order they were written.
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()
    return list(rows), total
