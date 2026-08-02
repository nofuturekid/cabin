"""Unit tests for the append-only audit log itself (spec 0009 FR-1/FR-2/FR-3):
the row a :func:`cabin.audit.record` call writes, the action vocabulary the
rest of cabin is allowed to use, and the list query behind /audit.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from cabin import audit
from cabin.audit import Actor, ActorKind, AuditAction, AuditEvent
from cabin.store import create_session_factory, run_migrations

#: Exactly the actions spec 0009 FR-2 names. Spelled out rather than derived
#: from the enum, so adding an action to cabin without adding it to the spec
#: (or vice versa) fails here instead of passing silently.
SPEC_ACTIONS = {
    "login_success",
    "login_failed",
    "logout",
    "user_created",
    "user_role_changed",
    "user_password_reset",
    "user_deleted",
    "ca_created",
    "ca_imported",
    "settings_changed",
    "cert_issued",
    "cert_signed",
    "cert_revoked",
    "token_created",
    "token_revoked",
}


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    session = create_session_factory(db_url)()
    try:
        yield session
    finally:
        session.close()


def _all(db: Session) -> list[AuditEvent]:
    return list(db.scalars(sa.select(AuditEvent).order_by(AuditEvent.id)))


# --- FR-1/FR-2: one call, one row ---------------------------------------------


def test_record_appends_row(db: Session) -> None:
    moment = datetime(2026, 8, 1, 12, 30, tzinfo=UTC)
    event = audit.record(
        db,
        Actor(kind=ActorKind.user, id=7, label="alice"),
        AuditAction.cert_issued,
        summary="issued certificate for 'nas.lan'",
        target_type="certificate",
        target_id=42,
        detail={"serial_hex": "beef", "profile": "server"},
        ip="10.0.0.5",
        now=moment,
    )

    rows = _all(db)
    assert [row.id for row in rows] == [event.id]
    row = rows[0]
    assert row.occurred_at == "2026-08-01T12:30:00+00:00"
    assert (row.actor_kind, row.actor_id, row.actor_label) == ("user", 7, "alice")
    assert row.action == "cert_issued"
    assert (row.target_type, row.target_id) == ("certificate", "42")
    assert row.summary == "issued certificate for 'nas.lan'"
    assert json.loads(row.detail_json or "") == {
        "serial_hex": "beef",
        "profile": "server",
    }
    assert row.detail == {"serial_hex": "beef", "profile": "server"}
    assert row.ip == "10.0.0.5"
    assert row.occurred_at_dt == moment

    # Append-only: a second call adds a row, it never replaces the first.
    audit.record(db, audit.SYSTEM_ACTOR, AuditAction.logout, summary="logout")
    assert len(_all(db)) == 2
    assert _all(db)[1].actor_kind == "system"
    assert _all(db)[1].actor_id is None
    assert _all(db)[1].detail is None


def test_record_bounds_what_a_caller_can_put_in_a_label(db: Session) -> None:
    """The label of a failed login is an attacker-supplied username, so the
    column's width has to be enforced here rather than trusted -- SQLite would
    take a megabyte of it, PostgreSQL would raise."""
    audit.record(
        db,
        Actor(kind=ActorKind.user, id=None, label="x" * 5_000),
        AuditAction.login_failed,
        summary="failed login",
    )
    assert len(_all(db)[0].actor_label) == audit.MAX_LABEL_LENGTH


def test_record_refuses_a_naive_timestamp(db: Session) -> None:
    """A naive datetime would be read as local time and stored shifted by the
    host's UTC offset -- a log that quietly moves its own timestamps is worse
    than one that refuses to write."""
    with pytest.raises(ValueError):
        audit.record(
            db,
            audit.SYSTEM_ACTOR,
            AuditAction.logout,
            summary="logout",
            now=datetime(2026, 8, 1, 12, 30),
        )
    assert _all(db) == []


def test_actions_enum_complete() -> None:
    assert {action.value for action in AuditAction} == SPEC_ACTIONS
    # FR-1: the four actor kinds the table's CHECK constraint accepts.
    assert {kind.value for kind in ActorKind} == {"user", "token", "system", "acme"}
    # The filter tuples the UI renders are the enums plus "no filter at all".
    assert audit.ACTION_FILTERS[0] == "all"
    assert set(audit.ACTION_FILTERS) == {"all", *SPEC_ACTIONS}
    assert audit.ACTOR_KIND_FILTERS[0] == "all"
    assert set(audit.ACTOR_KIND_FILTERS) == {"all", "user", "token", "system", "acme"}


def test_module_offers_no_way_to_change_the_past() -> None:
    """FR-2: append-only *by construction* -- there is no update or delete
    helper for a caller to reach for, so "the app cannot edit the log" is a
    property of the module surface, not a habit."""
    changers = [
        name
        for name, value in vars(audit).items()
        if callable(value)
        and not name.startswith("_")
        and any(word in name for word in ("delete", "update", "purge", "edit", "prune"))
    ]
    assert changers == []


# --- FR-3: secrets never reach a detail blob ----------------------------------


def test_setting_change_detail_masks_secret_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert audit.setting_change_detail("base_url", None, "https://ca.example.org") == {
        "key": "base_url",
        "old": None,
        "new": "https://ca.example.org",
    }
    # No setting is secret today; the rule is codified anyway, so the first
    # one that is gets masked without anyone having to remember.
    monkeypatch.setattr(audit, "SECRET_SETTING_KEYS", frozenset({"smtp_password"}))
    assert audit.setting_change_detail("smtp_password", "old-pw", "new-pw") == {
        "key": "smtp_password",
        "old": audit.MASKED,
        "new": audit.MASKED,
    }


# --- FR-6: the list query behind /audit and /api/v1/audit ---------------------


def _seed(db: Session) -> None:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    entries = [
        (
            Actor(ActorKind.user, 1, "alice"),
            AuditAction.login_success,
            "login for 'alice'",
        ),
        (
            Actor(ActorKind.user, None, "mallory"),
            AuditAction.login_failed,
            "failed for 'mallory'",
        ),
        (
            Actor(ActorKind.token, 3, "ansible"),
            AuditAction.cert_issued,
            "issued for 'nas.lan'",
        ),
        (
            Actor(ActorKind.user, 1, "alice"),
            AuditAction.cert_issued,
            "issued for 'vpn.lan'",
        ),
        (audit.SYSTEM_ACTOR, AuditAction.settings_changed, "setting base_url changed"),
    ]
    for offset, (actor, action, summary) in enumerate(entries):
        audit.record(db, actor, action, summary=summary, now=start + timedelta(minutes=offset))


def test_list_events_filters(db: Session) -> None:
    _seed(db)

    rows, total = audit.list_events(db)
    assert total == 5
    # Newest first.
    assert rows[0].summary == "setting base_url changed"

    rows, total = audit.list_events(db, action=AuditAction.cert_issued)
    assert total == 2
    assert {row.summary for row in rows} == {
        "issued for 'nas.lan'",
        "issued for 'vpn.lan'",
    }

    rows, total = audit.list_events(db, actor_kind=ActorKind.token)
    assert (total, [row.actor_label for row in rows]) == (1, ["ansible"])

    # q is a case-insensitive substring over actor_label, action and summary.
    assert audit.list_events(db, q="ALICE")[1] == 2
    assert audit.list_events(db, q="login_")[1] == 2
    assert audit.list_events(db, q="nas.lan")[1] == 1

    # ... and the three combine.
    rows, total = audit.list_events(db, q="alice", action=AuditAction.cert_issued)
    assert (total, [row.summary for row in rows]) == (1, ["issued for 'vpn.lan'"])
    assert audit.list_events(db, q="alice", actor_kind=ActorKind.token)[1] == 0

    # An unknown value filters nothing away rather than raising.
    assert audit.list_events(db, action="all", actor_kind="all")[1] == 5

    # LIKE metacharacters are literal, not wildcards.
    assert audit.list_events(db, q="%")[1] == 0
    assert audit.list_events(db, q="x" * (audit.MAX_QUERY_LENGTH + 50))[1] == 0


def test_list_events_pagination(db: Session) -> None:
    start = datetime(2026, 8, 1, tzinfo=UTC)
    for index in range(audit.PER_PAGE + 5):
        audit.record(
            db,
            audit.SYSTEM_ACTOR,
            AuditAction.settings_changed,
            summary=f"event {index:03d}",
            now=start + timedelta(minutes=index),
        )

    first, total = audit.list_events(db, page=1)
    assert total == audit.PER_PAGE + 5
    assert len(first) == audit.PER_PAGE
    assert first[0].summary == "event 054"

    second, _ = audit.list_events(db, page=2)
    assert [row.summary for row in second] == [f"event {index:03d}" for index in range(4, -1, -1)]

    # Out of range is an empty page, never an error (AC-4).
    assert audit.list_events(db, page=99)[0] == []
    assert audit.list_events(db, page=0)[0] == first
    assert audit.list_events(db, page=-5)[0] == first
    assert audit.list_events(db, page=audit.MAX_PAGE * 1000)[0] == []
