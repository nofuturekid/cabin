"""The audit log viewer (spec 0009 FR-6): ``/audit``, newest first, with a
free-text, action and actor-kind filter.

Open to every authenticated user, viewers included: an entry is metadata --
who did what, when -- and never carries key material, so there is nothing
here a logged-in operator may not see. Read-only by construction, because
:mod:`cabin.audit` offers no way to change a row.
"""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.audit import (
    ACTION_FILTERS,
    ACTOR_KIND_FILTERS,
    MAX_QUERY_LENGTH,
    PER_PAGE,
    AuditEvent,
)
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import base_context, get_current_user, get_db

router = APIRouter(prefix="/audit")


def _row(event: AuditEvent) -> dict[str, object]:
    """One line of the log, fully computed here: the template renders values,
    it does not decide them."""
    return {
        "occurred_at": event.occurred_at_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "actor_kind": event.actor_kind,
        "actor_label": event.actor_label,
        "action": event.action,
        "summary": event.summary,
        "ip": event.ip or "",
        # FR-6: a certificate target is a link. The row is not checked
        # against the inventory first -- a target that has since disappeared
        # must still render, and following the link is then a plain 404.
        "cert_id": event.target_id if event.target_type == "certificate" else None,
    }


def _page_url(q: str, action: str, actor_kind: str, page: int) -> str:
    """A pager link that keeps the active filters."""
    return "/audit?" + urlencode({"q": q, "action": action, "actor_kind": actor_kind, "page": page})


@router.get("")
def audit_page(
    request: Request,
    q: str = "",
    action: str = "all",
    actor_kind: str = "all",
    page: int = 1,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    term = q.strip()[:MAX_QUERY_LENGTH]
    # An unknown filter value is a typo, not an error: show everything --
    # the same answer the inventory gives an unknown ?status=.
    active_action = action if action in ACTION_FILTERS else "all"
    active_kind = actor_kind if actor_kind in ACTOR_KIND_FILTERS else "all"
    page = max(page, 1)
    rows, total = audit.list_events(
        db,
        q=term,
        action=active_action,
        actor_kind=active_kind,
        page=page,
        per_page=PER_PAGE,
    )
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    context = base_context(request, user)
    context.update(
        {
            "events": [_row(event) for event in rows],
            "q": term,
            "action": active_action,
            "actions": ACTION_FILTERS,
            "actor_kind": active_kind,
            "actor_kinds": ACTOR_KIND_FILTERS,
            # What the page *says* it is showing is clamped to a page that
            # exists: a hand-edited ?page=10000000 still answers with an
            # empty list (AC-4), but it must not print "page 10000000 of 3".
            "page": min(page, pages),
            "pages": pages,
            "total": total,
            # Past the last page there is nothing behind us either, so the
            # back link is clamped to a page that actually has rows.
            "prev_url": (
                _page_url(term, active_action, active_kind, min(page - 1, pages))
                if page > 1
                else None
            ),
            "next_url": (
                _page_url(term, active_action, active_kind, page + 1) if page < pages else None
            ),
        }
    )
    return templates.TemplateResponse(request, "audit.html", context)
