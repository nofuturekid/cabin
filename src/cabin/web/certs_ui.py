"""UI routes for the certificate inventory (spec 0006 FR-1/FR-2) and leaf
issuance (spec 0005 FR-6): /certs lists what has been issued, /certs/new
carries both issuance forms (server-generated key | pasted CSR) and is
admin-only because it exists solely to mutate; /certs/{id} shows one
certificate to any logged-in user, but the private key block only to
admins. The download routes live in :mod:`cabin.web.certs_download_ui`.

Spec 0017 FR-6/FR-14 adds an issuer selector to both issuance forms,
rendered only when more than one issuer is active (a single-CA install sees
no new field), and FR-7 makes a clamped validity visible on the result page.

Spec 0018 narrows that selector's source from every active issuer to this
principal's *granted* active issuers (FR-11), and threads a required
``principal`` through every issue/sign/revoke call (FR-5/FR-6) so a request
this identity is not granted for is refused before anything is written.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from urllib.parse import urlencode

from cryptography import x509
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.audit import Actor, AuditAction
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import leaf
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import (
    MAX_QUERY_LENGTH,
    PER_PAGE,
    STATUS_FILTERS,
    Certificate,
    certificate_status,
)
from cabin.ca.leaf import (
    DEFAULT_DAYS,
    MAX_DAYS,
    MIN_DAYS,
    IssueError,
    Profile,
    parse_profile,
    parse_san_lines,
)
from cabin.ca.revocation import RevocationReason
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    IssuerRequiredError,
    IssuerRetiredError,
    UnknownIssuerError,
)
from cabin.ca.x509 import KEY_TYPES
from cabin.issuer_grants import (
    IssuerForbiddenError,
    NoGrantedIssuerError,
    Principal,
    granted_issuers,
    resolve_granted_issuer,
    user_principal,
)
from cabin.users import Role, User
from cabin.web import templates
from cabin.web.deps import (
    ADMIN_ROLES,
    base_context,
    certificate_or_404,
    client_ip,
    current_actor,
    get_current_user,
    get_db,
    is_htmx,
    preview_fragment,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/certs")

_NO_CA = "no CA yet: create or import one under CA before issuing certificates"
#: Spec 0024 FR-7: the middle case, between "nothing exists" and "something
#: exists but I'm not granted it" -- a CA hierarchy exists but carries no
#: active intermediate yet, the normal state right after ``POST /ca/create``
#: and before its own ``POST .../intermediate``. Kept distinct from
#: ``_NO_CA``, which sends an operator to *create* a hierarchy they are
#: already looking at.
_NO_ACTIVE_ISSUER = (
    "this CA hierarchy has no active issuer yet: add an intermediate under its own page"
)
#: Spec 0018 FR-4/FR-11: the other reason the selector can be empty -- a CA
#: exists and is active, but this identity holds no grant on any of them.
#: Kept distinct from ``_NO_CA``, which sends an operator off to build a
#: second hierarchy -- exactly the wrong advice for someone who is merely
#: not granted one that already exists.
_NO_GRANT = "no issuer is granted to you: ask a superadmin to grant one under Users"
#: Spec 0029 FR-14, byte for byte: the two sentences the constraint panel's
#: verdict line can carry when the whole-set call returns. The third -- the
#: refusal -- is deliberately not here: it is ``NameConstraintError``'s own
#: message, rendered unchanged, which is both the sentence
#: ``POST /certs/issue`` already shows for the same request and the only
#: string guaranteed to agree with it (FR-4).
_VERDICT_PERMITTED = "Every name is inside what this issuer permits."
_VERDICT_UNCONSTRAINED = (
    "This issuer sets no name constraints, so any name it is asked for is permitted."
)
#: Spec 0007 FR-7: the confirm checkbox is the last stop before an
#: irreversible action, so a post without it is refused rather than assumed.
_CONFIRM_REVOKE = "tick the confirmation box: revoking a certificate cannot be undone"
#: The reason ends up in the CRL, so an unknown one is refused, not guessed.
_UNKNOWN_REASON = "unknown revocation reason: {!r}"
#: How much of the serial identifies a certificate in the list and in
#: download filenames (FR-1/FR-4).
SERIAL_CHARS = 8
#: SANs shown per row before collapsing the rest into "+N more" (FR-1).
SAN_PREVIEW = 3
#: Domain failures that mean "the issuer choice was missing, ambiguous or
#: unusable" (spec 0017 FR-6/AC-2/AC-3) -- the same 400 an unusable CSR or an
#: out-of-range days value gets, with the form re-rendered rather than
#: thrown away. CANotConfiguredError is handled separately: its message does
#: not name "CA" the way the wizard's own wording does.
_ISSUER_ERRORS = (IssuerRequiredError, IssuerRetiredError, UnknownIssuerError)
#: Spec 0018 FR-14: an authorization failure, not the bad input the errors
#: above are -- 403, like `require_role`'s own refusal, and never thrown
#: away: the domain layer's own message says what happened.
_GRANT_ERRORS = (IssuerForbiddenError, NoGrantedIssuerError)


def _issuer_options(db: Session, principal: Principal) -> list[CACertificate]:
    """Spec 0018 FR-11: what the select offers is narrowed from every active
    issuer to this principal's *granted* active issuers -- a selector
    offering a choice that would then be refused is worse than one that
    offers nothing (AC-2 proves the POST is refused server-side regardless).
    """
    return granted_issuers(db, principal)


@dataclass(frozen=True)
class _NoIssuer:
    """What the empty-issuer-list message says, and where it sends an
    operator to fix it (spec 0024 FR-7, AC-7): ``href``/``link_text`` are
    both ``None`` for ``_NO_GRANT``, which points at asking a superadmin,
    not at a page this operator can act on alone.
    """

    message: str
    href: str | None
    link_text: str | None


def _no_issuer_message(db: Session) -> _NoIssuer:
    """Which of the three reasons an empty issuer list has (spec 0018 FR-4,
    spec 0024 FR-7): no ``ca_certificates`` row exists at all, one exists
    but carries no active intermediate, or one does and this identity simply
    is not granted any of it. The first two differ in more than wording --
    each points at a different place to fix it, ``/ca/new`` versus that
    hierarchy's own detail page -- which is what AC-7 tells apart.
    """
    if not ca_service.list_cas(db):
        return _NoIssuer(_NO_CA, "/ca/new", "Create a CA")
    if not ca_service.active_issuers(db):
        roots = ca_service.list_cas(db, kind="root")
        href = f"/ca/{roots[0].id}" if roots else None
        return _NoIssuer(_NO_ACTIVE_ISSUER, href, "Add an intermediate")
    return _NoIssuer(_NO_GRANT, None, None)


def _form_page(
    request: Request,
    user: User,
    error: str | None,
    template: str,
    *,
    issuers: Sequence[CACertificate] = (),
    values: dict[str, object] | None = None,
    status_code: int = 200,
    error_href: str | None = None,
    error_href_text: str | None = None,
) -> Response:
    """The two ways to get a certificate are separate pages (spec 0015 FR-10)
    but ask for the same things, so they share one context.

    ``values`` carries back whatever the operator typed on a rejected POST
    (spec 0017 AC-2): losing it on a 400 would be its own bug, so every
    error path re-renders the form with the submitted values intact.

    ``error_href``/``error_href_text`` (spec 0024 FR-7, AC-7): the empty-
    issuer message names a place to fix it -- ``/ca/new`` or a specific
    hierarchy's own page -- and the two states must differ by more than
    wording for AC-7 to hold, so the link rides alongside ``error`` rather
    than being folded into that string, which stays plain autoescaped text.
    """
    context = base_context(request, user)
    context.update(
        {
            "error": error,
            "error_href": error_href,
            "error_href_text": error_href_text,
            "profiles": list(Profile),
            "key_types": list(KEY_TYPES),
            "default_days": DEFAULT_DAYS,
            "min_days": MIN_DAYS,
            "max_days": MAX_DAYS,
            "issuers": issuers,
            # FR-14/AC-12: hidden entirely with zero or one active issuer --
            # a single-CA install must not see a new field.
            "show_issuer_select": len(issuers) > 1,
            "values": values or {},
        }
    )
    return templates.TemplateResponse(request, template, context, status_code=status_code)


def _new_page(
    request: Request,
    user: User,
    error: str | None,
    *,
    issuers: Sequence[CACertificate] = (),
    values: dict[str, object] | None = None,
    status_code: int = 200,
    error_href: str | None = None,
    error_href_text: str | None = None,
) -> Response:
    return _form_page(
        request,
        user,
        error,
        "certs_new.html",
        issuers=issuers,
        values=values,
        status_code=status_code,
        error_href=error_href,
        error_href_text=error_href_text,
    )


def _sign_page(
    request: Request,
    user: User,
    error: str | None,
    *,
    issuers: Sequence[CACertificate] = (),
    values: dict[str, object] | None = None,
    status_code: int = 200,
    error_href: str | None = None,
    error_href_text: str | None = None,
) -> Response:
    return _form_page(
        request,
        user,
        error,
        "certs_sign.html",
        issuers=issuers,
        values=values,
        status_code=status_code,
        error_href=error_href,
        error_href_text=error_href_text,
    )


def _cert_row(row: Certificate, now: datetime) -> dict[str, object]:
    """One inventory line, fully computed here: the template renders values,
    it does not decide them (FR-1)."""
    sans = row.sans
    return {
        "id": row.id,
        "subject_cn": row.subject_cn,
        "profile": row.profile,
        # Spec 0012 FR-7: which front door this came out of. Displayed only
        # -- it is not a filter facet, because the status filter already
        # partitions the inventory and a second dimension would have to
        # combine with it, which the query is not shaped for.
        "source": row.source,
        "has_key": row.key_sealed is not None,
        "not_after": row.not_after_dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "status": certificate_status(row.not_after_dt, now, row.revoked_at_dt).value,
        "sans": sans[:SAN_PREVIEW],
        "sans_more": max(len(sans) - SAN_PREVIEW, 0),
        "serial_short": row.serial_hex[:SERIAL_CHARS],
    }


def _page_url(q: str, status: str, page: int) -> str:
    """A pager link that keeps the active filters (FR-2)."""
    return "/certs?" + urlencode({"q": q, "status": status, "page": page})


@router.get("")
def certs_list(
    request: Request,
    q: str = "",
    status: str = "all",
    page: int = 1,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """FR-1/FR-2: the paginated inventory with its text and status filters,
    open to any logged-in user."""
    term = q.strip()[:MAX_QUERY_LENGTH]
    # An unknown ?status= is a typo, not an error: show everything.
    active = status if status in STATUS_FILTERS else "all"
    page = max(page, 1)
    # One clock for the filter and the badges, so a row can't be selected as
    # "expiring" and then rendered as "expired" a tick later.
    now = datetime.now(UTC)
    rows, total = certs_service.list_certificates(
        db, q=term, status=active, page=page, per_page=PER_PAGE, now=now
    )
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    context = base_context(request, user)
    context.update(
        {
            "certs": [_cert_row(row, now) for row in rows],
            "q": term,
            "status": active,
            "statuses": STATUS_FILTERS,
            "page": page,
            "pages": pages,
            "total": total,
            # Past the last page there is nothing behind us either, so the
            # back link is clamped to a page that actually has rows.
            "prev_url": (_page_url(term, active, min(page - 1, pages)) if page > 1 else None),
            "next_url": _page_url(term, active, page + 1) if page < pages else None,
            "can_issue": Role(user.role) in ADMIN_ROLES,
        }
    )
    return templates.TemplateResponse(request, "certs_list.html", context)


@router.get("/new")
def certs_new(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    issuers = _issuer_options(db, user_principal(user))
    no_issuer = None if issuers else _no_issuer_message(db)
    return _new_page(
        request,
        user,
        no_issuer.message if no_issuer else None,
        issuers=issuers,
        error_href=no_issuer.href if no_issuer else None,
        error_href_text=no_issuer.link_text if no_issuer else None,
    )


@router.get("/sign")
def certs_sign_form(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    issuers = _issuer_options(db, user_principal(user))
    no_issuer = None if issuers else _no_issuer_message(db)
    return _sign_page(
        request,
        user,
        no_issuer.message if no_issuer else None,
        issuers=issuers,
        error_href=no_issuer.href if no_issuer else None,
        error_href_text=no_issuer.link_text if no_issuer else None,
    )


#: spec 0017 FR-7: the result page names both the requested and the granted
#: expiry. There is no session-scoped flash mechanism in this codebase and
#: the redirect target is a plain "/certs/{id}" (matched by the API/MCP
#: response shape and by every existing caller of the location header), so
#: the one issuance response that knows ``capped_from`` hands it off here,
#: keyed by the certificate id, for the *next* GET of that same certificate
#: to pick up and discard. Never recomputed from stored state -- a later,
#: unrelated visit to the same page reads nothing back.
_pending_capped: dict[int, tuple[int, datetime]] = {}
_pending_capped_lock = Lock()


def _remember_capped(cert_id: int, days: int, capped_from: datetime | None) -> None:
    if capped_from is None:
        return
    with _pending_capped_lock:
        _pending_capped[cert_id] = (days, capped_from)


def _take_capped(cert_id: int) -> tuple[int | None, datetime | None]:
    with _pending_capped_lock:
        pending = _pending_capped.pop(cert_id, None)
    return pending if pending is not None else (None, None)


@router.post("/issue")
def certs_issue(
    request: Request,
    subject_cn: str = Form(...),
    sans: str = Form(""),
    profile: str = Form("server"),
    key_type: str = Form("ecdsa-p256"),
    days: int = Form(DEFAULT_DAYS),
    issuer_id: int | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    principal = user_principal(user)
    issuers = _issuer_options(db, principal)
    values = {
        "subject_cn": subject_cn,
        "sans": sans,
        "profile": profile,
        "key_type": key_type,
        "days": days,
        "issuer_id": issuer_id,
    }
    try:
        issued = certs_service.issue_and_store(
            db,
            request.app.state.secrets,
            principal=principal,
            profile=parse_profile(profile),
            subject_cn=subject_cn,
            sans=parse_san_lines(sans),
            days=days,
            key_type=key_type,
            issuer_id=issuer_id,
        )
    except IssueError as exc:
        return _new_page(request, user, str(exc), issuers=issuers, values=values, status_code=400)
    except CANotConfiguredError:
        no_issuer = _no_issuer_message(db)
        return _new_page(
            request,
            user,
            no_issuer.message,
            issuers=issuers,
            values=values,
            status_code=400,
            error_href=no_issuer.href,
            error_href_text=no_issuer.link_text,
        )
    except _GRANT_ERRORS as exc:
        return _new_page(request, user, str(exc), issuers=issuers, values=values, status_code=403)
    except _ISSUER_ERRORS as exc:
        return _new_page(request, user, str(exc), issuers=issuers, values=values, status_code=400)
    row, capped_from = issued.row, issued.capped_from
    audit.record(
        db,
        actor,
        AuditAction.cert_issued,
        summary=audit.issued_summary(row),
        target_type="certificate",
        target_id=row.id,
        detail=audit.certificate_detail(
            row,
            key_type=key_type,
            days_requested=days if capped_from is not None else None,
            validity_capped_from=capped_from,
        ),
        ip=client_ip(request, db),
    )
    _remember_capped(row.id, days, capped_from)
    # The key is never carried in the redirect: the result page re-derives
    # it from the sealed column for whoever is authorized to see it (FR-6).
    return RedirectResponse(f"/certs/{row.id}", status_code=303)


@router.post("/sign")
def certs_sign(
    request: Request,
    csr_pem: str = Form(...),
    profile: str = Form("server"),
    days: int = Form(DEFAULT_DAYS),
    sans_override: str = Form(""),
    issuer_id: int | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    principal = user_principal(user)
    issuers = _issuer_options(db, principal)
    values = {
        "csr_pem": csr_pem,
        "profile": profile,
        "days": days,
        "sans_override": sans_override,
        "issuer_id": issuer_id,
    }
    try:
        issued = certs_service.sign_csr_and_store(
            db,
            request.app.state.secrets,
            principal=principal,
            csr_pem=csr_pem,
            profile=parse_profile(profile),
            days=days,
            sans_override=parse_san_lines(sans_override),
            issuer_id=issuer_id,
        )
    except IssueError as exc:
        return _sign_page(request, user, str(exc), issuers=issuers, values=values, status_code=400)
    except CANotConfiguredError:
        no_issuer = _no_issuer_message(db)
        return _sign_page(
            request,
            user,
            no_issuer.message,
            issuers=issuers,
            values=values,
            status_code=400,
            error_href=no_issuer.href,
            error_href_text=no_issuer.link_text,
        )
    except _GRANT_ERRORS as exc:
        return _sign_page(request, user, str(exc), issuers=issuers, values=values, status_code=403)
    except _ISSUER_ERRORS as exc:
        return _sign_page(request, user, str(exc), issuers=issuers, values=values, status_code=400)
    # The CSR itself is not recorded: it is bulky, and what it asked for is
    # already described by the certificate that came out of it (FR-3).
    row, capped_from = issued.row, issued.capped_from
    audit.record(
        db,
        actor,
        AuditAction.cert_signed,
        summary=audit.signed_summary(row),
        target_type="certificate",
        target_id=row.id,
        detail=audit.certificate_detail(
            row,
            days_requested=days if capped_from is not None else None,
            validity_capped_from=capped_from,
        ),
        ip=client_ip(request, db),
    )
    _remember_capped(row.id, days, capped_from)
    return RedirectResponse(f"/certs/{row.id}", status_code=303)


# --- spec 0029: the two /certs previews ------------------------------------


def _blank_issue_preview() -> dict[str, object]:
    """The seven keys with nothing resolved: no issuer, so no names, no
    verdict and no expiry to state."""
    return {
        "issuer": None,
        "names": [],
        "verdict": None,
        "refused": False,
        "expires": None,
        "capped_from": None,
        "chain": None,
    }


def _issue_preview(
    db: Session,
    principal: Principal,
    *,
    subject_cn: str,
    sans: str,
    issuer_id: int | None,
    days: int,
) -> dict[str, object]:
    """FR-4/FR-5: what `POST /certs/issue` would answer, computed with the
    signer's own calls and nothing else.

    The names are resolved through :func:`leaf.resolve_sans` with exactly
    what ``issue_certificate`` passes it -- the normalised SAN lines, no CSR
    SANs, the common name -- because the two rungs of that ladder cannot be
    approximated: an empty SAN box falls back to the CN, and that fallback is
    ``IP:`` for an address and ``DNS:`` for a hostname. Handing
    ``check_name_constraints`` an empty list instead lets *its* own fallback
    append ``DNS:<cn>``, which is a different question with a more permissive
    answer (FR-5's measured case).

    ``check_name_constraints`` is then called twice, and both calls matter:

    * **once per name**, with ``subject_cn=None``, for that name's own mark.
      ``None`` so the common-name rule cannot fire inside a single-name call,
      where it would mark a name for a reason that is not about that name.
    * **once over the whole set**, byte for byte the call ``_build_leaf``
      makes, for the verdict. The verdict is *always* that call's and is
      never derived from the marks: the common name is checked as a dNSName
      only when the SAN list carries no DNS entry at all (``leaf.py``'s FR-5
      rule 7), so a request whose names are each permitted can still be
      refused as a set -- and a panel that says otherwise sends an operator
      into a 400.

    Nothing here is re-implemented: no regex, no suffix comparison, no ``in``
    test against ``constraints_of``'s lists. ``constraints_of`` is read for
    one thing only -- which of the two *permitted* sentences to print -- and
    no mark and no verdict is computed from it.

    Writes nothing and unseals nothing: the issuer's certificate comes from
    ``ca_certificates.cert_pem``, and ``ca_service.signing_credentials`` --
    the one function that decrypts a CA key -- is never on this path.
    """
    try:
        issuer = resolve_granted_issuer(db, principal, issuer_id)
    except (CANotConfiguredError, *_ISSUER_ERRORS):
        # No issuer to preview against is not an error on a form nobody has
        # finished filling in; the grant refusals above are, and they are
        # left to the handler, which answers them the way the mutation does.
        return _blank_issue_preview()

    issuer_cert = x509.load_pem_x509_certificate(issuer.cert_pem.encode("utf-8"))
    cn = subject_cn.strip() or None
    names: list[dict[str, object]] = []
    verdict: str | None = None
    refused = False

    try:
        resolved = leaf.resolve_sans(parse_san_lines(sans), [], cn)
    except IssueError as exc:
        # An unparsable SAN line, a CN that is neither hostname nor IP with an
        # empty SAN box, more than MAX_SANS entries: the message the POST
        # would show, from the same call (FR-5).
        resolved = []
        refused = True
        verdict = str(exc)

    for name in resolved:
        try:
            leaf.check_name_constraints(issuer_cert, None, [name])
        except leaf.NameConstraintError as exc:
            names.append({"name": name, "ok": False, "note": str(exc)})
        else:
            names.append({"name": name, "ok": True, "note": None})

    if resolved:
        try:
            leaf.check_name_constraints(issuer_cert, cn, resolved)
        except leaf.NameConstraintError as exc:
            refused = True
            verdict = str(exc)
        else:
            verdict = (
                _VERDICT_UNCONSTRAINED
                if leaf.constraints_of(issuer_cert).is_empty()
                else _VERDICT_PERMITTED
            )

    try:
        # Whole seconds, which is the precision a certificate's own notAfter
        # carries: stating more would be a claim the certificate cannot keep,
        # and it would make two renders of one request disagree in their
        # microseconds (AC-7 compares the two envelopes byte for byte).
        now = datetime.now(UTC).replace(microsecond=0)
        not_after, capped_from = leaf.clamp_validity(issuer_cert, days, now)
    except IssueError:
        not_after, capped_from = None, None

    return {
        "issuer": issuer.name,
        "names": names,
        "verdict": verdict,
        "refused": refused,
        "expires": not_after.isoformat() if not_after is not None else None,
        "capped_from": capped_from.isoformat() if capped_from is not None else None,
        "chain": " \u2192 ".join(row.name for row in ca_service.chain_for(db, issuer.id)),
    }


def _sign_preview(csr_pem: str) -> dict[str, object]:
    """FR-8: the pasted CSR, parsed and nothing else -- no database, no
    issuer, no constraint check.

    No verdict either, deliberately (Out of Scope): the effective SAN set for
    a CSR depends on ``sans_override`` and on the resolution ladder's second
    rung, and a verdict computed from one of the two would be exactly the
    disagreement FR-4 exists to prevent.

    A paste that does not parse is reported, not raised: a preview that fails
    on bad input fails on every keystroke of a half-typed one.
    """
    text = csr_pem.strip()
    if not text:
        return {"subject": None, "sans": [], "key": None, "error": None}
    try:
        csr = x509.load_pem_x509_csr(text.encode("utf-8"))
    except ValueError as exc:
        return {"subject": None, "sans": [], "key": None, "error": f"not a valid CSR PEM: {exc}"}
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        sans: list[str] = []
    else:
        sans = leaf.san_strings(extension.value)
    return {
        "subject": csr.subject.rfc4514_string(),
        "sans": sans,
        # The one spelling of a key-type label this project has; a second one
        # here would let two pages describe one key differently.
        "key": ca_x509._key_type_label(csr.public_key()),
        "error": None,
    }


@router.post("/issue/preview")
def certs_issue_preview(
    request: Request,
    subject_cn: str = Form(""),
    sans: str = Form(""),
    profile: str = Form("server"),
    key_type: str = Form("ecdsa-p256"),
    days: int = Form(DEFAULT_DAYS),
    issuer_id: int | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-3: guarded exactly like `POST /certs/issue` -- same dependencies,
    in the same order -- because a preview is a read of privileged state and
    one that is easier to reach than its mutation is an information leak with
    a friendly name.

    Two envelopes, one macro: the panel stack alone for htmx, the form page
    itself with that same panel stack in it for everybody else. The page goes
    through ``_new_page`` with ``values`` filled, which is why the
    no-JavaScript envelope re-fills the form for free.
    """
    principal = user_principal(user)
    issuers = _issuer_options(db, principal)
    values: dict[str, object] = {
        "subject_cn": subject_cn,
        "sans": sans,
        "profile": profile,
        "key_type": key_type,
        "days": days,
        "issuer_id": issuer_id,
    }
    try:
        found = _issue_preview(
            db, principal, subject_cn=subject_cn, sans=sans, issuer_id=issuer_id, days=days
        )
    except _GRANT_ERRORS as exc:
        return _new_page(request, user, str(exc), issuers=issuers, values=values, status_code=403)
    # `days` rides alongside the seven keys the Interface Contract fixes for
    # `_issue_preview`: the clamp note names the validity that was asked for,
    # and the macro reads nothing but the dictionary it is handed.
    preview: dict[str, object] = {"days": days, **found}
    if is_htmx(request):
        return preview_fragment("issue_panel", preview)
    values["preview"] = preview
    return _new_page(request, user, None, issuers=issuers, values=values)


@router.post("/sign/preview")
def certs_sign_preview(
    request: Request,
    csr_pem: str = Form(""),
    profile: str = Form("server"),
    days: int = Form(DEFAULT_DAYS),
    sans_override: str = Form(""),
    issuer_id: int | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-3/FR-8: the same two envelopes over `_sign_preview`.

    The issuer is resolved and then thrown away. Nothing on this panel is
    computed from it -- FR-8 gives the sign page no verdict -- but naming an
    issuer this principal is not granted has to be refused here exactly the
    way `POST /certs/sign` refuses it, or the preview is the easier door.
    """
    principal = user_principal(user)
    issuers = _issuer_options(db, principal)
    values: dict[str, object] = {
        "csr_pem": csr_pem,
        "profile": profile,
        "days": days,
        "sans_override": sans_override,
        "issuer_id": issuer_id,
    }
    try:
        resolve_granted_issuer(db, principal, issuer_id)
    except _GRANT_ERRORS as exc:
        return _sign_page(request, user, str(exc), issuers=issuers, values=values, status_code=403)
    except (CANotConfiguredError, *_ISSUER_ERRORS):
        pass
    preview = _sign_preview(csr_pem)
    if is_htmx(request):
        return preview_fragment("sign_panel", preview)
    values["preview"] = preview
    return _sign_page(request, user, None, issuers=issuers, values=values)


def _detail_page(
    request: Request,
    user: User,
    row: Certificate,
    error: str | None = None,
    status_code: int = 200,
    *,
    days_requested: int | None = None,
    capped_from: datetime | None = None,
) -> Response:
    context = base_context(request, user)
    context["cert"] = row
    # FR-6: viewers see the certificate, never the private key. A key we can
    # no longer unseal must not take the whole page down either -- the
    # certificate itself is still perfectly usable.
    is_admin = Role(user.role) in ADMIN_ROLES
    key_pem, key_error = (
        certs_service.key_material(request.app.state.secrets, row) if is_admin else (None, None)
    )
    context["key_pem"] = key_pem
    context["key_error"] = key_error
    # Spec 0006 AC-6: no key/PKCS#12 controls in a viewer's HTML at all, and
    # none for a CSR-signed certificate whose key cabin never had.
    context["can_download_key"] = is_admin and row.key_sealed is not None
    revoked_at = row.revoked_at_dt
    context["revoked_at"] = (
        revoked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if revoked_at else None
    )
    # Spec 0007 FR-7: the form is for admins, and only while there is
    # something left to revoke.
    context["can_revoke"] = is_admin and revoked_at is None
    context["reasons"] = list(RevocationReason)
    context["error"] = error
    # Spec 0017 FR-7/AC-7: present only right after an issuance that was
    # capped -- handed off by the issuance route, not stored or recomputed.
    context["days_requested"] = days_requested
    context["capped_from"] = capped_from.isoformat() if capped_from is not None else None
    response = templates.TemplateResponse(
        request, "cert_detail.html", context, status_code=status_code
    )
    # This page can render an unsealed private key -- no cache, anywhere,
    # may keep a copy of it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/{cert_id}")
def cert_detail(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    days_requested, capped_from = _take_capped(cert_id)
    return _detail_page(
        request,
        user,
        certificate_or_404(db, cert_id),
        days_requested=days_requested,
        capped_from=capped_from,
    )


@router.post("/{cert_id}/revoke")
def cert_revoke(
    cert_id: int,
    request: Request,
    reason: str = Form(str(RevocationReason.unspecified)),
    confirm: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0007 FR-7: revocation cannot be undone, so it takes an explicit
    confirmation on top of CSRF and the admin role."""
    row = certificate_or_404(db, cert_id)
    # Revoking is idempotent, so "was it already revoked" decides whether
    # this request changes anything -- and only a change is an event.
    was_revoked = row.revoked_at is not None
    if not confirm:
        return _detail_page(request, user, row, _CONFIRM_REVOKE, status_code=400)
    try:
        # A reason cabin does not know is refused rather than quietly
        # downgraded: the operator would be told the certificate was revoked
        # for a reason that never reaches the CRL.
        parsed = RevocationReason(reason)
    except ValueError:
        return _detail_page(request, user, row, _UNKNOWN_REASON.format(reason), status_code=400)
    try:
        crl_service.revoke_certificate(
            db, request.app.state.secrets, cert_id, parsed, principal=user_principal(user)
        )
    except CANotConfiguredError:
        # Spec 0024 FR-7: the same three-way distinction certs_new/certs_sign
        # make, though this page's own `_detail_page` carries no link -- a
        # revoke that hits this is already deep in a specific certificate's
        # page, not the issuer-selection form the link is for.
        return _detail_page(request, user, row, _no_issuer_message(db).message, status_code=400)
    except IssuerForbiddenError as exc:
        return _detail_page(request, user, row, str(exc), status_code=403)
    if not was_revoked:
        audit.record(
            db,
            actor,
            AuditAction.cert_revoked,
            summary=audit.revoked_summary(row, parsed),
            target_type="certificate",
            target_id=row.id,
            detail=audit.revocation_detail(row, parsed),
            ip=client_ip(request, db),
        )
    return RedirectResponse(f"/certs/{cert_id}", status_code=303)
