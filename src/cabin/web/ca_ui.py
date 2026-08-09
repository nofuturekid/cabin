"""UI routes for the CA hierarchies (spec 0023, narrowed by spec 0025 FR-2):
a list with no forms (`GET /ca`), one hierarchy in full with its own actions
(`GET /ca/{ca_id}`), and a create page (`GET /ca/new`). GETs need only a
logged-in session (viewer included, `/ca/new` admin-only); the mutating
POSTs need role admin or superadmin plus CSRF, and keep the paths they had
before spec 0023 (FR-7) -- only where a response goes changed.

The import page and both import POSTs moved to :mod:`cabin.web.transfer_ui`
(spec 0025 FR-2): they answer under `/ca/import` and `/ca/cross-import`
still, but this module no longer owns them.
"""

from cryptography import x509
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.acme import http as acme_http
from cabin.audit import Actor, AuditAction
from cabin.ca import crl as crl_service
from cabin.ca import leaf
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.leaf import NameConstraintError, NameConstraintSpec
from cabin.ca.service import (
    CACertificate,
    CANotConfiguredError,
    CrossSignError,
    RetireError,
    RowRetiredError,
    UnknownIssuerError,
)
from cabin.issuer_grants import grant, user_principal
from cabin.settings import ACME_ENABLED, TLS_ISSUER_ID, get_flag, get_setting
from cabin.tls import TlsMode
from cabin.users import User
from cabin.web import templates
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    get_current_user,
    get_db,
    require_admin,
    verify_csrf,
)

router = APIRouter(prefix="/ca")

_MIN_YEARS = 1
_MAX_YEARS = 50
#: FR-13/AC-11: below 1 no intermediate could be signed at all; the upper
#: bound is a sanity cap, not an X.509 invariant.
_MIN_PATH_LENGTH = 1
_MAX_PATH_LENGTH = 4
#: FR-2: not cabin's own policy -- what `x509.NameAttribute` enforces on
#: `NameOID.COMMON_NAME` (cryptography 49.0.0), measured as UTF-8 bytes, not
#: characters.
_MAX_NAME_BYTES = 64


def _name_error(name: str) -> str | None:
    """FR-2: refuses what `create_root`/`create_intermediate_under` would
    otherwise hand straight to `cryptography`'s `NameAttribute`, so its own
    sentence -- "Attribute's length must be >= 1 and <= 64, but it was 0" --
    never reaches an operator as if cabin had written it.

    Takes ``name`` already stripped: the caller strips once and reuses that
    same stripped value both for this check and for what is actually signed
    and stored (AC-3), so the two can never disagree the way "validated
    unstripped, stored stripped" would.

    The bound is bytes, not characters: `NameAttribute` measures the value's
    UTF-8 encoding, so 64 U+00E4 characters (128 bytes) would be refused by
    cryptography where 64 ASCII characters (64 bytes) would not -- counting
    characters here would silently disagree with what is actually enforced
    one layer down.
    """
    if not name:
        return "name must not be empty"
    if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
        return f"name must be at most {_MAX_NAME_BYTES} bytes long (UTF-8 encoded)"
    return None


#: FR-9: the same pattern `certs_ui._CONFIRM_REVOKE` already sets for a
#: dangerous action's confirm checkbox -- refused before the row is touched
#: rather than assumed ticked.
_CONFIRM_RETIRE = "tick the confirmation box: retiring cannot be undone from here"


def _cert_info(row: CACertificate) -> dict[str, object]:
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    info = ca_x509.describe_certificate(cert)
    info["kind"] = row.kind
    constraints = leaf.constraints_of(cert)
    info["permitted_dns"] = list(constraints.permitted_dns)
    info["permitted_ip"] = [str(network) for network in constraints.permitted_ip]
    info["excluded_dns"] = list(constraints.excluded_dns)
    info["excluded_ip"] = [str(network) for network in constraints.excluded_ip]
    info["has_constraints"] = not constraints.is_empty()
    return info


def _canonical_entries(spec: NameConstraintSpec) -> tuple[list[str], list[str]]:
    """FR-10: the audit detail's ``permitted``/``excluded`` -- the canonical
    entry strings (DNS suffixes then IP networks, each side) read back from
    the certificate that was actually produced, not echoed from the form."""
    permitted = [*spec.permitted_dns, *(str(network) for network in spec.permitted_ip)]
    excluded = [*spec.excluded_dns, *(str(network) for network in spec.excluded_ip)]
    return permitted, excluded


def _constraints_form_error(
    permitted_names: str, excluded_names: str
) -> tuple[NameConstraintSpec | None, str | None]:
    """FR-3: parsed here, at the route, before anything is written -- a
    constraint that fails to parse must not leave an orphan root behind
    (``create_hierarchy`` inserts and flushes the root before it builds the
    intermediate)."""
    try:
        return leaf.parse_name_constraints(permitted_names, excluded_names), None
    except NameConstraintError as exc:
        return None, str(exc)


def _year_bounds_error(value: int, field: str) -> str | None:
    if not _MIN_YEARS <= value <= _MAX_YEARS:
        return f"{field} must be between {_MIN_YEARS} and {_MAX_YEARS}"
    return None


def _years_error(root_years: int) -> str | None:
    """FR-3: used to also compare `intermediate_years` against `root_years`;
    that comparison went with the second field the moment a create stopped
    asking for one. Kept as a named wrapper -- rather than inlined at its one
    call site -- because the Interface Contract pins its name across this
    spec as "loses its `intermediate_years` argument", not "is removed".
    """
    return _year_bounds_error(root_years, "root_years")


def _path_length_error(path_length: int) -> str | None:
    if not _MIN_PATH_LENGTH <= path_length <= _MAX_PATH_LENGTH:
        return f"path_length must be between {_MIN_PATH_LENGTH} and {_MAX_PATH_LENGTH}"
    return None


def _key_type_error(key_type: str) -> str | None:
    if key_type not in ca_x509.KEY_TYPES:
        return f"key_type must be one of: {', '.join(ca_x509.KEY_TYPES)}"
    return None


def _subject(row: CACertificate) -> str:
    """``row``'s own subject, read back off its stored certificate -- what an
    audit entry has to name, since "the CA" is otherwise anonymous. Takes the
    row whose subject is meant (FR-4: a root for a root create, an
    intermediate for an intermediate create) rather than a `CAHierarchy`,
    since after FR-3 a create only ever produces one row at a time.
    """
    return str(_cert_info(row)["subject"])


def _tls_self_signed(request: Request) -> bool:
    """Spec 0022 FR-14: whether the first-run warning note belongs on this
    page -- only while cabin is currently serving a self-signed certificate.
    `app.state.tls` is `None` with TLS off, and `.mode` is `None` before the
    first `ensure_current`; both mean "no". Spec 0023 FR-10: the note moved
    from `ca_setup.html` into `/ca`'s own empty state, under this same
    condition.
    """
    tls = request.app.state.tls
    return tls is not None and tls.mode == TlsMode.self_signed


def _refuse_retire_of_tls_issuer(
    request: Request, db: Session, ca_id: int, row: CACertificate
) -> None:
    """Spec 0022 FR-17: retiring the issuer bound to cabin's own TLS
    certificate is refused while TLS is on. Retiring it would leave
    `tls.resolve_tls_issuer` with nothing to renew from, and cabin's own
    certificate would then expire 30 to 90 days later -- the maximum
    possible distance between cause and symptom, with nothing left
    connecting the two.

    Lives here rather than in `ca_service.retire` because only the route
    has `request.app.state.config`; with TLS off the binding is inert and
    an operator not using cabin's own TLS must not be obstructed by it.

    Reads the raw `TLS_ISSUER_ID` setting rather than calling
    `resolve_tls_issuer` -- that function's job is deciding what to issue
    *with*, including persisting the sole-active-issuer default, which is
    not a decision a retire check should be the one to trigger. Uses
    `retire_targets` for the set a retire would actually touch, so
    retiring a root whose bound intermediate hangs underneath it is
    refused too, not just a direct hit on the bound row's own id.
    """
    if row.status != "active" or not request.app.state.config.tls:
        return
    stored = get_setting(db, TLS_ISSUER_ID)
    if not stored:
        return
    try:
        bound_id = int(stored)
    except ValueError:
        return
    if bound_id in ca_service.retire_targets(db, ca_id):
        raise RetireError(
            f"retiring {row.name!r} would leave cabin's own TLS certificate with no "
            "issuer to renew from; rebind under Settings first, then retire"
        )


def _row_view(
    db: Session, row: CACertificate, *, parent_has_key: bool, acme_enabled: bool
) -> dict[str, object]:
    """One hierarchy row: identity, status, which actions are safe to offer
    (AC-13, an imported root has no stored key so creating an intermediate
    under it or renewing it would only ever 500), and -- for an intermediate
    -- where its CRL and its AIA `caIssuers` document are published (spec
    0007 FR-6, spec 0022 FR-16: the exact URLs embedded in certificates that
    issuer signs, so an operator can see why a certificate carries none, or
    click through to check a wrong port mapping), and where its ACME
    directory is (spec 0019 FR-13: a directory belongs to one issuer, so it
    is shown in that issuer's own row rather than once for the whole page).
    Built through the same helper the ACME server itself resolves a
    directory with, never by reassembling the string here.

    Works unchanged for a ``kind == "cross"`` row (spec 0021 FR-13): it has
    no key of its own, so ``parent_has_key`` -- the *signing* root's key
    state for a cross row, the group's own root's for an intermediate --
    decides ``can_renew`` exactly the way FR-11 moved the guard.

    ``can_renew`` also requires ``row.status == "active"`` (bugfix
    following spec 0026): a retired row is never served again, so a
    working Renew form on one would let an operator produce a certificate
    for nothing. ``renew_in_place`` carries the same check server-side --
    hiding the form here is not itself the fix.
    """
    has_key = row.key_sealed is not None
    signing_key_available = has_key if row.kind == "root" else parent_has_key
    is_intermediate = row.kind == "intermediate"
    return {
        **_cert_info(row),
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "status": row.status,
        "can_create_intermediate": row.kind == "root" and has_key,
        "can_renew": signing_key_available and row.status == "active",
        "can_retire": row.status == "active",
        "crl_url": crl_service.distribution_url(db, row.id) if is_intermediate else None,
        "ca_url": crl_service.ca_issuers_url(db, row.id) if is_intermediate else None,
        "acme_directory_url": (
            acme_http.directory_url(db, row.id) if is_intermediate and acme_enabled else None
        ),
    }


def _page_of(row: CACertificate) -> str:
    """Spec 0026 FR-11: the page that owns ``row`` -- the one place that
    mapping lives, so a table's ``href`` and a POST's redirect can never
    disagree about where a row is shown. A root's page is the hierarchy page
    itself; an intermediate hangs under its ``parent_id``; a cross row hangs
    under its ``cross_of_id``, its **subject** root, because that is the
    hierarchy whose table lists it (FR-8) -- ``parent_id`` on a cross row is
    the *signing* root and would name a page reachable from no table at all.

    Takes the row alone: both foreign keys are on it, so no ``Session`` is
    needed to answer this.
    """
    if row.kind == "root":
        return f"/ca/{row.id}"
    if row.kind == "intermediate":
        assert row.parent_id is not None  # FR-1's invariant: every intermediate has a parent
        return f"/ca/{row.parent_id}/issuer/{row.id}"
    assert row.cross_of_id is not None  # FR-1's invariant: every cross row names its subject
    return f"/ca/{row.cross_of_id}/cross/{row.id}"


def _child_view(row: CACertificate) -> dict[str, object]:
    """Spec 0026 FR-12: one row of the ``Issuers`` or ``Cross certificates``
    table, and nothing more -- id, name, status, expiry and the link to the
    row's own page. Deliberately **not** a thinner ``_row_view``: it calls
    neither ``leaf.constraints_of`` nor ``crl_service.distribution_url`` nor
    ``crl_service.ca_issuers_url`` nor ``acme_http.directory_url``, because
    nothing in a table row displays any of them. A page doing hidden work for
    output it no longer produces leaves the next reader unable to tell which
    of the two was the mistake.

    Parses the certificate once, through ``describe_certificate`` rather than
    ``_cert_info``, for the reason ``_overview``'s docstring gives.
    """
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    return {
        "id": row.id,
        "name": row.name,
        "status": row.status,
        "not_valid_after": ca_x509.describe_certificate(cert)["not_valid_after"],
        "href": _page_of(row),
    }


def _cross_sign_candidates(
    rows: list[CACertificate], subject: CACertificate
) -> list[dict[str, object]]:
    """FR-13: the roots that could sign ``subject`` -- a different root,
    with a stored key (FR-4), whose ``path_length`` can carry the extra hop
    (FR-3, ``cross_path_length_error``). A root that cannot sign is not
    offered in the select rather than offered and then refused.
    """
    subject_cert = x509.load_pem_x509_certificate(subject.cert_pem.encode("utf-8"))
    candidates: list[dict[str, object]] = []
    for row in rows:
        if row.kind != "root" or row.id == subject.id or row.key_sealed is None:
            continue
        issuer_cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
        if ca_x509.cross_path_length_error(subject_cert, issuer_cert) is None:
            candidates.append({"id": row.id, "name": row.name})
    return candidates


def _overview(db: Session, rows: list[CACertificate]) -> list[dict[str, object]]:
    """FR-2: `/ca`'s own view -- one entry per ``kind == "root"`` row, in
    ``list_cas`` order, carrying only what the list shows: name, status,
    expiry and how many intermediates and cross certificates hang off it.
    The counts come from ``rows``, already loaded; the expiry is read out of
    the parsed certificate (``ca_certificates`` has no ``not_after``
    column), one per hierarchy rather than one per row -- and, deliberately,
    through ``describe_certificate`` rather than ``_cert_info``: this list
    has no `<details>`, no CRL or ACME URL and no constraints block, so it
    has no reason to call ``leaf.constraints_of`` at all. ``db`` is unused --
    kept for symmetry with ``_group``, whose sibling this is.
    """
    del db
    intermediate_counts: dict[int, int] = {}
    cross_counts: dict[int, int] = {}
    for row in rows:
        if row.kind == "intermediate" and row.parent_id is not None:
            intermediate_counts[row.parent_id] = intermediate_counts.get(row.parent_id, 0) + 1
        elif row.kind == "cross" and row.cross_of_id is not None:
            cross_counts[row.cross_of_id] = cross_counts.get(row.cross_of_id, 0) + 1
    overview: list[dict[str, object]] = []
    for row in rows:
        if row.kind != "root":
            continue
        cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
        overview.append(
            {
                "id": row.id,
                "name": row.name,
                "status": row.status,
                "not_valid_after": ca_x509.describe_certificate(cert)["not_valid_after"],
                "intermediate_count": intermediate_counts.get(row.id, 0),
                "cross_count": cross_counts.get(row.id, 0),
            }
        )
    return overview


def _group(
    db: Session,
    rows: list[CACertificate],
    root: CACertificate,
) -> dict[str, object]:
    """FR-3: one hierarchy, in full -- today's ``_groups`` (spec 0017-0022)
    for a single root, same keys (``root``, ``intermediates``,
    ``cross_certificates``, ``chain``, ``cross_sign_candidates``), same body
    otherwise. ``rows`` is **every** row on the instance, not just this
    hierarchy's: ``_cross_sign_candidates`` needs to see roots outside the
    group being built, and a detail page that queried only its own subtree
    would render an empty select and silently remove the cross-signing
    action from an instance that can perform it (FR-3's own warning).
    ``root`` names which group to build.

    Spec 0026: the two child lists are ``_child_view`` entries -- five keys
    for an intermediate, those plus ``signed_by`` and ``served`` for a cross
    row -- because both are tables now and everything else about a row is on
    the row's own page (FR-2, FR-3, FR-6). The ``acme_enabled`` keyword went
    with them: the only row left on this page is the root, and
    ``_row_view`` computes an ACME directory URL on its intermediate branch
    only, so the flag's value cannot reach the result.
    """
    rows_by_id = {row.id: row for row in rows}
    children = [row for row in rows if row.kind == "intermediate" and row.parent_id == root.id]
    cross_source = [row for row in rows if row.kind == "cross" and row.cross_of_id == root.id]

    # FR-6/FR-7: the one place this reads which path is actually served --
    # computed fresh on every render, never cached on a row.
    chain_set = ca_service.chains_for(db, root.id)
    default_cross_id = chain_set.default.via_cross_id
    alternate_cross_ids = {
        alt.via_cross_id for alt in chain_set.alternates if alt.via_cross_id is not None
    }
    cross_rows: list[dict[str, object]] = []
    for cross in cross_source:
        if cross.id == default_cross_id:
            served = "default"
        elif cross.id in alternate_cross_ids:
            served = "alternate"
        else:
            served = "not_served"
        # A cross row's parent_id always names its signing root (FR-1's
        # first invariant) -- the `is not None` guards are for mypy's
        # benefit, not because either lookup is ever expected to miss.
        signer = rows_by_id.get(cross.parent_id) if cross.parent_id is not None else None
        cross_rows.append(
            {
                **_child_view(cross),
                "signed_by": signer.name if signer is not None else "unknown",
                "served": served,
            }
        )
    return {
        "root": _row_view(db, root, parent_has_key=False, acme_enabled=False),
        "intermediates": [_child_view(child) for child in children],
        "cross_certificates": cross_rows,
        "chain": {
            "default_name": chain_set.default.rows[-1].name,
            "default_id": chain_set.default.rows[-1].id,
            "default_via_cross": chain_set.default.via_cross_id is not None,
            "alternates": [
                {
                    "name": alt.rows[-1].name,
                    "id": alt.rows[-1].id,
                    "via_cross": alt.via_cross_id is not None,
                }
                for alt in chain_set.alternates
            ],
        },
        "cross_sign_candidates": _cross_sign_candidates(rows, root),
    }


def _root_of(db: Session, row: CACertificate) -> CACertificate:
    """The hierarchy ``row`` is shown under: the row itself for a root, its
    ``parent_id`` for an intermediate, its ``cross_of_id`` for a cross row.

    Spec 0026 left it exactly one call site -- FR-10's re-render, which needs
    the root **row** to build an issuer page, not a path. The redirects it
    used to serve go through ``_page_of`` now, which answers the finer
    question (which *page* owns a row) and needs no ``Session`` to do it.
    """
    if row.kind == "root":
        return row
    if row.kind == "intermediate":
        assert row.parent_id is not None  # FR-1's invariant: every intermediate has a parent
        return ca_service.get_ca(db, row.parent_id)
    assert row.cross_of_id is not None  # FR-1's invariant: every cross row names its subject
    return ca_service.get_ca(db, row.cross_of_id)


def _load_pair(
    db: Session, root_id: int, row_id: int, *, kind: str
) -> tuple[CACertificate, CACertificate]:
    """Spec 0026 FR-7: the only place the two new pages' seven refusals
    live, so ``/ca/{root}/issuer/{id}`` and ``/ca/{root}/cross/{id}`` cannot
    drift apart. Every one of them is a 404 (FR-9): not a redirect to the
    hierarchy the row really belongs to -- the next thing an operator does
    on that page is renew or retire, and a silently corrected URL means
    acting on a hierarchy they did not think they had open -- and not a 403,
    since every logged-in user may read every row at its correct URL.

    ``kind`` is ``"intermediate"`` or ``"cross"``, and it decides which
    foreign key has to name ``root_id``: ``parent_id`` for an intermediate,
    ``cross_of_id`` for a cross row. That difference is the whole point
    (FR-8): a cross row's ``parent_id`` is the root that *signed* it, while
    the table that links to it sits on its *subject* root's page, so a guard
    written against ``parent_id`` would refuse the URL the instance actually
    links to and serve one reachable from no table at all.
    """
    try:
        root = ca_service.get_ca(db, root_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if root.kind != "root":
        raise HTTPException(
            status_code=404, detail="a hierarchy is named by its root, not by this id"
        )
    try:
        row = ca_service.get_ca(db, row_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if row.kind != kind:
        raise HTTPException(status_code=404, detail=f"this id does not name a {kind} certificate")
    owner_id = row.parent_id if kind == "intermediate" else row.cross_of_id
    if owner_id != root.id:
        raise HTTPException(status_code=404, detail="this row does not belong to that hierarchy")
    return root, row


def _detail_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    status_code: int = 200,
) -> Response:
    """The one renderer for ``ca_detail.html``, used by the GET and by every
    POST that re-renders it (create-intermediate, cross-sign, retire without
    its confirmation). Loads every row, not just ``root``'s group, for the
    reason ``_group``'s docstring gives.

    No longer takes ``open_form`` (FR-8): every action is its own `<details>`-
    free `.section` now, so there is nothing left to open.

    Spec 0026: no longer reads ``ACME_ENABLED`` either -- the only ACME
    directory URL this page ever showed belonged to an intermediate, and an
    intermediate is a table row here now. That lookup moved to
    ``_issuer_page``, which is where the URL is rendered.
    """
    rows = ca_service.list_cas(db)
    context = base_context(request, user)
    context["error"] = error
    context["group"] = _group(db, rows, root)
    context["values"] = values or {}
    return templates.TemplateResponse(request, "ca_detail.html", context, status_code=status_code)


def _issuer_page(
    request: Request,
    db: Session,
    user: User,
    root: CACertificate,
    row: CACertificate,
    error: str | None,
    *,
    status_code: int = 200,
) -> Response:
    """Spec 0026 FR-6: the one renderer for ``ca_issuer.html`` -- one
    intermediate or one cross certificate in full, under the hierarchy it
    belongs to. Used by both new GETs and by FR-10's 400, because the page
    that owns a form is the page an unticked confirmation has to come back
    to.

    ``parent_has_key`` is read from ``row.parent_id``, never from ``root``.
    For an intermediate the two are the same row; for a cross row they are
    not -- ``parent_id`` is the *signing* root (FR-8) -- and ``_row_view``
    decides ``can_renew`` from it. Taking it from the subject root would
    offer a Renew button on an imported cross certificate that can only ever
    500, and hide it on one cabin itself signed.
    """
    parent_has_key = False
    if row.parent_id is not None:
        parent_has_key = ca_service.get_ca(db, row.parent_id).key_sealed is not None
    view = _row_view(
        db, row, parent_has_key=parent_has_key, acme_enabled=get_flag(db, ACME_ENABLED)
    )
    if row.kind == "cross":
        # Exactly what `_group` computes for the same row, from the same
        # `ChainSet`: which path this instance actually serves is decided
        # fresh on every render and never cached on a row.
        chain_set = ca_service.chains_for(db, root.id)
        alternate_cross_ids = {
            alt.via_cross_id for alt in chain_set.alternates if alt.via_cross_id is not None
        }
        if row.id == chain_set.default.via_cross_id:
            view["served"] = "default"
        elif row.id in alternate_cross_ids:
            view["served"] = "alternate"
        else:
            view["served"] = "not_served"
        signer = ca_service.get_ca(db, row.parent_id) if row.parent_id is not None else None
        view["signed_by"] = signer.name if signer is not None else "unknown"
    context = base_context(request, user)
    context["error"] = error
    context["root"] = {"id": root.id, "name": root.name}
    context["row"] = view
    return templates.TemplateResponse(request, "ca_issuer.html", context, status_code=status_code)


def _new_page(request: Request, user: User, error: str | None, status_code: int = 200) -> Response:
    context = base_context(request, user)
    context["error"] = error
    return templates.TemplateResponse(request, "ca_new.html", context, status_code=status_code)


@router.get("")
def ca_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """FR-2: the list, nothing else. `_overview`'s empty state carries
    FR-10's TLS note under the same condition ``ca_setup.html`` did: visible
    only while both hold -- self-signed TLS and no hierarchy at all."""
    rows = ca_service.list_cas(db)
    context = base_context(request, user)
    context["overview"] = _overview(db, rows)
    context["tls_self_signed"] = _tls_self_signed(request)
    return templates.TemplateResponse(request, "ca_list.html", context)


@router.get("/new")
def ca_new_page(request: Request, user: User = Depends(require_admin)) -> Response:
    return _new_page(request, user, None)


@router.get("/{ca_id:int}")
def ca_detail(
    ca_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """FR-3/FR-9: one hierarchy, named by its root. The ``:int`` converter
    (matching ``crl_ui.py:93``) is what keeps this route from swallowing
    ``/ca/new``, ``/ca/import``, ``/ca/{id}.pem`` and the ``.cer`` route
    that lives in the crl router included after this one -- a bare
    ``/{ca_id}`` would compile to ``^/ca/(?P<ca_id>[^/]+)$`` and match all
    four before any of them got a chance to answer (spec 0017's ``/crl/7.pem``
    bug, exactly). An id naming an intermediate or a cross row, or naming
    nothing at all, is a 404: a hierarchy is named by its root, not by any
    row in it.
    """
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if row.kind != "root":
        raise HTTPException(
            status_code=404, detail="a hierarchy is named by its root, not by this id"
        )
    return _detail_page(request, db, user, row, None)


@router.get("/{root_id:int}/issuer/{issuer_id:int}")
def ca_issuer_detail(
    root_id: int,
    issuer_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Spec 0026 FR-5: one intermediate in full -- its identity, its
    downloads, its published URLs, its constraints and its renew and retire
    controls, all of which used to be a `.section` on the hierarchy page.

    Nested under the root rather than generalising ``/ca/{ca_id}``: that path
    means "the hierarchy whose root is this id" and refuses every non-root id,
    a refusal one spec old. Nesting costs nothing -- both ids are in hand
    wherever the link is rendered -- and it buys ``_load_pair``'s guard.

    ``:int`` on **both** parameters (spec 0023 FR-9): without the converter a
    non-numeric segment reaches the handler and answers 422 from conversion
    instead of 404 from routing.
    """
    root, row = _load_pair(db, root_id, issuer_id, kind="intermediate")
    return _issuer_page(request, db, user, root, row, None)


@router.get("/{root_id:int}/cross/{cross_id:int}")
def ca_cross_detail(
    root_id: int,
    cross_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Spec 0026 FR-5: one cross certificate in full, under its **subject**
    root (FR-8). A separate path from ``/issuer/`` because cabin reserves the
    word "issuer" for something that signs leaves -- that is what
    ``resolve_issuer``, ``active_issuers`` and every ACME directory URL mean
    by it -- and a cross certificate signs nothing. One URL covering both
    would be a page lying about what it shows.
    """
    root, row = _load_pair(db, root_id, cross_id, kind="cross")
    return _issuer_page(request, db, user, root, row, None)


@router.post("/create")
def ca_create(
    request: Request,
    # `Form(...)` treats an empty submitted value as *missing* rather than
    # present-and-invalid, which is a 422 FastAPI answers before `_name_error`
    # ever runs (verified against a bare FastAPI app) -- an explicit default
    # is what lets `name=""` reach the validator at all (FR-2, AC-2).
    name: str = Form(""),
    key_type: str = Form("ecdsa-p256"),
    root_years: int = Form(20),
    path_length: int = Form(1),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-3: creates a root and nothing else -- the intermediate, if any, is
    a separate decision made on the root's own page
    (``ca_create_intermediate`` below), which is also where the grant now
    lives (FR-5): it has nothing to act on here, since a bare root is not an
    issuer.

    ``name`` is stripped once (FR-2) and the stripped value is what
    `_name_error` checks and what is signed and stored -- never the raw
    submission, which could carry the leading/trailing space AC-3 exists to
    catch.
    """
    stripped_name = name.strip()
    form_error = (
        _name_error(stripped_name)
        or _key_type_error(key_type)
        or _years_error(root_years)
        or _path_length_error(path_length)
    )
    if form_error is not None:
        return _new_page(request, user, form_error, status_code=400)
    root = ca_service.create_root(
        db,
        request.app.state.secrets,
        stripped_name,
        key_type=key_type,
        years=root_years,
        path_length=path_length,
    )
    audit.record(
        db,
        actor,
        AuditAction.ca_created,
        summary=f"created CA root {stripped_name!r}",
        target_type="ca_certificate",
        target_id=root.id,
        detail={
            "name": stripped_name,
            "key_type": key_type,
            "root_years": root_years,
            "path_length": path_length,
            "subject": _subject(root),
        },
        ip=client_ip(request, db),
    )
    # Spec 0022 FR-6: a root alone has no active issuer, so this can only
    # ever bootstrap or keep a *self-signed* certificate (`resolve_tls_issuer`
    # finds nothing to swap to yet) -- the actual swap away from it happens
    # in `ca_create_intermediate` below, the step that produces one (FR-5).
    # Still called here so a fresh instance with TLS on has *something*
    # loaded the moment its first root exists, rather than nothing until the
    # hourly check runs. A failure here is logged and audited by
    # `ensure_current` itself and never turned into a 5xx -- the root *was*
    # created, and losing that outcome over a certificate swap would be the
    # worse error.
    tls_manager = request.app.state.tls
    if tls_manager is not None:
        tls_manager.ensure_current(db, request.app.state.secrets)
    return RedirectResponse("/ca", status_code=303)


@router.post("/{root_id}/intermediate")
def ca_create_intermediate(
    root_id: int,
    request: Request,
    # `Form(...)` treats an empty submitted value as *missing* (see
    # `ca_create`'s own comment) -- an explicit default is what lets
    # `name=""` reach `_name_error` as a 400 instead of FastAPI's own 422.
    name: str = Form(""),
    key_type: str = Form("ecdsa-p256"),
    years: int = Form(10),
    permitted_names: str = Form(""),
    excluded_names: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-8: every refusal re-renders ``root_id``'s own detail page at 400,
    the form re-filled from what was submitted (``values``) -- in place of
    the bare ``HTTPException`` this route used to raise on every one of
    them. ``UnknownIssuerError`` stays a 404: no page can be rendered for a
    root that does not exist.

    FR-5: the grant and cabin's own TLS hook move here from ``ca_create``,
    since this is now the route that actually produces an issuer -- a bare
    root has nothing for either to act on.
    """
    try:
        root = ca_service.get_ca(db, root_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    values: dict[str, object] = {
        "name": name,
        "key_type": key_type,
        "years": years,
        "permitted_names": permitted_names,
        "excluded_names": excluded_names,
    }
    stripped_name = name.strip()
    form_error = (
        _name_error(stripped_name)
        or _key_type_error(key_type)
        or _year_bounds_error(years, "years")
    )
    constraints, constraints_error = _constraints_form_error(permitted_names, excluded_names)
    if form_error is None:
        form_error = constraints_error
    if form_error is not None:
        return _detail_page(request, db, user, root, form_error, values=values, status_code=400)
    assert constraints is not None  # form_error is None only when parsing succeeded
    try:
        row = ca_service.create_intermediate_under(
            db,
            request.app.state.secrets,
            root_id,
            stripped_name,
            key_type=key_type,
            years=years,
            constraints=constraints,
        )
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (CANotConfiguredError, ValueError) as exc:
        return _detail_page(request, db, user, root, str(exc), values=values, status_code=400)
    # Spec 0018 FR-8: whoever creates the intermediate is granted it
    # immediately -- written even for a superadmin, so a later demotion does
    # not take it away from them. Spec 0024 FR-5: the only call site on this
    # path now, a root-only create has nothing to grant.
    grant(db, user_principal(user), row.id)
    # FR-10: read back off the certificate that was actually produced.
    produced = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    permitted, excluded = _canonical_entries(leaf.constraints_of(produced))
    audit.record(
        db,
        actor,
        AuditAction.ca_created,
        summary=f"created intermediate {row.name!r} under root {root_id}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={
            "name": stripped_name,
            "key_type": key_type,
            "years": years,
            "root_id": root_id,
            "granted_to": user.id,
            "permitted": permitted,
            "excluded": excluded,
        },
        ip=client_ip(request, db),
    )
    # Spec 0022 FR-6, moved here by spec 0024 FR-5: this is now the step that
    # can actually produce an issuer, so this is where the swap away from a
    # self-signed certificate gets the chance to happen immediately rather
    # than waiting for the hourly check. A failure here is logged and audited
    # by `ensure_current` itself and never turned into a 5xx -- the
    # intermediate *was* created, and losing that outcome over a certificate
    # swap would be the worse error.
    tls_manager = request.app.state.tls
    if tls_manager is not None:
        tls_manager.ensure_current(db, request.app.state.secrets)
    return RedirectResponse(f"/ca/{root_id}", status_code=303)


@router.post("/{ca_id}/cross-sign")
def ca_cross_sign(
    ca_id: int,
    request: Request,
    signing_root_id: int = Form(...),
    years: int = Form(10),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0021 FR-4/FR-13: cabin signs a second certificate for
    ``ca_id``'s root, using ``signing_root_id``'s key. Every refusal --
    unknown id, not a root, no stored key, ``path_length`` too small, an
    active cross certificate for this pair already existing -- re-renders
    ``ca_id``'s own detail page at 400 with the message and its own
    before any row is written, the same way ``ca_create_intermediate``'s
    form errors do (FR-7).
    """
    try:
        root = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    form_error = _year_bounds_error(years, "years")
    if form_error is not None:
        return _detail_page(request, db, user, root, form_error, status_code=400)
    try:
        row = ca_service.cross_sign_root(
            db, request.app.state.secrets, ca_id, signing_root_id, years
        )
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, CANotConfiguredError, CrossSignError) as exc:
        return _detail_page(request, db, user, root, str(exc), status_code=400)
    produced = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    audit.record(
        db,
        actor,
        AuditAction.ca_cross_signed,
        summary=f"cross-signed {row.name!r} with root {signing_root_id}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={
            "signing_root_id": signing_root_id,
            "subject_root_id": ca_id,
            "years": years,
            "not_after": produced.not_valid_after_utc.replace(microsecond=0).isoformat(),
        },
        ip=client_ip(request, db),
    )
    return RedirectResponse(f"/ca/{ca_id}", status_code=303)


@router.post("/{ca_id}/renew")
def ca_renew(
    ca_id: int,
    request: Request,
    years: int = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-7: unchanged but for its redirect target. Spec 0026 FR-11 moves
    that target one step further, from the hierarchy page to the row's own
    page (``_page_of``): this is 0023 FR-7's own rule -- an action comes back
    to the page that owns the control -- following the control onto the page
    it now lives on. Out of Scope: the bare ``HTTPException`` on a
    form-bounds refusal is left as it was; a single number lost on a 400 is
    not FR-8's defect."""
    form_error = _year_bounds_error(years, "years")
    if form_error is not None:
        raise HTTPException(status_code=400, detail=form_error)
    try:
        row = ca_service.renew_in_place(db, request.app.state.secrets, ca_id, years)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (CANotConfiguredError, RowRetiredError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(
        db,
        actor,
        AuditAction.ca_renewed,
        summary=f"renewed CA {row.name!r}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={"years": years},
        ip=client_ip(request, db),
    )
    return RedirectResponse(_page_of(row), status_code=303)


@router.post("/{ca_id}/retire")
def ca_retire(
    ca_id: int,
    request: Request,
    confirm: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-9: the confirmation checkbox is enforced here, the same way
    ``certs_ui.cert_revoke`` enforces its own (``certs_ui.py:515, 527``) --
    refused before the row is touched, re-rendering the row's own detail
    page at 400 rather than the bare ``HTTPException`` this route used to
    raise unconditionally. This is the one place this spec extends 0023's
    Out of Scope note about ``ca_retire``'s bare ``HTTPException``: a missing
    checkbox is a state an operator reaches by forgetting one click, not a
    domain refusal, so it gets a form response rather than a JSON error
    document.

    Spec 0026 FR-10: that re-render has to be the page which actually
    carries the form the operator just failed to submit, and after the split
    the hierarchy page carries it only for the root itself. So the branch
    chooses by kind -- ``_detail_page`` for a root, ``_issuer_page`` for an
    intermediate or a cross row. The status code, the message and the rule
    that the row is not touched before the check are all unchanged.
    """
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not confirm:
        if row.kind == "root":
            return _detail_page(request, db, user, row, _CONFIRM_RETIRE, status_code=400)
        return _issuer_page(
            request, db, user, _root_of(db, row), row, _CONFIRM_RETIRE, status_code=400
        )
    was_active = row.status == "active"
    try:
        _refuse_retire_of_tls_issuer(request, db, ca_id, row)
        ca_service.retire(db, ca_id)
    except RetireError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Retiring an already-retired row is a no-op (FR-4): only a real state
    # change is worth an event, the same rule the role/token routes apply.
    if was_active:
        audit.record(
            db,
            actor,
            AuditAction.ca_retired,
            summary=f"retired CA {row.name!r}",
            target_type="ca_certificate",
            target_id=ca_id,
            ip=client_ip(request, db),
        )
    return RedirectResponse(_page_of(row), status_code=303)


@router.get("/{ca_id}.pem")
def ca_cert_pem(
    ca_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="no such CA") from exc
    return PlainTextResponse(row.cert_pem, media_type="application/x-pem-file")


@router.get("/{issuer_id}/chain.pem")
def ca_chain_pem(
    issuer_id: int,
    anchor: int | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> PlainTextResponse:
    """Spec 0021 FR-8: the default chain, or -- with ``?anchor=``, naming a
    path by its topmost row's id (``ChainSet.by_anchor``) -- one specific
    alternate. An ``anchor`` naming no path in this leaf's current
    ``ChainSet`` is a 404, never a silent fallback to the default: a client
    that asked for a specific anchor and got a different one has been
    misinformed about the one thing it asked about.
    """
    try:
        chain_set = ca_service.chains_for(db, issuer_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail="no such CA") from exc
    if anchor is None:
        chain = chain_set.default.rows
    else:
        found = chain_set.by_anchor(anchor)
        if found is None:
            raise HTTPException(status_code=404, detail="no such chain")
        chain = found.rows
    body = "".join(row.cert_pem for row in chain)
    return PlainTextResponse(body, media_type="application/x-pem-file")
