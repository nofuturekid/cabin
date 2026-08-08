"""UI routes for the CA hierarchies (spec 0017 FR-14): the wizard
(create/import) when no hierarchy exists at all, the list of every
hierarchy plus per-row actions once at least one does, and the PEM
downloads. GETs need only a logged-in session (viewer included); the
mutating POSTs need role admin or superadmin plus CSRF.
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
    CAHierarchy,
    CANotConfiguredError,
    CrossSignError,
    RetireError,
    UnknownIssuerError,
)
from cabin.ca.x509 import CAImportError
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


def _years_error(root_years: int, intermediate_years: int) -> str | None:
    return (
        _year_bounds_error(root_years, "root_years")
        or _year_bounds_error(intermediate_years, "intermediate_years")
        or (
            "intermediate_years must not exceed root_years"
            if intermediate_years > root_years
            else None
        )
    )


def _path_length_error(path_length: int) -> str | None:
    if not _MIN_PATH_LENGTH <= path_length <= _MAX_PATH_LENGTH:
        return f"path_length must be between {_MIN_PATH_LENGTH} and {_MAX_PATH_LENGTH}"
    return None


def _key_type_error(key_type: str) -> str | None:
    if key_type not in ca_x509.KEY_TYPES:
        return f"key_type must be one of: {', '.join(ca_x509.KEY_TYPES)}"
    return None


def _subject(hierarchy: CAHierarchy) -> str:
    """The signing CA's subject, read back off the stored certificate -- what
    an audit entry has to name, since "the CA" is otherwise anonymous."""
    return str(_cert_info(hierarchy.intermediate)["subject"])


def _tls_self_signed(request: Request) -> bool:
    """Spec 0022 FR-14: whether ca_setup.html's first-run warning note
    belongs on this page -- only while cabin is currently serving a
    self-signed certificate. `app.state.tls` is `None` with TLS off, and
    `.mode` is `None` before the first `ensure_current`; both mean "no".
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
    """One ``/ca`` row: identity, status, which actions are safe to offer
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
        "can_renew": signing_key_available,
        "can_retire": row.status == "active",
        "crl_url": crl_service.distribution_url(db, row.id) if is_intermediate else None,
        "ca_url": crl_service.ca_issuers_url(db, row.id) if is_intermediate else None,
        "acme_directory_url": (
            acme_http.directory_url(db, row.id) if is_intermediate and acme_enabled else None
        ),
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


def _groups(
    db: Session, rows: list[CACertificate], *, acme_enabled: bool
) -> list[dict[str, object]]:
    """Every row grouped under its root: root first, then its intermediates
    in creation order (AC-12), then the cross certificates that duplicate it
    (spec 0021 FR-13) -- each rendered under the root it *duplicates*
    (``cross_of_id``), since that is where an operator looks for "what
    paths does this hierarchy have". ``list_cas`` already orders by id, so
    every one of these comes out in that order too.

    Before this spec a cross row was invisible here: children were
    collected only for ``kind == "intermediate"`` and a group was built
    only for ``kind == "root"``, so a certificate cabin serves to every
    client would show on no page at all.
    """
    key_sealed_by_id = {row.id: row.key_sealed is not None for row in rows}
    rows_by_id = {row.id: row for row in rows}
    children: dict[int, list[CACertificate]] = {}
    crosses: dict[int, list[CACertificate]] = {}
    for row in rows:
        if row.kind == "intermediate" and row.parent_id is not None:
            children.setdefault(row.parent_id, []).append(row)
        elif row.kind == "cross" and row.cross_of_id is not None:
            crosses.setdefault(row.cross_of_id, []).append(row)

    groups: list[dict[str, object]] = []
    for root in rows:
        if root.kind != "root":
            continue
        # FR-6/FR-7: the one place this reads which path is actually served
        # -- computed fresh on every render, never cached on a row.
        chain_set = ca_service.chains_for(db, root.id)
        default_cross_id = chain_set.default.via_cross_id
        alternate_cross_ids = {
            alt.via_cross_id for alt in chain_set.alternates if alt.via_cross_id is not None
        }
        cross_rows: list[dict[str, object]] = []
        for cross in crosses.get(root.id, []):
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
            parent_has_key = (
                key_sealed_by_id.get(cross.parent_id, False)
                if cross.parent_id is not None
                else False
            )
            cross_rows.append(
                {
                    **_row_view(
                        db,
                        cross,
                        parent_has_key=parent_has_key,
                        acme_enabled=acme_enabled,
                    ),
                    "signed_by": signer.name if signer is not None else "unknown",
                    "served": served,
                }
            )
        groups.append(
            {
                "root": _row_view(db, root, parent_has_key=False, acme_enabled=acme_enabled),
                "intermediates": [
                    _row_view(
                        db,
                        child,
                        parent_has_key=key_sealed_by_id.get(root.id, False),
                        acme_enabled=acme_enabled,
                    )
                    for child in children.get(root.id, [])
                ],
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
        )
    return groups


def _list_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
) -> Response:
    rows = ca_service.list_cas(db)
    context = base_context(request, user)
    context["error"] = error
    # Spec 0022 FR-14: ca_setup.html's first-run warning note is read from
    # this key regardless of which template ends up rendering below.
    context["tls_self_signed"] = _tls_self_signed(request)
    if not rows:
        return templates.TemplateResponse(
            request, "ca_setup.html", context, status_code=status_code
        )
    context["groups"] = _groups(db, rows, acme_enabled=get_flag(db, ACME_ENABLED))
    return templates.TemplateResponse(request, "ca_list.html", context, status_code=status_code)


@router.get("")
def ca_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    return _list_page(request, db, user, None)


@router.post("/create")
def ca_create(
    request: Request,
    name: str = Form(...),
    key_type: str = Form("ecdsa-p256"),
    root_years: int = Form(20),
    intermediate_years: int = Form(10),
    path_length: int = Form(1),
    permitted_names: str = Form(""),
    excluded_names: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = (
        _key_type_error(key_type)
        or _years_error(root_years, intermediate_years)
        or _path_length_error(path_length)
    )
    constraints, constraints_error = _constraints_form_error(permitted_names, excluded_names)
    if form_error is None:
        form_error = constraints_error
    if form_error is not None:
        context = base_context(request, user)
        context["error"] = form_error
        context["tls_self_signed"] = _tls_self_signed(request)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    assert constraints is not None  # form_error is None only when parsing succeeded
    hierarchy = ca_service.create_hierarchy(
        db,
        request.app.state.secrets,
        name,
        key_type=key_type,
        root_years=root_years,
        intermediate_years=intermediate_years,
        path_length=path_length,
        constraints=constraints,
    )
    # Spec 0018 FR-8: whoever creates a hierarchy is granted it immediately --
    # written even for a superadmin, so a later demotion does not take the
    # hierarchy they built away from them.
    grant(db, user_principal(user), hierarchy.intermediate.id)
    # FR-10: read back off the certificate that was actually produced, not
    # echoed from the form -- so the log matches what was signed even if a
    # future bug in the writer drifted from what was typed.
    produced = x509.load_pem_x509_certificate(hierarchy.intermediate.cert_pem.encode("utf-8"))
    permitted, excluded = _canonical_entries(leaf.constraints_of(produced))
    audit.record(
        db,
        actor,
        AuditAction.ca_created,
        summary=f"created CA hierarchy {name!r}",
        target_type="ca_certificate",
        target_id=hierarchy.intermediate.id,
        detail={
            "name": name,
            "key_type": key_type,
            "root_years": root_years,
            "intermediate_years": intermediate_years,
            "path_length": path_length,
            "subject": _subject(hierarchy),
            "granted_to": user.id,
            "permitted": permitted,
            "excluded": excluded,
        },
        ip=client_ip(request, db),
    )
    # Spec 0022 FR-6: a freshly created CA can now sign cabin's own
    # certificate, so the swap is offered the chance to happen immediately
    # rather than waiting for the hourly check. A failure here is logged and
    # audited by `ensure_current` itself and never turned into a 5xx -- the
    # CA *was* created, and losing that outcome over a certificate swap
    # would be the worse error.
    tls_manager = request.app.state.tls
    if tls_manager is not None:
        tls_manager.ensure_current(db, request.app.state.secrets)
    return RedirectResponse("/ca", status_code=303)


@router.post("/import")
def ca_import(
    request: Request,
    cert_pem: str = Form(...),
    key_pem: str = Form(...),
    key_passphrase: str = Form(""),
    chain_pem: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        hierarchy = ca_service.import_hierarchy(
            db,
            request.app.state.secrets,
            cert_pem,
            key_pem,
            key_passphrase or None,
            chain_pem,
        )
    except CAImportError as exc:
        context = base_context(request, user)
        context["error"] = str(exc)
        context["tls_self_signed"] = _tls_self_signed(request)
        return templates.TemplateResponse(request, "ca_setup.html", context, status_code=400)
    # The subject only -- neither the submitted key nor its passphrase has any
    # business in a log (spec 0004 FR-3).
    subject = _subject(hierarchy)
    # Spec 0018 FR-8: same as ca_create above -- the importer is granted the
    # new intermediate immediately.
    grant(db, user_principal(user), hierarchy.intermediate.id)
    audit.record(
        db,
        actor,
        AuditAction.ca_imported,
        summary=f"imported CA {subject}",
        target_type="ca_certificate",
        target_id=hierarchy.intermediate.id,
        detail={"subject": subject, "granted_to": user.id},
        ip=client_ip(request, db),
    )
    # Spec 0022 FR-6: same as ca_create above -- an imported CA is just as
    # eligible to sign cabin's own certificate as a freshly generated one.
    tls_manager = request.app.state.tls
    if tls_manager is not None:
        tls_manager.ensure_current(db, request.app.state.secrets)
    return RedirectResponse("/ca", status_code=303)


@router.post("/{root_id}/intermediate")
def ca_create_intermediate(
    root_id: int,
    request: Request,
    name: str = Form(...),
    key_type: str = Form("ecdsa-p256"),
    years: int = Form(10),
    permitted_names: str = Form(""),
    excluded_names: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    form_error = _key_type_error(key_type) or _year_bounds_error(years, "years")
    constraints, constraints_error = _constraints_form_error(permitted_names, excluded_names)
    if form_error is None:
        form_error = constraints_error
    if form_error is not None:
        raise HTTPException(status_code=400, detail=form_error)
    assert constraints is not None  # form_error is None only when parsing succeeded
    try:
        row = ca_service.create_intermediate_under(
            db,
            request.app.state.secrets,
            root_id,
            name,
            key_type=key_type,
            years=years,
            constraints=constraints,
        )
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (CANotConfiguredError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Spec 0018 FR-8: same as ca_create above -- the creator is granted the
    # new intermediate immediately.
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
            "name": name,
            "key_type": key_type,
            "years": years,
            "root_id": root_id,
            "granted_to": user.id,
            "permitted": permitted,
            "excluded": excluded,
        },
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


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
    the list page at 400 with the message, before any row is written, the
    same way ``ca_create``'s form errors do (FR-13); nothing here is a bare
    HTTPException, because the action lives inside a details block on
    ``/ca`` rather than on its own page.
    """
    form_error = _year_bounds_error(years, "years")
    if form_error is not None:
        return _list_page(request, db, user, form_error, status_code=400)
    try:
        row = ca_service.cross_sign_root(
            db, request.app.state.secrets, ca_id, signing_root_id, years
        )
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, CANotConfiguredError, CrossSignError) as exc:
        return _list_page(request, db, user, str(exc), status_code=400)
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
    return RedirectResponse("/ca", status_code=303)


@router.post("/cross-import")
def ca_cross_import(
    request: Request,
    cross_pem: str = Form(...),
    issuer_pem: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """Spec 0021 FR-5/FR-13: import a cross certificate produced elsewhere.
    No key, no name -- the subject root is resolved by matching the
    submitted certificate against what is already on this instance
    (``import_cross``), and 0017's naming rule reads the row's name off its
    own certificate. Refused the same way ``ca_cross_sign`` is: a re-render
    of the list page at 400, no row written.
    """
    try:
        row = ca_service.import_cross(db, cross_pem, issuer_pem)
    except CAImportError as exc:
        return _list_page(request, db, user, str(exc), status_code=400)
    cross_info = ca_x509.describe_certificate(
        x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    )
    issuer_info = ca_x509.describe_certificate(
        x509.load_pem_x509_certificate(issuer_pem.encode("utf-8"))
    )
    audit.record(
        db,
        actor,
        AuditAction.ca_cross_imported,
        summary=f"imported cross certificate for {row.name!r}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={
            "subject_root_id": row.cross_of_id,
            "signing_root_id": row.parent_id,
            "cross_fingerprint": cross_info["fingerprint"],
            "signing_fingerprint": issuer_info["fingerprint"],
        },
        ip=client_ip(request, db),
    )
    return RedirectResponse("/ca", status_code=303)


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
    form_error = _year_bounds_error(years, "years")
    if form_error is not None:
        raise HTTPException(status_code=400, detail=form_error)
    try:
        row = ca_service.renew_in_place(db, request.app.state.secrets, ca_id, years)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CANotConfiguredError as exc:
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
    return RedirectResponse("/ca", status_code=303)


@router.post("/{ca_id}/retire")
def ca_retire(
    ca_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
    return RedirectResponse("/ca", status_code=303)


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
