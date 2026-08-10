"""UI routes for the transfer area (spec 0025): everything that moves
material into cabin or out of it, in one rail group with five pages.

Two of the five are the CA imports, moved here from :mod:`cabin.web.ca_ui`
-- their own pages now, unchanged apart from which page an error re-renders
(FR-2). The other three did not exist before this spec: a trust bundle (the
roots this instance vouches for, concatenated), a CA key export (superadmin
only -- see :func:`ca_key_export`'s docstring for why), and the certificate
inventory as a CSV or JSON file.

Two routers, because the paths this module owns are not all under one
prefix: ``router`` (``/transfer``) is the five pages and their download
routes; ``ca_router`` (``/ca``) carries only the two import POSTs, whose
paths are pinned by roughly ninety existing tests and could not move
without turning a cheap reorganisation into an expensive one (FR-2, the
same call spec 0023 FR-7 made for the same reason).
"""

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from cabin import audit
from cabin.api.views import certificate_fields
from cabin.audit import Actor, AuditAction
from cabin.ca import service as ca_service
from cabin.ca import x509 as ca_x509
from cabin.ca.certs import MAX_QUERY_LENGTH, STATUS_FILTERS, Certificate, export_certificates
from cabin.ca.service import CACertificate, UnknownIssuerError
from cabin.ca.x509 import CAImportError
from cabin.issuer_grants import grant, user_principal
from cabin.secrets import SecretsError
from cabin.users import User
from cabin.web import templates
from cabin.web.certs_download_ui import MIN_P12_PASSWORD, attachment, slug
from cabin.web.deps import (
    base_context,
    client_ip,
    current_actor,
    flash,
    get_current_user,
    get_db,
    is_htmx,
    preview_fragment,
    require_admin,
    require_superadmin,
    verify_csrf,
)

router = APIRouter(prefix="/transfer")
ca_router = APIRouter(prefix="/ca")

#: FR-11's last row: every key type cabin issues today (Ed25519 included)
#: serializes into a PKCS#12 bundle. This is the guard for the day one does
#: not -- the same wording certs_download_ui.py:41 carries for the leaf
#: bundle, kept as a separate constant here since FR-12 exports only
#: `attachment`/`slug`, not this message.
_P12_UNSUPPORTED = "this key type cannot be stored in a PKCS#12 bundle"

#: FR-5: the API's own field order (`api/views.py:certificate_fields`),
#: which both export files write as their header/keys. Kept as a constant
#: rather than read off a sample row so the header exists even when the
#: filtered set is empty.
_FIELDS = (
    "id",
    "serial_hex",
    "subject_cn",
    "sans",
    "profile",
    "not_before",
    "not_after",
    "status",
    "has_key",
    "revoked_at",
    "revocation_reason",
)


# --- shared with the two import POSTs ---------------------------------------


def _subject(row: CACertificate) -> str:
    """``row``'s own subject, read back off its stored certificate -- what
    the import audit events name, since "the CA" is otherwise anonymous."""
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    return cert.subject.rfc4514_string()


def _ca_import_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    status_code: int = 200,
    *,
    values: dict[str, object] | None = None,
) -> Response:
    """``values`` is spec 0029's one addition, keyword-only and empty by
    default: `POST /ca/import/preview` answers this same page with the
    ``Parsed`` panel filled and the two certificate textareas re-filled
    (FR-3). It carries only what that endpoint declares -- the two
    certificates -- so the private key and its passphrase have nowhere here
    to come back from either (FR-11)."""
    context = base_context(request, db, user)
    context["error"] = error
    context["values"] = values or {}
    return templates.TemplateResponse(
        request, "transfer_ca_import.html", context, status_code=status_code
    )


def _import_preview(cert_pem: str, chain_pem: str) -> dict[str, object]:
    """Spec 0029 FR-10: the two pasted certificates, read.

    Two parameters and four keys, and no parameter anywhere on this path for
    a private key or a passphrase: this form carries both, and a handler that
    debounces on keystrokes must ship neither to an endpoint that echoes what
    it parses. What cannot be named cannot be echoed.

    An unparsable paste is reported rather than raised, for the reason
    `certs_ui._sign_preview` gives: half a PEM block is what every keystroke
    of a paste looks like.
    """
    subject: str | None = None
    parent: str | None = None
    key: str | None = None
    error: str | None = None

    text = cert_pem.strip()
    if text:
        try:
            cert = x509.load_pem_x509_certificate(text.encode("utf-8"))
        except ValueError as exc:
            error = f"the signing CA certificate does not parse: {exc}"
        else:
            subject = cert.subject.rfc4514_string()
            # The one spelling of a key-type label this project has.
            key = ca_x509._key_type_label(cert.public_key())

    chain = chain_pem.strip()
    if chain:
        try:
            parent_cert = x509.load_pem_x509_certificate(chain.encode("utf-8"))
        except ValueError as exc:
            error = error or f"the parent/root certificate does not parse: {exc}"
        else:
            parent = parent_cert.subject.rfc4514_string()

    return {"subject": subject, "parent": parent, "key": key, "error": error}


def _cross_import_page(
    request: Request, db: Session, user: User, error: str | None, status_code: int = 200
) -> Response:
    context = base_context(request, db, user)
    context["error"] = error
    return templates.TemplateResponse(
        request, "transfer_cross_import.html", context, status_code=status_code
    )


@router.get("/ca-import")
def ca_import_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    return _ca_import_page(request, db, user, None)


@router.get("/cross-import")
def cross_import_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Response:
    return _cross_import_page(request, db, user, None)


@ca_router.post("/import/preview")
def ca_import_preview(
    request: Request,
    cert_pem: str = Form(""),
    chain_pem: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-3/FR-11: guarded exactly like `POST /ca/import`, and declaring
    exactly the two fields the panel reads plus the token ``verify_csrf``
    takes.

    There is no ``key_pem`` and no ``key_passphrase`` parameter, so no code
    path exists that could echo one, and a hand-built request carrying them
    is answered by a page containing neither string. That is what makes the
    no-JavaScript path safe as well: the round-trip `Check` button is a
    `<button formaction>` inside the form, so the browser posts every field
    including the key and its passphrase -- one deliberate submit, to the same
    origin the mutation posts to, where they land in no parameter, are read by
    nothing, are written to no log and appear in no response. What FR-11
    forbids is a keystroke stream carrying a passphrase, and the template's
    `hx-trigger` is what forbids it.
    """
    preview = _import_preview(cert_pem, chain_pem)
    if is_htmx(request):
        return preview_fragment("import_panel", preview)
    values: dict[str, object] = {
        "cert_pem": cert_pem,
        "chain_pem": chain_pem,
        "preview": preview,
    }
    return _ca_import_page(request, db, user, None, values=values)


@ca_router.post("/import")
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
    """FR-2: unchanged from ``ca_ui.ca_import`` apart from which page an
    error re-renders -- moved, not rewritten, since roughly ninety existing
    tests reach this exact path, method, field set, guard and CSRF rule."""
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
        return _ca_import_page(request, db, user, str(exc), status_code=400)
    # The subject only -- neither the submitted key nor its passphrase has any
    # business in a log (spec 0004 FR-3).
    subject = _subject(hierarchy.intermediate)
    # Spec 0018 FR-8: the importer is granted the new intermediate immediately.
    grant(db, user_principal(user), hierarchy.intermediate.id)
    # Spec 0030 FR-3: the longest message this project can produce, which is
    # why `sessions.flash` is `sa.Text` -- a subject is operator-supplied.
    summary = f"imported CA {subject}"
    audit.record(
        db,
        actor,
        AuditAction.ca_imported,
        summary=summary,
        target_type="ca_certificate",
        target_id=hierarchy.intermediate.id,
        detail={"subject": subject, "granted_to": user.id},
        ip=client_ip(request, db),
    )
    # Spec 0022 FR-6: an imported CA is just as eligible to sign cabin's own
    # certificate as a freshly generated one.
    tls_manager = request.app.state.tls
    if tls_manager is not None:
        tls_manager.ensure_current(db, request.app.state.secrets)
    flash(request, db, summary)
    return RedirectResponse("/ca", status_code=303)


@ca_router.post("/cross-import")
def ca_cross_import(
    request: Request,
    cross_pem: str = Form(...),
    issuer_pem: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-2: unchanged from ``ca_ui.ca_cross_import`` apart from which page
    an error re-renders."""
    try:
        row = ca_service.import_cross(db, cross_pem, issuer_pem)
    except CAImportError as exc:
        return _cross_import_page(request, db, user, str(exc), status_code=400)
    cross_info = ca_x509.describe_certificate(
        x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    )
    issuer_info = ca_x509.describe_certificate(
        x509.load_pem_x509_certificate(issuer_pem.encode("utf-8"))
    )
    summary = f"imported cross certificate for {row.name!r}"
    audit.record(
        db,
        actor,
        AuditAction.ca_cross_imported,
        summary=summary,
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
    flash(request, db, summary)
    return RedirectResponse("/ca", status_code=303)


# --- the trust bundle (FR-4) -------------------------------------------------


def _root_rows(db: Session) -> list[dict[str, object]]:
    """FR-4's page listing: every ``kind == "root"`` row, whatever its
    status -- unlike the file itself (active roots only), the page is where
    an operator sees *why* a retired root is missing from it and can still
    reach that hierarchy's own bundle. ``intermediate_count`` counts every
    intermediate under it, any status, the same count ``ca_ui._overview``
    already reports.
    """
    rows = ca_service.list_cas(db)
    intermediate_counts: dict[int, int] = {}
    for row in rows:
        if row.kind == "intermediate" and row.parent_id is not None:
            intermediate_counts[row.parent_id] = intermediate_counts.get(row.parent_id, 0) + 1
    return [
        {
            "id": row.id,
            "name": row.name,
            "status": row.status,
            "intermediate_count": intermediate_counts.get(row.id, 0),
        }
        for row in rows
        if row.kind == "root"
    ]


def _trust_bundle_rows(db: Session, root_id: int | None) -> list[CACertificate]:
    """FR-4: the whole-instance set -- every **active** ``kind == "root"``
    row -- when ``root_id`` is ``None``; one hierarchy -- that root,
    whatever its own status, plus its active intermediates in id order --
    when given. Never a ``kind == "cross"`` row: a cross certificate carries
    the same subject and public key as the root it duplicates, so trusting
    it adds nothing that trusting that root does not already give.

    Assumes ``root_id``, when given, already names an existing
    ``kind == "root"`` row -- the route checks that first, since the two
    ways it can fail (unknown id, wrong kind) answer with different 404
    wording.
    """
    rows = ca_service.list_cas(db)
    if root_id is None:
        return [row for row in rows if row.kind == "root" and row.status == "active"]
    root = next(row for row in rows if row.id == root_id)
    intermediates = sorted(
        (
            row
            for row in rows
            if row.kind == "intermediate" and row.parent_id == root_id and row.status == "active"
        ),
        key=lambda r: r.id,
    )
    return [root, *intermediates]


@router.get("/trust-bundle")
def trust_bundle_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    context = base_context(request, db, user)
    context["roots"] = _root_rows(db)
    return templates.TemplateResponse(request, "transfer_trust_bundle.html", context)


@router.get("/trust-bundle.pem")
def trust_bundle_pem(
    request: Request,
    ca: int | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> Response:
    if ca is None:
        rows = _trust_bundle_rows(db, None)
        filename = "cabin-trust-bundle.pem"
    else:
        try:
            root = ca_service.get_ca(db, ca)
        except UnknownIssuerError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if root.kind != "root":
            # FR-4: the same wording ca_ui.ca_detail uses (ca_ui.py:492-495)
            # -- a hierarchy is named by its root, not by any row in it.
            raise HTTPException(
                status_code=404, detail="a hierarchy is named by its root, not by this id"
            )
        rows = _trust_bundle_rows(db, ca)
        filename = f"{slug(root.name)}-{ca}-trust-bundle.pem"
    body = "".join(row.cert_pem for row in rows)
    return attachment(body.encode("ascii"), "application/x-pem-file", filename)


# --- the CA key export (FR-6..FR-11) -----------------------------------------


def _exportable(row: CACertificate) -> bool:
    """FR-9: a row is exportable iff cabin actually holds its key -- true for
    every generated CA and for an imported *intermediate* (its key was
    uploaded through ``POST /ca/import``), false for an imported root, the
    signing root of an imported cross certificate, and every
    ``kind == "cross"`` row (none of the three ever carries one). The only
    place this rule is written; the row list and the ``<select>`` both use
    it, so they cannot disagree.
    """
    return row.key_sealed is not None


def _ca_key_page(
    request: Request,
    db: Session,
    user: User,
    error: str | None,
    *,
    values: dict[str, object] | None = None,
    status_code: int = 200,
) -> Response:
    """The one renderer for ``transfer_ca_key.html``, used by the GET and by
    every 400 the POST produces (FR-11) -- the shape ``ca_ui._detail_page``
    has. Lists **every** CA row with its exportability (FR-9's second half):
    an operator who cannot find a row in the select is told why, instead of
    wondering whether it exists at all.
    """
    all_rows = ca_service.list_cas(db)

    def view(row: CACertificate) -> dict[str, object]:
        return {"id": row.id, "name": row.name, "kind": row.kind, "exportable": _exportable(row)}

    # Spec 0030 FR-9/FR-15: the same grouped list `/ca` and the dashboard
    # draw -- one entry per root with its intermediates under `issuers`, one
    # per cross row at root level -- carrying the same three cell values per
    # row this page carries today.
    children: dict[int | None, list[CACertificate]] = {}
    for row in all_rows:
        if row.kind == "intermediate":
            children.setdefault(row.parent_id, []).append(row)
    grouped: list[dict[str, object]] = []
    for row in all_rows:
        if row.kind not in {"root", "cross"}:
            continue
        entry = view(row)
        entry["issuers"] = [
            view(child) for child in (children.get(row.id, []) if row.kind == "root" else [])
        ]
        grouped.append(entry)
    context = base_context(request, db, user)
    context["error"] = error
    context["values"] = values or {}
    context["rows"] = grouped
    context["exportable_rows"] = [view(row) for row in all_rows if _exportable(row)]
    return templates.TemplateResponse(
        request, "transfer_ca_key.html", context, status_code=status_code
    )


@router.get("/ca-key")
def ca_key_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
) -> Response:
    """FR-6: superadmin only. The route refuses anyone else with a 403 before
    a page is ever built -- ``nav.ca_key`` only decides whether the rail
    entry is offered, it enforces nothing."""
    return _ca_key_page(request, db, user, None)


@router.post("/ca-key")
def ca_key_export(
    request: Request,
    ca_id: int = Form(...),
    # FR-7: `Form("")`, not `Form(...)` -- an empty submitted value must
    # reach this handler as "" rather than FastAPI's own 422, so a missing
    # password is the same clean 400 as a too-short one
    # (certs_download_ui.py:174-179's reasoning, repeated here).
    password: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_superadmin),
    actor: Actor = Depends(current_actor),
    _csrf: None = Depends(verify_csrf),
) -> Response:
    """FR-6..FR-11: cabin's one route that hands out a CA's private key.

    Whoever receives this file can issue as this CA, for as long as its
    certificate is valid, and cabin will see none of it -- the CRL only
    covers what cabin itself issued. Superadmin (the dependency above), a
    mandatory password checked before anything is unsealed (FR-7, FR-11), an
    audit event written only after the bundle actually exists (FR-8), and
    nothing ever written to disk (FR-10, via `attachment` streaming the body
    straight from memory) all follow from that.
    """
    # FR-11: checked first, before the row is even looked up -- nothing about
    # a specific CA's key is touched before the caller has proven they can
    # actually use the file that would come back.
    if len(password) < MIN_P12_PASSWORD:
        return _ca_key_page(
            request,
            db,
            user,
            f"the bundle password must be at least {MIN_P12_PASSWORD} characters",
            values={"ca_id": ca_id},
            status_code=400,
        )
    try:
        row = ca_service.get_ca(db, ca_id)
    except UnknownIssuerError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not _exportable(row):
        return _ca_key_page(
            request,
            db,
            user,
            f"CA certificate {ca_id}'s private key is not available",
            values={"ca_id": ca_id},
            status_code=400,
        )
    try:
        cert, key = ca_service.signing_credentials(db, request.app.state.secrets, ca_id)
    except SecretsError as exc:
        # FR-11: a key that exists but cannot be decrypted is a state
        # conflict, not a 500 -- certs_download_ui.py:97-108's rule, applied
        # here for the first time on the CA side; nothing here caught
        # SecretsError before this route.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    # FR-7 says "the rest of its default chain" and cites `chain_for` -- but
    # `chain_for` serves the DEFAULT chain a *leaf download* prefers, which
    # spec 0021 deliberately lets a valid cross certificate replace (the
    # oldest one becomes the default the moment it exists). A CA key export
    # is not a leaf download: it hands over the row's own signing lineage,
    # so it must always be the self-signed walk, whatever else is currently
    # marked default -- `chains_for(...).self_signed` (spec 0021 FR-6) is
    # the one path that never substitutes a cross certificate for a real
    # parent.
    cas = [
        x509.load_pem_x509_certificate(parent.cert_pem.encode("ascii"))
        for parent in ca_service.chains_for(db, ca_id).self_signed.rows[1:]
    ]
    try:
        bundle = pkcs12.serialize_key_and_certificates(
            name=row.name.encode("utf-8"),
            # The PEM parser's return type is wider than what PKCS#12 can
            # carry; the except below -- not a type check -- is what turns a
            # key it cannot carry into a clean 400 (FR-11).
            key=cast(pkcs12.PKCS12PrivateKeyTypes, key),
            cert=cert,
            cas=cas,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    except (TypeError, ValueError):
        return _ca_key_page(
            request, db, user, _P12_UNSUPPORTED, values={"ca_id": ca_id}, status_code=400
        )
    # FR-8: written after the bundle exists and before the response goes out
    # -- every refusal above returns before this line, so the log can only
    # ever say a key left the instance if one actually did. The password is
    # in neither the summary nor the detail (spec 0004 FR-3).
    audit.record(
        db,
        actor,
        AuditAction.ca_key_exported,
        summary=f"exported CA key for {row.name!r}",
        target_type="ca_certificate",
        target_id=row.id,
        detail={
            "kind": row.kind,
            "subject": cert.subject.rfc4514_string(),
            "fingerprint": ca_x509.describe_certificate(cert)["fingerprint"],
        },
        ip=client_ip(request, db),
    )
    return attachment(bundle, "application/x-pkcs12", f"{slug(row.name)}-{row.id}.p12")


# --- the inventory export (FR-5) ---------------------------------------------


def _normalize_filters(q: str, status: str) -> tuple[str, str]:
    """``/certs``' own normalisation (``certs_ui.py:291-293``): the query is
    capped, and an unknown ``status`` is treated as "all" rather than an
    error -- the export must accept a stale or hand-edited ``?status=`` the
    same way the list it is exported from does."""
    return q.strip()[:MAX_QUERY_LENGTH], status if status in STATUS_FILTERS else "all"


def _inventory_rows(db: Session, q: str, status: str, now: datetime) -> list[Certificate]:
    """A thin wrapper over :func:`cabin.ca.certs.export_certificates` that
    applies ``/certs``' own filter normalisation, so the export and the list
    can never disagree about what a filter means."""
    term, active = _normalize_filters(q, status)
    return export_certificates(db, q=term, status=active, now=now)


def _iso(moment: datetime) -> str:
    """A point in time in the shape FR-5 specifies for both export files --
    the same shape ``ca_ui.py``'s cross-sign audit detail already writes."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def _csv_row(fields: dict[str, Any]) -> list[str]:
    """FR-5: one inventory row as ``csv.writer`` writes it -- ``sans`` joined
    with a single space, ``has_key`` as ``true``/``false``, an absent
    ``revoked_at``/``revocation_reason`` as an empty cell."""
    revoked_at = fields["revoked_at"]
    return [
        str(fields["id"]),
        str(fields["serial_hex"]),
        str(fields["subject_cn"]),
        " ".join(fields["sans"]),
        str(fields["profile"]),
        _iso(fields["not_before"]),
        _iso(fields["not_after"]),
        str(fields["status"]),
        "true" if fields["has_key"] else "false",
        _iso(revoked_at) if revoked_at else "",
        str(fields["revocation_reason"] or ""),
    ]


def _json_item(fields: dict[str, Any]) -> dict[str, Any]:
    """FR-5: one inventory row for the JSON file -- ``sans`` a list,
    ``has_key`` a boolean, an absent ``revoked_at``/``revocation_reason`` as
    ``null``."""
    revoked_at = fields["revoked_at"]
    return {
        "id": fields["id"],
        "serial_hex": fields["serial_hex"],
        "subject_cn": fields["subject_cn"],
        "sans": fields["sans"],
        "profile": fields["profile"],
        "not_before": _iso(fields["not_before"]),
        "not_after": _iso(fields["not_after"]),
        "status": str(fields["status"]),
        "has_key": fields["has_key"],
        "revoked_at": _iso(revoked_at) if revoked_at else None,
        "revocation_reason": fields["revocation_reason"],
    }


@router.get("/inventory")
def inventory_page(
    request: Request,
    q: str = "",
    status: str = "all",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    now = datetime.now(UTC)
    term, active = _normalize_filters(q, status)
    total = len(_inventory_rows(db, q, status, now))
    context = base_context(request, db, user)
    context.update(
        {
            "q": term,
            "status": active,
            "statuses": STATUS_FILTERS,
            # Spec 0030 FR-15: the same segmented control the inventory has,
            # built from the same `_normalize_filters` values -- the only way
            # this page can look like the rest of the application.
            "status_urls": {
                option: "/transfer/inventory?" + urlencode({"q": term, "status": option})
                for option in STATUS_FILTERS
            },
            "total": total,
        }
    )
    return templates.TemplateResponse(request, "transfer_inventory.html", context)


@router.get("/inventory.csv")
def inventory_csv(
    request: Request,
    q: str = "",
    status: str = "all",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    now = datetime.now(UTC)
    rows = _inventory_rows(db, q, status, now)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_FIELDS)
    for row in rows:
        writer.writerow(_csv_row(certificate_fields(row, now)))
    return attachment(
        buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8", "cabin-inventory.csv"
    )


@router.get("/inventory.json")
def inventory_json(
    request: Request,
    q: str = "",
    status: str = "all",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    now = datetime.now(UTC)
    term, active = _normalize_filters(q, status)
    rows = _inventory_rows(db, q, status, now)
    payload = {
        "generated_at": _iso(now),
        "filter": {"q": term, "status": active},
        "total": len(rows),
        "items": [_json_item(certificate_fields(row, now)) for row in rows],
    }
    return attachment(
        json.dumps(payload).encode("utf-8"), "application/json", "cabin-inventory.json"
    )
