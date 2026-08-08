"""Tests for spec 0020 (name constraints): the CA-creation and display
surfaces -- the HTTP creation routes (``POST /ca/create`` and
``POST /ca/{root_id}/intermediate``), the import form, what ``GET /ca``
displays, the creation forms' rejections, and the ``ca_created`` audit
detail.

The matching rules and the crypto layer (``cabin.ca.leaf``'s
``NameConstraintSpec``/``parse_name_constraints``/``check_name_constraints``,
and ``cabin.ca.x509``'s handling of the extension) live in
``tests/test_name_constraints.py``. Enforcement reaching every issuance
door -- the two UI forms, the two REST endpoints, the two MCP tools, ACME
finalize, cabin's own TLS certificate, and a renewal's carry-over of the
extension including a route that ignores posted constraint fields -- lives
in ``tests/test_name_constraints_doors.py`` and is not repeated here.

This branch is red by design: none of ``cabin.ca.leaf``'s new names
(``NameConstraintSpec``, ``parse_name_constraints``,
``name_constraints_extension``, ``constraints_of``) exist on disk yet, and
neither ``ca_service.create_hierarchy``/``create_intermediate_under`` nor
``web/ca_ui.py``'s routes accept a constraint yet. ``cabin.ca.leaf`` is
imported as a module (``leaf_mod``), following the same technique the two
files above already use, so a missing symbol fails the one test that
touches it rather than collection of the whole file.

Real DOM parsing (``html.parser.HTMLParser``), never a bare substring
search, for two reasons this project has been burned by before: a
constraints block that "appears somewhere on the page" could just as well
be the create form's own textarea, and an absent form field has to be
proven absent from the *right* form, not merely absent as a page-wide
string (the create form gains ``permitted_names`` right next to the import
form that must never have it).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.audit import AuditAction, AuditEvent
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca.service import CACertificate
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory

_PASSWORD = "whatever12345"


# --- fixtures / helpers, mirroring tests/test_web_ca.py's own -----------------


def make_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _setup_superadmin(client: TestClient) -> None:
    resp = client.post("/setup", data={"username": "root", "password": _PASSWORD})
    assert resp.status_code == 303


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _rows(cfg: Config) -> list[CACertificate]:
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        for row in rows:
            _ = row.id, row.kind, row.name, row.status, row.parent_id, row.cert_pem
        db.expunge_all()
        return rows
    finally:
        db.close()


def _by_name(cfg: Config, name: str) -> CACertificate:
    matches = [row for row in _rows(cfg) if row.name == name]
    assert len(matches) == 1, f"expected exactly one row named {name!r}, got {len(matches)}"
    return matches[0]


def _cert_of(row: CACertificate) -> x509.Certificate:
    return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))


def _no_name_constraints(cert: x509.Certificate) -> None:
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.NameConstraints)


def _create_ca(client: TestClient, cfg: Config, name: str = "cabin") -> None:
    resp = client.post(
        "/ca/create",
        data={
            "name": name,
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _pem_key(key: object) -> str:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _ca_created_event(cfg: Config, target_id: int) -> AuditEvent | None:
    db = _db(cfg)
    try:
        event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == AuditAction.ca_created.value,
                AuditEvent.target_id == str(target_id),
            )
        )
        if event is not None:
            _ = event.detail  # decode while the session is open
        return event
    finally:
        db.close()


#: FR-3's four rejection shapes, shared between the /ca/create and
#: /ca/{root_id}/intermediate loops below.
_BAD_CONSTRAINT_INPUTS: list[tuple[str, str]] = [
    ("wildcard", "*.example.com"),
    ("host_bits_set", "10.1.2.3/8"),
    ("not_a_hostname", "not a hostname"),
    (
        "too_many_entries",
        "\n".join(f"h{i}.example.com" for i in range(leaf_mod.MAX_NAME_CONSTRAINTS + 1)),
    ),
]


# --- a self-signed root that itself carries constraints (Out of Scope's own
#     configuration: an imported root's constraints, which create_root
#     cannot produce since FR-1 gives create_root no constraint argument
#     at all) ----------------------------------------------------------------


def _root_with_constraints(
    subject_cn: str, permitted_dns: tuple[str, ...]
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(UTC)
    key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(d) for d in permitted_dns], excluded_subtrees=None
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * 20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(nc, critical=True)
    )
    cert = builder.sign(key, algorithm=hashes.SHA256())
    return cert, key


# --- real DOM parsing --------------------------------------------------------


class _FormFieldNames(HTMLParser):
    """The ``name`` attribute of every ``<input>``/``<textarea>`` inside the
    ``<form>`` whose ``action`` equals ``action`` -- so "this field is
    absent" can be asserted against the *right* form. The create form gains
    exactly the field the import form must never have, so a page-wide
    substring search would prove nothing (AC-10)."""

    def __init__(self, action: str) -> None:
        super().__init__()
        self._action = action
        self.found_form = False
        self.field_names: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "form" and attrs_dict.get("action") == self._action:
            self.found_form = True
            self._depth = 1
            return
        if self._depth > 0:
            if tag == "form":
                self._depth += 1
            elif tag in ("input", "textarea"):
                name = attrs_dict.get("name")
                if name is not None:
                    self.field_names.append(name)

    def handle_endtag(self, tag: str) -> None:
        if self._depth > 0 and tag == "form":
            self._depth -= 1


def _fields_of_form(html: str, action: str) -> _FormFieldNames:
    parser = _FormFieldNames(action)
    parser.feed(html)
    return parser


# === HTTP creation routes: both take constraints (FR-1, AC-1) ==================


def test_ca_create_route_applies_constraints_to_the_intermediate(
    client: TestClient, cfg: Config
) -> None:
    """AC-1 via ``POST /ca/create``: the intermediate carries a critical
    ``NameConstraints`` extension matching what was posted, and the root
    carries none -- read with ``cryptography`` off the stored ``cert_pem``,
    never through a chain check."""
    _setup_superadmin(client)
    resp = client.post(
        "/ca/create",
        data={
            "name": "wired",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "permitted_names": "example.com",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    intermediate = _cert_of(_by_name(cfg, "wired Intermediate CA"))
    extension = intermediate.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical is True
    assert extension.value.permitted_subtrees == [x509.DNSName("example.com")]
    assert extension.value.excluded_subtrees is None

    root = _cert_of(_by_name(cfg, "wired Root CA"))
    _no_name_constraints(root)


def test_ca_create_intermediate_route_applies_constraints(client: TestClient, cfg: Config) -> None:
    """AC-1 via ``POST /ca/{root_id}/intermediate`` -- the rotation path,
    which is 0017's only other way to add a further intermediate, and the
    one FR-1 warns is easy to leave unwired while the wizard's own path
    gets fixed."""
    _setup_superadmin(client)
    _create_ca(client, cfg, "rotation-base")
    root = _by_name(cfg, "rotation-base Root CA")

    resp = client.post(
        f"/ca/{root.id}/intermediate",
        data={
            "name": "rotated",
            "key_type": "ecdsa-p256",
            "years": 5,
            "permitted_names": "",
            "excluded_names": "lab.internal",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    rotated = _cert_of(_by_name(cfg, "rotated Intermediate CA"))
    extension = rotated.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical is True
    assert extension.value.excluded_subtrees == [x509.DNSName("lab.internal")]
    assert extension.value.permitted_subtrees is None


def test_ca_create_intermediate_route_with_empty_constraint_fields_stays_unconstrained(
    client: TestClient, cfg: Config
) -> None:
    """The counter-check for the same route: blank ``permitted_names`` and
    ``excluded_names`` (the form's own default) must not be read as "empty
    strings", i.e. an empty-but-present ``NameConstraints`` extension --
    RFC 5280 forbids one with both sides absent, and FR-2 requires *no*
    extension at all here."""
    _setup_superadmin(client)
    _create_ca(client, cfg, "plain-base")
    root = _by_name(cfg, "plain-base Root CA")

    resp = client.post(
        f"/ca/{root.id}/intermediate",
        data={
            "name": "plain-child",
            "key_type": "ecdsa-p256",
            "years": 5,
            "permitted_names": "",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    _no_name_constraints(_cert_of(_by_name(cfg, "plain-child Intermediate CA")))


# === Bad input is refused at the route, before anything is written (AC-11) =====


def test_ca_create_rejects_bad_constraint_input_and_writes_no_row(
    client: TestClient, cfg: Config
) -> None:
    """The whole point of AC-11: a rejected ``POST /ca/create`` must leave
    the ``ca_certificates`` table exactly as it found it -- *including* the
    root, which ``create_hierarchy`` inserts and flushes before it ever
    reaches the intermediate (and the constraint). Parsing must happen in
    the route, before that insert, or this test finds an orphan root behind
    an operation the operator was told had failed."""
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    for label, bad_value in _BAD_CONSTRAINT_INPUTS:
        resp = client.post(
            "/ca/create",
            data={
                "name": f"bad-{label}",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "permitted_names": bad_value,
                "excluded_names": "",
                "csrf_token": csrf,
            },
        )
        assert resp.status_code == 400, f"{label}: expected 400, got {resp.status_code}"
        assert _rows(cfg) == [], f"{label}: a row was written by a rejected creation"


def test_ca_create_intermediate_rejects_bad_constraint_input_and_writes_no_row(
    client: TestClient, cfg: Config
) -> None:
    """The same four inputs at the rotation path: 400, and no new row under
    the root -- the row count that matters here is the *total*, since a
    silently-written unconstrained fallback would also leave the count
    looking right for the wrong reason."""
    _setup_superadmin(client)
    _create_ca(client, cfg, "guarded-base")
    root = _by_name(cfg, "guarded-base Root CA")
    csrf = _csrf(client, cfg)
    baseline = len(_rows(cfg))

    for label, bad_value in _BAD_CONSTRAINT_INPUTS:
        resp = client.post(
            f"/ca/{root.id}/intermediate",
            data={
                "name": f"bad-{label}",
                "key_type": "ecdsa-p256",
                "years": 5,
                "permitted_names": bad_value,
                "excluded_names": "",
                "csrf_token": csrf,
            },
        )
        assert resp.status_code == 400, f"{label}: expected 400, got {resp.status_code}"
        assert len(_rows(cfg)) == baseline, f"{label}: a row was written by a rejected creation"


def test_ca_create_route_names_the_offending_line_for_host_bits(
    client: TestClient, cfg: Config
) -> None:
    """FR-3's host-bits rule specifically: ``10.1.2.3/8`` is refused rather
    than silently widened to ``10.0.0.0/8``, and the operator is told
    *which line* was wrong -- not just that the form failed -- so they can
    find and fix it (AC-6)."""
    _setup_superadmin(client)
    resp = client.post(
        "/ca/create",
        data={
            "name": "hostbits",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "permitted_names": "10.1.2.3/8",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 400
    assert "10.1.2.3/8" in resp.text
    assert _rows(cfg) == []


# === /ca shows what each certificate carries (AC-12) ============================


def _seed_alpha_beta(cfg: Config) -> None:
    """A constrained hierarchy and an unconstrained one, seeded directly
    through ``ca_service`` -- this test is about what the page *renders*,
    not about the creation route (already covered above)."""
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        ca_service.create_hierarchy(
            db,
            secrets,
            "alpha",
            constraints=leaf_mod.NameConstraintSpec(permitted_dns=("example.com",)),
        )
        ca_service.create_hierarchy(db, secrets, "beta")
    finally:
        db.close()


def test_ca_page_shows_constraints_per_row(client: TestClient, cfg: Config) -> None:
    """AC-12's positive half: alpha's row renders ``example.com`` as visible
    text, scoped to alpha's own block -- not found by searching the whole
    page, which would pass even if it were rendered on the wrong row."""
    _setup_superadmin(client)
    _seed_alpha_beta(cfg)

    html = client.get("/ca").text
    alpha_int_i = html.index("alpha Intermediate CA")
    beta_root_i = html.index("beta Root CA")
    assert alpha_int_i < beta_root_i
    alpha_block = html[alpha_int_i:beta_root_i]
    assert "example.com" in alpha_block

    expected = leaf_mod.constraints_of(_cert_of(_by_name(cfg, "alpha Intermediate CA")))
    assert expected.permitted_dns == ("example.com",)


def test_ca_page_shows_no_block_for_an_unconstrained_row(client: TestClient, cfg: Config) -> None:
    """AC-12's negative half: beta's row renders no constraints block at
    all. Checked as the absence of the block's own vocabulary
    ("permitted"/"excluded", the words FR-9's UI uses and the words
    ``permitted_names``/``excluded_names`` are built from) inside beta's own
    slice of the page -- not an empty string, which a block rendering ``""``
    for an empty tuple would also satisfy."""
    _setup_superadmin(client)
    _seed_alpha_beta(cfg)

    html = client.get("/ca").text
    beta_int_i = html.index("beta Intermediate CA")
    create_section_i = html.index("Create a new CA")
    assert beta_int_i < create_section_i
    beta_block = html[beta_int_i:create_section_i].lower()
    assert "permitted" not in beta_block
    assert "excluded" not in beta_block

    assert leaf_mod.constraints_of(_cert_of(_by_name(cfg, "beta Intermediate CA"))).is_empty()


def test_ca_page_shows_an_imported_roots_constraints(client: TestClient, cfg: Config) -> None:
    """Out of Scope's own configuration, made visible: cabin never writes
    constraints on a root it generates (FR-1), but an *imported* root may
    carry them -- decided by whoever signed it, not by cabin. AC-12 requires
    that they show up on the root's own row."""
    _setup_superadmin(client)
    root_cert, root_key = _root_with_constraints("Delegated Root CA", ("partner.example",))
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Delegated Intermediate CA", "ecdsa-p256"
    )
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert(intermediate_cert),
            "key_pem": _pem_key(intermediate_key),
            "chain_pem": _pem_cert(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    html = client.get("/ca").text
    root_i = html.index("Delegated Root CA")
    intermediate_i = html.index("Delegated Intermediate CA")
    assert root_i < intermediate_i
    root_block = html[root_i:intermediate_i]
    assert "partner.example" in root_block

    expected = leaf_mod.constraints_of(_cert_of(_by_name(cfg, "Delegated Root CA")))
    assert expected.permitted_dns == ("partner.example",)


# === The import form offers no constraint field (FR-9, AC-10) ==================


def test_import_form_offers_no_constraint_field(client: TestClient, cfg: Config) -> None:
    """An imported certificate is already signed; its constraints were
    decided by whoever signed it, and a field that appeared to change them
    would change nothing. Checked on both templates the import form lives
    on -- the first-run wizard (``ca_setup.html``, before any CA exists) and
    the ongoing list page (``ca_list.html``, once one does) -- since they
    are two copies of the same form and only one of them accidentally
    growing the field would be exactly the kind of copy-paste this file
    exists to catch.
    """
    _setup_superadmin(client)

    wizard_html = client.get("/ca").text
    wizard_import = _fields_of_form(wizard_html, "/ca/import")
    assert wizard_import.found_form is True
    assert "permitted_names" not in wizard_import.field_names
    assert "excluded_names" not in wizard_import.field_names
    # the create form on the very same page DOES grow the fields -- proving
    # the parser is actually scoped to the right form, not failing to find
    # either.
    wizard_create = _fields_of_form(wizard_html, "/ca/create")
    assert "permitted_names" in wizard_create.field_names
    assert "excluded_names" in wizard_create.field_names

    _create_ca(client, cfg, "any")
    list_html = client.get("/ca").text
    list_import = _fields_of_form(list_html, "/ca/import")
    assert list_import.found_form is True
    assert "permitted_names" not in list_import.field_names
    assert "excluded_names" not in list_import.field_names


def test_imported_intermediate_constraint_is_displayed_on_ca(
    client: TestClient, cfg: Config
) -> None:
    """AC-10's display half: an imported *intermediate* (not just an
    imported root, covered separately above) shows its own constraint on
    ``/ca``, read from its certificate. Enforcement of this same
    certificate -- issuing inside the permitted set and refusing outside it,
    at every door -- is already proven by
    ``tests/test_name_constraints_doors.py::test_imported_intermediate_is_enforced_from_its_certificate``;
    repeating it here would only duplicate that file. What is new here is
    that the page shows what that test relies on being true."""
    _setup_superadmin(client)
    root_cert, root_key = create_root("Delegating Root CA", "ecdsa-p256")
    spec = leaf_mod.NameConstraintSpec(permitted_dns=("delegated.example",))
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert,
        root_key,
        "Delegated Partner Intermediate CA",
        "ecdsa-p256",
        name_constraints=leaf_mod.name_constraints_extension(spec),
    )
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert(intermediate_cert),
            "key_pem": _pem_key(intermediate_key),
            "chain_pem": _pem_cert(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    html = client.get("/ca").text
    intermediate_i = html.index("Delegated Partner Intermediate CA")
    block = html[intermediate_i : intermediate_i + 1000]
    assert "delegated.example" in block


# === Audit: ca_created records the constraints that were actually produced =====
# (AC-16, FR-10)


def test_audit_ca_created_records_the_constraints_via_create_route(
    client: TestClient, cfg: Config
) -> None:
    """The detail is read back from the certificate that was actually
    produced, per FR-10 -- not echoed from the form. With a single entry on
    each side there is no ordering ambiguity to hide a swap of the two
    behind."""
    _setup_superadmin(client)
    resp = client.post(
        "/ca/create",
        data={
            "name": "audited",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "permitted_names": "audit.example",
            "excluded_names": "blocked.audit.example",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    intermediate = _by_name(cfg, "audited Intermediate CA")
    event = _ca_created_event(cfg, intermediate.id)
    assert event is not None
    assert event.detail is not None
    assert event.detail["permitted"] == ["audit.example"]
    assert event.detail["excluded"] == ["blocked.audit.example"]


def test_audit_ca_created_records_the_constraints_via_intermediate_route(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "audit-base")
    root = _by_name(cfg, "audit-base Root CA")
    resp = client.post(
        f"/ca/{root.id}/intermediate",
        data={
            "name": "audited-child",
            "key_type": "ecdsa-p256",
            "years": 5,
            "permitted_names": "child.audit.example",
            "excluded_names": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    child = _by_name(cfg, "audited-child Intermediate CA")
    event = _ca_created_event(cfg, child.id)
    assert event is not None
    assert event.detail is not None
    assert event.detail["permitted"] == ["child.audit.example"]
    assert event.detail["excluded"] == []


def test_audit_records_empty_lists_for_an_unconstrained_ca(client: TestClient, cfg: Config) -> None:
    """FR-10: present and empty, not absent -- so the log can tell "this CA
    was created unconstrained" apart from "this cabin version didn't record
    it"."""
    _setup_superadmin(client)
    resp = client.post(
        "/ca/create",
        data={
            "name": "unaudited-plain",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text

    intermediate = _by_name(cfg, "unaudited-plain Intermediate CA")
    event = _ca_created_event(cfg, intermediate.id)
    assert event is not None
    assert event.detail is not None
    assert event.detail["permitted"] == []
    assert event.detail["excluded"] == []
