"""Web-layer tests for spec 0004 FR-5/FR-6 (AC-1, AC-4, AC-5) and spec 0017
FR-14 (AC-11, AC-12, AC-13): the /ca page as a list of hierarchies, per-row
actions, and role/CSRF guards on all of them.

Route contract this file exercises (spec 0017 FR-10/FR-14, no route names
are fixed by the spec text itself, so they are fixed here instead):
  - POST /ca/create                     unchanged: a further hierarchy, not
                                         "the" hierarchy (FR-2 deletes
                                         CAExistsError).
  - POST /ca/import                     unchanged.
  - POST /ca/{root_id}/intermediate     create a further intermediate under
                                         an existing root (FR-3 rotation).
  - POST /ca/{ca_id}/renew              renew a row in place (FR-5).
  - POST /ca/{ca_id}/retire             retire a row (FR-4).
  - GET  /ca/{ca_id}.pem                one certificate, authenticated
                                         (replaces /ca/root.pem).
  - GET  /ca/{issuer_id}/chain.pem      issuer + ancestors, root last,
                                         authenticated (replaces
                                         /ca/chain.pem).
"""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca import service as ca_service
from cabin.ca.service import signing_credentials
from cabin.ca.x509 import create_intermediate, create_root
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.settings import TLS_ISSUER_ID, set_setting
from cabin.store import create_session_factory


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
    factory = create_session_factory(cfg.db_url)
    return factory()


def _setup_superadmin(
    client: TestClient, username: str = "alice", password: str = "correcthorse1"
) -> None:
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303


def _csrf_token_for(cfg: Config, raw_token: str) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, raw_token)
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _csrf(client: TestClient, cfg: Config) -> str:
    return _csrf_token_for(cfg, client.cookies["cabin_session"])


def _create_user_as_superadmin(client: TestClient, cfg: Config, username: str, role: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


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


def _pem_key_str(key: object, *, password: bytes | None = None) -> str:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


def _pem_cert_str(cert: object) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]


def _rows(cfg: Config) -> list[ca_service.CACertificate]:
    db = _db(cfg)
    try:
        rows = ca_service.list_cas(db)
        for row in rows:
            _ = row.id, row.kind, row.name, row.status, row.parent_id  # detach-safe read
        db.expunge_all()
        return rows
    finally:
        db.close()


def _by_name(cfg: Config, name: str) -> ca_service.CACertificate:
    matches = [row for row in _rows(cfg) if row.name == name]
    assert len(matches) == 1, f"expected exactly one row named {name!r}, got {len(matches)}"
    return matches[0]


_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
_TAG_RE = re.compile(r"""<(/?)([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>""")
_CLASS_RE = re.compile(r'class="([^"]*)"')


def _row(html: str, marker: str, *, class_name: str, tag: str = "div") -> str:
    """The full outer HTML of the innermost ``<tag class="class_name">``
    element that contains ``marker``'s first occurrence -- scoped by parsing
    the actual tag nesting, not by slicing a fixed number of characters
    after the marker. A row's markup can grow or shrink for any reason (a
    class added, a hint reworded) without ever moving what a test measures,
    and there is no fixed budget for the next change to silently exceed.
    """
    marker_idx = html.index(marker)
    stack: list[tuple[str, str, int]] = []  # (tag name, attrs text, start offset)
    for m in _TAG_RE.finditer(html):
        closing, name, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if name in _VOID_TAGS or attrs.rstrip().endswith("/"):
            continue  # void or self-closing: no nesting depth to track
        if not closing:
            stack.append((name, attrs, m.start()))
            continue
        if not stack or stack[-1][0] != name:
            continue  # not well-formed at this point; nothing to close
        open_name, open_attrs, open_start = stack.pop()
        if open_start <= marker_idx < m.end():
            classes = _CLASS_RE.search(open_attrs)
            if open_name == tag and classes is not None and class_name in classes.group(1).split():
                return html[open_start : m.end()]
    raise AssertionError(f"no <{tag} class={class_name!r}> element wraps {marker!r}")


# --- FR-2/FR-14: a further hierarchy is ordinary operation, not an error ----


def test_ca_wizard_ui_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)

    # dashboard hints at /ca before any CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" in resp.text

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "Create a new CA" in resp.text
    assert "Import an existing CA" in resp.text

    _create_ca(client, cfg, "cabin")

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "cabin Root CA" in resp.text
    assert "cabin Intermediate CA" in resp.text

    # the dashboard hint is gone once a CA exists
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CA: not set up" not in resp.text

    # FR-2: CAExistsError is deleted -- a second hierarchy is ordinary
    # operation, not a 409. Both coexist afterward, at the DB and on the page.
    _create_ca(client, cfg, "again")

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "cabin Root CA" in resp.text
    assert "again Root CA" in resp.text

    roots = [row for row in _rows(cfg) if row.kind == "root"]
    assert len(roots) == 2
    assert {row.name for row in roots} == {"cabin Root CA", "again Root CA"}


# --- AC-12: /ca groups every row under its root, with its status -----------


def test_ca_page_lists_hierarchies(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "alpha")
    _create_ca(client, cfg, "beta")

    page = client.get("/ca")
    assert page.status_code == 200
    html = page.text

    # every row present
    for name in (
        "alpha Root CA",
        "alpha Intermediate CA",
        "beta Root CA",
        "beta Intermediate CA",
    ):
        assert name in html, name

    # grouped under its own root: alpha's intermediate must appear between
    # alpha's root and beta's root, not after beta's own rows.
    alpha_root_i = html.index("alpha Root CA")
    alpha_int_i = html.index("alpha Intermediate CA")
    beta_root_i = html.index("beta Root CA")
    beta_int_i = html.index("beta Intermediate CA")
    assert alpha_root_i < alpha_int_i < beta_root_i < beta_int_i, (
        alpha_root_i,
        alpha_int_i,
        beta_root_i,
        beta_int_i,
    )

    # retire beta's intermediate directly (bypassing the HTTP action, since
    # this test is about what the page *shows*, not the action itself) and
    # confirm the status is attached to the right row, not sprayed globally.
    db = _db(cfg)
    try:
        beta_intermediate = next(
            r
            for r in ca_service.list_cas(db, kind="intermediate")
            if r.name == "beta Intermediate CA"
        )
        beta_intermediate.status = "retired"
        db.commit()
    finally:
        db.close()

    page = client.get("/ca").text
    beta_window = _row(page, "beta Intermediate CA", class_name="ca-row")
    alpha_window = _row(page, "alpha Intermediate CA", class_name="ca-row")
    assert "retired" in beta_window.lower()
    assert "retired" not in alpha_window.lower()


# --- AC-12: create-intermediate/renew/retire need admin role + CSRF --------


def test_ca_actions_require_admin_and_csrf(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")

    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    admin_csrf = _csrf(client, cfg)

    routes = (
        (f"/ca/{root.id}/intermediate", {"name": "second", "key_type": "ecdsa-p256", "years": 5}),
        (f"/ca/{root.id}/renew", {"years": 25}),
        (f"/ca/{intermediate.id}/retire", {}),
    )

    # admin, missing CSRF -> 403, nothing about the CSRF guard depends on
    # whether the action would otherwise have succeeded
    for path, data in routes:
        resp = client.post(path, data=data)
        assert resp.status_code == 403, path

    # admin, wrong CSRF -> 403
    for path, data in routes:
        resp = client.post(path, data={**data, "csrf_token": "not-the-token"})
        assert resp.status_code == 403, path

    # viewer, correct-for-admin CSRF is not even the viewer's own -> log in
    # as viewer and use its own (valid) session/csrf, still 403 on role
    client.cookies.clear()
    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    viewer_csrf = _csrf(client, cfg)
    for path, data in routes:
        resp = client.post(path, data={**data, "csrf_token": viewer_csrf})
        assert resp.status_code == 403, path

    # sanity: admin_csrf was a real token (used nowhere above on purpose,
    # since every case above must fail before reaching the domain layer)
    assert admin_csrf


# --- AC-13: unavailable actions are not offered, not a 500 button ----------


def test_ca_page_hides_unavailable_actions_for_imported_root(
    client: TestClient, cfg: Config
) -> None:
    """An imported root has no stored private key (key_sealed is NULL by
    design), so it cannot sign a further intermediate and cannot renew
    itself. The page must not offer those actions for it -- the negative
    alone proves nothing, so a generated root's row must still offer both."""
    _setup_superadmin(client)

    # a generated hierarchy: both actions must be offered for its root
    _create_ca(client, cfg, "generated")
    generated_root = _by_name(cfg, "generated Root CA")

    # an imported hierarchy: the imported ROOT (the chain_pem parent) never
    # gets a key_sealed value (ca/service.py's import_hierarchy stores it as
    # None) -- that is the row whose actions must disappear.
    root_cert, root_key = create_root("Imported Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Imported Intermediate CA", "ecdsa-p256"
    )
    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key),
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    imported_root = _by_name(cfg, "Imported Root CA")
    assert imported_root.key_sealed is None  # the premise this test measures

    html = client.get("/ca").text
    generated_window = _row(html, "generated Root CA", class_name="section")
    imported_window = _row(html, "Imported Root CA", class_name="section")

    create_intermediate_url = f"/ca/{generated_root.id}/intermediate"
    renew_url = f"/ca/{generated_root.id}/renew"
    assert create_intermediate_url in generated_window
    assert renew_url in generated_window

    blocked_create_url = f"/ca/{imported_root.id}/intermediate"
    blocked_renew_url = f"/ca/{imported_root.id}/renew"
    assert blocked_create_url not in imported_window
    assert blocked_renew_url not in imported_window


# --- AC-11: root path_length is bounded, and the default is unchanged ------


def test_root_path_length_bounds_rejected(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    for bad in (0, 5):
        resp = client.post(
            "/ca/create",
            data={
                "name": "cabin",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": 10,
                "path_length": bad,
                "csrf_token": csrf,
            },
        )
        assert resp.status_code == 400, bad
    assert _rows(cfg) == []  # no row written by either rejected attempt

    # omitted entirely -> default stays 1
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    root = _by_name(cfg, "cabin Root CA")
    cert = x509.load_pem_x509_certificate(root.cert_pem.encode("ascii"))
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.path_length == 1


# --- AC-5 (spec 0004)/FR-10: PEM downloads ----------------------------------


def test_ca_downloads_pem(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")

    resp = client.get(f"/ca/{root.id}.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=cabin Root CA"

    resp = client.get(f"/ca/{intermediate.id}/chain.pem")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    # nearest issuer first, root last (FR-2 chain_for)
    assert len(chain_certs) == 2
    assert chain_certs[0].subject.rfc4514_string() == "CN=cabin Intermediate CA"
    assert chain_certs[1].subject.rfc4514_string() == "CN=cabin Root CA"


def test_ca_downloads_404_for_unknown_id(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    assert client.get("/ca/999999.pem").status_code == 404
    assert client.get("/ca/999999/chain.pem").status_code == 404


# --- AC-5: viewer read-only ----------------------------------------------------


def test_viewer_readonly_on_ca(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg, "cabin")
    root = _by_name(cfg, "cabin Root CA")
    intermediate = _by_name(cfg, "cabin Intermediate CA")
    _create_user_as_superadmin(client, cfg, "vera", "viewer")
    client.cookies.clear()

    resp = client.post("/login", data={"username": "vera", "password": "whatever12345"})
    assert resp.status_code == 303
    viewer_csrf = _csrf(client, cfg)

    # viewer can GET everything under /ca
    assert client.get("/ca").status_code == 200
    assert client.get(f"/ca/{root.id}.pem").status_code == 200
    assert client.get(f"/ca/{intermediate.id}/chain.pem").status_code == 200

    # but mutating POSTs are 403
    resp = client.post(
        "/ca/create",
        data={
            "name": "x",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": "irrelevant",
            "key_pem": "irrelevant",
            "chain_pem": "irrelevant",
            "csrf_token": viewer_csrf,
        },
    )
    assert resp.status_code == 403


# --- AC-3/FR-3 (spec 0004): import happy path (encrypted key, root key absent) --


def test_ca_import_happy_path_web_flow(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Import Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Import Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"import-passphrase"),
            "key_passphrase": "import-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/ca"

    resp = client.get("/ca")
    assert resp.status_code == 200
    assert "Import Root CA" in resp.text
    assert "Import Intermediate CA" in resp.text

    root = _by_name(cfg, "Import Root CA")
    intermediate = _by_name(cfg, "Import Intermediate CA")
    assert root.key_sealed is None  # FR-3: root key absent on import
    assert intermediate.key_sealed is not None

    db = _db(cfg)
    try:
        secrets = SecretStore.open(cfg.data_dir, None)
        cert, key = signing_credentials(db, secrets, intermediate.id)
        message = b"web-import-roundtrip"
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
        cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))  # no exception
    finally:
        db.close()


# --- AC-5 (spec 0004): import must not leak a chain_pem bundle/preamble ----


def test_ca_import_root_pem_is_clean_despite_bundle_and_preamble(
    client: TestClient, cfg: Config
) -> None:
    """chain_pem may arrive as an openssl-style dump (subject=/issuer= text
    before the PEM block) or as a multi-cert bundle; either way, the root
    download must serve exactly one clean certificate and the chain exactly
    two."""
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Junky Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Junky Intermediate CA", "ecdsa-p256"
    )
    unrelated_cert, _unrelated_key = create_root("Unrelated CA", "ecdsa-p256")
    junky_chain_pem = (
        "subject=CN=Junky Root CA\nissuer=CN=Junky Root CA\n"
        + _pem_cert_str(root_cert)
        + _pem_cert_str(unrelated_cert)
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key),
            "chain_pem": junky_chain_pem,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 303

    root = _by_name(cfg, "Junky Root CA")
    intermediate = _by_name(cfg, "Junky Intermediate CA")

    resp = client.get(f"/ca/{root.id}.pem")
    assert resp.status_code == 200
    assert resp.content.decode("ascii").strip().startswith("-----BEGIN CERTIFICATE-----")
    root_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(root_certs) == 1
    assert root_certs[0].subject.rfc4514_string() == "CN=Junky Root CA"

    resp = client.get(f"/ca/{intermediate.id}/chain.pem")
    assert resp.status_code == 200
    chain_certs = x509.load_pem_x509_certificates(resp.content)
    assert len(chain_certs) == 2


# --- FR-6/FR-14: year-range and key-type validation re-render the wizard ---


def test_ca_create_invalid_years_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 100,  # out of range: max is 50
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "root_years" in resp.text
    assert "Create a new CA" in resp.text  # re-rendered wizard, not a JSON error body

    assert _rows(cfg) == []


def test_ca_create_intermediate_years_exceeds_root_rerenders_error(
    client: TestClient, cfg: Config
) -> None:
    """An intermediate must never be requested to outlive its root."""
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "ecdsa-p256",
            "root_years": 5,
            "intermediate_years": 10,  # exceeds root_years
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "intermediate_years" in resp.text

    assert _rows(cfg) == []


def test_ca_create_invalid_key_type_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin",
            "key_type": "dsa-1024",
            "root_years": 20,
            "intermediate_years": 10,
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "key_type" in resp.text

    assert _rows(cfg) == []


# --- FR-2/AC-3 (spec 0004): import failure path re-renders the wizard ------


def test_ca_import_wrong_passphrase_rerenders_setup_with_error(
    client: TestClient, cfg: Config
) -> None:
    _setup_superadmin(client)
    csrf = _csrf(client, cfg)

    root_cert, root_key = create_root("Wrong Passphrase Root CA", "ecdsa-p256")
    intermediate_cert, intermediate_key = create_intermediate(
        root_cert, root_key, "Wrong Passphrase Intermediate CA", "ecdsa-p256"
    )

    resp = client.post(
        "/ca/import",
        data={
            "cert_pem": _pem_cert_str(intermediate_cert),
            "key_pem": _pem_key_str(intermediate_key, password=b"correct-passphrase"),
            "key_passphrase": "wrong-passphrase",
            "chain_pem": _pem_cert_str(root_cert),
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "decrypt" in resp.text.lower()


# --- spec 0022 FR-17: retiring cabin's own bound TLS issuer is refused -----
#
# FR-17: "Retiring the bound issuer is refused while TLS is on. ... The
# check must cover the cascade: retiring a root also retires its
# intermediates, so it tests the whole set that would be stood down, not
# just the named row. ... With TLS off there is no refusal at all."
#
# Not implemented yet on this branch: verified by hand that with TLS on,
# two active issuers and one bound via ``tls_issuer_id``, POST
# ``/ca/{bound}/retire`` returns 303 and the row is retired. These four
# tests are expected to be RED until the guard lands in
# ``web/ca_ui.py``'s retire route.


def make_tls_config(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)


@pytest.fixture
def tls_cfg(tmp_path: Path) -> Config:
    return make_tls_config(tmp_path)


@pytest.fixture
def tls_client(tls_cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(tls_cfg), follow_redirects=False) as c:
        yield c


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _bind_tls_issuer(cfg: Config, ca_id: int) -> None:
    db = _db(cfg)
    try:
        set_setting(db, TLS_ISSUER_ID, str(ca_id))
        db.commit()
    finally:
        db.close()


def _two_hierarchies(cfg: Config) -> tuple[int, int, int, int]:
    """Two independent, active hierarchies (ids only: root_a,
    intermediate_a, root_b, intermediate_b), created directly through
    ``ca_service`` rather than the HTTP wizard -- what matters here is the
    retire route, not the create flow. Two hierarchies rather than one so
    that retiring either issuer always leaves an active one elsewhere: the
    pre-existing "would leave no active issuer" invariant
    (``ca/service.retire``) never fires on its own, and every retire in the
    tests below can only be blocked -- or not -- by FR-17's bound-issuer
    check, nothing else.
    """
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        alpha = ca_service.create_hierarchy(db, secrets, "alpha")
        beta = ca_service.create_hierarchy(db, secrets, "beta")
        return alpha.root.id, alpha.intermediate.id, beta.root.id, beta.intermediate.id
    finally:
        db.close()


def _status_of(cfg: Config, ca_id: int) -> str:
    db = _db(cfg)
    try:
        return ca_service.get_ca(db, ca_id).status
    finally:
        db.close()


def test_retire_bound_tls_issuer_is_refused(tls_client: TestClient, tls_cfg: Config) -> None:
    """Retiring the issuer bound to cabin's own TLS certificate, directly by
    its own id, must be refused while TLS is on."""
    _setup_superadmin(tls_client)
    _root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(f"/ca/{intermediate_a}/retire", data={"csrf_token": csrf})

    assert resp.status_code == 400, resp.text
    assert _status_of(tls_cfg, intermediate_a) == "active"


def test_retire_root_of_bound_tls_issuer_is_refused_via_cascade(
    tls_client: TestClient, tls_cfg: Config
) -> None:
    """The bound issuer is alpha's INTERMEDIATE; this retires alpha's ROOT,
    whose cascade (``ca_service.retire_targets``) would stand the bound
    intermediate down too. The id named in the URL is never itself the
    bound row, so a guard that only compares the URL's ``ca_id`` against
    the binding -- instead of the whole cascade -- would let this through.
    Refused, and neither row changes status.
    """
    _setup_superadmin(tls_client)
    root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(f"/ca/{root_a}/retire", data={"csrf_token": csrf})

    assert resp.status_code == 400, resp.text
    assert _status_of(tls_cfg, root_a) == "active"
    assert _status_of(tls_cfg, intermediate_a) == "active"


def test_retire_bound_tls_issuer_succeeds_when_tls_is_off(client: TestClient, cfg: Config) -> None:
    """The identical binding, the identical retirement -- but TLS is off, so
    the binding is inert and must not obstruct an installation that does
    not use cabin's own TLS (FR-17: "With TLS off there is no refusal at
    all"). Without this counter-check, a guard that simply refuses every
    retirement regardless of ``config.tls`` would pass the two tests above.
    """
    _setup_superadmin(client)
    _root_a, intermediate_a, _root_b, _intermediate_b = _two_hierarchies(cfg)
    _bind_tls_issuer(cfg, intermediate_a)
    csrf = _csrf(client, cfg)

    resp = client.post(f"/ca/{intermediate_a}/retire", data={"csrf_token": csrf})

    assert resp.status_code == 303, resp.text
    assert _status_of(cfg, intermediate_a) == "retired"


def test_retire_non_bound_issuer_succeeds_while_tls_is_on(
    tls_client: TestClient, tls_cfg: Config
) -> None:
    """TLS is on and an issuer IS bound, but this retires the OTHER active
    issuer -- not the bound one and not its root. FR-17's refusal must not
    spill over onto issuers the binding has nothing to do with."""
    _setup_superadmin(tls_client)
    _root_a, intermediate_a, _root_b, intermediate_b = _two_hierarchies(tls_cfg)
    _bind_tls_issuer(tls_cfg, intermediate_a)
    csrf = _csrf(tls_client, tls_cfg)

    resp = tls_client.post(f"/ca/{intermediate_b}/retire", data={"csrf_token": csrf})

    assert resp.status_code == 303, resp.text
    assert _status_of(tls_cfg, intermediate_b) == "retired"
    assert _status_of(tls_cfg, intermediate_a) == "active"
