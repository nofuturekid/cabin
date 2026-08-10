"""Web-layer tests for spec 0006: the /certs inventory page and the
per-certificate downloads (FR-1/FR-2/FR-4..FR-6, AC-1..AC-6)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import ca_fixtures
import dom
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.certs import STATUS_FILTERS, get_certificate
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.web import certs_download_ui, certs_ui


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    factory = create_session_factory(cfg.db_url)
    return factory()


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _setup_superadmin(client: TestClient) -> None:
    assert (
        client.post("/setup", data={"username": "alice", "password": "correcthorse1"}).status_code
        == 303
    )


def _last_root_id(cfg: Config) -> int:
    db = _db(cfg)
    try:
        row = db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "root")
            .order_by(CACertificate.id.desc())
        ).first()
        assert row is not None, "no root row exists"
        return row.id
    finally:
        db.close()


def _create_ca(client: TestClient, cfg: Config) -> None:
    """``POST /ca/create`` then ``POST /ca/{root_id}/intermediate`` -- the
    two steps spec 0024 FR-3 split a single create into (FR-11).

    Root and intermediate are given distinct literal names --
    ``create_intermediate_under`` refuses an intermediate whose subject
    collides with its own root's (spec 0024 FR-13), and "cabin" reused for
    both is exactly that collision.
    """
    resp = client.post(
        "/ca/create",
        data={
            "name": "cabin Root CA",
            "key_type": "ecdsa-p256",
            "root_years": 20,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    root_id = _last_root_id(cfg)
    resp = client.post(
        f"/ca/{root_id}/intermediate",
        data={
            "name": "cabin Intermediate CA",
            "key_type": "ecdsa-p256",
            "years": 10,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _create_viewer(client: TestClient, cfg: Config) -> None:
    resp = client.post(
        "/users",
        data={
            "username": "vera",
            "password": "whatever12345",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _issue(
    client: TestClient,
    cfg: Config,
    cn: str = "nas.lan",
    sans: str = "",
    key_type: str = "ecdsa-p256",
) -> int:
    resp = client.post(
        "/certs/issue",
        data={
            "subject_cn": cn,
            "sans": sans or cn,
            "profile": "server",
            "key_type": key_type,
            "days": "90",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _sign_csr(client: TestClient, cfg: Config, cn: str = "app.lan") -> int:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, algorithm=hashes.SHA256())
    )
    resp = client.post(
        "/certs/sign",
        data={
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "profile": "server",
            "days": "60",
            "sans_override": "",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303
    return int(resp.headers["location"].rsplit("/", 1)[1])


def _revoke(client: TestClient, cfg: Config, cert_id: int) -> None:
    resp = client.post(
        f"/certs/{cert_id}/revoke",
        data={
            "reason": "superseded",
            "confirm": "on",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def _serial(cfg: Config, cert_id: int) -> str:
    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        return row.serial_hex
    finally:
        db.close()


def _bulk_insert(cfg: Config, count: int) -> None:
    """Rows straight into the table: the pager only reads columns, and 60
    real issuances would buy nothing but runtime. issuer_id points at
    ca_fixtures' sole stub issuer -- none of the pagination tests calling
    this build a real hierarchy (spec 0017 FR-1)."""
    db = _db(cfg)
    now = datetime.now(UTC)
    try:
        issuer_id = ca_fixtures.sole_active_issuer(db)
        for i in range(count):
            ca_fixtures.insert_cert(
                db,
                issuer_id=issuer_id,
                cn=f"host{i:02d}.lan",
                serial=f"beef{i:012x}",
                with_key=False,
                created_at=(now - timedelta(minutes=i)),
            )
    finally:
        db.close()


# --- FR-1/FR-2, AC-1/AC-2: the inventory page ---------------------------------


def test_list_page_shows_certificates(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _issue(client, cfg, cn="nas.lan", sans="nas.lan\nip:10.0.0.5")
    _issue(client, cfg, cn="printer.lan")

    resp = client.get("/certs")

    assert resp.status_code == 200
    assert "nas.lan" in resp.text
    assert "printer.lan" in resp.text
    assert "10.0.0.5" in resp.text  # SANs are visible without opening a row
    assert 'href="/certs"' in resp.text  # FR-6: nav entry
    assert "tag-valid" in resp.text  # FR-1: expiry status per row
    assert "tag-expired" not in resp.text
    # FR-1: an expiry an operator can read at a glance, not a raw timestamp
    assert " UTC" in resp.text
    assert "+00:00" not in resp.text


def _listed(html: str) -> list[str]:
    """The common names the inventory's own rows carry.

    Read off the rows rather than searched for in the page, because spec 0030
    FR-3 puts the summary of the last mutation on the next page the operator
    sees: `_issue` posts `/certs/issue`, which answers 303 and records exactly
    one audit event, so the following `GET /certs` carries
    `issued certificate for 'printer.lan'` in its flash panel. A page-wide
    `"printer.lan" not in resp.text` then measures the panel and not the
    filter, and would go green again the moment the flash was removed. What
    spec 0006 FR-2 requires is about the rows, so the rows are what is read.
    """
    tree = dom.parse(html)
    tables = tree.find_all(cls="cols-certs")
    assert len(tables) <= 1, f"the inventory renders {len(tables)} certificate tables"
    if not tables:
        return []
    return [node.text() for node in tables[0].find_all(cls="rowlink")]


def test_list_page_filters(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _issue(client, cfg, cn="nas.lan")
    _issue(client, cfg, cn="printer.lan")

    resp = client.get("/certs", params={"q": "nas", "status": "valid"})

    assert resp.status_code == 200
    listed = _listed(resp.text)
    assert "nas.lan" in listed, listed
    assert "printer.lan" not in listed, listed
    # FR-2: the filter is reflected back into the form, so a reload keeps it
    assert 'value="nas"' in resp.text

    empty = client.get("/certs", params={"q": "nas", "status": "expired"})
    assert empty.status_code == 200
    assert _listed(empty.text) == []
    # empty state, and it points an admin at issuance (FR-1)
    assert "No certificates match" in empty.text
    assert "Issue one" in empty.text


def test_list_pagination_links(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _bulk_insert(cfg, 60)

    first = client.get("/certs", params={"q": "host"})
    assert first.status_code == 200
    assert first.text.count("/certs/") >= 50
    assert "host00.lan" in first.text
    assert "host50.lan" not in first.text
    # AC-2: the next-page link carries the active filter along
    assert "q=host" in first.text
    assert "page=2" in first.text

    second = client.get("/certs", params={"q": "host", "page": 2})
    assert "host50.lan" in second.text
    assert "host00.lan" not in second.text

    out_of_range = client.get("/certs", params={"page": 99})
    assert out_of_range.status_code == 200


def test_list_page_absurd_page_is_empty_not_an_error(client: TestClient, cfg: Config) -> None:
    """AC-2: a hand-edited page number is an empty page, never an error --
    including one past the range the database can bind as an OFFSET."""
    _setup_superadmin(client)
    _bulk_insert(cfg, 3)

    resp = client.get("/certs", params={"page": 9223372036854775808})

    assert resp.status_code == 200
    assert "host00.lan" not in resp.text
    assert "No certificates match" in resp.text
    # the pager stays anchored to the real page count, so there is a way back
    assert "page=1" in resp.text


def test_list_requires_login(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)
    client.cookies.clear()

    for path in ("/certs", f"/certs/{cert_id}/download/cert.pem"):
        resp = client.get(path)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


def test_inventory_revoked_badge_and_filter(client: TestClient, cfg: Config) -> None:
    """Spec 0007 FR-7/AC-6: a revoked certificate is visibly revoked in the
    list, and the status filter can single those rows out."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    revoked_id = _issue(client, cfg, cn="gone.lan")
    _issue(client, cfg, cn="live.lan")
    _revoke(client, cfg, revoked_id)

    listing = client.get("/certs")
    assert listing.status_code == 200
    assert "tag-revoked" in listing.text
    # spec 0030 FR-10 re-points this from the `<option value="revoked">` of a
    # `<select>` to the `.seg` link that replaces it. Spec 0006 FR-2's
    # requirement is unchanged -- the filter offers `revoked` and narrowing
    # by it narrows the list -- and only the control has moved.
    assert "revoked" in _seg_labels(listing.text), (
        f"the status filter does not offer `revoked`: {_seg_labels(listing.text)}"
    )

    only_revoked = client.get("/certs", params={"status": "revoked"})
    assert "gone.lan" in only_revoked.text
    assert "live.lan" not in only_revoked.text

    # revocation wins over the time-based states: a revoked certificate is
    # not "valid" just because its notAfter is still in the future
    still_valid = client.get("/certs", params={"status": "valid"})
    assert "live.lan" in still_valid.text
    assert "gone.lan" not in still_valid.text


# === spec 0030 AC-9/AC-10: the filter bar, the pager and the sort that
# does not ship ==============================================================


def _seg(html: str) -> dom.Node:
    tree = dom.parse(html)
    found = tree.find_all(cls="seg")
    assert len(found) == 1, (
        f"the page carries {len(found)} `.seg` elements; FR-10 replaces the status "
        f"`<select>` with exactly one segmented control"
    )
    return found[0]


def _seg_links(html: str) -> list[dom.Node]:
    return [node for node in _seg(html).find_all(tag="a")]


def _seg_labels(html: str) -> list[str]:
    return [node.text() for node in _seg_links(html)]


def test_the_inventory_filter_is_five_links_that_keep_the_search(
    client: TestClient, cfg: Config
) -> None:
    """AC-9, four clauses plus the no-JavaScript half.

    The clause that matters most is 2: each link's `href` is
    `certs_ui._page_url(q, status, 1)`, the function the pager already uses,
    so a filter link and a pager link cannot disagree about what "carry the
    other parameters through" means. A build whose links drop `q` would
    silently discard the operator's search on every click, and no other
    assertion here would see it.

    The second half runs with **no** `HX-Request` header anywhere, because a
    control with an address is the whole point: FR-10's links are fetched by
    htmx second and followed by a browser first.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _issue(client, cfg, cn="nas.lan")
    _issue(client, cfg, cn="printer.lan")

    page = client.get("/certs", params={"q": "nas", "status": "valid", "page": 1})
    assert page.status_code == 200

    links = _seg_links(page.text)
    assert [node.text() for node in links] == [str(value) for value in STATUS_FILTERS], (
        f"the segmented control offers {[node.text() for node in links]}; FR-10 "
        f"renders one link per STATUS_FILTERS entry, in the tuple's order, with the "
        f"labels those `<option>`s carry today"
    )
    for status, link in zip(STATUS_FILTERS, links, strict=True):
        expected = certs_ui._page_url("nas", str(status), 1)
        assert link.get("href") == expected, (
            f"the {status} link points at {link.get('href')!r}, not at "
            f"`_page_url('nas', {str(status)!r}, 1)` = {expected!r}. Every link has "
            f"to carry the active search text through and reset to page 1"
        )
        assert link.get("hx-get") == expected, (
            f"the {status} link's hx-get is {link.get('hx-get')!r}, not its own href"
        )
        assert link.get("hx-select") == "#inventory", link.get("hx-select")
        assert link.get("hx-target") == "#inventory", link.get("hx-target")

    on = [link for link in links if "seg-on" in link.classes]
    assert [link.text() for link in on] == ["valid"], (
        f"`seg-on` is on {[link.text() for link in on]}; exactly one link carries it "
        f"and it is the active status"
    )

    tree = dom.parse(page.text)
    regions = [node for node in tree.walk() if node.get("id") == "inventory"]
    assert len(regions) == 1, f"the page has {len(regions)} elements with id=inventory"
    assert regions[0].find_all(tag="table"), "#inventory does not contain the table"
    assert regions[0].find_all(cls="pager"), "#inventory does not contain the pager"

    forms = [node for node in tree.find_all(tag="form") if node.get("action") == "/certs"]
    assert len(forms) == 1, f"the search form moved: {len(forms)} forms post to /certs"
    assert (forms[0].get("method") or "").lower() == "get"
    hidden = [
        node
        for node in forms[0].find_all(tag="input")
        if node.get("type") == "hidden" and node.get("name") == "status"
    ]
    assert [node.get("value") for node in hidden] == ["valid"], (
        f"the search form carries {[node.get('value') for node in hidden]} as its "
        f"hidden status; submitting a search has to keep the filter the way the "
        f"links keep the search"
    )
    assert forms[0].find_all(tag="button"), "the search box lost its submit"

    # --- and all of it works with no htmx at all
    expired_link = next(link for link in links if link.text() == "expired")
    followed = client.get(expired_link.get("href") or "")
    assert followed.status_code == 200, (
        f"following a filter link answered {followed.status_code}; a `<button>` or a "
        f"`#`-only anchor has no address to follow without JavaScript"
    )
    assert [link.text() for link in _seg_links(followed.text) if "seg-on" in link.classes] == [
        "expired"
    ]
    search = dom.parse(followed.text).find_all(tag="input")
    assert any(node.get("name") == "q" and node.get("value") == "nas" for node in search), (
        "following a filter link lost the search text"
    )

    _bulk_insert(cfg, 51)
    first = client.get("/certs")
    assert first.status_code == 200
    next_link = [
        node
        for node in dom.parse(first.text).find(cls="pager").find_all(tag="a")
        if "Next" in node.text()
    ]
    assert len(next_link) == 1, "the pager offers no next page with 51 certificates"
    second = client.get(next_link[0].get("href") or "")
    assert second.status_code == 200, f"the pager's Next -> {second.status_code}"
    assert dom.parse(second.text).find_all(tag="tbody")[0].find_all(tag="tr"), (
        "the second page rendered no rows"
    )


def test_the_inventory_is_still_newest_first(client: TestClient, cfg: Config) -> None:
    """AC-10: the page's own lead sentence, and a sort that does not ship.

    The design makes `Common name` and `Valid until` sortable. cabin has no
    sort at all -- `list_certificates` orders by `created_at desc, id desc`
    -- and that ordering is the page's own lead sentence. Clause 3 is what
    catches an implementation that quietly honours a `?sort=` the spec
    declined: the sentence would then be false in every state but one.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg)
    for name in ("alpha.lan", "zulu.lan", "mike.lan"):
        _issue(client, cfg, cn=name)

    page = client.get("/certs")
    assert page.status_code == 200
    tree = dom.parse(page.text)
    leads = [node.text() for node in tree.find_all(cls="sub")]
    assert "Everything this CA has issued, newest first." in leads, (
        f"the inventory's lead paragraph is {leads}; wording is out of scope (FR-19) "
        f"and this sentence is what FR-10 declines a sort control to keep true"
    )

    linked_headings = [
        node.text()
        for node in tree.find_all(tag="th")
        if node.tag == "th" and (node.find_all(tag="a") or node.get("href"))
    ]
    assert linked_headings == [], (
        f"these column headings are links: {linked_headings}. Sorting does not ship "
        f"(FR-10) -- it needs a query parameter, a whitelist, a tie-breaker and the "
        f"same ordering in `export_certificates`"
    )

    def names(html: str) -> list[str]:
        body = dom.parse(html).find_all(tag="tbody")
        if not body:
            return []
        return [row.children[0].text() for row in body[0].children if row.tag == "tr"]

    sorted_request = client.get("/certs", params={"sort": "subject_cn", "dir": "asc"})
    assert sorted_request.status_code == 200
    assert names(sorted_request.text) == names(page.text), (
        "`?sort=subject_cn&dir=asc` changed the order of the list, so a sort was "
        "implemented after all and the page's lead sentence is now false"
    )


# --- FR-4, AC-4: PEM downloads -------------------------------------------------


def test_download_cert_pem(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    resp = client.get(f"/certs/{cert_id}/download/cert.pem")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    certs = x509.load_pem_x509_certificates(resp.content)
    assert len(certs) == 1
    assert certs[0].subject.rfc4514_string() == "CN=nas.lan"
    assert resp.headers["content-disposition"] == (
        f'attachment; filename="nas-lan-{_serial(cfg, cert_id)[:8]}.pem"'
    )


def test_download_chain_pem_order(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    resp = client.get(f"/certs/{cert_id}/download/chain.pem")

    assert resp.status_code == 200
    chain = x509.load_pem_x509_certificates(resp.content)
    # AC-4: leaf first, then its issuer, then the root -- the order every
    # server expects when it is handed a chain file.
    assert len(chain) == 3
    cns = [c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value for c in chain]
    assert cns == ["nas.lan", "cabin Intermediate CA", "cabin Root CA"]
    chain[0].verify_directly_issued_by(chain[1])
    chain[1].verify_directly_issued_by(chain[2])


def test_download_key_pem_admin_only(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_viewer(client, cfg)
    cert_id = _issue(client, cfg)

    admin = client.get(f"/certs/{cert_id}/download/key.pem")
    assert admin.status_code == 200
    assert "BEGIN PRIVATE KEY" in admin.text
    key = serialization.load_pem_private_key(admin.content, password=None)
    leaf = x509.load_pem_x509_certificates(
        client.get(f"/certs/{cert_id}/download/cert.pem").content
    )[0]
    assert key.public_key() == leaf.public_key()

    _login(client, "vera")
    assert client.get(f"/certs/{cert_id}/download/key.pem").status_code == 403


def test_download_key_404_for_csr_signed(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _sign_csr(client, cfg)

    # cabin never had this key, so there is nothing to hand out -- and the
    # certificate itself still downloads fine.
    assert client.get(f"/certs/{cert_id}/download/key.pem").status_code == 404
    assert client.get(f"/certs/{cert_id}/download/cert.pem").status_code == 200
    p12 = client.post(
        f"/certs/{cert_id}/download/bundle.p12",
        data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
    )
    assert p12.status_code == 404


def test_download_key_unsealable_is_not_a_500(client: TestClient, cfg: Config) -> None:
    """FR-6: a key sealed with a different master key (or a damaged column)
    is a clean, explained error on every key-bearing path -- the download
    routes included."""
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    db = _db(cfg)
    try:
        row = get_certificate(db, cert_id)
        assert row is not None
        row.key_sealed = "A" * 40  # valid base64url, fails GCM authentication
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/certs/{cert_id}/download/key.pem")
    assert resp.status_code == 409
    assert "could not be decrypted" in resp.text
    p12 = client.post(
        f"/certs/{cert_id}/download/bundle.p12",
        data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
    )
    assert p12.status_code == 409
    # the certificate itself is unaffected
    assert client.get(f"/certs/{cert_id}/download/cert.pem").status_code == 200


# --- FR-4/FR-5, AC-5: the PKCS#12 bundle ---------------------------------------


def test_p12_requires_password_and_csrf(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)
    url = f"/certs/{cert_id}/download/bundle.p12"

    no_csrf = client.post(url, data={"password": "hunter2hunter2"})
    assert no_csrf.status_code == 403

    short = client.post(url, data={"password": "short", "csrf_token": _csrf(client, cfg)})
    assert short.status_code == 400

    missing = client.post(url, data={"csrf_token": _csrf(client, cfg)})
    assert missing.status_code == 400

    ok = client.post(url, data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)})
    assert ok.status_code == 200


def test_p12_roundtrip_loads(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)

    resp = client.post(
        f"/certs/{cert_id}/download/bundle.p12",
        data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
    )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pkcs12")
    # AC-5: what we hand out must actually import somewhere -- key, leaf and
    # a non-empty chain, unlocked by the password that was asked for.
    key, cert, chain = pkcs12.load_key_and_certificates(resp.content, b"hunter2hunter2")
    assert key is not None
    assert cert is not None
    assert cert.subject.rfc4514_string() == "CN=nas.lan"
    assert key.public_key() == cert.public_key()
    assert len(chain) == 2
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(resp.content, b"wrong-password")


def test_p12_ed25519_clean_error(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-5: a key PKCS#12 cannot represent must come back as a clean 400.

    pyca/cryptography can carry Ed25519 in a PKCS#12 bundle, so the live
    Ed25519 path succeeds here; what must never happen is a traceback, so
    the guard is also exercised against a serializer that refuses the key.
    """
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg, cn="ed.lan", key_type="ed25519")
    url = f"/certs/{cert_id}/download/bundle.p12"

    resp = client.post(url, data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)})
    assert resp.status_code == 200
    key, _cert, _chain = pkcs12.load_key_and_certificates(resp.content, b"hunter2hunter2")
    assert key is not None

    # ValueError and TypeError are both ways pyca/cryptography says no, and
    # there is no type check in front of the serializer to catch either.
    for error in (ValueError, TypeError):

        def _refuse(_error: type[Exception] = error, **_kwargs: object) -> bytes:
            raise _error("Key type not supported for PKCS12")

        monkeypatch.setattr(certs_download_ui.pkcs12, "serialize_key_and_certificates", _refuse)
        refused = client.post(
            url, data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)}
        )
        assert refused.status_code == 400
        assert "PKCS#12" in refused.text


# --- FR-4/FR-6, AC-6: headers and what a viewer may see ------------------------


def test_downloads_have_attachment_and_no_store(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    cert_id = _issue(client, cfg)
    short_serial = _serial(cfg, cert_id)[:8]

    responses = [
        client.get(f"/certs/{cert_id}/download/cert.pem"),
        client.get(f"/certs/{cert_id}/download/chain.pem"),
        client.get(f"/certs/{cert_id}/download/key.pem"),
        client.post(
            f"/certs/{cert_id}/download/bundle.p12",
            data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
        ),
    ]

    for resp in responses:
        assert resp.status_code == 200
        # a browser must save these, and no cache may keep the key material
        assert resp.headers["content-disposition"].startswith("attachment; filename=")
        assert f"nas-lan-{short_serial}" in resp.headers["content-disposition"]
        assert resp.headers["cache-control"] == "no-store"


def test_viewer_sees_no_key_controls(client: TestClient, cfg: Config) -> None:
    _setup_superadmin(client)
    _create_ca(client, cfg)
    _create_viewer(client, cfg)
    cert_id = _issue(client, cfg)

    admin_page = client.get(f"/certs/{cert_id}")
    assert "download/key.pem" in admin_page.text
    assert "download/bundle.p12" in admin_page.text

    _login(client, "vera")
    page = client.get(f"/certs/{cert_id}")
    assert page.status_code == 200
    # AC-6: a viewer gets the public halves and no hint of the private ones
    assert "download/cert.pem" in page.text
    assert "download/chain.pem" in page.text
    assert "download/key.pem" not in page.text
    assert "bundle.p12" not in page.text
    assert client.get("/certs").status_code == 200
    assert client.get(f"/certs/{cert_id}/download/chain.pem").status_code == 200
    assert client.get(f"/certs/{cert_id}/download/key.pem").status_code == 403
    assert (
        client.post(
            f"/certs/{cert_id}/download/bundle.p12",
            data={"password": "hunter2hunter2", "csrf_token": _csrf(client, cfg)},
        ).status_code
        == 403
    )
