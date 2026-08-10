"""Tests for spec 0016: the dashboard.

Two things are being protected here. The counts and the lists they link to
must agree — a dashboard that says "3 expiring" and links to a page showing
two is worse than no dashboard. And the page must not become a way around
authorisation: it aggregates data from pages with different roles attached,
so every section has to keep the role its source page has.
"""

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import ca_fixtures
import dom
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.certs import Certificate, CertStatus, list_certificates, status_counts
from cabin.ca.service import CACertificate
from cabin.ca.x509 import create_root
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.web.ui import _ca_expiry


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db")


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _superadmin(client: TestClient) -> None:
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


def _create_ca(
    client: TestClient,
    cfg: Config,
    name: str = "cabin",
    intermediate_years: int = 10,
    path_length: int = 1,
) -> None:
    """``POST /ca/create`` then ``POST /ca/{root_id}/intermediate`` -- the
    two steps spec 0024 FR-3 split a single create into (FR-11).

    Root and intermediate are given distinct literal names (``name`` with
    " Root CA"/" Intermediate CA" appended by *this test file*, not by
    production) so this file's many name/window-based lookups below keep
    telling the two rows apart.

    ``path_length`` defaults to what the form defaults to (``ca_ui.py:751``),
    which is what every caller here wanted until spec 0030's AC-8 needed a
    root that can cross-sign another: ``cross_path_length_error`` refuses a
    signing root whose ``path_length`` is 1, and the refusal is a 200
    re-render, so a fixture that leaves it at the default builds two roots
    that cannot be cross-signed at all.
    """
    assert (
        client.post(
            "/ca/create",
            data={
                "name": f"{name} Root CA",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "path_length": path_length,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    root_id = _last_root_id(cfg)
    assert (
        client.post(
            f"/ca/{root_id}/intermediate",
            data={
                "name": f"{name} Intermediate CA",
                "key_type": "ecdsa-p256",
                "years": intermediate_years,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )


def _key_pem_bytes(key: object) -> bytes:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_pem_str(cert: object) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]


def _direct_issuer(
    db: Session, secrets: SecretStore, name: str, *, status: str, delta: timedelta
) -> CACertificate:
    """A root + intermediate inserted directly, with the intermediate's
    ``not_after`` set to ``delta`` from now (may be negative, i.e. already
    expired) and ``status`` set explicitly. Local to this file: FR-14's
    "retired only flagged once actually expired" rule needs expiry states
    (already-expired, near-expiry-but-retired) that ca_fixtures does not
    parametrize and create_root/create_intermediate can't express (they only
    take whole years)."""
    root_cert, root_key = create_root(f"{name} Root CA", "ecdsa-p256", years=20)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    key = ec.generate_private_key(ec.SECP256R1())
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
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Intermediate CA")])
        )
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # Fixed, generous backdate so a negative delta (already expired)
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + delta)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski),
            critical=False,
        )
        .sign(root_key, algorithm=hashes.SHA256())
    )

    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=_cert_pem_str(root_cert),
        key_sealed=secrets.seal(_key_pem_bytes(root_key)),
    )
    db.add(root_row)
    db.flush()
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status=status,
        cert_pem=_cert_pem_str(intermediate_cert),
        key_sealed=secrets.seal(_key_pem_bytes(key)),
    )
    db.add(intermediate_row)
    db.commit()
    return intermediate_row


def _window(html: str, marker: str, size: int = 400) -> str:
    """The text following ``marker``'s first occurrence -- scopes an
    assertion to the row that marker belongs to, instead of the whole page
    (spec 0017: a dashboard warning must be attached to the *right* issuer,
    not just present somewhere on the page)."""
    idx = html.index(marker)
    return html[idx : idx + size]


def _insert(
    cfg: Config,
    name: str,
    *,
    expires_in: timedelta,
    revoked: bool = False,
    sans: int = 1,
) -> None:
    """A row straight into the table: the dashboard only reads columns, and
    a real issuance per fixture would buy nothing but runtime. issuer_id
    points at ca_fixtures' sole stub issuer when a test builds no real
    hierarchy of its own (spec 0017 FR-1)."""
    db = _db(cfg)
    # X.509 validity is second-granular and so is every not_after cabin
    # stores; keeping microseconds here would make the fixture compare
    # differently to a real certificate at the exact 30-day boundary.
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        ca_fixtures.insert_cert(
            db,
            issuer_id=ca_fixtures.sole_active_issuer(db),
            cn=name,
            sans=[f"DNS:{name}"] * sans,
            serial=f"beef{abs(hash(name)) % 10**12:012x}",
            created_at=now,
            expires_in=expires_in,
            revoked_at=(now if revoked else None),
        )
    finally:
        db.close()


def _spread(cfg: Config) -> None:
    """The AC-1 fixture: one of each state."""
    _insert(cfg, "soon.lan", expires_in=timedelta(days=5))
    _insert(cfg, "later.lan", expires_in=timedelta(days=20))
    _insert(cfg, "fine.lan", expires_in=timedelta(days=90))
    _insert(cfg, "gone.lan", expires_in=timedelta(days=-1))
    _insert(cfg, "dead.lan", expires_in=timedelta(days=200), revoked=True)


# --- FR-3 / AC-9: the counts ---------------------------------------------------


def test_status_counts_agree_with_list_certificates(client: TestClient, cfg: Config) -> None:
    """A count that disagrees with the page it links to is a lie.

    Takes ``client`` for the migrated schema its startup creates, not for HTTP.
    """
    _spread(cfg)
    now = datetime.now(UTC)
    db = _db(cfg)
    try:
        counts = status_counts(db, now)
        for status in (
            CertStatus.valid,
            CertStatus.expiring,
            CertStatus.expired,
            CertStatus.revoked,
        ):
            _, total = list_certificates(db, q="", status=status, page=1, per_page=1, now=now)
            assert counts[status] == total, status
        assert counts == {"valid": 1, "expiring": 2, "expired": 1, "revoked": 1}
    finally:
        db.close()


def test_status_counts_boundary_30d(client: TestClient, cfg: Config) -> None:
    """AC-9: exactly 30 days out is expiring, a second more is valid — the
    same boundary `certificate_status` draws."""
    _insert(cfg, "exactly.lan", expires_in=timedelta(days=30))
    _insert(cfg, "justover.lan", expires_in=timedelta(days=30, seconds=30))
    db = _db(cfg)
    try:
        counts = status_counts(db, datetime.now(UTC))
        assert counts["expiring"] == 1
        assert counts["valid"] == 1
    finally:
        db.close()


# --- FR-2 / AC-1..AC-3: expiring soon ------------------------------------------


def test_dashboard_lists_expiring_soonest_first(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    _spread(cfg)

    page = client.get("/")
    assert page.status_code == 200
    body = page.text
    assert "soon.lan" in body and "later.lan" in body
    assert body.index("soon.lan") < body.index("later.lan"), "not soonest first"
    # Only the expiring ones belong in that table.
    assert "fine.lan" not in body
    assert "gone.lan" not in body


def test_dashboard_counts_match_inventory(client: TestClient, cfg: Config) -> None:
    """AC-2: each count links to the inventory filtered to it, and the
    inventory then shows exactly that many rows."""
    _superadmin(client)
    _create_ca(client, cfg)
    _spread(cfg)

    page = client.get("/").text
    expected = {"valid": 1, "expiring": 2, "expired": 1, "revoked": 1}
    for status, count in expected.items():
        assert f'href="/certs?status={status}"' in page, status
        listing = client.get("/certs", params={"status": status}).text
        assert f"{count} certificate(s)" in listing, status


def test_dashboard_caps_expiring_list_at_ten(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    for i in range(12):
        _insert(cfg, f"host{i:02d}.lan", expires_in=timedelta(days=i + 1))

    page = client.get("/").text
    shown = [f"host{i:02d}.lan" for i in range(12) if f"host{i:02d}.lan" in page]
    assert len(shown) == 10, shown
    assert 'href="/certs?status=expiring"' in page


def test_dashboard_empty_expiring_says_so(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    _insert(cfg, "fine.lan", expires_in=timedelta(days=200))

    page = client.get("/").text
    assert "Nothing expires in the next 30 days" in page


# --- FR-4 / AC-4: the CA's own expiry ------------------------------------------


def test_dashboard_ca_expiry_is_shown(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    page = client.get("/").text
    assert "Intermediate" in page
    assert "Root" in page


def test_dashboard_ca_expiry_warns_within_a_year(client: TestClient, cfg: Config) -> None:
    """AC-4: replacing an intermediate is not a five-minute job, so the
    warning has to come a long time before the expiry does."""
    _superadmin(client)
    _create_ca(client, cfg, intermediate_years=1)
    page = client.get("/").text
    assert "tag-warn" in page


def test_dashboard_ca_far_out_is_not_warned(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg, intermediate_years=10)
    page = client.get("/").text
    # No CA warning; the only tags on a quiet dashboard are neutral ones.
    assert "tag-warn" not in page


# --- spec 0017 FR-14: warnings are per issuer, not "the" CA ------------------


def test_dashboard_warns_per_issuer(client: TestClient, cfg: Config) -> None:
    """CA_WARN_DAYS applies per active issuer. The row belonging to the
    issuer set up to be near expiry must carry the warning treatment, and
    the row belonging to a healthy issuer must not -- a test that can't
    distinguish the two issuers proves nothing."""
    _superadmin(client)
    _create_ca(client, cfg, name="warn", intermediate_years=1)
    _create_ca(client, cfg, name="healthy", intermediate_years=10)

    page = client.get("/").text
    warn_window = _window(page, "warn Intermediate CA")
    healthy_window = _window(page, "healthy Intermediate CA")

    assert "tag-warn" in warn_window
    assert "tag-warn" not in healthy_window


def test_dashboard_retired_issuer_only_flagged_when_expired(
    client: TestClient, cfg: Config
) -> None:
    """FR-14: a retired row within the warn window is not flagged -- its
    remaining job is signing its CRL, and a year's notice on something
    already stood down is noise. The same row once actually expired IS
    flagged. Both halves, on two isolated rows so neither result depends on
    the other."""
    _superadmin(client)
    _create_ca(client, cfg)  # an active hierarchy, so the dashboard renders
    secrets = SecretStore.open(cfg.data_dir, None)
    db = _db(cfg)
    try:
        _direct_issuer(db, secrets, "near-retired", status="retired", delta=timedelta(days=5))
        _direct_issuer(db, secrets, "expired-retired", status="retired", delta=-timedelta(hours=1))
    finally:
        db.close()

    page = client.get("/").text
    near_window = _window(page, "near-retired Intermediate CA")
    expired_window = _window(page, "expired-retired Intermediate CA")

    assert "tag-warn" not in near_window
    assert "tag-bad" not in near_window
    assert "tag-bad" in expired_window


# === spec 0030 AC-8: the authorities block is the grouped list ============


def _authorities_rows(html: str) -> list[dom.Node]:
    """The `<tr>` elements of the dashboard's authorities list.

    Scoped by the `cols-authorities` class the table carries (spec 0030
    FR-17), not by splitting the page on the heading: FR-8 keeps the heading
    (`The CA itself` is not in FR-19's exception table) but replaces the flat
    table under it, and a window measured in characters cannot tell a
    grouped list from a flat one.
    """
    tree = dom.parse(html)
    tables = [node for node in tree.find_all(tag="table") if "cols-authorities" in node.classes]
    assert len(tables) == 1, (
        f"the dashboard carries {len(tables)} table(s) with `cols-authorities`; "
        f"FR-8/FR-17 give the authorities block exactly one"
    )
    bodies = tables[0].find_all(tag="tbody")
    assert len(bodies) == 1
    return [node for node in bodies[0].children if node.tag == "tr"]


def test_the_dashboard_authorities_block_is_the_grouped_list(
    client: TestClient, cfg: Config
) -> None:
    """AC-8, four clauses.

    Clause 1 is spec 0017 FR-14's requirement measured against the database
    rather than against a literal: one entry per `ca_certificates` row, so
    that no CA certificate's expiry warning can go missing. It is also what
    catches the shape this change would take if the block were built by
    filtering for `kind == "root"` and hanging children off it -- a cross
    row has no root to hang under and would silently disappear.

    Clause 4 is the other half: the grouped list is *reused* (spec 0028
    FR-5's component), not written a second time under new names, so each of
    its class names has exactly one rule block in `cabin.css`.
    """
    _superadmin(client)
    #: alpha is the signing root, so it needs `path_length=2`: a root at the
    #: form's default cannot cross-sign anything (`ca_x509
    #: .cross_path_length_error`), and the refusal is a 200 re-render rather
    #: than an exception. Without it this fixture builds two roots that cannot
    #: be cross-signed, no cross row exists, and clause 1 -- the row a grouped
    #: list built by filtering for roots would drop -- has nothing to measure.
    _create_ca(client, cfg, name="alpha", path_length=2)
    _create_ca(client, cfg, name="beta")
    alpha_root = _root_id_named(cfg, "alpha Root CA")
    beta_root = _root_id_named(cfg, "beta Root CA")
    assert (
        client.post(
            f"/ca/{alpha_root}/intermediate",
            data={
                "name": "alpha Second Intermediate CA",
                "key_type": "ecdsa-p256",
                "years": 10,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    cross = client.post(
        f"/ca/{beta_root}/cross-sign",
        data={"signing_root_id": alpha_root, "years": 5, "csrf_token": _csrf(client, cfg)},
    )
    assert cross.status_code == 303, cross.text

    page = client.get("/")
    assert page.status_code == 200
    rows = _authorities_rows(page.text)

    db = _db(cfg)
    try:
        ca_rows = list(db.scalars(select(CACertificate).order_by(CACertificate.id)))
        expected_expiry = {
            row.id: _ca_expiry(row, datetime.now(UTC))["not_after"] for row in ca_rows
        }
        kinds = {row.id: row.kind for row in ca_rows}
        names = {row.name: row.id for row in ca_rows}
    finally:
        db.close()

    assert len(rows) == len(ca_rows), (
        f"the authorities block draws {len(rows)} rows and `ca_certificates` holds "
        f"{len(ca_rows)}. Spec 0017 FR-14 makes it one entry per row so that no CA "
        f"certificate's expiry warning can go missing, and a cross row is the one "
        f"a grouped list built by filtering for roots would drop"
    )

    # clause 2: roots at root level, their intermediates immediately under
    # them, and the cross row at root level with its own kind tag
    seen_root: str | None = None
    for index, row in enumerate(rows):
        kind_classes = {"row-root", "row-child"} & row.classes
        assert len(kind_classes) == 1, (
            f"row {index} carries {sorted(row.classes)}; spec 0028 FR-5's grouped "
            f"list marks every row either `row-root` or `row-child`"
        )
        label = row.children[0].text()
        if "row-root" in kind_classes:
            seen_root = label
        else:
            assert seen_root is not None, f"row {index} is a child before any root"

    #: A row is found by its name **and** its kind, not by its name alone. A
    #: cross row's name equals its subject root's -- that is the whole reason
    #: spec 0028 FR-5 refuses to indent one -- so a name lookup finds two rows
    #: for `beta Root CA`, silently takes the first, and checks the root twice
    #: while never looking at the cross row this criterion exists for. The kind
    #: tag in the name cell is what tells them apart, and FR-9 requires it to
    #: be there.
    def kind_tag(row: dom.Node) -> str:
        tags = [node.text() for node in row.children[0].find_all(cls="tag")]
        assert len(tags) == 1, f"the name cell carries {tags}; FR-9 gives it one kind tag"
        return tags[0]

    for name, row_id in names.items():
        matching = [
            row for row in rows if name in row.children[0].text() and kind_tag(row) == kinds[row_id]
        ]
        assert len(matching) == 1, (
            f"the authorities block draws {len(matching)} rows named {name!r} of kind "
            f"{kinds[row_id]!r}: {[row.children[0].text() for row in rows]}"
        )
        row = matching[0]
        expected_kind = "row-child" if kinds[row_id] == "intermediate" else "row-root"
        assert expected_kind in row.classes, (
            f"{name} ({kinds[row_id]}) is a {sorted(row.classes)} row, not {expected_kind}. "
            f"Spec 0028 FR-5 refuses to indent a cross row under a root, because a "
            f"cross row's name equals its subject root's"
        )
        # clause 3: the expiry the row prints is the expiry `_ca_expiry` computes
        assert expected_expiry[row_id] in row.text(), (
            f"{name}'s row prints {row.text()!r}, which does not carry "
            f"{expected_expiry[row_id]!r} -- the number the dashboard prints for a "
            f"row is the number it prints today"
        )

    # clause 4: reused, not re-implemented.
    #
    # Corrected: "exactly one rule block per name" is not satisfiable and was
    # not satisfiable at this spec's base commit either. Spec 0028's grouped
    # list ships a base rule *and* descendant rules for the same names --
    # `.row-root` and `.row-root td:first-child a`, `.row-child` and
    # `.row-child td:first-child`, `.rowlink::after` beside the two
    # `tr:has(.rowlink)` rules -- so the component this criterion asks to be
    # reused fails a count of one by construction, and a build that satisfied
    # the count would have had to delete part of it.
    #
    # What FR-9 means by "no second rule is written for any of them" is that
    # *this spec* writes none, so that is what is measured: the selectors
    # naming each of the six are compared against the set the stylesheet
    # carried at the base commit. A grouped list re-implemented here under
    # these names adds a selector and fails; one re-implemented under new
    # names is caught by clauses 1 to 3, which read the rendered rows.
    #
    # That set is recorded in `tests/data/`, not resolved out of git. Reading
    # it with `git show` is what made this test fail on CI -- the base commit
    # is on a feature branch and the runner's checkout is shallow -- but the
    # snapshot is also the more honest instrument, because the claim outlives
    # the commit: *nobody* may write a second rule for these six names, this
    # spec or any later one, and a comparison against a vanishing object could
    # only ever have said it about one diff.
    #
    # `0030_routes.json` next to it is the same pattern for the same reason.
    # Both are regenerated by a deliberate act, and a diff in either is a
    # decision rather than an accident.
    css = CSS.read_text()
    recorded = json.loads(GROUPED_LIST_SELECTORS.read_text())["selectors"]
    assert set(recorded) == {
        "row-root",
        "row-child",
        "tree",
        "state-active",
        "state-retired",
        "rowlink",
    }, sorted(recorded)
    for name, before in recorded.items():
        pattern = rf"\.{name}(?![\w-])"
        blocks = [selector for selector, _body in _css_rules(css) if re.search(pattern, selector)]
        assert before, (
            f".{name} is recorded with no rule at all, so the comparison below would "
            f"pass on a stylesheet that never had spec 0028's grouped list in it"
        )
        assert blocks == before, (
            f".{name} is the subject of {blocks} in cabin.css and of {before} in the "
            f"recorded baseline. FR-9 reuses spec 0028's grouped list; a rule written "
            f"for one of its names is the component written twice"
        )


def _root_id_named(cfg: Config, name: str) -> int:
    db = _db(cfg)
    try:
        return int(db.scalars(select(CACertificate).where(CACertificate.name == name)).one().id)
    finally:
        db.close()


def _css_rules(text: str) -> list[tuple[str, str]]:
    """Every rule as `(selector, body)`, at-rules flattened."""
    rules: list[tuple[str, str]] = []

    def walk(chunk: str) -> None:
        depth = 0
        start = 0
        selector = ""
        body_start = 0
        for index, char in enumerate(chunk):
            if char == "{":
                if depth == 0:
                    selector = chunk[start:index].strip()
                    body_start = index + 1
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    body = chunk[body_start:index]
                    if selector.startswith("@"):
                        walk(body)
                    else:
                        rules.append((selector, body))
                    start = index + 1

    walk(re.sub(r"/\*.*?\*/", "", text, flags=re.S))
    return rules


def test_dashboard_lists_one_entry_per_ca_row(client: TestClient, cfg: Config) -> None:
    """FR-14: the dashboard used to show the pair [intermediate, root] of
    "the" hierarchy; now it must show one entry per ca_certificates row --
    all four rows of two hierarchies, not just the first hierarchy's two."""
    _superadmin(client)
    _create_ca(client, cfg, name="alpha")
    _create_ca(client, cfg, name="beta")

    # spec 0030 FR-8/FR-9: the flat `The CA itself` table becomes the grouped
    # list. The requirement is unchanged -- spec 0016 FR-4 and spec 0017
    # FR-14: one entry per `ca_certificates` row -- and only the element it is
    # read out of has moved.
    page = client.get("/").text
    section = " ".join(row.text() for row in _authorities_rows(page))
    for name in (
        "alpha Root CA",
        "alpha Intermediate CA",
        "beta Root CA",
        "beta Intermediate CA",
    ):
        assert name in section, name


# --- FR-5 / AC-5: revocation ---------------------------------------------------


def test_dashboard_crl_absent_says_so(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    assert "No CRL has been generated yet" in client.get("/").text


def test_dashboard_crl_stale_is_danger(client: TestClient, cfg: Config) -> None:
    """A CRL past its nextUpdate is the difference between clients seeing a
    revocation and clients silently trusting a revoked certificate."""
    _superadmin(client)
    _create_ca(client, cfg)
    _insert(cfg, "dead.lan", expires_in=timedelta(days=100))
    # Revoking generates a CRL; age it past its 7-day validity.
    db = _db(cfg)
    try:
        row = db.query(Certificate).filter(Certificate.subject_cn == "dead.lan").one()
        cert_id = row.id
    finally:
        db.close()
    assert (
        client.post(
            f"/certs/{cert_id}/revoke",
            data={
                "reason": "superseded",
                "confirm": "on",
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )
    assert "tag-bad" not in client.get("/").text.split("Revocation")[-1][:600]

    from cabin.ca.crl import CRLState

    db = _db(cfg)
    try:
        state = db.query(CRLState).one()
        state.generated_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=8)
        db.commit()
    finally:
        db.close()
    assert "stale" in client.get("/").text


# --- FR-6 / AC-6, AC-7: services, and who may see them -------------------------


def test_dashboard_hides_services_from_viewer(client: TestClient, cfg: Config) -> None:
    """AC-6: the dashboard aggregates pages with different roles attached. It
    must keep those roles, or it becomes a way around them."""
    _superadmin(client)
    _create_ca(client, cfg)
    _insert(cfg, "soon.lan", expires_in=timedelta(days=5))
    client.post(
        "/users",
        data={
            "username": "vera",
            "password": "correcthorse1x",
            "role": "viewer",
            "csrf_token": _csrf(client, cfg),
        },
    )

    admin_page = client.get("/").text
    assert "Services" in admin_page

    client.post("/logout", data={"csrf_token": _csrf(client, cfg)})
    client.post("/login", data={"username": "vera", "password": "correcthorse1x"})
    viewer_page = client.get("/").text
    assert "Services" not in viewer_page
    assert "ACME" not in viewer_page
    assert "MCP" not in viewer_page
    # ...but a viewer still gets the part of the page that is theirs to see.
    assert "soon.lan" in viewer_page


def test_settings_refuses_acme_without_base_url_so_dashboard_cannot_show_it(
    client: TestClient, cfg: Config
) -> None:
    """AC-7: the dashboard has no "enabled but unreachable" warning because
    the state cannot exist — spec 0010 FR-5 refuses to store it. Asserted
    here so that, if that gate is ever relaxed, this test says the dashboard
    now needs the warning back.
    """
    _superadmin(client)
    _create_ca(client, cfg)

    rejected = client.post(
        "/settings",
        data={"acme_enabled": "on", "base_url": "", "csrf_token": _csrf(client, cfg)},
    )
    assert rejected.status_code == 400
    assert "set a base URL before enabling the ACME server" in rejected.text

    accepted = client.post(
        "/settings",
        data={
            "acme_enabled": "on",
            "base_url": "https://ca.example.org",
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert accepted.status_code == 303
    page = client.get("/").text
    assert "enabled" in page
    assert "https://ca.example.org" in page


# --- FR-7, AC-8 ----------------------------------------------------------------


def test_dashboard_recent_activity_lists_five(client: TestClient, cfg: Config) -> None:
    _superadmin(client)
    _create_ca(client, cfg)
    page = client.get("/").text
    assert "Recent activity" in page
    assert 'href="/audit"' in page
    assert "ca_created" in page


def test_dashboard_without_ca_shows_setup_prompt(client: TestClient, cfg: Config) -> None:
    """AC-8: before there is a CA there is nothing to summarise."""
    _superadmin(client)
    page = client.get("/")
    assert page.status_code == 200
    assert "CA: not set up" in page.text
    assert "Expiring soon" not in page.text


#: Tags that carry a fact rather than an alarm — where a certificate came
#: from, which role someone has. Deliberately unstyled; everything else needs
#: a rule or it renders grey.
NEUTRAL_TAGS = {
    "tag-source-ui",
    "tag-source-acme",
    "tag-source-api",
    "tag-source-mcp",
    "tag-superadmin",
    "tag-admin",
    "tag-viewer",
    "tag-user",
    "tag-system",
    "tag-token",
    "tag-acme",
    "tag-unused",
}

CSS = Path(__file__).resolve().parents[1] / "src/cabin/web/static/cabin.css"

#: The selectors naming spec 0028's grouped-list classes, as `cabin.css`
#: carried them at spec 0030's base commit. Recorded rather than resolved out
#: of git; the file says why, and clause 4 of
#: `test_the_dashboard_authorities_block_is_the_grouped_list` says what it is
#: for. Regenerated only by a deliberate act.
GROUPED_LIST_SELECTORS = (
    Path(__file__).resolve().parent / "data" / "0030_grouped_list_selectors.json"
)


def test_every_rendered_tag_class_has_a_rule(client: TestClient, cfg: Config) -> None:
    """A tag class with no rule in the stylesheet renders grey — the warning
    is emitted, satisfies an `in page` assertion, and is invisible.

    That is how "expires in 364 days" first shipped colourless: spec 0015
    renamed the rules to value names while this view still emitted role
    names. So the fixture below deliberately drives every alarm state —
    expiring, revoked, a CA inside its warning year, a stale CRL — because a
    test that never reaches a state cannot check its colour.
    """
    _superadmin(client)
    _create_ca(client, cfg, intermediate_years=1)  # -> tag-warn
    _insert(cfg, "soon.lan", expires_in=timedelta(days=3))  # -> tag-expiring
    _insert(cfg, "gone.lan", expires_in=timedelta(days=-1))  # -> tag-expired
    _insert(cfg, "dead.lan", expires_in=timedelta(days=100))
    db = _db(cfg)
    try:
        cert_id = db.query(Certificate).filter(Certificate.subject_cn == "dead.lan").one().id
    finally:
        db.close()
    client.post(
        f"/certs/{cert_id}/revoke",
        data={"reason": "superseded", "confirm": "on", "csrf_token": _csrf(client, cfg)},
    )
    from cabin.ca.crl import CRLState

    db = _db(cfg)
    try:  # age the CRL past its validity -> tag-bad
        db.query(CRLState).one().generated_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
            days=8
        )
        db.commit()
    finally:
        db.close()

    emitted: set[str] = set()
    for path in ("/", "/certs", f"/certs/{cert_id}", "/users", "/audit", "/tokens"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        for classes in re.findall(r'class="tag ([^"]*)"', resp.text):
            emitted.update(c for c in classes.split() if c.startswith("tag-"))

    # The fixture must actually have produced the states, or this proves nothing.
    assert {"tag-warn", "tag-bad", "tag-expiring", "tag-revoked"} <= emitted, emitted

    defined = set(re.findall(r"\.(tag-[\w-]+)", CSS.read_text()))
    unstyled = emitted - defined - NEUTRAL_TAGS
    assert unstyled == set(), f"emitted with no rule and not declared neutral: {unstyled}"
