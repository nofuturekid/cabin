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

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin.app import create_app
from cabin.ca.certs import Certificate, CertStatus, list_certificates, status_counts
from cabin.config import Config
from cabin.sessions import get_session
from cabin.store import create_session_factory


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


def _create_ca(client: TestClient, cfg: Config, intermediate_years: int = 10) -> None:
    assert (
        client.post(
            "/ca/create",
            data={
                "name": "cabin",
                "key_type": "ecdsa-p256",
                "root_years": 20,
                "intermediate_years": intermediate_years,
                "csrf_token": _csrf(client, cfg),
            },
        ).status_code
        == 303
    )


def _insert(
    cfg: Config,
    name: str,
    *,
    expires_in: timedelta,
    revoked: bool = False,
    sans: int = 1,
) -> None:
    """A row straight into the table: the dashboard only reads columns, and
    a real issuance per fixture would buy nothing but runtime."""
    db = _db(cfg)
    # X.509 validity is second-granular and so is every not_after cabin
    # stores; keeping microseconds here would make the fixture compare
    # differently to a real certificate at the exact 30-day boundary.
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        db.add(
            Certificate(
                serial_hex=f"beef{abs(hash(name)) % 10**12:012x}",
                subject_cn=name,
                sans_json=json.dumps([f"DNS:{name}"] * sans),
                profile="server",
                not_before=now.isoformat(),
                not_after=(now + expires_in).isoformat(),
                cert_pem="-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
                key_sealed=None,
                created_at=now.replace(tzinfo=None),
                revoked_at=(now.replace(tzinfo=None) if revoked else None),
                revocation_reason=("superseded" if revoked else None),
            )
        )
        db.commit()
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
