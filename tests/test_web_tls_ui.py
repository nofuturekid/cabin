"""Web-layer tests for spec 0022's operator-facing TLS surfaces: FR-14 (the
dashboard/setup banner), FR-16 (the CDP/AIA links on /ca, AC-20) and FR-17
(the issuer binding on /settings).

This file tests Frontend's routes and templates (``web/ca_ui.py``,
``web/ui.py``, ``web/settings_ui.py`` and their templates) -- it does not
implement any of them. Everything here is expected to be RED until that
work lands; see the work split (``cabin-0022-worksplit.md``) for why the
test author and the implementer are different people for this module.

Three hazards this file is built against, all named in the spec and the
work split's mutation-harness warning (this project has twice shipped a UI
test that stayed green while the feature was broken):

* A CDP/AIA URL that merely *appears* on the page proves nothing -- it has
  to be the same string embedded in a certificate that issuer actually
  signed (AC-20), so every URL assertion here compares against a parsed
  ``x509.Certificate``, never against ``crl.distribution_url`` alone.
* A ``<select>`` with nothing marked ``selected`` is not "unset" to a
  browser -- it silently highlights the first ``<option>``, indistinguishable
  from a real choice. The ambiguous-binding tests assert on the *disabled
  placeholder* being the one carrying ``selected``, mirroring the existing
  ``issuer_id`` selector on ``/certs/new`` (``certs_new.html:47``).
* A banner has to say something different in each mode, or it is worse than
  no banner. Every banner test checks the OTHER mode's wording is absent,
  not just that its own wording is present.

Every assertion is anchored to a specific parsed element (an ``<a href=...>``
found by its href, a ``<select>`` found by its ``name``, an element found by
its ``id``) via small ``html.parser.HTMLParser`` subclasses -- the same
pattern ``tests/test_web_certs.py``'s ``_SelectFinder`` already uses in this
project, never a bare ``"..." in html.text`` substring check.

Two settings-table keys and one audit action referenced here
(``tls_issuer_id``, ``CertSource.system``, ``AuditAction.tls_certificate_issued``)
are Crypto's own Phase-2 additions to ``cabin.settings`` / ``cabin.ca.certs`` /
``cabin.audit`` and do not exist on this branch yet. They are therefore never
imported by name at module level (which would break collection of this whole
file) -- the settings key is used as the literal string the spec's Interface
Contract fixes it to, and the audit action is checked as a rendered
``<option>`` value, exactly as spec line 695 says AC-18 must.
"""

import contextlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

import grant_fixtures
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cabin import settings as settings_mod
from cabin.app import create_app
from cabin.ca import certs as certs_service
from cabin.ca import crl as crl_service
from cabin.ca import service as ca_service
from cabin.ca.certs import Certificate
from cabin.ca.leaf import Profile
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.tls import TlsManager, TlsMode

#: Spec 0022 Interface Contract: ``TLS_ISSUER_ID = "tls_issuer_id"``. Used as
#: a literal because ``cabin.settings.TLS_ISSUER_ID`` is Crypto's own
#: Phase-2 addition and does not exist yet -- importing it by name would
#: break collection of this whole file. Assumed to double as the settings
#: form's field/select name, following this codebase's own convention
#: (``base_url`` names both the setting and the form field).
TLS_ISSUER_ID_KEY = "tls_issuer_id"


# --- app/db plumbing, matching tests/test_web_ca.py's style ----------------


def make_config(tmp_path: Path, *, tls: bool = False) -> Config:
    data_dir = tmp_path / "data"
    return Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=tls)


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def client(cfg: Config) -> Iterator[TestClient]:
    with TestClient(create_app(cfg), follow_redirects=False) as c:
        yield c


@contextlib.contextmanager
def _client(cfg: Config, tls: TlsManager | None) -> Iterator[TestClient]:
    """Like the ``client`` fixture, but for tests that need a specific
    ``TlsManager`` (or none) attached -- the Interface Contract's
    ``create_app(config, tls=None)`` parameter (spec 0022, R1)."""
    with TestClient(create_app(cfg, tls), follow_redirects=False) as c:
        yield c


def _db(cfg: Config) -> Session:
    return create_session_factory(cfg.db_url)()


def _secrets(cfg: Config) -> SecretStore:
    return SecretStore.open(cfg.data_dir, cfg.master_passphrase)


def _setup_superadmin(
    client: TestClient, username: str = "alice", password: str = "correcthorse1"
) -> None:
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303, resp.text


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _window(html: str, marker: str, size: int = 600) -> str:
    """The text following ``marker``'s first occurrence -- scopes an
    assertion to the row it belongs to, the same cheap-proxy pattern
    ``test_web_ca.py``/``test_web_dashboard.py`` already use for rows with
    no id of their own."""
    idx = html.index(marker)
    return html[idx : idx + size]


class _SpyTlsManager(TlsManager):
    """A ``TlsManager`` that records every ``ensure_current`` call instead
    of doing anything real, so a settings-page test can tell "the setting
    was saved" apart from "the swap was actually triggered" -- FR-17 says
    changing the binding "triggers ensure_current, so the new chain is
    served immediately"; a route that only writes the setting satisfies
    none of that and must fail here.
    """

    def __init__(self, data_dir: Path, mode: TlsMode | None = None) -> None:
        super().__init__(data_dir)
        self.mode = mode
        self.ensure_current_calls = 0

    def ensure_current(self, db: Session, secrets: SecretStore) -> bool:
        self.ensure_current_calls += 1
        return False


def _plant_system_certificate(db: Session, issuer: ca_service.CACertificate) -> None:
    """A leaf row with ``source == "system"`` -- the shape spec 0022 FR-6's
    stage-2 issuance produces (``CertSource.system``, AC-18), planted
    directly since that enum member is Crypto's own Phase-2 addition and not
    on this branch yet. The ``source`` column has no CHECK constraint (spec
    line 675), so the literal string is exactly what a real ``CertSource.system``
    would write. This is what a "which root is cabin's own certificate from"
    lookup on the dashboard must have something to find.
    """
    now = datetime.now(UTC).replace(microsecond=0)
    row = Certificate(
        issuer_id=issuer.id,
        serial_hex=format(x509.random_serial_number(), "x"),
        subject_cn="cabin",
        sans_json=json.dumps(["DNS:cabin"]),
        profile="server",
        not_before=now.isoformat(),
        not_after=(now + timedelta(days=90)).isoformat(),
        cert_pem="-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
        key_sealed=None,
        created_at=now.replace(tzinfo=None),
        source="system",
    )
    db.add(row)
    db.commit()


def _cdp_url(cert: x509.Certificate) -> str:
    ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert ext[0].full_name is not None
    value = ext[0].full_name[0].value
    assert isinstance(value, str)
    return value


def _aia_url(cert: x509.Certificate) -> str:
    ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    value = next(iter(ext)).access_location.value
    assert isinstance(value, str)
    return value


# --- real DOM parsing, never a bare substring check -------------------------


class _Anchors(HTMLParser):
    """Every ``<a href>`` on the page, paired with its own visible text --
    so a test can assert a URL is rendered as a link whose *text* is that
    same URL (FR-16: "unlabelled crl link with the URL invisible" is
    exactly the defect being fixed), not merely that the URL string appears
    somewhere in the markup.
    """

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


def _anchors(html: str) -> list[tuple[str, str]]:
    parser = _Anchors()
    parser.feed(html)
    return parser.links


def _anchor_text(html: str, href: str) -> str | None:
    """The visible text of the (first) anchor whose href is exactly
    ``href``, or None if no such link exists -- what AC-20's "goes red if
    the URL is rendered but not as a link" needs: this returns None both
    when the href is entirely absent and when it exists only as plain text
    with no anchor around it."""
    for link_href, text in _anchors(html):
        if link_href == href:
            return text
    return None


@dataclass(frozen=True)
class _Option:
    value: str | None
    disabled: bool
    selected: bool


class _SelectOptions(HTMLParser):
    """A ``<select name=...>`` and its ``<option>`` children -- value,
    ``disabled`` and ``selected`` -- so a test can tell "the disabled
    placeholder is selected" apart from "some real issuer is selected"
    (spec 0022 FR-17). Same shape as ``test_web_certs.py``'s
    ``_SelectFinder``, extended with the two boolean flags that ambiguity
    hinges on.
    """

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self.found = False
        self.options: list[_Option] = []
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "select" and attrs_dict.get("name") == self._name:
            self.found = True
            self._inside = True
        elif tag == "option" and self._inside:
            self.options.append(
                _Option(
                    value=attrs_dict.get("value"),
                    disabled="disabled" in attrs_dict,
                    selected="selected" in attrs_dict,
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._inside = False


def _select(html: str, name: str) -> _SelectOptions:
    parser = _SelectOptions(name)
    parser.feed(html)
    return parser


class _ElementById(HTMLParser):
    """The first element carrying ``id=target_id``: its own attributes, its
    flattened text content, and the hrefs of any ``<a>`` nested inside it --
    so a banner's state can be read off the actual DOM structure instead of
    guessed at with a substring search over the whole page.
    """

    def __init__(self, target_id: str) -> None:
        super().__init__()
        self._target_id = target_id
        self.found = False
        self.attrs: dict[str, str | None] = {}
        self.anchor_hrefs: list[str] = []
        self._text: list[str] = []
        self._tag: str | None = None
        self._depth = 0
        self._inside = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if not self._inside and attrs_dict.get("id") == self._target_id:
            self.found = True
            self._inside = True
            self._tag = tag
            self._depth = 1
            self.attrs = attrs_dict
            return
        if self._inside:
            if tag == self._tag:
                self._depth += 1
            if tag == "a":
                href = attrs_dict.get("href")
                if href is not None:
                    self.anchor_hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if self._inside and tag == self._tag:
            self._depth -= 1
            if self._depth == 0:
                self._inside = False

    def handle_data(self, data: str) -> None:
        if self._inside:
            self._text.append(data)

    @property
    def text(self) -> str:
        return "".join(self._text)


def _element(html: str, target_id: str) -> _ElementById:
    parser = _ElementById(target_id)
    parser.feed(html)
    return parser


# --- FR-16/AC-20: the CDP/AIA links on /ca ----------------------------------


def test_ca_page_shows_cdp_and_aia_links_per_issuer(client: TestClient, cfg: Config) -> None:
    """Every active issuer gets its OWN CDP and AIA link, rendered as real,
    clickable anchors -- not the same pair copy-pasted onto every row, and
    not the URL as plain, unlinked text. Two issuers whose links must differ
    is what a hardcoded or first-issuer-only implementation cannot pass."""
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        alpha = ca_service.create_hierarchy(db, secrets, "alpha")
        beta = ca_service.create_hierarchy(db, secrets, "beta")
        settings_mod.set_setting(db, settings_mod.BASE_URL, "https://ca.example.lan")
        alpha_crl = crl_service.distribution_url(db, alpha.intermediate.id)
        alpha_aia = crl_service.ca_issuers_url(db, alpha.intermediate.id)
        beta_crl = crl_service.distribution_url(db, beta.intermediate.id)
        beta_aia = crl_service.ca_issuers_url(db, beta.intermediate.id)
    finally:
        db.close()
    assert alpha_crl is not None and beta_crl is not None
    assert alpha_aia is not None and beta_aia is not None
    assert alpha_crl != beta_crl
    assert alpha_aia != beta_aia

    html = client.get("/ca").text
    assert _anchor_text(html, alpha_crl) == alpha_crl
    assert _anchor_text(html, alpha_aia) == alpha_aia
    assert _anchor_text(html, beta_crl) == beta_crl
    assert _anchor_text(html, beta_aia) == beta_aia


def test_displayed_urls_match_issued_certificate(client: TestClient, cfg: Config) -> None:
    """AC-20's core measurement: the hrefs shown on /ca must equal, string
    for string, the CDP and AIA a real issued leaf carries. Comparing
    against the CERTIFICATE (not against ``crl.distribution_url`` /
    ``crl.ca_issuers_url`` a second time) is what catches the page and
    issuance drifting apart even if each individually looks right -- exactly
    the failure AC-20 is written to make impossible to pass by accident.
    """
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        hierarchy = ca_service.create_hierarchy(db, secrets, "cabin")
        principal = grant_fixtures.granted_admin(db, hierarchy.intermediate.id)
        settings_mod.set_setting(db, settings_mod.BASE_URL, "https://ca.example.lan")
        issued = certs_service.issue_and_store(
            db,
            secrets,
            principal=principal,
            profile=Profile.server,
            subject_cn="leaf.example.lan",
            sans=["DNS:leaf.example.lan"],
            issuer_id=hierarchy.intermediate.id,
        )
        cert = x509.load_pem_x509_certificate(issued.row.cert_pem.encode("ascii"))
        expected_cdp = _cdp_url(cert)
        expected_aia = _aia_url(cert)
    finally:
        db.close()

    html = client.get("/ca").text
    assert _anchor_text(html, expected_cdp) == expected_cdp
    assert _anchor_text(html, expected_aia) == expected_aia


def test_ca_page_urls_absent_without_base_url(client: TestClient, cfg: Config) -> None:
    """Without a base URL there is nothing valid to embed in a certificate,
    so /ca must show neither link -- and the existing "no base URL" note
    (ca_list.html:39) must be what appears in its place, not silence."""
    _setup_superadmin(client)
    db = _db(cfg)
    try:
        hierarchy = ca_service.create_hierarchy(db, _secrets(cfg), "cabin")
    finally:
        db.close()

    html = client.get("/ca").text
    crl_href = f"/crl/{hierarchy.intermediate.id}"
    aia_href = f"/ca/{hierarchy.intermediate.id}.cer"
    hrefs = {href for href, _text in _anchors(html)}
    assert crl_href not in hrefs
    assert aia_href not in hrefs

    note = _window(html, hierarchy.intermediate.name, size=900)
    assert "base URL" in note


# --- FR-17: which issuer signs cabin's own certificate is visible ----------


def test_settings_issuer_select_rendered_only_with_tls(tmp_path: Path) -> None:
    on_cfg = make_config(tmp_path / "on", tls=True)
    off_cfg = make_config(tmp_path / "off", tls=False)

    with _client(on_cfg, TlsManager(on_cfg.data_dir)) as on_client:
        _setup_superadmin(on_client)
        db = _db(on_cfg)
        try:
            ca_service.create_hierarchy(db, _secrets(on_cfg), "cabin")
        finally:
            db.close()
        on_html = on_client.get("/settings").text

    with _client(off_cfg, None) as off_client:
        _setup_superadmin(off_client)
        db = _db(off_cfg)
        try:
            ca_service.create_hierarchy(db, _secrets(off_cfg), "cabin")
        finally:
            db.close()
        off_html = off_client.get("/settings").text

    assert _select(on_html, TLS_ISSUER_ID_KEY).found is True
    assert _select(off_html, TLS_ISSUER_ID_KEY).found is False


def test_settings_shows_current_tls_issuer_binding(tmp_path: Path) -> None:
    """With two active issuers, the select must reflect exactly the one
    that is actually bound -- not the other, and not "nothing" (which would
    be indistinguishable from the ambiguous-state test below)."""
    cfg = make_config(tmp_path, tls=True)
    with _client(cfg, TlsManager(cfg.data_dir)) as tls_client:
        _setup_superadmin(tls_client)
        db = _db(cfg)
        try:
            secrets = _secrets(cfg)
            first = ca_service.create_hierarchy(db, secrets, "first")
            second = ca_service.create_hierarchy(db, secrets, "second")
            settings_mod.set_setting(db, TLS_ISSUER_ID_KEY, str(second.intermediate.id))
        finally:
            db.close()

        select = _select(tls_client.get("/settings").text, TLS_ISSUER_ID_KEY)
        assert select.found is True
        selected = [opt for opt in select.options if opt.selected]
        assert len(selected) == 1, selected
        assert selected[0].value == str(second.intermediate.id)
        assert selected[0].value != str(first.intermediate.id)


def test_settings_ambiguous_tls_issuer_binding_shown_explicitly(tmp_path: Path) -> None:
    """FR-17: several active issuers, nothing bound. A select that lets the
    browser fall back to highlighting its first ``<option>`` would be
    indistinguishable, to an operator, from a real, deliberate choice --
    exactly the "empty field" hazard the spec calls out. cabin must say "not
    decided" explicitly, the same way the existing ``issuer_id`` selector on
    /certs/new already does: a disabled, ``selected`` placeholder with no
    ``value`` (``certs_new.html:47``).
    """
    cfg = make_config(tmp_path, tls=True)
    with _client(cfg, TlsManager(cfg.data_dir)) as tls_client:
        _setup_superadmin(tls_client)
        db = _db(cfg)
        try:
            secrets = _secrets(cfg)
            first = ca_service.create_hierarchy(db, secrets, "first")
            second = ca_service.create_hierarchy(db, secrets, "second")
        finally:
            db.close()

        select = _select(tls_client.get("/settings").text, TLS_ISSUER_ID_KEY)
        assert select.found is True
        real_ids = {str(first.intermediate.id), str(second.intermediate.id)}
        selected = [opt for opt in select.options if opt.selected]
        # Exactly one option selected -- never zero (native "first option
        # wins" ambiguity) and never a real issuer.
        assert len(selected) == 1, selected
        assert selected[0].value not in real_ids
        assert selected[0].value is None
        assert selected[0].disabled is True


def test_settings_changing_tls_issuer_binding_persists_and_triggers_ensure_current(
    tmp_path: Path,
) -> None:
    """ "Changing it takes effect" is two facts, not one: the new choice is
    persisted, AND it triggers ``ensure_current`` so the new chain is served
    immediately (FR-17). A route that only writes the setting -- and never
    calls the seam the Interface Contract names
    (``request.app.state.tls.ensure_current(db, request.app.state.secrets)``)
    -- must fail the second half.
    """
    cfg = make_config(tmp_path, tls=True)
    spy = _SpyTlsManager(cfg.data_dir, mode=TlsMode.self_signed)
    with _client(cfg, spy) as tls_client:
        _setup_superadmin(tls_client)
        db = _db(cfg)
        try:
            secrets = _secrets(cfg)
            first = ca_service.create_hierarchy(db, secrets, "first")
            second = ca_service.create_hierarchy(db, secrets, "second")
        finally:
            db.close()

        # Precondition: unbound, so this test genuinely exercises the
        # unset -> set transition FR-17 cares about, not "still selected
        # from before".
        before = _select(tls_client.get("/settings").text, TLS_ISSUER_ID_KEY)
        before_selected = [opt for opt in before.options if opt.selected]
        assert len(before_selected) == 1
        assert before_selected[0].value is None

        calls_before = spy.ensure_current_calls
        resp = tls_client.post(
            "/settings",
            data={
                "tls_issuer_id": str(second.intermediate.id),
                "csrf_token": _csrf(tls_client, cfg),
            },
        )
        assert resp.status_code == 303, resp.text

        db = _db(cfg)
        try:
            assert settings_mod.get_setting(db, TLS_ISSUER_ID_KEY) == str(second.intermediate.id)
        finally:
            db.close()

        after = _select(tls_client.get("/settings").text, TLS_ISSUER_ID_KEY)
        after_selected = [opt for opt in after.options if opt.selected]
        assert len(after_selected) == 1
        assert after_selected[0].value == str(second.intermediate.id)
        assert after_selected[0].value != str(first.intermediate.id)

        assert spy.ensure_current_calls > calls_before


# --- FR-14: the banner tells the truth about the current mode --------------


def test_dashboard_banner_self_signed(tmp_path: Path) -> None:
    """Rendered even before any CA exists -- stage 1 is exactly when a
    self-signed certificate is what cabin is serving -- and it must not say
    anything the CA-issued banner also says (a banner identical in two
    states is worse than none, per the brief)."""
    cfg = make_config(tmp_path, tls=True)
    manager = TlsManager(cfg.data_dir)
    manager.mode = TlsMode.self_signed
    with _client(cfg, manager) as tls_client:
        _setup_superadmin(tls_client)
        html = tls_client.get("/").text

    banner = _element(html, "tls-banner")
    assert banner.found is True
    assert banner.attrs.get("data-tls-mode") == "self_signed"
    text = banner.text.lower()
    assert "self-signed" in text
    assert "trust store" not in text
    assert not any(href.endswith(".cer") for href in banner.anchor_hrefs)


def test_dashboard_banner_ca_issued_links_root(tmp_path: Path) -> None:
    """Once cabin serves a CA-issued certificate, the banner must say a
    DIFFERENT thing (not the self-signed wording) and its link must resolve
    to the actual root the certificate chains to -- fetched and parsed, not
    just present as a string, so a stale or wrong id cannot pass."""
    cfg = make_config(tmp_path, tls=True)
    manager = TlsManager(cfg.data_dir)
    manager.mode = TlsMode.ca_issued
    with _client(cfg, manager) as tls_client:
        _setup_superadmin(tls_client)
        db = _db(cfg)
        try:
            secrets = _secrets(cfg)
            hierarchy = ca_service.create_hierarchy(db, secrets, "cabin")
            _plant_system_certificate(db, hierarchy.intermediate)
        finally:
            db.close()

        html = tls_client.get("/").text
        banner = _element(html, "tls-banner")
        assert banner.found is True
        assert banner.attrs.get("data-tls-mode") == "ca_issued"
        text = banner.text.lower()
        assert "trust store" in text
        assert "self-signed" not in text

        root_href = f"/ca/{hierarchy.root.id}.cer"
        assert root_href in banner.anchor_hrefs

        cer_resp = tls_client.get(root_href)
        assert cer_resp.status_code == 200
        served_root = x509.load_der_x509_certificate(cer_resp.content)
        expected_root = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))
        assert served_root.fingerprint(hashes.SHA256()) == expected_root.fingerprint(
            hashes.SHA256()
        )


def test_dashboard_banner_absent_without_tls(tmp_path: Path) -> None:
    """``app.state.tls is None`` means TLS is off (Interface Contract, R1):
    the banner element must not exist in the parsed DOM at all -- not an
    empty one, not one hidden by CSS."""
    cfg = make_config(tmp_path, tls=False)
    with _client(cfg, None) as tls_client:
        _setup_superadmin(tls_client)
        html = tls_client.get("/").text
    assert _element(html, "tls-banner").found is False


def test_setup_pages_carry_the_warning_note_only_when_self_signed(tmp_path: Path) -> None:
    """FR-14's first bullet: setup.html and ca_setup.html carry the "this
    warning is expected" note, rendered only while the mode is self-signed
    -- absent once cabin is CA-issued, and absent with TLS off. All three
    states compared in one test, on the same two pages, so a "note always
    shown" or "note never shown" implementation cannot pass either half.
    """

    def _note_presence(subdir: str, mode: TlsMode | None) -> tuple[bool, bool]:
        mode_cfg = make_config(tmp_path / subdir, tls=mode is not None)
        manager = None
        if mode is not None:
            manager = TlsManager(mode_cfg.data_dir)
            manager.mode = mode
        with _client(mode_cfg, manager) as mode_client:
            setup_present = _element(mode_client.get("/setup").text, "tls-setup-note").found
            _setup_superadmin(mode_client)
            ca_setup_present = _element(mode_client.get("/ca").text, "tls-setup-note").found
        return setup_present, ca_setup_present

    assert _note_presence("self-signed", TlsMode.self_signed) == (True, True)
    assert _note_presence("ca-issued", TlsMode.ca_issued) == (False, False)
    assert _note_presence("tls-off", None) == (False, False)


def test_audit_filter_offers_tls_certificate_issued(client: TestClient, cfg: Config) -> None:
    """FR-14's audit event only has a written history if the audit filter
    can find it -- the filter dropdown is generated from ``AuditAction``
    (``audit_ui.py``), so this is the same pattern
    ``test_web_audit.py:387-388`` already uses for ``ca_renewed``/``ca_retired``.
    """
    _setup_superadmin(client)
    page = client.get("/audit")
    assert page.status_code == 200
    assert '<option value="tls_certificate_issued"' in page.text
