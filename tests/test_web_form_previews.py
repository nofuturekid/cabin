"""Spec 0029: the five form pages take the design's two-column shape, and
htmx is wired for the first time in this project.

**This branch is red by design, and every test in it currently fails on a
weak oracle.** None of the four preview routes exists, so eleven of the
thirteen tests here die on a 404 -- "the route is missing" and "the route
answers the wrong thing" are indistinguishable until one exists. That is
unavoidable and it is stated rather than glossed. What each test does carry
is an oracle that bites *after* the route exists and that a stub cannot
satisfy: a certificate actually issued from the same inputs (AC-3, AC-4), a
recording spy's call list (AC-3, AC-5), a fragment found verbatim inside the
page (AC-7), the guard of the mutation beside it (AC-6), a browser probe
(AC-15).

Three clauses stay weak permanently and are worth knowing about:
ADR-0003's five rejected options are matched as prose in
`test_web_design_shell` (it can tell that an option was named, not that it
was argued); AC-11's tone is read as a class token, and only AC-15's
contrast run says the two tones can be told apart on screen; and AC-1's
`assert targets` is a guard against a build with no htmx rather than a
measurement of one.

The `_spy` helper and every parser in this file are counter-checked
against synthetic input and against the *mutations* the previews mirror --
`audit.record`, `signing_credentials`, `_unseal_signing_key` and
`certs._store` all fire for `POST /ca/create` and `POST /certs/issue`, so
the zeroes AC-5 asserts are measurements and not dead instruments.

Three things are worth knowing before reading this file.

**The panel is compared with the signer, never with the checker twice.**
AC-3 and AC-4 both issue a real certificate from the same inputs and compare
the rendered panel with what was stored. A criterion that called
`clamp_validity` to check `clamp_validity`, or `check_name_constraints` to
check `check_name_constraints`, would pass on the one defect an extraction
actually has -- both call sites wrong in the same way.

**AC-1's ten-times-shorter clause is not applied to the two `hx-get`
targets, and cannot be.** FR-2 clause 2 says every non-preview `hx-` target
is a URL that exists for the no-JavaScript path first, fetched by htmx
second, "with `hx-select` naming the region to take out of it" -- the
narrowing happens in the browser, so `GET /ca/{id}?add=intermediate` answers
the same full page with the header and without it. Requiring a tenfold
difference there would force exactly the fragment-aware disclosure endpoint
FR-3 forbids. The ratio is asserted for the four previews, which FR-3 does
make fragment-aware; for the `hx-get` targets the *stronger* statement of
clause 2 is asserted instead: the two responses are byte-identical.

**Every helper that parses HTML is imported, not re-typed.**
`test_ca_issuer_pages` already owns the tag-nesting scoper and the id walker;
a second copy of either would be a second thing to repair. Only the
client/config/CSRF plumbing is duplicated, which is what every web test file
in this project already does (there is no conftest.py).

**AC-14 is retired**, with its argument where the test was. It compared these
pages against spec 0029's base commit, which is a claim about one diff and
not about the codebase; the section marked `AC-14` below says so at length.
"""

import inspect
import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import probes
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from grant_fixtures import grant_user
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from test_ca_issuer_pages import (
    _form_actions,
    _row,
    _text_of,
)
from test_web_design_shell import css_rules, declarations

from cabin import audit
from cabin.app import create_app
from cabin.audit import ACTOR_KIND_FILTERS, AuditEvent
from cabin.ca import certs as ca_certs
from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca.certs import STATUS_FILTERS as certs_STATUS_FILTERS
from cabin.ca.certs import Certificate
from cabin.ca.service import CACertificate
from cabin.config import Config
from cabin.secrets import SecretStore
from cabin.sessions import get_session
from cabin.store import create_session_factory
from cabin.users import User
from cabin.web import audit_ui, certs_ui

REPO = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = REPO / "src/cabin/web/templates"
STATIC_DIR = REPO / "src/cabin/web/static"

#: FR-3's table. The key is the preview URL, the value the mutation it
#: previews and the page it belongs to -- the three are asserted against each
#: other rather than each being written out three times.
PREVIEWS = {
    "/certs/issue/preview": ("/certs/issue", "/certs/new"),
    "/certs/sign/preview": ("/certs/sign", "/certs/sign"),
    "/ca/create/preview": ("/ca/create", "/ca/new"),
    "/ca/import/preview": ("/ca/import", "/transfer/ca-import"),
}

#: FR-3's four panels: the heading each preview's own panel carries (FR-14,
#: verbatim from the brief) and the keys its `.kv` grid names. Scoping every
#: read to the panel rather than to the page is what stops "a value that is
#: not a dash" being satisfied by the rail beside it.
PANELS = {
    "/certs/issue/preview": ("Result", ("Expires", "Chain", "Key held by")),
    "/certs/sign/preview": ("Parsed request", ("Subject", "SANs", "Key")),
    "/ca/create/preview": ("What gets created", ("Root", "Expires", "Issuers", "Key")),
    "/ca/import/preview": ("Parsed", ("Subject", "Parent", "Key")),
}

#: The constrained issuer's own entries (FR-4's fixture). Deliberately not
#: any string that appears in a template's placeholder or hint: `example.com`
#: and `10.0.0.0/8` are both already printed by `ca_detail.html`, so a panel
#: assertion made with them could be satisfied by the form beside it.
PERMITTED_DNS = "lan.example.test"
PERMITTED_NET = "10.0.0.0/8"
EXCLUDED_DNS = "secret.lan.example.test"

#: FR-14's two new verdict sentences, byte for byte.
VERDICT_PERMITTED = "Every name is inside what this issuer permits."
VERDICT_UNCONSTRAINED = (
    "This issuer sets no name constraints, so any name it is asked for is permitted."
)

#: The design's dim hex, which FR-10 refuses **for the unparsed values**.
#: It is not refused from the file: it is spec 0027's `--disabled` token,
#: named in the brief and pinned by AC-16's palette test, so "it is not in
#: cabin.css" would fail a build that is correct. What FR-10 states is that
#: the dim state is `--text-muted`, and that is what is asserted -- once as
#: the declaration the dim rule carries, and once as effect, by putting the
#: unparsed state in front of the contrast probe.
REFUSED_DIM = "#5a5d6b"
REFUSED_DIM_TOKEN = "--disabled"


# --- fixtures and plumbing, duplicated as every web test file here does ----


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


#: The superadmin every test here sets up. Named, because the rail footer's
#: avatar (spec 0030 FR-11) renders its first character and a test below has
#: to be able to say so without repeating the letter.
_SUPERADMIN = "alice"


def _setup_superadmin(
    client: TestClient, username: str = _SUPERADMIN, password: str = "correcthorse1"
) -> None:
    resp = client.post("/setup", data={"username": username, "password": password})
    assert resp.status_code == 303


def _csrf(client: TestClient, cfg: Config) -> str:
    db = _db(cfg)
    try:
        row = get_session(db, client.cookies["cabin_session"])
        assert row is not None
        return row.csrf_token
    finally:
        db.close()


def _create_user(client: TestClient, cfg: Config, username: str, role: str) -> None:
    resp = client.post(
        "/users",
        data={
            "username": username,
            "password": "whatever12345",
            "role": role,
            "csrf_token": _csrf(client, cfg),
        },
    )
    assert resp.status_code == 303, resp.text


def _login(client: TestClient, username: str, password: str = "whatever12345") -> None:
    client.cookies.clear()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303


def _cert_of(cfg: Config, ca_id: int) -> x509.Certificate:
    db = _db(cfg)
    try:
        return x509.load_pem_x509_certificate(ca_service.get_ca(db, ca_id).cert_pem.encode("ascii"))
    finally:
        db.close()


def _count(cfg: Config, model: type[Any]) -> int:
    db = _db(cfg)
    try:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)
    finally:
        db.close()


@dataclass(frozen=True)
class Fixture:
    """The spec's own fixture, plus the two extra issuers two criteria need.

    **alpha** carries the constraints FR-4 argues from: it permits
    `lan.example.test` and `10.0.0.0/8` and excludes `secret.lan.example.test`,
    which is the only shape in which the common-name rule
    (`leaf.py:608-615`) can be shown to fire in one request and not in the
    next. **beta** is unconstrained, so FR-4's other verdict branch has a
    fixture too.

    **short** exists for AC-4: an issuer whose own `not_valid_after` is
    nearer than a 3650-day request, so the clamp has something to clamp
    against. **ipnet** exists for FR-5: it permits an IP subtree and *no*
    DNS subtree at all, which is the one configuration in which resolving
    an IP common name to `IP:` and passing an empty SAN list give opposite
    answers.
    """

    alpha_root: int
    alpha_int: int
    beta_root: int
    beta_int: int
    short_root: int
    short_int: int
    ipnet_root: int
    ipnet_int: int
    alpha_int_name: str
    beta_int_name: str


def _seed(cfg: Config) -> Fixture:
    db = _db(cfg)
    try:
        secrets = _secrets(cfg)
        alpha = ca_service.create_hierarchy(
            db,
            secrets,
            "alpha root",
            "alpha issuer",
            path_length=2,
            constraints=leaf_mod.parse_name_constraints(
                f"{PERMITTED_DNS}\n{PERMITTED_NET}", EXCLUDED_DNS
            ),
        )
        beta = ca_service.create_hierarchy(db, secrets, "beta root", "beta issuer")
        short = ca_service.create_hierarchy(
            db, secrets, "short root", "short issuer", intermediate_years=1
        )
        ipnet = ca_service.create_hierarchy(
            db,
            secrets,
            "ipnet root",
            "ipnet issuer",
            constraints=leaf_mod.parse_name_constraints("192.168.0.0/16", ""),
        )
        return Fixture(
            alpha_root=alpha.root.id,
            alpha_int=alpha.intermediate.id,
            beta_root=beta.root.id,
            beta_int=beta.intermediate.id,
            short_root=short.root.id,
            short_int=short.intermediate.id,
            ipnet_root=ipnet.root.id,
            ipnet_int=ipnet.intermediate.id,
            alpha_int_name=alpha.intermediate.name,
            beta_int_name=beta.intermediate.name,
        )
    finally:
        db.close()


def _encrypted_key_pem(passphrase: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    ).decode("ascii")


def _csr_pem(common_name: str, sans: list[x509.GeneralName]) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    from cryptography.hazmat.primitives import hashes

    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --- the four preview payloads --------------------------------------------


def _issue_form(fix: Fixture, cfg: Config, client: TestClient, **over: object) -> dict[str, object]:
    data: dict[str, object] = {
        "subject_cn": f"nas.{PERMITTED_DNS}",
        "sans": f"nas.{PERMITTED_DNS}",
        "profile": "server",
        "key_type": "ecdsa-p256",
        "days": 30,
        "issuer_id": fix.alpha_int,
        "csrf_token": _csrf(client, cfg),
    }
    data.update(over)
    return data


def _sign_form(fix: Fixture, cfg: Config, client: TestClient, **over: object) -> dict[str, object]:
    data: dict[str, object] = {
        "csr_pem": _csr_pem(f"csr.{PERMITTED_DNS}", [x509.DNSName(f"csr.{PERMITTED_DNS}")]),
        "profile": "server",
        "sans_override": "",
        "days": 30,
        "issuer_id": fix.alpha_int,
        "csrf_token": _csrf(client, cfg),
    }
    data.update(over)
    return data


def _create_form(cfg: Config, client: TestClient, **over: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "preview corp",
        "key_type": "ecdsa-p384",
        "root_years": 12,
        "path_length": 2,
        "csrf_token": _csrf(client, cfg),
    }
    data.update(over)
    return data


def _import_form(cfg: Config, client: TestClient, **over: object) -> dict[str, object]:
    root_cert, root_key = _foreign_pair()
    data: dict[str, object] = {
        "cert_pem": root_cert,
        "chain_pem": root_key,
        "csrf_token": _csrf(client, cfg),
    }
    data.update(over)
    return data


def _foreign_pair() -> tuple[str, str]:
    """A parseable intermediate and its parent root, as PEM -- built here so
    the import preview has something real to say `Subject` and `Parent` about
    without any row being written."""
    from cabin.ca import x509 as ca_x509

    root_cert, root_key = ca_x509.create_root("foreign root", "ecdsa-p256", path_length=2)
    inter_cert, _inter_key = ca_x509.create_intermediate(
        root_cert, root_key, "foreign issuer", "ecdsa-p256"
    )
    return (
        inter_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def _payload(url: str, fix: Fixture, cfg: Config, client: TestClient) -> dict[str, object]:
    """The form body for one preview URL. A URL with no entry here fails by
    name rather than being posted empty, so a fifth preview endpoint cannot
    slip past AC-1 by answering 422 to a body nobody wrote."""
    builders: dict[str, Callable[[], dict[str, object]]] = {
        "/certs/issue/preview": lambda: _issue_form(fix, cfg, client),
        "/certs/sign/preview": lambda: _sign_form(fix, cfg, client),
        "/ca/create/preview": lambda: _create_form(cfg, client),
        "/ca/import/preview": lambda: _import_form(cfg, client),
    }
    assert url in builders, (
        f"{url} is posted to by an hx-post attribute and this test has no body for "
        f"it. FR-3 names four preview endpoints and this spec adds no others"
    )
    return builders[url]()


# --- reading a rendered panel ----------------------------------------------


class _TextList(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.texts: list[str] = []
        self._muted = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._muted += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._muted:
            self._muted -= 1

    def handle_data(self, data: str) -> None:
        if self._muted:
            return
        text = " ".join(unescape(data).split())
        if text:
            self.texts.append(text)


def _texts(fragment: str) -> list[str]:
    """Every non-empty visible text node, in document order."""
    parser = _TextList()
    parser.feed(fragment)
    return parser.texts


def _panel(html: str, heading: str) -> str:
    """The `.panel` whose `.kicker` reads `heading` (FR-15).

    Scoped by parsing tag nesting, never by a character window: a panel's own
    heading is the only marker on these pages that is guaranteed unique, and
    the value beside it is what every criterion below actually reads.
    """
    marker = f">{heading}<"
    assert marker in html, (
        f"no element on this page has the exact text {heading!r}. FR-14 fixes "
        f"every panel heading byte for byte"
    )
    return _row(html, marker, class_name="panel", tag=None)


def _values(panel_html: str, *keys: str) -> dict[str, str]:
    """The key/value pairs of a panel's `.kv` grid (FR-15), read as text
    nodes: the value of a key is the text node that follows it.

    Structure-agnostic on purpose -- `<dt>/<dd>`, two divs or a `<span>` in a
    grid cell all produce the same node sequence -- so this measures what the
    operator reads rather than which element the implementer reached for.
    """
    texts = _texts(panel_html)
    found: dict[str, str] = {}
    for i, text in enumerate(texts):
        if text in keys and text not in found:
            assert i + 1 < len(texts), f"{text!r} is the last text in the panel: no value beside it"
            found[text] = texts[i + 1]
    missing = [key for key in keys if key not in found]
    assert missing == [], f"the panel names no {missing} -- it has {texts}"
    return found


_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
)


class _Marks(HTMLParser):
    """Every `.mark-ok`/`.mark-bad` element (FR-15) and the text of the line
    it stands on -- the mark and the name it marks, read as a pair.

    "The line" is bounded by the element that *encloses* the mark, tracked
    through a tag stack. Left unbounded it would run to the end of the
    fragment, and the last mark's text would swallow the verdict sentence
    below it -- at which point `"…" in line` is satisfied by anything on the
    panel and the pairing this helper exists to measure measures nothing.
    """

    def __init__(self) -> None:
        super().__init__()
        self.marks: list[tuple[bool, str]] = []
        self._stack: list[str] = []
        self._ok: bool | None = None
        self._parent_depth = 0
        self._line = ""

    def _finish(self) -> None:
        if self._ok is not None:
            self.marks.append((self._ok, " ".join(self._line.split())))
            self._ok = None
            self._line = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = (dict(attrs).get("class") or "").split()
        if "mark-ok" in classes or "mark-bad" in classes:
            assert not ("mark-ok" in classes and "mark-bad" in classes), attrs
            self._finish()
            self._ok = "mark-ok" in classes
            self._parent_depth = len(self._stack)
        if tag not in _VOID:
            self._stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID and self._stack:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        if self._ok is not None:
            self._line += " " + unescape(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in self._stack:
            while self._stack.pop() != tag:
                pass
        if self._ok is not None and len(self._stack) < self._parent_depth:
            self._finish()

    def close(self) -> None:
        super().close()
        self._finish()


def _marks(html: str) -> list[tuple[bool, str]]:
    parser = _Marks()
    parser.feed(html)
    parser.close()
    return parser.marks


#: `ca_new.html:45`'s path-length hint, as that template carried it before
#: FR-9 moved it into the panel column.
#:
#: Frozen here rather than read out of git at the base commit, which is what
#: it used to be. The commit is on this branch and a squash merge takes it
#: with it, so a test resolving it would break permanently on `main` -- but
#: the deeper reason is that FR-14's claim is not about a commit. It is
#: *this sentence, in the panel column, unedited*, and a sentence is a thing
#: a test can hold.
#:
#: A frozen copy can be edited into agreeing with the template, which the git
#: read could not. What replaces that guarantee is visibility: this constant
#: and `ca_new.html` are two files in one diff, and "moving a sentence is not
#: editing it" is a claim a reviewer can check by reading it. A silent edit
#: to the template alone still fails.
PATH_LENGTH_HINT = (
    "How many further intermediates may sign under the root. Cannot be changed later. "
    "A root that may ever need to cross-sign an older one needs at least 2 -- planned "
    "one root generation ahead, since this cannot be widened afterwards."
)


def _error_box(html: str) -> str | None:
    """The text of the page's own error box -- the one `POST /certs/sign`
    fills -- or None when there is none. AC-10 needs the *absence* of it to
    be provable, which a substring search over the page cannot give."""
    found = re.search(r'<div class="error">(.*?)</div>', html, re.S)
    return None if found is None else _text_of(found.group(1))


# --- htmx attributes, read out of the templates ----------------------------

_HX_RE = re.compile(r'\b(hx-[a-zA-Z-]+|hx-on[^\s=]*)="([^"]*)"')


def _hx_attributes() -> list[tuple[str, str, str]]:
    """`(template name, attribute, value)` for every `hx-*` attribute in
    every template."""
    found = []
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        text = path.read_text()
        for name, value in _HX_RE.findall(text):
            found.append((path.name, name, value))
    return found


def _hx_targets(root_id: int) -> tuple[set[tuple[str, str]], int]:
    """`(method, url)` for every literal `hx-get`/`hx-post` in the templates,
    plus how many were skipped because they are interpolated.

    Spec 0030 changes what this can do. Half of that spec's targets are
    built out of a value -- `/users?edit={{ row.id }}`, `_page_url`'s output
    -- and a URL still containing `{{` cannot be fetched. The old form
    asserted loudly on any unresolved interpolation, which was right while
    the one interpolation in the templates was `{{ root.id }}`; with
    interpolated targets now the normal case, what it does instead is skip
    them here and **count what it skipped**, so that a build in which every
    target is unresolvable is distinguishable from one in which there are
    none. The resolved ones come off the rendered pages (`_rendered_hx_targets`).
    """
    targets = set()
    skipped = 0
    for _name, attribute, value in _hx_attributes():
        if attribute not in {"hx-get", "hx-post"}:
            continue
        url = re.sub(r"{{\s*root\.id\s*}}", str(root_id), value)
        if "{{" in url or "{%" in url:
            skipped += 1
            continue
        targets.add(("GET" if attribute == "hx-get" else "POST", url))
    return targets, skipped


_RENDERED_HX_RE = re.compile(r'\shx-(get|post)="([^"]*)"')


def _rendered_hx_targets(pages: dict[str, str]) -> set[tuple[str, str]]:
    """`(method, url)` for every `hx-get`/`hx-post` on a *rendered* page.

    This is the half spec 0030 adds. A target the templates carry as
    `/users?edit={{ row.id }}` is a real URL only once a row exists, and the
    walker has to fetch the URL the browser would -- so it collects from the
    nineteen screens as well as from the files, and the union is what AC-1's
    "every htmx target answers a full page" is asserted over.
    """
    found = set()
    for html in pages.values():
        for method, url in _RENDERED_HX_RE.findall(html):
            assert "{{" not in url and "{%" not in url, (
                f"a rendered page carries an unresolved interpolation in an hx- attribute: {url!r}"
            )
            found.add(("GET" if method == "get" else "POST", unescape(url)))
    return found


#: Every query parameter an htmx target may carry. Spec 0030's Interface
#: Contract adds exactly one to what already existed -- `edit` on
#: `GET /users` -- and a target carrying anything else is a new endpoint
#: wearing a query string.
KNOWN_QUERY_PARAMETERS = {"q", "status", "page", "action", "actor_kind", "add", "edit"}

#: The screens that carry spec 0030's interpolated targets. Rendered rather
#: than read, because `/users?edit={{ row.id }}` and `_page_url`'s output are
#: only URLs once there are rows.
SPEC_0030_SCREENS = ("/users", "/certs", "/audit")


def _flatten_routes(routes: Any) -> list[Any]:
    """Every real route, walking FastAPI's `_IncludedRouter` wrappers --
    `app.routes` holds one per `include_router` call rather than the routes
    themselves in this version."""
    out: list[Any] = []
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            out.extend(_flatten_routes(inner.routes))
        else:
            out.append(route)
    return out


def _rendered_screens(client: TestClient, cfg: Config, fix: Fixture) -> dict[str, str]:
    """The pages whose htmx targets are interpolated, plus the two spec 0029
    disclosures' own page.

    Asserted to carry **no** flash panel: a popped message is a difference
    between two otherwise identical responses, and the byte-identical clause
    below would then be comparing the response that had it against the one
    that did not.
    """
    paths = [*SPEC_0030_SCREENS, f"/ca/{fix.alpha_root}", "/certs/new", "/certs/sign", "/ca/new"]
    pages = {}
    for path in paths:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert 'class="flash' not in resp.text, (
            f"{path} carries a pending flash. This fixture seeds through the database "
            f"and one HTTP POST that records nothing, so nothing should have written "
            f"one -- and a popped message would make two otherwise identical "
            f"responses differ"
        )
        pages[path] = resp.text
    return pages


def _expected_targets(cfg: Config, fix: Fixture) -> set[tuple[str, str]]:
    """The targets specs 0029 and 0030 require, derived rather than listed.

    Derived from the same functions the pages build their links with
    (`certs_ui._page_url`, `audit_ui._page_url`) and from the fixture's own
    rows, so that a filter link that quietly dropped a parameter shows up
    here as a missing target rather than as a different string nobody
    compared.
    """
    expected = {("POST", url) for url in PREVIEWS} | {
        ("GET", f"/ca/{fix.alpha_root}?add=intermediate"),
        ("GET", f"/ca/{fix.alpha_root}?add=cross-sign"),
    }
    db = _db(cfg)
    try:
        user_ids = [row.id for row in db.scalars(select(User).order_by(User.id))]
    finally:
        db.close()
    assert user_ids, "the fixture has no user, so the row-edit target has no id"
    expected |= {("GET", f"/users?edit={user_id}") for user_id in user_ids}
    expected |= {("GET", certs_ui._page_url("", str(status), 1)) for status in certs_STATUS_FILTERS}
    expected |= {
        ("GET", audit_ui._page_url("", "all", str(kind), 1)) for kind in ACTOR_KIND_FILTERS
    }
    return expected


def _request(
    client: TestClient,
    method: str,
    url: str,
    *,
    data: dict[str, object] | None = None,
    htmx: bool = False,
) -> Any:
    headers = {"HX-Request": "true"} if htmx else {}
    if method == "GET":
        return client.get(url, headers=headers)
    return client.post(url, data=data or {}, headers=headers)


# --- spies -----------------------------------------------------------------


def _spy(monkeypatch: pytest.MonkeyPatch, module: Any, name: str) -> list[tuple[Any, ...]]:
    """Wrap `module.name` in a recorder, everywhere it is reachable.

    Patched on the defining module *and* on every already-imported `cabin`
    module that holds the same object under the same name: a
    `from x import y` at the top of a web module would otherwise leave the
    spy watching a door nobody uses, and a spy that cannot see the call is
    a spy that reports zero for the wrong reason.
    """
    import sys

    original = getattr(module, name)
    calls: list[tuple[Any, ...]] = []

    def recorder(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return original(*args, **kwargs)

    patched = 0
    for mod in list(sys.modules.values()):
        if mod is None or not getattr(mod, "__name__", "").startswith("cabin"):
            continue
        if getattr(mod, name, None) is original:
            monkeypatch.setattr(mod, name, recorder)
            patched += 1
    assert patched >= 1, f"{module.__name__}.{name} was not found anywhere to patch"
    return calls


# --- AC-1 ------------------------------------------------------------------


def test_every_hx_target_answers_a_full_page(client: TestClient, cfg: Config) -> None:
    """AC-1: nothing else in the suite would notice a fragment-only endpoint.

    Every other test here either sends `HX-Request` or asserts on the
    fragment, and a fragment-only endpoint renders perfectly in a browser
    with JavaScript on -- so this is the whole of the no-JavaScript story's
    load-bearing assertion, and it is made from the templates outward rather
    than from a list somebody maintained.

    The tenfold-shorter clause is asserted for the four previews only. FR-2
    clause 2 makes the two `hx-get` targets URLs that answer the *same* page
    either way, narrowed client-side by `hx-select`; a length ratio there
    would require the fragment-aware disclosure endpoint FR-3 forbids. What
    is asserted for them instead is the stronger form of clause 2: the two
    responses are identical.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)

    literal, skipped = _hx_targets(fix.alpha_root)
    pages = _rendered_screens(client, cfg, fix)
    resolved = _rendered_hx_targets(pages)
    targets = literal | resolved

    assert targets, (
        "no template carries an hx-get or hx-post attribute at all, so this test "
        "found nothing and would pass by finding nothing (AC-1)"
    )
    assert skipped == 0 or resolved, (
        f"{skipped} hx- target(s) in the templates are interpolated and not one of "
        f"them was resolved off a rendered page, so every one of them dropped out of "
        f"this test's coverage. That is the state spec 0030's walker counts skips to "
        f"make visible"
    )
    expected = _expected_targets(cfg, fix)
    assert expected <= targets, (
        f"these htmx targets are required by spec 0029 FR-2 and spec 0030 FR-10, "
        f"FR-11 and FR-12 and no template carries one. Spec 0030's corrected "
        f"Strengthened entry asks for a derived lower bound rather than an exact "
        f"number: FR-10 gives the inventory's five links their `hx-` attributes and "
        f"FR-15 leaves open whether the inventory export's five carry them too, so "
        f"no exact number is derivable from anything the spec says. The bound plus "
        f"the no-new-endpoint check below is FR-20 clause 1 measured instead.\n  "
        f"missing: {sorted(expected - targets)}"
    )
    assert len(targets) >= len(expected) > 0, (targets, expected)

    # FR-20 clause 1: htmx adds no endpoint and no query parameter but `edit`.
    #
    # Matched against the routes, not compared with their paths. Half of spec
    # 0030's targets are interpolated -- `/users?edit={{ row.id }}`, the output
    # of `_page_url`, `/ca/{{ row.id }}?add=` -- so what the walker resolves off
    # a rendered page is `/ca/1`, while `route.path` is `/ca/{root_id}`. A set
    # membership between a resolved URL and a route template is false for every
    # such target and true only for the literal ones, which is why this clause
    # was green while the walker collected from templates alone and cannot be
    # once it collects from pages. Starlette's own `path_regex` is what decides
    # whether a path is one this application already routes.
    known = [
        route
        for route in _flatten_routes(client.app.routes)  # type: ignore[attr-defined]
        if getattr(route, "path_regex", None) is not None
    ]
    assert known, "no route carries a path_regex, so the clause below matches nothing"
    for method, url in sorted(targets):
        parsed = urlparse(url)
        assert any(route.path_regex.fullmatch(parsed.path) for route in known), (
            f"{method} {parsed.path} is not a route this application already has. "
            f"'Every htmx target is a URL that also works as a page' (ADR-0003) and "
            f"spec 0030 FR-20 adds no endpoint at all"
        )
        strays = set(parse_qs(parsed.query)) - KNOWN_QUERY_PARAMETERS
        assert strays == set(), (
            f"{method} {url} carries the query parameter(s) {sorted(strays)}. The "
            f"Interface Contract adds exactly one, `edit` on GET /users"
        )

    for method, url in sorted(targets):
        data = _payload(url, fix, cfg, client) if method == "POST" else None
        plain = _request(client, method, url, data=data)
        assert plain.status_code == 200, f"{method} {url} without HX-Request -> {plain.status_code}"
        body = plain.text
        assert "<html" in body, f"{method} {url} answers no document without HX-Request"
        assert '<aside class="rail">' in body, f"{method} {url} answers a page with no rail"
        assert '<main id="main">' in body, f"{method} {url} answers a page with no <main id=main>"

        framed = _request(client, method, url, data=data, htmx=True)
        assert framed.status_code == 200, f"{method} {url} with HX-Request -> {framed.status_code}"
        if method == "POST":
            assert len(body) >= 10 * len(framed.text), (
                f"{url} answers {len(body)} bytes without HX-Request and "
                f"{len(framed.text)} with it -- the two envelopes of FR-3 are not "
                f"two envelopes"
            )
        else:
            assert framed.text == body, (
                f"GET {url} answers a different body with HX-Request. FR-2 clause 2: "
                f"a disclosure target is a page htmx narrows with hx-select, not a "
                f"fifth endpoint"
            )


# --- AC-3 ------------------------------------------------------------------


def test_the_constraint_panel_agrees_with_the_signer(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3: the panel agrees with the signer where a per-name loop cannot.

    Both halves live in one test because a build that always says "refused"
    passes the first on its own and a build that always says "permitted"
    passes the second. Neither half compares the panel with
    `check_name_constraints` a second time: the oracle is `POST /certs/issue`
    with the same inputs, and whether a row exists afterwards.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    before = _count(cfg, Certificate)

    # 1. An excluded CN with an IP-only SAN list. The one name is permitted;
    #    the whole-set call appends DNS:<cn> because no DNS SAN exists, and
    #    refuses. A verdict derived from the marks says "permitted" here.
    refused_form = _issue_form(fix, cfg, client, subject_cn=EXCLUDED_DNS, sans="10.0.0.5")
    calls = _spy(monkeypatch, leaf_mod, "check_name_constraints")
    preview = client.post("/certs/issue/preview", data=dict(refused_form))
    # Snapshotted here, before anything else in this test reaches the signer.
    # `_build_leaf` calls the same function, so a list read after the
    # `POST /certs/issue` below holds issuance's own whole-set call as well --
    # and `preview_calls[:-1]` would then end on the preview's whole-set call,
    # whose second argument is the common name. The only build passing that
    # arrangement is one that makes a per-name call and no whole-set call,
    # which is exactly what FR-4 forbids and what the IP case proves wrong.
    preview_calls = list(calls)
    assert preview.status_code == 200, preview.text
    panel = _panel(preview.text, "Name constraints — checked before signing")

    marks = _marks(panel)
    assert len(marks) == 1, f"expected one marked name, got {marks}"
    ok, line = marks[0]
    assert ok is True, f"10.0.0.5 is inside {PERMITTED_NET} and the panel marks it refused: {line}"
    assert "10.0.0.5" in line, line

    # The spy: once per name, then once over the whole set, in that order --
    # asserted on the snapshot, above the issuance that would pollute it.
    resolve = getattr(leaf_mod, "resolve_sans", None)
    assert resolve is not None, "leaf.resolve_sans does not exist (FR-5: _resolve_sans renamed)"
    resolved = resolve([leaf_mod._normalize_san("10.0.0.5")], [], EXCLUDED_DNS)
    issuer_cert = _cert_of(cfg, fix.alpha_int)
    assert len(preview_calls) == len(resolved) + 1, (
        f"the preview called check_name_constraints {len(preview_calls)} times for "
        f"{len(resolved)} name(s). FR-4 asks for one call per name plus one over "
        f"the whole set; zero calls means the check was re-implemented in the web "
        f"layer: {preview_calls}"
    )
    for call in preview_calls[:-1]:
        assert call[1] is None, (
            f"a per-name call passed subject_cn={call[1]!r}; FR-4 requires None so "
            f"the common-name rule cannot fire inside a single-name call"
        )
    last = preview_calls[-1]
    assert last[0] == issuer_cert, "the whole-set call was made against another certificate"
    assert last[1] == EXCLUDED_DNS, f"the whole-set call passed subject_cn={last[1]!r}"
    assert list(last[2]) == list(resolved), (
        f"the whole-set call was made over {list(last[2])}, not over resolve_sans's "
        f"own output {list(resolved)} -- FR-5's whole point"
    )

    issued = client.post(
        "/certs/issue",
        data=_issue_form(fix, cfg, client, **dict(subject_cn=EXCLUDED_DNS, sans="10.0.0.5")),
    )
    assert issued.status_code == 400, (
        f"POST /certs/issue accepted an excluded common name with an IP-only SAN "
        f"list ({issued.status_code}); the fixture no longer exercises FR-4"
    )
    signer_message = _error_box(issued.text)
    assert signer_message, "the issue form's 400 carries no error box to compare against"
    assert signer_message in " ".join(_texts(panel)), (
        f"the panel does not carry the signer's own refusal. FR-4: the verdict is "
        f"NameConstraintError's own message, which is the only sentence guaranteed "
        f"to agree with the one POST /certs/issue shows.\n  signer: "
        f"{signer_message!r}\n  panel: {_texts(panel)}"
    )
    assert VERDICT_PERMITTED not in _texts(panel), (
        "the panel says every name is permitted for a request the signer refuses -- "
        "the verdict is being computed from the marks (FR-4)"
    )
    assert _count(cfg, Certificate) == before, "a refused issuance wrote a row"

    # ...and the counter-check that the snapshot above was taken at the right
    # moment: the signer calls the same function, so the list has grown.
    assert len(calls) > len(preview_calls), (
        "POST /certs/issue made no check_name_constraints call of its own, so "
        "either the spy stopped recording or the check left _build_leaf -- and "
        "the snapshot above is measuring a window that no longer means anything"
    )

    # 2. The same excluded CN, this time with a DNS SAN. The CN is no longer
    #    checked, so this one signs -- and the panel has to say so.
    permitted_form = dict(subject_cn=EXCLUDED_DNS, sans=f"nas.{PERMITTED_DNS}", days=30)
    second = client.post(
        "/certs/issue/preview", data=_issue_form(fix, cfg, client, **permitted_form)
    )
    assert second.status_code == 200, second.text
    second_panel = _panel(second.text, "Name constraints — checked before signing")
    second_marks = _marks(second_panel)
    assert len(second_marks) == 1, f"expected one marked name, got {second_marks}"
    assert second_marks[0][0] is True, (
        f"nas.{PERMITTED_DNS} is under the permitted subtree {PERMITTED_DNS} and the "
        f"panel marks it refused: {second_marks}"
    )
    assert f"nas.{PERMITTED_DNS}" in second_marks[0][1], second_marks
    assert VERDICT_PERMITTED in _texts(second_panel), (
        f"the panel refuses a request the signer accepts -- it is refusing whenever "
        f"the CN is excluded, regardless of the SAN list (FR-4): "
        f"{_texts(second_panel)}"
    )

    signed = client.post("/certs/issue", data=_issue_form(fix, cfg, client, **permitted_form))
    assert signed.status_code == 303, (
        f"POST /certs/issue refused a request whose CN is excluded but whose SAN "
        f"list carries a DNS entry ({signed.status_code}); the panel and the signer "
        f"are being compared against different behaviour.\n{signed.text[:800]}"
    )
    assert _count(cfg, Certificate) == before + 1


# --- FR-5: the IP common name, the case the extraction exists for ----------


def test_the_panel_resolves_an_ip_common_name_the_way_the_signer_does(
    client: TestClient, cfg: Config
) -> None:
    """FR-5: the names the panel checks are the names the signer would check.

    The disagreement FR-5 argues from is constructible, and this is it. With
    an empty SAN box and an IP common name, `resolve_sans` produces
    `IP:10.0.0.5` and the signer evaluates it against the permitted **IP**
    subtrees. Handing `check_name_constraints` an empty SAN list instead --
    the shortcut FR-5 forbids -- makes its own fallback append
    `DNS:10.0.0.5` (`_HOSTNAME_RE` matches a dotted quad) and evaluate that
    against the permitted **DNS** subtrees, of which the `ipnet` issuer has
    none, so everything passes.

    Against `ipnet` those two answers are opposite: the signer refuses,
    the shortcut permits. The counter-check is in the test -- the shortcut is
    computed here and asserted to be the *wrong* answer, so a build that
    happens to agree with both cannot make this test vacuous.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    issuer_cert = _cert_of(cfg, fix.ipnet_int)

    # The counter-check: the two questions really do have different answers.
    leaf_mod.check_name_constraints(issuer_cert, "10.0.0.5", [])
    with pytest.raises(leaf_mod.NameConstraintError):
        leaf_mod.check_name_constraints(issuer_cert, "10.0.0.5", ["IP:10.0.0.5"])

    form = dict(subject_cn="10.0.0.5", sans="", issuer_id=fix.ipnet_int)
    preview = client.post("/certs/issue/preview", data=_issue_form(fix, cfg, client, **form))
    assert preview.status_code == 200, preview.text
    panel = _panel(preview.text, "Name constraints — checked before signing")

    issued = client.post("/certs/issue", data=_issue_form(fix, cfg, client, **form))
    assert issued.status_code == 400, (
        f"POST /certs/issue accepted 10.0.0.5 under an issuer permitting only "
        f"192.168.0.0/16 ({issued.status_code}) -- the fixture no longer poses the "
        f"question FR-5 exists for"
    )
    signer_message = _error_box(issued.text)
    assert signer_message, "the issue form's 400 carries no error box"
    assert signer_message in " ".join(_texts(panel)), (
        f"the panel does not repeat the signer's refusal. Passing the empty SAN box "
        f"straight to check_name_constraints would make the panel say permitted "
        f"here, which is the disagreement FR-5's rename exists to prevent.\n"
        f"  signer: {signer_message!r}\n  panel: {_texts(panel)}"
    )
    assert VERDICT_PERMITTED not in _texts(panel)
    marks = _marks(panel)
    assert marks and all("IP:10.0.0.5" in line for _ok, line in marks), (
        f"the panel does not name IP:10.0.0.5 at all, so it is not checking the "
        f"name the signer checks (FR-5): {marks}"
    )


# --- AC-4 ------------------------------------------------------------------


def _stated_expiry(html: str) -> datetime:
    """The `Expires` value the `Result` panel prints, as a datetime.

    Parsed rather than string-compared, because AC-4 compares it with a
    stored certificate's `not_valid_after_utc` -- and a date-only rendering
    cannot answer "equals exactly", which is what the criterion asks and what
    the Interface Contract's ISO-8601 string gives.
    """
    value = _values(_panel(html, "Result"), "Expires")["Expires"]
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover - the failure message is the point
        raise AssertionError(
            f"the panel states {value!r} as its expiry, which is not an ISO-8601 "
            f"moment. AC-4 compares it with a certificate's own not_valid_after_utc "
            f"and the Interface Contract makes `expires` an ISO-8601 string: {exc}"
        ) from exc
    assert moment.tzinfo is not None, (
        f"the panel states {value!r}, a naive moment: a leaf's expiry compared "
        f"across two requests has to carry its offset"
    )
    return moment.astimezone(UTC)


def _issued_certificate(cfg: Config, response: Any) -> x509.Certificate:
    assert response.status_code == 303, f"issuance failed: {response.status_code}"
    location = response.headers["location"]
    cert_id = int(location.rsplit("/", 1)[1])
    db = _db(cfg)
    try:
        row = db.get(Certificate, cert_id)
        assert row is not None
        return x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    finally:
        db.close()


def _clamp_note(html: str) -> str | None:
    """The clamp note, found by its own sentence shape rather than by class:
    FR-14 lifts it from `cert_detail.html:15-17` with `is` -> `would be`, so
    the phrase is fixed and the element it lands in is not."""
    for text in _texts(html):
        if "own expiry is sooner" in text and "would be valid only until" in text:
            return text
    return None


def test_the_panel_expiry_is_the_issued_expiry(client: TestClient, cfg: Config) -> None:
    """AC-4: measured against a certificate that was actually issued.

    Neither half calls `clamp_validity`. A criterion that compared the panel
    with the helper a second time would pass when both call sites are wrong
    in the same way, which is precisely the failure mode of an extraction.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    short_cert = _cert_of(cfg, fix.short_int)

    # 1. Clamped: the issuer expires in about a year, the request asks 3650.
    clamped = dict(subject_cn="clamped.example", sans="", issuer_id=fix.short_int, days=3650)
    preview = client.post("/certs/issue/preview", data=_issue_form(fix, cfg, client, **clamped))
    assert preview.status_code == 200, preview.text
    stated = _stated_expiry(preview.text)
    assert _clamp_note(preview.text) is not None, (
        f"days=3650 against an issuer expiring {short_cert.not_valid_after_utc} is "
        f"clamped, and the panel renders no clamp note (FR-7 clause 3): "
        f"{_texts(_panel(preview.text, 'Result'))}"
    )

    cert = _issued_certificate(
        cfg, client.post("/certs/issue", data=_issue_form(fix, cfg, client, **clamped))
    )
    assert cert.not_valid_after_utc == stated, (
        f"the panel states {stated.isoformat()} and the certificate cabin then "
        f"issued from the same inputs expires {cert.not_valid_after_utc.isoformat()}"
    )
    assert cert.not_valid_after_utc == short_cert.not_valid_after_utc, (
        "the issued leaf was not clamped to its issuer at all -- this half is "
        "measuring an unclamped request and cannot fail for the defect it exists for"
    )

    # ...and one day inside the issuer's window is not clamped, so the note
    # is a note about this request and not decoration on the page.
    inside_days = (short_cert.not_valid_after_utc - datetime.now(UTC)).days - 1
    assert inside_days > 0, "the short issuer has already expired; the fixture is broken"
    inside = dict(subject_cn="inside.example", sans="", issuer_id=fix.short_int, days=inside_days)
    near = client.post("/certs/issue/preview", data=_issue_form(fix, cfg, client, **inside))
    assert near.status_code == 200, near.text
    assert _clamp_note(near.text) is None, (
        "a request one day inside the issuer's own window renders the clamp note; "
        "the note does not depend on capped_from (FR-7 clause 3)"
    )

    # 2. Not clamped, against a long-lived issuer.
    plain = dict(subject_cn=f"plain.{PERMITTED_DNS}", sans="", issuer_id=fix.alpha_int, days=30)
    unclamped = client.post("/certs/issue/preview", data=_issue_form(fix, cfg, client, **plain))
    assert unclamped.status_code == 200, unclamped.text
    stated_plain = _stated_expiry(unclamped.text)
    assert _clamp_note(unclamped.text) is None, "an unclamped request renders a clamp note"

    plain_cert = _issued_certificate(
        cfg, client.post("/certs/issue", data=_issue_form(fix, cfg, client, **plain))
    )
    drift = abs((plain_cert.not_valid_after_utc - stated_plain).total_seconds())
    assert drift <= 5, (
        f"the panel states {stated_plain.isoformat()} and the certificate issued "
        f"from the same inputs expires {plain_cert.not_valid_after_utc.isoformat()} "
        f"-- {drift:.0f}s apart, which is more than the wall time between two "
        f"requests"
    )
    assert plain_cert.not_valid_after_utc < _cert_of(cfg, fix.alpha_int).not_valid_after_utc, (
        "this half's request was clamped after all, so it measures the same thing as the first half"
    )


# --- AC-5 ------------------------------------------------------------------


def test_a_preview_writes_nothing_and_unseals_nothing(
    client: TestClient, cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-5: and a build that does no work cannot pass by doing nothing.

    `_unseal_signing_key` is spied alongside `signing_credentials` because it
    is the function that actually decrypts: reaching past the named door
    would satisfy the criterion as written while every keystroke still
    unsealed a CA private key.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    counts = {model: _count(cfg, model) for model in (Certificate, CACertificate, AuditEvent)}

    unsealed = _spy(monkeypatch, ca_service, "signing_credentials")
    decrypted = _spy(monkeypatch, ca_service, "_unseal_signing_key")
    recorded = _spy(monkeypatch, audit, "record")
    stored = _spy(monkeypatch, ca_certs, "_store")

    for url in PREVIEWS:
        resp = client.post(url, data=_payload(url, fix, cfg, client))
        assert resp.status_code == 200, f"{url} -> {resp.status_code}: {resp.text[:400]}"
        heading, keys = PANELS[url]
        values = _values(_panel(resp.text, heading), *keys)
        assert set(values.values()) != {"—"}, (
            f"{url}'s {heading!r} panel is all dashes for a request that carries "
            f"real input, so a build that does no work would pass this criterion by "
            f"doing nothing: {values}"
        )
        assert unsealed == [], (
            f"{url} called ca_service.signing_credentials -- the issuer's "
            f"certificate is in `ca_certificates.cert_pem` and a preview that "
            f"reaches for the key decrypts one on every keystroke: {unsealed}"
        )
        assert decrypted == [], f"{url} unsealed a private key: {len(decrypted)} call(s)"
        assert recorded == [], f"{url} wrote an audit event: {recorded}"
        assert stored == [], f"{url} stored a certificate: {stored}"

    for model, before in counts.items():
        assert _count(cfg, model) == before, f"the four previews changed {model.__name__} rows"

    # The counter-check: the same spies do fire for the mutation each preview
    # previews, so "zero" above is a measurement and not a dead instrument.
    assert client.post("/ca/create", data=_create_form(cfg, client)).status_code == 303
    assert recorded, (
        "POST /ca/create recorded no audit event either, so the audit spy is not "
        "wired to anything and its zero above proves nothing"
    )


# --- AC-6 ------------------------------------------------------------------


def test_each_preview_is_guarded_like_its_mutation(client: TestClient, cfg: Config) -> None:
    """AC-6: a preview is a read of privileged state.

    Compared *pairwise against the mutation* rather than against four
    hard-coded numbers: the requirement is "guarded exactly like the mutation
    it previews", and a status this test spelled out itself would stop
    tracking the mutation the day the mutation's own guard changed.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    _create_user(client, cfg, "vera", "viewer")
    admin_cookies = dict(client.cookies)

    for preview_url, (mutation_url, _page) in PREVIEWS.items():
        body = _payload(preview_url, fix, cfg, client)

        client.cookies.clear()
        anon_preview = client.post(preview_url, data=dict(body))
        anon_mutation = client.post(mutation_url, data=dict(body))
        assert anon_preview.status_code == anon_mutation.status_code, (
            f"anonymous: {preview_url} -> {anon_preview.status_code}, "
            f"{mutation_url} -> {anon_mutation.status_code}"
        )
        assert anon_preview.headers.get("location") == anon_mutation.headers.get("location"), (
            f"anonymous {preview_url} does not redirect where {mutation_url} does"
        )

        _login(client, "vera")
        viewer_body = dict(body, csrf_token=_csrf(client, cfg))
        viewer_preview = client.post(preview_url, data=dict(viewer_body))
        viewer_mutation = client.post(mutation_url, data=dict(viewer_body))
        assert viewer_preview.status_code == viewer_mutation.status_code == 403, (
            f"viewer: {preview_url} -> {viewer_preview.status_code}, "
            f"{mutation_url} -> {viewer_mutation.status_code}"
        )

        client.cookies.clear()
        client.cookies.update(admin_cookies)
        no_token = {k: v for k, v in body.items() if k != "csrf_token"}
        assert (
            client.post(preview_url, data=dict(no_token)).status_code
            == client.post(mutation_url, data=dict(no_token)).status_code
            == 403
        ), f"{preview_url} accepts a request with no csrf_token"
        wrong = dict(body, csrf_token="not-the-token")
        assert (
            client.post(preview_url, data=dict(wrong)).status_code
            == client.post(mutation_url, data=dict(wrong)).status_code
            == 403
        ), f"{preview_url} accepts a wrong csrf_token"

    # ...and the grant check, which only the two /certs previews can fail.
    client.cookies.clear()
    client.cookies.update(admin_cookies)
    _create_user(client, cfg, "bob", "admin")
    _login(client, "bob")
    ungranted = _issue_form(fix, cfg, client, issuer_id=fix.alpha_int)
    assert (
        client.post("/certs/issue/preview", data=dict(ungranted)).status_code
        == client.post("/certs/issue", data=dict(ungranted)).status_code
        == 403
    ), "an admin granted no issuer reaches the issue preview but not the issuance"

    db = _db(cfg)
    try:
        bob = db.scalars(select(User).where(User.username == "bob")).one()
        grant_user(db, bob, fix.beta_int)
        db.commit()
    finally:
        db.close()
    named = _issue_form(fix, cfg, client, issuer_id=fix.alpha_int)
    refused = client.post("/certs/issue/preview", data=dict(named))
    assert (
        refused.status_code == client.post("/certs/issue", data=dict(named)).status_code == 403
    ), "naming an issuer this principal is not granted is not refused by the preview"
    assert fix.alpha_int_name not in refused.text, (
        f"the refusal names an issuer this principal is not granted: "
        f"{fix.alpha_int_name!r} appears in the response body"
    )


# --- AC-7 ------------------------------------------------------------------


def test_one_macro_two_envelopes(client: TestClient, cfg: Config) -> None:
    """AC-7: the substring assertion is what makes "one code path" a
    measurement rather than a claim.

    A fragment rendered by a second template that drifts from the page's
    would still look right in a browser and would still pass every other test
    in this file.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)

    for preview_url, (mutation_url, page_url) in PREVIEWS.items():
        body = _payload(preview_url, fix, cfg, client)

        fragment = client.post(preview_url, data=dict(body), headers={"HX-Request": "true"})
        assert fragment.status_code == 200, f"{preview_url} -> {fragment.status_code}"
        assert fragment.headers["content-type"].startswith("text/html"), (
            f"{preview_url} answers {fragment.headers['content-type']} to htmx"
        )
        assert "<html" not in fragment.text, f"{preview_url}'s fragment is a whole document"
        assert '<aside class="rail">' not in fragment.text, (
            f"{preview_url}'s fragment carries the rail"
        )

        full = client.post(preview_url, data=dict(body))
        assert full.status_code == 200
        assert fragment.text.strip() in full.text, (
            f"{preview_url}'s fragment does not appear verbatim inside the page it "
            f"answers without HX-Request. FR-3: one Jinja macro, two envelopes"
        )
        assert mutation_url in _form_actions(full.text), (
            f"the page {preview_url} answers is not {page_url}: no <form> on it "
            f"posts to {mutation_url}. FR-3: the existing page renderer, with the "
            f"panel filled"
        )

        refilled = _submitted_values(full.text)
        for name, value in body.items():
            if name == "csrf_token":
                continue
            assert name in refilled, (
                f"{page_url} came back without the {name!r} field the request "
                f"submitted -- the no-JavaScript envelope loses what was typed"
            )
            assert refilled[name] == str(value), (
                f"{page_url} came back with {name}={refilled[name]!r}, not the "
                f"{str(value)!r} that was submitted"
            )


class _SubmittedValues(HTMLParser):
    """Every form control's current value, by name: `value=` for an input,
    the selected `<option>` for a select, the body for a textarea.

    A textarea's body is taken **verbatim except for one leading newline**,
    which is what a browser does with it (HTML parses away a single `\\n`
    immediately after the open tag and no other whitespace). Stripping it
    instead is wrong in the direction that matters here: a PEM ends in a
    newline, that newline is part of what was submitted, and a helper that
    trimmed it would report a re-filled textarea as lost on every one of
    these four pages. Trailing whitespace a browser would resubmit is
    therefore preserved and compared.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}
        self._textarea: str | None = None
        self._select: str | None = None
        self._option: str | None = None
        self._buffer = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        if tag == "input" and found.get("name") and found.get("type") != "hidden":
            self.values[found["name"] or ""] = found.get("value") or ""
        elif tag == "textarea" and found.get("name"):
            self._textarea = found["name"]
            self._buffer = ""
        elif tag == "select" and found.get("name"):
            self._select = found["name"]
        elif tag == "option" and self._select is not None:
            self._option = found.get("value")
            if "selected" in found:
                self.values[self._select] = found.get("value") or ""

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._buffer += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "textarea" and self._textarea is not None:
            body = self._buffer
            self.values[self._textarea] = body[1:] if body.startswith("\n") else body
            self._textarea = None
        elif tag == "select":
            self._select = None
        elif tag == "option":
            self._option = None


def _submitted_values(html: str) -> dict[str, str]:
    parser = _SubmittedValues()
    parser.feed(html)
    return parser.values


# --- AC-8 ------------------------------------------------------------------


class _Buttons(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.buttons: list[dict[str, str | None]] = []
        self._form_action: str | None = None
        self._form_hx: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        if tag == "form":
            self._form_action = found.get("action")
            self._form_hx = [name for name in found if name.startswith("hx-")]
        elif tag == "button":
            self.buttons.append(
                {
                    "type": found.get("type"),
                    "class": found.get("class"),
                    "formaction": found.get("formaction"),
                    "formmethod": found.get("formmethod"),
                    "form_action": self._form_action,
                    "form_hx": ",".join(self._form_hx),
                    "hx": ",".join(name for name in found if name.startswith("hx-")),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form_action = None
            self._form_hx = []


def _buttons(html: str) -> list[dict[str, str | None]]:
    parser = _Buttons()
    parser.feed(html)
    return parser.buttons


def test_the_forms_work_with_javascript_off(client: TestClient, cfg: Config) -> None:
    """AC-8: no page silently does nothing.

    No `HX-Request` header is sent anywhere in this test, deliberately: this
    is the whole session of an operator whose browser runs no JavaScript, and
    at the end of it a certificate exists.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)

    for preview_url, (mutation_url, page_url) in PREVIEWS.items():
        page = client.get(page_url)
        assert page.status_code == 200, f"{page_url} -> {page.status_code}"
        buttons = _buttons(page.text)

        checks = [b for b in buttons if b["formaction"] == preview_url]
        assert len(checks) == 1, (
            f"{page_url} carries {len(checks)} submit buttons whose formaction is "
            f"{preview_url}; FR-12 asks for exactly one"
        )
        check = checks[0]
        assert check["type"] == "submit", f"the Check button on {page_url} is {check['type']!r}"
        assert check["formmethod"] == "post", (
            f"the Check button on {page_url} has formmethod={check['formmethod']!r}"
        )
        assert check["form_action"] == mutation_url, (
            f"the Check button on {page_url} sits in a form whose action is "
            f"{check['form_action']!r}, not the mutation's {mutation_url!r}"
        )
        assert check["form_hx"] == "", (
            f"the form on {page_url} carries {check['form_hx']} -- FR-12: neither "
            f"issue form is ever run through htmx"
        )

        primaries = [
            b
            for b in buttons
            if b["form_action"] == mutation_url and (b["class"] or "").split() == ["primary"]
        ]
        assert len(primaries) == 1, f"{page_url} has {len(primaries)} primary buttons"
        assert primaries[0]["formaction"] is None, (
            f"{page_url}'s primary button was repointed at a preview URL: "
            f"{primaries[0]['formaction']}"
        )
        assert primaries[0]["hx"] == "", (
            f"{page_url}'s primary button carries {primaries[0]['hx']} (FR-12)"
        )

        replayed = client.post(preview_url, data=_payload(preview_url, fix, cfg, client))
        assert replayed.status_code == 200, f"{preview_url} -> {replayed.status_code}"
        assert "<html" in replayed.text, f"{preview_url} answers no page to the Check button"

    # ...and the primary path still works, with no htmx anywhere in sight.
    before = _count(cfg, Certificate)
    issued = client.post("/certs/issue", data=_issue_form(fix, cfg, client))
    assert issued.status_code == 303, issued.text
    assert _count(cfg, Certificate) == before + 1


# --- AC-9 ------------------------------------------------------------------


def _routed(app: Any) -> list[Any]:
    """Every routed endpoint reachable from `app`, whatever it is wrapped in.

    `app.routes` is not the route table in this FastAPI: every
    `include_router` leaves one `_IncludedRouter` object whose own `path` is
    `None` and whose members live on `original_router`. A flat scan of
    `app.routes` therefore finds **no** route for any included path -- not
    only for the four this spec adds -- so the version of AC-9 clause 2 that
    did one reported "no such route" whatever the code did. That is the
    failure mode this whole file is written against, so the walker recurses
    and `_route_handler` proves on a route that already existed that it can
    find anything at all.
    """
    seen: set[int] = set()
    found: list[Any] = []

    def walk(obj: Any) -> None:
        if id(obj) in seen:
            return
        seen.add(id(obj))
        for route in getattr(obj, "routes", []):
            if getattr(route, "path", None) is not None and getattr(route, "methods", None):
                found.append(route)
            walk(route)
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(inner)

    walk(app)
    return found


def _route_handler(client: TestClient, path: str, method: str) -> Callable[..., Any]:
    routes = _routed(client.app)
    control = [r for r in routes if r.path == "/ca/import" and "POST" in r.methods]
    assert len(control) == 1, (
        f"the route walker found {len(control)} routes for the pre-existing "
        f"POST /ca/import, so it cannot find anything and a zero below would say "
        f"nothing about the endpoint under test"
    )
    matches = [r for r in routes if r.path == path and method in r.methods]
    assert len(matches) == 1, f"expected one {method} {path} route, found {len(matches)}"
    return matches[0].endpoint  # type: ignore[no-any-return]


def test_the_import_preview_ships_no_secret(client: TestClient, cfg: Config) -> None:
    """AC-9: parsed from the template, read off the signature, measured as
    effect -- three clauses that fail in three different ways.

    The include list is asserted **by name**. `key_pem` not appearing in the
    markup is not the assertion: `hx-include="closest form"` contains neither
    string and ships both.
    """
    _setup_superadmin(client)
    _seed(cfg)
    source = (TEMPLATES_DIR / "transfer_ca_import.html").read_text()

    includes = re.findall(r'hx-include="([^"]*)"', source)
    assert includes == ["#csrf-ca-import, #cert_pem, #chain_pem"], (
        f"transfer_ca_import.html's hx-include is {includes}, not the three ids "
        f"FR-11 clause 2 writes out literally"
    )
    assert "closest form" not in source, (
        "`closest form` appears in transfer_ca_import.html: this form holds a CA "
        "private key and its passphrase, and including the form includes both"
    )
    triggers = re.findall(r'hx-trigger="([^"]*)"', source)
    assert len(triggers) == 1, f"expected one hx-trigger on this page, got {triggers}"
    trigger = triggers[0]
    assert "#cert_pem" in trigger and "#chain_pem" in trigger, (
        f"hx-trigger={trigger!r} does not name the two textareas it debounces on"
    )
    assert "key_pem" not in trigger and "key_passphrase" not in trigger, (
        f"hx-trigger={trigger!r} fires on the private key or its passphrase: "
        f"typing a passphrase would send a request per keystroke (FR-11 clause 1)"
    )
    assert 'id="csrf-ca-import"' in source, (
        "the hidden CSRF input has no id, so the token cannot be included by name "
        "and only the whole form would do (FR-11 clause 2)"
    )

    parameters = inspect.signature(_route_handler(client, "/ca/import/preview", "POST")).parameters
    forbidden = [name for name in parameters if name in {"key_pem", "key_passphrase"}]
    assert forbidden == [], (
        f"POST /ca/import/preview declares {forbidden}: a parameter that exists is "
        f"a parameter something can echo (FR-11 clause 3)"
    )

    key_pem = _encrypted_key_pem("hunter2")
    audit_before = _count(cfg, AuditEvent)
    resp = client.post(
        "/ca/import/preview",
        data=_import_form(cfg, client, key_pem=key_pem, key_passphrase="hunter2"),
    )
    assert resp.status_code == 200, resp.text
    assert "hunter2" not in resp.text, "the passphrase came back in the preview's response"
    for line in key_pem.splitlines():
        if len(line.strip()) > 16:
            assert line.strip() not in resp.text, (
                f"a line of the private key came back in the preview's response: "
                f"{line.strip()[:24]}…"
            )
    assert _count(cfg, AuditEvent) == audit_before, "the import preview wrote an audit event"


# --- AC-10 -----------------------------------------------------------------


def test_the_sign_panel_parses_and_says_when_it_cannot(client: TestClient, cfg: Config) -> None:
    """AC-10: a preview that fails on bad input fails on every keystroke of a
    half-typed one, so an unparsable paste is a 200 with a message in it."""
    _setup_superadmin(client)
    fix = _seed(cfg)

    sans = [x509.DNSName(f"one.{PERMITTED_DNS}"), x509.IPAddress(ipaddress.ip_address("10.0.0.9"))]
    csr_pem = _csr_pem(f"csr.{PERMITTED_DNS}", sans)
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    expected = leaf_mod.san_strings(
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    )
    assert len(expected) == 2, expected

    good = client.post("/certs/sign/preview", data=_sign_form(fix, cfg, client, csr_pem=csr_pem))
    assert good.status_code == 200, good.text
    panel = _panel(good.text, "Parsed request")
    values = _values(panel, "Subject", "SANs", "Key")
    assert f"csr.{PERMITTED_DNS}" in values["Subject"], (
        f"the panel's Subject is {values['Subject']!r} and the CSR's CN is csr.{PERMITTED_DNS}"
    )
    panel_texts = " ".join(_texts(panel))
    for entry in expected:
        assert entry in panel_texts, (
            f"the panel does not name {entry!r}, which leaf.san_strings reads out of "
            f"this CSR's own SAN extension: {panel_texts}"
        )
    assert values["Key"] != "—", "the panel says nothing about the CSR's key"

    broken = client.post(
        "/certs/sign/preview", data=_sign_form(fix, cfg, client, csr_pem="not a csr")
    )
    assert broken.status_code == 200, (
        f"an unparsable paste answered {broken.status_code}; a preview reports what "
        f"it found, and 'this is not a PEM block' is a successful preview"
    )
    broken_panel = _panel(broken.text, "Parsed request")
    assert _error_box(broken.text) is None, (
        f"the parse failure landed in the page's own error box, which belongs to "
        f"POST /certs/sign: {_error_box(broken.text)!r}"
    )
    assert set(_texts(broken_panel)) - {"Parsed request", "Subject", "SANs", "Key", "—"}, (
        f"the panel names no failure at all for an unparsable CSR: {_texts(broken_panel)}"
    )

    empty = client.post("/certs/sign/preview", data=_sign_form(fix, cfg, client, csr_pem=""))
    assert empty.status_code == 200, empty.text
    blank = _values(_panel(empty.text, "Parsed request"), "Subject", "SANs", "Key")
    assert set(blank.values()) == {"—"}, f"an empty paste renders {blank}, not the design's dashes"


# --- AC-11 -----------------------------------------------------------------


def test_the_create_panel_flips_tone_with_path_length(client: TestClient, cfg: Config) -> None:
    """AC-11: both tones in one criterion, because a build that renders one
    tone always would otherwise pass."""
    _setup_superadmin(client)
    _seed(cfg)
    hint = PATH_LENGTH_HINT

    for path_length, expect_warning in ((2, False), (1, True)):
        form = _create_form(cfg, client, path_length=path_length)
        resp = client.post("/ca/create/preview", data=dict(form))
        assert resp.status_code == 200, resp.text

        marker = hint[:40]
        assert marker in resp.text, (
            f"the path-length note is not on the page at all at path_length="
            f"{path_length}; FR-9 moves ca_new.html:45's hint into the panel column"
        )
        note = _row(resp.text, marker, class_name="callout", tag=None)
        classes = re.search(r'class="([^"]*)"', note.split(">", 1)[0])
        assert classes is not None
        tokens = classes.group(1).split()
        assert ("warning" in tokens) is expect_warning, (
            f"at path_length={path_length} the note carries {tokens}; FR-9 flips the "
            f"tone with the value -- info-toned at >= 2, warning-toned at 1"
        )
        assert "callout" in tokens, f"the note is not a .callout: {tokens}"
        assert " ".join(_texts(note)) == hint, (
            f"the sentence in the note is not the sentence ca_new.html:45 carried "
            f"before FR-9 moved it. FR-14: moving a sentence is not editing it.\n"
            f"  before: {hint!r}\n  after:  {' '.join(_texts(note))!r}"
        )

        panel = _panel(resp.text, "What gets created")
        values = _values(panel, "Root", "Expires", "Issuers", "Key")
        assert values["Root"] == "preview corp", f"Root is {values['Root']!r}"
        assert "ecdsa-p384" in values["Key"], f"Key is {values['Key']!r}"
        expected_year = datetime.now(UTC).year + int(form["root_years"])  # type: ignore[arg-type]
        assert str(expected_year) in values["Expires"], (
            f"Expires is {values['Expires']!r}; now + root_years is {expected_year}"
        )


# --- AC-14: nothing was lost, and the test that said so is retired ---------
#
# `test_no_sentence_changed_on_the_form_pages` lived here. It rendered the six
# form pages twice against one database -- once through the templates as they
# stand and once through the templates as they stood at spec 0029's base
# commit, `b1f5631` -- and asserted that no text node had disappeared and that
# every new one was named in FR-14's table.
#
# It is retired, for the reason spec 0028 retired
# `test_only_layout_html_changed`: what it asserted is **a property of one
# commit, not of the codebase**. "The diff from b1f5631 to the 0029 merge
# removed no sentence from these six pages" was true when it was written, is
# true now, and nothing a later commit does can make it false, so there is no
# regression left for it to catch. Its evidence is the diff, and a diff is
# better evidence than a test here, because it cannot be edited into agreeing
# with the code.
#
# CI is what forced the question rather than what decided it. `b1f5631` is a
# commit on `feat/0.2.0`, the runner's checkout is shallow, and PR #17 may
# squash -- so this failed on the runner while passing locally, and deepening
# the checkout would only have moved the failure to the day the branch merged.
#
# The two halves it asserted do not retire together, and only one of them
# needed a baseline at all.
#
# * *Every addition is named* is asserted positively and by name, on the
#   rendered page, by the criteria above: AC-3's constraint-panel test and
#   the AC-9/AC-10/AC-11 panel tests read each preview panel's heading, its
#   rows and its dashes off the page. A string this spec added that stops
#   being rendered fails there, which is where a reader would look for it.
# * *Nothing is lost* is the half that needed the base commit, and it is the
#   half that is a claim about the diff. It goes with the commit.
#
# Retired, not deleted: what it verified about today's pages is still
# verified, and the criterion it answered is answered by the record of the
# change.


# --- AC-15 -----------------------------------------------------------------

needs_chrome = pytest.mark.skipif(
    not Path(probes.CHROME).exists(), reason="headless Chrome not installed"
)


def _filled_pages(client: TestClient, cfg: Config, fix: Fixture) -> dict[str, str]:
    """The six pages FR-17 names, each with its panel **filled** by a POST
    rather than left at `—`.

    A panel showing a dash is not the panel that can push a page sideways,
    which is the whole reason this criterion re-runs a probe that already
    passes over `/certs/new` today. The SAN is 200 characters and the import
    carries a full PEM subject, which is what a fixed-width aside has to
    survive.
    """
    long_san = ("a" * 60 + ".") + ("b" * 60 + ".") + ("c" * 61 + ".") + PERMITTED_DNS
    assert len(long_san) >= 200, len(long_san)
    pages = {}
    filled = {
        "certs_new": (
            "/certs/issue/preview",
            _issue_form(fix, cfg, client, subject_cn=f"nas.{PERMITTED_DNS}", sans=long_san),
        ),
        "certs_sign": ("/certs/sign/preview", _sign_form(fix, cfg, client)),
        "ca_new": ("/ca/create/preview", _create_form(cfg, client, path_length=1)),
        "transfer_ca_import": ("/ca/import/preview", _import_form(cfg, client)),
    }
    for name, (url, body) in filled.items():
        resp = client.post(url, data=dict(body))
        assert resp.status_code == 200, f"{url} -> {resp.status_code}"
        pages[name] = resp.text
    # ...and the import page a second time with nothing that parses, because
    # AC-15's contrast clause names "the dim unparsed values of FR-10" and the
    # filled render above shows none of them. Without this page the contrast
    # run never sees the state FR-10 is entirely about.
    dim = client.post(
        "/ca/import/preview",
        data=_import_form(cfg, client, cert_pem="not a pem", chain_pem=""),
    )
    assert dim.status_code == 200, f"/ca/import/preview (unparsed) -> {dim.status_code}"
    assert "data-dim" in dim.text, (
        "the import preview renders no dim value for input that does not parse, so "
        "the contrast run below cannot measure FR-10's dim state"
    )
    pages["transfer_ca_import_dim"] = dim.text

    for name, path in (
        ("transfer_cross_import", "/transfer/cross-import"),
        ("ca_detail_open", f"/ca/{fix.alpha_root}?add=intermediate"),
    ):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        pages[name] = resp.text
    return pages


@needs_chrome
def test_the_form_pages_do_not_scroll_sideways(
    client: TestClient, cfg: Config, tmp_path: Path
) -> None:
    """AC-15: with the panels filled, at both widths, in both schemes.

    An aside beside a form is a second column on four pages that had one,
    which is the change that has broken this project's geometry before. The
    contrast run covers the ✓/✕ marks on `--surface` and FR-10's dim
    unparsed values in the same pass, and the stacking probe answers the one
    thing neither of the other two can see: below the breakpoint the aside
    comes *after* the form, so the tab order is the reading order.
    """
    _setup_superadmin(client)
    fix = _seed(cfg)
    pages = _filled_pages(client, cfg, fix)

    # FR-10: the dim state is `--text-muted`, not the design's `#5a5d6b`.
    # Asserted as which token the dim rule reaches for, never as the hex being
    # absent from the file -- `#5a5d6b` is spec 0027's `--disabled`, it is in
    # the brief, and AC-16's palette test fails if it is removed.
    css = (STATIC_DIR / "cabin.css").read_text()
    dim_rules = [(selector, body) for selector, body in css_rules(css) if "[data-dim]" in selector]
    assert dim_rules, (
        "no rule in cabin.css selects the unparsed state, so FR-10's dim values are "
        "either not rendered or not styled at all"
    )
    for selector, body in dim_rules:
        colour = dict(declarations(body)).get("color")
        assert colour == "var(--text-muted)", (
            f"`{selector}` sets color: {colour} for FR-10's dim values. One step "
            f"less faint is `--text-muted`; `{REFUSED_DIM_TOKEN}` ({REFUSED_DIM}) is "
            f"2.4:1 on --surface and these are values an operator is meant to read"
        )
        assert REFUSED_DIM not in body and REFUSED_DIM_TOKEN not in body, (
            f"`{selector}` reaches for {REFUSED_DIM_TOKEN}/{REFUSED_DIM}: {body!r}"
        )

    for scheme in ("dark", "light"):
        for width, height in ((1440, 1150), (390, 900)):
            root = tmp_path / f"overflow-{scheme}-{width}"
            root.mkdir()
            probes.stage(root, STATIC_DIR, pages, probes.OVERFLOW_PROBE, scheme=scheme)
            httpd, port = probes.serve(root)
            try:
                for name in pages:
                    found = probes.overflow(f"http://127.0.0.1:{port}/{name}.html", width, height)
                    assert found["bad"] == [], f"{name} at {width} ({scheme}): {found['bad']}"
                    assert int(found["examined"]) >= 20, (  # type: ignore[call-overload]
                        f"{name} at {width} ({scheme}) examined {found['examined']} "
                        f"elements -- a probe that looks at nothing reports nothing"
                    )
            finally:
                httpd.shutdown()

        contrast_root = tmp_path / f"contrast-{scheme}"
        contrast_root.mkdir()
        probes.stage(contrast_root, STATIC_DIR, pages, probes.CONTRAST_PROBE, scheme=scheme)
        httpd, port = probes.serve(contrast_root)
        try:
            for name in pages:
                found = probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150)
                assert found["bad"] == [], f"{name} ({scheme}): {found['bad']}"
                assert found["examined"] >= 20, f"{name} ({scheme}): {found}"
        finally:
            httpd.shutdown()

    stack_root = tmp_path / "stack"
    stack_root.mkdir()
    probes.stage(stack_root, STATIC_DIR, pages, probes.STACK_PROBE)
    httpd, port = probes.serve(stack_root)
    try:
        wide = {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150) for name in pages
        }
        narrow = {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 390, 900) for name in pages
        }
    finally:
        httpd.shutdown()

    # Keyed on the page rather than on the render: `transfer_ca_import` is
    # staged twice, filled and unparsed, and both carry the split. FR-16's
    # claim is about which *pages* have an aside, and the two that must not
    # are named on the other side so the assertion fails in both directions.
    split_pages = [name for name in pages if wide[name]["examined"]]
    expected_split = {"ca_new", "certs_new", "certs_sign", "transfer_ca_import"}
    assert {name.removesuffix("_dim") for name in split_pages} == expected_split, (
        f"the .form-split/aside pair was found on {sorted(split_pages)}; FR-16 gives "
        f"the cross-import page no aside and FR-13 gives the hierarchy page none"
    )
    assert {"transfer_cross_import", "ca_detail_open"} & set(split_pages) == set(), (
        f"a page FR-16 draws as one column carries a preview aside: {sorted(split_pages)}"
    )

    for name in split_pages:
        for pair in narrow[name]["pairs"]:
            assert pair["asideTop"] > pair["formTop"], (
                f"{name} at 390: the aside is drawn at {pair['asideTop']} and the "
                f"form at {pair['formTop']} -- FR-17 stacks the aside *after* the "
                f"form, so the operator meets the fields first"
            )
        for pair in wide[name]["pairs"]:
            assert pair["asideTop"] <= pair["formTop"], (
                f"{name} at 1440: the aside is below the form ({pair['asideTop']} vs "
                f"{pair['formTop']}) -- the split did not become two columns"
            )
            assert pair["asideLeft"] > pair["formLeft"], (
                f"{name} at 1440: the aside is not beside the form "
                f"({pair['asideLeft']} vs {pair['formLeft']})"
            )
