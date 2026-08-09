"""Spec 0027: the shell, the token layer and the component vocabulary.

The redesign lands in four steps and this is the first: the stylesheet is
rewritten, `layout.html` gains one wrapper and one id, the fonts change, and
**no content template's markup is touched** (FR-18, AC-1). Everything here
therefore measures chrome around content that has not moved.

Three things in this file are worth knowing before reading it.

**The overflow probe had to be repaired before anything else.** The design's
shell is `overflow:hidden`, and the old walker excused any element with a
horizontally-clipping ancestor -- so the moment the shell landed it would
have returned nothing for all nineteen screens at both widths while looking
green. The repair lives in `tests/probes.py` (FR-2/FR-3) and
`test_the_pre_repair_walker_excused_the_whole_page` demonstrates the defect
rather than describing it.

**The contrast checks compute their own ratios.** No figure from the spec or
the brief is hard-coded as an expected result; the WCAG 2.x formula is
implemented here and applied to whatever the stylesheet actually declares.

**The light scheme cannot be forced by a browser flag.** Headless Chrome
reports `prefers-color-scheme: dark` and no switch changes it, so the light
runs are served a copy of `cabin.css` with the media wrapper stripped
(`probes.light_stylesheet`). That is only faithful while the light block
holds one `:root` rule and nothing else, which
`test_light_block_holds_nothing_but_token_overrides` in `test_web_layout.py`
asserts.
"""

import re
import subprocess
from pathlib import Path

import probes
import pytest
from fastapi.testclient import TestClient
from test_web_layout import _populate, page_paths, render_pages

from cabin.app import create_app
from cabin.config import Config

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "src/cabin/web/templates"
STATIC = REPO / "src/cabin/web/static"
CSS = STATIC / "cabin.css"
BRIEF = REPO / "docs/design/0027-brief.md"

#: The commit this spec starts from. AC-1 compares every content template
#: against its content here, which is what makes "the chrome changed and
#: nothing else did" a fact rather than a claim.
BASELINE = "c455922"

#: FR-19: renaming one of these is a deliberate act with an argument, not a
#: side effect of a stylesheet rewrite. Thirty-one assertions across the suite
#: scope by them; a rename would not fail those assertions, it would make them
#: find nothing, which is worse.
LOAD_BEARING = (
    "rail",
    "rail-foot",
    "nav-group",
    "shell",
    "section",
    "scroller",
    "tag",
    "note",
    "constraints",
    "error",
    "card-narrow",
)


# --------------------------------------------------------------------------
# stylesheet parsing
# --------------------------------------------------------------------------


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def css_rules(text: str) -> list[tuple[str, str]]:
    """Every rule in the stylesheet as ``(selector, body)``, at-rules flattened.

    Parsed rather than pattern-matched because FR-20's reverse direction has
    to distinguish a class selector from the string `woff2` inside
    `url("…/PublicSans.woff2")`, which a bare ``re.findall(r"\\.([\\w-]+)")``
    over the whole file cannot -- it would report a font filename as an
    unused class forever.
    """
    rules: list[tuple[str, str]] = []

    def walk(chunk: str) -> None:
        depth = 0
        start = 0
        selector = ""
        body_start = 0
        for i, ch in enumerate(chunk):
            if ch == "{":
                if depth == 0:
                    selector = chunk[start:i].strip()
                    body_start = i + 1
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = chunk[body_start:i]
                    if selector.startswith("@"):
                        walk(body)
                    else:
                        rules.append((selector, body))
                    start = i + 1

    walk(strip_comments(text))
    return rules


def class_selectors(text: str) -> set[str]:
    """Every class name that a rule in the stylesheet actually selects."""
    names: set[str] = set()
    for selector, _body in css_rules(text):
        names.update(re.findall(r"\.([a-zA-Z][\w-]*)", selector))
    return names


_DECL_RE = re.compile(r"([-\w]+)\s*:\s*([^;{}]+)")


def declarations(body: str) -> list[tuple[str, str]]:
    return [(name, " ".join(value.split())) for name, value in _DECL_RE.findall(body)]


def norm(value: str) -> str:
    """A colour or length in one canonical spelling.

    ``rgba(233, 233, 237, 0.08)`` in the brief and ``rgba(233,233,237,.08)``
    in the stylesheet are the same colour, and a test that says otherwise is
    testing the whitespace.
    """
    text = " ".join(value.split()).lower().rstrip(";").strip()
    match = re.fullmatch(r"rgba?\(([^)]*)\)", text)
    if match:
        parts = [p for p in re.split(r"[,\s/]+", match.group(1)) if p]
        nums = [float(p) for p in parts]
        if len(nums) == 3:
            nums.append(1.0)
        return "rgba(" + ",".join(f"{n:g}" for n in nums) + ")"
    if re.fullmatch(r"#[0-9a-f]{3}", text):
        return "#" + "".join(c * 2 for c in text[1:])
    return text


def is_colour(value: str) -> bool:
    return norm(value).startswith(("#", "rgba(", "hsl", "color(", "lab(", "oklch("))


def token_block(text: str, start: int) -> str:
    open_brace = text.index("{", start)
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : i]
    raise AssertionError("unbalanced braces")


def tokens_in(block: str) -> dict[str, str]:
    return {name: norm(value) for name, value in declarations(block) if name.startswith("--")}


def dark_tokens(text: str) -> dict[str, str]:
    """The default ``:root`` -- which is the dark scheme now (FR-8)."""
    return tokens_in(token_block(text, text.index(":root")))


def light_tokens(text: str) -> dict[str, str]:
    """The effective light palette: the defaults with the overrides applied."""
    media = text.find(probes._LIGHT_MEDIA)
    assert media != -1, f"cabin.css has no {probes._LIGHT_MEDIA} block (spec 0027 FR-8)"
    block = token_block(text, media)
    overrides = tokens_in(token_block(block, block.index(":root")))
    return {**dark_tokens(text), **overrides}


# --------------------------------------------------------------------------
# WCAG 2.x, computed here rather than quoted from the spec
# --------------------------------------------------------------------------


def rgb(value: str) -> tuple[float, float, float]:
    text = norm(value)
    if text.startswith("#"):
        assert len(text) == 7, f"not a colour: {value!r}"
        return tuple(int(text[i : i + 2], 16) for i in (1, 3, 5))  # type: ignore[return-value]
    match = re.fullmatch(r"rgba\(([^)]*)\)", text)
    assert match is not None, f"not a colour: {value!r}"
    nums = [float(p) for p in match.group(1).split(",")]
    assert nums[3] == 1, f"{value!r} is translucent; contrast needs a ground"
    return nums[0], nums[1], nums[2]


def luminance(value: str) -> float:
    channels = []
    for raw in rgb(value):
        c = raw / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


#: FR-12 rule 1's second half, and AC-7's list of pairs: which text token is
#: drawn on which ground. The six body-text tokens sit on the page; the two
#: faint steps additionally sit on the recessed surface and the hover tint;
#: `--text-faint` and the disarmed danger label sit on the raised panel.
RAMP = ("--text", "--text-2", "--text-3", "--text-muted", "--text-faint", "--text-hint")

TEXT_ON_GROUND: tuple[tuple[str, str], ...] = (
    *((token, "--bg") for token in RAMP),
    ("--text-faint", "--surface-low"),
    ("--text-faint", "--surface-hover"),
    ("--text-faint", "--surface"),
    ("--text-hint", "--surface-low"),
    ("--text-hint", "--surface-hover"),
    ("--danger-disarmed-fg", "--surface"),
)

#: FR-12 rule 1's first half. `--surface-hover` is deliberately absent: it is
#: 1.0241 from `--surface-low` in the design's own values, being a hover tint
#: rather than a fourth ground, and folding it in would replace one rule the
#: design violates with another.
GROUNDS = ("--bg", "--surface-low", "--surface")

#: The floor the three grounds must clear pairwise. Above the 1.0241 step the
#: design itself treats as a tint, below the 1.0517 its tightest real pair
#: reaches.
GROUND_FLOOR = 1.04


def ground_defects(tokens: dict[str, str]) -> list[str]:
    """Every pair of grounds too close to be two grounds (FR-12 rule 1)."""
    defects = []
    for i, first in enumerate(GROUNDS):
        for second in GROUNDS[i + 1 :]:
            ratio = contrast(tokens[first], tokens[second])
            if ratio < GROUND_FLOOR:
                defects.append(
                    f"{first} {tokens[first]} and {second} {tokens[second]} are only "
                    f"{ratio:.4f}:1 apart, under the {GROUND_FLOOR} floor -- they are "
                    f"one ground, or a step no screen resolves"
                )
    return defects


def text_clearance_defects(tokens: dict[str, str]) -> list[str]:
    """Every text token that fails 4.5:1 on a ground it is drawn on."""
    defects = []
    for token, ground in TEXT_ON_GROUND:
        ratio = contrast(tokens[token], tokens[ground])
        if ratio < 4.5:
            defects.append(
                f"{token} {tokens[token]} is {ratio:.2f}:1 on {ground} "
                f"{tokens[ground]}, and it is drawn there"
            )
    return defects


def grey_at_ratio(base: str, target: float) -> str:
    """The grey whose contrast against `base` comes closest to `target`.

    Used only to build the two counter-checks below. A rule stated as a floor
    that everything already clears measures nothing, so each floor is shown to
    reject a *near miss* -- a ground 1.03:1 from the page, a label 4.4:1 on the
    panel -- rather than only an absurd value like an identical colour.
    """
    greys = ["#" + f"{channel:02x}" * 3 for channel in range(256)]
    return min(greys, key=lambda grey: abs(contrast(grey, base) - target))


# --------------------------------------------------------------------------
# the checked-in brief
# --------------------------------------------------------------------------


def brief_tokens() -> dict[str, str]:
    """The token block in section 10 of `docs/design/0027-brief.md`."""
    text = BRIEF.read_text()
    at = text.index("## 10.")
    fence = text.index("```css", at)
    end = text.index("```", fence + 6)
    return tokens_in(token_block(text[fence:end], 0))


def section_one_colours() -> set[str]:
    """Every colour literal the brief's section 1 names in a table row.

    AC-6's third provenance. Section 10 calls itself a *suggested* token set
    and omits one colour the Interface Contract requires --
    `--danger-disarmed-line: #3a2b30`, which section 1's text table carries as
    "Disarmed danger-button border, paired with `#6d5259`". Section 1 is where
    the colours of this design actually come from, so it is provenance; the
    clause is narrow (it cannot re-value a token section 10 already names) so
    a nudged colour still fails.
    """
    text = BRIEF.read_text()
    body = text[text.index("## 1. Palette") : text.index("## 2. Typography")]
    found = set()
    for line in body.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        for literal in re.findall(r"`(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))`", line):
            found.add(norm(literal))
    return found


def register_rows() -> list[tuple[str, str, str, str]]:
    """The palette register in the brief's header: the deliberate divergences.

    ``token | brief value | shipped value | reason``. FR-1's rule is that a
    departure from the design is made by editing that file, with the reason
    beside the value, in the same change as the stylesheet -- so a colour
    nudged in `cabin.css` alone cannot pass, and a later change of mind shows
    up as a diff someone can read.
    """
    text = BRIEF.read_text()
    start = text.index("### Divergence register — palette")
    end = text.index("### Divergence register — everything else")
    rows = []
    for line in text[start:end].splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not cells[0].startswith("`--"):
            continue
        rows.append(
            (
                cells[0].strip("`"),
                norm(cells[1].strip("`")),
                norm(cells[2].strip("`")),
                cells[3],
            )
        )
    return rows


# --------------------------------------------------------------------------
# the rendered pages, built once for the whole module
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """The nineteen screens, with the data that makes them wide.

    Built once per module rather than per test: `_populate` generates six key
    pairs and signs a cross certificate, and every probe below wants the same
    pages. TLS is on for the reason `test_no_horizontal_overflow` gives --
    `settings.html`'s issuer `<select>` does not render otherwise.
    """
    tmp = tmp_path_factory.mktemp("design-pages")
    data_dir = tmp / "data"
    cfg = Config(port=8080, data_dir=data_dir, db_url=f"sqlite:///{data_dir}/cabin.db", tls=True)
    with TestClient(create_app(cfg), follow_redirects=False) as client:
        cert_path = _populate(client, cfg, second_issuer=True)
        return render_pages(client, page_paths(cfg, cert_path))


needs_chrome = pytest.mark.skipif(
    not Path(probes.CHROME).exists(), reason="headless Chrome not installed"
)


def one_page(tmp_path: Path, name: str, html: str, probe: str, scheme: str = "dark") -> object:
    root = tmp_path / f"page-{name}-{scheme}"
    root.mkdir(parents=True, exist_ok=True)
    probes.stage(root, STATIC, {name: html}, probe, scheme)
    httpd, port = probes.serve(root)
    try:
        return probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 900)
    finally:
        httpd.shutdown()


# === AC-2: the probe examines the page, and can still be made to fail ======


@needs_chrome
def test_the_overflow_probe_reports_what_it_examined(
    rendered: dict[str, str], tmp_path: Path
) -> None:
    """FR-4: a bare list of offenders cannot tell "nothing is broken" from
    "nothing was looked at". The counter is what separates the two."""
    found = one_page(tmp_path, "certs", rendered["certs"], probes.OVERFLOW_PROBE)
    assert isinstance(found, dict)
    assert found["bad"] == []
    assert int(found["examined"]) >= 20, (
        f"the repaired probe examined {found['examined']} elements on /certs -- "
        f"the floor is twenty times what a walker that excuses the page leaves, "
        f"so this is a probe that has stopped measuring: {found}"
    )


@needs_chrome
def test_the_overflow_probe_catches_a_planted_overflow(
    rendered: dict[str, str], tmp_path: Path
) -> None:
    """AC-2: a probe that cannot be made to fail is not evidence.

    The 4000px div is planted inside `<main>`, which the design clips with
    `overflow-x: hidden`. Clipping is exactly why the old walker would have
    excused it; `getBoundingClientRect` reports layout geometry, so the
    repaired probe still sees it.
    """
    html = rendered["certs"].replace("</main>", '<div style="width:4000px">x</div></main>')
    assert html != rendered["certs"], "the planted div was not inserted"
    found = one_page(tmp_path, "planted", html, probes.OVERFLOW_PROBE)
    assert isinstance(found, dict)
    assert found["bad"] != [], (
        "a 4000px-wide div inside the shell was not reported -- the probe "
        "cannot go red, which is the failure mode this spec is guarding against"
    )


#: The walker exactly as it stood at `c455922`, kept as a literal so that the
#: defect can be demonstrated instead of described. It counts only; the
#: comparison half is left out so that the container walker keeps having
#: exactly one definition in the whole suite (AC-4).
PRE_REPAIR_WALKER = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function scrollable(el) {
      for (var p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        var ox = getComputedStyle(p).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden') return true;
      }
      return false;
    }
    var seen = 0, skipped = 0;
    document.querySelectorAll('body *').forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (scrollable(el)) { skipped++; return; }
      seen++;
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({examined: seen, excused: skipped});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


@needs_chrome
def test_the_pre_repair_walker_excused_the_whole_page(
    rendered: dict[str, str], tmp_path: Path
) -> None:
    """AC-2's third half: the defect, demonstrated on the shipped shell.

    `.shell` is `overflow:hidden` and `<main>` scrolls, so under the old
    walker every element on every page has a horizontally-clipping ancestor
    and is excused. Only `.shell` itself -- whose parent is `<body>`, where
    the walk stops -- survives. The old probe would have reported `[]` for
    all nineteen screens at both widths and `assert offenders == {}` would
    have passed while measuring nothing.
    """
    found = one_page(tmp_path, "certs", rendered["certs"], PRE_REPAIR_WALKER)
    assert isinstance(found, dict)
    assert int(found["excused"]) > 0, f"nothing was excused at all: {found}"
    assert int(found["examined"]) <= 5, (
        f"the pre-repair walker still examined {found['examined']} elements. Either "
        f"the shell is not in place, or it does not clip -- and if it does not "
        f"clip, the repair in tests/probes.py was not needed: {found}"
    )


# === AC-4: the probe has one definition ====================================


def test_the_probe_has_one_definition() -> None:
    """FR-2: two identical copies is how the second one came to exist.

    A repair applied to one of them would have left the other vacuously
    green over nine CA and transfer pages -- the same defect this spec exists
    to fix, one level up.
    """
    needle = "function " + "container("
    hits = {
        path.name: path.read_text().count(needle)
        for path in sorted((REPO / "tests").glob("*.py"))
        if path.read_text().count(needle)
    }
    assert hits == {"probes.py": 1}, hits

    for name in ("test_web_layout.py", "test_ca_names_and_actions.py"):
        source = (REPO / "tests" / name).read_text()
        assert "import probes" in source, f"{name} does not import the shared probe"
        assert "probes.OVERFLOW_PROBE" in source, f"{name} does not use the shared probe"


# === AC-5: the horizontal-scroll set is exactly {.scroller} ================


def test_only_the_scroller_scrolls_sideways() -> None:
    """Spec 0015 FR-4, re-asserted and tightened (FR-5).

    `pre.pem` loses its `overflow-x: auto` -- the design's PEM block wraps
    (`white-space: pre-wrap; word-break: break-all`, brief section 6.9), so
    it no longer needs the exemption. That leaves `.scroller` as the only
    element permitted to scroll sideways, which is what makes the probe's
    allow-list comparable against the stylesheet: the two cannot drift apart
    without one of them failing.
    """
    text = CSS.read_text()
    sideways = set()
    main_rules: list[tuple[str, str]] = []
    pem_rules: list[tuple[str, str]] = []
    for selector, body in css_rules(text):
        for name, value in declarations(body):
            if name == "overflow-x" and value in {"auto", "scroll"}:
                sideways.add(selector)
            if name == "overflow" and value.split()[0] in {"auto", "scroll"}:
                sideways.add(selector)
        if re.search(r"(^|[\s,>#])main\b", selector):
            main_rules.append((selector, body))
        if "pem" in selector:
            pem_rules.append((selector, body))

    assert sideways == {".scroller"}, (
        f"exactly one construct may scroll sideways; these do: {sorted(sideways)}"
    )

    allow = re.search(r'closest\("([^"]+)"\)', probes.OVERFLOW_PROBE)
    assert allow is not None, "the overflow probe has no allow-list selector"
    assert {allow.group(1)} == sideways, (
        f"the probe excuses {allow.group(1)!r} but the stylesheet lets "
        f"{sorted(sideways)} scroll -- the allow-list and the stylesheet have drifted"
    )

    main_decls = dict(decl for _sel, body in main_rules for decl in declarations(body))
    assert main_decls.get("overflow-y") == "auto", main_decls
    assert main_decls.get("overflow-x") == "hidden", (
        "main is not overflow-x: hidden -- a <main> that scrolls horizontally "
        f"is a page that scrolls sideways with extra steps: {main_decls}"
    )

    pem_decls = dict(decl for _sel, body in pem_rules for decl in declarations(body))
    assert pem_rules, "no rule for the PEM block at all"
    assert "overflow-x" not in pem_decls and "overflow" not in pem_decls, pem_decls
    assert pem_decls.get("white-space") == "pre-wrap", pem_decls


# === AC-6: the palette equals the checked-in brief =========================


def test_the_palette_equals_the_checked_in_brief() -> None:
    """FR-1/FR-10: "matches the design" is a comparison, not an opinion.

    Both directions. A token the brief names and `:root` omits fails; a
    colour-valued token in `:root` that neither the brief nor the register
    names fails. Without this the palette is 76 screenshots and an opinion,
    and a colour quietly nudged in the stylesheet alone can pass.
    """
    assert BRIEF.exists(), "the brief is not checked in (FR-1)"
    brief = brief_tokens()
    assert len(brief) > 30, f"section 10 of the brief parsed to {len(brief)} tokens"

    rows = register_rows()
    assert len(rows) == 3, f"the palette register has {len(rows)} rows, not three: {rows}"
    for name, brief_value, shipped, reason in rows:
        assert name.startswith("--"), name
        assert brief_value and shipped, (name, brief_value, shipped)
        assert brief_value != shipped, f"{name} is registered as a divergence but does not diverge"
        assert len(reason.strip()) > 20, f"{name} has no reason beside it: {reason!r}"

    expected = dict(brief)
    for name, _brief_value, shipped, _reason in rows:
        expected[name] = shipped

    root = dark_tokens(CSS.read_text())
    wrong = {
        name: (value, root.get(name)) for name, value in expected.items() if root.get(name) != value
    }
    assert wrong == {}, f"token: (brief/register, :root) -- {wrong}"

    # Clause 3: a token section 10 does not name at all is legal when its
    # shipped value is one of the colours section 1 inventories. It cannot
    # re-value a token section 10 already names, so `expected` is checked
    # first and a nudged colour still fails above.
    inventoried = section_one_colours()
    assert len(inventoried) > 20, f"section 1 parsed to {len(inventoried)} colours"
    unnamed = {
        name: value
        for name, value in root.items()
        if is_colour(value)
        and name not in expected
        and not (name not in brief and value in inventoried)
    }
    assert unnamed == {}, (
        f"these colours are in :root and have no provenance in the brief -- not "
        f"section 10, not the register, not a colour section 1 names: {unnamed}"
    )


# === AC-7: the three lifted colours reach the floor ========================


def test_the_lifted_colours_reach_the_floor() -> None:
    """FR-11: three colours are lifted, and the exemption for the others is
    made checkable rather than asserted.

    The ratios are computed here with the WCAG 2.x formula rather than taken
    from the spec's table, because a figure copied from a plan is not a
    measurement. `--text-faint` is checked against all four grounds it is
    drawn on: a value lifted to 4.5:1 against the page ground only and then
    used on a panel is exactly the failure the second and third grounds
    catch.
    """
    text = CSS.read_text()
    root = dark_tokens(text)
    for token, ground in TEXT_ON_GROUND:
        for name in (token, ground):
            assert name in root, f"{name} is not declared"

    # One list of "which text sits on which ground", shared with AC-8, which
    # re-runs it against the derived light values. Two copies of it would be
    # two things to keep in step, and the weaker one would win.
    assert text_clearance_defects(root) == [], (
        f"WCAG 1.4.3 wants 4.5:1 for text under 18.66px and every one of these "
        f"is drawn at 10-12px: {text_clearance_defects(root)}"
    )

    # Each lifted value must actually differ from the design's, or the
    # register is recording a divergence that was never made.
    for name, brief_value, shipped, _reason in register_rows():
        assert root[name] == shipped != brief_value, (name, root.get(name), shipped, brief_value)

    # FR-21: the WCAG exemption for `--text-disabled` is a fact about the
    # stylesheet, not a claim about intent.
    misused = [
        selector
        for selector, body in css_rules(text)
        if "--text-disabled" in body
        and ":root" not in selector
        and not re.search(r":disabled|\[disabled\]|\[aria-disabled=\"true\"\]", selector)
    ]
    assert misused == [], (
        f"--text-disabled is 2.9:1 and exempt only because it is on a disabled "
        f"control; these rules use it elsewhere: {misused}"
    )


# === AC-8: the light palette is derived, not inverted ======================


def test_the_light_palette_is_derived_not_inverted() -> None:
    """FR-12: a naive inversion breaks the derivation, and the checks bite.

    Rule 1, in both schemes. The three grounds stay three grounds -- every
    pair at least 1.04:1 apart, so none of them can collapse into another or
    into a step no screen resolves -- and each of them is a ground its own
    text clears at 4.5:1. AC-7 asserts the second half for the dark scheme;
    this is what carries it into the light one, where the values are derived
    rather than given.

    Rule 2: six body-text tokens strictly ordered by contrast against the page
    ground, in both schemes, with no light step weaker than its dark
    counterpart. This is the clause that catches an inverted palette --
    inversion leaves three distinct tones, so distinctness does not disturb
    it, but dark-scheme greys inverted onto a light ground come out below
    their dark counterparts' ratios.

    Rule 3: `#9184d9` is 3.23:1 on white, which is a fine focus ring and not
    link text, so the light scheme takes its own three accent values.
    """
    text = CSS.read_text()
    schemes = {"dark": dark_tokens(text), "light": light_tokens(text)}

    for scheme, tokens in schemes.items():
        assert ground_defects(tokens) == [], f"{scheme}: {ground_defects(tokens)}"
        assert text_clearance_defects(tokens) == [], f"{scheme}: {text_clearance_defects(tokens)}"

    ratios = {}
    for scheme, tokens in schemes.items():
        ratios[scheme] = [contrast(tokens[name], tokens["--bg"]) for name in RAMP]
        ordered = ratios[scheme]
        assert ordered == sorted(ordered, reverse=True) and len(set(ordered)) == len(ordered), (
            f"{scheme}: the text ramp is not a ramp: "
            f"{dict(zip(RAMP, [round(r, 2) for r in ordered], strict=True))}"
        )
    weaker = {
        name: (round(light, 2), round(dark, 2))
        for name, light, dark in zip(RAMP, ratios["light"], ratios["dark"], strict=True)
        if light < dark - 0.005
    }
    assert weaker == {}, f"light steps weaker than their dark counterparts: {weaker}"

    for scheme, tokens in schemes.items():
        for ground in GROUNDS:
            accent = contrast(tokens["--accent"], tokens[ground])
            assert accent >= 3, (
                f"{scheme}: --accent {tokens['--accent']} is {accent:.2f}:1 on "
                f"{ground}; WCAG 1.4.11 wants 3:1 for a focus ring"
            )
            link = contrast(tokens["--accent-text"], tokens[ground])
            assert link >= 4.5, (
                f"{scheme}: --accent-text {tokens['--accent-text']} is "
                f"{link:.2f}:1 on {ground}, and it is the link colour"
            )

    assert schemes["light"]["--accent"] != schemes["dark"]["--accent"], (
        "the light accent is the dark one -- #9184d9 is 3.23:1 on white, so a "
        "mirrored accent is a link colour nobody can read"
    )

    # Counter-check, both rules, on the shipped values. A floor everything
    # already clears measures nothing, so each is shown to reject a near miss
    # rather than only a collapse.
    for scheme, tokens in schemes.items():
        near = grey_at_ratio(tokens["--bg"], 1.03)
        gap = contrast(near, tokens["--bg"])
        assert 1.0 < gap < GROUND_FLOOR, f"{scheme}: the counter-check grey is {gap:.4f}:1"
        assert ground_defects({**tokens, "--surface-low": near}) != [], (
            f"{scheme}: a --surface-low {gap:.4f}:1 from the page was accepted as a "
            f"distinct ground -- the {GROUND_FLOOR} floor does not bite"
        )

        dim = grey_at_ratio(tokens["--surface"], 4.4)
        reach = contrast(dim, tokens["--surface"])
        assert 4.0 < reach < 4.5, f"{scheme}: the counter-check grey is {reach:.2f}:1"
        assert text_clearance_defects({**tokens, "--text-faint": dim}) != [], (
            f"{scheme}: a --text-faint at {reach:.2f}:1 on --surface was accepted -- "
            f"the 4.5:1 clearance rule does not bite"
        )


# === AC-10: contrast holds on the rendered page, in both schemes ===========


@needs_chrome
@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_contrast_holds_on_every_rendered_page(
    rendered: dict[str, str], tmp_path: Path, scheme: str
) -> None:
    """FR-14: rendered pairs, not the token table.

    A token table can be correct in the abstract and wrong on the page.
    `--text-hint` clears 4.5:1 on three grounds and not on the fourth, and
    only a probe that looks at what is actually drawn on what can tell the
    difference between a colour that is fine where it was solved for and the
    same colour used somewhere else.
    """
    root = tmp_path / f"contrast-{scheme}"
    root.mkdir()
    probes.stage(root, STATIC, rendered, probes.CONTRAST_PROBE, scheme)
    httpd, port = probes.serve(root)
    try:
        results = {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150)
            for name in rendered
        }
    finally:
        httpd.shutdown()

    offenders = {name: found["bad"] for name, found in results.items() if found["bad"]}
    distinct = sorted({item for items in offenders.values() for item in items})
    assert offenders == {}, (
        f"{scheme}: {len(offenders)} of {len(results)} pages draw text below the "
        f"threshold, {len(distinct)} distinct pairs:\n" + "\n".join(distinct[:20])
    )
    thin = {name: found["examined"] for name, found in results.items() if found["examined"] < 30}
    assert thin == {}, f"{scheme}: the probe barely looked at these pages: {thin}"


# === AC-11: focus is visible on every interactive element ==================


@needs_chrome
def test_focus_is_visible_on_every_interactive_element(
    rendered: dict[str, str], tmp_path: Path
) -> None:
    """FR-15: the focus state the design does not contain.

    Every clickable thing in the prototype is a `<div onClick>`, so nothing
    in it is focusable and no focus state was ever drawn; the one focus rule
    the brief carries is for fields. cabin uses real links, buttons, forms
    and checkboxes on every page, and an operator who works from the keyboard
    has to be able to see where they are.
    """
    text = CSS.read_text()
    suppressed = [
        (selector, name, value)
        for selector, body in css_rules(text)
        for name, value in declarations(body)
        if name == "outline" and value.strip() in {"none", "0"}
    ]
    assert suppressed == [], (
        f"a suppressed outline is invisible to a screenshot review and obvious "
        f"to a grep: {suppressed}"
    )

    root = tmp_path / "focus"
    root.mkdir()
    probes.stage(root, STATIC, rendered, probes.FOCUS_PROBE)
    httpd, port = probes.serve(root)
    try:
        results = {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150)
            for name in rendered
        }
    finally:
        httpd.shutdown()

    offenders = {name: found["bad"] for name, found in results.items() if found["bad"]}
    distinct = sorted({item for items in offenders.values() for item in items})
    assert offenders == {}, (
        f"{len(offenders)} of {len(results)} pages have an element with no "
        f"visible focus ring, {len(distinct)} distinct:\n" + "\n".join(distinct[:20])
    )
    thin = {name: found["examined"] for name, found in results.items() if found["examined"] < 5}
    assert thin == {}, f"the probe focused almost nothing on these pages: {thin}"


# === AC-12: the shell does not scroll, and main does =======================


SHELL_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var doc = document.scrollingElement;
    var shell = document.querySelector('.shell');
    var main = document.querySelector('#main');
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({
      docScroll: doc.scrollHeight, docClient: doc.clientHeight,
      shellFound: !!shell,
      shellScroll: shell ? shell.scrollHeight : null,
      shellClient: shell ? shell.clientHeight : null,
      mainFound: !!main,
      mainScroll: main ? main.scrollHeight : null,
      mainClient: main ? main.clientHeight : null
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


@needs_chrome
def test_the_shell_does_not_scroll(rendered: dict[str, str], tmp_path: Path) -> None:
    """AC-12: the window stays put and the content moves under the rail.

    The third clause is what stops a build where nothing scrolls at all from
    passing -- "the page does not scroll" is satisfied perfectly by a page
    with no content in it.
    """
    found = one_page(tmp_path, "cert_detail", rendered["cert_detail"], SHELL_PROBE)
    assert isinstance(found, dict)
    assert found["shellFound"], "there is no .shell element (FR-6)"
    assert found["mainFound"], "there is no #main element (FR-23)"
    assert found["docScroll"] <= found["docClient"] + 1, (
        f"the window scrolls, which takes the rail with it: {found}"
    )
    assert found["shellScroll"] <= found["shellClient"] + 1, f"the shell scrolls: {found}"
    assert found["mainScroll"] > found["mainClient"], (
        f"nothing scrolls at all on a certificate detail page, which carries "
        f"two PEM blocks: {found}"
    )


# === AC-18: the twelve numbers the design is made of =======================


NUMBERS_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function cs(sel) {
      var el = document.querySelector(sel);
      return el ? getComputedStyle(el) : null;
    }
    function pick(sel, props) {
      var style = cs(sel);
      if (!style) return null;
      var out = {};
      props.forEach(function (p) { out[p] = style[p]; });
      return out;
    }
    var main = document.querySelector('#main');
    var wrapper = main ? main.firstElementChild : null;
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({
      rail: pick('.rail', ['width']),
      section: pick('.section', ['gridTemplateColumns', 'columnGap',
                                 'paddingTop', 'paddingBottom']),
      main: pick('#main', ['paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft']),
      wrapper: wrapper ? getComputedStyle(wrapper).maxWidth : null,
      tag: pick('.tag', ['borderTopLeftRadius']),
      button: pick('button', ['borderTopLeftRadius']),
      scroller: pick('.scroller', ['borderTopLeftRadius']),
      h1: pick('h1', ['fontSize']),
      h2: pick('h2', ['fontSize']),
      td: pick('tbody td', ['paddingTop', 'paddingLeft'])
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


@needs_chrome
def test_the_twelve_numbers(rendered: dict[str, str], tmp_path: Path) -> None:
    """FR-22: computed styles, not a text match.

    A value in the file and a value on the screen are different claims, and
    only the second one is the design. Each number gets its own assertion so
    that a failure names the number rather than the table.

    The content wrapper is addressed as `#main`'s first element child, because
    FR-6 gives it no class name -- it is "main's inner wrapper", the one
    element 0027 owns and the one `cabinIn` is applied to (FR-16).
    """
    found = one_page(tmp_path, "ca_detail", rendered["ca_detail"], NUMBERS_PROBE)
    assert isinstance(found, dict)
    for key in ("rail", "section", "main", "tag", "button", "scroller", "h1", "h2", "td"):
        assert found[key] is not None, f"the page has no element for {key}"
    assert found["wrapper"] is not None, "main has no inner wrapper (FR-6)"

    assert found["rail"]["width"] == "230px"
    assert found["section"]["gridTemplateColumns"].split()[0] == "250px", found["section"]
    assert found["section"]["columnGap"] == "28px"
    assert found["section"]["paddingTop"] == "22px"
    assert found["section"]["paddingBottom"] == "22px"
    assert found["main"]["paddingTop"] == "26px"
    assert found["main"]["paddingRight"] == "34px"
    assert found["main"]["paddingLeft"] == "34px"
    assert found["main"]["paddingBottom"] == "60px"
    assert found["wrapper"] == "1180px"
    assert found["tag"]["borderTopLeftRadius"] == "4px"
    assert found["button"]["borderTopLeftRadius"] == "6px"
    assert found["scroller"]["borderTopLeftRadius"] == "8px"
    assert found["h1"]["fontSize"] == "29px"
    assert found["h2"]["fontSize"] == "17px"
    assert found["td"]["paddingTop"] == "10px"
    assert found["td"]["paddingLeft"] == "12px"


# === AC-19: type is in rem and honours a raised root =======================


TYPE_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function sizes() {
      var body = getComputedStyle(document.body);
      return {
        h1: parseFloat(getComputedStyle(document.querySelector('h1')).fontSize),
        h2: parseFloat(getComputedStyle(document.querySelector('h2')).fontSize),
        bodySize: parseFloat(body.fontSize),
        lineHeight: parseFloat(body.lineHeight)
      };
    }
    var base = sizes();
    document.documentElement.style.fontSize = '20px';
    var raised = sizes();
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({base: base, raised: raised});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


@needs_chrome
def test_type_scales_with_the_root_font_size(rendered: dict[str, str], tmp_path: Path) -> None:
    """FR-16/AC-19: px reproduces the design exactly for everyone except the
    operator who raised their base font size, which is the one person the
    setting exists for. The prototype had no such user; cabin does."""
    found = one_page(tmp_path, "ca_detail", rendered["ca_detail"], TYPE_PROBE)
    assert isinstance(found, dict)
    base, raised = found["base"], found["raised"]
    assert abs(base["h1"] - 29) < 0.5, f"h1 is {base['h1']}px at a 16px root, not 29"
    assert abs(base["h2"] - 17) < 0.5, f"h2 is {base['h2']}px at a 16px root, not 17"
    assert abs(raised["h1"] - base["h1"] * 1.25) <= 1, (
        f"h1 did not scale with a 20px root: {base['h1']} -> {raised['h1']}"
    )
    assert abs(raised["h2"] - base["h2"] * 1.25) <= 1, (
        f"h2 did not scale with a 20px root: {base['h2']} -> {raised['h2']}"
    )
    assert abs(base["lineHeight"] - base["bodySize"] * 1.5) < 0.5, (
        f"body line-height is {base['lineHeight']}px against a {base['bodySize']}px "
        f"font; the prototype relies on the browser default, which is not "
        f"reproducible across engines"
    )


# === AC-21: the danger button arms with its checkbox =======================


ARM_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var root = getComputedStyle(document.documentElement);
    var button = document.querySelector('button.danger');
    var out = document.createElement('div');
    out.id = 'probe-result';
    if (!button) {
      out.textContent = JSON.stringify({found: false});
      document.body.appendChild(out);
      return;
    }
    var box = button.closest('form').querySelector('input[name="confirm"]');
    box.checked = false;
    var disarmed = getComputedStyle(button).color;
    box.checked = true;
    var armed = getComputedStyle(button).color;
    out.textContent = JSON.stringify({
      found: true,
      boxFound: !!box,
      disarmed: disarmed,
      armed: armed,
      disarmedToken: root.getPropertyValue('--danger-disarmed-fg').trim(),
      armedToken: root.getPropertyValue('--dead-fg').trim()
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


def _rgb_string(value: str) -> str:
    r, g, b = rgb(value)
    return f"rgb({int(r)}, {int(g)}, {int(b)})"


@needs_chrome
def test_the_danger_button_arms_with_its_checkbox(rendered: dict[str, str], tmp_path: Path) -> None:
    """FR-24/AC-21: the one interactive nuance in the design that costs no
    JavaScript, and the half that says the confirmation treatment is visible
    rather than merely present in the DOM.

    Both states in one run: written against the wrong selector the button
    never arms, written too loosely it arms without the box, and the two
    halves fail in opposite directions.
    """
    found = one_page(tmp_path, "ca_detail", rendered["ca_detail"], ARM_PROBE)
    assert isinstance(found, dict)
    assert found["found"], "the hierarchy page carries no button.danger to check"
    assert found["boxFound"], "the danger button has no confirm checkbox in its form"
    assert found["disarmedToken"] and found["armedToken"], found
    assert found["disarmed"] == _rgb_string(found["disarmedToken"]), (
        f"unchecked, the button is {found['disarmed']}, not --danger-disarmed-fg "
        f"({found['disarmedToken']}) -- it is armed before the box is ticked"
    )
    assert found["armed"] == _rgb_string(found["armedToken"]), (
        f"checked, the button is {found['armed']}, not --dead-fg "
        f"({found['armedToken']}) -- ticking the box changes nothing"
    )


# === AC-1: the boundary holds ==============================================


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True)


_JINJA_RE = re.compile(r"{%.*?%}|{{.*?}}", re.S)


def _jinja_tags(text: str) -> set[str]:
    return {" ".join(tag.split()) for tag in _JINJA_RE.findall(text)}


def test_only_layout_html_changed() -> None:
    """FR-18/AC-1: `layout.html` is the only template this spec edits.

    That boundary is what makes 0027 verifiable in one step: the claim that
    the suite still passes only means something if the chrome fits the
    content exactly as it already was. A content template "just slightly"
    adjusted to make a new rule look right would make that claim empty.

    The second half is the formatter (FR-25). It has turned
    `{% if x == "y" %}` into `{% if x="" ="y" %}` and cost this project five
    debugging sessions; a Jinja tag in the new file that is not in the old
    one is what that failure looks like.
    """
    listed = _git("ls-tree", "-r", "--name-only", BASELINE, "src/cabin/web/templates/")
    assert listed.returncode == 0, listed.stderr.decode()
    baseline_names = [line for line in listed.stdout.decode().split() if line.endswith(".html")]
    assert len(baseline_names) > 10, baseline_names

    current = sorted(p.name for p in TEMPLATES.glob("*.html"))
    assert current == sorted(Path(name).name for name in baseline_names), (
        "a template was added or removed; 0027 adds none"
    )

    changed = []
    for name in baseline_names:
        show = _git("show", f"{BASELINE}:{name}")
        assert show.returncode == 0, show.stderr.decode()
        if show.stdout != (REPO / name).read_bytes():
            changed.append(Path(name).name)
    assert changed == ["layout.html"], (
        f"0027 edits layout.html and nothing else under templates/; changed: {changed}"
    )

    before = _git("show", f"{BASELINE}:src/cabin/web/templates/layout.html").stdout.decode()
    after = (TEMPLATES / "layout.html").read_text()
    invented = _jinja_tags(after) - _jinja_tags(before)
    assert invented == set(), (
        f"layout.html grew Jinja tags that were not in it before -- the "
        f"formatter's failure mode is a broken tag, and this is what it looks "
        f"like: {sorted(invented)}"
    )


# === AC-16: the load-bearing names survive =================================


def test_the_load_bearing_class_names_survive() -> None:
    """FR-19: renaming one of these is a deliberate act with an argument.

    Thirty-one assertions across the suite scope by ten of these names. A
    rename would not make them fail -- it would make them find nothing, which
    is worse. `.card` and `badge*` stay banned for the reason spec 0015 had:
    the `card` clause is what keeps "one content width" from being quietly
    undone the moment someone wants a box around something, and the `badge`
    clause protects the `tag-*` naming a dozen assertions scope by.
    """
    text = CSS.read_text()
    defined = class_selectors(text)
    markup = {path.name: path.read_text() for path in TEMPLATES.glob("*.html")}

    without_rule = [name for name in LOAD_BEARING if name not in defined]
    assert without_rule == [], f"no rule in cabin.css for {without_rule}"

    unused = [
        name
        for name in LOAD_BEARING
        if not any(re.search(rf'class="[^"]*\b{name}\b', text) for text in markup.values())
    ]
    assert unused == [], f"no template emits {unused}"

    banned_in_css = [
        selector
        for selector in defined
        if selector == "card" or selector.startswith(("card-wide", "badge"))
    ]
    assert banned_in_css == [], banned_in_css
    offenders = {
        name: hits
        for name, text in markup.items()
        if (hits := re.findall(r'class="[^"]*\b(card(?!-narrow)\b|card-wide|badge[\w-]*)', text))
    }
    assert offenders == {}, offenders


# === AC-17: no colour outside the token blocks, and no color-mix ===========


def test_no_colour_outside_the_token_blocks() -> None:
    """FR-21: the token layer is the source of every colour.

    This is the one check that proves the table beside the stylesheet is not
    being ignored by the stylesheet. `color-mix()` goes with it: it computes
    the three tag borders and the error box today, and the design supplies an
    explicit background, text and border for each of its five status families
    and three note tones, so the computation has nothing left to do.
    """
    text = strip_comments(CSS.read_text())
    assert "color-mix" not in text, "color-mix has nothing left to compute (FR-21)"

    literals = []
    for selector, body in css_rules(text):
        if selector.strip() == ":root":
            continue
        for name, value in declarations(body):
            if re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", value):
                literals.append(f"{selector} {{ {name}: {value} }}")
    assert literals == [], (
        f"every colour belongs to a token; these rules carry their own: {literals}"
    )
