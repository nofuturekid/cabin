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

**Neither scheme can be forced by a browser flag, so both are forced in the
file.** `prefers-color-scheme` under `--headless` is whatever the machine
underneath reports -- dark on a desktop with a dark system theme, light on a
CI runner with no desktop -- so every run is served its own copy of
`cabin.css` with the light media wrapper either promoted to unconditional or
deleted (`probes.scheme_stylesheet`). Leaving the dark run to the default was
what made this file measure the light scheme twice on CI while looking green:
"nothing is below threshold" is true of the wrong page too. That is only
faithful while the light block holds one `:root` rule and nothing else, which
`test_light_block_holds_nothing_but_token_overrides` in `test_web_layout.py`
asserts.
"""

import re
from pathlib import Path

import probes
import pytest
from fastapi.testclient import TestClient
from test_web_layout import (
    _populate,
    all_pages,
    assert_examined_enough,
    assert_probe_list_is_sound,
)

from cabin.app import create_app
from cabin.config import Config

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "src/cabin/web/templates"
STATIC = REPO / "src/cabin/web/static"
CSS = STATIC / "cabin.css"
BRIEF = REPO / "docs/design/0027-brief.md"

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
    text = strip_comments(text)
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
    """Every colour literal the brief's section 1 names.

    AC-6's third provenance. Section 10 calls itself a *suggested* token set
    and omits one colour the Interface Contract requires --
    `--danger-disarmed-line: #3a2b30`, which section 1's text table carries as
    "Disarmed danger-button border, paired with `#6d5259`". Section 1 is where
    the colours of this design actually come from, so it is provenance; the
    clause is narrow (it cannot re-value a token section 10 already names) so
    a nudged colour still fails.

    Spec 0028 FR-11 widens the clause from "in a table row of section 1" to
    "in section 1", and the reason is that the old form turned out to depend
    on a typographic accident. `--bar-active: #3f7d55` is named in section 1 --
    in the paragraph *after* the status table, "Two more status colours appear
    exactly once each, as the 2px left edge bar on hierarchy-list rows" -- and
    not in a row of any table. Section 1 is the design's inventory of what it
    is made of either way; the clause still cannot re-value a token section 10
    already names, and the divergence register is still pinned at three rows.
    """
    text = BRIEF.read_text()
    body = text[text.index("## 1. Palette") : text.index("## 2. Typography")]
    return {norm(literal) for literal in re.findall(r"`(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))`", body)}


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
    """The twenty-three screens, with the data that makes them wide.

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
        # spec 0030 FR-21: `/login`, `/setup` and a refused render join the
        # list -- three screens the contrast and focus probes have never
        # covered -- and a flash panel is staged into one of them.
        return all_pages(client, cfg, cert_path)


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
    assert_probe_list_is_sound(rendered)
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
    assert_examined_enough("contrast", results)


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

    assert_probe_list_is_sound(rendered)
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
    assert_examined_enough("focus", results)


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
      rowTd: pick('.rows tbody td', ['paddingTop', 'paddingLeft']),
      rowTr: pick('.rows tbody tr', ['paddingTop', 'paddingLeft'])
    });
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: The twelfth number, on the inventory's list row (FR-12, re-pointed again
#: by spec 0030 FR-17). It reports the cell's padding, the row's padding and
#: whether the row is a grid, because after FR-17 the two numbers live on two
#: elements and a reading of the cell alone can no longer see the 12px.
ORDINARY_ROW_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var el = document.querySelector('tbody td');
    var row = el ? el.parentElement : null;
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify(el ? {
      paddingTop: getComputedStyle(el).paddingTop,
      paddingLeft: getComputedStyle(el).paddingLeft,
      grid: getComputedStyle(row).display,
      rowPaddingTop: getComputedStyle(row).paddingTop,
      rowPaddingLeft: getComputedStyle(row).paddingLeft
    } : null);
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

    **The twelfth number is re-pointed twice** and never dropped. It asserts
    that a list row's padding is the design's `10px 12px` (brief section 6.2,
    "10px 12px (inventory, issuer lists)").

    Spec 0028 FR-12 moved the reading off `/ca/{root}` and onto `/certs`,
    because after FR-8 every table on `/ca/{root}` is a `.rows` table, where
    the 12px horizontal inset is on the `<tr>` and the cells are `10px 0` --
    so a reading of the cell's two paddings would fail against a build that is
    exactly right. Spec 0030 FR-17 gives `/certs` `.cols-certs`, which is a
    `.rows` table too, so there is no unconverted list left in cabin and the
    reading has nowhere flatter to move to.

    It therefore stays on `/certs` and takes the grid form: the cell's `10px`
    and the row's `12px`, the two elements the design's one declaration is
    split across. The clause that asked whether the row is a grid is kept and
    **inverted** -- it now has to be one. That is not a weakening: a `/certs`
    row that is not `display: grid` means `.cols-certs` was declared in the
    stylesheet and never applied to anything, which is exactly the build AC-16
    splits its own two tests to catch. The thirteenth reading keeps asserting
    the same two numbers on `/ca/{root}`, so both of the design's named users
    of the number are still measured, on the page each names.
    """
    found = one_page(tmp_path, "ca_detail", rendered["ca_detail"], NUMBERS_PROBE)
    assert isinstance(found, dict)
    for key in ("rail", "section", "main", "tag", "button", "scroller", "h1", "h2"):
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

    # twelfth, re-pointed again: the inventory's list row, in the grid form
    # spec 0030 FR-17 gives it.
    ordinary = one_page(tmp_path, "certs", rendered["certs"], ORDINARY_ROW_PROBE)
    assert ordinary is not None, "/certs renders no table row to read the number off"
    assert isinstance(ordinary, dict)
    assert ordinary["grid"] == "grid", (
        f"/certs' list row is `display: {ordinary['grid']}`. FR-17 puts `.cols-certs` "
        f"on that table, and a column template that is declared but never applied "
        f"draws nothing"
    )
    assert ordinary["paddingTop"] == "10px", ordinary
    assert ordinary["paddingLeft"] == "0px", (
        f"the inventory's cell keeps its own horizontal inset, so the rule between "
        f"rows would not run the full width of the row as the design draws it: "
        f"{ordinary}"
    )
    assert ordinary["rowPaddingTop"] == "0px", ordinary
    assert ordinary["rowPaddingLeft"] == "12px", ordinary

    # thirteenth: the same two numbers, on the page the twelfth was read from,
    # in the two places the grid row puts them.
    assert found["rowTd"] is not None and found["rowTr"] is not None, (
        f"/ca/{{root}} carries no .rows table at all (spec 0028 FR-8): {found}"
    )
    assert found["rowTd"]["paddingTop"] == "10px", found["rowTd"]
    assert found["rowTd"]["paddingLeft"] == "0px", (
        f"a .rows cell keeps its own horizontal inset, so the row's rule would not "
        f"run the full width of the row as the design draws it: {found['rowTd']}"
    )
    assert found["rowTr"]["paddingTop"] == "0px", found["rowTr"]
    assert found["rowTr"]["paddingLeft"] == "12px", found["rowTr"]


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


# === AC-1: the boundary held, and the test that said so is retired =========
#
# `test_only_layout_html_changed` lived here. It compared every template
# against commit `c455922` and asserted that `layout.html` was the only one
# that differed, which is spec 0027 FR-18/AC-1: *0027 touched no content
# template's markup*. Spec 0028 edits five of them by requirement (FR-1), so
# the test now fails on exactly the change it was written to permit later.
#
# It is retired rather than re-pointed, and the argument is that the thing it
# asserted is **a property of one commit, not of the codebase**. "The diff
# from c455922 to the 0027 merge touched one template" was true when it was
# written, is true now, and will be true forever; nothing a later commit does
# can make it false. So there is no regression for it to catch. Re-pointing it
# at a second fixed pair of commits would assert only that git history is
# immutable, which git already guarantees and which no reader would think to
# check for.
#
# Its evidence therefore lives where it always lived: in the commit. `git
# show c455922..<0027>` -- src/cabin/web/templates/ is the record, and it is a
# better one than a test, because it cannot be edited to agree with the code.
#
# What it also carried was the formatter guard (0027 FR-25): a Jinja tag in
# the new file that was not in the old one. That half is not lost with it --
# every spec since 0021 has carried the same rule, and 0028 FR-18 restates it
# with the same enforcement (read `git diff` after every template edit). The
# rendered pages are the check that a mangled tag cannot survive: a broken
# `{% if %}` does not render a page, and twenty of them are fetched with
# `assert resp.status_code == 200` by `render_pages` before any probe in this
# file runs.


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


# ==========================================================================
# spec 0028: what the vocabulary this file pinned is allowed to become
# ==========================================================================

#: Spec 0027 FR-18 reserved eight names without defining them, because
#: `test_stylesheet_and_templates_agree_in_both_directions` fails in its
#: reverse direction on a rule with no user. Spec 0028 rendered two of them
#: and spec 0029 a third.
#:
#: **Spec 0030 FR-18 empties the list.** All five remaining names are the
#: design's last components and this spec renders every one of them, so the
#: criterion inverts rather than shrinking: what was "these have no rule"
#: becomes "each of these has a rule *and* a literal user", which is the same
#: guard doing the same job from the other side. What it stops is a sixth
#: component being defined "while we are in the file", and with the list empty
#: the general reverse direction in
#: `test_stylesheet_and_templates_agree_in_both_directions` is what stops it.
RESERVED: tuple[str, ...] = ()

#: FR-10's table: every class spec 0028 defines, each of which must have a
#: rule *and* a literal user.
DEFINED_BY_0028 = (
    "rows",
    "cols-hierarchies",
    "cols-issuers",
    "cols-crosses",
    "facts",
    "facts-indent",
    "rowlink",
    "row-root",
    "row-child",
    "state-active",
    "state-retired",
    "tree",
    "panel",
    "panel-danger",
)

#: Spec 0029 FR-15's table: the seven classes that spec defines, each of
#: which must have a rule *and* a literal user for the same reason the
#: fourteen above must. `.mark-ok`/`.mark-bad` are the reason FR-15 repeats
#: spec 0028 FR-10's "written literally, never interpolated": `mark-{{ … }}`
#: would leave `.mark-bad` a rule with no user at all.
DEFINED_BY_0029 = (
    "form-split",
    "preview",
    "kicker",
    "kv",
    "checks",
    "mark-ok",
    "mark-bad",
)

#: Spec 0030 FR-18's table: the five names spec 0027 reserved, plus the six
#: components and the eleven column templates this spec first renders. Every
#: one of them must have a rule and a literal user, and the status-like ones
#: (`seg-on`, `pill-on`, `editing`) are in the list for the reason spec 0028
#: FR-10 gives: written out by a branch, never glued to an interpolation,
#: because a rule whose only user is `seg-{{ … }}` has no user at all.
DEFINED_BY_0030 = (
    "flash",
    "nav-count",
    "seg",
    "seg-on",
    "pill",
    "pill-on",
    "toggle",
    "copyable",
    "editing",
    "avatar",
    "chips",
    "crl-grid",
    "cols-expiring",
    "cols-authorities",
    "cols-activity",
    "cols-certs",
    "cols-trust-bundle",
    "cols-ca-keys",
    "cols-audit",
    "cols-users",
    "cols-tokens",
    "cols-eab",
    "cols-directories",
)


def literal_class_tokens() -> set[str]:
    """Every class name a template carries *statically* (spec 0027 FR-20).

    A `{{ … }}` or `{% … %}` fragment contributes no name, so
    `class="state-{{ row.status }}"` contributes nothing at all -- which is
    why FR-10 requires the status classes to be written out by a branch. A
    rule for `.state-retired` with only an interpolated user is a rule with no
    user, and the agreement test's reverse direction fails on it.
    """
    names: set[str] = set()
    for path in TEMPLATES.glob("*.html"):
        for classes in re.findall(r'class="([^"]*)"', path.read_text()):
            marked = re.sub(r"{{.*?}}|{%.*?%}", "\x00", classes, flags=re.S)
            names.update(name for name in marked.split() if "\x00" not in name)
    return names


def test_the_reserved_classes_are_still_reserved() -> None:
    """AC-11, extended by spec 0029 AC-13 and **inverted by spec 0030 AC-17**.

    Two directions, and spec 0030 empties the first one. The names spec 0027
    reserved and no spec since renders must still have no rule -- and there
    are none left, because FR-18 renders all five. So the load moves entirely
    onto the second direction: each name spec 0028, 0029 or 0030 *does*
    define must have both a rule and a literal user, because a rule whose
    only user is an interpolation has no user at all as far as
    `test_stylesheet_and_templates_agree_in_both_directions` is concerned.

    _Supersedes spec 0029 AC-13's second half_, which asserts that each of
    `.nav-count`, `.seg`, `.pill`, `.toggle` and `.flash` has **no** rule.
    All five are rendered here, so the assertion is that each now has one.
    """
    defined = class_selectors(CSS.read_text())
    rendered_here = DEFINED_BY_0028 + DEFINED_BY_0029 + DEFINED_BY_0030

    assert set(RESERVED) & set(rendered_here) == set(), (
        f"a name is both reserved and rendered: {sorted(set(RESERVED) & set(rendered_here))}"
    )
    assert RESERVED == (), (
        f"spec 0030 AC-17 asserts the reserved-and-undefined list is empty -- all "
        f"five of `.nav-count`, `.seg`, `.pill`, `.toggle` and `.flash` are rendered "
        f"by the pages this spec redesigns -- and this list holds {RESERVED}"
    )
    for name in ("nav-count", "seg", "pill", "toggle", "flash"):
        assert name in rendered_here, (
            f".{name} was reserved by spec 0027 and left the list without being rendered anywhere"
        )

    premature = [name for name in RESERVED if name in defined]
    assert premature == [], (
        f"these names are reserved and no template renders one, so a rule for one "
        f"is a rule with no user: {premature}"
    )

    without_rule = [name for name in rendered_here if name not in defined]
    assert without_rule == [], (
        f"rendered by spec 0028/0029/0030, no rule in cabin.css: {without_rule}"
    )

    literal = literal_class_tokens()
    without_user = [name for name in rendered_here if name not in literal]
    assert without_user == [], (
        f"these have a rule and no template writes them out literally. A status "
        f"class glued to an interpolation -- `state-{{{{ row.status }}}}`, or "
        f"`seg-{{{{ … }}}}` -- contributes no name at all, which is what FR-10's, "
        f"FR-15's and FR-18's branch requirement is for: {without_user}"
    )

    # The exemption list the agreement test carries is for `tag-*` values that
    # only ever exist as an interpolation. AC-11 and spec 0030 AC-17 both
    # require this spec to add nothing to it; a widened list is how a rule
    # with no user gets parked.
    agreement = (REPO / "tests/test_ca_names_and_actions.py").read_text()
    assert 'exempt = {name for name in defined - used if re.match(r"^tag-", name)}' in agreement, (
        "the agreement test's exemption list is no longer exactly the `^tag-` names; "
        "spec 0028 adds nothing to it (AC-11) and neither does spec 0030 (AC-17)"
    )


#: Spec 0029 FR-2 clause 3: the closed attribute set. `hx-boost`,
#: `hx-swap-oob`, `hx-vals`, `hx-ext`, `hx-headers`, `hx-history` and every
#: `hx-on*` attribute are outside it -- the first turns ordinary navigation
#: into fragment swapping across the whole application, the last is inline
#: JavaScript by another name.
ALLOWED_HX = frozenset(
    {
        "hx-get",
        "hx-post",
        "hx-target",
        "hx-select",
        "hx-swap",
        "hx-trigger",
        "hx-include",
        "hx-push-url",
    }
)

#: The five alternatives spec 0029 FR-2 requires ADR-0003 to address, each as
#: a pattern the `## Considered Options` section has to match. This is the
#: one clause in this file that measures prose, and it is the weakest thing
#: here: it can tell that an option was named and cannot tell whether it was
#: argued. It exists so that an ADR listing only the option that won fails.
REJECTED_OPTIONS = {
    "no htmx at all (the brief's round-trip option)": r"round[- ]trip",
    "static description panels (the brief's option 2)": r"[Ss]tatic panels",
    "htmx with fragment-only endpoints": r"fragment-only",
    "<details> for the disclosure": r"`?<?details>?`?",
    "hand-written JavaScript doing the checks client-side": r"hand-written JavaScript",
}

_HX_ATTR_RE = re.compile(r'\s(hx-[a-zA-Z][\w:-]*)\s*=\s*"')


def test_the_htmx_attribute_set_is_closed_and_the_adr_exists() -> None:
    """Spec 0029 AC-2: `hx-boost` "to make navigation feel faster" is the
    single change that would make FR-2's rule meaningless.

    It would turn every link and form in cabin into a fragment swap, at which
    point "every htmx target is a URL that also works as a page" is true of
    nothing in particular. The allowlist is asserted as a subset rather than
    as an equality, because which of the eight a build needs is a design
    decision and which of them it may not use is not.

    **The `<script>` clause is asserted as "exactly the one that is already
    there", not as "none".** AC-2 says no template contains `<script`;
    `layout.html:9` has loaded htmx from a `<script>` element since spec
    0015, which this spec's own Context paragraph cites, so the criterion as
    written cannot be satisfied by any build. FR-2 clause 4's wording -- "no
    template *gains* a `<script>` element" -- is what is measured here, and
    it is the stronger of the two anyway: it pins the one script that exists
    to its file and its src.
    """
    used: dict[str, set[str]] = {}
    for path in sorted(TEMPLATES.glob("*.html")):
        for name in _HX_ATTR_RE.findall(path.read_text()):
            used.setdefault(name, set()).add(path.name)

    outside = {name: sorted(files) for name, files in used.items() if name not in ALLOWED_HX}
    assert outside == {}, (
        f"an hx- attribute outside FR-2 clause 3's closed set is in use: {outside}"
    )
    on_handlers = [name for name in used if name.startswith("hx-on")]
    assert on_handlers == [], f"hx-on* is inline JavaScript by another name: {on_handlers}"

    # ...and the set is not empty, or this criterion passes over a build that
    # wired no htmx at all.
    assert {"hx-get", "hx-post"} <= set(used), (
        f"no template carries an hx-get or hx-post attribute, so the allowlist "
        f"above was checked against nothing: {sorted(used)}"
    )

    scripts = {
        path.name: re.findall(r"<script\b[^>]*>", path.read_text())
        for path in sorted(TEMPLATES.glob("*.html"))
    }
    with_script = {name: found for name, found in scripts.items() if found}
    assert list(with_script) == ["layout.html"], (
        f"a template other than layout.html carries a <script> element (FR-2 "
        f"clause 4: no template gains one): {with_script}"
    )
    assert with_script["layout.html"] == ['<script src="/static/htmx.min.js">'], (
        f"layout.html's one script element is no longer exactly htmx's: "
        f"{with_script['layout.html']}"
    )

    linked = set()
    for path in sorted(TEMPLATES.glob("*.html")):
        linked.update(re.findall(r"/static/([\w.-]+\.js)", path.read_text()))
    assert linked == {"htmx.min.js"}, (
        f"the templates link {sorted(linked)}; htmx.min.js stays the only JavaScript "
        f"file cabin serves to a page (FR-2 clause 4)"
    )
    assert (STATIC / "htmx.min.js").exists(), "htmx.min.js is not vendored"

    adr = REPO / "docs/adr/0003-url-state-disclosure-and-htmx.md"
    assert adr.exists(), f"{adr.relative_to(REPO)} does not exist (FR-2)"
    text = adr.read_text()
    for line in ("- Status:", "- Date:", "- Deciders:"):
        assert re.search(rf"^{re.escape(line)}", text, re.M), (
            f"ADR-0003 carries no {line!r} header line; docs/adr/0000-template.md does"
        )
    template_headings = re.findall(
        r"^## .+$", (REPO / "docs/adr/0000-template.md").read_text(), re.M
    )
    assert len(template_headings) >= 5, template_headings
    missing = [head for head in template_headings if head not in text]
    assert missing == [], f"ADR-0003 does not follow the template's headings: {missing}"

    options = re.search(r"^## Considered Options$(.*?)^## ", text, re.M | re.S)
    assert options is not None, "ADR-0003 has no Considered Options section"
    unaddressed = [
        name
        for name, pattern in REJECTED_OPTIONS.items()
        if re.search(pattern, options.group(1)) is None
    ]
    assert unaddressed == [], (
        f"ADR-0003 does not name these alternatives at all, so the decision was "
        f"recorded without the options it was taken against (FR-2): {unaddressed}"
    )


def test_the_status_bar_colour_has_provenance() -> None:
    """AC-12/FR-11: one new token, and the criterion it overturns.

    `#3f7d55` is in the brief's section 1 -- in the paragraph after the status
    table rather than in a row of it, which is the whole of why spec 0027
    AC-6's clause 3 had to be widened (`section_one_colours`). The colour's
    two counterparts are asserted here as well: the light scheme has one of
    its own (spec 0027 FR-13), and the *expired* bar the design also draws is
    deliberately not shipped, because a `ca_certificates` row is `active` or
    `retired` and inventing a third state behind a colour would be a content
    change.
    """
    text = CSS.read_text()
    dark = dark_tokens(text)
    light = light_tokens(text)

    assert "--bar-active" in dark, "the status bar's colour is not a token (FR-11/AC-12)"
    assert dark["--bar-active"] == norm("#3f7d55"), dark["--bar-active"]
    assert norm("#3f7d55") in section_one_colours(), (
        "clause 3 admits a token section 10 does not name only when section 1 "
        "inventories its value; this one is not there"
    )
    assert light["--bar-active"] != dark["--bar-active"], (
        "the light scheme repeats the dark bar colour; spec 0027 FR-13 requires a "
        "counterpart that differs"
    )

    used = [
        selector
        for selector, body in css_rules(text)
        for _name, value in declarations(body)
        if "--bar-active" in value
    ]
    assert used != [], "a token nothing draws with is a colour that is not on any page"

    assert norm("#8c3f3d") not in set(dark.values()), (
        "the design's *expired* status bar is not shipped (FR-11): cabin computes no "
        "expired state for a CA row, and inventing one behind a colour would be a "
        "content change"
    )
    assert dark["--line-control"] == norm("#3f424d"), (
        "the retired bar reuses --line-control, which has to still be the design's "
        "own value for that to be the design's retired colour"
    )


#: AC-14: who claims the decoration exemption, and where the tree glyphs are.
ARIA_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function label(el) {
      return el.tagName.toLowerCase() + '.' + (el.className || '').toString()
        + ' "' + el.textContent.trim().slice(0, 12) + '"';
    }
    var hidden = [], trees = [], untagged = [], dots = [];
    document.querySelectorAll('[aria-hidden="true"]').forEach(function (el) {
      hidden.push(label(el));
      if (el.closest('.flash') !== null) dots.push(label(el));
    });
    document.querySelectorAll('.tree').forEach(function (el) {
      trees.push(label(el));
      if (el.getAttribute('aria-hidden') !== 'true') untagged.push(label(el));
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify(
      {hidden: hidden, trees: trees, untagged: untagged, dots: dots});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: FR-9's census, by name: the pages whose grouped lists draw a tree glyph,
#: and how many rows of each have a parent. `/ca` had them before this spec;
#: the dashboard's authorities block and the CA-key page's list are the two
#: users spec 0028 FR-5 said were waiting.
DECORATION_CENSUS = {"ca": 1, "dashboard": 1, "transfer_ca_key": 1}

#: A span the contrast probe would report: `--accent-deep` (#5d5294) is
#: 2.60:1 on the page ground, which is what the design draws the tree glyph
#: in and what spec 0027's Out of Scope left open.
#:
#: It carries a class so that the probe's own label for it (`tagName` plus
#: `className`) names it in the output. "Something was reported" is a weaker
#: claim than "this was reported", and the counter-check below wants the
#: second one.
PLANTED_DECORATION = '<span class="planted" %s style="color:#5d5294">planted decoration</span>'


@needs_chrome
def test_the_tree_glyph_is_the_only_decoration(rendered: dict[str, str], tmp_path: Path) -> None:
    """FR-13/AC-14: the exemption is bounded rather than trusted.

    WCAG 1.4.3 exempts text that is pure decoration, and the tree glyph is
    decoration -- the indentation, the kind tag and the position under the
    root all carry the structure; the glyph draws a line. So `CONTRAST_PROBE`
    skips `[aria-hidden="true"]`. But an exemption keyed on an attribute an
    author writes is an exemption an author can spread, and the only way it
    can do harm is by silencing a real failure on something that is not
    decoration. This asserts the set of elements claiming it is exactly the
    tree glyphs, across every page the probe covers.

    The contrast run itself is `test_contrast_holds_on_every_rendered_page`,
    which already covers this same page list in both schemes with the
    `examined >= 30` floor; repeating it here would double the most expensive
    run in the suite to assert the same thing twice. What is added here is the
    pair of counter-checks that gives both halves teeth: the planted element
    is genuinely below the threshold (the probe reports it without the
    attribute), the attribute is genuinely what silences it (the probe stops
    reporting it with the attribute), and the guard reports the planted
    element as an unbudgeted user of the exemption.
    """
    assert_probe_list_is_sound(rendered)
    root = tmp_path / "aria"
    root.mkdir()
    probes.stage(root, STATIC, rendered, ARIA_PROBE)
    httpd, port = probes.serve(root)
    try:
        results = {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", 1440, 1150)
            for name in rendered
        }
    finally:
        httpd.shutdown()

    assert results["ca"]["trees"], (
        "the grouped list draws no tree glyph at all (FR-5/FR-13), so this "
        "exemption has no user and the argument for it has not been made"
    )
    untagged = {name: found["untagged"] for name, found in results.items() if found["untagged"]}
    assert untagged == {}, f"a .tree glyph is read out to a screen reader: {untagged}"

    # spec 0030 FR-9 _supersedes spec 0028 AC-14's census_. The grouped list
    # arrives on two more pages, so the glyph does too, and the flash panel's
    # dot (FR-4) is a fourth user of the exemption -- the message is the words
    # beside it. The census is widened by *naming* its users, never by
    # dropping the count: a fifth still has to be argued for in the spec that
    # adds it, because anything claiming the exemption that is neither a
    # `.tree` nor the flash dot still fails here.
    for page, expected in DECORATION_CENSUS.items():
        assert page in results, f"the probe list no longer contains {page!r}"
        drawn = len(results[page]["trees"])
        assert drawn >= expected, (
            f"{page} draws {drawn} tree glyphs and FR-9 puts at least {expected} "
            f"there: the grouped list arrives on the dashboard and the CA-key page, "
            f"and this census names its users rather than being widened to 'anywhere'"
        )

    spread = {}
    for name, found in results.items():
        # The flash dot is the fourth named user, and only on the page that
        # carries the panel -- `all_pages` stages exactly one. It is
        # identified by the panel it sits in rather than by a class of its
        # own: FR-4 gives it none, and a census keyed on a class the spec
        # does not require would pass for the wrong reason.
        allowed = set(found["trees"]) | set(found["dots"])
        extra = [item for item in found["hidden"] if item not in allowed]
        if extra:
            spread[name] = sorted(extra)
    assert spread == {}, (
        f"aria-hidden is claimed by something that is neither a tree glyph nor the "
        f"flash panel's dot. A fifth user of the decoration exemption is argued for "
        f"in the spec that adds it, not discovered later in a screenshot: {spread}"
    )
    with_dots = {name: found["dots"] for name, found in results.items() if found["dots"]}
    assert len(with_dots) == 1 and all(len(items) == 1 for items in with_dots.values()), (
        f"the flash panel's dot is drawn on {with_dots}. FR-4 renders exactly one "
        f'`<span aria-hidden="true">` inside the one panel `all_pages` stages, and '
        f"it is the fourth user FR-9's census names"
    )

    # Counter-check, three ways, on one page.
    page = rendered["certs"]
    visible = page.replace("</main>", PLANTED_DECORATION % "" + "</main>")
    hidden = page.replace("</main>", PLANTED_DECORATION % 'aria-hidden="true"' + "</main>")
    assert visible != page and hidden != page, "the planted span was not inserted"

    clean = one_page(tmp_path, "planted-none", page, probes.CONTRAST_PROBE)
    reported = one_page(tmp_path, "planted-visible", visible, probes.CONTRAST_PROBE)
    assert isinstance(clean, dict) and isinstance(reported, dict)
    assert clean["bad"] == [], f"this page was already failing contrast: {clean}"

    # `examined` first, and separately from `bad`. A counter-check that stops
    # firing turns the exemption below it into decoration, and the only way to
    # tell "the probe looked at the span and it passed" from "the probe never
    # saw the span" is the count -- which is precisely the two failures this
    # split tells apart. It ceased to fire on CI for the first reason: the
    # staged "dark" page was rendered light there, because
    # `prefers-color-scheme` under `--headless` follows the machine underneath
    # and a runner has no desktop, and #5d5294 clears 4.5:1 on a light ground.
    # `probes.scheme_stylesheet` forces both schemes in the file now, and this
    # assertion is what would have said which of the two had happened.
    assert reported["examined"] == clean["examined"] + 1, (
        f"the planted span is not in the set the contrast probe examined -- "
        f"{clean['examined']} elements without it, {reported['examined']} with it. "
        f"Nothing below is measuring an exemption from a check that never ran"
    )
    assert [entry for entry in reported["bad"] if entry.startswith("span.planted")], (
        f"the planted span is #5d5294 on the page ground -- 2.60:1 in the dark "
        f"scheme -- and the contrast probe examined it and passed it, so the page "
        f"that was measured is not the page this counter-check describes: {reported}"
    )

    silenced = one_page(tmp_path, "planted-hidden", hidden, probes.CONTRAST_PROBE)
    assert isinstance(silenced, dict)
    assert silenced["bad"] == [], (
        f"aria-hidden did not silence the planted span, so the skip clause spec 0028 "
        f"added to CONTRAST_PROBE is not in effect: {silenced}"
    )
    # The same count, from the other side: the attribute has to take the span
    # out of the examined set. A `bad` that is empty because the span was never
    # planted would satisfy the clause above and nothing else.
    assert silenced["examined"] == clean["examined"], (
        f"aria-hidden left {silenced['examined']} elements examined against "
        f"{clean['examined']} on the bare page -- the attribute is not what removed "
        f"the planted span from the probe's set"
    )

    guarded = one_page(tmp_path, "planted-guard", hidden, ARIA_PROBE)
    assert isinstance(guarded, dict)
    assert set(guarded["hidden"]) - set(guarded["trees"]) != set(), (
        "the guard did not notice an aria-hidden element that is not a tree glyph -- "
        "it cannot go red, and an exemption nobody bounds is a hole"
    )


# ==========================================================================
# spec 0030 AC-16: the column templates are the design's
# ==========================================================================

#: FR-17's table, keyed by the brief section each is read out of. `None`
#: means "the design has no track list for this one" -- `re-ordered`,
#: `reduced`, `extended` and `derived` in FR-17's own last column -- so the
#: ratios are compared against the numbers written in the requirement rather
#: than against the brief, and the word *verbatim* keeps meaning something
#: because the six that claim it are checked against the file.
COLUMN_TEMPLATES = {
    "cols-expiring": ((2.0, 0.6, 1.1, 0.8), "5.1"),
    "cols-authorities": ((1.6, 1.1, 1.0, 0.8), "5.1"),
    "cols-activity": ((1.1, 0.9, 1.3, 2.0), "5.1"),
    "cols-certs": ((1.7, 0.7, 0.7, 1.5, 1.0, 0.5, 1.2), "5.3"),
    "cols-trust-bundle": ((2.0, 0.8, 0.9, 1.2), "5.13"),
    "cols-ca-keys": ((2.0, 1.0, 1.6), "5.14"),
    "cols-audit": ((1.1, 0.9, 1.2, 2.2, 0.6), None),
    "cols-users": ((1.5, 0.8, 1.5, 0.7, 0.8), None),
    "cols-tokens": ((1.2, 0.7, 1.4, 0.7, 1.0, 1.0, 1.0, 0.6), None),
    "cols-eab": ((1.2, 1.4, 1.2, 0.7, 1.4, 1.0, 0.6), None),
    "cols-directories": ((1.6, 0.8, 2.2), None),
}

#: Spec 0028 FR-9's three, which stay exactly as they are. They are named
#: here so that "the stylesheet declares column templates for exactly these"
#: has one owner: `test_ca_issuer_pages.test_the_column_templates_are_the_designs`
#: keeps asserting its own three are right and this test owns the census.
COLUMN_TEMPLATES_0028 = ("cols-hierarchies", "cols-issuers", "cols-crosses")


def split_tracks(value: str) -> list[str]:
    """One `grid-template-columns` value as its tracks, paren-aware --
    `minmax(0, 2fr)` carries a comma and a space inside itself."""
    tracks: list[str] = []
    depth = 0
    current = ""
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char.isspace() and depth == 0:
            if current:
                tracks.append(current)
            current = ""
            continue
        current += char
    if current:
        tracks.append(current)
    return tracks


def declared_column_templates(css_text: str) -> dict[str, list[str]]:
    templates: dict[str, list[str]] = {}
    for selector, body in css_rules(css_text):
        names = re.findall(r"\.(cols-[\w-]+)", selector)
        if not names:
            continue
        for name, value in declarations(body):
            if name == "grid-template-columns":
                for cols_class in names:
                    templates[cols_class] = split_tracks(value)
    return templates


def brief_tracks(section: str) -> list[tuple[float, ...]]:
    """Every `Nfr Nfr ...` run the brief writes in one section 5 subsection.

    Read out of the file so that the six FR-17 marks *verbatim* are compared
    against the design and not against numbers repeated in this test. A
    subsection can name more than one list (5.1 names three), so every run is
    returned and the caller looks for its own.
    """
    text = BRIEF.read_text()
    start = text.index(f"### {section} ")
    end = text.index("### ", start + 4)
    body = text[start:end]
    found = []
    for run in re.findall(r"((?:[\d.]+fr[\s`]+){1,9}[\d.]+fr)", body):
        numbers = tuple(float(value) for value in re.findall(r"([\d.]+)fr", run))
        if len(numbers) >= 3:
            found.append(numbers)
    return found


def test_the_column_templates_are_the_designs() -> None:
    """AC-16's stylesheet half: the eleven templates FR-17 names, in the
    `minmax(0, Nfr)` form, with the six marked *verbatim* checked against the
    brief itself.

    The form is load-bearing rather than decorative (spec 0028 FR-9): a bare
    `Nfr` is `minmax(auto, Nfr)`, whose minimum is the content's, so it
    bounds a track to whatever the longest cell happens to be in the fixture
    that measured it.
    """
    declared = declared_column_templates(CSS.read_text())
    expected = set(COLUMN_TEMPLATES) | set(COLUMN_TEMPLATES_0028)
    assert set(declared) == expected, (
        f"the stylesheet declares column templates for {sorted(declared)}; spec 0028 "
        f"FR-9 names three and spec 0030 FR-17 names eleven more.\n"
        f"  missing: {sorted(expected - set(declared))}\n"
        f"  extra: {sorted(set(declared) - expected)}"
    )

    for name, (ratios, section) in sorted(COLUMN_TEMPLATES.items()):
        tracks = declared[name]
        assert len(tracks) == len(ratios), (
            f".{name} declares {len(tracks)} tracks, FR-17 gives it {len(ratios)}: {tracks}"
        )
        bare = [track for track in tracks if not re.fullmatch(r"minmax\(\s*0(px)?\s*,.*\)", track)]
        assert bare == [], (
            f".{name} has tracks that are not `minmax(0, …)`: {bare}. The form is the "
            f"design's own (brief section 6.14) and it bounds every track to the "
            f"container whatever the cell holds"
        )
        written = tuple(
            float(re.search(r"([\d.]+)fr", track).group(1))  # type: ignore[union-attr]
            for track in tracks
        )
        assert written == ratios, f".{name} declares {written}, FR-17 has {ratios}"
        if section is None:
            continue
        assert ratios in brief_tracks(section), (
            f".{name} is marked *verbatim* from brief section {section} and that "
            f"section's track lists are {brief_tracks(section)}, none of which is "
            f"{ratios}. The last clause is what makes the word verbatim mean something"
        )


#: AC-16's rendered half and AC-4's: what the browser resolved each list
#: row's column template to, and what it resolved the flash panel's
#: animation to. Both are read in one pass because both need the same staged
#: pages and Chrome is the most expensive thing in this suite.
_GRID_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var tables = [];
    document.querySelectorAll('table').forEach(function (table) {
      var tr = table.querySelector('tbody tr');
      if (!tr) return;
      var style = getComputedStyle(tr);
      tables.push({
        classes: (table.className || '').toString(),
        display: style.display,
        tracks: style.gridTemplateColumns,
        cells: tr.children.length
      });
    });
    var flash = null;
    var panel = document.querySelector('.flash');
    if (panel) {
      var cs = getComputedStyle(panel);
      var box = panel.getBoundingClientRect();
      flash = {
        animationName: cs.animationName,
        fillMode: cs.animationFillMode,
        delay: cs.animationDelay,
        left: Math.round(box.left),
        right: Math.round(box.right)
      };
    }
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({
      tables: tables, flash: flash, viewport: document.documentElement.clientWidth});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""


def _grids(tmp_path: Path, pages: dict[str, str], width: int = 1440) -> dict[str, object]:
    root = tmp_path / f"grids-{width}"
    root.mkdir(parents=True, exist_ok=True)
    probes.stage(root, STATIC, pages, _GRID_PROBE)
    httpd, port = probes.serve(root)
    try:
        return {
            name: probes.run(f"http://127.0.0.1:{port}/{name}.html", width, 1150) for name in pages
        }
    finally:
        httpd.shutdown()


@needs_chrome
def test_the_column_templates_resolve_in_the_browser(
    rendered: dict[str, str], tmp_path: Path
) -> None:
    """AC-16's rendered half: the file says which *form* was written, the
    browser says what the columns came out as.

    They are two different statements and only both together are the
    requirement -- a template declared and never applied (a row that is not
    `display: grid`) satisfies the file and draws nothing.
    """
    assert_probe_list_is_sound(rendered)
    measured = _grids(tmp_path, rendered)
    seen: dict[str, list[float]] = {}
    for page, found in measured.items():
        assert isinstance(found, dict)
        for entry in found["tables"]:  # type: ignore[index]
            classes = set(str(entry["classes"]).split())
            for name in COLUMN_TEMPLATES:
                if name not in classes:
                    continue
                assert entry["display"] == "grid", (
                    f"{page}: a .{name} row is `display: {entry['display']}`, so the "
                    f"column template is not applied at all: {entry}"
                )
                seen[name] = [float(track.rstrip("px")) for track in split_tracks(entry["tracks"])]

    missing = sorted(set(COLUMN_TEMPLATES) - set(seen))
    assert missing == [], (
        f"no row of these tables was rendered on any of the {len(rendered)} screens, "
        f"so their tracks were checked against the file and never against a browser: "
        f"{missing}"
    )

    for name, widths in sorted(seen.items()):
        ratios = COLUMN_TEMPLATES[name][0]
        assert len(widths) == len(ratios), (
            f".{name} resolved to {len(widths)} tracks, not {len(ratios)}: {widths}"
        )
        total, share = sum(widths), sum(ratios)
        drift = {
            index: (round(widths[index], 2), round(total * ratios[index] / share, 2))
            for index in range(len(widths))
            if abs(widths[index] - total * ratios[index] / share) > 1.0
        }
        assert drift == {}, (
            f".{name} resolved to widths that are not in the proportion FR-17 "
            f"describes (measured, expected): {drift}"
        )


@needs_chrome
def test_the_flash_panel_animates_in_the_browser(rendered: dict[str, str], tmp_path: Path) -> None:
    """AC-4's rendered half, and AC-19's geometry clause.

    The stylesheet half is
    `test_web_flash_and_refusal.test_the_flash_animation_is_declared_and_reducible`.
    What only a browser can say is that the two keyframes are actually on the
    element -- a rule written for `.flash .dot` or scoped under a media query
    parses fine and animates nothing -- and where the panel is at 390.
    """
    assert_probe_list_is_sound(rendered)
    staged = [name for name, html in rendered.items() if 'class="flash' in html]
    assert len(staged) == 1, (
        f"`all_pages` staged {len(staged)} flash panels; AC-4's rendered half needs "
        f"exactly one page carrying the panel: {staged}"
    )
    page = {staged[0]: rendered[staged[0]]}

    wide = _grids(tmp_path, page, width=1440)[staged[0]]
    assert isinstance(wide, dict)
    flash = wide["flash"]
    assert flash is not None, "the browser drew no `.flash` element"
    assert "cabinToast" in flash["animationName"], flash  # type: ignore[index]
    assert "cabinToastOut" in flash["animationName"], (  # type: ignore[index]
        f"the computed animation-name is {flash['animationName']!r}; the hide half "  # type: ignore[index]
        f"is not on the panel"
    )
    assert "forwards" in flash["fillMode"], (  # type: ignore[index]
        f"animation-fill-mode is {flash['fillMode']!r}; without `forwards` the panel "  # type: ignore[index]
        f"reappears when the animation ends"
    )
    assert "3.2s" in flash["delay"], flash  # type: ignore[index]
    assert flash["left"] == 250, (  # type: ignore[index]
        f"at 1440 the panel's left edge is {flash['left']}, not the design's 250"  # type: ignore[index]
    )

    narrow = _grids(tmp_path, page, width=390)[staged[0]]
    assert isinstance(narrow, dict)
    small = narrow["flash"]
    assert small is not None
    assert small["left"] >= 0 and small["right"] <= narrow["viewport"], (  # type: ignore[index]
        f"at 390 the panel is drawn from {small['left']} to {small['right']} in a "  # type: ignore[index]
        f"{narrow['viewport']}px viewport. The design's `left: 250px` unqualified "
        f"puts a 520px panel 250px into a phone screen, which is the one piece of "
        f"geometry this spec adds and the one an eye on a desktop screenshot cannot see"
    )
