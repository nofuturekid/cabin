"""The browser probes, in one place (spec 0027 FR-2).

Until 0027 the overflow walker existed twice, character for character, in
``test_web_layout.py`` and ``test_ca_names_and_actions.py``, and
``_DANGER_PROBE`` existed twice in ``test_ca_issuer_pages.py`` and
``test_ca_names_and_actions.py``. Repairing or strengthening one copy would
have left the other vacuously green over nine CA and transfer pages, which is
the same defect one level up. There is one definition of each here and every
caller imports it.

**What the repair is** (FR-3). The old walker excused any element with an
ancestor whose computed ``overflow-x`` was ``auto``, ``scroll`` or
``hidden``. The design's shell is ``height:100vh; display:flex;
overflow:hidden`` and its ``<main>`` is ``overflow-y:auto``, so *every*
element on *every* page would have gained such an ancestor: the probe would
have returned nothing for all nineteen screens at both widths while looking
green. ``scrollable()`` is gone. An element is excused only when it sits
inside ``.scroller`` -- the one construct spec 0015 FR-4 permits to scroll
sideways. Computed style is not consulted, because ``overflow:hidden`` on an
ancestor now means "this overflow is invisible", which is the strongest
reason to report it rather than to excuse it.

The exemption is for what a scroller may hold, not for where a scroller may
sit: ``excused`` walks from ``parentElement``, so the ``.scroller`` itself is
still measured against its own container. A ``.scroller`` wider than the grid
column it sits in is the ordinary way a scroller breaks a page, and the
walker being replaced -- which examined ancestors only -- caught it.

``container()`` and both comparisons are unchanged: ``getBoundingClientRect``
reports layout geometry and is unaffected by clipping, so the "past viewport"
clause still catches an element drawn outside the window that the shell now
merely hides.

The three walking probes -- overflow, contrast, focus -- report how much they
looked at and not only what they found (FR-4), because a probe that examines
nothing and reports nothing is indistinguishable from a clean page unless it
says how many elements it saw. ``DANGER_PROBE`` returns a bare list instead:
its callers already carry a ``_count_danger_buttons(html) >= 1`` assertion per
page, which is the same guarantee arrived at from the other side.
"""

import json
import re
import shutil
import subprocess
import threading
from collections.abc import Mapping
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

CHROME = "/opt/google/chrome/chrome"

#: The forced-light copy of the stylesheet, served beside the real one.
LIGHT_CSS = "cabin-light.css"

#: Reports every element drawn past the viewport or past its own container,
#: together with how many it examined and how many it excused (FR-3, FR-4).
#: Result: ``{"bad": [...], "examined": N, "excused": M}``.
OVERFLOW_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function excused(el) {
      return (
        el.parentElement !== null &&
        el.parentElement.closest(".scroller") !== null
      );
    }
    function container(el) {
      for (var p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
        if (getComputedStyle(p).display !== 'inline' && p.getBoundingClientRect().width > 0) {
          return p;
        }
      }
      return null;
    }
    var vw = document.documentElement.clientWidth, bad = [], seen = 0, skipped = 0;
    document.querySelectorAll('body *').forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (excused(el)) { skipped++; return; }
      seen++;
      var c = container(el);
      var label = el.tagName.toLowerCase() + '.' + (el.className || '').toString().slice(0, 30);
      if (r.right > vw + 1) bad.push(label + ' past viewport by ' + Math.round(r.right - vw));
      else if (c) {
        var over = Math.round(r.right - c.getBoundingClientRect().right);
        if (over > 1) bad.push(label + ' out of container by ' + over);
      }
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({bad: bad, examined: seen, excused: skipped});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: Walks every element carrying a text node of its own, resolves its effective
#: colour and the first opaque background beneath it, and reports every pair
#: below WCAG 1.4.3's threshold -- 4.5:1, or 3:1 for large text (>= 24px, or
#: >= 18.66px at weight >= 700). Disabled controls are exempt and skipped
#: (FR-14). Result: ``{"bad": [...], "examined": N}``.
#:
#: Spec 0028 FR-13 adds ``[aria-hidden="true"]`` to that skip clause. WCAG
#: 1.4.3 exempts text that is pure decoration, and the tree glyph the grouped
#: list draws is decoration in ``--accent-deep`` -- 2.60:1 on the page ground,
#: which the probe would otherwise report on every render of ``/ca``. An
#: exemption keyed on an attribute an author writes is an exemption an author
#: can spread, so it is **bounded** rather than trusted:
#: ``test_the_tree_glyph_is_the_only_decoration`` (AC-14) asserts that the set
#: of elements matching this selector, across every page in the probe's list,
#: is exactly the tree glyphs. A second user has to be argued for in the spec
#: that adds it rather than discovered later in a screenshot.
CONTRAST_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function parse(text) {
      var m = /rgba?\\(([^)]+)\\)/.exec(text);
      if (!m) return null;
      var p = m[1].split(',').map(function (x) { return parseFloat(x); });
      return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1};
    }
    function over(top, under) {
      return {
        r: top.r * top.a + under.r * (1 - top.a),
        g: top.g * top.a + under.g * (1 - top.a),
        b: top.b * top.a + under.b * (1 - top.a),
        a: 1
      };
    }
    function lum(c) {
      var v = [c.r, c.g, c.b].map(function (x) {
        x = x / 255;
        return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
    }
    function ratio(a, b) {
      var la = lum(a), lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }
    function ground(el) {
      var stack = [];
      for (var p = el; p; p = p.parentElement) {
        var c = parse(getComputedStyle(p).backgroundColor);
        if (!c || c.a === 0) continue;
        stack.push(c);
        if (c.a === 1) break;
      }
      var base = {r: 255, g: 255, b: 255, a: 1};
      for (var i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
      return base;
    }
    function ownText(el) {
      for (var i = 0; i < el.childNodes.length; i++) {
        var n = el.childNodes[i];
        if (n.nodeType === 3 && n.textContent.trim() !== '') return true;
      }
      return false;
    }
    function show(c) {
      return Math.round(c.r) + ',' + Math.round(c.g) + ',' + Math.round(c.b);
    }
    var bad = [], seen = 0;
    document.querySelectorAll('body *').forEach(function (el) {
      if (el.id === 'probe-result' || !ownText(el)) return;
      var r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (el.closest(':disabled, [disabled], [aria-disabled="true"], [aria-hidden="true"]')) return;
      var cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none') return;
      var fg = parse(cs.color);
      if (!fg) return;
      var bg = ground(el);
      if (fg.a < 1) fg = over(fg, bg);
      var size = parseFloat(cs.fontSize);
      var weight = parseInt(cs.fontWeight, 10) || 400;
      var need = (size >= 24 || (size >= 18.66 && weight >= 700)) ? 3 : 4.5;
      seen++;
      var got = ratio(fg, bg);
      if (got + 0.005 < need) {
        bad.push(el.tagName.toLowerCase() + '.' + (el.className || '').toString().slice(0, 24)
          + ' ' + show(fg) + ' on ' + show(bg) + ' at ' + Math.round(size) + 'px = '
          + got.toFixed(2) + ':1, needs ' + need);
      }
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({bad: bad, examined: seen});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: Focuses every focusable element in turn and reports any whose focus ring is
#: absent, thinner than 2px, or the same colour as the element's own
#: background (FR-15). Hidden and disabled controls cannot take focus and are
#: not counted. Result: ``{"bad": [...], "examined": N}``.
FOCUS_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var sel = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])';
    var bad = [], seen = 0;
    document.querySelectorAll(sel).forEach(function (el) {
      if (el.type === 'hidden') return;
      if (el.closest(':disabled, [disabled], [aria-disabled="true"]')) return;
      var r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      var label = el.tagName.toLowerCase() + '.' + (el.className || '').toString().slice(0, 24);
      el.focus();
      if (document.activeElement !== el) {
        bad.push(label + ' could not be focused');
        return;
      }
      seen++;
      var cs = getComputedStyle(el);
      var width = parseFloat(cs.outlineWidth);
      if (cs.outlineStyle === 'none') bad.push(label + ' has outline-style: none');
      else if (!(width >= 2)) bad.push(label + ' outline-width is ' + cs.outlineWidth);
      else if (cs.outlineColor === cs.backgroundColor) {
        bad.push(label + ' outline colour equals its own background: ' + cs.outlineColor);
      }
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify({bad: bad, examined: seen});
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

#: Spec 0024 AC-11 and spec 0027 FR-24/AC-21: every ``button.danger`` has a
#: confirm checkbox inside its own ``<form>``, and the button's colour changes
#: the instant that box is ticked.
#:
#: The second half is what says the confirmation treatment is *visible* rather
#: than merely present in the DOM. The design's disarmed button is a
#: desaturated red that reads as "not yet armed", and the rule that produces
#: it costs no JavaScript -- ``form:has(input[name="confirm"]:checked)
#: button.danger``. Written against the wrong selector the button never arms;
#: written too loosely it arms without the box. The two halves fail in
#: opposite directions.
#:
#: Like the overflow walker, this probe existed in two byte-identical copies
#: (``test_ca_issuer_pages.py`` and ``test_ca_names_and_actions.py``). Giving
#: one of them the armed/disarmed half and not the other would have left nine
#: pages reporting the treatment as present while never measuring that it can
#: be seen -- the same defect FR-2 exists to remove. Result: ``list[str]``.
DANGER_PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    function rgbOf(hex) {
      var h = hex.replace('#', '');
      if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
      return 'rgb(' + parseInt(h.slice(0, 2), 16) + ', ' + parseInt(h.slice(2, 4), 16)
        + ', ' + parseInt(h.slice(4, 6), 16) + ')';
    }
    var root = getComputedStyle(document.documentElement);
    var disarmedToken = root.getPropertyValue('--danger-disarmed-fg').trim();
    var armedToken = root.getPropertyValue('--dead-fg').trim();
    var bad = [];
    document.querySelectorAll('button.danger').forEach(function (btn, i) {
      var form = btn.closest('form');
      var box = form && form.querySelector('input[name="confirm"]');
      if (!box) {
        bad.push('danger button ' + i + ' has no confirm checkbox in its form');
        return;
      }
      if (!disarmedToken || !armedToken) {
        bad.push('danger button ' + i + ': --danger-disarmed-fg/--dead-fg are not declared');
        return;
      }
      box.checked = false;
      var disarmed = getComputedStyle(btn).color;
      box.checked = true;
      var armed = getComputedStyle(btn).color;
      box.checked = false;
      if (disarmed !== rgbOf(disarmedToken)) {
        bad.push('danger button ' + i + ' is ' + disarmed + ' with the box unticked, not '
          + rgbOf(disarmedToken) + ' -- it is armed before it was confirmed');
      }
      if (armed !== rgbOf(armedToken)) {
        bad.push('danger button ' + i + ' is ' + armed + ' with the box ticked, not '
          + rgbOf(armedToken) + ' -- ticking the box changes nothing');
      }
    });
    var out = document.createElement('div');
    out.id = 'probe-result';
    out.textContent = JSON.stringify(bad);
    document.body.appendChild(out);
  }, 300);
});
</script>
"""

_RESULT_RE = re.compile(r'<div id="probe-result">(.*?)</div>', re.S)

_LIGHT_MEDIA = "@media (prefers-color-scheme: light)"


def serve(root: Path) -> tuple[ThreadingHTTPServer, int]:
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def dump_dom(url: str, width: int, height: int) -> str:
    return subprocess.run(
        [
            CHROME,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--window-size={width},{height}",
            "--virtual-time-budget=6000",
            "--dump-dom",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=90,
    ).stdout


def result(dom: str) -> Any:
    found = _RESULT_RE.search(dom)
    assert found is not None, "probe did not run -- Chrome rendered nothing"
    return json.loads(found.group(1).replace("&quot;", '"').replace("&amp;", "&"))


def run(url: str, width: int, height: int) -> Any:
    return result(dump_dom(url, width, height))


def overflow(url: str, width: int, height: int) -> dict[str, object]:
    """``{"bad": list[str], "examined": int, "excused": int}`` (FR-4).

    The bare list the old helper returned could not tell "nothing is broken"
    from "nothing was looked at", which is the failure mode this whole spec
    is guarding against.
    """
    found = run(url, width, height)
    assert isinstance(found, dict), f"the overflow probe returned {found!r}, not a dict"
    return found


def light_stylesheet(text: str) -> str:
    """``cabin.css`` with the light scheme's media wrapper removed (FR-14).

    Headless Chrome reports ``prefers-color-scheme: dark`` and no flag
    changes that, so the light scheme is forced by making its ``:root`` block
    -- which comes after the default one and has equal specificity --
    unconditional. The transformation is only faithful because FR-8 requires
    that block to hold exactly one ``:root`` rule and nothing else; AC-9
    asserts that shape, so this cannot silently stop being valid.
    """
    start = text.find(_LIGHT_MEDIA)
    assert start != -1, f"cabin.css has no {_LIGHT_MEDIA} block (spec 0027 FR-8)"
    assert text.find(_LIGHT_MEDIA, start + 1) == -1, "more than one light media block (FR-8)"
    open_brace = text.index("{", start)
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                inner = text[open_brace + 1 : i]
                return text[:start] + inner + text[i + 1 :]
    raise AssertionError("the light media block is never closed")


def stage(
    root: Path,
    static: Path,
    pages: Mapping[str, str],
    probe: str,
    scheme: str = "dark",
) -> None:
    """Write every rendered page into ``root`` with ``probe`` appended and the
    real stylesheet beside it, in one of the two schemes.

    The dark scheme is what headless Chrome reports by default and needs
    nothing; the light one is served the stripped copy ``light_stylesheet``
    produces. Both runs therefore use the real values from the real file.
    """
    assert scheme in {"dark", "light"}, scheme
    shutil.copytree(static, root / "static", dirs_exist_ok=True)
    if scheme == "light":
        css = light_stylesheet((static / "cabin.css").read_text())
        (root / "static" / LIGHT_CSS).write_text(css)
    for name, html in pages.items():
        body = html.replace("</body>", probe + "</body>")
        if scheme == "light":
            body = body.replace("/static/cabin.css", f"/static/{LIGHT_CSS}")
        (root / f"{name}.html").write_text(body)
