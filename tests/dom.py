"""A parsed element tree, in one place (spec 0030).

Spec 0030's criteria are anchored to elements and to where they sit -- "one
element with class `flash`, inside `.shell` and as a sibling of
`<main id="main">`", "exactly five `<a>` inside one `.seg`", "zero `<form>`
elements inside `<tbody>`" -- and none of those can be measured with a
substring search over the page. The existing web test files each carry a
small ``HTMLParser`` subclass of their own for the one shape they need
(``_FormActions`` in ``test_transfer.py``, ``_SelectOptions`` in
``test_web_ca_pages.py``); six more of those would be six things to repair,
which is the argument ``tests/probes.py`` already makes one level up.

This is the smallest tree that answers the questions this spec asks:
containment, document order, own text, and attributes. It is deliberately
not a full HTML5 parser -- ``html.parser`` does not do implied end tags, so
the void elements below are closed here and nothing else is guessed.
"""

from __future__ import annotations

from html.parser import HTMLParser

#: Elements that never have an end tag. Without this list a ``<input>``
#: inside a ``<form>`` would swallow everything after it as a child, and
#: "the form contains one button" would be measured against a tree that is
#: not the browser's.
VOID = frozenset(
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


class Node:
    """One element. ``root`` is a synthetic node whose tag is ``#document``."""

    def __init__(self, tag: str, attrs: dict[str, str], parent: Node | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.children: list[Node] = []
        #: The text nodes belonging to this element itself, in order.
        self.own_text: list[str] = []

    # --- attributes --------------------------------------------------------

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def get(self, name: str) -> str | None:
        return self.attrs.get(name)

    # --- text --------------------------------------------------------------

    def text(self) -> str:
        """This element's whole text content, whitespace collapsed."""
        parts = list(self.own_text)
        for child in self.children:
            parts.append(child.text())
        return " ".join(" ".join(parts).split())

    def text_nodes(self) -> list[str]:
        """Every non-empty text node in this subtree, in document order.

        ``<script>`` and ``<style>`` bodies are not text a reader sees, so
        they are not collected -- otherwise the whole of ``htmx.min.js``'s
        tag would count as a sentence on every page.
        """
        if self.tag in {"script", "style"}:
            return []
        found = [" ".join(part.split()) for part in self.own_text]
        out = [part for part in found if part]
        for child in self.children:
            out.extend(child.text_nodes())
        return out

    # --- searching ---------------------------------------------------------

    def walk(self) -> list[Node]:
        out: list[Node] = []
        for child in self.children:
            out.append(child)
            out.extend(child.walk())
        return out

    def find_all(
        self, tag: str | None = None, cls: str | None = None, id: str | None = None
    ) -> list[Node]:
        return [
            node
            for node in self.walk()
            if (tag is None or node.tag == tag)
            and (cls is None or cls in node.classes)
            and (id is None or node.attrs.get("id") == id)
        ]

    def find(self, tag: str | None = None, cls: str | None = None, id: str | None = None) -> Node:
        found = self.find_all(tag=tag, cls=cls, id=id)
        assert len(found) == 1, (
            f"expected exactly one element matching "
            f"tag={tag!r} class={cls!r} id={id!r}, found {len(found)}"
        )
        return found[0]

    def ancestors(self) -> list[Node]:
        out: list[Node] = []
        node = self.parent
        while node is not None:
            out.append(node)
            node = node.parent
        return out

    def closest(self, tag: str | None = None, cls: str | None = None) -> Node | None:
        for node in self.ancestors():
            if (tag is None or node.tag == tag) and (cls is None or cls in node.classes):
                return node
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        shown = " ".join(f"{k}={v!r}" for k, v in sorted(self.attrs.items()))
        return f"<{self.tag} {shown}>".replace("  ", " ")


class _Builder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("#document", {}, None)
        self._stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag, {name: (value or "") for name, value in attrs}, self._stack[-1])
        self._stack[-1].children.append(node)
        if tag not in VOID:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag, {name: (value or "") for name, value in attrs}, self._stack[-1])
        self._stack[-1].children.append(node)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        self._stack[-1].own_text.append(data)


def parse(html: str) -> Node:
    builder = _Builder()
    builder.feed(html)
    builder.close()
    return builder.root
