"""Minimal HTML extraction for the crawler.

Uses the standard library's ``html.parser`` rather than BeautifulSoup or
selectolax. The crawler needs links, forms, and script sources — three tag
types — and stdlib covers that without adding a dependency to a container that
needs nothing else from it. If extraction ever needs CSS selectors or has to
cope with genuinely broken markup, that is the point to reconsider.

Tolerant by design: a pentest target is frequently serving malformed HTML, and
a parser that raises on bad markup would turn "the app is broken" into "recon
crashed".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class ParsedPage:
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    title: str = ""
    generator: str = ""
    """Content of <meta name="generator">, a common technology giveaway."""


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = ParsedPage()
        self._form: dict | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a" and attr.get("href"):
            self.page.links.append(attr["href"])
        elif tag == "script" and attr.get("src"):
            self.page.scripts.append(attr["src"])
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and attr.get("name", "").lower() == "generator":
            self.page.generator = attr.get("content", "")
        elif tag == "form":
            self._form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = attr.get("name")
            if name:
                self._form["fields"].append(
                    {"name": name, "type": attr.get("type", tag)})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.page.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.page.title:
            self.page.title = data.strip()[:200]


def parse_page(html: str) -> ParsedPage:
    """Extract links, script sources, and forms. Never raises on bad markup."""
    extractor = _Extractor()
    try:
        extractor.feed(html)
    except Exception:  # noqa: BLE001 - malformed input is expected here
        pass
    # A form left open by unclosed markup still describes a real input surface.
    if extractor._form is not None:
        extractor.page.forms.append(extractor._form)
    return extractor.page
