"""Check published notes against their Markdown sources and local link targets."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import hashlib
import json
import re
import sys
from urllib.parse import unquote, urlsplit, urlunsplit
import posixpath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build_notes


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids, self.links, self.headings = [], [], []
        self.text = ""
        self.feed(html)

    def handle_data(self, data):
        self.text += data

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(tag)


def check_pages(outputs):
    errors = []
    pages = {str(name): Page(html) for name, html in outputs.items()}
    for name, page in pages.items():
        if re.search(r"\b(?:kali|windows)-\d+\b", page.text):
            errors.append(f"Visible internal inventory ID: {name}")
        if len(page.headings) < 1 or page.headings.count("h1") != 1:
            errors.append(f"Missing or duplicate document title: {name}")
        for anchor, count in Counter(page.ids).items():
            if count > 1:
                errors.append(f"Duplicate anchor: {name}#{anchor}")
        for href in page.links:
            if not href:
                # Explicit Markdown anchors may have an id without a destination.
                continue
            parsed = urlsplit(href)
            if parsed.scheme or parsed.netloc:
                continue
            target = (ROOT / name).parent / unquote(parsed.path) if parsed.path else ROOT / name
            target = target.resolve()
            try:
                relative = str(target.relative_to(ROOT))
            except ValueError:
                errors.append(f"Link outside project: {name}: {href}")
                continue
            if target.suffix == ".md" and target != (ROOT / name).with_suffix(".md"):
                errors.append(f"Raw Markdown link: {name}: {href}")
            if relative not in pages and not target.is_file():
                errors.append(f"Missing local target: {name}: {href}")
                continue
            if parsed.fragment and target.suffix == ".html":
                target_page = pages.get(relative) or Page(target.read_text())
                if unquote(parsed.fragment) not in target_page.ids:
                    errors.append(f"Missing local fragment: {name}: {href}")
    return errors


def main():
    outputs = {str(name): html for name, html in build_notes.render_notes().items()}
    assert len(outputs) == len(build_notes.NOTES) == 7, "Expected seven explicit published notes"
    errors = check_pages(outputs)
    for name, html in outputs.items():
        target = ROOT / name
        if not target.exists() or target.read_text() != html:
            errors.append(f"Stale or missing rendered note: {name}")
    # Check authored headings/explicit anchors independently of renderer output equality.
    for source in build_notes.NOTES:
        source = Path(source)
        source = source if source.is_absolute() else ROOT / source
        output = str(source.relative_to(ROOT).with_suffix(".html"))
        page = Page(outputs[output])
        text = source.read_text()
        from markdown_it import MarkdownIt
        tokens = MarkdownIt("commonmark", {"html": True}).enable("table").parse(text)
        for token in tokens:
            for child in token.children or []:
                if child.type != "link_open":
                    continue
                href = child.attrGet("href")
                parsed = urlsplit(href)
                target = posixpath.normpath(posixpath.join(posixpath.dirname(str(source.relative_to(ROOT))), unquote(parsed.path)))
                if not parsed.scheme and not parsed.netloc and target in build_notes.NOTES:
                    href = urlunsplit(parsed._replace(path=parsed.path[:-3] + ".html"))
                if href not in page.links:
                    errors.append(f"Lost or wrongly rewritten source link: {output}: {href}")
        for anchor in re.findall(r'<a\s+id="([^"]+)"', text):
            if anchor not in page.ids:
                errors.append(f"Lost explicit anchor: {output}#{anchor}")
        # Ignore fenced code when counting authored heading lines.
        prose = re.sub(r"^```[^\n]*\n.*?^```\s*$", "", text, flags=re.M | re.S)
        expected_headings = re.findall(r"^(#{1,6})\s+", prose, re.M)
        if len(page.headings) != len(expected_headings):
            errors.append(f"Lost source headings: {output}")
    bad = check_pages({"negative.html": '<h1 id="same">x</h1><h2 id="same">y</h2><a href="#absent">x</a><a href="no-such-fixture.txt">x</a><a href="LEARNING_RESOURCES.md">x</a>'})
    assert len(bad) == 4, bad
    inputs = [ROOT / "build_notes.py", ROOT / "notes-template.html", *[ROOT / Path(name) for name in build_notes.NOTES]]
    report = {"notes": len(outputs), "errors": errors, "input_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, "output_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in outputs if (ROOT / name).exists()}}
    (ROOT / "research/testing-notes.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
