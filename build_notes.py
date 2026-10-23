"""Render the explicitly linked local notes without changing their Markdown sources."""
import hashlib
import html
from pathlib import Path
import posixpath
from string import Template
from urllib.parse import unquote, urlsplit, urlunsplit

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent
NOTES = (
    "LEARNING_RESOURCES.md", "PRACTICE_WORKSHEETS.md",
    "APPROVED_TOOL_REFERENCES.md", "RESOURCE_EVALUATION.md", "EVENT_SOURCES.md",
    "research/learning/practice/README.md", "research/learning/review.md",
)


def render_notes():
    """Return {relative HTML path: document}; the site builder owns file writes."""
    template = Template((ROOT / "notes-template.html").read_text(encoding="utf-8"))
    # Sources are trusted repository prose; raw HTML supplies anchors and answer disclosures.
    markdown = MarkdownIt("commonmark", {"html": True}).enable("table")
    markdown.renderer.rules["table_open"] = lambda *args: (
        '<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable table"><table>\n'
    )
    markdown.renderer.rules["table_close"] = lambda *args: '</table></div>\n'
    pages = {}
    for source in NOTES:
        raw = (ROOT / source).read_bytes()
        tokens = markdown.parse(raw.decode("utf-8"))
        title = next(tokens[index + 1].content for index, token in enumerate(tokens)
                     if token.type == "heading_open" and token.tag == "h1")
        for token in tokens:
            for child in token.children or []:
                if child.type != "link_open":
                    continue
                url = urlsplit(child.attrGet("href"))
                target = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(url.path)))
                if not url.scheme and not url.netloc and url.path and target in NOTES:
                    child.attrSet("href", urlunsplit(url._replace(path=url.path[:-3] + ".html")))
        pages[str(Path(source).with_suffix(".html"))] = template.substitute(
            title=html.escape(title),
            field_guide=posixpath.relpath("index.html", posixpath.dirname(source) or "."),
            source=html.escape(Path(source).name),
            source_sha256=hashlib.sha256(raw).hexdigest(),
            content=markdown.renderer.render(tokens, markdown.options, {}),
        )
    return pages
