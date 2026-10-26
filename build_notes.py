"""Render the explicitly linked local notes without changing their Markdown sources."""
import hashlib
import html
from pathlib import Path
import posixpath
from string import Template
from urllib.parse import unquote, urlsplit, urlunsplit

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent
NOTE_OUTPUTS = {source: str(Path(source).with_suffix(".html")) for source in (
    "LEARNING_RESOURCES.md", "PRACTICE_WORKSHEETS.md", "HASHCAT.md", "CTF_CHEATSHEET.md", "CORE_WORKFLOWS.md", "SPECIALIST_WORKFLOWS.md",
    "APPROVED_TOOL_REFERENCES.md", "EVENT_SOURCES.md", "RESOURCE_EVALUATION.md",
    "research/learning/practice/README.md",
    "research/learning/video-coverage/practice/TRIAGE_PRACTICE.md",
    "research/learning/video-coverage/practice/AUDIO_PRACTICE.md",
)}
NOTE_OUTPUTS.update({"scripts/README.md": "TOOLKIT.html", "scripts/chatbot_strategies.md": "CHATBOT_STRATEGIES.html", "docs/public-rules.md": "RULES.html", "scripts/templates/README.md": "TEMPLATES.html", "examples/core/README.md": "CORE_PRACTICE.html"})
NOTES = tuple(NOTE_OUTPUTS)
NOTE_LINKS = {**NOTE_OUTPUTS, "research/learning/review.md": "research/learning/review.html"}


def render_notes(read_bytes=None):
    """Return {relative HTML path: document}; the site builder owns file writes."""
    if read_bytes is None:
        read_bytes = lambda source: (ROOT / source).read_bytes()
    template = Template(read_bytes("notes-template.html").decode("utf-8"))
    # Sources are trusted repository prose; raw HTML supplies anchors and answer disclosures.
    markdown = MarkdownIt("commonmark", {"html": True}).enable("table")
    markdown.renderer.rules["table_open"] = lambda *args: (
        '<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable table"><table>\n'
    )
    markdown.renderer.rules["table_close"] = lambda *args: '</table></div>\n'
    pages = {}
    for source, output in NOTE_OUTPUTS.items():
        raw = read_bytes(source)
        tokens = markdown.parse(raw.decode("utf-8"))
        title = next(tokens[index + 1].content for index, token in enumerate(tokens)
                     if token.type == "heading_open" and token.tag == "h1")
        for token in tokens:
            for child in token.children or []:
                if child.type != "link_open":
                    continue
                url = urlsplit(child.attrGet("href"))
                target = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(url.path)))
                if not url.scheme and not url.netloc and url.path:
                    target = NOTE_LINKS.get(target, target)
                    path = posixpath.relpath(target, posixpath.dirname(output) or ".")
                    child.attrSet("href", urlunsplit(url._replace(path=path)))
        pages[output] = template.substitute(
            title=html.escape(title),
            field_guide=posixpath.relpath("index.html", posixpath.dirname(output) or "."),
            source=html.escape(Path(source).name),
            source_sha256=hashlib.sha256(raw).hexdigest(),
            content=markdown.renderer.render(tokens, markdown.options, {}),
        )
    return pages
