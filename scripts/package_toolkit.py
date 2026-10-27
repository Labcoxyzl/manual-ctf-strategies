#!/usr/bin/env python3
"""Export only the authored offline guide and toolkit into a new directory."""
import argparse
from collections import Counter
import html
from html.parser import HTMLParser
import os
from pathlib import Path
import posixpath
import shutil
import stat
import sys
from urllib.parse import unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PAGES = (
    'index.html', 'keyword-preview.html', 'TOOLKIT.html', 'CHATBOT_STRATEGIES.html', 'RULES.html', 'HASHCAT.html', 'TEMPLATES.html', 'CTF_CHEATSHEET.html', 'CORE_WORKFLOWS.html', 'CORE_PRACTICE.html',
    'LEARNING_RESOURCES.html', 'PRACTICE_WORKSHEETS.html', 'SPECIALIST_WORKFLOWS.html',
    'APPROVED_TOOL_REFERENCES.html', 'RESOURCE_EVALUATION.html',
    'research/learning/practice/README.html',
    'research/learning/video-coverage/practice/TRIAGE_PRACTICE.html',
    'research/learning/video-coverage/practice/AUDIO_PRACTICE.html',
)
COMPANIONS = (
    'examples/core/README.md', 'examples/core/SHA256SUMS',
    'examples/core/can-capture.txt', 'examples/core/can-malformed.asc',
    'examples/core/cyberchef-recipe.json', 'examples/core/gzip-base64.txt',
    'examples/core/not-gzip-base64.txt', 'examples/core/http.pcap',
    'examples/core/http-incomplete.pcap', 'examples/core/expected.txt',
    'examples/core/checker.c', 'examples/core/RecoverComparison.java',
    'examples/core/http-port19091.pcap', 'examples/core/carrier.png',
    'examples/core/appended.png', 'examples/core/attachment.pdf',
    'examples/core/streams.pdf', 'examples/core/expected-payload.bin',
    'examples/core/disk.img', 'examples/core/gdb-checker.c',
    'examples/core/expected-lsb.txt', 'examples/core/expected-stream.txt',

    'HASHCAT.md', 'CTF_CHEATSHEET.md', 'CORE_WORKFLOWS.md',
    'research/learning/practice/http-demo.pcap',
    'research/learning/practice/check_input.c',
    'research/learning/practice/match.txt',
    'research/learning/practice/near-miss.txt',
    'research/learning/practice/training.yar',
    'research/learning/practice/http/clue.txt',
    'research/learning/video-coverage/practice/triage.bin',
    'research/learning/video-coverage/practice/stream-demo.pdf',
    'research/learning/video-coverage/practice/embedded-note.rtf',
    'research/learning/video-coverage/practice/audio-tones.wav',
)
# Explicit authored fixture paths only; never discover files recursively.
FIXTURES = (
    'tests/fixtures/toolkit/development/framed-bits.txt',
    'tests/fixtures/toolkit/development/wrapped-bits.txt',
)
CODE = ('scripts/ctf.py', 'scripts/autosolve.py', 'scripts/autosolve_lib/__init__.py',
        'scripts/autosolve_lib/core.py', 'scripts/autosolve_lib/service.py',
        'scripts/autosolve_lib/service_inventory.py',
        'scripts/autosolve_lib/web.py',
        'scripts/autosolve_lib/setup.py',
        'scripts/autosolve_lib/setup_env.py', 'tests/test_autosolve_setup_env.py',
        'scripts/autosolve_requirements/core.in', 'scripts/autosolve_requirements/core.lock.txt',
        'scripts/autosolve_lib/candidates.py', 'tests/test_autosolve_candidates.py',
        'scripts/autosolve_lib/family_catalog.json', 'scripts/autosolve_lib/profiles/__init__.py',
        'scripts/autosolve_lib/profiles/encoding.py', 'scripts/autosolve_lib/profiles/documents.py',
        'scripts/autosolve_lib/profiles/tar.py', 'tests/test_autosolve_tar.py',
        'scripts/autosolve_lib/profiles/xor.py', 'tests/test_autosolve_xor.py',
        'scripts/autosolve_lib/profiles/rsa.py', 'tests/test_autosolve_rsa.py',
        'scripts/autosolve_lib/profiles/symmetric.py', 'tests/test_autosolve_symmetric.py',
        'scripts/autosolve_lib/profiles/passwords.py', 'tests/test_autosolve_passwords.py',
        'scripts/autosolve_lib/profiles/image_metadata.py', 'tests/test_autosolve_image_metadata.py',
        'scripts/autosolve_lib/profiles/canlog.py', 'tests/test_autosolve_canlog.py',
        'scripts/autosolve_lib/profiles/can_dbc.py', 'tests/test_autosolve_can_dbc.py',
        'scripts/autosolve_lib/profiles/packets.py', 'tests/test_autosolve_packets.py',
        'scripts/autosolve_lib/profiles/packet_objects.py', 'tests/test_autosolve_packet_objects.py',
        'scripts/autosolve_lib/profiles/packet_streams.py', 'tests/test_autosolve_packet_streams.py',
        'scripts/autosolve_lib/profiles/packet_tls.py', 'tests/test_autosolve_packet_tls.py',
        'scripts/autosolve_lib/profiles/sqlite.py', 'tests/test_autosolve_sqlite.py',
        'scripts/autosolve_lib/profiles/disk.py', 'tests/test_autosolve_disk.py',
        'scripts/autosolve_lib/profiles/disk_recovery.py', 'tests/test_autosolve_disk_recovery.py',
        'scripts/autosolve_lib/profiles/os_artifacts.py', 'tests/test_autosolve_os_artifacts.py',
        'scripts/autosolve_lib/profiles/memory.py', 'tests/test_autosolve_memory.py',
        'scripts/autosolve_lib/profiles/images.py', 'tests/test_autosolve_images.py',
        'scripts/autosolve_lib/profiles/zsteg.py', 'tests/test_autosolve_zsteg.py',
        'scripts/autosolve_lib/profiles/stegseek.py', 'tests/test_autosolve_stegseek.py',
        'scripts/autosolve_lib/profiles/qr.py', 'tests/test_autosolve_qr.py',
        'scripts/autosolve_lib/profiles/media.py', 'tests/test_autosolve_media.py',
        'scripts/autosolve_lib/profiles/tones.py', 'tests/test_autosolve_tones.py',
        'scripts/autosolve_lib/profiles/sstv.py', 'tests/test_autosolve_sstv.py',
        'scripts/autosolve_lib/profiles/elf.py', 'tests/test_autosolve_elf.py',
        'scripts/autosolve_lib/profiles/binary_static.py', 'tests/test_autosolve_binary_static.py',
        'scripts/autosolve_lib/profiles/checker.py', 'tests/test_autosolve_checker.py',
        'scripts/autosolve_lib/profiles/service_transport.py', 'tests/test_autosolve_service_transport.py',
        'tests/test_autosolve_service_cli.py',
        'scripts/autosolve_lib/profiles/service_inventory.py', 'tests/test_autosolve_service_inventory.py',
        'tests/test_autosolve_service_inventory_cli.py',
        'scripts/autosolve_lib/profiles/web_static.py', 'tests/test_autosolve_web_static.py',
        'scripts/autosolve_lib/profiles/web_discovery.py', 'tests/test_autosolve_web_discovery.py',
        'scripts/autosolve_lib/profiles/web_leads.py', 'tests/test_autosolve_web_leads.py',
        'scripts/autosolve_lib/profiles/web_sql.py', 'tests/test_autosolve_web_sql.py',
        'scripts/autosolve_lib/profiles/web_workflows.py', 'tests/test_autosolve_web_workflows.py',
        'scripts/autosolve_lib/profiles/jwt.py', 'tests/test_autosolve_jwt.py',
        'scripts/autosolve_lib/profiles/osint_ids.py', 'tests/test_autosolve_osint_ids.py',
        'scripts/autosolve_lib/profiles/osint_snapshots.py', 'tests/test_autosolve_osint_snapshots.py',
        'scripts/autosolve_lib/profiles/mime.py', 'tests/test_autosolve_mime.py',
        'scripts/autosolve_lib/profiles/pdf.py', 'tests/test_autosolve_pdf.py',
        'scripts/autosolve_lib/profiles/office.py', 'tests/test_autosolve_office.py',
        'scripts/autosolve_lib/profiles/chatbot.py',
        'scripts/autosolve_lib/profiles/chatbot_strategies.py',
        'scripts/ai_model.py', 'tests/test_ai_model.py', 'tests/test_autosolve_chatbot.py',
        'scripts/ai_model_attack.py', 'tests/test_ai_model_attack.py',
        'scripts/templates/ai_model_adapter.py',
        'scripts/chatbot_evidence.py', 'tests/test_chatbot_evidence.py',
        'scripts/chatbot_callback.py', 'tests/test_chatbot_callback.py',
        'scripts/chatbot_strategies.md',
        'scripts/chatbot_recipes/context_bloat.json',
        'scripts/chatbot_recipes/kb_article.json',
        'scripts/chatbot_recipes/document_upload.json',
        'scripts/chatbot_recipes/example_injection.txt',
        'scripts/chatbot_recipes/history_idor.json',
        'scripts/chatbot_recipes/vector_store.json',
        'scripts/chatbot_recipes/tool_audit.json',
        'scripts/chatbot_recipes/workflow_action.json',
        'scripts/chatbot_recipes/debug_verifier.json',
        'scripts/chatbot_recipes/scorer_batch.json',
        'scripts/chatbot_recipes/tab_claim.json',
        'scripts/chatbot_recipes/tab_heartbeat.json',
        'scripts/chatbot_recipes/sign_network.json',
        'scripts/chatbot_recipes/model_parity.json',
        'tests/test_autosolve_core.py', 'tests/test_autosolve_encoding.py',
        'tests/test_autosolve_documents.py', 'tests/test_autosolve_setup.py',
        'scripts/README.md', 'requirements.txt', 'constraints.txt', 'tests/test_toolkit.py',
        'tests/test_toolkit_acceptance.py', 'scripts/templates/pwntools_starter.py',
        'scripts/templates/README.md', 'tests/test_templates.py',
        'scripts/templates/binary_parser.py', 'scripts/templates/http_probe.py',
        'scripts/templates/jwt_inspect.py',
        'scripts/templates/datastore_pref.py', 'tests/test_datastore_pref.py',
        'scripts/templates/file_intel.py', 'scripts/templates/cross_site_form.html',
        'scripts/templates/math_client.py',
        'scripts/templates/math_demo.py', 'tests/test_math_client.py')
INTERNAL_EVIDENCE = {
    'research/learning-resources.json', 'research/learning/check-results.json',
    'research/learning/validation.json', 'research/learning/review.md',
    'research/learning/review.html',
}
PUBLIC_README = '''# Manual CTF Strategies offline toolkit

Open [index.html](index.html) in a browser. Instructions, search, worksheets and
bundled synthetic inputs work offline. External technical references need internet.
Read [TOOLKIT.html](TOOLKIT.html) for commands, limits and approved manual alternatives;
[RULES.html](RULES.html) summarizes competition restrictions.
[Core workflows](CORE_WORKFLOWS.md) prioritize the 32 Trend Micro proposals;
[specialist workflows](SPECIALIST_WORKFLOWS.html) cover the other prepared task routes.
[Practice inputs](CORE_PRACTICE.html) and the [Hashcat cheatsheet](HASHCAT.md) are available offline; [Challenge templates](TEMPLATES.html)
include file preview, JWT inspection, binary parsing, HTTP and browser-form experiments, and optional pwntools clients.
[Python requirements](requirements.txt) and [reviewed dependency pins](constraints.txt)
list the optional, non-AI packages for Linux/WSL CPython 3.11/3.12.

From this folder, in Linux or WSL with CPython 3.10 or newer:

```sh
python3 --version
python3 scripts/ctf.py doctor --workflow bytes
python3 scripts/ctf.py bits --text '01000001' --json
python3 -m unittest discover -s tests -p 'test_toolkit*.py'
python3 scripts/autosolve.py --help
```

`autosolve.py` supports bounded local encoding and declared crypto, selected
archive/document/media and offline packet inspection, static binary leads,
and an opt-in bounded checker search. Run executable checkers only inside an
isolated analysis environment; the runner's resource limits are not a sandbox.
Its explicit-origin chatbot, web and service commands may contact assigned
endpoints. `setup` installs a hash-pinned core into an isolated environment when
network access is available; `doctor` reports missing native tools. `ai_model.py`
inspects offline model metadata and checks explicit wrapper parity. Reports
remain private and mark unsupported families as partial or not implemented;
a candidate is not a validated challenge answer.

Use paths understood by that interpreter; quote paths containing spaces.
Native Windows Python is unsupported. The byte workflows use only the standard
library. Full inspection also needs approved `file` and ExifTool installations;
`doctor --workflow inspect` reports readiness without installing anything.

Locally tested on CPython 3.11.11 and 3.12.3 in Ubuntu/WSL. Python 3.10, Kali and organiser
machines remain unverified. This export is a local snapshot; it does not update
the hosted guide.
This folder contains authored content only; private evidence and organiser
source documents are excluded. Prewritten helpers are not new approved tools.
'''


def open_directory(path):
    """Pin each path component without following a replaced parent symlink."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.absolute().parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_source(root, name):
    path = root / name
    try:
        parent = open_directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
    except OSError as error:
        raise ValueError(f'Symlinked, missing or unreadable input: {name}') from error
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f'Input is not a regular file: {name}')
        return source.read()


def local_target(page, href):
    parsed = urlsplit(href)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme and parsed.scheme.lower() not in {'https', 'http', 'mailto', 'data'}:
            raise ValueError(f'Excluded URL scheme: {page}: {href}')
        return None, parsed
    if parsed.path.startswith('/') or '\\' in unquote(parsed.path):
        raise ValueError(f'Nonportable local link: {page}: {href}')
    name = (posixpath.normpath(posixpath.join(posixpath.dirname(page), unquote(parsed.path)))
            if parsed.path else page)
    if name == '..' or name.startswith('../'):
        raise ValueError(f'Link escapes export: {page}: {href}')
    return name, parsed


class PublicHTML(HTMLParser):
    """Rewrite the fixed public graph, preserving content and script text."""
    def __init__(self, page, text, outputs):
        super().__init__(convert_charrefs=False)
        self.page, self.outputs = page, outputs
        self.parts, self.omitted_anchor = [], None
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            name, parsed = local_target(self.page, attrs['href'])
            if name in INTERNAL_EVIDENCE:
                self.omitted_anchor = 'evidence'
                return
            # Old renderer versions included a Markdown-source footer.
            if attrs.get('class') == 'source-link' and name and name.endswith('.md'):
                self.omitted_anchor = 'source'
                return
            if name in {'EVENT_SOURCES.md', 'EVENT_SOURCES.html'}:
                target = 'RULES.html'
                parsed = parsed._replace(fragment='')
            else:
                target = self.outputs.get(name, name)
            if name is not None and target != name:
                relative = posixpath.relpath(target, posixpath.dirname(self.page) or '.')
                attrs['href'] = urlunsplit(parsed._replace(path=relative))
        if self.omitted_anchor == 'source':
            return
        self.parts.append('<' + tag + ''.join(
            ' ' + key + ('' if value is None else '="' + html.escape(value, quote=True) + '"')
            for key, value in attrs.items()) + '>')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == 'a' and self.omitted_anchor:
            if self.omitted_anchor == 'evidence':
                self.parts.append(' (internal evidence; not distributed)')
            self.omitted_anchor = None
        elif self.omitted_anchor != 'source':
            self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        if self.omitted_anchor != 'source':
            self.parts.append(data)

    def handle_entityref(self, name):
        self.handle_data('&' + name + ';')

    def handle_charref(self, name):
        self.handle_data('&#' + name + ';')

    def handle_comment(self, data):
        self.parts.append('<!--' + data + '-->')

    def handle_decl(self, decl):
        self.parts.append('<!' + decl + '>')


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.links, self.tools, self.routes, self.categories = [], [], [], 0, 0
        self.headings, self.exercises = 0, 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        for attr in ('href', 'src'):
            if attrs.get(attr):
                self.links.append(attrs[attr])
        classes = attrs.get('class', '').split()
        if 'data-source-ids' in attrs:
            self.tools.extend(attrs['data-source-ids'].split())
        self.routes += 'task-route' in classes
        self.categories += 'catalog' in classes
        self.headings += tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6')
        self.exercises += tag == 'details'


def validate_export(files, originals):
    from markdown_it import MarkdownIt

    allowed = set(PUBLIC_PAGES + CODE + COMPANIONS + FIXTURES) | {'README.md'}
    if set(files) != allowed:
        raise ValueError('Export contents differ from the explicit allowlist')
    pages = {name: Page(files[name].decode('utf-8')) for name in PUBLIC_PAGES}
    markdown = MarkdownIt('commonmark', {'html': True})
    pages.update({name: Page(markdown.render(data.decode('utf-8')))
                  for name, data in files.items() if name.endswith('.md')})
    for name, page in pages.items():
        if any(count != 1 for count in Counter(page.ids).values()):
            raise ValueError(f'Duplicate public anchor: {name}')
        for href in page.links:
            target, parsed = local_target(name, href)
            if target is None:
                continue
            if target not in files:
                raise ValueError(f'Excluded or unknown local target: {name}: {href}')
            if parsed.fragment and target in pages and unquote(parsed.fragment) not in pages[target].ids:
                raise ValueError(f'Missing public anchor: {name}: {href}')
        if name in originals:
            original = Page(originals[name])
            if (page.headings, page.exercises) != (original.headings, original.exercises):
                raise ValueError(f'Preparation structure lost: {name}')
    index = pages['index.html']
    canonical = {f'windows-{number}' for number in range(1, 40)} | {f'kali-{number}' for number in range(1, 162)}
    if (len(index.tools) != 200 or len(set(index.tools)) != 200
            or index.routes != 45 or index.categories != 7):
        raise ValueError('Public guide lost approved tools, categories or routes')
    if set(index.tools) != canonical:
        raise ValueError('Public guide changed canonical inventory identities')
    if files['index.html'] != files['keyword-preview.html']:
        raise ValueError('Public entry points differ')


def collect(root):
    # Build-time renderer is already installed; exported scripts do not import it.
    read_source(root, 'build_notes.py')
    sys.path.insert(0, str(root))
    import build_notes
    rendered = build_notes.render_notes(lambda name: read_source(root, name))
    originals = {name: (read_source(root, name).decode('utf-8')
                       if name in ('index.html', 'keyword-preview.html') else rendered[name])
                 for name in PUBLIC_PAGES}
    files = {name: ''.join(PublicHTML(name, source, build_notes.NOTE_OUTPUTS).parts).encode('utf-8')
             for name, source in originals.items()}
    files.update({name: read_source(root, name) for name in CODE + COMPANIONS + FIXTURES})
    files['README.md'] = PUBLIC_README.encode('utf-8')
    validate_export(files, originals)
    return files


def package(out, root=ROOT):
    root = root.resolve()
    if out.is_symlink() or out.exists():
        raise ValueError('Output must be a nonexistent directory')
    out = out.absolute()
    resolved = out.resolve()
    if resolved == root or root in resolved.parents or resolved in root.parents:
        raise ValueError('Source and output must not overlap')
    if any(part.is_symlink() for part in (out.parent, *out.parent.parents)):
        raise ValueError('Output parent must not be symlinked')
    parent = open_directory(out.parent)
    try:
        files = collect(root)
        os.mkdir(out.name, mode=0o700, dir_fd=parent)
        # Linux descriptor path keeps publication in the validated parent after renames.
        pinned = Path('/proc/self/fd') / str(parent) / out.name
        try:
            for name, content in files.items():
                target = pinned / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(content)
        except BaseException:
            shutil.rmtree(pinned)
            raise
    finally:
        os.close(parent)
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='New directory outside the development tree')
    args = parser.parse_args()
    try:
        count = package(args.out)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Export failed: {error}\n')
    print(f'Exported {count} allowlisted files to {args.out}')


if __name__ == '__main__':
    main()
