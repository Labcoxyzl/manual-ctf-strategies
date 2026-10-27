"""Bounded, offline inventory of supplied HTML, JavaScript and source maps."""

import bisect
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit


_TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
_MAP_REF = re.compile(r'[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)')
_ATTR = re.compile(r'\b(href|src|action|formaction)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)
_JSON_ITEM = re.compile(r'"(?:\\.|[^"\\])*"|null')
_ROUTE = re.compile(r'^(?:https?://|//|/|\./|\.\./)', re.I)


def _origin(value):
    if not isinstance(value, str) or any(char.isspace() or ord(char) < 33 for char in value):
        raise ValueError('origin must be one HTTP(S) origin')
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ValueError('invalid origin') from error
    if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in ('', '/') or parts.query or parts.fragment
            or parts.netloc.endswith(':') or port == 0):
        raise ValueError('origin must be an HTTP(S) origin without credentials or path')
    return parts.scheme, parts.hostname.lower(), port or (443 if parts.scheme == 'https' else 80)


def _scope_parts(value):
    # HTTP(S) URL parsing treats backslashes and extra leading slashes as authority separators.
    return urlsplit(re.sub(r'^/{3,}', '//', value.replace('\\', '/')))


def _scope(value, origin):
    try:
        parts = _scope_parts(value)
        port = parts.port
    except ValueError:
        return 'invalid'
    if parts.scheme and parts.scheme not in ('http', 'https'):
        return 'non_http'
    if not parts.scheme and re.match(r'^[\\/]{2}', value) and not parts.netloc:
        return 'invalid'
    if parts.scheme or parts.netloc:
        if not parts.hostname or parts.username is not None or parts.password is not None:
            return 'invalid'
        if origin is None:
            return 'unknown_origin'
        scheme = parts.scheme or origin[0]
        target = scheme, parts.hostname.lower(), port if port is not None else (443 if scheme == 'https' else 80)
        return 'same_origin' if target == origin else 'cross_origin'
    if value.startswith('/'):
        return 'same_origin' if origin is not None else 'unknown_origin'
    return 'same_origin' if origin is not None else 'relative'


class _Inventory:
    def __init__(self, path, text, origin, max_records, deadline):
        self.path, self.text, self.origin = str(path), text, origin
        self.max_records, self.deadline = max_records, deadline
        self.records, self.warnings = [], []
        self.lines, self.byte_lines = [0], [0]
        chars = byte_count = 0
        for line in text.splitlines(keepends=True):
            chars += len(line)
            byte_count += len(line.encode('utf-8', 'surrogateescape'))
            if line.endswith('\n'):
                self.lines.append(chars)
                self.byte_lines.append(byte_count)

    def location(self, char_offset):
        row = bisect.bisect_right(self.lines, char_offset) - 1
        line_start = self.lines[row]
        offset = self.byte_lines[row] + len(self.text[line_start:char_offset].encode('utf-8', 'surrogateescape'))
        return offset, row + 1, char_offset - line_start + 1

    def add(self, kind, value, char_offset, **details):
        if time.monotonic() >= self.deadline:
            raise TimeoutError
        if len(value) > 2048:
            if 'web value byte limit reached' not in self.warnings:
                self.warnings.append('web value byte limit reached')
            return
        if len(self.records) >= self.max_records:
            if 'web record limit reached' not in self.warnings:
                self.warnings.append('web record limit reached')
            return
        offset, line, column = self.location(char_offset)
        row = {'kind': kind, 'value': value, 'source': self.path, 'offset': offset,
               'line': line, 'column': column, 'locator': f'line {line} byte {offset}'}
        if kind in ('link', 'form', 'resource', 'base', 'literal_endpoint',
                    'source_map_ref', 'source_map_source'):
            row['scope'] = _scope(value, self.origin)
        row.update(details)
        self.records.append(row)

    def js(self, script, base, *, embedded_source=None, map_index=None, mapping=None):
        def add(kind, value, position, **details):
            if map_index is None:
                self.add(kind, value, base + position, **details)
                return
            inner = script[:position]
            inner_offset = len(inner.encode('utf-8', 'surrogateescape'))
            self.add(kind, value, base + mapping[position], embedded_source=embedded_source,
                     embedded_offset=inner_offset, embedded_line=inner.count('\n') + 1,
                     locator=f'sourcesContent[{map_index}] line {inner.count(chr(10)) + 1} '
                             f'offset {inner_offset}', **details)

        for token in _TOKEN.finditer(script):
            raw = token.group()
            if raw.startswith(('//', '/*')):
                add('js_comment', raw[:512], token.start(), truncated=len(raw) > 512)
                match = _MAP_REF.search(raw)
                if match:
                    add('source_map_ref', match.group(1), token.start() + match.start(1))
                continue
            if raw.startswith('`') and '${' in raw:
                continue
            value = raw[1:-1]
            if '\\' in value:
                value = re.sub(r'\\([/"\'`\\])', r'\1', value)
            if not _ROUTE.match(value) or len(value) > 2048:
                continue
            add('literal_endpoint', value, token.start() + 1)


class _HTML(HTMLParser):
    def __init__(self, inventory):
        super().__init__(convert_charrefs=True)
        self.inventory = inventory
        self.script = False
        self.base_href = None

    def handle_starttag(self, tag, attrs):
        self.script = tag == 'script'
        if tag not in ('a', 'area', 'link', 'form', 'base', 'script', 'img', 'iframe',
                       'source', 'audio', 'video'):
            return
        fields = dict(attrs)
        raw = self.get_starttag_text()
        line, column = self.getpos()
        base = self.inventory.lines[line - 1] + column
        for match in _ATTR.finditer(raw):
            name = match.group(1).lower()
            value = match.group(2) if match.group(2) is not None else match.group(3)
            if value is None:
                value = match.group(4)
            if name not in fields or html.unescape(value) != fields[name]:
                continue
            kind = ('base' if tag == 'base' and name == 'href' else
                    'form' if tag == 'form' and name == 'action' else
                    'link' if tag in ('a', 'area', 'link') else 'resource')
            if kind == 'base' and self.base_href is None:
                self.base_href = fields[name]
            details = {'tag': tag, 'attribute': name}
            if kind == 'form':
                details['method'] = (fields.get('method') or 'GET')[:16].upper()
            self.inventory.add(kind, fields[name], base + match.start(2 if match.group(2) is not None else
                                                                    3 if match.group(3) is not None else 4),
                               **details)

    def handle_endtag(self, tag):
        if tag == 'script':
            self.script = False

    def handle_data(self, data):
        if self.script:
            line, column = self.getpos()
            self.inventory.js(data, self.inventory.lines[line - 1] + column)

    def handle_comment(self, data):
        line, column = self.getpos()
        base = self.inventory.lines[line - 1] + column
        self.inventory.add('html_comment', data[:512], base + 4,
                           truncated=len(data) > 512)


def _json_items(text, key):
    decoder = json.JSONDecoder()
    position = text.find('{') + 1
    if position == 0:
        return
    while position < len(text):
        while position < len(text) and text[position] in ' \t\r\n,':
            position += 1
        if position >= len(text) or text[position] == '}':
            return
        field, position = decoder.raw_decode(text, position)
        while position < len(text) and text[position] in ' \t\r\n':
            position += 1
        if text[position] != ':':
            return
        position += 1
        while position < len(text) and text[position] in ' \t\r\n':
            position += 1
        value_start = position
        value, position = decoder.raw_decode(text, position)
        if field != key or not isinstance(value, list):
            continue
        cursor = value_start + 1
        for expected in value:
            while cursor < len(text) and text[cursor] in ' \t\r\n,':
                cursor += 1
            item = _JSON_ITEM.match(text, cursor)
            if not item or json.loads(item.group()) != expected:
                return
            yield expected, item.start(), item.group()
            cursor = item.end()
        return


def _json_mapping(token):
    # Map decoded source characters to their exact positions in the JSON string token.
    mapping = []
    index = 1
    while index < len(token) - 1:
        mapping.append(index)
        if token[index] == '\\':
            if token[index + 1] == 'u':
                end = index + 6
                if (end + 6 <= len(token) - 1 and token[end:end + 2] == '\\u'
                        and 0xD800 <= int(token[index + 2:end], 16) <= 0xDBFF):
                    end += 6
                index = end
            else:
                index += 2
        else:
            index += 1
    return mapping


def inspect_web_static(path: Path, *, origin: str | None = None, source_name: str | None = None,
                       max_bytes: int = 1024 * 1024, max_records: int = 256,
                       timeout: float = 2.0) -> tuple[list[dict], list[str]]:
    """Inventory local evidence only; returned URLs are never fetched or executed."""
    if not 0 < max_bytes <= 4 * 1024 * 1024 or not 0 < max_records <= 1000 or not 0 < timeout <= 30:
        raise ValueError('web inventory limits must be positive and bounded')
    if source_name is not None and (not isinstance(source_name, str) or len(source_name) > 256):
        raise ValueError('source name must be a bounded string')
    parsed_origin = _origin(origin) if origin is not None else None
    path = Path(path)
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return [], ['web input is not a regular file']
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return [], ['web input is not a regular file']
            if info.st_size > max_bytes:
                return [], ['web input byte limit reached']
            data = stream.read(max_bytes + 1)
    except OSError as error:
        return [], [f'web input unavailable: {type(error).__name__}']
    if len(data) > max_bytes:
        return [], ['web input byte limit reached']
    text = data.decode('utf-8', 'surrogateescape')
    inventory = _Inventory(path, text, parsed_origin, max_records, time.monotonic() + timeout)
    try:
        name = source_name or path.name
        if name.lower().endswith('.map') or (text.lstrip().startswith('{') and
                                            '"sources"' in text and '"version"' in text):
            document = json.loads(text)
            if not isinstance(document, dict) or document.get('version') != 3:
                return [], ['unsupported source map']
            sources = document.get('sources', [])
            contents = document.get('sourcesContent', [])
            if not isinstance(sources, list) or not isinstance(contents, list):
                return [], ['invalid source map sources']
            for index, (source, position, _) in enumerate(_json_items(text, 'sources')):
                if isinstance(source, str) and index < len(sources) and source == sources[index]:
                    inventory.add('source_map_source', source, position,
                                  map_index=index)
            for index, (content, position, token) in enumerate(_json_items(text, 'sourcesContent')):
                if isinstance(content, str) and index < len(contents) and content == contents[index]:
                    mapping = _json_mapping(token)
                    if len(mapping) != len(content):
                        inventory.warnings.append(f'sourcesContent[{index}]: source offset mapping incomplete')
                        continue
                    embedded_source = sources[index] if index < len(sources) else None
                    if not isinstance(embedded_source, str) or len(embedded_source) > 2048:
                        inventory.warnings.append(f'sourcesContent[{index}]: source name missing or over limit')
                        embedded_source = None
                    inventory.js(content, position, embedded_source=embedded_source,
                                 map_index=index, mapping=mapping)
        elif Path(name).suffix.lower() in ('.js', '.mjs', '.cjs') or (
                Path(name).suffix.lower() not in ('.html', '.htm') and
                not text.lstrip().startswith('<')):
            inventory.js(text, 0)
        else:
            parser = _HTML(inventory)
            parser.feed(text)
            parser.close()
            if parsed_origin is not None and parser.base_href:
                base_scope = _scope(parser.base_href, parsed_origin)
                if base_scope in ('cross_origin', 'non_http', 'invalid'):
                    for record in inventory.records:
                        if record.get('scope') in ('same_origin', 'relative'):
                            value = _scope_parts(record['value'])
                            if not value.scheme and not value.netloc:
                                record['scope'] = base_scope
    except TimeoutError:
        inventory.warnings.append('web inventory timed out; records may be incomplete')
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        inventory.warnings.append(f'web parse failed: {type(error).__name__}')
    return inventory.records, inventory.warnings
