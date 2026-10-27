"""Finite static PowerShell constant extraction; source is never executed."""

import base64
import bisect
import binascii
import os
import re
import stat
import time
from pathlib import Path


MAX_SOURCE_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RECORDS = 64
MAX_DEPTH = 2

_LITERAL = r"(?:'(?:''|[^'])*'|\"(?:`.|[^\"`$])*\")"
_EXPR = rf'{_LITERAL}(?:\s*\+\s*{_LITERAL})*'
_CONCAT = re.compile(rf'{_LITERAL}(?:\s*\+\s*{_LITERAL})+')
_QUOTE = re.compile(_LITERAL)
_BASE64 = re.compile(rf'\[\s*convert\s*\]::frombase64string\(\s*(?P<arg>{_EXPR})\s*\)', re.I)
_BASE64_CALL = re.compile(r'\[\s*convert\s*\]::frombase64string\s*\(', re.I)
_COMMAND = re.compile(r'''(?<![\w-])-(?:encodedcommand|enc|e)\s+
    (?P<quote>['"])?(?P<arg>[A-Za-z0-9+/=]{8,})
    (?(quote)(?P=quote)|(?=$|[\s;)]))''', re.I | re.X)
_COMMAND_FLAG = re.compile(r'(?<![\w-])-(?:encodedcommand|enc|e)\s+', re.I)
_TOKEN = re.compile(r'''(?:<#[\s\S]*?(?:#>|\Z)|'(?:''|[^'])*'|"(?:`.|[^"`])*"|#[^\n]*)''')
_HERE_OPEN = re.compile(r'''@(?P<quote>['"])\r?\n''')
_VARIABLE = r'\$[A-Za-z_][\w:]*'
_DYNAMIC_STRING = r'"(?:`.|[^"`])*?\$[^"`]*"'
_VALUE = rf'(?:{_LITERAL}|{_VARIABLE}|{_DYNAMIC_STRING})'
_DYNAMIC_CONCAT = re.compile(
    rf'(?:{_VARIABLE}|{_DYNAMIC_STRING})\s*\+\s*{_VALUE}|'
    rf'{_VALUE}\s*\+\s*(?:{_VARIABLE}|{_DYNAMIC_STRING})', re.S)
_ESCAPES = {'n': '\n', 'r': '\r', 't': '\t', '0': '\0', '`': '`', '"': '"', "'": "'"}


def _read(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('source is not a regular file or exceeds byte limit')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(data) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('source changed or exceeds byte limit')
    return data


def _literal(token: str) -> str | None:
    if token[0] == "'":
        return token[1:-1].replace("''", "'")
    value = token[1:-1]
    if '$' in value:
        return None
    def escape(match):
        return _ESCAPES.get(match.group(1), '\uffff')
    value = re.sub(r'`(.)', escape, value, flags=re.S)
    return None if '\uffff' in value else value


def _expression(expr: str) -> str | None:
    tokens = _QUOTE.findall(expr)
    if not tokens or not re.fullmatch(_EXPR, expr):
        return None
    values = [_literal(token) for token in tokens]
    return None if any(value is None for value in values) else ''.join(values)


def _mask_comments(text: str) -> str:
    chars = list(text)
    for match in _TOKEN.finditer(text):
        if match.group().startswith(('#', '<#')):
            chars[match.start():match.end()] = ' ' * (match.end() - match.start())
    return ''.join(chars)


def _mask_here_strings(text: str) -> tuple[str, bool]:
    chars = list(text)
    tokens = [(match.start(), match.end()) for match in _TOKEN.finditer(text)]
    starts = [begin for begin, _ in tokens]
    cursor = 0
    unterminated = False
    while opener := _HERE_OPEN.search(text, cursor):
        start = opener.start()
        index = bisect.bisect_right(starts, start) - 1
        if index >= 0 and tokens[index][0] <= start < tokens[index][1]:
            cursor = opener.end()
            continue
        close = re.compile(rf'(?m)^[ \t]*{re.escape(opener.group("quote"))}@[ \t]*(?=\r?$)')
        terminator = close.search(text, opener.end())
        end = terminator.end() if terminator else len(text)
        for position in range(start, end):
            if chars[position] not in '\r\n':
                chars[position] = ' '
        if not terminator:
            unterminated = True
            break
        cursor = end
    return ''.join(chars), unterminated


def inspect_powershell(path: Path, *, timeout: float = 5,
                       max_source_bytes: int = MAX_SOURCE_BYTES,
                       max_output_bytes: int = MAX_OUTPUT_BYTES,
                       max_records: int = MAX_RECORDS) -> tuple[list[dict], list[str]]:
    """Return exact byte candidates and warnings for supported literal forms."""
    if not (0 < timeout <= 120 and 0 < max_source_bytes <= MAX_SOURCE_BYTES and
            0 < max_output_bytes <= MAX_OUTPUT_BYTES and 0 < max_records <= MAX_RECORDS):
        raise ValueError('invalid PowerShell inspection limits')
    try:
        source = _read(Path(path), max_source_bytes)
    except (OSError, ValueError) as error:
        return [], [f'PowerShell source unavailable or byte limit reached: {type(error).__name__}']
    if source.startswith(b'\xff\xfe'):
        codec, prefix = 'utf-16le', 2
    elif source.startswith(b'\xef\xbb\xbf'):
        codec, prefix = 'utf-8', 3
    else:
        codec, prefix = 'utf-8', 0
    try:
        text = source[prefix:].decode(codec)
    except UnicodeDecodeError:
        return [], ['PowerShell source encoding unsupported or malformed']

    records, warnings = [], []
    deadline = time.monotonic() + timeout

    def scan(script: str, depth: int, parent: dict | None = None,
             parent_chain: list[str] | None = None) -> None:
        if time.monotonic() >= deadline:
            if 'PowerShell inspection timed out; analysis incomplete' not in warnings:
                warnings.append('PowerShell inspection timed out; analysis incomplete')
            return
        here_masked, unterminated = _mask_here_strings(script)
        if unterminated:
            warnings.append('PowerShell unterminated here-string; values unresolved')
        masked = _mask_comments(here_masked)
        quotes = [(match.start(), match.end()) for match in _TOKEN.finditer(masked)
                  if match.group().startswith(("'", '"'))]
        quote_starts = [begin for begin, _ in quotes]
        unparsed = list(masked)
        for begin, end in quotes:
            unparsed[begin:end] = ' ' * (end - begin)
        if any(char in "'\"" for char in unparsed):
            warnings.append('PowerShell unsupported or malformed quotation; values unresolved')
        code_only = ''.join(unparsed)
        def outside_quote(position: int) -> bool:
            index = bisect.bisect_right(quote_starts, position) - 1
            return index < 0 or not quotes[index][0] < position < quotes[index][1]
        candidates = []
        for pattern, kind in ((_CONCAT, 'concat'), (_BASE64, 'base64'),
                              (_COMMAND, 'encoded_command')):
            candidates.extend((match.start(), match, kind) for match in pattern.finditer(masked))
        candidates.sort(key=lambda item: item[0])
        supported_positions = {'base64': set(), 'encoded_command': set()}
        for _, match, kind in candidates:
            if not outside_quote(match.start()):
                continue
            if time.monotonic() >= deadline:
                warnings.append('PowerShell inspection timed out; analysis incomplete')
                return
            if len(records) >= max_records:
                warnings.append('PowerShell record limit reached; analysis incomplete')
                return
            arg = match.group('arg') if kind != 'concat' else match.group()
            if (kind == 'encoded_command' and not match.group('quote') and
                    (script.startswith('#', match.end('arg')) or
                     script.startswith('<#', match.end('arg')))):
                warnings.append('PowerShell unsupported or malformed expression; dynamic values unresolved')
                continue
            value = _expression(arg) if kind != 'encoded_command' else arg
            if value is None:
                warnings.append('PowerShell unsupported or malformed expression; dynamic values unresolved')
                continue
            if kind == 'concat':
                data = value.encode('utf-8')
                transform = ['literal-concat']
                start, end = match.span()
            else:
                try:
                    if len(value) > max_output_bytes * 4:
                        raise ValueError('encoded input limit')
                    raw = base64.b64decode(value, validate=True)
                    if kind == 'encoded_command':
                        decoded = raw.decode('utf-16le')
                        data = decoded.encode('utf-8')
                    else:
                        data = raw
                except (ValueError, UnicodeError, binascii.Error):
                    continue
                transform = (['literal-concat'] if '+' in arg else []) + ['base64']
                if kind == 'encoded_command':
                    transform.append('utf-16le')
                start, end = match.span('arg')
                if kind == 'base64' and arg[0] in "'\"" and '+' not in arg:
                    start += 1
                    end -= 1
            if len(data) > max_output_bytes:
                warnings.append('PowerShell output byte limit reached; analysis incomplete')
                continue
            if not data:
                continue
            if parent is None:
                begin = prefix + len(script[:start].encode(codec))
                finish = prefix + len(script[:end].encode(codec))
                location = {'byte_start': begin, 'byte_end': finish,
                            'line': script.count('\n', 0, start) + 1,
                            'column': start - script.rfind('\n', 0, start),
                            'derived_spans': []}
            else:
                location = {**parent, 'derived_spans': parent['derived_spans'] + [{
                    'byte_start': len(script[:start].encode('utf-8')),
                    'byte_end': len(script[:end].encode('utf-8'))}]}
            chain = (parent_chain or []) + transform
            records.append({'kind': kind, 'data': data, 'source_locator': location,
                            'transform_chain': chain, 'state': 'candidate'})
            if kind in supported_positions:
                supported_positions[kind].add(match.start())
            if kind == 'encoded_command' and depth < MAX_DEPTH:
                scan(decoded, depth + 1, location, chain)
        if (any(match.start() not in supported_positions['base64']
                for match in _BASE64_CALL.finditer(code_only)) or
                any(match.start() not in supported_positions['encoded_command']
                    for match in _COMMAND_FLAG.finditer(code_only)) or
                any(outside_quote(match.start()) for match in _DYNAMIC_CONCAT.finditer(masked))):
            warnings.append('PowerShell unsupported or malformed expression; dynamic values unresolved')

    scan(text, 0)
    return records, list(dict.fromkeys(warnings))
