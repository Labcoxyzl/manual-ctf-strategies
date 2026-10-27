"""Offline, bounded text clues with exact source byte spans."""

import ipaddress
import re
from heapq import merge
from urllib.parse import urlsplit


_URL = re.compile(r"(?<![A-Za-z0-9_])https?://[^\s<>\"'`]+", re.I)
_EMAIL = re.compile(r"(?<![A-Za-z0-9_.+%-])[A-Za-z][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![A-Za-z0-9_-])")
_HANDLE = re.compile(r"(?<![A-Za-z0-9_.@])@[A-Za-z][A-Za-z0-9_]{2,29}(?![A-Za-z0-9_])")
_COORDS = re.compile(r"(?<![A-Za-z0-9_.])[-+]?(?:[0-8]?\d|90)\.\d{3,8}\s*,\s*[-+]?(?:1[0-7]\d|[0-9]?\d|180)\.\d{3,8}(?![A-Za-z0-9_]|\.\d)")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_AMBIGUITY = {
    'url': 'URL pattern only; destination and ownership unverified',
    'email': 'email pattern only; mailbox and ownership unverified',
    'handle': 'handle pattern only; platform and identity unverified',
    'coordinates': 'numeric coordinate pattern only; location unverified',
}


def _valid_host(host: str) -> bool:
    if len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split('.')
    return (len(labels) >= 2 and 2 <= len(labels[-1]) <= 24 and labels[-1].isalpha()
            and all(_LABEL.fullmatch(label) for label in labels))


def _valid_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return (parts.scheme.lower() in ('http', 'https') and '@' not in parts.netloc
                and parts.hostname is not None
                and _valid_host(parts.hostname) and (parts.port is None or parts.port > 0)
                and len(value) <= 2048)
    except ValueError:
        return False


def extract_identifiers(data: bytes, *, max_bytes: int = 1024 * 1024,
                        max_records: int = 128) -> tuple[list[dict], list[str]]:
    """Return local leads only; byte spans are [offset, offset + length) in input."""
    if not isinstance(data, bytes):
        raise TypeError('identifier input must be bytes')
    if not 0 < max_bytes <= 4 * 1024 * 1024 or not 0 < max_records <= 512:
        raise ValueError('identifier limits must be positive and bounded')
    warnings = []
    truncated = len(data) > max_bytes
    if truncated:
        warnings.append(f'source byte scan limit reached; results cover first {max_bytes} bytes')
        data = data[:max_bytes]
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        encoding = 'utf-16-le' if data[:2] == b'\xff\xfe' else 'utf-16-be'
        try:
            text = data[2:].decode(encoding)
        except UnicodeDecodeError:
            return [], warnings + ['invalid BOM-marked UTF-16; identifier scan incomplete']
        base = 2
    else:
        try:
            text = data.decode('utf-8')
            encoding = 'utf-8'
        except UnicodeDecodeError:
            text = data.decode('latin-1')
            encoding = 'latin-1'
        base = 0

    def scan(rank, kind, pattern):
        return ((match.start(), rank, kind, match) for match in pattern.finditer(text))

    streams = (scan(rank, kind, pattern) for rank, (kind, pattern) in
               enumerate((('url', _URL), ('email', _EMAIL), ('handle', _HANDLE),
                          ('coordinates', _COORDS))))
    matches = []
    blocked_until = 0
    for start, _, kind, match in merge(*streams):
        if start < blocked_until:
            continue
        if kind == 'url':
            blocked_until = match.end()
            if truncated and match.end() == len(text):
                continue
            value = match.group().rstrip('.,;:!?)]}’”')
            if not value or not _valid_url(value):
                continue
        else:
            if truncated and match.end() == len(text):
                continue
            value = match.group()
            if kind == 'email' and (len(value) > 320 or not _valid_host(value.rsplit('@', 1)[1])):
                continue
            if kind == 'coordinates':
                latitude, longitude = value.split(',', 1)
                if abs(float(latitude)) > 90 or abs(float(longitude)) > 180:
                    continue
        matches.append((start, start + len(value), kind, value))
        if len(matches) > max_records:
            break
    if len(matches) > max_records:
        warnings.append('identifier record limit reached; later clues omitted')
        matches = matches[:max_records]

    records = []
    cursor, offset = 0, base
    for start, end, kind, value in matches:
        offset += len(text[cursor:start].encode(encoding))
        length = len(value.encode(encoding))
        records.append({'kind': kind, 'value': value, 'byte_offset': offset,
                        'byte_length': length, 'encoding': encoding,
                        'locator': f'bytes {offset}-{offset + length}',
                        'ambiguity': _AMBIGUITY[kind]})
        cursor = start
    return records, warnings
