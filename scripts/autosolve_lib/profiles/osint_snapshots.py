"""Source-linked, offline relationships among supplied site and document artifacts."""

import bisect
from datetime import date
import hashlib
import os
from pathlib import Path
import posixpath
import re
import stat
import time
from urllib.parse import unquote, urlsplit


_DATE = re.compile(rb'(?<![0-9])((?:19|20)[0-9]{2})[-/]([0-9]{1,2})[-/]([0-9]{1,2})(?![0-9])')
_STATIC = {'.html', '.htm', '.js', '.mjs', '.cjs', '.map', '.pdf', '.txt', '.md', '.json',
           '.xml', '.csv', '.eml', '.png', '.jpg', '.jpeg', '.gif', '.zip', '.docx', '.xlsx'}
_DOC = {'.pdf', '.txt', '.md', '.eml', '.docx'}
_REF_KINDS = {'link', 'resource', 'source_map_ref', 'source_map_source'}
_AMBIGUITY = 'Offline supplied snapshot only; relation and current live state are unverified'


def _name(value):
    if not isinstance(value, str) or not value or '\x00' in value or '\\' in value:
        return None
    name = posixpath.normpath(value)
    if name.startswith('/') or name in ('.', '..') or name.startswith('../'):
        return None
    return name


def _local_name(source_name, value, base=None):
    if not isinstance(value, str) or len(value) > 2048:
        return None, 'invalid'
    try:
        parts = urlsplit(value)
    except ValueError:
        return None, 'invalid'
    if parts.scheme or parts.netloc:
        return None, 'external'
    if not parts.path:
        return source_name, 'local'
    path = unquote(parts.path)
    if '\\' in path or '\x00' in path:
        return None, 'invalid'
    if path.startswith('/'):
        candidate = path.lstrip('/')
    else:
        directory = posixpath.dirname(source_name)
        if base:
            try:
                base_parts = urlsplit(base)
            except ValueError:
                return None, 'invalid'
            if base_parts.scheme or base_parts.netloc:
                return None, 'external'
            if base_parts.path:
                base_path = unquote(base_parts.path)
                if base_path.startswith('/'):
                    directory = base_path.lstrip('/')
                else:
                    directory = posixpath.join(directory, base_path)
                if not base_path.endswith('/'):
                    directory = posixpath.dirname(directory)
        candidate = posixpath.join(directory, path)
    name = _name(candidate)
    return name, 'local' if name else 'outside_snapshot'


def _read(source, max_file_bytes):
    path = Path(source['path'])
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None, 'not a regular file'
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None, 'not a regular file'
            if info.st_size > max_file_bytes:
                return None, 'source byte limit reached'
            data = stream.read(max_file_bytes + 1)
    except OSError as error:
        return None, f'source unavailable: {type(error).__name__}'
    if len(data) > max_file_bytes:
        return None, 'source byte limit reached'
    if hashlib.sha256(data).hexdigest() != source.get('sha256'):
        return None, 'source changed since its recorded identity'
    return data, None


def build_snapshot_trail(sources, *, max_sources=64, max_file_bytes=1024 * 1024,
                         max_total_bytes=8 * 1024 * 1024, max_records=512,
                         timeout=5.0):
    """Join existing WEB01/OS02 records with dated local files; never fetch URLs.

    Each source supplies artifact_id, source_name (snapshot-relative), path, sha256,
    and optional web_records / identifier_records from the existing profiles.
    """
    if (not 0 < max_sources <= 128 or not 0 < max_file_bytes <= 4 * 1024 * 1024
            or not 0 < max_total_bytes <= 16 * 1024 * 1024 or not 0 < max_records <= 1024
            or not 0 < timeout <= 30):
        raise ValueError('snapshot limits must be positive and bounded')
    if not isinstance(sources, (list, tuple)):
        raise TypeError('sources must be a list or tuple')
    warnings = []
    if len(sources) > max_sources:
        warnings.append('snapshot source count limit reached')
    deadline = time.monotonic() + timeout
    selected = sources[:max_sources]
    names = {}
    records = []
    total_bytes = 0
    verified = []
    dates = []
    links_by_source = {}
    for source in selected:
        if time.monotonic() >= deadline:
            warnings.append('snapshot analysis timed out')
            break
        artifact_id = source.get('artifact_id')
        name = _name(source.get('source_name'))
        if not isinstance(artifact_id, str) or not artifact_id or name is None:
            warnings.append('snapshot source identity or relative name invalid')
            continue
        data, error = _read(source, max_file_bytes)
        if error:
            warnings.append(f'{name}: {error}')
            continue
        total_bytes += len(data)
        if total_bytes > max_total_bytes:
            warnings.append('snapshot total byte limit reached')
            break
        verified.append((source, name, artifact_id, data))
        names.setdefault(name, []).append(artifact_id)
    for source, name, artifact_id, data in verified:
        if time.monotonic() >= deadline:
            warnings.append('snapshot analysis timed out')
            break
        line_starts = [0] + [match.end() for match in re.finditer(b'\n', data)]

        def location(offset, length, kind, value, relation='direct_observation', **details):
            if len(records) >= max_records:
                if 'snapshot record limit reached' not in warnings:
                    warnings.append('snapshot record limit reached')
                return None
            if not isinstance(offset, int) or not 0 <= offset < len(data):
                return None
            row = {'kind': kind, 'value': value, 'source_artifact_id': artifact_id,
                   'source_name': name, 'source_offset': offset,
                   'source_length': min(max(1, length), len(data) - offset),
                   'source_line': bisect.bisect_right(line_starts, offset),
                   'relation': relation, 'ambiguity': _AMBIGUITY}
            row.update(details)
            records.append(row)
            return row

        web_records = source.get('web_records') or []
        base = next((row['value'] for row in web_records if row.get('kind') == 'base'), None)
        seen = set()
        for item in web_records:
            if time.monotonic() >= deadline:
                warnings.append('snapshot analysis timed out')
                break
            kind, value, offset = item.get('kind'), item.get('value'), item.get('offset')
            if not isinstance(value, str) or not isinstance(offset, int):
                continue
            encoded = value.encode('utf-8', 'surrogateescape')
            length = len(encoded) if data[offset:offset + len(encoded)] == encoded else 1
            if kind in ('html_comment', 'js_comment'):
                location(offset, length, 'comment', value)
            elif kind in _REF_KINDS:
                target, scope = _local_name(name, value, base if kind != 'source_map_source' else None)
                if scope == 'local' and target in names and len(names[target]) == 1:
                    row = location(offset, length, 'local_link', value, 'direct_link',
                                   target_name=target, target_artifact_id=names[target][0])
                    if row:
                        links_by_source.setdefault(artifact_id, []).append(row)
                elif scope == 'local' and target in names:
                    location(offset, length, 'ambiguous_target', value, 'unresolved_local_reference',
                             target_name=target)
                elif scope == 'local' and target and posixpath.splitext(target)[1].lower() in _STATIC:
                    location(offset, length, 'missing_local_target', value, 'unresolved_local_reference',
                             target_name=target)
                else:
                    location(offset, length, 'reference', value, 'unresolved_reference', scope=scope)
            elif kind in ('literal_endpoint', 'form'):
                location(offset, length, 'endpoint', value)
            seen.add((offset, value))
        for item in source.get('identifier_records') or []:
            if item.get('kind') != 'url':
                continue
            offset, value = item.get('byte_offset'), item.get('value')
            if not isinstance(offset, int) or not isinstance(value, str) or (offset, value) in seen:
                continue
            location(offset, item.get('byte_length', 1), 'url', value)
        for match in _DATE.finditer(data):
            if time.monotonic() >= deadline:
                warnings.append('snapshot analysis timed out')
                break
            try:
                value = date(*(int(part) for part in match.groups())).isoformat()
            except ValueError:
                continue
            row = location(match.start(), len(match.group()), 'date', value)
            if row:
                dates.append(row)
    claims = {}
    for row in dates:
        links = [link for link in links_by_source.get(row['source_artifact_id'], [])
                 if link['source_line'] == row['source_line']
                 and abs(link['source_offset'] - row['source_offset']) <= 256]
        if not links:
            continue
        link = min(links, key=lambda item: abs(item['source_offset'] - row['source_offset']))
        row['inferred_target_artifact_id'] = link['target_artifact_id']
        row['relation'] = 'inferred_near_link'
        claims.setdefault(link['target_artifact_id'], []).append(row)
    for row in dates:
        if (row['relation'] == 'direct_observation'
                and posixpath.splitext(row['source_name'])[1].lower() in _DOC
                and row['source_artifact_id'] in claims):
            row['relation'] = 'inferred_document_date'
            claims[row['source_artifact_id']].append(row)
    for target_id, rows in claims.items():
        if len({row['value'] for row in rows}) < 2:
            continue
        first = rows[0]
        if len(records) >= max_records:
            if 'snapshot record limit reached' not in warnings:
                warnings.append('snapshot record limit reached')
            break
        records.append({'kind': 'date_conflict', 'value': next(
            name for name, ids in names.items() if target_id in ids),
            'source_artifact_id': first['source_artifact_id'],
            'source_name': first['source_name'], 'source_offset': first['source_offset'],
            'source_length': first['source_length'], 'source_line': first['source_line'],
            'relation': 'inferred_conflict', 'ambiguity': _AMBIGUITY,
            'target_artifact_id': target_id,
            'claims': [{'date': row['value'], 'source_artifact_id': row['source_artifact_id'],
                        'source_name': row['source_name'], 'source_offset': row['source_offset'],
                        'relation': row['relation']} for row in rows]})
    return records, list(dict.fromkeys(warnings))
