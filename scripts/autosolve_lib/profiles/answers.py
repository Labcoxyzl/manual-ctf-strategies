"""Bounded JSONL facts for explicitly declared multi-question answers."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from string import Formatter
import time


MAX_BYTES = 8 * 1024 * 1024
MAX_LINES = 4096
MAX_LINE = 64 * 1024
MAX_CHOICES = 16
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')


def validate_schema(schema):
    if type(schema) is not dict or not {'fields'} <= set(schema) <= {'fields', 'compose'}:
        raise ValueError('answer_schema requires fields and optional compose')
    fields = schema['fields']
    if type(fields) is not list or not 1 <= len(fields) <= 16:
        raise ValueError('answer_schema fields requires 1 to 16 entries')
    names = []
    for field in fields:
        if (type(field) is not dict or set(field) != {'name', 'question'} or
                type(field['name']) is not str or not NAME.fullmatch(field['name']) or
                type(field['question']) is not str or
                not 0 < len(field['question']) <= 256 or
                any(ord(char) < 32 for char in field['question'])):
            raise ValueError('answer_schema fields require bounded name and question strings')
        names.append(field['name'])
    if len(set(names)) != len(names):
        raise ValueError('answer_schema field names must be unique')
    template = schema.get('compose')
    if template is not None:
        if (type(template) is not str or not 0 < len(template) <= 512 or
                any(ord(char) < 32 for char in template)):
            raise ValueError('answer_schema compose must be bounded text')
        try:
            parts = list(Formatter().parse(template))
        except ValueError as error:
            raise ValueError('answer_schema compose has invalid braces') from error
        if not any(field is not None for _, field, _, _ in parts):
            raise ValueError('answer_schema compose must reference a field')
        if any(field is not None and (field not in names or spec or conversion)
               for _, field, spec, conversion in parts):
            raise ValueError('answer_schema compose allows only declared {field} references')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _jsonl_name(artifact):
    if Path(artifact['path']).suffix.lower() == '.jsonl':
        return True
    return any(isinstance(value, str) and Path(value).suffix.lower() == '.jsonl'
               for value in artifact.get('source_locator', {}).values())


def collect_answers(artifacts, schema, deadline):
    """Return sourced fields and an optional composition, without claiming acceptance."""
    validate_schema(schema)
    names = [field['name'] for field in schema['fields']]
    values = {name: {} for name in names}
    warnings = []
    total = 0
    lines = 0
    for artifact in artifacts:
        if not (artifact.get('current') and artifact.get('complete') and _jsonl_name(artifact)):
            continue
        if time.monotonic() >= deadline:
            warnings.append('answer JSONL work budget ended')
            break
        path = Path(artifact['path'])
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise OSError('nonregular source')
                if info.st_size > MAX_BYTES - total:
                    warnings.append(f"{artifact['id']}: answer JSONL byte limit reached")
                    break
                raw = stream.read(info.st_size + 1)
            if (len(raw) != info.st_size or len(raw) != artifact['size'] or
                    hashlib.sha256(raw).hexdigest() != artifact['sha256']):
                warnings.append(f"{artifact['id']}: answer JSONL source changed")
                continue
        except OSError:
            warnings.append(f"{artifact['id']}: answer JSONL source unavailable")
            continue
        total += len(raw)
        offset = 0
        for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
            lines += 1
            if lines > MAX_LINES or len(line) > MAX_LINE or time.monotonic() >= deadline:
                warnings.append(f"{artifact['id']}: answer JSONL line or work limit reached")
                break
            try:
                record = json.loads(line, object_pairs_hook=_object)
            except (ValueError, UnicodeError, RecursionError):
                warnings.append(f"{artifact['id']}: invalid JSONL at line {line_number}")
                offset += len(line)
                continue
            if type(record) is not dict:
                warnings.append(f"{artifact['id']}: non-object JSONL at line {line_number}")
                offset += len(line)
                continue
            for name in names:
                value = record.get(name)
                if value is None:
                    continue
                if type(value) not in (str, int) or not str(value).strip() or len(str(value)) > 512:
                    warnings.append(f"{artifact['id']}: unsupported {name} value at line {line_number}")
                    continue
                source = {'artifact_id': artifact['id'],
                          'source_locator': {'line': line_number, 'byte_offset': offset,
                                             'json_key': name}}
                if str(value) not in values[name] and len(values[name]) >= MAX_CHOICES:
                    warning = f'{name}: answer JSONL distinct value limit reached'
                    if warning not in warnings:
                        warnings.append(warning)
                    continue
                references = values[name].setdefault(str(value), [])
                if len(references) < 4:
                    references.append(source)
            offset += len(line)
        if lines > MAX_LINES or time.monotonic() >= deadline:
            break
    fields = []
    for field in schema['fields']:
        name = field['name']
        choices = values[name]
        entry = {'name': name, 'question': field['question'],
                 'status': 'unresolved' if not choices else 'answered' if len(choices) == 1 else 'conflict'}
        if len(choices) == 1:
            entry['value'], entry['sources'] = next(iter(choices.items()))
        elif choices:
            entry['alternatives'] = [{'value': value, 'sources': sources}
                                     for value, sources in choices.items()]
        fields.append(entry)
    result = {'fields': fields}
    if 'compose' in schema:
        missing = [field['name'] for field in fields if field['status'] != 'answered']
        if warnings or missing:
            result['composition'] = {'status': 'unresolved', 'missing_fields': missing,
                                     'incomplete_evidence': bool(warnings)}
        else:
            selected = {field['name']: field['value'] for field in fields}
            result['composition'] = {
                'status': 'ready',
                'value': ''.join(literal + (selected[name] if name is not None else '')
                                 for literal, name, _, _ in Formatter().parse(schema['compose'])),
                'source_fields': names}
    return result, warnings
