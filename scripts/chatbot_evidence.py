#!/usr/bin/env python3
"""Decode chatbot output representations and compare exposed tool arguments."""

import argparse
import base64
import hashlib
import json
import math
import re
import uuid
from pathlib import Path


NATO = dict(zip(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'alfa bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu'.split()))
NATO = {name: letter for letter, name in NATO.items()} | {'alpha': 'A', 'juliet': 'J'}
NATO.update({name: str(number) for number, name in enumerate('zero one two three four five six seven eight nine'.split())})
NATO.update({'dash': '-', 'hyphen': '-', 'underscore': '_', 'space': ' ', 'leftbrace': '{', 'rightbrace': '}'})


def _private(root):
    run = Path(root or '.autosolve/runs') / f'chat-evidence-{uuid.uuid4().hex[:12]}'
    run.mkdir(parents=True, mode=0o700)
    return run


def _input(path, limit=128 * 1024):
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > limit:
        raise ValueError('input must be a regular file within the size limit')
    return source.read_text()


def _nested(value, field):
    for part in field.split('.'):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise ValueError(f'missing audit field: {field}')
    return value


def _changed_paths(left, right, prefix=''):
    if type(left) is not type(right):
        return [prefix or '<root>']
    if isinstance(left, dict):
        return [path for key in sorted(set(left) | set(right))
                for path in ([f'{prefix}.{key}'.lstrip('.')]
                             if key not in left or key not in right else
                             _changed_paths(left[key], right[key], f'{prefix}.{key}'.lstrip('.')))]
    if isinstance(left, list):
        return [path for index in range(max(len(left), len(right)))
                for path in ([f'{prefix}.{index}'.lstrip('.')]
                             if index >= len(left) or index >= len(right) else
                             _changed_paths(left[index], right[index], f'{prefix}.{index}'.lstrip('.')))]
    return [prefix or '<root>'] if left != right else []


def decode(text, mode):
    text = text.strip()
    if mode == 'codepoints':
        values = json.loads(text)
        if not isinstance(values, list) or len(values) > 4096 or any(type(x) is not int or not 0 <= x <= 0x10ffff or 0xd800 <= x <= 0xdfff for x in values):
            raise ValueError('codepoints require a JSON array of Unicode scalar integers')
        return ''.join(map(chr, values))
    if mode == 'characters':
        values = json.loads(text)
        if not isinstance(values, list) or len(values) > 4096 or any(not isinstance(x, str) or len(x) != 1 for x in values):
            raise ValueError('characters require a JSON array of one-character strings')
        return ''.join(values)
    if mode == 'embedding-bytes':
        values = json.loads(text)
        if not isinstance(values, list) or not 1 <= len(values) <= 4096 or any(type(x) not in (int, float) or not math.isfinite(x) or not 0 <= x <= 1 for x in values):
            raise ValueError('embedding-bytes needs 1-4096 finite values between 0 and 1')
        return bytes(round(value * 255) for value in values).rstrip(b'\x00').decode('utf-8')
    if mode == 'nato':
        words = re.findall(r'[A-Za-z]+', text.lower().replace('x-ray', 'xray'))
        if not words or len(words) > 4096 or any(word not in NATO for word in words):
            raise ValueError('unknown NATO or spelling word')
        return ''.join(NATO[word] for word in words)
    if mode == 'initials':
        words = re.findall(r'\b\w+', text)
        if not words or len(words) > 4096:
            raise ValueError('initials need 1-4096 words')
        return ''.join(word[0] for word in words)
    if mode == 'reversed':
        return text[::-1]
    if mode == 'groups':
        return re.sub(r'[\s-]+', '', text)
    if mode == 'base64':
        return base64.b64decode(text, validate=True).decode('utf-8')
    raise ValueError('unknown decoding mode')


def audit(text, line, fields):
    if line is not None:
        lines = text.splitlines()
        if not 1 <= line <= len(lines):
            raise ValueError('transcript line is out of range')
        value = json.loads(lines[line - 1])
        if not isinstance(value, dict):
            raise ValueError('transcript line must be a JSON object')
        value = value.get('response', value)
    else:
        value = json.loads(text)
    stages = {name: _nested(value, field) for name, field in fields.items()}
    fingerprints = {name: {'type': type(item).__name__, 'sha256': hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()}
                    for name, item in stages.items()}
    pairs = []
    ordered = list(stages)
    for before, after in zip(ordered, ordered[1:]):
        left, right = stages[before], stages[after]
        changed = _changed_paths(left, right)[:100]
        pairs.append({'from': before, 'to': after, 'equal': left == right,
                      'type_changed': type(left).__name__ != type(right).__name__, 'changed_paths': changed})
    return {'stages': fingerprints, 'comparisons': pairs,
            'limit': 'argument differences are leads; applied state needs a direct authorized check'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root')
    modes = parser.add_subparsers(dest='mode', required=True)
    dec = modes.add_parser('decode')
    dec.add_argument('--input', required=True)
    dec.add_argument('--mode', dest='encoding', required=True, choices=('codepoints', 'characters', 'embedding-bytes', 'nato', 'initials', 'reversed', 'groups', 'base64'))
    check = modes.add_parser('audit')
    check.add_argument('--input', required=True)
    check.add_argument('--line', type=int, help='one-based transcript JSONL line')
    for name in ('raw', 'validated', 'normalized', 'applied'):
        check.add_argument(f'--{name}-field', default=f'args_{name}')
    args = parser.parse_args(argv)
    try:
        text = _input(args.input)
        run = _private(args.runs_root)
        if args.mode == 'decode':
            candidate = decode(text, args.encoding)
            target = run / 'candidate.txt'
            target.write_text(candidate)
            target.chmod(0o600)
            result = {'state': 'candidate', 'mode': args.encoding, 'length': len(candidate),
                      'sha256': hashlib.sha256(candidate.encode()).hexdigest(), 'candidate_file': str(target)}
        else:
            result = audit(text, args.line, {name: getattr(args, f'{name}_field') for name in ('raw', 'validated', 'normalized', 'applied')})
        report = run / 'result.json'
        report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': 'complete', 'report': str(report),
                          'candidate_file': result.get('candidate_file')}))
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print(json.dumps({'status': 'invalid_input', 'reason': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
