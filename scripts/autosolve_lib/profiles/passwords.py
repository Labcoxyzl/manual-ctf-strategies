"""Bounded checks of supplied passwords against explicitly declared hash recipes."""

import hashlib
import hmac
import math
import re
import time


MAX_RECORDS = 32
MAX_WORDS = 4096
MAX_WORD_BYTES = 128
MAX_SALT_BYTES = 128
MAX_SECONDS = 5
_DIGEST_BYTES = {'md5': 16, 'sha1': 20, 'sha256': 32, 'sha512': 64}
_HEX = re.compile(r'[0-9a-fA-F]+\Z')
_FIELDS = {'algorithm', 'digest', 'salt_hex', 'salt_position', 'encoding'}


def _hex_bytes(value, maximum):
    if (type(value) is not str or not value or len(value) > maximum * 2
            or len(value) % 2 or not _HEX.fullmatch(value)):
        return None
    return bytes.fromhex(value)


def inspect_password_hashes(records, words, *, budget_seconds=MAX_SECONDS):
    """Return one result per hash; only a declared recipe can verify a candidate.

    ``records`` contain ``algorithm`` and ``digest`` (hex), with optional
    ``salt_hex`` and ``salt_position`` (prefix/suffix). Unicode words use the
    record's ``encoding`` (UTF-8 by default, or Latin-1); byte words are exact.
    Results contain password bytes only after digest equality is verified.
    """
    if (type(records) is not list or len(records) > MAX_RECORDS
            or type(words) is not list or len(words) > MAX_WORDS
            or type(budget_seconds) not in (int, float) or not math.isfinite(budget_seconds)
            or budget_seconds <= 0):
        raise ValueError('hash check exceeds input or work limit')
    if any((type(word) not in (bytes, str) or len(word) > MAX_WORD_BYTES)
           for word in words):
        raise ValueError('password candidate exceeds 128 bytes or characters')

    deadline = time.monotonic() + min(budget_seconds, MAX_SECONDS)
    results = []
    for source_index, record in enumerate(records):
        row = {'family': 'ENC10', 'source_index': source_index}
        if type(record) is not dict or set(record) - _FIELDS:
            results.append({**row, 'status': 'invalid_input'})
            continue
        digest = _hex_bytes(record.get('digest'), max(_DIGEST_BYTES.values()))
        if digest is None:
            results.append({**row, 'status': 'invalid_input'})
            continue
        algorithm = record.get('algorithm')
        if algorithm is None:
            plausible = [name for name, size in _DIGEST_BYTES.items() if size == len(digest)]
            results.append({**row, 'status': 'ambiguous',
                            'evidence': {'plausible_algorithms': plausible},
                            'limitations': 'Digest length alone cannot identify its hash format.'})
            continue
        if type(algorithm) is not str or algorithm not in _DIGEST_BYTES:
            results.append({**row, 'status': 'unsupported'})
            continue
        encoding = record.get('encoding', 'utf-8')
        salt_hex = record.get('salt_hex')
        position = record.get('salt_position')
        salt = b'' if salt_hex is None else _hex_bytes(salt_hex, MAX_SALT_BYTES)
        if (len(digest) != _DIGEST_BYTES[algorithm] or encoding not in ('utf-8', 'latin-1')
                or salt is None or (salt_hex is None and position is not None)
                or (salt_hex is not None and position not in ('prefix', 'suffix'))):
            results.append({**row, 'status': 'invalid_input'})
            continue
        evidence = {'algorithm': algorithm, 'digest_hex': digest.hex(),
                    'salt_hex': salt.hex(), 'salt_position': position,
                    'encoding': encoding, 'checked': 0, 'skipped': 0}
        for candidate_index, word in enumerate(words):
            if time.monotonic() >= deadline:
                results.append({**row, 'status': 'incomplete', 'evidence': evidence,
                                'limitations': 'Time budget expired before the candidate list ended.'})
                break
            try:
                password = word if type(word) is bytes else word.encode(encoding)
            except UnicodeEncodeError:
                evidence['skipped'] += 1
                continue
            if len(password) > MAX_WORD_BYTES:
                evidence['skipped'] += 1
                continue
            message = salt + password if position == 'prefix' else password + salt
            try:
                candidate_digest = hashlib.new(algorithm, message).digest()
            except (ValueError, OSError):
                results.append({**row, 'status': 'tool_error', 'evidence': evidence})
                break
            evidence['checked'] += 1
            if hmac.compare_digest(candidate_digest, digest):
                results.append({**row, 'status': 'validated_transform',
                                'password': password,
                                'evidence': {**evidence, 'candidate_index': candidate_index,
                                             'digest_verified': True},
                                'limitations': 'Verified the declared hash recipe only.'})
                break
        else:
            status = 'incomplete' if evidence['skipped'] else 'no_match'
            results.append({**row, 'status': status, 'evidence': evidence,
                            **({'limitations': 'Some candidates could not be encoded within limits.'}
                               if evidence['skipped'] else {})})
    return results
