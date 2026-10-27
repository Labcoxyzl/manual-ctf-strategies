"""Shared run state and local artifact flow for autosolve."""

import bz2
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import resource
import shutil
import signal
import stat
import tarfile
import tempfile
import time
import uuid
import zipfile
import zlib
from collections import deque
from pathlib import Path

from .candidates import scan_candidates


ROOT = Path(__file__).resolve().parents[2]
CATALOG = json.loads(Path(__file__).with_name('family_catalog.json').read_text())['families']
DOMAINS = {row['domain'] for row in CATALOG}
ALIASES = {'crypto': 'encoding', 'audio': 'audio_video', 'video': 'audio_video',
           'disk': 'disk_memory', 'memory': 'disk_memory', 'reversing': 'malware_reversing',
           'pwn': 'pwn_services', 'service': 'pwn_services', 'can': 'can_misc',
           'misc': 'can_misc', 'archives': 'documents', 'ai': 'ai_chatbot',
           'chatbot': 'ai_chatbot'}
HINT_TYPES = {'flag_patterns': list, 'known_plaintext': str, 'password_file': str,
              'key_files': list, 'rsa_parameters': (dict, list), 'tls_keylog': str,
              'symmetric_parameters': list, 'hash_parameters': list,
              'hash_wordlist_file': str, 'disk_target_paths': list,
              'memory_image': bool, 'memory_symbol_dir': str, 'memory_dump_targets': list,
              'dbc': str, 'symbol_paths': list, 'byte_order': str, 'checker': dict,
              'scope_origin': str, 'jwt_keys': list, 'jwt_wordlist_file': str}
HINT_TYPES.update({'capa_rules': str, 'capa_signatures': str, 'yara_rules': str})
SCHEMA = 1
MAX_READ = 8 * 1024 * 1024
MAX_CHILD = 16 * 1024 * 1024
MAX_DERIVED = 512 * 1024 * 1024
MAX_ARTIFACTS = 256
MAX_DEPTH = 6


class InvalidInput(ValueError):
    pass


class RunBusy(RuntimeError):
    pass


class WorkLimit(RuntimeError):
    pass


def _worker_entry(operation, *args):
    os.setsid()
    operation(*args)


def _stop_worker(worker):
    worker.join(0.1)
    if worker.pid is not None:
        try:
            os.killpg(worker.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    worker.join(0.5)
    if worker.is_alive():
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        worker.join()


def category_name(value):
    result = ALIASES.get(value, value)
    if result != 'auto' and result not in DOMAINS:
        raise InvalidInput(f'unknown category: {value}')
    return result


def load_hints(path):
    if path is None:
        return {}, None
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise InvalidInput('hints must be a regular file')
    if p.stat().st_size > 1024 * 1024:
        raise InvalidInput('hints exceed 1 MiB')
    with p.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise InvalidInput('hints exceed 1 MiB')
    try:
        hints = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InvalidInput(f'invalid hints JSON: {error}') from error
    if not isinstance(hints, dict):
        raise InvalidInput('hints must be a JSON object')
    for key, value in hints.items():
        if key not in HINT_TYPES or not isinstance(value, HINT_TYPES[key]):
            raise InvalidInput(f'unknown or invalid hint: {key}')
    if 'known_plaintext' in hints:
        try:
            crib_bytes = hints['known_plaintext'].encode('utf-8')
        except UnicodeEncodeError as error:
            raise InvalidInput('known_plaintext must be UTF-8 text') from error
        if len(crib_bytes) > 256:
            raise InvalidInput('known_plaintext exceeds 256 UTF-8 bytes')
    if 'scope_origin' in hints:
        from .profiles.web_static import _origin
        try:
            _origin(hints['scope_origin'])
        except ValueError as error:
            raise InvalidInput(str(error)) from error
    patterns = hints.get('flag_patterns', [])
    if len(patterns) > 16 or any(not isinstance(x, str) or len(x) > 256 for x in patterns):
        raise InvalidInput('flag_patterns must contain at most 16 strings of 256 characters')
    for pattern in patterns:
        try:
            re.compile(pattern.encode())
        except (re.error, UnicodeError) as error:
            raise InvalidInput(f'invalid flag pattern: {error}') from error
    for key in ('key_files', 'symbol_paths'):
        if any(not isinstance(x, str) for x in hints.get(key, [])):
            raise InvalidInput(f'{key} must contain paths')
    for key in ('capa_rules', 'capa_signatures', 'yara_rules'):
        value = hints.get(key)
        if value is not None and (not value or len(value) > 4096 or
                                  any(ord(char) < 32 for char in value)):
            raise InvalidInput(f'{key} must be a bounded path')
    targets = hints.get('disk_target_paths', [])
    if len(targets) > 32 or any(not isinstance(value, str) or not value or len(value) > 512
                              or value.startswith('/') or any(ord(char) < 32 for char in value)
                              or any(part in ('', '.', '..') for part in value.split('/'))
                              for value in targets):
        raise InvalidInput('disk_target_paths must contain at most 32 safe relative paths')
    symbol_dir = hints.get('memory_symbol_dir')
    if symbol_dir is not None and (not symbol_dir or len(symbol_dir) > 4096 or
                                   any(ord(char) < 32 for char in symbol_dir)):
        raise InvalidInput('memory_symbol_dir must be a bounded directory path')
    memory_targets = hints.get('memory_dump_targets', [])
    if len(memory_targets) > 8 or any(
            type(item) is not dict or set(item) != {'address', 'space', 'name'} or
            type(item['address']) is not int or not 0 <= item['address'] < 2 ** 64 or
            item['space'] not in ('physical', 'virtual') or
            type(item['name']) is not str or not 0 < len(item['name']) <= 512 or
            any(ord(char) < 32 for char in item['name']) for item in memory_targets):
        raise InvalidInput('memory_dump_targets require at most 8 exact address, space and name records')
    _rsa_parameters(hints, path)
    _symmetric_parameters(hints)
    _hash_parameters(hints)
    _jwt_hints(hints, path)
    if 'checker' in hints:
        from .profiles.checker import _hints as checker_hints
        try:
            checker_hints(hints['checker'])
        except ValueError as error:
            raise InvalidInput(str(error)) from error
    return hints, hashlib.sha256(raw).hexdigest()


def _jwt_hints(hints, hints_path):
    records = hints.get('jwt_keys', [])
    if len(records) > 32:
        raise InvalidInput('jwt_keys allows at most 32 records')

    def read_private(name, limit):
        source = Path(name)
        if not source.is_absolute():
            source = Path(hints_path).absolute().parent / source
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise InvalidInput('JWT private material is not a bounded regular file')
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
        except OSError as error:
            raise InvalidInput('JWT private material is unavailable') from error
        if (len(raw) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise InvalidInput('JWT private material changed or exceeded its limit')
        return raw

    keys, identities = [], []
    paths = hints.get('key_files', [])
    for index, record in enumerate(records):
        if (type(record) is not dict or set(record) - {'alg', 'kid', 'key_file_index'}
                or set(record) - {'kid'} != {'alg', 'key_file_index'}
                or record['alg'] not in ('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512')
                or type(record['key_file_index']) is not int
                or not 0 <= record['key_file_index'] < len(paths)
                or 'kid' in record and (type(record['kid']) is not str or
                                        len(record['kid']) > 256)):
            raise InvalidInput(f'invalid JWT key declaration {index}')
        material = read_private(paths[record['key_file_index']], 4096)
        if not material:
            raise InvalidInput(f'JWT key file {index} is empty')
        keys.append({'alg': record['alg'], 'key': material, **({'kid': record['kid']}
                    if 'kid' in record else {})})
        identities.append((record['alg'], record.get('kid'), hashlib.sha256(material).hexdigest()))
    words = []
    word_hash = None
    if 'jwt_wordlist_file' in hints:
        raw = read_private(hints['jwt_wordlist_file'], 1024 * 257)
        words = raw.split(b'\n') if raw else []
        if raw.endswith(b'\n'):
            words.pop()
        words = [word.removesuffix(b'\r') for word in words]
        if len(words) > 1024 or any(not 0 < len(word) <= 256 for word in words):
            raise InvalidInput('JWT wordlist allows at most 1024 nonempty words of 256 bytes')
        word_hash = hashlib.sha256(raw).hexdigest()
    fingerprint = hashlib.sha256(json.dumps([identities, word_hash],
                                         sort_keys=True).encode()).hexdigest()
    return keys, words, fingerprint


def _symmetric_parameters(hints):
    records = hints.get('symmetric_parameters')
    if records is None:
        return [], None
    if not isinstance(records, list) or len(records) > 32:
        raise InvalidInput('symmetric_parameters must contain at most 32 records')
    allowed = {'algorithm', 'mode', 'key', 'nonce', 'iv', 'ciphertext', 'tag', 'aad', 'padding'}
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) - allowed:
            raise InvalidInput(f'invalid symmetric record {index}')
        mode = record.get('mode')
        if record.get('algorithm') != 'AES' or mode not in ('GCM', 'CBC', 'CTR'):
            raise InvalidInput(f'unsupported symmetric algorithm/mode in record {index}')
        for field in ('key', 'ciphertext', 'nonce', 'iv', 'tag', 'aad'):
            if field not in record:
                continue
            value = record[field]
            if (not isinstance(value, str) or len(value) > 2 * 1024 * 1024
                    or len(value) % 2 or re.fullmatch(r'[0-9a-fA-F]*', value) is None):
                raise InvalidInput(f'invalid hex {field} in symmetric record {index}')
        key = record.get('key')
        if key is None or len(key) not in (32, 48, 64) or 'ciphertext' not in record:
            raise InvalidInput(f'symmetric record {index} needs AES key and ciphertext')
        if mode == 'GCM':
            if ('iv' in record or 'padding' in record or 'nonce' not in record
                    or 'tag' not in record or not 16 <= len(record['nonce']) <= 256
                    or not 8 <= len(record['tag']) <= 32):
                raise InvalidInput(f'invalid GCM parameters in record {index}')
        elif mode == 'CBC':
            if (any(field in record for field in ('nonce', 'tag', 'aad'))
                    or len(record.get('iv', '')) != 32 or len(record['ciphertext']) % 32
                    or record.get('padding', 'none') not in ('none', 'pkcs7')):
                raise InvalidInput(f'invalid CBC parameters in record {index}')
        elif (any(field in record for field in ('iv', 'tag', 'aad', 'padding'))
              or len(record.get('nonce', '')) != 32):
            raise InvalidInput(f'invalid CTR parameters in record {index}')
    return records, hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def _hash_parameters(hints):
    records = hints.get('hash_parameters')
    if records is None:
        return [], None
    if len(records) > 32:
        raise InvalidInput('hash_parameters must contain at most 32 records')
    allowed = {'algorithm', 'digest', 'salt_hex', 'salt_position', 'encoding'}
    for index, record in enumerate(records):
        if type(record) is not dict or set(record) - allowed:
            raise InvalidInput(f'invalid hash record {index}')
        digest = record.get('digest')
        if (type(digest) is not str or not 0 < len(digest) <= 128
                or len(digest) % 2 or re.fullmatch(r'[0-9a-fA-F]+', digest) is None):
            raise InvalidInput(f'hash record {index} needs a bounded hex digest')
        salt = record.get('salt_hex')
        if salt is not None and (type(salt) is not str or not 0 < len(salt) <= 256
                                 or len(salt) % 2 or re.fullmatch(r'[0-9a-fA-F]+', salt) is None):
            raise InvalidInput(f'hash record {index} has invalid salt hex')
    return records, hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def _rsa_parameters(hints, hints_path=None):
    from .profiles.rsa import parse_public_key
    supplied = hints.get('rsa_parameters')
    if supplied is None:
        return [], None
    if isinstance(supplied, dict):
        records = supplied.get('records', [supplied])
        if set(supplied) - {'records'} and 'records' in supplied:
            raise InvalidInput('rsa_parameters object with records has unknown fields')
    else:
        records = supplied
    if not isinstance(records, list) or len(records) > 32:
        raise InvalidInput('rsa_parameters must contain at most 32 records')
    normalized = []
    for index, record in enumerate(records):
        key_fields = {'public_key_pem', 'public_key_der_hex', 'key_file_index'}
        if not isinstance(record, dict) or set(record) - {'n', 'e', 'c', 'message_label', *key_fields}:
            raise InvalidInput(f'invalid RSA record {index}')
        item = {}
        supplied_key = key_fields.intersection(record)
        if supplied_key:
            if len(supplied_key) != 1 or 'n' in record or 'e' in record:
                raise InvalidInput(f'RSA record {index} must select one public key source')
            field = next(iter(supplied_key))
            value = record[field]
            if field == 'key_file_index':
                paths = hints.get('key_files', [])
                if type(value) is not int or not 0 <= value < len(paths) or hints_path is None:
                    raise InvalidInput(f'RSA record {index} has invalid key file index')
                key_path = Path(paths[value])
                if not key_path.is_absolute():
                    key_path = Path(hints_path).absolute().parent / key_path
                try:
                    fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode) or before.st_size > 16384:
                            raise InvalidInput(f'RSA record {index} needs a regular public key file')
                        value = stream.read(16385)
                        after = os.fstat(stream.fileno())
                except OSError as error:
                    raise InvalidInput(f'RSA record {index} needs a regular public key file') from error
                if len(value) > 16384:
                    raise InvalidInput(f'RSA record {index} public key file exceeds 16 KiB')
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    raise InvalidInput(f'RSA record {index} public key file changed while reading')
            elif field == 'public_key_der_hex':
                if (not isinstance(value, str) or len(value) > 32768 or len(value) % 2
                        or re.fullmatch(r'[0-9a-fA-F]+', value) is None):
                    raise InvalidInput(f'RSA record {index} needs DER hex public key')
                value = bytes.fromhex(value)
            elif not isinstance(value, str) or len(value) > 16384:
                raise InvalidInput(f'RSA record {index} needs PEM public key')
            public = parse_public_key(value)
            if public is None:
                raise InvalidInput(f'RSA record {index} has unsupported public key')
            item.update(public)
        for field in (('c',) if supplied_key else ('n', 'e', 'c')):
            value = record.get(field)
            if type(value) is int:
                item[field] = value
            elif (isinstance(value, str) and len(value) <= 1300
                  and re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)', value)):
                item[field] = int(value, 16 if value.lower().startswith('0x') else 10)
            else:
                raise InvalidInput(f'RSA record {index} needs literal integer {field}')
        if (item['n'] <= 3 or item['n'] % 2 == 0 or item['n'].bit_length() > 4096
                or not 2 <= item['e'] <= 65537 or not 0 <= item['c'] < item['n']):
            raise InvalidInput(f'RSA record {index} has out-of-range parameters')
        label = record.get('message_label')
        if label is not None:
            if not isinstance(label, str) or not 0 < len(label) <= 128:
                raise InvalidInput(f'invalid RSA message_label in record {index}')
            item['message_label'] = label
        normalized.append(item)
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    return normalized, digest


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _write_text(path, value):
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _event(run, event, **fields):
    with (run / 'events.jsonl').open('a') as stream:
        stream.write(json.dumps({'at': time.time(), 'event': event, **fields}, sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def _hash(path, deadline):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        while True:
            if time.monotonic() >= deadline:
                return None
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _kind(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        source_size = os.fstat(stream.fileno()).st_size
        head = stream.read(4096)
        header = head[:512]
        try:
            if head.startswith((b'\x1f\x8b', b'BZh', b'\xfd7zXZ\x00')):
                compressed = io.BytesIO(head + stream.read(65536 - len(head)))
            if head.startswith(b'\x1f\x8b'):
                with gzip.GzipFile(fileobj=compressed) as decoded:
                    header = decoded.read(512)
            elif head.startswith(b'BZh'):
                with bz2.BZ2File(compressed) as decoded:
                    header = decoded.read(512)
            elif head.startswith(b'\xfd7zXZ\x00'):
                with lzma.LZMAFile(compressed) as decoded:
                    header = decoded.read(512)
            if len(header) == 512:
                tarfile.TarInfo.frombuf(header, 'utf-8', 'surrogateescape')
                return 'tar'
        except (tarfile.TarError, OSError, EOFError, ValueError,
                zlib.error, lzma.LZMAError):
            pass
    if len(head) >= 8 and head[4:8] == b'ftyp':
        return 'mp4'
    if head.startswith(b'MZ') and len(head) >= 0x40:
        pe_offset = int.from_bytes(head[0x3c:0x40], 'little')
        if pe_offset <= len(head) - 4 and head[pe_offset:pe_offset + 4] == b'PE\0\0':
            return 'pe'
    if re.fullmatch(rb'dex\n0(?:3[5-9]|4[01])\x00', head[:8]):
        return 'dex'
    signatures = ((b'PK\x03\x04', 'zip'), (b'7z\xbc\xaf\x27\x1c', '7z'),
                  (b'\x1f\x8b', 'gzip'),
                  (b'\x89PNG\r\n\x1a\n', 'png'), (b'BM', 'bmp'), (b'%PDF-', 'pdf'),
                  (b'SQLite format 3\x00', 'sqlite'),
                  (b'regf', 'registry'), (b'ElfFile\x00', 'evtx'),
                  (b'\xd4\xc3\xb2\xa1', 'pcap'), (b'\xa1\xb2\xc3\xd4', 'pcap'),
                  (b'\x4d\x3c\xb2\xa1', 'pcap'), (b'\xa1\xb2\x3c\x4d', 'pcap'),
                  (b'\x0a\x0d\x0d\x0a', 'pcapng'),
                  (b'\xff\xd8\xff', 'jpeg'), (b'GIF87a', 'gif'),
                  (b'GIF89a', 'gif'), (b'II*\x00', 'tiff'), (b'MM\x00*', 'tiff'),
                  (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'office'),
                  (b'\x7fELF', 'elf'), (b'RIFF', 'riff'),
                  (b'fLaC', 'flac'), (b'OggS', 'ogg'),
                  (b'\x1a\x45\xdf\xa3', 'matroska'), (b'ID3', 'mp3'))
    for signature, kind in signatures:
        if head.startswith(signature):
            return kind
    if len(head) >= 512 and head[510:512] == b'\x55\xaa' and any(
            head[446 + index * 16 + 4] and
            int.from_bytes(head[446 + index * 16 + 8:446 + index * 16 + 12], 'little') and
            int.from_bytes(head[446 + index * 16 + 12:446 + index * 16 + 16], 'little')
            for index in range(4)):
        return 'disk_image'
    if len(head) >= 2048:
        from .profiles.disk import is_raw_ext_image
        if is_raw_ext_image(head, source_size):
            return 'disk_image'
    header = head.replace(b'\r\n', b'\n').split(b'\n\n', 1)[0].lower()
    if b'mime-version:' in header or b'content-type: multipart/' in header:
        return 'mime'
    if head.lstrip().startswith(b'{\\rtf'):
        return 'office'
    if (re.search(rb'(?m)^\(\d+(?:\.\d+)?\)\s+\S+\s+[0-9A-Fa-f]{3,8}(?:#|\s+\[)', head)
            or re.search(rb'(?m)^\S+\s+(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})(?:#|\s+\[)', head)
            or (re.search(rb'(?im)^base\s+(?:hex|dec)\s+timestamps', head)
                and (b' Rx ' in head or b' Tx ' in head))):
        return 'can_log'
    return 'text' if head and sum(32 <= byte < 127 or byte in (9, 10, 13)
                                  for byte in head) >= len(head) * .85 else 'binary'


def _sources(path, *, allow_empty=False, exclude=None, excluded_files=(), excluded_identities=()):
    source = Path(path).absolute()
    private = {Path(item).absolute() for item in excluded_files}
    private_identities = {tuple(item) for item in excluded_identities}
    for item in private:
        try:
            metadata = item.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            private_identities.add((metadata.st_dev, metadata.st_ino))
    if source.is_symlink():
        raise InvalidInput('source symlinks are not accepted')
    if source.is_file():
        metadata = source.stat(follow_symlinks=False)
        if source in private or (metadata.st_dev, metadata.st_ino) in private_identities:
            raise InvalidInput('private hint data cannot be analyzed as a challenge input')
        return [source]
    if not source.is_dir():
        raise InvalidInput('source must be a regular file or directory')
    result = []
    excluded = Path(exclude).absolute() if exclude else None
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink()
                         and (Path(base) / d).absolute() != excluded
                         and (Path(base) / d).absolute() not in private)
        for name in sorted(files):
            p = Path(base) / name
            if p.is_symlink() or not p.is_file() or p.absolute() in private:
                continue
            metadata = p.stat(follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) in private_identities:
                continue
            result.append(p)
            if len(result) > MAX_ARTIFACTS:
                raise InvalidInput('directory contains more than 256 regular files')
    if not result and not allow_empty:
        raise InvalidInput('directory contains no regular files')
    return result


def _private_paths(hints_path, hints):
    if hints_path is None:
        return ()
    values = [str(Path(hints_path).absolute())]
    for key in ('password_file', 'hash_wordlist_file', 'jwt_wordlist_file',
                'tls_keylog', 'dbc', 'memory_symbol_dir',
                'capa_rules', 'capa_signatures', 'yara_rules'):
        if key in hints:
            values.append(hints[key])
    for key in ('key_files', 'symbol_paths'):
        values.extend(hints.get(key, []))
    paths = []
    for value in values:
        path = Path(value)
        paths.append(path.absolute())
        if not path.is_absolute():
            paths.append((Path(hints_path).absolute().parent / path).absolute())
    return paths


def _remember_private_hints(manifest, hints_path, hints):
    paths = set(manifest.get('private_hint_paths', []))
    identities = {tuple(item) for item in manifest.get('private_hint_identities', [])}
    private_dirs = {}
    for key, cap in (('memory_symbol_dir', 512), ('capa_rules', 4096),
                     ('capa_signatures', 4096)):
        if key in hints:
            directory = Path(hints[key])
            if not directory.is_absolute():
                directory = Path(hints_path).absolute().parent / directory
            private_dirs[directory.absolute()] = cap
    for path in _private_paths(hints_path, hints):
        paths.add(str(path.absolute()))
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            identities.add((metadata.st_dev, metadata.st_ino))
        elif stat.S_ISDIR(metadata.st_mode) and path.absolute() in private_dirs:
            count = 0
            directories = 0
            for base, _, files in os.walk(path, followlinks=False):
                directories += 1
                if directories > 2048:
                    raise InvalidInput('memory symbol directory exceeds 2048 directories')
                for name in files:
                    item = Path(base) / name
                    info = item.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        identities.add((info.st_dev, info.st_ino))
                        count += 1
                        if count > private_dirs[path.absolute()]:
                            raise InvalidInput('private hint directory file limit reached')
    manifest['private_hint_paths'] = sorted(paths)
    manifest['private_hint_identities'] = sorted(map(list, identities))


def _edge_locator(artifact, edge):
    if 'source_locator' in edge:
        return edge['source_locator']
    if artifact['parents'] and edge is artifact['parents'][0]:
        return artifact['source_locator']
    return {'transform': edge['operation']}


def _refresh_current(manifest, source_ids):
    current = set(source_ids)
    current_password = manifest.get('password_file_sha256')
    fingerprints = manifest.get('current_adapter_fingerprints', {})
    jobs_by_id = {job['id']: job for job in manifest['jobs']}
    producers = {}
    for job in manifest['jobs']:
        for child_id in job.get('child_ids', []):
            producers.setdefault(child_id, []).append(job)

    def valid_job(job):
        return (job['status'] == 'complete' and
                job.get('tool_fingerprint') in fingerprints.get(job['adapter_id'], []) and
                (job['adapter_id'] != 'packet-tls' or
                 job.get('data_fingerprints', {}).get('tls_keylog') == manifest.get('tls_keylog_sha256')) and
                (job['adapter_id'] != 'can-dbc' or
                 job.get('data_fingerprints', {}).get('dbc') == manifest.get('dbc_sha256')) and
                (job['adapter_id'] != 'disk' or
                 job.get('data_fingerprints', {}).get('disk_target_paths') ==
                 manifest.get('disk_target_paths_sha256')) and
                (job['adapter_id'] != 'memory' or
                 (job.get('data_fingerprints', {}).get('memory_symbols') ==
                  manifest.get('memory_symbols_sha256') and
                  job.get('data_fingerprints', {}).get('memory_targets') ==
                  manifest.get('memory_targets_sha256') and
                  job['input_ids'][0] in manifest.get('memory_routed_input_ids', []))) and
                (job['adapter_id'] != 'os-artifact' or
                 job.get('data_fingerprints', {}).get('sqlite_companions') ==
                 manifest.get('sqlite_companions', {}).get(job['input_ids'][0])) and
                (job['adapter_id'] != 'web-static' or
                 job.get('data_fingerprints', {}).get('scope_origin') ==
                 manifest.get('web_scope_origin')) and
                (job['adapter_id'] != 'jwt' or
                 job.get('data_fingerprints', {}).get('jwt_hints') ==
                 manifest.get('jwt_hints_sha256')) and
                (job['adapter_id'] != 'xor-search' or
                 job.get('data_fingerprints', {}).get('known_plaintext') ==
                 manifest.get('xor_crib_sha256')) and
                (job['adapter_id'] != 'rev-rules' or
                 job.get('data_fingerprints', {}).get('rule_hints') ==
                 manifest.get('rev_rules_identity')) and
                (job['adapter_id'] != 'checker' or
                 job.get('data_fingerprints', {}).get('checker_hints') ==
                 manifest.get('checker_hints_sha256')) and
                (job['adapter_id'] != 'osint-snapshots' or
                 (all(source_id in current for source_id in job['input_ids']) and
                  job.get('data_fingerprints', {}).get('scope_origin') ==
                  manifest.get('web_scope_origin'))))

    valid_producers = {child_id: {job['key']: job for job in jobs if valid_job(job)}
                       for child_id, jobs in producers.items()}

    def current_edge(artifact, edge):
        job = valid_producers.get(artifact['id'], {}).get(edge.get('job_key'))
        if edge['id'] not in current or job is None:
            return False
        if (job['adapter_id'] in ('zip', '7z', 'stegseek') and
                job.get('data_fingerprints', {}).get('password_file') != current_password):
            return False
        if (job['adapter_id'] == 'sqlite' and
                artifact['source_locator'].get('sqlite_companion_sha256') !=
                manifest.get('sqlite_companions', {}).get(edge['id'])):
            return False
        return True

    while True:
        children = {artifact['id'] for artifact in manifest['artifacts']
                    if artifact['depth'] > 0 and artifact['complete']
                    and (any(current_edge(artifact, edge) for edge in artifact['parents']) or
                         (artifact['source_locator'].get('symmetric_hint_index') is not None and
                          artifact['source_locator'].get('symmetric_parameters_sha256') ==
                          manifest.get('symmetric_parameters_sha256') and
                          artifact.get('producer_key') in valid_producers.get(artifact['id'], {})))}
        if children <= current:
            break
        current |= children
    for artifact in manifest['artifacts']:
        artifact['current'] = artifact['id'] in current
        if artifact['current'] and artifact['depth'] > 0:
            edges = [edge for edge in artifact['parents'] if current_edge(artifact, edge)]
            artifact['current_source_locators'] = (
                [{'parent_id': edge['id'], 'operation': edge['operation'],
                  'locator': _edge_locator(artifact, edge)} for edge in edges]
                if edges else [{'producer_key': artifact.get('producer_key'),
                                'locator': artifact['source_locator']}])
        else:
            artifact.pop('current_source_locators', None)
    for finding in manifest['findings']:
        if 'hash_parameters_sha256' in finding:
            finding['current'] = (finding['hash_parameters_sha256'] == manifest.get('hash_parameters_sha256')
                                  and finding.get('hash_wordlist_sha256') ==
                                  manifest.get('hash_wordlist_sha256')
                                  and (job := jobs_by_id.get(finding.get('job_id'))) is not None
                                  and valid_job(job))
        elif 'rsa_parameters_sha256' in finding:
            finding['current'] = (finding['rsa_parameters_sha256'] == manifest.get('rsa_parameters_sha256')
                                  and (job := jobs_by_id.get(finding.get('job_id'))) is not None
                                  and valid_job(job))
        elif 'symmetric_parameters_sha256' in finding:
            finding['current'] = (finding['symmetric_parameters_sha256'] ==
                                  manifest.get('symmetric_parameters_sha256')
                                  and (job := jobs_by_id.get(finding.get('job_id'))) is not None
                                  and valid_job(job)
                                  and (finding['artifact_id'] is None or finding['artifact_id'] in current))
        else:
            finding['current'] = (finding['artifact_id'] in current and
                                  (finding['operation'] not in ('user pattern', 'printable text') or
                                   finding.get('pattern_sha256') == manifest.get('candidate_pattern_sha256'))
                                  and (finding.get('job_id') is None or
                                       ((job := jobs_by_id.get(finding['job_id'])) is not None and
                                        valid_job(job))))
    for item in manifest.get('intelligence', []):
        job = jobs_by_id.get(item.get('job_id'))
        item['current'] = (item['artifact_id'] in current and not item.get('superseded', False)
                           and job is not None and valid_job(job))


def _upgrade_lineage(manifest):
    if manifest.get('lineage_schema') == 2:
        return
    by_id = {item['id']: item for item in manifest['artifacts']}
    prefixes = {'zip': ('zip member',), 'tar': ('tar member',),
                'mime': ('MIME part',), 'pdf': ('PDF ',),
                'png-tail': ('PNG tail',), 'xor-one': ('single-byte XOR',),
                'xor-search': ('single-byte XOR', 'repeating-key XOR'),
                'sqlite': ('SQLite ',), 'disk': ('disk file',),
                'disk-recovery': ('disk recovered', 'disk carve'),
                'image-metadata': ('image frame',)}
    missing = 0
    for child in manifest['artifacts']:
        if child['depth'] == 0:
            continue
        for edge in child['parents']:
            if edge.get('job_key') is not None:
                continue
            parent = by_id.get(edge['id'])
            matches = set()
            for job in manifest['jobs']:
                if child['id'] not in job.get('child_ids', []):
                    continue
                if job['adapter_id'] in prefixes:
                    if not edge['operation'].startswith(prefixes[job['adapter_id']]):
                        continue
                elif job['adapter_id'] == 'encoding':
                    if edge['operation'].startswith(('zip member', 'tar member', 'MIME part', 'PDF ', 'PNG tail',
                                                     'single-byte XOR', 'repeating-key XOR',
                                                     'SQLite ', 'image frame')):
                        continue
                else:
                    continue
                if parent and any(by_id.get(input_id, {}).get('sha256') == parent['sha256']
                                  for input_id in job.get('input_ids', [])):
                    matches.add(job['key'])
            if len(matches) == 1:
                edge['job_key'] = matches.pop()
            else:
                missing += 1
    manifest['lineage_schema'] = 2
    if missing:
        manifest['warnings'].append(f'{missing} older artifact edge(s) lack verifiable job identity')


def _descends_from(manifest, artifact_id, ancestor_id):
    if artifact_id == ancestor_id:
        return True
    by_id = {item['id']: item for item in manifest['artifacts']}
    pending = [artifact_id]
    visited = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        for edge in by_id[current]['parents']:
            if edge['id'] == ancestor_id:
                return True
            pending.append(edge['id'])
    return False


def _source_record(path, deadline):
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise InvalidInput(f'nonregular source: {path}')
    digest = _hash(path, deadline)
    after = path.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise InvalidInput(f'source changed during hashing: {path}')
    return {'id': uuid.uuid4().hex, 'sha256': digest, 'size': before.st_size,
            'path': str(path), 'kind_evidence': _kind(path), 'complete': digest is not None,
            'parents': [], 'source_locator': {'path': str(path)}, 'depth': 0,
            'current': True}


def _store_child(run, manifest, parent, data, operation, deadline, *, source_locator=None,
                 force_record=False, producer_key=None):
    if not data or len(data) > MAX_CHILD:
        return None
    if manifest['derived_bytes'] + len(data) > MAX_DERIVED or len(manifest['artifacts']) >= MAX_ARTIFACTS:
        manifest['warnings'].append('derived artifact limit reached')
        return None
    digest = hashlib.sha256(data).hexdigest()
    locator = source_locator or {'transform': operation}
    if digest == parent['sha256']:
        return None
    ancestors = {parent['id']}
    while True:
        earlier = {edge['id'] for item in manifest['artifacts'] if item['id'] in ancestors
                   for edge in item['parents']}
        if earlier <= ancestors:
            break
        ancestors |= earlier
    for old in manifest['artifacts']:
        if (not force_record and old['sha256'] == digest and old['complete']
                and old['id'] not in ancestors and old['depth'] > 0):
            old_path = Path(old['path'])
            if old_path.is_symlink() or not old_path.is_file() or _hash(old_path, deadline) != digest:
                old['complete'] = False
                old['current'] = False
                continue
            edge = {'id': parent['id'], 'operation': operation, 'job_key': producer_key,
                    'source_locator': locator}
            if edge not in old['parents']:
                old['parents'].append(edge)
            old['current'] = True
            return old
    target = run / 'artifacts' / digest
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        fd, name = tempfile.mkstemp(prefix='.stage-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    child = {'id': uuid.uuid4().hex, 'sha256': digest, 'size': len(data),
             'path': str(target), 'kind_evidence': _kind(target), 'complete': True,
             'parents': [{'id': parent['id'], 'operation': operation, 'job_key': producer_key,
                          'source_locator': locator}],
             'source_locator': locator, 'depth': parent['depth'] + 1,
             'current': True}
    manifest['artifacts'].append(child)
    manifest['derived_bytes'] += len(data)
    _event(run, 'artifact', id=child['id'], sha256=digest, parent=parent['id'])
    return child


def _store_symmetric_plaintext(run, manifest, job, index, data, deadline):
    if not data or len(data) > MAX_CHILD or manifest['derived_bytes'] + len(data) > MAX_DERIVED:
        manifest['warnings'].append('authenticated plaintext empty or exceeds derived artifact limit')
        return None
    if len(manifest['artifacts']) >= MAX_ARTIFACTS:
        manifest['warnings'].append('derived artifact count limit reached')
        return None
    digest = hashlib.sha256(data).hexdigest()
    target = run / 'artifacts' / digest
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or not target.is_file() or _hash(target, deadline) != digest:
        fd, name = tempfile.mkstemp(prefix='.stage-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    child = {'id': uuid.uuid4().hex, 'sha256': digest, 'size': len(data),
             'path': str(target), 'kind_evidence': _kind(target), 'complete': True,
             'parents': [], 'producer_key': job['key'],
             'source_locator': {'symmetric_hint_index': index,
                                'symmetric_parameters_sha256': job['data_fingerprints']['symmetric_parameters'],
                                'authentication': 'GCM tag verified'},
             'depth': 1, 'current': True}
    manifest['artifacts'].append(child)
    manifest['derived_bytes'] += len(data)
    _event(run, 'artifact', id=child['id'], sha256=digest, producer=job['id'])
    return child


def _store_staged(run, manifest, parent, record, deadline, *, locator=None,
                  operation=None, producer_key=None):
    stage = Path(record['path'])
    size = stage.stat().st_size
    if size != record['size'] or size + manifest['derived_bytes'] > MAX_DERIVED:
        manifest['warnings'].append('ZIP member changed or exceeded the derived byte limit')
        return None
    digest = _hash(stage, deadline)
    if digest is None or digest != record['sha256']:
        manifest['warnings'].append('ZIP member identity incomplete or changed')
        return None
    if digest == parent['sha256']:
        return None
    operation = operation or f"zip member {record['index']}"
    locator = locator or {'archive_member': record['member'], 'member_index': record['index']}
    ancestors = {parent['id']}
    while True:
        earlier = {edge['id'] for item in manifest['artifacts'] if item['id'] in ancestors
                   for edge in item['parents']}
        if earlier <= ancestors:
            break
        ancestors |= earlier
    for old in manifest['artifacts']:
        if (old['complete'] and old['depth'] > 0 and old['sha256'] == digest
                and old['source_locator'] == locator and old['id'] not in ancestors):
            old_path = Path(old['path'])
            if old_path.is_symlink() or not old_path.is_file() or _hash(old_path, deadline) != digest:
                old['complete'] = False
                old['current'] = False
                continue
            edge = {'id': parent['id'], 'operation': operation, 'job_key': producer_key,
                    'source_locator': locator}
            if edge not in old['parents']:
                old['parents'].append(edge)
            old['current'] = True
            return old
    if len(manifest['artifacts']) >= MAX_ARTIFACTS:
        manifest['warnings'].append('derived artifact count limit reached')
        return None
    target = run / 'artifacts' / digest
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and _hash(target, deadline) != digest):
        os.replace(stage, target)
    elif not target.exists():
        os.link(stage, target)
    child = {'id': uuid.uuid4().hex, 'sha256': digest, 'size': size, 'path': str(target),
             'kind_evidence': _kind(target), 'complete': True,
             'parents': [{'id': parent['id'], 'operation': operation, 'job_key': producer_key,
                          'source_locator': locator}],
             'source_locator': locator,
             'depth': parent['depth'] + 1, 'current': True}
    manifest['artifacts'].append(child)
    manifest['derived_bytes'] += size
    _event(run, 'artifact', id=child['id'], sha256=digest, parent=parent['id'])
    return child


def _passwords(hints, hints_path):
    name = hints.get('password_file')
    if not name:
        return [], None
    source = Path(name)
    if not source.is_absolute():
        source = Path(hints_path).absolute().parent / source
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 64 * 1024:
        raise InvalidInput('password_file must be a regular file of at most 64 KiB')
    with source.open('rb') as stream:
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise InvalidInput('password_file exceeds 64 KiB')
    values = raw.split(b'\n') if raw else []
    if raw.endswith(b'\n'):
        values.pop()
    values = [line.removesuffix(b'\r') for line in values]
    if len(values) > 8 or any(len(value) > 128 for value in values):
        raise InvalidInput('password_file allows at most eight candidates of 128 bytes')
    return values, hashlib.sha256(raw).hexdigest()


def _hash_wordlist(hints, hints_path):
    name = hints.get('hash_wordlist_file')
    if not name:
        return [], None
    source = Path(name)
    if not source.is_absolute():
        source = Path(hints_path).absolute().parent / source
    maximum = 4096 * 129
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise InvalidInput('hash_wordlist_file must be a regular file of at most 528384 bytes')
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise InvalidInput('hash_wordlist_file must be a readable regular file') from error
    if (len(raw) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise InvalidInput('hash_wordlist_file exceeded limit or changed while reading')
    words = raw.split(b'\n') if raw else []
    if raw.endswith(b'\n'):
        words.pop()
    if len(words) > 4096 or any(len(word) > 128 for word in words):
        raise InvalidInput('hash_wordlist_file allows at most 4096 exact byte lines of 128 bytes')
    return words, hashlib.sha256(raw).hexdigest()


def _sqlite_companions(path, deadline):
    fingerprints = {}
    for suffix in ('-wal', '-shm'):
        companion = path.with_name(path.name + suffix)
        if companion.is_symlink():
            fingerprints[suffix] = 'symlink'
        elif companion.exists():
            fingerprints[suffix] = _hash(companion, deadline) or 'incomplete'
        else:
            fingerprints[suffix] = None
    digest = hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()
    return fingerprints, digest


def _zip_worker(path, staging, max_members, max_bytes, passwords, pipe):
    from .profiles.documents import extract_zip
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_DERIVED, MAX_DERIVED))
    try:
        with zipfile.ZipFile(path) as archive:
            encrypted_indices = {index for index, info in enumerate(archive.infolist()[:max_members])
                                 if info.flag_bits & 1 and not info.is_dir()}
        records, warnings = extract_zip(path, staging / 'plain', max_members=max_members,
                                        max_total_bytes=max_bytes)
        total = sum(record['size'] for record in records)
        warnings = [warning for warning in warnings if 'password required' not in warning]
        recovered = set()
        if passwords and encrypted_indices:
            for index, password in enumerate(passwords):
                extracted, _ = extract_zip(
                    path, staging / f'password-{index}', max_members=max_members,
                    max_total_bytes=max(0, max_bytes - total), password=password,
                    encrypted_only=True)
                for item in extracted:
                    if item['index'] not in recovered:
                        records.append(item)
                        recovered.add(item['index'])
                        total += item['size']
                    else:
                        item['path'].unlink()
                if recovered >= encrypted_indices:
                    break
        for index in sorted(encrypted_indices - recovered):
            warnings.append(f'member {index}: ' + ('supplied passwords did not validate'
                                                 if passwords else 'password required'))
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_zip(path, staging, max_members, max_bytes, passwords, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_zip_worker, path, staging, max_members, max_bytes, passwords, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('ZIP extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _sevenzip_worker(path, staging, max_members, max_bytes, passwords, executable, pipe):
    from .profiles.sevenzip import extract_7z
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_DERIVED, MAX_DERIVED))
    try:
        records, warnings = extract_7z(path, staging, max_members=max_members,
                                        max_total_bytes=max_bytes, max_member_bytes=MAX_CHILD,
                                        passwords=passwords, executable=executable)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_sevenzip(path, staging, max_members, max_bytes, passwords, executable, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_sevenzip_worker, path, staging, max_members,
                                           max_bytes, passwords, executable, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('7z extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _tar_worker(path, staging, max_members, max_bytes, pipe):
    from .profiles.tar import extract_tar
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_DERIVED, MAX_DERIVED))
    try:
        records, warnings = extract_tar(path, staging, max_members=max_members,
                                        max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_tar(path, staging, max_members, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_tar_worker, path, staging, max_members, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('TAR extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _mime_worker(path, staging, max_parts, max_bytes, pipe):
    from .profiles.mime import parse_mime
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = parse_mime(path, staging, max_parts=max_parts, max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_mime(path, staging, max_parts, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_mime_worker, path, staging, max_parts, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('MIME extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _pdf_worker(path, staging, max_pages, max_bytes, pipe):
    from .profiles.pdf import extract_pdf
    # pypdf -> Pillow -> NumPy can reserve many OpenBLAS thread stacks before parsing.
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = extract_pdf(path, staging, max_pages=max_pages, max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_pdf(path, staging, max_pages, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_pdf_worker, path, staging, max_pages, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('PDF extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _office_worker(path, staging, max_parts, max_bytes, pipe):
    from .profiles.office import inspect_office
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = inspect_office(path, staging, max_parts=max_parts,
                                            max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_office(path, staging, max_parts, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_office_worker, path, staging, max_parts, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('Office inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _can_worker(path, max_frames, max_bytes, pipe):
    from .profiles.canlog import parse_can_log
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        frames, warnings = parse_can_log(path, max_frames=max_frames, max_bytes=max_bytes)
        pipe.send(('ok', frames, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_can(path, max_frames, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_can_worker, path, max_frames, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('CAN log normalization exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _can_dbc_worker(frames, database_path, max_frames, max_db_bytes, max_output_bytes,
                    timeout, pipe):
    from .profiles.can_dbc import decode_can_frames
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        records, warnings = decode_can_frames(frames, database_path, max_frames=max_frames,
                                              max_db_bytes=max_db_bytes,
                                              max_output_bytes=max_output_bytes,
                                              timeout=timeout)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_can_dbc(frames, database_path, max_frames, max_db_bytes, max_output_bytes,
                 timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_can_dbc_worker, frames, database_path, max_frames,
                                           max_db_bytes, max_output_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('CAN signal decoding exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _packets_worker(path, timeout, max_output, pipe):
    from .profiles.packets import inspect_pcap
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        records, warnings = inspect_pcap(path, timeout=timeout, max_output=max_output)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_packets(path, timeout, max_output):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_packets_worker, path, timeout, max_output, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('packet inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _packet_objects_worker(path, staging, max_objects, max_bytes, timeout, pipe):
    from .profiles.packet_objects import export_http_objects
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = export_http_objects(path, staging, timeout=timeout,
                                                max_objects=max_objects,
                                                max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_packet_objects(path, staging, max_objects, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_packet_objects_worker, path, staging,
                                           max_objects, max_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('HTTP object export exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _packet_tls_worker(path, keylog, staging, max_objects, max_bytes, timeout, pipe):
    from .profiles.packet_tls import decrypt_tls_http
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = decrypt_tls_http(path, keylog, staging, timeout=timeout,
                                             max_objects=max_objects,
                                             max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_packet_tls(path, keylog, staging, max_objects, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_packet_tls_worker, path, keylog, staging,
                                           max_objects, max_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('TLS decryption exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _packet_streams_worker(path, timeout, max_output, max_streams, max_bytes, pipe):
    from .profiles.packet_streams import reassemble_tcp
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        records, warnings = reassemble_tcp(path, timeout=timeout, max_output=max_output,
                                           max_streams=max_streams, max_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_packet_streams(path, timeout, max_output, max_streams, max_bytes):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_packet_streams_worker, path, timeout, max_output,
                                           max_streams, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('TCP stream reconstruction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _elf_worker(path, pipe):
    from .profiles.elf import inspect_elf
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        report, warnings = inspect_elf(path)
        pipe.send(('ok', report, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_elf(path, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_elf_worker, path, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('ELF static inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _binary_worker(path, pipe):
    from .profiles.binary_static import inspect_binary
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_binary(path)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_binary(path, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_binary_worker, path, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('binary static inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _rev_strings_worker(path, timeout, pipe):
    from .profiles.rev_strings import inspect_strings
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_strings(path, timeout=timeout)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_rev_strings(path, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_rev_strings_worker, path, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + 1):
            raise TimeoutError('REV02 string recovery exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _rev_powershell_worker(path, timeout, pipe):
    from .profiles.powershell import inspect_powershell
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_powershell(path, timeout=timeout)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_rev_powershell(path, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_rev_powershell_worker, path, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + 1):
            raise TimeoutError('REV11 static PowerShell inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _rev_rules_worker(path, paths, timeout, pipe):
    from .profiles.rev_rules import inspect_rules
    resource.setrlimit(resource.RLIMIT_CPU, (61, 61))
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    try:
        pipe.send(('ok', *inspect_rules(path, timeout=timeout, **paths)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_rev_rules(path, paths, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_rev_rules_worker, path, paths, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(2 * timeout + 5):
            raise TimeoutError('REV03 rule matching exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _rev_packers_worker(path, staging, timeout, max_bytes, upx, binwalk, pipe):
    from .profiles.rev_packers import inspect_packers
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_packers(path, staging, timeout=timeout,
                                          max_derived_bytes=max_bytes,
                                          upx_path=upx, binwalk_path=binwalk,
                                          supervised=True)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_rev_packers(path, staging, timeout, max_bytes, upx, binwalk):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_rev_packers_worker, path, staging, timeout,
                                           max_bytes, upx, binwalk, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + 1):
            raise TimeoutError('REV04 packer inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _pyinstaller_worker(path, staging, max_members, max_bytes, pipe):
    from .profiles.pyinstaller import inspect_pyinstaller
    resource.setrlimit(resource.RLIMIT_CPU, (21, 21))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_pyinstaller(path, staging,
                                             max_members=max_members,
                                             max_total_bytes=max_bytes)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_pyinstaller(path, staging, max_members, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_pyinstaller_worker, path, staging,
                                           max_members, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('PyInstaller extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _java_android_worker(path, staging, timeout, max_parts, max_bytes, pipe):
    from .profiles.java_android import inspect_java_android
    resource.setrlimit(resource.RLIMIT_CPU, (21, 21))
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024,
                                           4 * 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        pipe.send(('ok', *inspect_java_android(path, staging, timeout=timeout,
                                               max_parts=max_parts,
                                               max_total_bytes=max_bytes,
                                               supervised=True)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_java_android(path, staging, timeout, max_parts, max_bytes):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_java_android_worker, path, staging,
                                           timeout, max_parts, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + 1):
            raise TimeoutError('REV06 Java/Android inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _sqlite_worker(path, staging, max_rows, max_bytes, pipe):
    from .profiles.sqlite import inspect_sqlite
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = inspect_sqlite(path, staging, max_rows=max_rows, max_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_sqlite(path, staging, max_rows, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_sqlite_worker, path, staging, max_rows, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('SQLite inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _os_artifact_worker(path, max_records, max_bytes, pipe):
    from .profiles.os_artifacts import inspect_os_artifact
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    try:
        records, warnings = inspect_os_artifact(path, max_records=max_records, max_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_os_artifact(path, max_records, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_os_artifact_worker, path, max_records, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('OS artifact inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _osint_ids_worker(path, max_bytes, max_records, pipe):
    from .profiles.osint_ids import extract_identifiers
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            data = stream.read(max_bytes + 1)
        records, warnings = extract_identifiers(data, max_bytes=max_bytes,
                                                max_records=max_records)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_osint_ids(path, max_bytes, max_records, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_osint_ids_worker, path, max_bytes, max_records, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('OSINT clue extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _web_static_worker(path, origin, source_name, timeout, pipe):
    from .profiles.web_static import inspect_web_static
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        records, warnings = inspect_web_static(path, origin=origin, source_name=source_name,
                                               timeout=timeout)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_web_static(path, origin, source_name, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_web_static_worker, path, origin, source_name, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('web static inventory exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _jwt_worker(path, keys, words, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        from .profiles.jwt import inspect_jwt
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('JWT source must be a regular file')
            data = stream.read(1024 * 1024)
            oversized = bool(stream.read(1))
        records, warnings = inspect_jwt(data, keys=keys, words=words)
        if oversized:
            warnings.append('JWT input byte limit reached')
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_jwt(path, keys, words, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_jwt_worker, path, keys, words, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('JWT inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _snapshot_worker(sources, timeout, pipe):
    from .profiles.osint_snapshots import build_snapshot_trail
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', *build_snapshot_trail(sources, timeout=timeout)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_snapshot(sources, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_snapshot_worker, sources, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('OSINT snapshot trail exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _disk_worker(path, staging, targets, timeout, max_output, max_files, max_bytes, pipe):
    from .profiles.disk import inspect_disk
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    try:
        records, warnings = inspect_disk(path, staging, target_paths=targets, timeout=timeout,
                                         max_output=max_output, max_files=max_files,
                                         max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_disk(path, staging, targets, max_output, max_files, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_disk_worker, path, staging, targets, timeout,
                                           max_output, max_files, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('disk inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _memory_worker(path, staging, symbols_dir, targets, timeout, max_output,
                   max_files, max_bytes, pipe):
    from .profiles.memory import inspect_memory
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = inspect_memory(path, staging, symbols_dir=symbols_dir,
                                           targets=targets, timeout=timeout,
                                           max_output=max_output, max_files=max_files,
                                           max_total_bytes=max_bytes)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_memory(path, staging, symbols_dir, targets, max_output, max_files, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_memory_worker, path, staging, symbols_dir, targets,
                                           timeout, max_output, max_files, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('memory triage exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _disk_recovery_worker(path, staging, timeout, max_output, max_files, max_bytes, pipe):
    from .profiles.disk_recovery import recover_disk
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    try:
        rows, warnings = recover_disk(path, staging, timeout=timeout, max_output=max_output,
                                      max_files=max_files, max_total_bytes=max_bytes)
        pipe.send(('ok', rows, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_disk_recovery(path, staging, max_output, max_files, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_disk_recovery_worker, path, staging, timeout,
                                           max_output, max_files, max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('disk recovery exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _image_worker(path, max_output, pipe):
    from .profiles.images import OutputLimit, extract_image_tail
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024))
    try:
        pipe.send(('ok', extract_image_tail(path, max_output)))
    except OutputLimit as error:
        pipe.send(('limit', str(error)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_image(path, max_output, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_image_worker, path, max_output, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('image tail inspection exceeded its time limit')
        state, value = parent.recv()
        if state == 'limit':
            raise WorkLimit(value)
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _image_metadata_worker(path, staging, max_pixels, max_bytes, timeout, make_views, pipe):
    from .profiles.image_metadata import channel_views, read_metadata
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        tags, metadata_warnings = read_metadata(path, timeout=min(timeout, 10))
        views = []
        view_warnings = []
        if make_views:
            try:
                views, view_warnings = channel_views(path, staging, max_pixels=max_pixels,
                                                     max_total_bytes=max_bytes)
            except ImportError:
                view_warnings.append('Pillow unavailable for image views')
        pipe.send(('ok', tags, views, metadata_warnings, view_warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_image_metadata(path, staging, max_pixels, max_bytes, timeout, make_views):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_image_metadata_worker, path, staging, max_pixels,
                                           max_bytes, timeout, make_views, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('image metadata and views exceeded their time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2], result[3], result[4]
    finally:
        _stop_worker(worker)
        parent.close()


def _media_worker(path, staging, timeout, max_bytes, pipe):
    from .profiles.media import inspect_media
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = inspect_media(path, staging, timeout=timeout,
                                          max_bytes=max_bytes, max_frames=16,
                                          full_frames=True, supervised=True)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_media(path, staging, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_media_worker, path, staging, timeout,
                                           max_bytes, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('media inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _tones_worker(path, staging, timeout, pipe):
    from .profiles.tones import inspect_tones
    resource.setrlimit(resource.RLIMIT_CPU, (21, 21))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    try:
        staging.mkdir(parents=True, exist_ok=True, mode=0o700)
        rows, warnings = inspect_tones(path, timeout=timeout, max_output=64 * 1024,
                                       supervised=True, scratch_dir=staging)
        pipe.send(('ok', rows, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_tones(path, staging, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_tones_worker, path, staging, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('tone inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _sstv_worker(path, staging, max_bytes, timeout, pipe):
    from .profiles.sstv import decode_sstv
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (41, 41))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    try:
        records, warnings = decode_sstv(path, staging, timeout=timeout,
                                         max_bytes=max_bytes, supervised=True)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_sstv(path, staging, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_sstv_worker, path, staging, max_bytes,
                                           timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('SSTV decoding exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _zsteg_worker(path, staging, max_pixels, max_bytes, timeout, pipe):
    from .profiles.zsteg import inspect_lsb
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    try:
        records, warnings = inspect_lsb(path, staging, max_pixels=max_pixels,
                                         max_total_bytes=max_bytes, timeout=timeout,
                                         supervised=True)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_zsteg(path, staging, max_pixels, max_total_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_zsteg_worker, path, staging, max_pixels,
                                           max_total_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('zsteg inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _stegseek_worker(path, staging, passwords, max_bytes, timeout, pipe):
    from .profiles.stegseek import extract_steghide
    resource.setrlimit(resource.RLIMIT_CPU, (21, 21))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    try:
        records, warnings = extract_steghide(path, staging, passwords=passwords,
                                               max_total_bytes=max_bytes, timeout=timeout,
                                               supervised=True)
        pipe.send(('ok', records, warnings))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_stegseek(path, staging, passwords, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_stegseek_worker, path, staging, passwords,
                                           max_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('Stegseek extraction exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _qr_worker(path, max_pixels, max_bytes, timeout, pipe):
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    # Forked doctor probes can inherit a 1 GiB OpenBLAS address reservation from Pillow.
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))
    from .profiles.qr import decode_symbols
    try:
        pipe.send(('ok', *decode_symbols(path, max_pixels=max_pixels,
                                         max_total_bytes=max_bytes, timeout=timeout)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_qr(path, max_pixels, max_bytes, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_qr_worker, path, max_pixels, max_bytes, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .25):
            raise TimeoutError('QR inspection exceeded its time limit')
        result = parent.recv()
        if result[0] != 'ok':
            raise RuntimeError(result[1])
        return result[1], result[2]
    finally:
        _stop_worker(worker)
        parent.close()


def _decode_worker(data, max_output, pipe):
    from .profiles.encoding import decode
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        diagnostics = []
        pipe.send(('ok', (decode(data, max_output, diagnostics), diagnostics)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_decode(data, max_output, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_decode_worker, data, max_output, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('encoding operation exceeded its time limit')
        state, value = parent.recv()
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _xor_worker(data, crib, pipe):
    from .profiles.xor import recover_repeating_crib, recover_repeating_key, recover_single_byte
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        pipe.send(('ok', recover_single_byte(data) + recover_repeating_key(data) +
                   (recover_repeating_crib(data, crib) if crib else [])))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_xor(data, crib, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_xor_worker, data, crib, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('XOR search exceeded its time limit')
        state, value = parent.recv()
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _rsa_worker(parameters, timeout, pipe):
    from .profiles.rsa import inspect_rsa
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', inspect_rsa(parameters, budget_seconds=timeout)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_rsa(parameters, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_rsa_worker, parameters, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('RSA relationship check exceeded its time limit')
        state, value = parent.recv()
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _hash_worker(records, words, timeout, pipe):
    from .profiles.passwords import inspect_password_hashes
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', inspect_password_hashes(records, words, budget_seconds=timeout)))
    except Exception as error:
        pipe.send(('error', type(error).__name__))
    finally:
        pipe.close()


def _run_hash(records, words, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry,
                                     args=(_hash_worker, records, words, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('password hash check exceeded its time limit')
        state, value = parent.recv()
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _symmetric_worker(records, timeout, pipe):
    from .profiles.symmetric import decrypt_declared
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    try:
        pipe.send(('ok', decrypt_declared(records, max_output=1024 * 1024)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_symmetric(records, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_symmetric_worker, records, timeout, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise TimeoutError('declared symmetric decryption exceeded its time limit')
        state, value = parent.recv()
        if state != 'ok':
            raise RuntimeError(value)
        return value
    finally:
        _stop_worker(worker)
        parent.close()


def _coverage(category):
    return {row['id']: {'domain': row['domain'], 'delivery_stage': row['delivery_stage'],
                        'status': 'not scheduled', 'note': 'operation not implemented or not selected'}
            for row in CATALOG if category == 'auto' or row['domain'] == category}


def _mark_encoding_coverage(manifest, operations, diagnostics=(), artifact_id=None):
    produced = {'ENC02' if label.startswith(('gzip', 'zlib', 'bzip2', 'xz'))
                else 'ENC03' if label == 'rot13' or label.startswith(
                    ('atbash ', 'caesar-shift:', 'affine-decrypt:')) else 'ENC01'
                for label in operations}
    for family in ('ENC01', 'ENC02', 'ENC03'):
        if family in manifest['coverage']:
            if family in produced and manifest['coverage'][family]['status'] != 'truncated':
                manifest['coverage'][family]['status'] = 'ran'
            elif manifest['coverage'][family]['status'] == 'not scheduled':
                manifest['coverage'][family]['status'] = 'no finding'
            if manifest['coverage'][family]['status'] != 'truncated':
                manifest['coverage'][family]['note'] = 'finite stdlib transforms only'
    for record in diagnostics:
        if record['status'] == 'complete':
            continue
        kind, status = record['kind'], record['status']
        members = len(record['members'])
        detail = (f"{record['trailing_bytes']} trailing bytes after {members} complete member(s)"
                  if status == 'trailing' else
                  f"{status} stream after {members} complete member(s)"
                  if status != 'limit' else f"limit: {record['limit_reason']}")
        manifest['warnings'].append(f'{artifact_id}: {kind} {detail}')
        if 'ENC02' in manifest['coverage']:
            manifest['coverage']['ENC02']['status'] = 'truncated'
            manifest['coverage']['ENC02']['note'] = f'{kind} {detail}'


def _rsa_job(run, manifest, parameters, params_hash, deadline):
    families = ('ENC06', 'ENC07')
    if not parameters:
        for family in families:
            if family in manifest['coverage']:
                manifest['coverage'][family]['status'] = 'skipped prerequisite'
                manifest['coverage'][family]['note'] = 'RSA n/e/c or public key and ciphertext hints required'
        return
    if time.monotonic() >= deadline:
        manifest['warnings'].append('RSA check not scheduled before work budget ended')
        return
    fingerprint = _cryptography_fingerprint('rsa')
    key = hashlib.sha256(f"{params_hash}:rsa.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and job['status'] == 'complete'), None)
    if old:
        recovered = set(old.get('families', []))
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'rsa-literals',
               'input_ids': [], 'operation': 'bounded RSA public-parameter relations',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'rsa_parameters': params_hash},
               'cwd': str(run), 'limits': {'records': 32, 'seconds': 5},
               'status': 'running', 'families': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        try:
            rows = _run_rsa(parameters, min(5, max(.01, deadline - time.monotonic())))
            recovered = {row['family'] for row in rows}
            for row in rows:
                plaintext = row['plaintext_hex']
                manifest['findings'].append({
                    'state': row['status'], 'artifact_id': None, 'job_id': job['id'],
                    'rsa_parameters_sha256': params_hash, 'current': True,
                    'source_locator': {'rsa_hint_indices': row['source_indices']},
                    'evidence': f"{row['method']}: raw RSA preimage 0x{plaintext[:128]}"
                                + ('…' if len(plaintext) > 128 else '') + '; modular check passed',
                    'raw_preimage_hex': plaintext, 'operation': row['method'],
                    'next_action': 'Check padding, byte width, and challenge meaning before claiming an answer.'})
            job['families'] = sorted(recovered)
            job['status'] = 'complete'
        except Exception as error:
            recovered = set()
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"RSA job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    for family in families:
        if family in manifest['coverage']:
            manifest['coverage'][family]['status'] = ('failed' if (old or job)['status'] == 'failed'
                                                   else 'ran' if family in recovered else 'no finding')
            manifest['coverage'][family]['note'] = 'bounded textbook RSA relationships and PEM/DER public keys'


def _hash_job(run, manifest, records, params_hash, words, wordlist_hash, deadline):
    if 'ENC10' not in manifest['coverage']:
        return
    coverage = manifest['coverage']['ENC10']
    if not records or wordlist_hash is None:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'hash_parameters and private hash_wordlist_file required'
        return
    if time.monotonic() >= deadline:
        manifest['warnings'].append('password hash check not scheduled before work budget ended')
        return
    fingerprint = hashlib.sha256((Path(__file__).parent / 'profiles' / 'passwords.py').read_bytes()).hexdigest()
    key = hashlib.sha256(f'{params_hash}:{wordlist_hash}:password-hashes.v1:{fingerprint}'.encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and job['status'] == 'complete'), None)
    if old:
        statuses = old.get('result_statuses', [])
        failed = False
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'password-hashes',
               'input_ids': [], 'operation': 'declared bounded password hash checks',
               'tool_fingerprint': fingerprint,
               'data_fingerprints': {'hash_parameters': params_hash, 'hash_wordlist_file': wordlist_hash},
               'cwd': str(run), 'limits': {'records': 32, 'words': 4096, 'word_bytes': 128,
                                          'seconds': 5},
               'status': 'running', 'result_statuses': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        try:
            rows = _run_hash(records, words, min(5, max(.01, deadline - time.monotonic())))
            statuses = [row['status'] for row in rows]
            for row in rows:
                evidence = row.get('evidence', {})
                finding = {'state': row['status'], 'artifact_id': None, 'job_id': job['id'],
                           'hash_parameters_sha256': params_hash,
                           'hash_wordlist_sha256': wordlist_hash, 'current': True,
                           'source_locator': {'hash_hint_index': row['source_index']},
                           'evidence': f"declared {evidence.get('algorithm', 'unknown')} digest; "
                                       f"{evidence.get('checked', 0)} word(s) checked; "
                                       f"{row['status']}",
                           'operation': 'password_hash',
                           'next_action': 'Inspect the private finding and verify challenge meaning.'}
                if row['status'] == 'validated_transform':
                    finding['recovered_password_hex'] = row['password'].hex()
                    finding['evidence'] += f"; wordlist index {evidence['candidate_index']} verified"
                manifest['findings'].append(finding)
            job['result_statuses'] = statuses
            job['status'] = 'complete'
            failed = False
        except Exception as error:
            statuses = []
            failed = True
            job['status'] = 'failed'
            job['warning'] = type(error).__name__
            manifest['warnings'].append(f"password hash job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    coverage['status'] = ('failed' if failed or 'tool_error' in statuses else
                          'truncated' if 'incomplete' in statuses else
                          'ran' if 'validated_transform' in statuses else 'no finding')
    coverage['note'] = 'declared MD5/SHA digest recipes; bounded exact-byte wordlist only'


def _symmetric_job(run, manifest, records, params_hash, deadline):
    if 'ENC08' not in manifest['coverage']:
        return []
    if not records:
        manifest['coverage']['ENC08']['status'] = 'skipped prerequisite'
        manifest['coverage']['ENC08']['note'] = 'declared AES parameters required'
        return []
    if time.monotonic() >= deadline:
        manifest['warnings'].append('AES check not scheduled before work budget ended')
        return []
    fingerprint = _cryptography_fingerprint('symmetric')
    key = hashlib.sha256(f"{params_hash}:aes-declared.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old and 'child_ids' in old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
        old = None
    if old:
        found = old.get('result_count', 0)
        failed = False
        children = reusable
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'aes-declared',
               'input_ids': [], 'operation': 'declared AES decryption',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'symmetric_parameters': params_hash},
               'cwd': str(run), 'limits': {'records': 32, 'input_bytes': 1024 * 1024},
               'status': 'running', 'result_count': 0, 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        failed = False
        children = []
        try:
            rows = _run_symmetric(records, min(30, max(.01, deadline - time.monotonic())))
            found = len(rows)
            for row in rows:
                value = row['plaintext']
                child = None
                if row['status'] == 'validated_transform':
                    child = _store_symmetric_plaintext(run, manifest, job,
                                                       row['source_index'], value, deadline)
                    if child:
                        job['child_ids'].append(child['id'])
                        children.append(child)
                manifest['findings'].append({
                    'state': row['status'], 'artifact_id': child['id'] if child else None,
                    'job_id': job['id'],
                    'symmetric_parameters_sha256': params_hash, 'current': True,
                    'source_locator': {'symmetric_hint_index': row['source_index']},
                    'evidence': f"{row['method']}: raw bytes {repr(value[:128])}; "
                                + ('authentication verified' if row['status'] == 'validated_transform'
                                   else 'unauthenticated candidate'),
                    'raw_plaintext_hex': value.hex(), 'operation': row['method'],
                    'next_action': 'Check format and challenge meaning before claiming an answer.'})
            job['result_count'] = found
            job['status'] = 'complete'
        except Exception as error:
            found = 0
            failed = True
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"AES job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    manifest['coverage']['ENC08']['status'] = 'failed' if failed else 'ran' if found else 'no finding'
    manifest['coverage']['ENC08']['note'] = 'declared AES-GCM/CBC/CTR only; CBC/CTR are candidates'
    return children


def _media_job(run, manifest, artifact, deadline):
    from .profiles import media

    covered = [manifest['coverage'][name] for name in ('AV01', 'AV06')
               if name in manifest['coverage']]
    ffprobe = shutil.which(media.FFPROBE)
    ffmpeg = shutil.which(media.FFMPEG)
    if not ffprobe or not ffmpeg:
        for item in covered:
            item['status'] = 'skipped prerequisite'
            item['note'] = 'FFprobe and FFmpeg required for bounded media inspection'
        manifest['warnings'].append('AV01/AV06 skipped: FFprobe or FFmpeg unavailable')
        return []

    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(media.__file__).read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(
        f"{module_hash}:{_hash(Path(ffprobe), deadline)}:{_hash(Path(ffmpeg), deadline)}".encode()
    ).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:media.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        warnings = old.get('warnings', [])
        stream_types = old.get('stream_types', [])
        manifest['warnings'].extend(warnings)
        children = reusable
        failed = False
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'media',
               'input_ids': [artifact['id']], 'operation': 'bounded offline media inspection',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'derived_bytes': 16 * 1024 * 1024, 'frames': 16,
                          'audio_seconds': 20, 'seconds': 30},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] == 'Media stream':
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children, warnings, stream_types = [], [], []
        failed = False
        try:
            records, warnings = _run_media(
                path, staging, min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                min(30, max(.01, deadline - time.monotonic() - .1)))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('media source changed before preview publication')
            for record in records:
                if record['kind'] == 'stream':
                    stream_types.append(record['stream_type'])
                    manifest['intelligence'].append({
                        'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                        'tag': 'Media stream', 'group': record['stream_type'],
                        'value': json.dumps(record['metadata'], sort_keys=True)[:512],
                        'source_locator': {'stream_index': record['stream_index']},
                        'next_action': 'Inspect the source-linked preview or subtitle cues.'})
                    continue
                locator = {'stream_index': record['stream_index'],
                           'media_kind': record['kind'], 'media_preview': True}
                for field in ('channel', 'view', 'start_seconds', 'end_seconds',
                              'frame_sample', 'requested_seconds', 'sampled_seconds',
                              'sampling_mode', 'media_type'):
                    if field in record:
                        locator[field] = record[field]
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator, operation=record['locator'],
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    if record['kind'] != 'audio_view' or record['media_type'] == 'image/png':
                        children.append(child)
            job['stream_types'] = stream_types
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            failed = True
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"media job failed: {job['warning']}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'AV01' in manifest['coverage']:
        entry = manifest['coverage']['AV01']
        audio_warnings = [note for note in warnings if note.startswith((
            'audio ', 'stream ', 'ffmpeg ', 'ffprobe '))]
        entry['status'] = ('failed' if failed else 'truncated' if audio_warnings else
                           'ran' if 'audio' in stream_types else 'no finding')
        entry['note'] = 'first 20s, first two channels; waveform, spectrum and reversed PCM views'
    if 'AV06' in manifest['coverage']:
        entry = manifest['coverage']['AV06']
        video_warnings = [note for note in warnings if note.startswith(('video ', 'subtitle ',
                                                                        'frame ', 'stream ',
                                                                        'full-frame', 'ffmpeg ', 'ffprobe '))]
        entry['status'] = ('failed' if failed else 'truncated' if video_warnings else
                           'ran' if set(stream_types) & {'video', 'subtitle'} else 'no finding')
        entry['note'] = 'first video stream, at most 16 frames and 4 text subtitle streams; sampling may miss brief frames'
    return [child for child in children if child['kind_evidence'] != 'riff']


def _tones_job(run, manifest, artifact, deadline):
    from .profiles import tones

    coverage = [manifest['coverage'][name] for name in ('AV02', 'AV03')
                if name in manifest['coverage']]
    path = Path(artifact['path'])
    with path.open('rb') as stream:
        header = stream.read(12)
    if header[:4] != b'RIFF' or header[8:12] != b'WAVE':
        for item in coverage:
            item['status'] = 'skipped prerequisite'
            item['note'] = 'PCM WAV input required for supported tone modes'
        return
    if not shutil.which(tones.MULTIMON) or not shutil.which(tones.FFMPEG):
        for item in coverage:
            item['status'] = 'skipped prerequisite'
            item['note'] = 'multimon-ng and FFmpeg required for tone decode'
        manifest['warnings'].append('AV02/AV03 skipped: multimon-ng or FFmpeg unavailable')
        return

    fingerprint = manifest['current_adapter_fingerprints']['tones'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:tones.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink()
                     and _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        records = json.loads(output.read_text())
        warnings = old.get('warnings', [])
        failed = False
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'tones',
               'input_ids': [artifact['id']], 'operation': 'bounded WAV tone decoding',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': tones.MAX_SOURCE_BYTES,
                          'duration_seconds': tones.MAX_DURATION,
                          'decoder_output_bytes': tones.MAX_DECODER_OUTPUT,
                          'seconds': 20},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] in ('Tone decode', 'DTMF sequence'):
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        records, warnings, failed = [], [], False
        try:
            records, warnings = _run_tones(path, staging,
                                           min(20, max(.01, deadline - time.monotonic() - .1)))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('WAV source changed before tone publication')
            output = run / 'jobs' / f"{job['id']}.tones.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                raise RuntimeError('tone output identity incomplete before work budget ended')
            for record in records[:100]:
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'Tone decode', 'group': f"{record['mode']} channel {record['channel']}",
                    'value': record['raw_output'][:512],
                    'source_locator': {'channel': record['channel'], 'decoder_output': record['locator'],
                                       'duration_seconds': record['duration_seconds'],
                                       'event_time_seconds': record['event_time_seconds'],
                                       'time_basis': record['time_basis']},
                    'next_action': 'Verify decoder output against the recording before submitting.'})
            for channel in sorted({row['channel'] for row in records if row['mode'] == 'DTMF'}):
                sequence = ''.join(row['symbol'] for row in records
                                   if row['mode'] == 'DTMF' and row['channel'] == channel)
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'DTMF sequence', 'group': f'channel {channel}',
                    'value': sequence,
                    'source_locator': {'channel': channel, 'time_basis': 'decoder output order'},
                    'next_action': 'Use the literal symbols; keypad letters are ambiguous.'})
            if len(records) > 100:
                warnings.append('tone report shows first 100 events; all bounded records remain in job output')
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            failed = True
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"tone job failed: {job['warning']}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    limited = any('limit' in warning or 'timed out' in warning or 'incomplete' in warning
                  or 'exited' in warning or 'unavailable' in warning
                  for warning in warnings)
    for family, modes in (('AV02', {'DTMF'}), ('AV03', {'MORSE_CW', 'AFSK1200'})):
        if family in manifest['coverage']:
            entry = manifest['coverage'][family]
            entry['status'] = ('failed' if failed else 'truncated' if limited else
                               'ran' if any(row['mode'] in modes for row in records) else 'no finding')
            entry['note'] = 'literal decoder symbols/text; event times unavailable; no keypad word inference'


def _sstv_job(run, manifest, artifact, deadline):
    from .profiles import sstv

    entry = manifest['coverage'].get('AV04')
    if entry is None:
        return []
    if not shutil.which(sstv.FFMPEG) or not sstv.decoder_available():
        entry['status'] = 'skipped prerequisite'
        entry['note'] = 'FFmpeg and approved colaclanth SSTV decoder required'
        manifest['warnings'].append('AV04 skipped: FFmpeg or approved SSTV decoder unavailable')
        return []
    fingerprint = manifest['current_adapter_fingerprints']['sstv'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:sstv.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        children, warnings, failed = reusable, old.get('warnings', []), False
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'sstv',
               'input_ids': [artifact['id']], 'operation': 'bounded offline SSTV decode',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': sstv.MAX_SOURCE_BYTES,
                          'duration_seconds': sstv.MAX_DURATION,
                          'derived_bytes': sstv.MAX_IMAGE_BYTES, 'seconds': 40},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children, warnings, failed = [], [], False
        try:
            records, warnings = _run_sstv(
                Path(artifact['path']), staging,
                min(sstv.MAX_IMAGE_BYTES, MAX_DERIVED - manifest['derived_bytes']),
                min(40, max(.01, deadline - time.monotonic() - .1)))
            if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
                raise RuntimeError('SSTV source changed before image publication')
            for record in records:
                locator = {'mode': record['mode'], 'start_seconds': record['start_seconds'],
                           'end_seconds': record['end_seconds'], 'time_basis': record['time_basis'],
                           'media_type': record['media_type'], 'sstv_preview': True}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator, operation=f"SSTV {record['mode']} image",
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    children.append(child)
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            failed = True
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"SSTV job failed: {job['warning']}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    entry['status'] = ('failed' if failed else 'truncated' if any(
        word in warning for warning in warnings for word in
        ('truncated', 'limit', 'timed out', 'incomplete', 'exited')) else
        'ran' if children else 'no finding')
    entry['note'] = 'supported VIS modes only; complete decoder image is a candidate, with recording-time locator'
    return children


def _image_metadata_job(run, manifest, artifact, deadline, *, make_views):
    from .profiles import image_metadata
    from .profiles.image_metadata import read_metadata
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(read_metadata.__code__.co_filename).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(image_metadata._EXIFTOOL), deadline)
    except OSError:
        tool_hash = None
    fingerprint = hashlib.sha256(f'{module_hash}:{tool_hash}:views={make_views}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:image-metadata.v2:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        manifest['warnings'].extend(old.get('warnings', []))
        tags_found = old.get('tags_found', False)
        views_found = bool(reusable)
        warnings = old.get('warnings', [])
        metadata_warnings = old.get('metadata_warnings', warnings)
        view_warnings = old.get('view_warnings', warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'image-metadata',
               'input_ids': [artifact['id']], 'operation': 'ExifTool tags and bounded channel views',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'pixels': 4_000_000, 'derived_bytes': 16 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for old_info in manifest['intelligence']:
            if old_info['artifact_id'] == artifact['id']:
                old_info['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        tags_found = views_found = False
        metadata_warnings, view_warnings, warnings = [], [], []
        try:
            tags, views, metadata_warnings, view_warnings = _run_image_metadata(
                path, staging, 4_000_000,
                min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                min(30, max(.01, deadline - time.monotonic())), make_views)
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('image changed before metadata publication')
            for tag in tags[:100]:
                value = tag['value']
                if not isinstance(value, (str, int, float, bool, type(None))):
                    value = json.dumps(value, ensure_ascii=True)
                item = {
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': tag['tag'], 'group': tag['group'], 'value': str(value)[:512],
                    'source_locator': {'exif_tag': tag['source_tag']},
                    'next_action': 'Correlate this metadata with the original artifact.'}
                if tag.get('interpretation'):
                    item['interpretation'] = tag['interpretation'][:256]
                manifest['intelligence'].append(item)
            if len(tags) > 100:
                metadata_warnings.append('ExifTool tag display limit reached')
            tags_found = bool(tags)
            available_views = min(32, max(0, MAX_ARTIFACTS - len(manifest['artifacts']) - 64))
            if len(views) > available_views:
                view_warnings.append(f"stored at most {available_views} of {len(views)} image previews; "
                                     'artifact capacity reserved for extracted content')
                selected = ([views[round(index * (len(views) - 1) / (available_views - 1))]
                             for index in range(available_views)] if available_views > 1 else
                            views[:available_views])
            else:
                selected = views
            for view in selected:
                locator = {'frame': view['frame'], 'duration_ms': view['duration_ms'],
                           'channel': view['channel'], 'bit': view['bit'],
                           'source_mode': view['source_mode'], 'preview': True}
                child = _store_staged(run, manifest, artifact, view, deadline,
                                      locator=locator,
                                      operation=f"image frame {view['frame']} {view['channel']} bit {view['bit']}",
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
            views_found = bool(job['child_ids'])
            warnings = metadata_warnings + view_warnings
            manifest['warnings'].extend(warnings[:100])
            job['warnings'] = warnings[:100]
            job['metadata_warnings'] = metadata_warnings[:100]
            job['view_warnings'] = view_warnings[:100]
            job['tags_found'] = tags_found
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"image metadata job failed: {type(error).__name__}")
            metadata_warnings = view_warnings = warnings = [job['warning']]
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'IMG01' in manifest['coverage']:
        previous = manifest['coverage']['IMG01']['status']
        if previous != 'truncated':
            manifest['coverage']['IMG01']['status'] = ('ran' if tags_found or previous == 'ran' else
                                                        'truncated' if metadata_warnings else 'no finding')
        manifest['coverage']['IMG01']['note'] = 'ExifTool tags, image tails, and clear ZIP member CRCs'
    if 'IMG04' in manifest['coverage'] and make_views:
        manifest['coverage']['IMG04']['status'] = ('truncated' if view_warnings else
                                                   'ran' if views_found else 'no finding')
        manifest['coverage']['IMG04']['note'] = 'bounded sampled channel/bit-plane previews'
    if 'OS01' in manifest['coverage']:
        manifest['coverage']['OS01']['status'] = ('truncated' if metadata_warnings else
                                                  'ran' if tags_found else 'no finding')
        manifest['coverage']['OS01']['note'] = 'source-linked ExifTool metadata; coordinates are unverified clues'


def _zsteg_job(run, manifest, artifact, deadline):
    from .profiles import zsteg

    coverage = manifest['coverage']['IMG02']
    if artifact['size'] > 16 * 1024 * 1024:
        coverage['status'] = 'truncated'
        coverage['note'] = 'zsteg source limit is 16 MiB'
        manifest['warnings'].append(f"{artifact['id']}: zsteg source exceeds 16 MiB")
        return []
    tool = shutil.which(zsteg.ZSTEG)
    if importlib.util.find_spec('PIL') is None:
        tool = None
    if not tool:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'zsteg and Pillow required for PNG/BMP LSB extraction'
        manifest['warnings'].append('IMG02 skipped: zsteg or Pillow unavailable')
        return []

    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(zsteg.inspect_lsb.__code__.co_filename).read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(f'{module_hash}:{_hash(Path(tool), deadline)}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:zsteg.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
        children = reusable
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'zsteg',
               'input_ids': [artifact['id']], 'operation': 'bounded PNG/BMP LSB extraction',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'pixels': 4_000_000, 'derived_bytes': 16 * 1024 * 1024,
                          'selectors': 16, 'seconds': 20},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children = []
        warnings = []
        try:
            records, warnings = _run_zsteg(
                path, staging, max_pixels=4_000_000,
                max_total_bytes=min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                timeout=min(20, max(.01, deadline - time.monotonic() - .1)))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('image changed before zsteg publication')
            for record in records:
                locator = {'zsteg_selector': record['selector'],
                           'zsteg_finding_kind': record['finding_kind']}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator,
                                      operation=f"zsteg extraction {record['selector']}",
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    children.append(child)
                    manifest['findings'].append({
                        'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                        'current': True, 'source_locator': locator,
                        'evidence': f"zsteg {record['selector']}: {record['finding'][:128]}; "
                                    'extracted bytes are unverified',
                        'operation': 'zsteg extraction',
                        'next_action': 'Inspect the extracted bytes and validate challenge meaning.'})
            job['warnings'] = warnings[:100]
            manifest['warnings'].extend(warnings[:100])
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            warnings = [job['warning']]
            manifest['warnings'].append(f"zsteg job failed: {job['warning']}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    previous = coverage['status']
    coverage['status'] = ('failed' if reusable is None and job['status'] == 'failed' else
                          'truncated' if warnings else 'ran' if children or previous == 'ran'
                          else 'no finding')
    coverage['note'] = 'bounded zsteg PNG/BMP selectors; extracted bytes are candidates'
    return children


def _stegseek_job(run, manifest, artifact, deadline, passwords, password_hash):
    from .profiles import stegseek

    coverage = manifest['coverage']['IMG03']
    if not passwords:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'private password_file with at most eight candidates required'
        return []
    if artifact['size'] > 16 * 1024 * 1024:
        coverage['status'] = 'truncated'
        coverage['note'] = 'Stegseek source limit is 16 MiB'
        return []
    tool = shutil.which(stegseek.STEGSEEK)
    if not tool:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'Stegseek executable unavailable'
        return []

    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(stegseek.__file__).read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(f'{module_hash}:{_hash(Path(tool), deadline)}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:stegseek.v1:{fingerprint}:{password_hash}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        children = reusable
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'stegseek',
               'input_ids': [artifact['id']], 'operation': 'supplied-password Stegseek extraction',
               'tool_fingerprint': fingerprint,
               'data_fingerprints': {'password_file': password_hash}, 'cwd': str(run),
               'limits': {'passwords': 8, 'source_bytes': 16 * 1024 * 1024,
                          'derived_bytes': 16 * 1024 * 1024, 'seconds': 20},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children = []
        warnings = []
        try:
            records, warnings = _run_stegseek(
                path, staging, passwords,
                min(MAX_CHILD, MAX_DERIVED - manifest['derived_bytes']),
                min(20, max(.01, deadline - time.monotonic() - .1)))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('Stegseek source changed before payload publication')
            for record in records:
                locator = {'password_index': record['password_index'],
                           'password_file_sha256': password_hash,
                           'stego_engine': 'stegseek'}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator, operation='Stegseek payload extraction',
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    children.append(child)
                    manifest['findings'].append({
                        'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                        'current': True, 'source_locator': locator,
                        'evidence': f"Stegseek extracted {child['size']} bytes; SHA-256 {child['sha256']}; "
                                    'challenge meaning unverified',
                        'operation': 'Stegseek payload extraction',
                        'next_action': 'Inspect the extracted bytes and validate challenge meaning.'})
                else:
                    warnings.append('Stegseek payload publication limit reached; inspection incomplete')
            job['warnings'] = warnings[:100]
            manifest['warnings'].extend(warnings[:100])
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            warnings = [job['warning']]
            manifest['warnings'].append(f"Stegseek job failed: {type(error).__name__}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    previous = coverage['status']
    coverage['status'] = ('failed' if reusable is None and job['status'] == 'failed' else
                          'truncated' if any('timed out' in warning or 'byte limit' in warning
                                             for warning in warnings) or previous == 'truncated' else
                          'ran' if children or previous == 'ran' else 'no finding')
    coverage['note'] = 'Stegseek with supplied passwords; outputs are candidates; absence is ambiguous'
    return children


def _qr_job(run, manifest, artifact, deadline):
    coverage = manifest['coverage'].get('IMG05')
    if importlib.util.find_spec('PIL') is None or not any(
            importlib.util.find_spec(name) for name in ('zxingcpp', 'pyzbar')):
        if coverage is not None:
            coverage['status'] = 'skipped prerequisite'
            coverage['note'] = 'Pillow and zxing-cpp or pyzbar required for symbol decoding'
        manifest['warnings'].append('IMG05 skipped: image or barcode decoder unavailable')
        return []

    path = Path(artifact['path'])
    fingerprint = _qr_fingerprint()
    key = hashlib.sha256(f"{artifact['sha256']}:qr.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
        children = reusable
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'qr',
               'input_ids': [artifact['id']], 'operation': 'bounded image symbol decoding',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'pixels': 4_000_000, 'output_bytes': 1024 * 1024,
                          'symbols': 32, 'frames': 8, 'seconds': 10},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        children = []
        warnings = []
        try:
            records, warnings = _run_qr(path, 4_000_000,
                                        min(1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                                        min(10, max(.01, deadline - time.monotonic() - .1)))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('image changed before QR publication')
            for record in records:
                locator = {'frame': record['frame'], 'duration_ms': record['duration_ms'],
                           'source_mode': record['source_mode'],
                           'symbol_format': record['format'],
                           'symbol_position': record['position'],
                           'rotation_degrees': record['rotation_degrees'],
                           'inverted': record['inverted'], 'decoder': record['decoder']}
                if (artifact.get('source_locator') or {}).get('media_preview'):
                    locator['media_frame'] = artifact['source_locator']
                child = _store_child(run, manifest, artifact, record['payload'],
                                     f"QR/barcode {record['format']}", deadline,
                                     source_locator=locator, force_record=True,
                                     producer_key=key)
                if child is None:
                    warnings.append('QR payload publication limit reached; inspection incomplete')
                    break
                job['child_ids'].append(child['id'])
                children.append(child)
                manifest['findings'].append({
                    'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                    'current': True, 'source_locator': locator,
                    'evidence': f"decoded {record['format']} bytes SHA-256 {child['sha256']}; "
                                'challenge meaning unverified',
                    'operation': 'QR/barcode decode',
                    'next_action': 'Inspect symbol bytes and validate challenge meaning.'})
            job['warnings'] = warnings[:100]
            manifest['warnings'].extend(warnings[:100])
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            warnings = [job['warning']]
            manifest['warnings'].append(f"QR job failed: {job['warning']}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if coverage is not None:
        previous = coverage['status']
        coverage['status'] = ('failed' if reusable is None and job['status'] == 'failed' else
                              'truncated' if warnings else 'ran' if children or previous == 'ran'
                              else 'no finding')
        coverage['note'] = 'bounded QR/barcode payloads; DataMatrix requires zxing-cpp'
    return children


def _office_job(run, manifest, artifact, deadline):
    path = Path(artifact['path'])
    if artifact['kind_evidence'] == 'zip':
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source, zipfile.ZipFile(source) as archive:
                archive.getinfo('[Content_Types].xml')
        except (OSError, KeyError, zipfile.BadZipFile):
            return []
    fingerprint = _office_fingerprint()
    key = hashlib.sha256(f"{artifact['sha256']}:office.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            operation = next((edge['operation'] for edge in child['parents']
                              if edge.get('job_key') == key), 'Office embedded evidence')
            edge = {'id': artifact['id'], 'operation': operation, 'job_key': key}
            if edge not in child['parents']:
                child['parents'].append(edge)
            child['current'] = True
        manifest['warnings'].extend(old.get('warnings', []))
        status = old.get('coverage_status', 'no finding')
        children = reusable
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'office',
               'input_ids': [artifact['id']], 'operation': 'bounded Office static inspection',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'parts': 100, 'derived_bytes': 64 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children = []
        status = 'no finding'
        try:
            records, warnings = _run_office(
                path, staging, min(100, MAX_ARTIFACTS - len(manifest['artifacts'])),
                min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('Office source changed before output publication')
            for record in records:
                locator = {'office_locator': record['locator'], 'office_kind': record['kind']}
                for name in ('member', 'index', 'stream', 'module', 'offset', 'end', 'name'):
                    if name in record:
                        value = record[name]
                        locator[name] = value[:256] if isinstance(value, str) else value
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator,
                                      operation=f"Office {record['kind']} {record['locator']}",
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    children.append(child)
            prerequisite = any('unavailable' in note or 'password required' in note
                               for note in warnings)
            status = ('skipped prerequisite' if prerequisite and not children else
                      'truncated' if warnings else 'ran' if children else 'no finding')
            manifest['warnings'].extend(warnings[:100])
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"Office job failed: {type(error).__name__}")
            status = 'failed'
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DOC05' in manifest['coverage']:
        priority = {'not scheduled': 0, 'no finding': 1, 'ran': 2,
                    'skipped prerequisite': 3, 'truncated': 4, 'failed': 5}
        entry = manifest['coverage']['DOC05']
        if priority[status] > priority.get(entry['status'], 0):
            entry['status'] = status
        manifest['coverage']['DOC05']['note'] = 'bounded OOXML/OLE/RTF objects and static VBA source'
    return children


def _doc01_coverage(manifest, status):
    if 'DOC01' not in manifest['coverage']:
        return
    priority = {'not scheduled': 0, 'no finding': 1, 'ran': 2,
                'truncated': 3, 'failed': 4}
    entry = manifest['coverage']['DOC01']
    if priority[status] > priority.get(entry['status'], 0):
        entry['status'] = status
    entry['note'] = 'bounded safe ZIP/7z/TAR members and gzip containers'


def _tar_job(run, manifest, artifact, deadline):
    from .profiles.tar import extract_tar
    path = Path(artifact['path'])
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            magic = source.read(6)
    except OSError:
        magic = b''
    compression = ('gzip' if magic.startswith(b'\x1f\x8b') else
                   'bzip2' if magic.startswith(b'BZh') else
                   'xz' if magic.startswith(b'\xfd7zXZ\x00') else None)
    compression_note = f' ({compression} container)' if compression else ''
    fingerprint = hashlib.sha256(Path(extract_tar.__code__.co_filename).read_bytes()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:tar.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        manifest['warnings'].extend(old.get('warnings', []))
        status = old.get('coverage_status', 'no finding')
        children = reusable
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'tar',
               'input_ids': [artifact['id']], 'operation': 'bounded safe TAR extraction',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'members': 100, 'derived_bytes': MAX_DERIVED},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children = []
        status = 'no finding'
        try:
            records, warnings = _run_tar(
                path, staging, min(100, MAX_ARTIFACTS - len(manifest['artifacts'])),
                MAX_DERIVED - manifest['derived_bytes'],
                min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('TAR source changed before member publication')
            for record in records:
                child = _store_staged(
                    run, manifest, artifact, record, deadline,
                    locator={'archive_member': record['member'], 'member_index': record['index']},
                    operation=f"tar member {record['index']}{compression_note}", producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    children.append(child)
            status = 'truncated' if warnings else 'ran' if children else 'no finding'
            manifest['warnings'].extend(warnings[:100])
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
        except Exception as error:
            status = 'failed'
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"TAR job failed: {job['warning']}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    _doc01_coverage(manifest, status)
    return children


def _can_job(run, manifest, artifact, deadline):
    from .profiles.canlog import parse_can_log
    path = Path(artifact['path'])
    fingerprint = hashlib.sha256(Path(parse_can_log.__code__.co_filename).read_bytes()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:can-log.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    if old:
        output = Path(old.get('frames_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink()
                     and _hash(output, deadline) == old.get('frames_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        warnings = old.get('warnings', [])
        count = old['frame_count']
        frames = json.loads(output.read_text())
        manifest['warnings'].extend(warnings)
    else:
        frames = []
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'can-log',
               'input_ids': [artifact['id']], 'operation': 'bounded CAN text log normalization',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'frames': 10000, 'input_bytes': 8 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for old_info in manifest['intelligence']:
            if old_info['artifact_id'] == artifact['id'] and old_info['tag'] == 'CAN frame':
                old_info['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        try:
            frames, warnings = _run_can(path, 10000, 8 * 1024 * 1024,
                                        min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('CAN source changed before normalization publication')
            output = run / 'jobs' / f"{job['id']}.frames.json"
            _write_json(output, frames)
            job['frames_path'] = str(output)
            job['frames_sha256'] = _hash(output, deadline)
            if job['frames_sha256'] is None:
                warnings.append('CAN normalization identity incomplete before work budget ended')
            for frame in frames[:100]:
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'CAN frame', 'group': frame['bus'],
                    'value': f"{frame['timestamp']} {frame['can_id']} {frame['payload_hex']} "
                             f"DLC={frame['dlc']} ({frame['frame_type']})",
                    'source_locator': {'line': frame['source_line'],
                                       'timestamp_basis': frame['timestamp_basis']},
                    'next_action': 'Interpret payload meaning only with a supplied schema.'})
            if len(frames) > 100:
                warnings.append('CAN report displays first 100 frames; all bounded rows remain in job output')
            count = len(frames)
            job['frame_count'] = count
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            count = 0
            frames = []
            warnings = [f'{type(error).__name__}: {error}']
            job['status'] = 'failed'
            job['warning'] = warnings[0]
            manifest['warnings'].append(f"CAN job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'CAN01' in manifest['coverage']:
        manifest['coverage']['CAN01']['status'] = ('failed' if not old and job['status'] == 'failed' else
                                                   'truncated' if warnings else 'ran' if count else 'no finding')
        manifest['coverage']['CAN01']['note'] = 'bounded candump/ASC text frames; no signal semantics'
    return frames


def _can_dbc_fingerprint():
    from importlib import metadata
    from .profiles.can_dbc import decode_can_frames
    source = hashlib.sha256(Path(decode_can_frames.__code__.co_filename).read_bytes()).hexdigest()
    try:
        version = metadata.version('cantools')
    except metadata.PackageNotFoundError:
        version = 'unavailable'
    return hashlib.sha256(f'{source}:cantools={version}'.encode()).hexdigest()


def _can_dbc_job(run, manifest, artifact, frames, database_path, database_hash, deadline):
    coverage = manifest['coverage']['CAN02']
    fingerprint = manifest['current_adapter_fingerprints']['can-dbc'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:can-dbc.v1:"
                         f"{fingerprint}:{database_hash}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink()
                     and _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        coverage['status'] = old['coverage_status']
        coverage['note'] = old.get('coverage_note', 'supplied DBC/ARXML signal values and raw frames')
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'can-dbc',
           'input_ids': [artifact['id']], 'operation': 'decode supplied CAN signal database',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {'dbc': database_hash},
           'cwd': str(run),
           'limits': {'frames': 10000, 'database_bytes': 4 * 1024 * 1024,
                      'output_bytes': 16 * 1024 * 1024},
           'status': 'running', 'started': time.time()}
    manifest['jobs'].append(job)
    for old_info in manifest['intelligence']:
        if old_info['artifact_id'] == artifact['id'] and old_info['tag'] == 'CAN signal':
            old_info['superseded'] = True
    _write_json(run / 'manifest.json', manifest)
    try:
        records, warnings = _run_can_dbc(frames, database_path, 10000, 4 * 1024 * 1024,
                                         16 * 1024 * 1024,
                                         min(30, max(.01, deadline - time.monotonic())))
        if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('CAN source changed before signal publication')
        try:
            after_database_hash = _hash(database_path, deadline)
        except OSError:
            after_database_hash = None
        if after_database_hash != database_hash:
            raise RuntimeError('CAN signal database changed before publication')
        output = run / 'jobs' / f"{job['id']}.signals.json"
        _write_text(output, json.dumps(records, ensure_ascii=False, allow_nan=False,
                                      separators=(',', ':')) + '\n')
        job['records_path'] = str(output)
        job['records_sha256'] = _hash(output, deadline)
        if job['records_sha256'] is None:
            warnings.append('CAN signal output identity incomplete before work budget ended')
        shown = 0
        for record in records:
            if record['status'] not in ('decoded', 'out_of_range'):
                continue
            frame = record['frame']
            for item in record['signals']:
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'CAN signal', 'group': record['message'],
                    'value': f"{item['name']}={item['value']} {item['unit'] or ''} "
                             f"(raw={item['raw']})".strip(),
                    'source_locator': {'line': frame['source_line'], 'can_id': frame['can_id'],
                                       'payload_hex': frame['payload_hex'],
                                       'timestamp': frame['timestamp'],
                                       'timestamp_basis': frame['timestamp_basis'],
                                       'dbc_sha256': record['database_sha256'],
                                       'signal': item['name'],
                                       'multiplexer_signal': item['multiplexer_signal'],
                                       'multiplexer_value': item['multiplexer_value']},
                    'next_action': 'Check the supplied schema against this trace.'})
                shown += 1
                if shown >= 100:
                    break
            if shown >= 100:
                break
        decoded = sum(record['status'] in ('decoded', 'out_of_range') for record in records)
        unavailable = any(record['status'] in ('database_error', 'unavailable') for record in records)
        truncated = any('limit reached' in note for note in warnings)
        coverage['status'] = ('skipped prerequisite' if unavailable else
                              'truncated' if truncated else 'ran' if decoded else 'no finding')
        coverage['note'] = 'supplied DBC/ARXML signal values with raw frame and multiplexer provenance'
        if shown >= 100:
            warnings.append('CAN report displays first 100 signals; all bounded rows remain in job output')
        job['warnings'] = warnings[:100]
        job['coverage_status'] = coverage['status']
        job['coverage_note'] = coverage['note']
        job['record_count'] = len(records)
        job['status'] = 'complete'
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        coverage['status'] = 'failed'
        coverage['note'] = 'CAN signal decoder failed; raw CAN01 frames remain available'
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        manifest['warnings'].append(f"CAN signal job failed: {type(error).__name__}")
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _elf_job(run, manifest, artifact, deadline):
    coverage = manifest['coverage']['PWN02']
    if importlib.util.find_spec('elftools') is None:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'pyelftools required for bounded static ELF inspection'
        manifest['warnings'].append('PWN02 skipped: pyelftools unavailable')
        return
    path = Path(artifact['path'])
    fingerprint = _elf_fingerprint()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:elf.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    if old:
        output = Path(old.get('report_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink()
                     and _hash(output, deadline) == old.get('report_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        report = json.loads(Path(old['report_path']).read_text())
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'elf',
               'input_ids': [artifact['id']], 'operation': 'bounded static x86 ELF inspection',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': 32 * 1024 * 1024, 'symbols': 64,
                          'gadgets': 64, 'executable_scan_bytes': 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'].startswith('ELF '):
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        report = None
        warnings = []
        try:
            report, warnings = _run_elf(path, min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('ELF source changed before static report publication')
            output = run / 'jobs' / f"{job['id']}.elf.json"
            _write_json(output, report)
            job['report_path'] = str(output)
            job['report_sha256'] = _hash(output, deadline)
            if job['report_sha256'] is None:
                warnings.append('ELF report identity incomplete before work budget ended')
            if report is not None:
                mitigation = report['mitigations']
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'ELF mitigation', 'group': report['architecture'],
                    'value': (f"PIE={mitigation['pie']} NX={mitigation['nx']} "
                              f"RELRO={mitigation['relro']} canary={mitigation['canary']}"),
                    'source_locator': {'elf_header': 'e_type',
                                       'program_headers': ['PT_GNU_STACK', 'PT_GNU_RELRO'],
                                       'dynamic_tags': ['DT_BIND_NOW', 'DT_FLAGS', 'DT_FLAGS_1']},
                    'next_action': 'Treat these as static build properties, not an exploit result.'})
                for symbol in report['symbols']:
                    manifest['intelligence'].append({
                        'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                        'tag': 'ELF symbol', 'group': symbol['source_table'],
                        'value': f"{symbol['name']} static VA 0x{symbol['vaddr']:x}",
                        'source_locator': {'static_vaddr': symbol['vaddr'],
                                           'file_offset': symbol['file_offset'],
                                           'symbol_table': symbol['source_table'],
                                           'section': symbol['section']},
                        'next_action': 'Resolve a runtime base if PIE before using this address.'})
                for gadget in report['gadgets']:
                    manifest['intelligence'].append({
                        'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                        'tag': 'ELF gadget', 'group': f"segment {gadget['segment']}",
                        'value': (f"{gadget['instructions']} static VA "
                                  f"0x{gadget['vaddr']:x} bytes {gadget['bytes']}"),
                        'source_locator': {'static_vaddr': gadget['vaddr'],
                                           'file_offset': gadget['file_offset'],
                                           'segment': gadget['segment']},
                        'next_action': 'Verify control flow and runtime base; this is a gadget lead.'})
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"ELF job failed: {job['warning']}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    coverage['status'] = ('failed' if not old and job['status'] == 'failed' else
                          'skipped prerequisite' if report is None and any(
                              'unsupported' in note or 'malformed' in note for note in warnings) else
                          'truncated' if warnings else 'ran' if report else 'no finding')
    coverage['note'] = 'static x86 ELF protections, defined symbols and short gadget leads; runtime base unknown'


def _checker_job(run, manifest, artifact, hints, replay, deadline):
    coverage = manifest['coverage']['REV07']
    if not manifest['execute_local']:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = 'symbolic checker execution requires --execute-local'
        return
    if time.monotonic() >= deadline:
        coverage['status'] = 'truncated'
        coverage['note'] = 'REV07 was not scheduled before the work budget ended'
        return
    from .profiles.checker import inspect_checker
    fingerprint = manifest['current_adapter_fingerprints']['checker'][0]
    hint_hash = manifest['checker_hints_sha256']
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:checker.v1:"
                          f'{fingerprint}:{hint_hash}:replay={replay}'.encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and
                job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('report_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('report_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'checker',
           'input_ids': [artifact['id']],
           'operation': 'bounded symbolic checker search and optional concrete replay',
           'tool_fingerprint': fingerprint,
           'data_fingerprints': {'checker_hints': hint_hash}, 'cwd': str(run),
           'limits': {'source_bytes': 8 * 1024 * 1024, 'input_bytes': 64,
                      'time_seconds': 20, 'steps': 5000},
           'replay_requested': replay, 'status': 'running', 'started': time.time()}
    manifest['jobs'].append(job)
    _write_json(run / 'manifest.json', manifest)
    try:
        report, warnings = inspect_checker(
            Path(artifact['path']), hints, execute_local=True, replay=replay,
            timeout=min(20, max(.01, deadline - time.monotonic() - 1)))
        if report['source_sha256'] != artifact['sha256']:
            raise RuntimeError('checker source changed before report publication')
        output = run / 'jobs' / f"{job['id']}.checker.json"
        _write_json(output, report)
        job['report_path'] = str(output)
        job['report_sha256'] = _hash(output, deadline)
        if job['report_sha256'] is None:
            raise RuntimeError('checker report identity incomplete before work budget ended')
        outcome = report['status']
        coverage_status = ('ran' if outcome in ('candidate', 'validated_input') else
                           'no finding' if outcome == 'unsat_under_model' else
                           'skipped prerequisite' if outcome == 'skipped_prerequisite' or
                           outcome == 'incomplete' and report.get('reason', '').startswith('ModuleNotFoundError:')
                           else 'truncated')
        job['coverage_status'] = coverage_status
        job['coverage_note'] = f"{outcome}: {report.get('reason', 'bounded checker model')}"
        coverage['status'] = coverage_status
        coverage['note'] = job['coverage_note']
        if outcome in ('candidate', 'validated_input'):
            manifest['findings'].append({
                'state': 'validated_input' if outcome == 'validated_input' else 'candidate',
                'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                'source_locator': {'checker_input_channel': report['checker']['channel'],
                                   'found_address': report.get('found_address')},
                'evidence': f"REV07 checker input hex {report['candidate_hex']}",
                'operation': 'bounded symbolic checker search' +
                             (' and successful concrete replay' if outcome == 'validated_input' else ''),
                'next_action': ('Challenge acceptance remains unverified.' if outcome == 'validated_input'
                                else 'Replay explicitly against the checker to validate the modeled input.')})
        job['warnings'] = warnings[:100]
        manifest['warnings'].extend(warnings[:100])
        job['status'] = 'complete'
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'[:300]
        coverage['status'] = 'failed'
        coverage['note'] = 'REV07 checker inspection failed; source bytes remain available'
        manifest['warnings'].append(f"REV07 job failed: {job['warning']}")
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _binary_job(run, manifest, artifact, deadline):
    coverage = manifest['coverage']['REV01']
    kind = artifact['kind_evidence']
    dependency = 'elftools' if kind == 'elf' else 'pefile' if kind == 'pe' else None
    if dependency and importlib.util.find_spec(dependency) is None:
        coverage['status'] = 'skipped prerequisite'
        coverage['note'] = f'{dependency} required for bounded binary inspection'
        manifest['warnings'].append(f'REV01 skipped: {dependency} unavailable')
        return
    path = Path(artifact['path'])
    fingerprint = _binary_fingerprint()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:binary-static.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    if old:
        output = Path(old.get('report_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('report_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        report = json.loads(Path(old['report_path']).read_text())
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'binary-static',
               'input_ids': [artifact['id']], 'operation': 'bounded ELF/PE static structure',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': 32 * 1024 * 1024, 'sections': 128,
                          'imports': 256, 'strings': 256, 'string_scan_bytes': 8 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'].startswith('Binary '):
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        report, warnings = None, []
        try:
            report, warnings = _run_binary(path, min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('binary source changed before static report publication')
            output = run / 'jobs' / f"{job['id']}.binary.json"
            _write_json(output, report)
            job['report_path'] = str(output)
            job['report_sha256'] = _hash(output, deadline)
            if job['report_sha256'] is None:
                warnings.append('binary report identity incomplete before work budget ended')
            if report is not None:
                common = {'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True}
                manifest['intelligence'].append({**common, 'tag': 'Binary structure',
                    'group': report['format'],
                    'value': f"{report['architecture']} {report['bits']}-bit ABI={report['abi']}",
                    'source_locator': {'header': report['format'],
                                       'entry_static_vaddr': report['entry_vaddr'],
                                       'entry_file_offset': report.get('entry_file_offset')},
                    'next_action': 'Use the static structure to choose a bounded manual analysis path.'})
                manifest['intelligence'].append({**common, 'tag': 'Binary mitigation',
                    'group': report['format'], 'value': json.dumps(report['mitigations'], sort_keys=True),
                    'source_locator': {'header': report['format'],
                                       'evidence': report['mitigation_evidence']},
                    'next_action': 'Verify protections in the intended runtime before relying on them.'})
                for section in report['sections'][:64]:
                    manifest['intelligence'].append({**common, 'tag': 'Binary section',
                        'group': report['format'], 'value': section['name'],
                        'source_locator': {'file_offset': section['file_offset'],
                                           'raw_size': section['raw_size'],
                                           'static_vaddr': section['static_vaddr']},
                        'next_action': 'Inspect the bounded section bytes if relevant.'})
                for symbol in report['imports'][:128]:
                    locator = {'symbol_table': symbol.get('symbol_table'),
                               'symbol_file_offset': symbol.get('symbol_file_offset'),
                               'iat_file_offset': symbol.get('iat_file_offset'),
                               'iat_rva': symbol.get('iat_rva')}
                    manifest['intelligence'].append({**common, 'tag': 'Binary import',
                        'group': symbol.get('library') or symbol.get('symbol_table'),
                        'value': symbol.get('name') or f"ordinal {symbol.get('ordinal')}",
                        'source_locator': locator,
                        'next_action': 'An import is a static lead, not proof that a call executes.'})
                for string in report['strings'][:64]:
                    manifest['intelligence'].append({**common, 'tag': 'Binary string',
                        'group': string['section'] or 'unmapped file bytes',
                        'value': string['value'],
                        'source_locator': {'file_offset': string['file_offset'],
                                           'static_vaddr': string['static_vaddr'],
                                           'encoding': string['encoding']},
                        'next_action': 'Check code references; string presence does not establish behavior.'})
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"binary static job failed: {job['warning']}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    outcome = ('failed' if not old and job['status'] == 'failed' else
               'skipped prerequisite' if report is None else
               'truncated' if warnings else 'ran')
    priority = {'not scheduled': 0, 'skipped prerequisite': 1,
                'ran': 2, 'truncated': 3, 'failed': 4}
    if priority[outcome] > priority[coverage['status']]:
        coverage['status'] = outcome
    coverage['note'] = 'static ELF/PE sections, imports and located strings; runtime behavior unknown'


def _rev_strings_job(run, manifest, artifact, deadline, queue, depth):
    coverage = manifest['coverage']['REV02']
    path = Path(artifact['path'])
    fingerprint = manifest['current_adapter_fingerprints']['rev-strings'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:rev-strings.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        reused = _reusable_children(manifest, old, deadline) if valid else None
        if reused is None:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reused:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'rev-strings',
           'input_ids': [artifact['id']], 'operation': 'bounded static obfuscated string recovery',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
           'limits': {'source_bytes': 8 * 1024 * 1024, 'records': 64,
                      'string_bytes': 4096, 'time_seconds': 20},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    for item in manifest['intelligence']:
        if item['artifact_id'] == artifact['id'] and item['tag'] == 'REV02 string candidate':
            item['superseded'] = True
    _write_json(run / 'manifest.json', manifest)
    warnings = []
    try:
        records, warnings = _run_rev_strings(path, min(20, max(.01, deadline - time.monotonic() - 1)))
        if _hash(path, deadline) != artifact['sha256']:
            raise RuntimeError('binary source changed before REV02 publication')
        stored = [{**row, 'data_hex': row['data'].hex()} for row in records]
        for row in stored:
            del row['data']
        output = run / 'jobs' / f"{job['id']}.rev-strings.json"
        _write_json(output, stored)
        job['records_path'] = str(output)
        job['records_sha256'] = _hash(output, deadline)
        if job['records_sha256'] is None:
            raise RuntimeError('REV02 record identity incomplete before work budget ended')
        for record in records:
            locator = {**record['source_locator'], 'encoding': record['encoding'],
                       'candidate_state': 'candidate', 'key_hex': record.get('key_hex')}
            child = _store_child(run, manifest, artifact, record['data'],
                                 f"REV02 {record['kind']} candidate", deadline,
                                 source_locator=locator, producer_key=key)
            if child:
                if child['id'] not in job['child_ids']:
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
            else:
                warnings.append(f"REV02 {record['kind']} candidate artifact could not be stored")
            manifest['intelligence'].append({
                'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                'tag': 'REV02 string candidate', 'group': f"{record['kind']} via {record['backend']}",
                'value': record['text'][:256],
                'source_locator': {**locator, 'decoded_sha256': hashlib.sha256(record['data']).hexdigest(),
                                   'decoded_size': len(record['data']),
                                   'child_artifact_id': child['id'] if child else None},
                'next_action': 'Check the decoding logic and challenge oracle; this is a heuristic candidate.'})
        status = ('skipped prerequisite' if not records and any(
                      'unsupported executable' in note for note in warnings) else
                  'truncated' if warnings else 'ran' if records else 'no finding')
        job['record_count'] = len(records)
        job['coverage_status'] = status
        job['coverage_note'] = 'bounded stack/XOR and optional FLOSS strings; recovered bytes are candidates'
        job['warnings'] = warnings[:100]
        job['status'] = 'complete'
        coverage['status'] = status
        coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV02 string recovery failed; source bytes remain available'
        manifest['warnings'].append(f"REV02 job failed: {job['warning']}")
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _rev_powershell_job(run, manifest, artifact, deadline, queue, depth):
    coverage = manifest['coverage']['REV11']
    fingerprint = manifest['current_adapter_fingerprints']['rev-powershell'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:rev-powershell.v1:"
                         f"{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        reused = _reusable_children(manifest, old, deadline) if valid else None
        if reused is None:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reused:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        if coverage['status'] in ('not scheduled', 'no finding') or old['coverage_status'] == 'truncated':
            coverage['status'] = old['coverage_status']
            coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'rev-powershell',
           'input_ids': [artifact['id']], 'operation': 'finite static PowerShell constants',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
           'limits': {'source_bytes': 256 * 1024, 'output_bytes': 64 * 1024,
                      'records': 64, 'depth': 2, 'time_seconds': 5},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    for item in manifest['intelligence']:
        if item['artifact_id'] == artifact['id'] and item['tag'] == 'REV11 PowerShell candidate':
            item['superseded'] = True
    _write_json(run / 'manifest.json', manifest)
    warnings = []
    try:
        records, warnings = _run_rev_powershell(
            Path(artifact['path']), min(5, max(.01, deadline - time.monotonic() - 1)))
        if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('PowerShell source changed before REV11 publication')
        stored = [{**row, 'data_hex': row['data'].hex()} for row in records]
        for row in stored:
            del row['data']
        output = run / 'jobs' / f"{job['id']}.rev-powershell.json"
        _write_json(output, stored)
        job['records_path'] = str(output)
        job['records_sha256'] = _hash(output, deadline)
        if job['records_sha256'] is None:
            raise RuntimeError('REV11 record identity incomplete before work budget ended')
        for record in records:
            data = record['data']
            locator = {**record['source_locator'],
                       'transform_chain': record['transform_chain'],
                       'candidate_state': 'candidate'}
            child = _store_child(run, manifest, artifact, data,
                                 f"REV11 {record['kind']} candidate", deadline,
                                 source_locator=locator, producer_key=key)
            if child:
                if child['id'] not in job['child_ids']:
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
            else:
                warnings.append(f"REV11 {record['kind']} candidate artifact could not be stored")
            try:
                preview = data[:128].decode('utf-8')
            except UnicodeDecodeError:
                preview = data[:64].hex()
            manifest['intelligence'].append({
                'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                'tag': 'REV11 PowerShell candidate', 'group': record['kind'],
                'value': preview,
                'source_locator': {**locator, 'decoded_sha256': hashlib.sha256(data).hexdigest(),
                                   'decoded_size': len(data),
                                   'child_artifact_id': child['id'] if child else None},
                'next_action': 'Verify this static candidate against the challenge oracle.'})
        status = 'truncated' if warnings else 'ran' if records else 'no finding'
        job['record_count'] = len(records)
        job['coverage_status'] = status
        job['coverage_note'] = 'literal PowerShell constants only; dynamic evaluation unsupported'
        job['warnings'] = warnings[:100]
        job['status'] = 'complete'
        if coverage['status'] in ('not scheduled', 'no finding') or status == 'truncated':
            coverage['status'] = status
            coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV11 static inspection failed; source bytes remain available'
        manifest['warnings'].append(f"REV11 job failed: {job['warning']}")
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _rev_rules_job(run, manifest, artifact, deadline, rule_paths):
    coverage = manifest['coverage']['REV03']
    fingerprint = manifest['current_adapter_fingerprints']['rev-rules'][0]
    rule_identity = manifest['rev_rules_identity']
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:rev-rules.v1:"
                         f"{fingerprint}:{rule_identity}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    if old:
        output = Path(old.get('report_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('report_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'rev-rules',
           'input_ids': [artifact['id']], 'operation': 'bounded static capa/YARA rule matching',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {'rule_hints': rule_identity},
           'cwd': str(run), 'limits': {'source_bytes': 32 * 1024 * 1024,
                                      'rule_bytes': 64 * 1024 * 1024, 'matches': 64,
                                      'output_bytes': 4 * 1024 * 1024, 'time_seconds': 25},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    for item in manifest['intelligence']:
        if item['artifact_id'] == artifact['id'] and item['tag'] == 'REV03 rule match':
            item['superseded'] = True
    _write_json(run / 'manifest.json', manifest)
    warnings = []
    try:
        remaining = max(.01, deadline - time.monotonic())
        report, warnings = _run_rev_rules(Path(artifact['path']), rule_paths,
                                          min(10, max(.01, (remaining - 5) / 2)))
        if report['sample_sha256'] != artifact['sha256'] or _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('binary source changed before REV03 publication')
        output = run / 'jobs' / f"{job['id']}.rev-rules.json"
        _write_json(output, report)
        job['report_path'] = str(output)
        job['report_sha256'] = _hash(output, deadline)
        if job['report_sha256'] is None:
            raise RuntimeError('REV03 report identity incomplete before work budget ended')
        for engine, row in report['engines'].items():
            for match in row['matches']:
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'REV03 rule match', 'group': engine,
                    'value': match['rule'][:256],
                    'source_locator': {'address': match.get('address'),
                                       'evidence': match.get('evidence', []),
                                       'strings': match.get('strings', []),
                                       'namespace': match.get('namespace'),
                                       'rules_sha256': row['rules']['sha256'],
                                       'sample_sha256': report['sample_sha256']},
                    'next_action': 'Inspect the matched code or bytes; a rule match is not proof of runtime behavior.'})
        selected = [report['engines'][engine]['status'] for engine, keys in
                    (('capa', ('capa_rules', 'capa_signatures')),
                     ('yara', ('yara_rules',))) if any(key in rule_paths for key in keys)]
        if not selected or all(value in ('skipped_prerequisite', 'unavailable') for value in selected):
            status = 'skipped prerequisite'
        elif any(value == 'incomplete' for value in selected) or any(
                value in ('skipped_prerequisite', 'unavailable') for value in selected):
            status = 'truncated'
        elif any(value == 'matched' for value in selected):
            status = 'ran'
        else:
            status = 'no finding'
        job['coverage_status'] = status
        job['coverage_note'] = 'selected static rule matches with byte/address evidence; no runtime behavior proof'
        job['warnings'] = warnings[:100]
        job['status'] = 'complete'
        coverage['status'] = status
        coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV03 rule matching failed; sample bytes remain available'
        manifest['warnings'].append(f"REV03 job failed: {job['warning']}")
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _pyinstaller_job(run, manifest, artifact, deadline, queue, depth):
    coverage = manifest['coverage']['REV05']
    fingerprint = manifest['current_adapter_fingerprints']['pyinstaller'][0]
    key = hashlib.sha256(
        f"{artifact['id']}:{artifact['sha256']}:pyinstaller.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
        old = None
    if old:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        if old['coverage_status'] != 'no finding' or coverage['status'] == 'not scheduled':
            coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'pyinstaller',
           'input_ids': [artifact['id']], 'operation': 'bounded PyInstaller archive extraction',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
           'limits': {'source_bytes': 128 * 1024 * 1024, 'members': 64,
                      'derived_bytes': 16 * 1024 * 1024, 'time_seconds': 15},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    _write_json(run / 'manifest.json', manifest)
    staging = run / 'staging' / job['id']
    try:
        records, warnings = _run_pyinstaller(
            Path(artifact['path']), staging,
            min(64, MAX_ARTIFACTS - len(manifest['artifacts'])),
            min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
            min(15, max(.01, deadline - time.monotonic() - 1)))
        if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('PyInstaller source changed before output publication')
        for record in records:
            locator = {'pyinstaller_kind': record['kind'],
                       'member': record['member'][:256], 'index': record['index'],
                       'offset': record['offset'],
                       'compressed_size': record['compressed_size'],
                       'python_version': record['python_version']}
            for field in ('typecode', 'bytecode_magic', 'bytecode_inspection', 'carchive_index'):
                if field in record:
                    locator[field] = record[field]
            child = _store_staged(run, manifest, artifact, record, deadline,
                                  locator=locator,
                                  operation=f"REV05 {record['kind']} {record['locator'][:256]}",
                                  producer_key=key)
            if child:
                job['child_ids'].append(child['id'])
                queue.append((child, depth + 1))
            else:
                warnings.append(f"REV05 member {record['index']} could not be stored")
        status = ('truncated' if warnings else 'ran' if job['child_ids'] else 'no finding')
        job['coverage_status'] = status
        job['coverage_note'] = 'bounded CArchive/PYZ bytes and version; no execution or decompilation'
        job['warnings'] = warnings[:100]
        job['status'] = 'complete'
        if status != 'no finding' or coverage['status'] == 'not scheduled':
            coverage['status'] = status
        coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV05 archive inspection failed; source bytes remain available'
        manifest['warnings'].append(f"REV05 job failed: {job['warning']}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _java_android_job(run, manifest, artifact, deadline, queue, depth):
    coverage = manifest['coverage']['REV06']
    fingerprint = manifest['current_adapter_fingerprints']['java-android'][0]
    key = hashlib.sha256(
        f"{artifact['id']}:{artifact['sha256']}:java-android.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
        old = None
    if old:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            locator = child.get('source_locator') or {}
            member = locator.get('member') or ''
            if locator.get('java_kind') not in ('class', 'dex') and not (
                    member.startswith('lib/') and member.endswith('.so')):
                queue.append((child, depth + 1))
        if old['coverage_status'] != 'no finding' or coverage['status'] == 'not scheduled':
            coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'java-android',
           'input_ids': [artifact['id']],
           'operation': 'bounded static Java/Android archive and bytecode triage',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
           'limits': {'source_bytes': 64 * 1024 * 1024, 'parts': 64,
                      'derived_bytes': 32 * 1024 * 1024, 'time_seconds': 20},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    for item in manifest['intelligence']:
        if item['artifact_id'] == artifact['id'] and item['tag'] == 'REV06 DEX string lead':
            item['superseded'] = True
    _write_json(run / 'manifest.json', manifest)
    staging = run / 'staging' / job['id']
    try:
        parts = min(64, MAX_ARTIFACTS - len(manifest['artifacts']))
        remaining = min(32 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes'])
        if parts <= 0 or remaining <= 0:
            raise WorkLimit('REV06 artifact or derived byte limit reached')
        records, warnings = _run_java_android(
            Path(artifact['path']), staging,
            min(20, max(.01, deadline - time.monotonic() - 1)), parts, remaining)
        if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('REV06 source changed before output publication')
        for record in records:
            if record['source_sha256'] != artifact['sha256']:
                raise RuntimeError('REV06 source hash mismatch')
            locator = {'java_kind': record['kind'], **record['source_locator']}
            if record['kind'] == 'dex_string':
                child = _store_child(run, manifest, artifact, record['data'],
                                     'REV06 DEX literal string lead', deadline,
                                     source_locator=locator, producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'REV06 DEX string lead', 'group': record.get('member') or 'standalone DEX',
                    'value': record['data'].decode('ascii'),
                    'source_locator': {**locator, 'child_artifact_id': child['id'] if child else None,
                                       'validated': False},
                    'next_action': 'Confirm the literal is used by the checker; no DEX source was decompiled.'})
                continue
            child = _store_staged(run, manifest, artifact, record, deadline,
                                  locator=locator,
                                  operation=f"REV06 {record['kind']} {record['member']}",
                                  producer_key=key)
            if child:
                job['child_ids'].append(child['id'])
                if record['kind'] not in ('class', 'dex') and not (
                        record['member'].startswith('lib/') and record['member'].endswith('.so')):
                    queue.append((child, depth + 1))
            else:
                warnings.append(f"REV06 member {record['index']} could not be stored")
        warnings = [note[:300] for note in warnings[:100]]
        status = 'truncated' if warnings else 'ran' if job['child_ids'] else 'no finding'
        job['coverage_status'] = status
        job['coverage_note'] = ('exact Java/Android resources, javap class listings and located '
                                'DEX string leads; no challenge execution or claimed DEX source')
        job['warnings'] = warnings
        job['status'] = 'complete'
        if status != 'no finding' or coverage['status'] == 'not scheduled':
            coverage['status'] = status
        coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings)
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV06 static Java/Android inspection failed; source bytes remain available'
        manifest['warnings'].append(f"REV06 job failed: {job['warning']}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _rev_packers_job(run, manifest, artifact, deadline, queue, depth):
    coverage = manifest['coverage']['REV04']
    fingerprint = manifest['current_adapter_fingerprints']['rev-packers'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:rev-packers.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        reused = _reusable_children(manifest, old, deadline) if valid else None
        if reused is None:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reused:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        coverage['status'] = old['coverage_status']
        coverage['note'] = old['coverage_note']
        manifest['warnings'].extend(old.get('warnings', []))
        return
    upx, binwalk = shutil.which('upx'), shutil.which('binwalk')
    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'rev-packers',
           'input_ids': [artifact['id']], 'operation': 'bounded UPX and binwalk inspection',
           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
           'limits': {'source_bytes': 16 * 1024 * 1024, 'derived_bytes': 64 * 1024 * 1024,
                      'signature_leads': 32, 'time_seconds': 20},
           'status': 'running', 'child_ids': [], 'started': time.time()}
    manifest['jobs'].append(job)
    _write_json(run / 'manifest.json', manifest)
    staging = run / 'staging' / job['id']
    warnings = []
    try:
        remaining = MAX_DERIVED - manifest['derived_bytes']
        if remaining <= 0:
            raise WorkLimit('REV04 derived artifact byte limit reached')
        records, warnings = _run_rev_packers(
            Path(artifact['path']), staging,
            min(20, max(.01, deadline - time.monotonic() - 1)),
            min(64 * 1024 * 1024, remaining), upx, binwalk)
        if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
            raise RuntimeError('binary source changed before REV04 publication')
        by_sha = {artifact['sha256']: artifact}
        stored = []
        for record in records:
            if record['kind'] == 'upx-unpacked':
                if record['source_sha256'] != artifact['sha256']:
                    raise RuntimeError('UPX record source hash mismatch')
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator={'packer': 'UPX', 'source_sha256': artifact['sha256'],
                                               'validation': 'upx -t on private copy'},
                                      operation='REV04 UPX unpacked', producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
                    by_sha[child['sha256']] = child
                else:
                    warnings.append('REV04 validated UPX output could not be stored')
                stored.append({**record, 'path': str(child['path']) if child else None,
                               'child_artifact_id': child['id'] if child else None})
                continue
            source = by_sha.get(record['source_sha256'])
            if source is None:
                warnings.append('REV04 signature lead has no stored source artifact')
                continue
            manifest['intelligence'].append({
                'artifact_id': source['id'], 'job_id': job['id'], 'current': True,
                'tag': 'REV04 signature lead', 'group': 'binwalk',
                'value': record['description'][:256],
                'source_locator': {**record['source_locator'],
                                   'source_sha256': record['source_sha256'],
                                   'validated': False},
                'next_action': 'Validate the format and byte extent before extracting any embedded file.'})
            stored.append(record)
        output = run / 'jobs' / f"{job['id']}.rev-packers.json"
        _write_json(output, stored)
        job['records_path'] = str(output)
        job['records_sha256'] = _hash(output, deadline)
        if job['records_sha256'] is None:
            raise RuntimeError('REV04 record identity incomplete before work budget ended')
        status = ('skipped prerequisite' if upx is None else
                  'truncated' if any(any(word in note for word in
                                      ('limit', 'timed out', 'incomplete', 'changed'))
                                     for note in warnings) else
                  'ran' if job['child_ids'] or any(row['kind'] == 'signature-lead'
                                                  for row in stored) else 'no finding')
        job['coverage_status'] = status
        job['coverage_note'] = 'UPX-validated private unpacking; binwalk offsets are unvalidated leads'
        job['warnings'] = warnings[:100]
        job['status'] = 'complete'
        coverage['status'] = status
        coverage['note'] = job['coverage_note']
        manifest['warnings'].extend(warnings[:100])
    except Exception as error:
        job['status'] = 'failed'
        job['warning'] = f'{type(error).__name__}: {error}'
        coverage['status'] = 'failed'
        coverage['note'] = 'REV04 inspection failed; source bytes remain available'
        manifest['warnings'].append(f"REV04 job failed: {job['warning']}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    job['ended'] = time.time()
    _write_json(run / 'jobs' / f"{job['id']}.json", job)
    _write_json(run / 'manifest.json', manifest)


def _packets_job(run, manifest, artifact, deadline):
    from .profiles import packets
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(packets.__file__).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(packets.TSHARK), deadline)
    except OSError:
        tool_hash = None
    fingerprint = hashlib.sha256(f'{module_hash}:{tool_hash}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:packets.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink()
                     and _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        warnings = old.get('warnings', [])
        count = old['packet_count']
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'packets',
               'input_ids': [artifact['id']], 'operation': 'bounded offline TShark metadata',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'output_bytes': 8 * 1024 * 1024, 'records': 10000},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for old_info in manifest['intelligence']:
            if old_info['artifact_id'] == artifact['id'] and old_info['tag'] == 'PCAP frame':
                old_info['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        try:
            records, warnings = _run_packets(path, min(30, max(.01, deadline - time.monotonic())),
                                              8 * 1024 * 1024)
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('capture changed before packet publication')
            if len(records) > 10000:
                warnings.append('packet record limit reached; later frames omitted')
                records = records[:10000]
            output = run / 'jobs' / f"{job['id']}.packets.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                warnings.append('packet inventory identity incomplete before work budget ended')
            useful = [row for row in records if any(field in row for field in ('dns', 'http', 'tcp_analysis'))][:80]
            useful.extend(row for row in records[:20] if row not in useful)
            for row in useful[:100]:
                detail = (f"{row['src_address']}:{row['src_port']} -> "
                          f"{row['dst_address']}:{row['dst_port']} "
                          f"DNS={row.get('dns')} HTTP={row.get('http')} "
                          f"HTTPall={row.get('http_fields')} TCP={row.get('tcp_analysis')}")
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'PCAP frame', 'group': f"stream {row['tcp_stream']}",
                    'value': detail[:512],
                    'source_locator': {'packet': row['packet']},
                    'next_action': 'Use packet/stream reference before selecting a deeper decoder.'})
            count = len(records)
            job['packet_count'] = count
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            count = 0
            warnings = [f'{type(error).__name__}: {error}']
            job['status'] = 'failed'
            job['warning'] = warnings[0]
            manifest['warnings'].append(f"packet job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'NET01' in manifest['coverage']:
        manifest['coverage']['NET01']['status'] = ('failed' if not old and job['status'] == 'failed' else
                                                   'truncated' if warnings else 'ran' if count else 'no finding')
        manifest['coverage']['NET01']['note'] = 'frame-linked TShark DNS/HTTP/endpoints only'


def _packet_objects_job(run, manifest, artifact, deadline):
    from .profiles import packet_objects, packet_streams
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(packet_objects.__file__).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(packet_objects.TSHARK), deadline)
    except OSError:
        tool_hash = None
    stream_hash = hashlib.sha256(Path(packet_streams.__file__).read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(f'{module_hash}:{stream_hash}:{tool_hash}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:packet-objects.v2:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
        children = reusable
        status = old.get('coverage_status', 'no finding')
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'packet-objects',
               'input_ids': [artifact['id']], 'operation': 'bounded HTTP object export',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': 256 * 1024 * 1024, 'objects': 32,
                          'derived_bytes': 64 * 1024 * 1024, 'metadata_bytes': 32 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children = []
        warnings = []
        status = 'no finding'
        try:
            remaining = min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes'])
            if remaining <= 0:
                records, warnings = [], ['HTTP object derived byte limit reached']
            else:
                records, warnings = _run_packet_objects(
                    path, staging, 32, remaining,
                    min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('capture changed before HTTP object publication')
            for record in records:
                if record['size'] > MAX_CHILD:
                    warnings.append(f"HTTP object {record['index']}: child byte limit reached")
                    continue
                locator = {'protocol': 'http', 'object_index': record['index'],
                           'object_name': record['name'][:256],
                           'packet': record['packet'], 'tcp_stream': record['tcp_stream'],
                           'source_locators': record['source_locators'],
                           'wire_length_verified': bool(record['wire_verification']),
                           'wire_verification': record['wire_verification']}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator,
                                      operation=f"HTTP object {record['index']}",
                                      producer_key=key)
                if child is None:
                    warnings.append('HTTP object publication limit reached; export incomplete')
                    break
                job['child_ids'].append(child['id'])
                children.append(child)
                manifest['findings'].append({
                    'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                    'current': True, 'source_locator': locator,
                    'evidence': f"TShark HTTP response body SHA-256 {child['sha256']}; "
                                + ('Content-Length verified' if record['wire_verification'] == 'Content-Length'
                                   else 'chunk framing and gzip CRC verified'
                                   if record['wire_verification'] == 'chunked-gzip-wire'
                                   else 'wire completeness unverified'),
                    'operation': 'HTTP object export',
                    'next_action': 'Inspect extracted bytes and validate challenge meaning.'})
            status = ('skipped prerequisite' if any('TShark unavailable' in note for note in warnings) else
                      'truncated' if warnings else 'ran' if children else 'no finding')
            manifest['warnings'].extend(warnings[:100])
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"HTTP object job failed: {type(error).__name__}")
            status = 'failed'
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'NET02' in manifest['coverage']:
        previous = manifest['coverage']['NET02']['status']
        manifest['coverage']['NET02']['status'] = (
            'failed' if status == 'failed' else 'truncated' if status == 'truncated' or previous == 'truncated'
            else 'ran' if status == 'ran' or previous == 'ran' else status)
        manifest['coverage']['NET02']['note'] = 'exact TShark HTTP body exports with frame and stream references'
    return children


def _packet_tls_job(run, manifest, artifact, keylog, keylog_hash, deadline):
    from .profiles import packet_objects, packet_tls
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(packet_tls.__file__).read_bytes()).hexdigest()
    runner_hash = hashlib.sha256(Path(packet_objects.__file__).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(packet_tls.TSHARK), deadline)
    except OSError:
        tool_hash = None
    fingerprint = hashlib.sha256(f'{module_hash}:{runner_hash}:{tool_hash}'.encode()).hexdigest()
    key = hashlib.sha256(
        f"{artifact['id']}:{artifact['sha256']}:packet-tls.v1:{fingerprint}:{keylog_hash}".encode()
    ).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        children = reusable
        warnings = old.get('warnings', [])
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'packet-tls',
               'input_ids': [artifact['id']], 'operation': 'supplied-keylog TLS HTTP recovery',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'tls_keylog': keylog_hash},
               'cwd': str(run), 'limits': {'source_bytes': 256 * 1024 * 1024,
                                          'keylog_bytes': 1024 * 1024, 'objects': 32,
                                          'derived_bytes': 64 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        children, warnings, status = [], [], 'no finding'
        try:
            remaining = min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes'])
            if remaining <= 0:
                records, warnings = [], ['TLS object derived byte limit reached']
            else:
                records, warnings = _run_packet_tls(
                    path, keylog, staging, 32, remaining,
                    min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256'] or _hash(keylog, deadline) != keylog_hash:
                raise RuntimeError('capture or TLS key log changed before publication')
            for record in records:
                if record['size'] > MAX_CHILD or not record['length_verified']:
                    warnings.append(f"TLS HTTP object {record['index']}: body completeness unverified or child byte limit")
                    continue
                locator = {'protocol': 'https', 'object_index': record['index'],
                           'object_name': record['name'][:256],
                           'packet': record['packet'], 'tcp_stream': record['tcp_stream'],
                           'source_locators': record['source_locators'],
                           'wire_length_verified': True,
                           'decrypted_fields': record['decrypted_fields']}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator,
                                      operation=f"TLS HTTP object {record['index']}",
                                      producer_key=key)
                if child is None:
                    warnings.append('TLS object publication limit reached; export incomplete')
                    break
                job['child_ids'].append(child['id'])
                children.append(child)
                manifest['findings'].append({
                    'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                    'current': True, 'source_locator': locator,
                    'evidence': f"TShark decrypted HTTP response body SHA-256 {child['sha256']}; Content-Length verified",
                    'operation': 'TLS HTTP recovery',
                    'next_action': 'Inspect extracted bytes and validate challenge meaning.'})
            status = ('skipped prerequisite' if any('TShark unavailable' in note for note in warnings) else
                      'no finding' if any('no matching' in note or 'no TLS packets' in note
                                          for note in warnings) else
                      'truncated' if warnings else 'ran' if children else 'no finding')
            manifest['warnings'].extend(warnings[:100])
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"TLS job failed: {type(error).__name__}")
            status = 'failed'
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'NET05' in manifest['coverage']:
        previous = manifest['coverage']['NET05']['status']
        manifest['coverage']['NET05']['status'] = (
            'failed' if status == 'failed' else
            'truncated' if status == 'truncated' or previous == 'truncated' else
            'ran' if status == 'ran' or previous == 'ran' else status)
        manifest['coverage']['NET05']['note'] = 'explicit matching TLS key log; frame-linked complete HTTP response bodies only'
    return children


def _packet_streams_job(run, manifest, artifact, deadline):
    from .profiles import packet_streams
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(packet_streams.__file__).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(packet_streams.TSHARK), deadline)
    except OSError:
        tool_hash = None
    fingerprint = hashlib.sha256(f'{module_hash}:{tool_hash}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:packet-streams.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs']
                if job['key'] == key and job['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if reusable is not None:
        output = Path(old.get('records_path', ''))
        try:
            valid = output.is_file() and not output.is_symlink() and (
                _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            reusable = None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
        warnings = old.get('warnings', [])
        manifest['warnings'].extend(warnings)
        children = reusable
        status = old.get('coverage_status', 'no finding')
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'packet-streams',
               'input_ids': [artifact['id']], 'operation': 'bounded TCP direction reconstruction',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'streams': 16, 'output_bytes': 8 * 1024 * 1024,
                          'derived_bytes': 4 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for old_info in manifest['intelligence']:
            if old_info['artifact_id'] == artifact['id'] and old_info['tag'] == 'TCP stream':
                old_info['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        children = []
        warnings = []
        status = 'no finding'
        try:
            remaining = min(4 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes'])
            if remaining <= 0:
                records, warnings = [], ['TCP derived byte limit reached']
            else:
                records, warnings = _run_packet_streams(
                    path, min(30, max(.01, deadline - time.monotonic())),
                    8 * 1024 * 1024, 16, remaining)
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('capture changed before TCP stream publication')
            summaries = []
            for record in records:
                summary = {name: value for name, value in record.items() if name != 'data'}
                locator = {'tcp_stream': record['stream'], 'direction': record['direction'],
                           'first_frame': record['frames'][0], 'last_frame': record['frames'][-1],
                           'sequence_start': record['sequence_start'],
                           'sequence_end': record['sequence_end']}
                data = record.get('data')
                if record['complete'] and data:
                    child = _store_child(run, manifest, artifact, data,
                                         f"TCP stream {record['stream']} direction {record['direction']}",
                                         deadline, source_locator=locator, producer_key=key)
                    if child is None:
                        warnings.append(f"TCP stream {record['stream']} direction "
                                        f"{record['direction']}: publication limit reached")
                    else:
                        if child['id'] not in job['child_ids']:
                            job['child_ids'].append(child['id'])
                            children.append(child)
                        summary['artifact_id'] = child['id']
                        summary['data_sha256'] = child['sha256']
                        manifest['findings'].append({
                            'state': 'candidate', 'artifact_id': child['id'], 'job_id': job['id'],
                            'current': True, 'source_locator': locator,
                            'evidence': f"contiguous SYN-to-FIN TCP bytes SHA-256 {child['sha256']}; "
                                        'challenge meaning unverified',
                            'operation': 'TCP direction reconstruction',
                            'next_action': 'Inspect exact stream bytes and validate challenge meaning.'})
                summaries.append(summary)
                detail = (f"{record['src_address']}:{record['src_port']} -> "
                          f"{record['dst_address']}:{record['dst_port']}; "
                          f"frames={len(record['frames'])}; complete={record['complete']}; "
                          f"gaps={len(record['gaps'])}; conflicts={len(record['conflicts'])}; "
                          f"reasons={record['reasons']}")
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'TCP stream',
                    'group': f"stream {record['stream']} direction {record['direction']}",
                    'value': detail[:512], 'source_locator': locator,
                    'next_action': 'Review frame and gap evidence; inspect bytes only when complete.'})
            output = run / 'jobs' / f"{job['id']}.packet-streams.json"
            _write_json(output, summaries)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                warnings.append('TCP stream evidence identity incomplete before budget ended')
            status = ('skipped prerequisite' if any('TShark unavailable' in note for note in warnings) else
                      'truncated' if warnings or any(not row['complete'] for row in records) else
                      'ran' if records else 'no finding')
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            status = 'failed'
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"TCP stream job failed: {type(error).__name__}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'NET03' in manifest['coverage']:
        previous = manifest['coverage']['NET03']['status']
        manifest['coverage']['NET03']['status'] = (
            'failed' if status == 'failed' else 'truncated' if status == 'truncated' or previous == 'truncated'
            else 'ran' if status == 'ran' or previous == 'ran' else status)
        manifest['coverage']['NET03']['note'] = 'bounded SYN-to-FIN TCP directions with frame, sequence and gap evidence'
    return children


def _osint_ids_job(run, manifest, artifact, deadline):
    path = Path(artifact['path'])
    fingerprint = manifest['current_adapter_fingerprints']['osint-ids'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:osint-ids.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = output.is_file() and not output.is_symlink() and (
                _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        status = old.get('coverage_status', 'no finding')
        for row in manifest['intelligence']:
            if row.get('job_id') == old['id'] and row['tag'] == 'OSINT clue':
                row['superseded'] = False
        manifest['warnings'].extend(old.get('warnings', []))
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'osint-ids',
               'input_ids': [artifact['id']], 'operation': 'bounded offline text clue extraction',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'input_bytes': 1024 * 1024, 'records': 128, 'cpu_seconds': 6},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for row in manifest['intelligence']:
            if row['artifact_id'] == artifact['id'] and row['tag'] == 'OSINT clue':
                row['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        try:
            records, warnings = _run_osint_ids(path, 1024 * 1024, 128,
                                                min(10, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('OSINT clue source changed before publication')
            output = run / 'jobs' / f"{job['id']}.osint-ids.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                warnings.append('OSINT clue output identity incomplete before work budget ended')
            for record in records:
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'OSINT clue', 'group': record['kind'], 'value': record['value'],
                    'ambiguity': record['ambiguity'],
                    'source_locator': {'byte_offset': record['byte_offset'],
                                       'byte_length': record['byte_length'],
                                       'encoding': record['encoding']},
                    'next_action': (record['ambiguity'] + '; corroborate this source-linked pattern.')})
            status = 'truncated' if warnings else 'ran' if records else 'no finding'
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            status = 'failed'
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"OSINT clue job failed: {job['warning']}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    coverage = manifest['coverage'].get('OS02')
    if coverage:
        previous = coverage['status']
        coverage['status'] = ('failed' if status == 'failed' else
                              'truncated' if status == 'truncated' or previous == 'truncated' else
                              'ran' if status == 'ran' or previous == 'ran' else status)
        coverage['note'] = 'bounded offline URL, email, handle and coordinate patterns; all are unverified clues'


def _os_artifact_job(run, manifest, artifact, deadline):
    path = Path(artifact['path'])
    companions = (manifest.get('sqlite_companions', {}).get(artifact['id'])
                  if artifact['kind_evidence'] == 'sqlite' else None)
    if companions == 'incomplete':
        manifest['warnings'].append(f"{artifact['id']}: browser companion identity incomplete")
        return
    fingerprint = _os_artifact_fingerprint()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:{companions}:"
                          f"os-artifact.v1:{fingerprint}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and
                job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        warnings = old.get('warnings', [])
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'os-artifact',
               'input_ids': [artifact['id']], 'operation': 'bounded read-only OS artifact records',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'sqlite_companions': companions},
               'cwd': str(run), 'limits': {'records': 100, 'source_bytes': 64 * 1024 * 1024,
                                          'output_bytes': 2 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] == 'OS artifact':
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        warnings = []
        status = 'no finding'
        try:
            records, warnings = _run_os_artifact(
                path, 100, 64 * 1024 * 1024,
                min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('OS artifact changed before record publication')
            if artifact['kind_evidence'] == 'sqlite':
                _, after = _sqlite_companions(path, deadline)
                if after != companions:
                    raise RuntimeError('browser companions changed before record publication')
            while records and len(json.dumps(records, ensure_ascii=False).encode()) > 2 * 1024 * 1024:
                records.pop()
                if 'OS artifact output byte limit reached' not in warnings:
                    warnings.append('OS artifact output byte limit reached')
            output = run / 'jobs' / f"{job['id']}.os-artifacts.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                warnings.append('OS artifact record identity incomplete before work budget ended')
            for record in records[:100]:
                if record['kind'] == 'browser_visit':
                    detail = record.get('url') or 'URL row missing'
                elif record['kind'] == 'evtx_event':
                    detail = f"event {record.get('event_id')} provider {record.get('provider')}"
                else:
                    detail = str(record.get('values', []))
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'OS artifact', 'group': record['kind'],
                    'value': f"{record['locator']} @ {record.get('timestamp')}: {detail}"[:512],
                    'source_locator': {'record': record['locator'],
                                       'time': record.get('timestamp'),
                                       'time_basis': record.get('timestamp_basis')},
                    'next_action': 'Inspect the source-linked record before inferring an event sequence.'})
            status = ('skipped prerequisite' if any('unavailable' in note or 'unsupported' in note
                                                   for note in warnings) and not records else
                      'truncated' if warnings else 'ran' if records else 'no finding')
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"OS artifact job failed: {type(error).__name__}")
            status = 'failed'
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DF03' in manifest['coverage']:
        previous = manifest['coverage']['DF03']['status']
        manifest['coverage']['DF03']['status'] = (
            'failed' if status == 'failed' else 'truncated' if status == 'truncated' or previous == 'truncated'
            else 'ran' if status == 'ran' or previous == 'ran' else status)
        manifest['coverage']['DF03']['note'] = (
            'bounded Chromium visits, registry keys and optional EVTX metadata; original time basis retained')


def _web_source_name(artifact):
    names = [Path(artifact['path']).name]
    locator = artifact.get('source_locator') or {}
    names.extend(locator.get(key) for key in ('archive_member', 'filename', 'object_name',
                                              'attachment_name', 'member', 'name'))
    for name in names:
        if isinstance(name, str) and Path(name).suffix.lower() in ('.html', '.htm', '.js', '.mjs',
                                                                    '.cjs', '.map'):
            return name[-256:]
    return None


def _web_static_job(run, manifest, artifact, origin, deadline):
    from .profiles import web_static
    path = Path(artifact['path'])
    source_name = _web_source_name(artifact) or path.name
    fingerprint = hashlib.sha256(Path(web_static.__file__).read_bytes()).hexdigest()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:web-static.v1:"
                          f"{fingerprint}:{origin}:{source_name}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and
                job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = (output.is_file() and not output.is_symlink() and
                     _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        for item in manifest['intelligence']:
            if item.get('job_id') == old['id']:
                item['superseded'] = False
        warnings = old.get('warnings', [])
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'web-static',
               'input_ids': [artifact['id']], 'operation': 'offline HTML/JS/source-map inventory',
               'tool_fingerprint': fingerprint,
               'data_fingerprints': {'scope_origin': origin, 'source_name': source_name},
               'cwd': str(run), 'limits': {'source_bytes': 1024 * 1024, 'records': 256,
                                          'output_bytes': 2 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] == 'WEB01 static':
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        warnings = []
        status = 'no finding'
        try:
            records, warnings = _run_web_static(path, origin, source_name,
                                                min(4, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('web source changed before inventory publication')
            while records and len(json.dumps(records).encode()) > 2 * 1024 * 1024:
                records.pop()
                if 'web output byte limit reached' not in warnings:
                    warnings.append('web output byte limit reached')
            output = run / 'jobs' / f"{job['id']}.web-static.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                raise RuntimeError('web inventory identity incomplete before work budget ended')
            for record in records:
                locator = {'offset': record['offset'], 'line': record['line'],
                           'column': record['column'], 'record': record['locator'],
                           'scope': record.get('scope')}
                for field in ('embedded_source', 'embedded_offset', 'embedded_line'):
                    if field in record:
                        locator[field] = record[field]
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'WEB01 static', 'group': record['kind'],
                    'value': f"{record['locator']}: {record['value']}"[:512],
                    'source_locator': locator,
                    'next_action': 'Review the source and origin before any manual request.'})
            status = ('truncated' if warnings else 'ran' if records else 'no finding')
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"web static job failed: {type(error).__name__}")
            status = 'failed'
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    coverage = manifest['coverage'].get('WEB01')
    if coverage:
        previous = coverage['status']
        coverage['status'] = ('failed' if status == 'failed' else
                              'truncated' if status == 'truncated' or previous == 'truncated' else
                              'ran' if status == 'ran' or previous == 'ran' else status)
        coverage['note'] = 'offline source-linked HTML/JS/source-map inventory; URLs are evidence only'


def _jwt_job(run, manifest, artifact, keys, words, hint_hash, deadline):
    path = Path(artifact['path'])
    fingerprint = _jwt_fingerprint()
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:jwt.v1:"
                          f"{fingerprint}:{hint_hash}".encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and
                job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = output.is_file() and not output.is_symlink() and _hash(output, deadline) == old.get('records_sha256')
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        for item in manifest['intelligence']:
            if item.get('job_id') == old['id']:
                item['superseded'] = False
        warnings = old.get('warnings', [])
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'jwt',
               'input_ids': [artifact['id']], 'operation': 'offline JWT/JWS structure and local signature check',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'jwt_hints': hint_hash},
               'cwd': str(run), 'limits': {'source_bytes': 1024 * 1024, 'tokens': 64,
                                          'output_bytes': 2 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] == 'WEB04 JWT':
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        status, warnings = 'no finding', []
        try:
            importlib.import_module('.profiles.jwt', __package__)
            records, warnings = _run_jwt(path, keys, words, min(4, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('JWT source changed before inspection publication')
            while records and len(json.dumps(records).encode()) > 2 * 1024 * 1024:
                records.pop()
                if 'JWT output byte limit reached' not in warnings:
                    warnings.append('JWT output byte limit reached')
            output = run / 'jobs' / f"{job['id']}.jwt.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                raise RuntimeError('JWT record identity incomplete before work budget ended')
            for row in records:
                relation = ('signature locally verified' if row['signature_verified'] else
                            'signature not verified against supplied material')
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': 'WEB04 JWT', 'group': row['algorithm'] if isinstance(row['algorithm'], str) else 'unknown',
                    'value': (f"byte {row['offset']}: {relation}; claims untrusted; "
                              'server acceptance unknown'),
                    'source_locator': {'offset': row['offset'], 'token_sha256': row['token_sha256']},
                    'next_action': 'Inspect the private JWT record and validate server behavior separately.'})
            status = ('truncated' if any('limit reached' in warning for warning in warnings)
                      else 'ran' if records else 'no finding')
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            if (isinstance(error, ModuleNotFoundError) and error.name and
                    (error.name == 'cryptography' or error.name.startswith('cryptography.'))):
                job['status'] = status = 'skipped prerequisite'
                job['warning'] = 'cryptography unavailable'
                manifest['warnings'].append('WEB04 skipped prerequisite: cryptography unavailable')
            else:
                job['status'] = 'failed'
                job['warning'] = f'{type(error).__name__}: {error}'
                manifest['warnings'].append(f"JWT job failed: {type(error).__name__}")
                status = 'failed'
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    coverage = manifest['coverage'].get('WEB04')
    if coverage:
        previous = coverage['status']
        coverage['status'] = ('failed' if status == 'failed' else
                              'skipped prerequisite' if status == 'skipped prerequisite' else
                              'truncated' if status == 'truncated' or previous == 'truncated' else
                              'ran' if status == 'ran' or previous == 'ran' else status)
        coverage['note'] = ('cryptography required for offline JWT/JWS inspection'
                            if coverage['status'] == 'skipped prerequisite' else
                            'offline JWT/JWS only; claims are untrusted and local signatures do not prove server acceptance')


def _osint_snapshot_job(run, manifest, deadline):
    root = Path(manifest['input_path'])
    suffixes = {'.html', '.htm', '.js', '.mjs', '.cjs', '.map', '.pdf', '.txt', '.md',
                '.eml', '.json', '.xml', '.csv'}
    sources = []
    for artifact in manifest['artifacts']:
        if not artifact['current'] or not artifact['complete'] or artifact['sha256'] is None:
            continue
        if artifact['depth'] == 0:
            path = Path(artifact['path'])
            name = path.relative_to(root).as_posix() if root.is_dir() else path.name
        else:
            locator = artifact.get('source_locator') or {}
            name = next((locator[key] for key in ('archive_member', 'filename', 'attachment_name',
                                                  'member', 'name') if isinstance(locator.get(key), str)
                         and locator[key]), None)
        if name and Path(name).suffix.lower() in suffixes:
            sources.append({'artifact_id': artifact['id'], 'source_name': name,
                            'path': Path(artifact['path']), 'sha256': artifact['sha256']})
    if not any(Path(source['source_name']).suffix.lower() in ('.html', '.htm', '.js', '.mjs',
                                                               '.cjs', '.map') for source in sources):
        return
    sources.sort(key=lambda source: (source['source_name'], source['artifact_id']))
    if len(sources) > 64:
        manifest['warnings'].append('OSINT snapshot source count limit reached')
        sources = sources[:64]
    dependencies = []
    fingerprints = manifest['current_adapter_fingerprints']
    for source in sources:
        for adapter, field in (('web-static', 'web_records'), ('osint-ids', 'identifier_records')):
            job = next((item for item in reversed(manifest['jobs'])
                        if item['adapter_id'] == adapter and item['status'] == 'complete'
                        and item['input_ids'] == [source['artifact_id']]
                        and (adapter != 'web-static' or
                             item.get('data_fingerprints', {}).get('scope_origin') ==
                             manifest.get('web_scope_origin'))
                        and item['tool_fingerprint'] in fingerprints[adapter]), None)
            if job is None:
                continue
            output = Path(job.get('records_path', ''))
            try:
                if (output.is_file() and not output.is_symlink() and
                        _hash(output, deadline) == job.get('records_sha256')):
                    source[field] = json.loads(output.read_text())
                    dependencies.append((source['artifact_id'], adapter, job['key'],
                                         job['records_sha256']))
            except (OSError, ValueError):
                continue
    fingerprint = fingerprints['osint-snapshots'][0]
    identities = [(source['artifact_id'], source['sha256'], source['source_name']) for source in sources]
    key = hashlib.sha256(json.dumps([fingerprint, identities, dependencies,
                                     manifest.get('web_scope_origin')],
                                    sort_keys=True).encode()).hexdigest()
    old = next((job for job in manifest['jobs'] if job['key'] == key and
                job['status'] == 'complete'), None)
    if old:
        output = Path(old.get('records_path', ''))
        try:
            valid = output.is_file() and not output.is_symlink() and (
                _hash(output, deadline) == old.get('records_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        job = old
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(old.get('warnings', []))
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'osint-snapshots',
               'input_ids': [source['artifact_id'] for source in sources],
               'operation': 'offline supplied website and document trail',
               'tool_fingerprint': fingerprint,
               'data_fingerprints': {'dependencies': dependencies,
                                     'scope_origin': manifest.get('web_scope_origin')},
               'cwd': str(run), 'limits': {'sources': 64, 'source_bytes': 8 * 1024 * 1024,
                                          'records': 512, 'output_bytes': 2 * 1024 * 1024},
               'status': 'running', 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        try:
            records, warnings = _run_snapshot(sources, min(8, max(.01, deadline - time.monotonic())))
            if any(_hash(source['path'], deadline) != source['sha256'] for source in sources):
                raise RuntimeError('OSINT snapshot source changed before publication')
            while records and len(json.dumps(records).encode()) > 2 * 1024 * 1024:
                records.pop()
                if 'OSINT snapshot output byte limit reached' not in warnings:
                    warnings.append('OSINT snapshot output byte limit reached')
            output = run / 'jobs' / f"{job['id']}.osint-snapshots.json"
            _write_json(output, records)
            job['records_path'] = str(output)
            job['records_sha256'] = _hash(output, deadline)
            if job['records_sha256'] is None:
                raise RuntimeError('OSINT snapshot record identity incomplete')
            for record in records:
                manifest['intelligence'].append({
                    'artifact_id': record['source_artifact_id'], 'job_id': job['id'],
                    'current': True, 'tag': 'OS03 trail', 'group': record['kind'],
                    'value': f"{record['source_name']} byte {record['source_offset']}: "
                             f"{record['value']}"[:512],
                    'source_locator': {'byte_offset': record['source_offset'],
                                       'byte_length': record['source_length'],
                                       'line': record['source_line'], 'relation': record['relation'],
                                       'target_artifact_id': record.get('target_artifact_id'),
                                       'claims': record.get('claims')},
                    'next_action': record['ambiguity']})
            status = 'truncated' if warnings else 'ran' if records else 'no finding'
            job['record_count'] = len(records)
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            status = 'failed'
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"OSINT snapshot job failed: {job['warning']}")
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    for item in manifest['intelligence']:
        if item['tag'] == 'OS03 trail':
            item['superseded'] = item['job_id'] != job['id']
    coverage = manifest['coverage'].get('OS03')
    if coverage:
        coverage['status'] = status
        coverage['note'] = 'offline source-linked snapshot and dated document clues; relations are inferred'


def _sqlite_job(run, manifest, artifact, deadline, queue, depth):
    import sqlite3
    from .profiles.sqlite import inspect_sqlite
    path = Path(artifact['path'])
    companions, companion_hash = _sqlite_companions(path, deadline)
    manifest.setdefault('sqlite_companions', {})[artifact['id']] = companion_hash
    if 'incomplete' in companions.values():
        manifest['warnings'].append(f"{artifact['id']}: SQLite companion hash incomplete")
        return
    module_hash = hashlib.sha256(Path(inspect_sqlite.__code__.co_filename).read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(f'{module_hash}:{sqlite3.sqlite_version}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:{companion_hash}:sqlite.v1:{fingerprint}".encode()).hexdigest()
    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old and reusable is None:
        old['status'] = 'invalidated'
    if reusable is not None:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        warnings = old.get('warnings', [])
        count = len(reusable)
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'sqlite',
               'input_ids': [artifact['id']], 'operation': 'read-only SQLite snapshot and rows',
               'tool_fingerprint': fingerprint, 'data_fingerprints': companions, 'cwd': str(run),
               'limits': {'rows': 100, 'input_and_output_bytes': 64 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        warnings = []
        try:
            records, warnings = _run_sqlite(path, staging, 100,
                                            min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                                            min(30, max(.01, deadline - time.monotonic())))
            if _hash(path, deadline) != artifact['sha256']:
                raise RuntimeError('SQLite database changed before output publication')
            _, after_hash = _sqlite_companions(path, deadline)
            if after_hash != companion_hash:
                raise RuntimeError('SQLite companions changed before output publication')
            for record in records:
                locator = {'sqlite_locator': record['locator'], 'sqlite_kind': record['kind'],
                           'table': record.get('source_table'), 'rowid': record.get('rowid'),
                           'sqlite_companion_sha256': companion_hash}
                child = _store_staged(run, manifest, artifact, record, deadline,
                                      locator=locator, operation=f"SQLite {record['locator']}",
                                      producer_key=key)
                if child:
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
            count = len(job['child_ids'])
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            count = 0
            warnings = [f'{type(error).__name__}: {error}']
            job['status'] = 'failed'
            job['warning'] = warnings[0]
            manifest['warnings'].append(f"SQLite job failed: {type(error).__name__}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DF04' in manifest['coverage']:
        manifest['coverage']['DF04']['status'] = ('failed' if not old and job['status'] == 'failed' else
                                                  'truncated' if warnings else 'ran' if count else 'no finding')
        manifest['coverage']['DF04']['note'] = 'bounded copied SQLite schema/rows; WAL basis reported'


def _memory_job(run, manifest, artifact, symbols_dir, symbols_error, targets,
                deadline, queue, depth):
    from .profiles import memory
    if symbols_dir is None:
        manifest['coverage']['DF05']['status'] = 'skipped prerequisite'
        manifest['coverage']['DF05']['note'] = symbols_error
        manifest['warnings'].append(f"{artifact['id']}: {symbols_error}")
        return
    fingerprint = manifest['current_adapter_fingerprints']['memory'][0]
    symbol_hash = manifest['memory_symbols_sha256']
    target_hash = manifest['memory_targets_sha256']
    key = hashlib.sha256(
        f"{artifact['id']}:{artifact['sha256']}:memory.v1:{symbol_hash}:{target_hash}:{fingerprint}".encode()
    ).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and
                item['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old:
        inventory = Path(old.get('inventory_path', ''))
        try:
            valid = (reusable is not None and inventory.is_file() and not inventory.is_symlink()
                     and _hash(inventory, deadline) == old.get('inventory_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        warnings = old.get('warnings', [])
        status = old.get('coverage_status', 'no finding')
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'memory',
               'input_ids': [artifact['id']],
               'operation': 'offline Windows memory info, process, command and file triage',
               'tool_fingerprint': fingerprint,
               'data_fingerprints': {'memory_symbols': symbol_hash,
                                     'memory_targets': target_hash},
               'cwd': str(run), 'limits': {'seconds': 30, 'output_bytes_per_plugin': 1024 * 1024,
                                          'dump_files': 8, 'dump_bytes': 16 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'] == 'memory row':
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        warnings, status = [], 'no finding'
        try:
            records, warnings = _run_memory(
                Path(artifact['path']), staging, symbols_dir, targets,
                1024 * 1024, 8,
                min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                min(30, max(.01, deadline - time.monotonic())))
            if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
                raise RuntimeError('memory image changed before output publication')
            _, after_symbols, symbol_error = _memory_symbol_identity(
                {'memory_symbol_dir': str(symbols_dir)}, None, deadline)
            if symbol_error or after_symbols != symbol_hash:
                raise RuntimeError('memory symbols changed before output publication')
            current_module = hashlib.sha256(Path(memory.__file__).read_bytes()).hexdigest()
            try:
                current_vol = _hash(Path(memory.VOL), deadline)
            except OSError:
                current_vol = None
            if hashlib.sha256(f'{current_module}:{current_vol}'.encode()).hexdigest() != fingerprint:
                raise RuntimeError('Volatility executable or profile changed before publication')
            inventory = run / 'jobs' / f"{job['id']}.memory.json"
            _write_json(inventory, [{field: value for field, value in row.items()
                                     if field != 'path'} for row in records])
            job['inventory_path'] = str(inventory)
            job['inventory_sha256'] = _hash(inventory, deadline)
            if job['inventory_sha256'] is None:
                raise RuntimeError('memory inventory identity incomplete before budget ended')
            plugin_rows = {}
            for record in records:
                if record['kind'] == 'row':
                    plugin_rows.setdefault(record['plugin'], deque()).append(record)
            report_rows = set()
            while plugin_rows and len(report_rows) < 100:
                for plugin in tuple(plugin_rows):
                    record = plugin_rows[plugin].popleft()
                    report_rows.add(id(record))
                    if not plugin_rows[plugin]:
                        del plugin_rows[plugin]
                    if len(report_rows) == 100:
                        break
            rows = 0
            for record in records:
                if record['kind'] == 'file':
                    locator = {'memory_target': record['locator'],
                               'symbol_identity': record['symbol_identity'],
                               'cache': record['dump_row'].get('Cache'),
                               'file_object': record['dump_row'].get('FileObject')}
                    child = _store_staged(run, manifest, artifact, record, deadline,
                                          locator=locator,
                                          operation=f"memory dump {record['locator']['offset']}",
                                          producer_key=key)
                    if child:
                        job['child_ids'].append(child['id'])
                        queue.append((child, depth + 1))
                    else:
                        warnings.append('memory dump publication limit reached')
                elif record['kind'] == 'row':
                    rows += 1
                    if id(record) in report_rows:
                        manifest['intelligence'].append({
                            'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                            'tag': 'memory row', 'group': record['plugin'],
                            'value': json.dumps(record['row'], ensure_ascii=False)[:512],
                            'source_locator': {'memory_locator': record['locator'],
                                               'symbol_identity': record['symbol_identity']},
                            'next_action': 'Inspect the preserved raw plugin output and exact row locator.'})
            prerequisite = any(row['kind'] == 'plugin_output' and
                               row['plugin'] == 'windows.info' and
                               row['status'] == 'skipped' and
                               ('matching' in row.get('reason', '') or
                                'unavailable' in row.get('reason', '')) for row in records)
            status = ('skipped prerequisite' if prerequisite else 'truncated' if warnings or
                      any(row['kind'] == 'plugin_output' and row['status'] != 'complete'
                          for row in records) else 'ran' if rows else 'no finding')
            job['row_count'] = rows
            job['warnings'] = warnings[:100]
            job['coverage_status'] = status
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            status = 'failed'
            job['status'] = 'failed'
            job['warning'] = f'{type(error).__name__}: {error}'
            manifest['warnings'].append(f"memory job failed: {type(error).__name__}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    manifest['coverage']['DF05']['status'] = status
    manifest['coverage']['DF05']['note'] = (
        'offline Volatility 3 raw outputs and source-linked rows; exact filescan-gated dumps; '
        'network triage not attempted')


def _disk_job(run, manifest, artifact, targets, deadline, queue, depth):
    fingerprint = manifest['current_adapter_fingerprints']['disk'][0]
    target_hash = manifest['disk_target_paths_sha256']
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:disk.v1:{target_hash}:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and item['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old:
        inventory = Path(old.get('inventory_path', ''))
        try:
            valid = (reusable is not None and inventory.is_file() and not inventory.is_symlink()
                     and _hash(inventory, deadline) == old.get('inventory_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        warnings = old.get('warnings', [])
        partitions = old['partition_count']
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'disk',
               'input_ids': [artifact['id']], 'operation': 'read-only partition and allocated file inventory',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {'disk_target_paths': target_hash},
               'cwd': str(run), 'limits': {'output_bytes_per_tool': 2 * 1024 * 1024,
                                          'files': 8, 'extracted_bytes': 16 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'].startswith('disk '):
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        warnings = []
        partitions = 0
        try:
            records, warnings = _run_disk(Path(artifact['path']), staging, targets,
                                          2 * 1024 * 1024, 8,
                                          min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                                          min(30, max(.01, deadline - time.monotonic())))
            if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
                raise RuntimeError('disk image changed before output publication')
            summary = [{key: value for key, value in record.items() if key != 'path'}
                       for record in records]
            inventory = run / 'jobs' / f"{job['id']}.disk.json"
            _write_json(inventory, summary)
            inventory_hash = _hash(inventory, deadline)
            if inventory_hash is None:
                raise RuntimeError('disk inventory identity incomplete before budget ended')
            job['inventory_path'] = str(inventory)
            job['inventory_sha256'] = inventory_hash
            entries = 0
            for record in records:
                locator = {'disk_partition': record['slot'],
                           'disk_offset_sectors': record['offset_sectors'],
                           'disk_locator': record['locator']}
                if record['kind'] == 'partition':
                    partitions += 1
                    value = f"{record['description']}; sector {record['offset_sectors']}; " \
                            f"length {record['length_sectors']}; sector bytes {record['sector_size']}"
                    tag = 'disk volume' if record['slot'] == 'raw' else 'disk partition'
                elif record['kind'] == 'entry':
                    entries += 1
                    if entries > 40:
                        continue
                    locator.update({'disk_inode': record['inode'], 'disk_path': record['file_path']})
                    value = record['file_path']
                    tag = 'disk entry'
                else:
                    locator.update({'disk_inode': record['inode'], 'disk_path': record['file_path']})
                    child = _store_staged(run, manifest, artifact, record, deadline,
                                          locator=locator, operation=f"disk file {record['locator']}",
                                          producer_key=key)
                    if child:
                        job['child_ids'].append(child['id'])
                        queue.append((child, depth + 1))
                    continue
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': tag, 'group': record['slot'], 'value': value[:512],
                    'source_locator': locator,
                    'next_action': 'Select an allocated path in disk_target_paths for exact extraction.'})
            job['partition_count'] = partitions
            job['entry_count'] = entries
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            warnings = [f'{type(error).__name__}: {error}']
            job['status'] = 'failed'
            job['warning'] = warnings[0]
            manifest['warnings'].append(f"disk job failed: {type(error).__name__}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DF01' in manifest['coverage']:
        manifest['coverage']['DF01']['status'] = ('failed' if not old and job['status'] == 'failed' else
                                                  'truncated' if warnings else 'ran' if partitions else 'no finding')
        manifest['coverage']['DF01']['note'] = 'read-only partition and allocated-file inventory; exact targeted extraction'


def _disk_recovery_job(run, manifest, artifact, deadline, queue, depth):
    fingerprint = manifest['current_adapter_fingerprints']['disk-recovery'][0]
    key = hashlib.sha256(f"{artifact['id']}:{artifact['sha256']}:disk-recovery.v1:{fingerprint}".encode()).hexdigest()
    old = next((item for item in manifest['jobs'] if item['key'] == key and item['status'] == 'complete'), None)
    reusable = _reusable_children(manifest, old, deadline) if old else None
    if old:
        inventory = Path(old.get('inventory_path', ''))
        try:
            valid = (reusable is not None and inventory.is_file() and not inventory.is_symlink()
                     and _hash(inventory, deadline) == old.get('inventory_sha256'))
        except OSError:
            valid = False
        if not valid:
            old['status'] = 'invalidated'
            old = None
    if old:
        for child in reusable:
            _attach_reused_child(child, old, artifact)
            queue.append((child, depth + 1))
        warnings = old.get('warnings', [])
        entries = old['entry_count']
        count = old['recovered_count']
        manifest['warnings'].extend(warnings)
    else:
        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'disk-recovery',
               'input_ids': [artifact['id']], 'operation': 'read-only deleted metadata and verified carving',
               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
               'limits': {'source_bytes': 256 * 1024 * 1024,
                          'output_bytes_per_tool': 2 * 1024 * 1024,
                          'files': 8, 'recovered_bytes': 16 * 1024 * 1024},
               'status': 'running', 'child_ids': [], 'started': time.time()}
        manifest['jobs'].append(job)
        for item in manifest['intelligence']:
            if item['artifact_id'] == artifact['id'] and item['tag'].startswith('disk deleted'):
                item['superseded'] = True
        _write_json(run / 'manifest.json', manifest)
        staging = run / 'staging' / job['id']
        warnings = []
        entries = count = 0
        try:
            rows, warnings = _run_disk_recovery(
                Path(artifact['path']), staging, 2 * 1024 * 1024, 8,
                min(16 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                min(30, max(.01, deadline - time.monotonic())))
            if _hash(Path(artifact['path']), deadline) != artifact['sha256']:
                raise RuntimeError('disk image changed before recovery publication')
            summary = [{field: value for field, value in row.items() if field != 'path'}
                       for row in rows]
            inventory = run / 'jobs' / f"{job['id']}.disk-recovery.json"
            _write_json(inventory, summary)
            inventory_hash = _hash(inventory, deadline)
            if inventory_hash is None:
                raise RuntimeError('disk recovery inventory identity incomplete before budget ended')
            job['inventory_path'] = str(inventory)
            job['inventory_sha256'] = inventory_hash
            for row in rows:
                if row['kind'] == 'deleted_entry':
                    entries += 1
                    if entries <= 40:
                        manifest['intelligence'].append({
                            'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                            'tag': 'disk deleted entry', 'group': row['slot'],
                            'value': row['file_path'][:512],
                            'source_locator': {'disk_partition': row['slot'],
                                               'disk_offset_sectors': row['offset_sectors'],
                                               'disk_inode': row['inode'], 'disk_path': row['file_path'],
                                               'disk_locator': row['locator'],
                                               'uncertainty': row['uncertainty']},
                            'next_action': 'Compare recovered bytes with an independent checksum or copy.'})
                    continue
                if row['kind'] == 'deleted_file':
                    locator = {'disk_partition': row['slot'],
                               'disk_offset_sectors': row['offset_sectors'],
                               'disk_inode': row['inode'], 'disk_path': row['file_path'],
                               'disk_locator': row['locator'],
                               'recovery_state': 'uncertain_deleted_content',
                               'uncertainty': row['uncertainty']}
                    operation = f"disk recovered {row['locator']}"
                else:
                    locator = {'disk_carve_offset_bytes': row['offset_bytes'],
                               'disk_carve_format': row['format'],
                               'disk_verification': row['verification'],
                               'disk_locator': row['locator'],
                               'uncertainty': row['uncertainty']}
                    operation = f"disk carve {row['locator']}"
                child = _store_staged(run, manifest, artifact, row, deadline,
                                      locator=locator, operation=operation, producer_key=key)
                if child:
                    count += 1
                    job['child_ids'].append(child['id'])
                    queue.append((child, depth + 1))
            job['entry_count'] = entries
            job['recovered_count'] = count
            job['warnings'] = warnings[:100]
            job['status'] = 'complete'
            manifest['warnings'].extend(warnings[:100])
        except Exception as error:
            warnings = [f'{type(error).__name__}: {error}']
            job['status'] = 'failed'
            job['warning'] = warnings[0]
            manifest['warnings'].append(f"disk recovery job failed: {type(error).__name__}")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DF02' in manifest['coverage']:
        manifest['coverage']['DF02']['status'] = ('failed' if not old and job['status'] == 'failed' else
                                                  'truncated' if warnings else 'ran' if entries or count else 'no finding')
        manifest['coverage']['DF02']['note'] = 'deleted inode bytes uncertain; PNG/ZIP carves structurally verified'


def _reusable_children(manifest, job, deadline):
    children = []
    for child_id in job['child_ids']:
        child = next((a for a in manifest['artifacts'] if a['id'] == child_id), None)
        if child is None or not child['complete']:
            return None
        if job.get('input_ids') and not any(
                edge.get('job_key') == job['key'] and edge['id'] in job['input_ids']
                for edge in child['parents']):
            return None
        path = Path(child['path'])
        try:
            valid = not path.is_symlink() and path.is_file() and _hash(path, deadline) == child['sha256']
        except OSError:
            valid = False
        if not valid:
            for item in manifest['artifacts']:
                if item['path'] == child['path']:
                    item['complete'] = False
                    item['current'] = False
            manifest['warnings'].append(f"stored artifact {child_id} changed; affected job will rerun")
            return None
        children.append(child)
    return children


def _attach_reused_child(child, job, parent):
    original_edges = [edge for edge in child['parents']
                      if edge.get('job_key') == job['key'] and edge['id'] in job['input_ids']]
    if not original_edges:
        raise RuntimeError('reused child lacks producer operation')
    for original in original_edges:
        edge = {'id': parent['id'], 'operation': original['operation'], 'job_key': job['key'],
                'source_locator': _edge_locator(child, original)}
        if edge not in child['parents']:
            child['parents'].append(edge)
    child['current'] = True
    return sorted({edge['operation'] for edge in original_edges})


def _office_fingerprint():
    from importlib import metadata
    source = Path(__file__).parent / 'profiles' / 'office.py'
    packages = []
    for name in ('oletools', 'olefile'):
        try:
            packages.append(metadata.version(name))
        except metadata.PackageNotFoundError:
            packages.append('unavailable')
    return hashlib.sha256((hashlib.sha256(source.read_bytes()).hexdigest() +
                           ':' + ':'.join(packages)).encode()).hexdigest()


def _cryptography_fingerprint(profile):
    from importlib import metadata
    source = Path(__file__).parent / 'profiles' / f'{profile}.py'
    try:
        version = metadata.version('cryptography')
    except metadata.PackageNotFoundError:
        version = 'unavailable'
    return hashlib.sha256((hashlib.sha256(source.read_bytes()).hexdigest() +
                           ':cryptography=' + version).encode()).hexdigest()


def _jwt_fingerprint():
    package = _cryptography_fingerprint('jwt')
    try:
        importlib.import_module('.profiles.jwt', __package__)
        runtime = 'ready'
    except Exception as error:
        runtime = f'{type(error).__name__}:{getattr(error, "name", "")}'
    return hashlib.sha256(f'{package}:{runtime}'.encode()).hexdigest()


def _qr_fingerprint():
    from importlib import metadata
    from .profiles import qr
    parts = [hashlib.sha256(Path(qr.__file__).read_bytes()).hexdigest()]
    for module, package in (('zxingcpp', 'zxing-cpp'), ('pyzbar', 'pyzbar'), ('PIL', 'Pillow')):
        spec = importlib.util.find_spec(module)
        parts.append(hashlib.sha256(Path(spec.origin).read_bytes()).hexdigest() if spec and spec.origin else 'unavailable')
        if module == 'zxingcpp' and spec and spec.origin:
            parts.extend(hashlib.sha256(binary.read_bytes()).hexdigest()
                         for binary in sorted(Path(spec.origin).parent.glob('zxingcpp*.so')))
        try:
            parts.append(metadata.version(package))
        except metadata.PackageNotFoundError:
            parts.append('unavailable')
    return hashlib.sha256(':'.join(parts).encode()).hexdigest()


def _elf_fingerprint():
    from importlib import metadata
    source = Path(__file__).parent / 'profiles' / 'elf.py'
    try:
        version = metadata.version('pyelftools')
    except metadata.PackageNotFoundError:
        version = 'unavailable'
    return hashlib.sha256(f'{hashlib.sha256(source.read_bytes()).hexdigest()}:{version}'.encode()).hexdigest()


def _binary_fingerprint():
    from importlib import metadata
    sources = (Path(__file__).parent / 'profiles' / name for name in ('binary_static.py', 'elf.py'))
    versions = []
    for package in ('pyelftools', 'pefile'):
        try:
            versions.append(metadata.version(package))
        except metadata.PackageNotFoundError:
            versions.append('unavailable')
    payload = ':'.join([*(hashlib.sha256(source.read_bytes()).hexdigest() for source in sources),
                        *versions])
    return hashlib.sha256(payload.encode()).hexdigest()


def _rev_strings_fingerprint(deadline):
    from importlib import metadata
    import subprocess
    profiles = Path(__file__).parent / 'profiles'
    parts = [hashlib.sha256((profiles / name).read_bytes()).hexdigest()
             for name in ('rev_strings.py', 'xor.py')]
    for package in ('pyelftools', 'capstone', 'flare-floss'):
        try:
            parts.append(metadata.version(package))
        except metadata.PackageNotFoundError:
            parts.append('unavailable')
    executable = shutil.which('floss')
    if executable:
        parts.extend((executable, _hash(Path(executable), deadline) or 'unhashed'))
        try:
            version = subprocess.run([executable, '--version'], capture_output=True,
                                     timeout=2, check=False)
            parts.append(hashlib.sha256(version.stdout + version.stderr).hexdigest())
        except (OSError, subprocess.TimeoutExpired):
            parts.append('version-unavailable')
    else:
        parts.append('floss-unavailable')
    return hashlib.sha256(':'.join(parts).encode()).hexdigest()


def _rev_rules_fingerprint(deadline):
    from .profiles.rev_rules import _run
    source = Path(__file__).parent / 'profiles' / 'rev_rules.py'
    parts = [hashlib.sha256(source.read_bytes()).hexdigest()]
    for name, option in (('capa', '--version'), ('yara', '-v')):
        executable = shutil.which(name)
        if not executable:
            parts.append(f'{name}-unavailable')
            continue
        version, error = _run([executable, option], 2, 4096)
        parts.extend((executable, _hash(Path(executable), deadline) or 'unhashed',
                      hashlib.sha256(version).hexdigest() if version is not None else str(error)))
    return hashlib.sha256(':'.join(parts).encode()).hexdigest()


def _rev_rule_inputs(hints, hints_path):
    from .profiles.rev_rules import _identity
    paths, identities = {}, {}
    for key, suffixes in (('capa_rules', ('.yml', '.yaml')),
                          ('capa_signatures', ('.pat', '.pat.gz', '.sig')),
                          ('yara_rules', ())):
        if key not in hints:
            continue
        path = Path(hints[key])
        if not path.is_absolute():
            path = Path(hints_path).absolute().parent / path
        paths[key] = path.absolute()
        try:
            identities[key] = _identity(paths[key], suffixes)
        except (OSError, ValueError):
            identities[key] = {'path': str(paths[key]), 'unavailable': True}
    return paths, hashlib.sha256(json.dumps(identities, sort_keys=True).encode()).hexdigest()


def _os_artifact_fingerprint():
    from importlib import metadata
    import sqlite3
    source = Path(__file__).parent / 'profiles' / 'os_artifacts.py'
    parsers = []
    for package in ('python-registry', 'python-evtx'):
        try:
            parsers.append(metadata.version(package))
        except metadata.PackageNotFoundError:
            parsers.append('unavailable')
    return hashlib.sha256(f'{hashlib.sha256(source.read_bytes()).hexdigest()}:'
                          f'{sqlite3.sqlite_version}:{parsers}'.encode()).hexdigest()


def _memory_symbol_identity(hints, hints_path, deadline):
    supplied = hints.get('memory_symbol_dir')
    if not supplied:
        return None, None, 'memory symbol directory not supplied'
    directory = Path(supplied)
    if not directory.is_absolute():
        directory = Path(hints_path).absolute().parent / directory
    if directory.is_symlink() or not directory.is_dir():
        return None, None, 'memory symbol directory unavailable or unsafe'
    rows = []
    total = 0
    directory_count = 0
    walk_errors = []
    for base, dirs, files in os.walk(directory, followlinks=False, onerror=walk_errors.append):
        directory_count += 1
        if directory_count > 2048 or time.monotonic() >= deadline:
            return None, None, 'memory symbol identity incomplete before budget ended'
        if any((Path(base) / name).is_symlink() for name in dirs + files):
            return None, None, 'memory symbol directory contains a symlink'
        for name in sorted(files):
            path = Path(base) / name
            try:
                info = path.stat(follow_symlinks=False)
            except OSError:
                return None, None, 'memory symbol directory changed during inventory'
            if not stat.S_ISREG(info.st_mode):
                return None, None, 'memory symbol directory contains a non-file'
            total += info.st_size
            if len(rows) >= 512 or total > 512 * 1024 * 1024:
                return None, None, 'memory symbol identity exceeds 512 files or 512 MiB'
            try:
                digest = _hash(path, deadline)
                after = path.stat()
            except OSError:
                return None, None, 'memory symbol directory changed during hashing'
            if digest is None or (after.st_size, after.st_mtime_ns) != (
                    info.st_size, info.st_mtime_ns):
                return None, None, 'memory symbol identity incomplete before budget ended'
            rows.append((str(path.relative_to(directory)), digest))
    if walk_errors:
        return None, None, 'memory symbol directory unreadable during inventory'
    if not rows:
        return None, None, 'memory symbol directory is empty'
    identity = hashlib.sha256(json.dumps(
        [str(directory.resolve()), sorted(rows)], ensure_ascii=False).encode()).hexdigest()
    return directory, identity, None


def _current_adapter_fingerprints(deadline):
    import sqlite3
    from .profiles import disk, disk_recovery, image_metadata, media, memory, packet_objects, packet_streams, packet_tls, packets, sstv, stegseek, tones, zsteg
    profiles = Path(__file__).parent / 'profiles'

    def module_hash(name):
        return hashlib.sha256((profiles / f'{name}.py').read_bytes()).hexdigest()

    def executable_hash(path):
        if path is None:
            return None
        try:
            return _hash(Path(path), deadline)
        except OSError:
            return None

    image_hash = module_hash('image_metadata')
    exif_hash = executable_hash(image_metadata._EXIFTOOL)
    packet_hash = module_hash('packets')
    tshark_hash = executable_hash(packets.TSHARK)
    packet_object_hash = module_hash('packet_objects')
    packet_stream_hash = module_hash('packet_streams')
    packet_tls_hash = module_hash('packet_tls')
    sqlite_hash = module_hash('sqlite')
    disk_hash = module_hash('disk')
    disk_tools = [executable_hash(tool) for tool in (disk.MMLS, disk.FLS, disk.ICAT)]
    recovery_hash = module_hash('disk_recovery')
    binwalk_hash = executable_hash(disk_recovery.BINWALK)
    memory_hash = module_hash('memory')
    vol_hash = executable_hash(memory.VOL)
    zsteg_hash = module_hash('zsteg')
    zsteg_tool_hash = executable_hash(shutil.which(zsteg.ZSTEG) or zsteg.ZSTEG)
    stegseek_hash = module_hash('stegseek')
    stegseek_tool_hash = executable_hash(shutil.which(stegseek.STEGSEEK) or stegseek.STEGSEEK)
    media_hash = module_hash('media')
    ffprobe_hash = executable_hash(shutil.which(media.FFPROBE) or media.FFPROBE)
    ffmpeg_hash = executable_hash(shutil.which(media.FFMPEG) or media.FFMPEG)
    tones_hash = module_hash('tones')
    multimon_hash = executable_hash(shutil.which(tones.MULTIMON) or tones.MULTIMON)
    sstv_hash = module_hash('sstv')
    sstv_tool_hash = executable_hash(shutil.which(sstv.SSTV) or sstv.SSTV)
    packers_hash = module_hash('rev_packers')
    upx = shutil.which('upx')
    packers_binwalk = shutil.which('binwalk')
    upx_hash = executable_hash(Path(upx).resolve() if upx else None)
    packers_binwalk_hash = executable_hash(Path(packers_binwalk).resolve()
                                           if packers_binwalk else None)
    java_hash = module_hash('java_android')
    javap = shutil.which('javap')
    java = shutil.which('java')
    javap_hash = executable_hash(Path(javap).resolve() if javap else None)
    java_runtime_hash = executable_hash(Path(java).resolve() if java else None)
    sevenzip = shutil.which('7z') or shutil.which('7zz')
    sevenzip_hash = executable_hash(Path(sevenzip).resolve() if sevenzip else None)
    try:
        from importlib.metadata import PackageNotFoundError, version
        angr_version = version('angr')
    except (ImportError, PackageNotFoundError):
        angr_version = None
    return {
        'encoding': [module_hash('encoding')],
        'xor-one': [module_hash('xor')],
        'xor-search': [module_hash('xor')],
        'rsa-literals': [_cryptography_fingerprint('rsa')],
        'aes-declared': [_cryptography_fingerprint('symmetric')],
        'password-hashes': [module_hash('passwords')],
        'zip': [module_hash('documents')],
        '7z': [hashlib.sha256(f"{module_hash('sevenzip')}:{sevenzip_hash}".encode()).hexdigest()],
        'tar': [module_hash('tar')],
        'mime': [module_hash('mime')],
        'pdf': [module_hash('pdf')],
        'office': [_office_fingerprint()],
        'png-tail': [module_hash('images')],
        'image-tail': [module_hash('images')],
        'zsteg': [hashlib.sha256(f'{zsteg_hash}:{zsteg_tool_hash}'.encode()).hexdigest()],
        'stegseek': [hashlib.sha256(f'{stegseek_hash}:{stegseek_tool_hash}'.encode()).hexdigest()],
        'media': [hashlib.sha256(f'{media_hash}:{ffprobe_hash}:{ffmpeg_hash}'.encode()).hexdigest()],
        'tones': [hashlib.sha256(f'{tones_hash}:{multimon_hash}:{ffmpeg_hash}'.encode()).hexdigest()],
        'sstv': [hashlib.sha256(f'{sstv_hash}:{sstv_tool_hash}:{ffmpeg_hash}'.encode()).hexdigest()],
        'qr': [_qr_fingerprint()],
        'can-log': [module_hash('canlog')],
        'can-dbc': [_can_dbc_fingerprint()],
        'sqlite': [hashlib.sha256(f'{sqlite_hash}:{sqlite3.sqlite_version}'.encode()).hexdigest()],
        'os-artifact': [_os_artifact_fingerprint()],
        'web-static': [module_hash('web_static')],
        'jwt': [_jwt_fingerprint()],
        'osint-snapshots': [hashlib.sha256(':'.join(module_hash(name) for name in
                            ('osint_snapshots', 'web_static', 'osint_ids')).encode()).hexdigest()],
        'disk': [hashlib.sha256(f'{disk_hash}:{disk_tools}'.encode()).hexdigest()],
        'disk-recovery': [hashlib.sha256(
            f'{recovery_hash}:{disk_hash}:{disk_tools}:{binwalk_hash}'.encode()).hexdigest()],
        'memory': [hashlib.sha256(f'{memory_hash}:{vol_hash}'.encode()).hexdigest()],
        'packets': [hashlib.sha256(f'{packet_hash}:{tshark_hash}'.encode()).hexdigest()],
        'packet-objects': [hashlib.sha256(
            f'{packet_object_hash}:{packet_stream_hash}:{executable_hash(packet_objects.TSHARK)}'.encode()).hexdigest()],
        'packet-streams': [hashlib.sha256(
            f'{packet_stream_hash}:{executable_hash(packet_streams.TSHARK)}'.encode()).hexdigest()],
        'packet-tls': [hashlib.sha256(
            f'{packet_tls_hash}:{packet_object_hash}:{executable_hash(packet_tls.TSHARK)}'.encode()).hexdigest()],
        'elf': [_elf_fingerprint()],
        'binary-static': [_binary_fingerprint()],
        'rev-strings': [_rev_strings_fingerprint(deadline)],
        'rev-powershell': [module_hash('powershell')],
        'rev-rules': [_rev_rules_fingerprint(deadline)],
        'rev-packers': [hashlib.sha256(
            f'{packers_hash}:{upx_hash}:{packers_binwalk_hash}'.encode()).hexdigest()],
        'pyinstaller': [module_hash('pyinstaller')],
        'java-android': [hashlib.sha256(
            f'{java_hash}:{javap_hash}:{java_runtime_hash}'.encode()).hexdigest()],
        'checker': [hashlib.sha256(
            f"{module_hash('checker')}:{angr_version}".encode()).hexdigest()],
        'osint-ids': [module_hash('osint_ids')],
        'image-metadata': [hashlib.sha256(f'{image_hash}:{exif_hash}:views={mode}'.encode()).hexdigest()
                           for mode in (False, True)],
    }


def _scan_artifact(manifest, artifact, deadline, patterns, data=None, *, private_crib=b''):
    if time.monotonic() >= deadline:
        manifest['warnings'].append(f"{artifact['id']}: candidate scan not scheduled before budget ended")
        return
    path = Path(artifact['path'])
    try:
        if data is None and path.stat().st_size <= MAX_READ:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact['sha256']:
                manifest['warnings'].append(f"{artifact['id']}: bytes changed before candidate scan")
                return
        findings, warnings = scan_candidates(data if data is not None else path,
                                             artifact['id'], patterns, deadline,
                                             private_crib=private_crib)
        if data is None and _hash(path, deadline) != artifact['sha256']:
            manifest['warnings'].append(f"{artifact['id']}: bytes changed during candidate scan")
            return
    except OSError as error:
        manifest['warnings'].append(f"{artifact['id']}: candidate scan failed: {type(error).__name__}")
        return
    for finding in findings:
        finding['current'] = artifact['current']
        finding['pattern_sha256'] = manifest['candidate_pattern_sha256']
    manifest['findings'] = [finding for finding in manifest['findings']
                            if finding['artifact_id'] != artifact['id']
                            or finding['operation'] not in ('user pattern', 'printable text')]
    manifest['findings'].extend(findings)
    manifest['warnings'].extend(warnings)


def _render_report(run, manifest):
    lines = ['# Autosolve run', '', f"Status: {manifest['status']}",
             f"Run: `{run}`", '', '## Candidates', '']
    current_findings = [f for f in manifest['findings']
                        if f.get('current', True) and f['state'] in
                        ('candidate', 'validated_transform', 'validated_input', 'challenge_accepted')]
    if current_findings:
        for finding in current_findings[:50]:
            lines.append(f"- {finding['state']}: {finding['evidence']} "
                         f"({finding['artifact_id'] or finding.get('job_id')}, "
                         f"locator {json.dumps(finding['source_locator'], ensure_ascii=True)})")
    else:
        lines.append('No candidate found in the sampled bytes. This does not establish that the challenge is solved.')
    lines += ['', '## Actionable intelligence', '']
    for item in manifest['artifacts']:
        if item['current']:
            locator = (item.get('current_source_locators', item['source_locator'])
                       if item['depth'] > 0 else item['source_locator'])
            lines.append(f"- {item['kind_evidence']}: {json.dumps(item['path'])}; {item['size']} bytes; "
                         f"SHA-256 {item['sha256'] or 'incomplete'}; "
                         f"locator {json.dumps(locator, ensure_ascii=True)}")
    for item in manifest.get('intelligence', []):
        if item['current']:
            source = item.get('source_locator') or {}
            coordinates = ('byte_offset', 'byte_length', 'line', 'file_offset',
                           'raw_size', 'static_vaddr', 'symbol_file_offset',
                           'iat_file_offset', 'entry_file_offset', 'entry_static_vaddr')
            locator = {key: source[key] for key in coordinates
                       if isinstance(source.get(key), int) and not isinstance(source[key], bool)}
            if isinstance(source.get('exif_tag'), str):
                locator['exif_tag'] = source['exif_tag'][:64]
            if item['tag'] == 'OS03 trail' and item['group'] == 'date_conflict':
                dates = sorted({claim['date'] for claim in source.get('claims') or []
                                if isinstance(claim, dict) and
                                isinstance(claim.get('date'), str) and
                                re.fullmatch(r'\d{4}-\d{2}-\d{2}', claim['date'])})[:4]
                if dates:
                    locator['claim_dates'] = dates
            lines.append(f"- {json.dumps(item['tag'], ensure_ascii=True)} "
                         f"({json.dumps(item['group'], ensure_ascii=True)}): "
                         f"{json.dumps(item['value'], ensure_ascii=True)} "
                         f"from artifact {item['artifact_id']}" +
                         (f"; locator {json.dumps(locator, ensure_ascii=True)}" if locator else '') +
                         (f"; interpretation: {json.dumps(item['interpretation'][:256], ensure_ascii=True)}"
                          if isinstance(item.get('interpretation'), str) else ''))
    for warning in manifest['warnings']:
        lines.append(f'- Limit or prerequisite: {warning}')
    historical = sum(not f.get('current', True) for f in manifest['findings'])
    if historical:
        lines.append(f'- {historical} earlier candidate(s) belong to changed inputs; retained in findings.json.')
    lines += ['', '## Family coverage', '', '| Family | Status | Note |', '| --- | --- | --- |']
    for family, entry in manifest['coverage'].items():
        lines.append(f"| {family} | {entry['status']} | {entry['note']} |")
    _write_text(run / 'report.md', '\n'.join(lines) + '\n')


def _powershell_source(artifact):
    if artifact['kind_evidence'] not in ('text', 'binary'):
        return False
    path = Path(artifact['path'])
    if path.suffix.lower() in ('.ps1', '.psm1', '.psd1'):
        return True
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            head = stream.read(4096)
        if head.startswith(b'\xff\xfe'):
            text = head[2:].decode('utf-16le', 'ignore').lower()
        else:
            text = head.decode('utf-8', 'ignore').lower()
    except OSError:
        return False
    return '-encodedcommand' in text or 'frombase64string' in text


def _execute(run, manifest, budget, hints, hint_hash, hints_path, replay_checker=False):
    from .profiles.encoding import decode
    from .profiles.xor import recover_repeating_key, recover_single_byte
    from .profiles.documents import extract_zip
    from .profiles.sevenzip import extract_7z
    from .profiles.images import extract_image_tail
    from .profiles.mime import parse_mime
    from .profiles.pdf import extract_pdf
    deadline = time.monotonic() + budget
    passwords, password_hash = _passwords(hints, hints_path)
    hash_words, hash_wordlist_hash = _hash_wordlist(hints, hints_path)
    hash_records, hash_params_hash = _hash_parameters(hints)
    rsa_parameters, rsa_hash = _rsa_parameters(hints, hints_path)
    symmetric_parameters, symmetric_hash = _symmetric_parameters(hints)
    jwt_keys, jwt_words, jwt_hint_hash = _jwt_hints(hints, hints_path)
    manifest.setdefault('history_warnings', []).extend(manifest['warnings'])
    manifest.setdefault('intelligence', [])
    manifest['warnings'] = []
    _upgrade_lineage(manifest)
    manifest['coverage'] = _coverage(manifest['category'])
    if manifest['execute_local'] and 'checker' not in hints:
        manifest['warnings'].append('local execution requested but no execution adapter is implemented')
    manifest['budget_seconds'] = budget
    manifest['hint_sha256'] = hint_hash
    manifest['password_file_sha256'] = password_hash
    manifest['hash_wordlist_sha256'] = hash_wordlist_hash
    manifest['hash_parameters_sha256'] = hash_params_hash
    manifest['candidate_pattern_sha256'] = hashlib.sha256(
        json.dumps(hints.get('flag_patterns', []), ensure_ascii=False).encode()).hexdigest()
    crib = hints.get('known_plaintext', '').encode('utf-8')
    manifest['xor_crib_sha256'] = hashlib.sha256(crib).hexdigest() if crib else None
    xor_no_candidate_note = (
        f'no candidate matched supplied literal crib ({len(crib)} bytes; '
        f'key length up to {min(16, max(0, len(crib) - 5))} bytes) '
        'or printable English-frequency thresholds'
        if crib else 'no candidate met printable English-frequency thresholds')
    manifest['web_scope_origin'] = hints.get('scope_origin')
    manifest['jwt_hints_sha256'] = jwt_hint_hash
    manifest['rsa_parameters_sha256'] = rsa_hash
    manifest['symmetric_parameters_sha256'] = symmetric_hash
    manifest['checker_hints_sha256'] = (hashlib.sha256(
        json.dumps(hints['checker'], sort_keys=True).encode()).hexdigest()
        if 'checker' in hints else None)
    rule_paths, rule_identity = (_rev_rule_inputs(hints, hints_path)
                                 if manifest['category'] in ('auto', 'malware_reversing')
                                 else ({}, None))
    manifest['rev_rules_identity'] = rule_identity
    tls_keylog = None
    tls_keylog_hash = None
    if 'tls_keylog' in hints:
        tls_keylog = Path(hints['tls_keylog'])
        if not tls_keylog.is_absolute():
            tls_keylog = Path(hints_path).absolute().parent / tls_keylog
        try:
            info = tls_keylog.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise OSError('TLS key log unavailable or exceeds 1 MiB')
            tls_keylog_hash = _hash(tls_keylog, deadline)
            if tls_keylog_hash is None:
                raise OSError('TLS key log identity incomplete')
        except OSError:
            tls_keylog = None
            manifest['warnings'].append('supplied TLS key log unavailable, unsafe, or exceeds 1 MiB')
    manifest['tls_keylog_sha256'] = tls_keylog_hash
    dbc_path = None
    dbc_hash = None
    if 'dbc' in hints:
        dbc_path = Path(hints['dbc'])
        if not dbc_path.is_absolute():
            dbc_path = Path(hints_path).absolute().parent / dbc_path
        try:
            dbc_hash = _hash(dbc_path, deadline)
        except OSError:
            manifest['warnings'].append('supplied CAN database is unavailable or unsafe')
    manifest['dbc_sha256'] = dbc_hash
    manifest['disk_target_paths_sha256'] = hashlib.sha256(
        json.dumps(hints.get('disk_target_paths', []), ensure_ascii=False).encode()).hexdigest()
    manifest['memory_targets_sha256'] = hashlib.sha256(
        json.dumps(hints.get('memory_dump_targets', []), sort_keys=True,
                   ensure_ascii=False).encode()).hexdigest()
    memory_symbols_dir, memory_symbols_hash, memory_symbols_error = (
        _memory_symbol_identity(hints, hints_path, deadline)
        if 'memory_symbol_dir' in hints and manifest['category'] in ('auto', 'disk_memory')
        else (None, None, 'memory symbol directory not supplied'))
    manifest['memory_symbols_sha256'] = memory_symbols_hash
    manifest['current_adapter_fingerprints'] = _current_adapter_fingerprints(deadline)
    manifest['status'] = 'running'
    _write_json(run / 'manifest.json', manifest)
    active = []
    for path in _sources(manifest['input_path'], allow_empty=True, exclude=run.parent,
                         excluded_files=manifest['private_hint_paths'],
                         excluded_identities=manifest['private_hint_identities']):
        previous = next((a for a in reversed(manifest['artifacts'])
                         if a['depth'] == 0 and a['path'] == str(path) and a['current']), None)
        source = _source_record(path, deadline)
        if previous and previous['sha256'] == source['sha256'] and source['complete']:
            active.append(previous)
            continue
        if previous:
            previous['current'] = False
            _event(run, 'input_changed', old_id=previous['id'], path=str(path))
        manifest['artifacts'].append(source)
        active.append(source)
        _event(run, 'source', id=source['id'], sha256=source['sha256'])
        _write_json(run / 'manifest.json', manifest)
    manifest['sqlite_companions'] = {}
    for source in active:
        if source['kind_evidence'] == 'sqlite':
            try:
                _, companion_digest = _sqlite_companions(Path(source['path']), deadline)
                manifest['sqlite_companions'][source['id']] = companion_digest
            except OSError:
                manifest['warnings'].append(f"{source['id']}: SQLite companion identity unavailable")
    def memory_source(item):
        path = Path(item['path'])
        return (item['depth'] == 0 and
                ((hints.get('memory_image') is True and
                  Path(manifest['input_path']).is_file()) or
                 (item['kind_evidence'] == 'binary' and
                  path.suffix.lower() in ('.vmem', '.dmp', '.mem'))))

    manifest['memory_routed_input_ids'] = [item['id'] for item in active if memory_source(item)]
    _refresh_current(manifest, {artifact['id'] for artifact in active})
    if not active:
        manifest['warnings'].append('no regular source files remain in the selected directory')
    def routed_domain(item):
        if manifest['category'] != 'auto':
            return manifest['category']
        if memory_source(item):
            return 'disk_memory'
        if _web_source_name(item):
            return 'web'
        if _powershell_source(item):
            return 'malware_reversing'
        return {'sqlite': 'disk_memory', 'disk_image': 'disk_memory',
                'registry': 'disk_memory', 'evtx': 'disk_memory',
                'can_log': 'can_misc', 'elf': 'pwn_services', 'pe': 'malware_reversing',
                'pcap': 'packets', 'pcapng': 'packets',
                'riff': 'audio_video', 'flac': 'audio_video', 'ogg': 'audio_video',
                'mp4': 'audio_video', 'matroska': 'audio_video', 'mp3': 'audio_video',
                'png': 'images', 'bmp': 'images', 'jpeg': 'images', 'gif': 'images', 'tiff': 'images',
                'zip': 'documents', '7z': 'documents', 'dex': 'malware_reversing',
                'tar': 'documents', 'mime': 'documents', 'pdf': 'documents',
                'office': 'documents'}.get(
                    item['kind_evidence'], 'encoding')

    if manifest['category'] == 'auto':
        groups = {}
        for item in active:
            groups.setdefault(routed_domain(item), []).append(item)
        order = ('disk_memory', 'can_misc', 'pwn_services', 'malware_reversing',
                 'encoding', 'images', 'documents', 'audio_video', 'packets', 'web')
        first = [groups[domain][0] for domain in order if domain in groups]
        first.extend(groups[domain][0] for domain in groups if domain not in order)
        remainder = [item for group in groups.values() for item in group[1:]]
        queue = deque((item, 0) for item in first + remainder)
        remaining_first_domains = set(groups)
    else:
        queue = deque((item, 0) for item in active)
        remaining_first_domains = set()
    overall_deadline = deadline
    seen = {}
    encoding_selected = manifest['category'] in ('auto', 'encoding')
    hint_jobs_pending = encoding_selected
    images_selected = manifest['category'] in ('auto', 'images')
    metadata_selected = manifest['category'] in ('auto', 'images', 'osint')
    osint_selected = manifest['category'] in ('auto', 'osint')
    can_selected = manifest['category'] in ('auto', 'can_misc')
    packets_selected = manifest['category'] in ('auto', 'packets')
    disk_selected = manifest['category'] in ('auto', 'disk_memory')
    pwn_selected = manifest['category'] in ('auto', 'pwn_services')
    reversing_selected = manifest['category'] in ('auto', 'malware_reversing')
    media_selected = manifest['category'] in ('auto', 'audio_video')
    web_selected = manifest['category'] in ('auto', 'web', 'osint')
    while (queue or (hint_jobs_pending and not remaining_first_domains)) and time.monotonic() < overall_deadline:
        if hint_jobs_pending and not remaining_first_domains:
            _rsa_job(run, manifest, rsa_parameters, rsa_hash, overall_deadline)
            _hash_job(run, manifest, hash_records, hash_params_hash,
                      hash_words, hash_wordlist_hash, overall_deadline)
            queue.extend((child, child['depth']) for child in
                         _symmetric_job(run, manifest, symmetric_parameters,
                                        symmetric_hash, overall_deadline))
            hint_jobs_pending = False
            continue
        artifact, depth = queue.popleft()
        documents_selected = (manifest['category'] in ('auto', 'documents', 'osint') or
                              manifest['category'] == 'packets' and depth > 0)
        domain = routed_domain(artifact)
        if depth == 0 and domain in remaining_first_domains:
            now = time.monotonic()
            deadline = min(overall_deadline, now + max(.001,
                           (overall_deadline - now) / len(remaining_first_domains)))
            remaining_first_domains.remove(domain)
        else:
            deadline = overall_deadline
        if not artifact['complete'] or depth >= MAX_DEPTH:
            continue
        path = Path(artifact['path'])
        if (manifest['category'] in ('auto', 'web') and artifact['kind_evidence'] == 'text'
                and time.monotonic() < deadline):
            _jwt_job(run, manifest, artifact, jwt_keys, jwt_words, jwt_hint_hash, deadline)
        if images_selected and artifact['kind_evidence'] in ('jpeg', 'bmp', 'riff') and time.monotonic() < deadline:
            for child in _stegseek_job(run, manifest, artifact, deadline, passwords, password_hash):
                queue.append((child, depth + 1))
        if artifact['kind_evidence'] == 'png' and (
                (artifact.get('source_locator') or {}).get('media_preview') or
                (artifact.get('source_locator') or {}).get('sstv_preview')):
            for child in _qr_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            if (metadata_selected or (artifact.get('source_locator') or {}).get('sstv_preview')) and time.monotonic() < deadline:
                _image_metadata_job(run, manifest, artifact, deadline, make_views=False)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if images_selected and artifact['kind_evidence'] in ('png', 'jpeg'):
            image_kind = artifact['kind_evidence']
            fingerprint = hashlib.sha256(Path(extract_image_tail.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:{image_kind}-tail.v2:{fingerprint}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        _attach_reused_child(child, old, artifact)
                        queue.append((child, depth + 1))
                    if 'IMG01' in manifest['coverage']:
                        manifest['coverage']['IMG01']['status'] = 'ran' if reusable else 'no finding'
                        manifest['coverage']['IMG01']['note'] = 'ZIP structure and clear-member CRC checked in PNG/JPEG'
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'image-tail',
                           'input_ids': [artifact['id']], 'operation': f'checked {image_kind.upper()} trailing ZIP',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {},
                           'cwd': str(run), 'limits': {'output_bytes': MAX_CHILD},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    try:
                        result = _run_image(path, min(MAX_CHILD, MAX_DERIVED - manifest['derived_bytes']),
                                            min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('image changed before tail publication')
                        if result:
                            data, evidence = result
                            child = _store_child(run, manifest, artifact, data,
                                                 f"{image_kind.upper()} tail at byte {evidence['offset']}", deadline,
                                                 source_locator={'image_offset': evidence['offset'],
                                                                 **({'iend_offset': evidence['iend_offset'],
                                                                     'gap_bytes': evidence['gap_bytes'],
                                                                     'padding_bytes': evidence['padding_bytes']}
                                                                    if image_kind == 'png' else
                                                                    {'eoi_offset': evidence['eoi_offset'],
                                                                     'padding_bytes': evidence['padding_bytes'],
                                                                     'gap_bytes': evidence['gap_bytes']})},
                                                 force_record=True, producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        job['status'] = 'complete'
                        if 'IMG01' in manifest['coverage']:
                            manifest['coverage']['IMG01']['status'] = 'ran' if job['child_ids'] else 'no finding'
                            manifest['coverage']['IMG01']['note'] = 'ZIP structure and clear-member CRC checked in PNG/JPEG'
                    except WorkLimit as error:
                        job['status'] = 'truncated'
                        job['warning'] = str(error)
                        manifest['warnings'].append(str(error))
                        if 'IMG01' in manifest['coverage']:
                            manifest['coverage']['IMG01']['status'] = 'truncated'
                            manifest['coverage']['IMG01']['note'] = f'{image_kind.upper()} trailing ZIP exceeds output bound'
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"image tail job failed: {type(error).__name__}")
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            if images_selected and time.monotonic() < deadline:
                for child in _qr_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if image_kind == 'png' and images_selected and time.monotonic() < deadline:
                for child in _zsteg_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if metadata_selected and time.monotonic() < deadline:
                _image_metadata_job(run, manifest, artifact, deadline, make_views=True)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if images_selected and artifact['kind_evidence'] == 'bmp':
            if time.monotonic() < deadline:
                for child in _qr_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            for child in _zsteg_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            if time.monotonic() < deadline:
                _image_metadata_job(run, manifest, artifact, deadline, make_views=True)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if metadata_selected and artifact['kind_evidence'] in ('png', 'jpeg', 'gif', 'tiff'):
            if images_selected and time.monotonic() < deadline:
                for child in _qr_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if media_selected and artifact['kind_evidence'] == 'gif' and time.monotonic() < deadline:
                for child in _media_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            _image_metadata_job(run, manifest, artifact, deadline,
                                make_views=manifest['category'] != 'osint')
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if documents_selected and artifact['kind_evidence'] == 'tar':
            for child in _tar_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if reversing_selected and artifact['kind_evidence'] == 'dex':
            _java_android_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if reversing_selected and artifact['kind_evidence'] == 'zip':
            _java_android_job(run, manifest, artifact, deadline, queue, depth)
            if not documents_selected:
                _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
                continue
        if documents_selected and artifact['kind_evidence'] == 'zip':
            if time.monotonic() < deadline:
                for child in _office_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            fingerprint = hashlib.sha256(Path(extract_zip.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:zip.v3:{fingerprint}:{password_hash}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        _attach_reused_child(child, old, artifact)
                        queue.append((child, depth + 1))
                    manifest['warnings'].extend(old.get('warnings', []))
                    _doc01_coverage(manifest, old.get('coverage_status',
                                                     'ran' if reusable else 'no finding'))
                    if 'DOC02' in manifest['coverage']:
                        manifest['coverage']['DOC02']['status'] = (
                            'skipped prerequisite' if old.get('encrypted_unresolved') else
                            'ran' if old.get('encrypted_recovered') else 'no finding')
                        manifest['coverage']['DOC02']['note'] = 'supplied ZIP password candidates only'
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'zip',
                           'input_ids': [artifact['id']], 'operation': 'safe ZIP stream extraction',
                           'tool_fingerprint': fingerprint,
                           'data_fingerprints': {'password_file': password_hash}, 'cwd': str(run),
                           'limits': {'members': 100, 'derived_bytes': MAX_DERIVED},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    staging = run / 'staging' / job['id']
                    try:
                        records, warnings = _run_zip(path, staging,
                                                     min(100, MAX_ARTIFACTS - len(manifest['artifacts'])),
                                                     MAX_DERIVED - manifest['derived_bytes'], passwords,
                                                     min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('archive changed before member publication')
                        for record in records:
                            locator = {'archive_member': record['member'],
                                       'member_index': record['index'],
                                       'encrypted': record['encrypted']}
                            if record['encrypted']:
                                locator['password_file_sha256'] = password_hash
                            child = _store_staged(run, manifest, artifact, record, deadline,
                                                  locator=locator, producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        manifest['warnings'].extend(warnings[:100])
                        job['warnings'] = warnings[:100]
                        job['status'] = 'complete'
                        job['coverage_status'] = 'truncated' if warnings else 'ran' if records else 'no finding'
                        _doc01_coverage(manifest, job['coverage_status'])
                        if 'DOC02' in manifest['coverage']:
                            encrypted = any(record['encrypted'] for record in records)
                            unresolved = any('password' in warning for warning in warnings)
                            job['encrypted_recovered'] = encrypted
                            job['encrypted_unresolved'] = unresolved
                            manifest['coverage']['DOC02']['status'] = ('skipped prerequisite' if unresolved else
                                'ran' if encrypted
                                else 'no finding')
                            manifest['coverage']['DOC02']['note'] = 'supplied ZIP password candidates only'
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"ZIP job failed: {type(error).__name__}")
                        _doc01_coverage(manifest, 'failed')
                    finally:
                        shutil.rmtree(staging, ignore_errors=True)
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if documents_selected and artifact['kind_evidence'] == '7z':
            executable = shutil.which('7z') or shutil.which('7zz')
            if not executable:
                manifest['coverage']['DOC02']['status'] = 'skipped prerequisite'
                manifest['coverage']['DOC02']['note'] = '7-Zip executable unavailable'
                manifest['warnings'].append('7z extraction requires 7z or 7zz')
                continue
            fingerprint = manifest['current_adapter_fingerprints']['7z'][0]
            key = hashlib.sha256(f"{artifact['sha256']}:7z.v1:{fingerprint}:{password_hash}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        _attach_reused_child(child, old, artifact)
                        queue.append((child, depth + 1))
                    manifest['warnings'].extend(old.get('warnings', []))
                    _doc01_coverage(manifest, old.get('coverage_status',
                                                     'ran' if reusable else 'no finding'))
                    manifest['coverage']['DOC02']['status'] = (
                        'skipped prerequisite' if old.get('encrypted_unresolved') else
                        'ran' if old.get('encrypted_recovered') else 'no finding')
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': '7z',
                           'input_ids': [artifact['id']], 'operation': 'bounded 7z member streaming',
                           'tool_fingerprint': fingerprint,
                           'data_fingerprints': {'password_file': password_hash}, 'cwd': str(run),
                           'limits': {'members': 100, 'member_bytes': MAX_CHILD,
                                      'derived_bytes': MAX_DERIVED, 'seconds': 30},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    staging = run / 'staging' / job['id']
                    try:
                        records, warnings = _run_sevenzip(
                            path, staging, min(100, MAX_ARTIFACTS - len(manifest['artifacts'])),
                            MAX_DERIVED - manifest['derived_bytes'], passwords, executable,
                            min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('archive changed before member publication')
                        for record in records:
                            locator = {'archive_member': record['member'],
                                       'member_index': record['index'], 'encrypted': record['encrypted']}
                            if record['encrypted']:
                                locator['password_file_sha256'] = password_hash
                            child = _store_staged(run, manifest, artifact, record, deadline,
                                                  locator=locator,
                                                  operation=f"7z member {record['index']}",
                                                  producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        manifest['warnings'].extend(warnings[:100])
                        job['warnings'] = warnings[:100]
                        job['status'] = 'complete'
                        job['coverage_status'] = 'truncated' if warnings else 'ran' if records else 'no finding'
                        _doc01_coverage(manifest, job['coverage_status'])
                        job['encrypted_recovered'] = any(record['encrypted'] for record in records)
                        job['encrypted_unresolved'] = any('password' in warning for warning in warnings)
                        manifest['coverage']['DOC02']['status'] = (
                            'skipped prerequisite' if job['encrypted_unresolved'] else
                            'ran' if job['encrypted_recovered'] else 'no finding')
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"7z job failed: {type(error).__name__}")
                        _doc01_coverage(manifest, 'failed')
                    finally:
                        shutil.rmtree(staging, ignore_errors=True)
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            manifest['coverage']['DOC02']['note'] = 'supplied 7z password candidates only'
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if documents_selected and artifact['kind_evidence'] == 'office':
            for child in _office_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if documents_selected and artifact['kind_evidence'] == 'mime':
            fingerprint = hashlib.sha256(Path(parse_mime.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:mime.v1:{fingerprint}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        _attach_reused_child(child, old, artifact)
                        queue.append((child, depth + 1))
                    manifest['warnings'].extend(old.get('warnings', []))
                    if 'DOC06' in manifest['coverage']:
                        manifest['coverage']['DOC06']['status'] = (
                            'truncated' if old.get('warnings') else 'ran' if reusable else 'no finding')
                        manifest['coverage']['DOC06']['note'] = 'bounded MIME leaf parts only'
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'mime',
                           'input_ids': [artifact['id']], 'operation': 'bounded MIME part extraction',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
                           'limits': {'parts': 100, 'derived_bytes': 64 * 1024 * 1024},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    staging = run / 'staging' / job['id']
                    try:
                        records, warnings = _run_mime(path, staging,
                                                      min(100, MAX_ARTIFACTS - len(manifest['artifacts'])),
                                                      min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                                                      min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('MIME source changed before part publication')
                        for record in records:
                            locator = {'mime_part': record['part_path'], 'part_index': record['index'],
                                       'filename': record['filename'][:256] if record['filename'] else None,
                                       'media_type': record['media_type']}
                            child = _store_staged(run, manifest, artifact, record, deadline,
                                                  locator=locator,
                                                  operation=f"MIME part {record['part_path']}",
                                                  producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        manifest['warnings'].extend(warnings[:100])
                        job['warnings'] = warnings[:100]
                        job['status'] = 'complete'
                        if 'DOC06' in manifest['coverage']:
                            manifest['coverage']['DOC06']['status'] = (
                                'truncated' if warnings else 'ran' if job['child_ids'] else 'no finding')
                            manifest['coverage']['DOC06']['note'] = 'bounded MIME leaf parts only'
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"MIME job failed: {type(error).__name__}")
                    finally:
                        shutil.rmtree(staging, ignore_errors=True)
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if documents_selected and artifact['kind_evidence'] == 'pdf':
            fingerprint = hashlib.sha256(Path(extract_pdf.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:pdf.v1:{fingerprint}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        _attach_reused_child(child, old, artifact)
                        queue.append((child, depth + 1))
                    manifest['warnings'].extend(old.get('warnings', []))
                    if 'DOC04' in manifest['coverage']:
                        manifest['coverage']['DOC04']['status'] = old.get('coverage_status', 'no finding')
                        manifest['coverage']['DOC04']['note'] = 'bounded pypdf text, attachments and streams'
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'pdf',
                           'input_ids': [artifact['id']], 'operation': 'bounded PDF extraction',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
                           'limits': {'pages': 100, 'derived_bytes': 64 * 1024 * 1024},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    staging = run / 'staging' / job['id']
                    try:
                        records, warnings = _run_pdf(path, staging, 100,
                                                     min(64 * 1024 * 1024, MAX_DERIVED - manifest['derived_bytes']),
                                                     min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('PDF source changed before output publication')
                        for record in records:
                            locator = {'pdf_locator': record['locator'], 'pdf_kind': record['kind'],
                                       'object_id': record.get('object_id'),
                                       'attachment_name': record.get('name', '')[:256]}
                            child = _store_staged(run, manifest, artifact, record, deadline,
                                                  locator=locator, operation=f"PDF {record['locator']}",
                                                  producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        status = ('skipped prerequisite' if any('parser unavailable' in note or
                                                                'encrypted PDF' in note for note in warnings) else
                                  'truncated' if warnings else 'ran' if job['child_ids'] else 'no finding')
                        manifest['warnings'].extend(warnings[:100])
                        job['warnings'] = warnings[:100]
                        job['coverage_status'] = status
                        job['status'] = 'complete'
                        if 'DOC04' in manifest['coverage']:
                            manifest['coverage']['DOC04']['status'] = status
                            manifest['coverage']['DOC04']['note'] = 'bounded pypdf text, attachments and streams'
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"PDF job failed: {type(error).__name__}")
                    finally:
                        shutil.rmtree(staging, ignore_errors=True)
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if artifact['kind_evidence'] in ('elf', 'pe') and (pwn_selected or reversing_selected):
            if artifact['kind_evidence'] == 'elf' and pwn_selected:
                _elf_job(run, manifest, artifact, deadline)
            if (reversing_selected and artifact['kind_evidence'] == 'elf' and depth == 0
                    and Path(manifest['input_path']).is_file()):
                if 'checker' in hints:
                    _checker_job(run, manifest, artifact, hints['checker'], replay_checker, deadline)
                else:
                    manifest['coverage']['REV07']['status'] = 'skipped prerequisite'
                    manifest['coverage']['REV07']['note'] = 'selected checker hints are required'
            if reversing_selected and time.monotonic() < deadline:
                _binary_job(run, manifest, artifact, deadline)
            if reversing_selected and time.monotonic() < deadline:
                _pyinstaller_job(run, manifest, artifact, deadline, queue, depth)
            if reversing_selected and time.monotonic() < deadline:
                _rev_strings_job(run, manifest, artifact, deadline, queue, depth)
            if reversing_selected and time.monotonic() < deadline:
                _rev_rules_job(run, manifest, artifact, deadline, rule_paths)
            if reversing_selected and time.monotonic() < deadline:
                _rev_packers_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if (reversing_selected and artifact['kind_evidence'] in ('text', 'binary')
                and (manifest['category'] == 'malware_reversing' and depth == 0 and
                     artifact['kind_evidence'] == 'text' or _powershell_source(artifact))):
            if manifest['category'] == 'malware_reversing' and depth == 0:
                _binary_job(run, manifest, artifact, deadline)
            _rev_powershell_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if (artifact['kind_evidence'] == 'binary' and reversing_selected and
                (manifest['category'] == 'malware_reversing' or domain == 'encoding')):
            if manifest['category'] == 'malware_reversing' and depth == 0:
                _binary_job(run, manifest, artifact, deadline)
            if depth == 0 and time.monotonic() < deadline:
                _pyinstaller_job(run, manifest, artifact, deadline, queue, depth)
            if time.monotonic() < deadline:
                _rev_packers_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if manifest['category'] == 'malware_reversing' and depth == 0:
            _binary_job(run, manifest, artifact, deadline)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if media_selected and (artifact['kind_evidence'] in
                               ('riff', 'flac', 'ogg', 'mp4', 'matroska', 'mp3') or
                               manifest['category'] == 'audio_video' and
                               artifact['kind_evidence'] in ('gif', 'binary')):
            if artifact['kind_evidence'] == 'riff':
                _tones_job(run, manifest, artifact, deadline)
            for child in _sstv_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            for child in _media_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if can_selected and artifact['kind_evidence'] == 'can_log':
            frames = _can_job(run, manifest, artifact, deadline)
            if 'CAN02' in manifest['coverage']:
                if dbc_path is None:
                    manifest['coverage']['CAN02']['status'] = 'skipped prerequisite'
                    manifest['coverage']['CAN02']['note'] = 'supplied DBC/ARXML hint required'
                elif frames:
                    _can_dbc_job(run, manifest, artifact, frames, dbc_path, dbc_hash, deadline)
                else:
                    manifest['coverage']['CAN02']['status'] = 'no finding'
                    manifest['coverage']['CAN02']['note'] = 'no normalized data frames to decode'
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if packets_selected and artifact['kind_evidence'] in ('pcap', 'pcapng'):
            _packets_job(run, manifest, artifact, deadline)
            if time.monotonic() < deadline:
                for child in _packet_objects_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if time.monotonic() < deadline:
                for child in _packet_streams_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if 'NET05' in manifest['coverage']:
                if tls_keylog is None:
                    manifest['coverage']['NET05']['status'] = 'skipped prerequisite'
                    manifest['coverage']['NET05']['note'] = 'supply a regular TLS key log via tls_keylog hint'
                elif time.monotonic() < deadline:
                    for child in _packet_tls_job(run, manifest, artifact, tls_keylog,
                                                 tls_keylog_hash, deadline):
                        queue.append((child, depth + 1))
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if disk_selected and artifact['kind_evidence'] == 'sqlite':
            _os_artifact_job(run, manifest, artifact, deadline)
            if time.monotonic() < deadline:
                _sqlite_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if disk_selected and artifact['kind_evidence'] in ('registry', 'evtx'):
            _os_artifact_job(run, manifest, artifact, deadline)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if disk_selected and memory_source(artifact):
            _memory_job(run, manifest, artifact, memory_symbols_dir, memory_symbols_error,
                        hints.get('memory_dump_targets', []), deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if disk_selected and artifact['kind_evidence'] == 'disk_image':
            _disk_job(run, manifest, artifact, hints.get('disk_target_paths', []), deadline, queue, depth)
            if time.monotonic() < deadline:
                _disk_recovery_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
            continue
        if web_selected and (manifest['category'] == 'web' or domain == 'web' or
                             manifest['category'] == 'osint' and _web_source_name(artifact)):
            _web_static_job(run, manifest, artifact, hints.get('scope_origin'), deadline)
            if manifest['category'] != 'osint':
                _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), private_crib=crib)
                continue
        if (manifest['category'] == 'disk_memory' and depth == 0 and
                artifact['kind_evidence'] not in ('disk_image', 'sqlite', 'registry', 'evtx') and
                manifest['coverage']['DF01']['status'] == 'not scheduled'):
            manifest['coverage']['DF01']['status'] = 'skipped prerequisite'
            manifest['warnings'].append(f"{artifact['id']}: no supported partition image signature")
            if 'DF02' in manifest['coverage']:
                manifest['coverage']['DF02']['status'] = 'skipped prerequisite'
        if (manifest['category'] == 'packets' and depth == 0 and
                artifact['kind_evidence'] not in ('pcap', 'pcapng')):
            manifest['warnings'].append(f"{artifact['id']}: input has no supported PCAP signature")
            if 'NET01' in manifest['coverage']:
                manifest['coverage']['NET01']['status'] = 'skipped prerequisite'
        if manifest['category'] == 'can_misc' and artifact['kind_evidence'] == 'text':
            manifest['warnings'].append(f"{artifact['id']}: text has no supported CAN log framing")
            if 'CAN01' in manifest['coverage']:
                manifest['coverage']['CAN01']['status'] = 'skipped prerequisite'
        if not path.is_file():
            manifest['warnings'].append(f"{artifact['id']}: artifact file is unavailable")
            continue
        doc01_gzip = manifest['category'] in ('auto', 'documents') and artifact['kind_evidence'] == 'gzip'
        decode_selected = encoding_selected or doc01_gzip
        data = None
        if path.stat().st_size <= MAX_READ:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact['sha256']:
                manifest['warnings'].append(f"{artifact['id']}: bytes changed before processing")
                continue
        elif decode_selected and artifact['kind_evidence'] in ('text', 'gzip', 'binary'):
            manifest['warnings'].append(f"{artifact['id']}: decode input limit is 8 MiB")
            if doc01_gzip:
                _doc01_coverage(manifest, 'truncated')
        if osint_selected and artifact['kind_evidence'] in ('text', 'binary') and time.monotonic() < deadline:
            _osint_ids_job(run, manifest, artifact, deadline)
        if data is not None and decode_selected and artifact['kind_evidence'] in ('text', 'gzip', 'binary'):
            fingerprint = hashlib.sha256(Path(decode.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:encoding.v1:{fingerprint}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    reused_operations = []
                    for child in reusable:
                        reused_operations.extend(_attach_reused_child(child, old, artifact))
                        queue.append((child, depth + 1))
                    _mark_encoding_coverage(manifest, reused_operations,
                                            old.get('diagnostics', []), artifact['id'])
                    if doc01_gzip:
                        _doc01_coverage(manifest, 'ran' if any(
                            operation.startswith('gzip') for operation in reused_operations) else 'truncated')
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'encoding',
                           'input_ids': [artifact['id']], 'operation': 'stdlib finite decode',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {},
                           'cwd': str(run), 'limits': {'output_bytes': MAX_CHILD},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    try:
                        results, diagnostics = _run_decode(
                            data, min(MAX_CHILD, MAX_DERIVED - manifest['derived_bytes']),
                            min(30, max(.01, deadline - time.monotonic())))
                        job['diagnostics'] = diagnostics
                        produced = []
                        for decoded, operation in results:
                            bit_block = re.fullmatch(r'bit-text lines:(\d+)-(\d+) bits:(\d+)', operation)
                            locator = None
                            if bit_block:
                                locator = {'transform': 'bit-text', 'line_start': int(bit_block[1]),
                                           'line_end': int(bit_block[2]), 'bit_count': int(bit_block[3])}
                                declared = re.search(rb'(?im)^(?:bits found|bit count|declared bits)\s*:\s*(\d+)\s*$', data)
                                if declared and int(declared[1]) != int(bit_block[3]):
                                    manifest['warnings'].append(
                                        f"{artifact['id']}: declared bit count {int(declared[1])} "
                                        f"differs from decoded {int(bit_block[3])}")
                            compressed = next((item for item in diagnostics
                                               if operation.startswith(item['kind']) and item['members']), None)
                            if compressed:
                                locator = {'transform': compressed['kind'],
                                           'status': compressed['status'],
                                           'members': compressed['members'],
                                           'trailing_bytes': compressed['trailing_bytes']}
                                if 'padding_bytes' in compressed:
                                    locator['padding_bytes'] = compressed['padding_bytes']
                            child = _store_child(run, manifest, artifact, decoded, operation, deadline,
                                                 source_locator=locator, producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                                produced.append(operation)
                        job['status'] = 'complete'
                        _mark_encoding_coverage(manifest, produced, diagnostics, artifact['id'])
                        if doc01_gzip:
                            _doc01_coverage(manifest, 'ran' if any(
                                operation.startswith('gzip') for operation in produced) else 'truncated')
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"encoding job failed: {type(error).__name__}")
                        if doc01_gzip:
                            _doc01_coverage(manifest, 'failed')
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
        if (encoding_selected and (artifact['kind_evidence'] in ('text', 'binary') or
                                   manifest['category'] == 'encoding')
                and 'xor_key_hex' not in artifact['source_locator']):
            if data is None or len(data) > 1024 * 1024:
                manifest['warnings'].append(f"{artifact['id']}: XOR input limit is 1 MiB")
                if 'ENC05' in manifest['coverage'] and manifest['coverage']['ENC05']['status'] != 'ran':
                    manifest['coverage']['ENC05']['status'] = 'truncated'
                    manifest['coverage']['ENC05']['note'] = 'XOR input limit'
            elif len(data) >= 16 or (len(crib) >= 6 and len(data) >= len(crib)):
                fingerprint = hashlib.sha256(Path(recover_single_byte.__code__.co_filename).read_bytes()).hexdigest()
                key = hashlib.sha256(f"{artifact['sha256']}:xor-search.v1:{fingerprint}:8:"
                                     f"{manifest['xor_crib_sha256']}".encode()).hexdigest()
                if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                    seen.setdefault(key, artifact['id'])
                    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                    reusable = _reusable_children(manifest, old, deadline) if old else None
                    if old and reusable is None:
                        old['status'] = 'invalidated'
                    if reusable is not None:
                        for child in reusable:
                            _attach_reused_child(child, old, artifact)
                            queue.append((child, depth + 1))
                        if 'ENC05' in manifest['coverage']:
                            entry = manifest['coverage']['ENC05']
                            if reusable or entry['status'] != 'ran':
                                entry['status'] = 'ran' if reusable else 'no finding'
                                entry['note'] = 'XOR candidates retained' if reusable else xor_no_candidate_note
                    else:
                        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'xor-search',
                               'input_ids': [artifact['id']], 'operation': 'bounded XOR key search',
                               'tool_fingerprint': fingerprint,
                               'data_fingerprints': {'known_plaintext': manifest['xor_crib_sha256']},
                               'cwd': str(run),
                               'limits': {'input_bytes': 1024 * 1024, 'candidates_per_method': 8},
                               'status': 'running', 'child_ids': [], 'started': time.time()}
                        manifest['jobs'].append(job)
                        _write_json(run / 'manifest.json', manifest)
                        try:
                            candidates = _run_xor(data, crib, min(30, max(.01, deadline - time.monotonic())))
                            for candidate in candidates:
                                if candidate['data'] == data:
                                    continue
                                key_hex = candidate['key_hex']
                                repeated = candidate.get('key_length', 1) > 1
                                operation = f"{'repeating-key' if repeated else 'single-byte'} XOR key 0x{key_hex}"
                                locator = {'xor_key_hex': key_hex, 'xor_key_length': len(bytes.fromhex(key_hex))}
                                if 'crib_offset' in candidate:
                                    locator['xor_crib_offset'] = candidate['crib_offset']
                                    locator['xor_crib_key_phase'] = candidate['crib_key_phase']
                                child = _store_child(run, manifest, artifact, candidate['data'], operation,
                                                     deadline, source_locator=locator,
                                                     force_record=True, producer_key=key)
                                if child:
                                    job['child_ids'].append(child['id'])
                                    queue.append((child, depth + 1))
                                    manifest['findings'].append({
                                        'state': 'candidate', 'artifact_id': child['id'], 'current': True,
                                        'source_locator': {'offset': 0, **locator},
                                        'evidence': candidate['rationale'], 'operation': operation,
                                        'next_action': 'Verify the assumed key and recovered bytes against the challenge.'})
                            job['status'] = 'complete'
                            if 'ENC05' in manifest['coverage']:
                                entry = manifest['coverage']['ENC05']
                                if job['child_ids'] or entry['status'] != 'ran':
                                    entry['status'] = 'ran' if job['child_ids'] else 'no finding'
                                    entry['note'] = ('XOR candidates retained' if job['child_ids'] else
                                                     xor_no_candidate_note)
                        except Exception as error:
                            job['status'] = 'failed'
                            job['warning'] = f'{type(error).__name__}: {error}'
                            manifest['warnings'].append(f"XOR job failed: {type(error).__name__}")
                        job['ended'] = time.time()
                        _write_json(run / 'jobs' / f"{job['id']}.json", job)
                        _write_json(run / 'manifest.json', manifest)
            elif ('ENC05' in manifest['coverage'] and
                  manifest['coverage']['ENC05']['status'] == 'not scheduled'):
                manifest['coverage']['ENC05']['status'] = 'skipped prerequisite'
                manifest['coverage']['ENC05']['note'] = (
                    'fewer than 16 bytes; need text-frequency evidence or a six-byte literal crib')
        _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []),
                       data, private_crib=crib)
    if queue or time.monotonic() >= overall_deadline:
        manifest['warnings'].append('overall work budget ended before all artifacts were processed')
    _refresh_current(manifest, {artifact['id'] for artifact in active})
    if osint_selected and time.monotonic() < overall_deadline:
        _osint_snapshot_job(run, manifest, overall_deadline)
        _refresh_current(manifest, {artifact['id'] for artifact in active})
    incomplete = any(a['sha256'] is None for a in active) or bool(manifest['warnings'])
    pending = any(x['status'] not in ('ran', 'no finding') and x['delivery_stage'] == 'baseline'
                  for x in manifest['coverage'].values())
    manifest['status'] = 'partial' if incomplete or pending else 'complete'
    _write_json(run / 'findings.json', manifest['findings'])
    _write_json(run / 'manifest.json', manifest)
    _render_report(run, manifest)
    _event(run, 'checkpoint', status=manifest['status'])
    return manifest['status']


def _locked_execute(run, manifest, budget, hints, hint_hash, hints_path, replay_checker=False):
    if run.is_symlink():
        raise InvalidInput('run directory must not be a symlink')
    run.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = os.open(run / '.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RunBusy(f'run is already active: {run}') from error
        for job in manifest['jobs']:
            if job['status'] == 'running':
                job['status'] = 'interrupted'
        _remember_private_hints(manifest, hints_path, hints)
        _write_json(run / 'manifest.json', manifest)
        return _execute(run, manifest, budget, hints, hint_hash, hints_path, replay_checker)
    finally:
        os.close(lock)


def analyze(path, *, category='auto', budget=300, hints_path=None, runs_root=None,
            execute_local=False, replay_checker=False):
    category = category_name(category)
    if not 0 < budget <= 3600:
        raise InvalidInput('budget must be between 0 and 3600 seconds')
    if replay_checker and not execute_local:
        raise InvalidInput('--replay-checker requires --execute-local')
    root = Path(runs_root) if runs_root else ROOT / '.autosolve' / 'runs'
    if Path(path).absolute().is_dir() and Path(path).absolute() == root.absolute():
        raise InvalidInput('runs root must differ from the analyzed directory')
    hints, hint_hash = load_hints(hints_path)
    if replay_checker and 'checker' not in hints:
        raise InvalidInput('--replay-checker requires checker hints')
    _passwords(hints, hints_path)
    _hash_wordlist(hints, hints_path)
    _sources(path, exclude=root, excluded_files=_private_paths(hints_path, hints))
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    manifest = {'schema_version': SCHEMA, 'input_path': str(Path(path).absolute()),
                'category': category, 'execute_local': bool(execute_local),
                'lineage_schema': 2,
                'created': time.time(), 'status': 'new', 'artifacts': [], 'jobs': [],
                'findings': [], 'intelligence': [], 'coverage': _coverage(category), 'derived_bytes': 0,
                'warnings': []}
    status = _locked_execute(run, manifest, budget, hints, hint_hash, hints_path, replay_checker)
    return run, status


def resume(run_path, *, budget=300, hints_path=None, replay_checker=False):
    run = Path(run_path).absolute()
    if run.is_symlink():
        raise InvalidInput('run directory must not be a symlink')
    try:
        manifest = json.loads((run / 'manifest.json').read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidInput(f'run manifest unreadable: {error}') from error
    if manifest.get('schema_version') != SCHEMA:
        raise InvalidInput('unsupported run schema; preserve this run and export its files manually')
    if manifest.get('hint_sha256') is not None and 'private_hint_paths' not in manifest:
        raise InvalidInput('older run lacks private hint exclusions; start a new analysis run')
    if not 0 < budget <= 3600:
        raise InvalidInput('budget must be between 0 and 3600 seconds')
    if replay_checker and not manifest.get('execute_local'):
        raise InvalidInput('--replay-checker requires a run started with --execute-local')
    hints, hint_hash = load_hints(hints_path)
    if replay_checker and 'checker' not in hints:
        raise InvalidInput('--replay-checker requires checker hints')
    _passwords(hints, hints_path)
    _hash_wordlist(hints, hints_path)
    if hint_hash is None and manifest.get('hint_sha256') is not None:
        raise InvalidInput('resume requires the prior hints file or a replacement')
    status = _locked_execute(run, manifest, budget, hints, hint_hash, hints_path, replay_checker)
    return run, status


def report(run_path):
    run = Path(run_path).absolute()
    if run.is_symlink():
        raise InvalidInput('run directory must not be a symlink')
    try:
        manifest = json.loads((run / 'manifest.json').read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidInput(f'run manifest unreadable: {error}') from error
    if manifest.get('schema_version') != SCHEMA:
        raise InvalidInput('unsupported run schema')
    _render_report(run, manifest)
    return run / 'report.md'


def capabilities(category='auto'):
    category = category_name(category)
    implemented = {'ENC01', 'ENC02', 'ENC03', 'ENC05', 'ENC06', 'ENC07', 'ENC08', 'ENC10',
                   'DOC01', 'DOC02', 'DOC04', 'DOC05', 'DOC06',
                   'IMG01', 'IMG02', 'IMG03', 'IMG04', 'IMG05',
                   'AV01', 'AV02', 'AV03', 'AV04', 'AV06',
                   'OS01', 'OS02', 'OS03', 'CAN01', 'CAN02', 'MISC01',
                   'NET01', 'NET02', 'NET03', 'NET05',
                   'DF01', 'DF02', 'DF03', 'DF04', 'DF05',
                   'REV01', 'REV02', 'REV03', 'REV04', 'REV05', 'REV06', 'REV07', 'REV11',
                   'PWN01', 'PWN02', 'PWN07',
                   'WEB01', 'WEB02', 'WEB03', 'WEB04', 'WEB05', 'WEB08', 'AIC01', 'AIC02'}
    return [{'id': row['id'], 'domain': row['domain'], 'stage': row['delivery_stage'],
             'status': 'partial' if row['id'] in implemented
             else 'not implemented'} for row in CATALOG
            if category == 'auto' or row['domain'] == category]
