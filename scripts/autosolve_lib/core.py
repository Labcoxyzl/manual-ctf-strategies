"""Shared run state and local artifact flow for autosolve."""

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import resource
import shutil
import signal
import stat
import tempfile
import time
import uuid
import zipfile
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
              'symmetric_parameters': list,
              'dbc': str, 'symbol_paths': list, 'byte_order': str, 'checker': dict}
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
    _rsa_parameters(hints, path)
    _symmetric_parameters(hints)
    return hints, hashlib.sha256(raw).hexdigest()


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
                if key_path.is_symlink() or not key_path.is_file() or key_path.stat().st_size > 16384:
                    raise InvalidInput(f'RSA record {index} needs a regular public key file')
                before = key_path.stat()
                value = key_path.read_bytes()
                after = key_path.stat()
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
        head = stream.read(4096)
    signatures = ((b'PK\x03\x04', 'zip'), (b'\x1f\x8b', 'gzip'),
                  (b'\x89PNG\r\n\x1a\n', 'png'), (b'BM', 'bmp'), (b'%PDF-', 'pdf'),
                  (b'SQLite format 3\x00', 'sqlite'),
                  (b'\xd4\xc3\xb2\xa1', 'pcap'), (b'\xa1\xb2\xc3\xd4', 'pcap'),
                  (b'\x4d\x3c\xb2\xa1', 'pcap'), (b'\xa1\xb2\x3c\x4d', 'pcap'),
                  (b'\x0a\x0d\x0d\x0a', 'pcapng'),
                  (b'\xff\xd8\xff', 'jpeg'), (b'GIF87a', 'gif'),
                  (b'GIF89a', 'gif'), (b'II*\x00', 'tiff'), (b'MM\x00*', 'tiff'),
                  (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'office'),
                  (b'\x7fELF', 'elf'), (b'RIFF', 'riff'))
    for signature, kind in signatures:
        if head.startswith(signature):
            return kind
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


def _sources(path, *, allow_empty=False, exclude=None, excluded_files=()):
    source = Path(path).absolute()
    private = {Path(item).absolute() for item in excluded_files}
    private_identities = set()
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
    for key in ('password_file', 'tls_keylog', 'dbc'):
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
                job.get('tool_fingerprint') in fingerprints.get(job['adapter_id'], []))

    valid_producer_keys = {child_id: {job['key'] for job in jobs if valid_job(job)}
                           for child_id, jobs in producers.items()}

    while True:
        children = {artifact['id'] for artifact in manifest['artifacts']
                    if artifact['depth'] > 0 and artifact['complete']
                    and (artifact['source_locator'].get('encrypted') is not True or
                         artifact['source_locator'].get('password_file_sha256') == current_password)
                    and (not ('archive_member' in artifact['source_locator'] and
                              'encrypted' not in artifact['source_locator']) or
                         any(job['adapter_id'] == 'zip' and artifact['id'] in job['child_ids'] and
                             job.get('data_fingerprints', {}).get('password_file') == current_password
                             for job in manifest['jobs']))
                    and (any(edge['id'] in current and
                             edge.get('job_key') in valid_producer_keys.get(artifact['id'], set()) and
                             (artifact['source_locator'].get('sqlite_companion_sha256') is None or
                              artifact['source_locator']['sqlite_companion_sha256'] ==
                              manifest.get('sqlite_companions', {}).get(edge['id']))
                             for edge in artifact['parents']) or
                         (artifact['source_locator'].get('symmetric_hint_index') is not None and
                          artifact['source_locator'].get('symmetric_parameters_sha256') ==
                          manifest.get('symmetric_parameters_sha256') and
                          artifact.get('producer_key') in valid_producer_keys.get(artifact['id'], set())))}
        if children <= current:
            break
        current |= children
    for artifact in manifest['artifacts']:
        artifact['current'] = artifact['id'] in current
    for finding in manifest['findings']:
        if 'rsa_parameters_sha256' in finding:
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
                                   finding.get('pattern_sha256') == manifest.get('candidate_pattern_sha256')))
    for item in manifest.get('intelligence', []):
        job = jobs_by_id.get(item.get('job_id'))
        item['current'] = (item['artifact_id'] in current and not item.get('superseded', False)
                           and job is not None and valid_job(job))


def _upgrade_lineage(manifest):
    if manifest.get('lineage_schema') == 2:
        return
    by_id = {item['id']: item for item in manifest['artifacts']}
    prefixes = {'zip': ('zip member',), 'mime': ('MIME part',), 'pdf': ('PDF ',),
                'png-tail': ('PNG tail',), 'xor-one': ('single-byte XOR',),
                'xor-search': ('single-byte XOR', 'repeating-key XOR'),
                'sqlite': ('SQLite ',), 'image-metadata': ('image frame',)}
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
                    if edge['operation'].startswith(('zip member', 'MIME part', 'PDF ', 'PNG tail',
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
            edge = {'id': parent['id'], 'operation': operation, 'job_key': producer_key}
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
             'parents': [{'id': parent['id'], 'operation': operation, 'job_key': producer_key}],
             'source_locator': source_locator or {'transform': operation}, 'depth': parent['depth'] + 1,
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
            edge = {'id': parent['id'], 'operation': operation, 'job_key': producer_key}
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
             'parents': [{'id': parent['id'], 'operation': operation, 'job_key': producer_key}],
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
    values = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(values) > 8 or any(len(value) > 128 for value in values):
        raise InvalidInput('password_file allows at most eight candidates of 128 bytes')
    return values, hashlib.sha256(raw).hexdigest()


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


def _image_worker(path, max_output, pipe):
    from .profiles.images import OutputLimit, extract_png_tail
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', extract_png_tail(path, max_output)))
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
            raise TimeoutError('PNG inspection exceeded its time limit')
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


def _decode_worker(data, max_output, pipe):
    from .profiles.encoding import decode
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        pipe.send(('ok', decode(data, max_output)))
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


def _xor_worker(data, pipe):
    from .profiles.xor import recover_repeating_key, recover_single_byte
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        pipe.send(('ok', recover_single_byte(data) + recover_repeating_key(data)))
    except Exception as error:
        pipe.send(('error', f'{type(error).__name__}: {error}'))
    finally:
        pipe.close()


def _run_xor(data, timeout):
    import multiprocessing
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker_entry, args=(_xor_worker, data, child))
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


def _mark_encoding_coverage(manifest, operations):
    produced = {'ENC02' if label.startswith(('gzip', 'zlib', 'bzip2', 'xz'))
                else 'ENC03' if label == 'rot13' else 'ENC01' for label in operations}
    for family in ('ENC01', 'ENC02', 'ENC03'):
        if family in manifest['coverage']:
            if family in produced:
                manifest['coverage'][family]['status'] = 'ran'
            elif manifest['coverage'][family]['status'] == 'not scheduled':
                manifest['coverage'][family]['status'] = 'no finding'
            manifest['coverage'][family]['note'] = 'finite stdlib transforms only'


def _rsa_job(run, manifest, parameters, params_hash, deadline):
    from .profiles.rsa import inspect_rsa
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
    fingerprint = hashlib.sha256(Path(inspect_rsa.__code__.co_filename).read_bytes()).hexdigest()
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


def _symmetric_job(run, manifest, records, params_hash, deadline):
    from .profiles.symmetric import decrypt_declared
    if 'ENC08' not in manifest['coverage']:
        return []
    if not records:
        manifest['coverage']['ENC08']['status'] = 'skipped prerequisite'
        manifest['coverage']['ENC08']['note'] = 'declared AES parameters required'
        return []
    if time.monotonic() >= deadline:
        manifest['warnings'].append('AES check not scheduled before work budget ended')
        return []
    fingerprint = hashlib.sha256(Path(decrypt_declared.__code__.co_filename).read_bytes()).hexdigest()
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
    key = hashlib.sha256(f"{artifact['sha256']}:image-metadata.v2:{fingerprint}".encode()).hexdigest()
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
                manifest['intelligence'].append({
                    'artifact_id': artifact['id'], 'job_id': job['id'], 'current': True,
                    'tag': tag['tag'], 'group': tag['group'], 'value': str(value)[:512],
                    'source_locator': {'exif_tag': tag['source_tag']},
                    'next_action': 'Correlate this metadata with the original artifact.'})
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
        manifest['coverage']['IMG01']['note'] = 'ExifTool tags and validated PNG tail only'
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
            edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                    'job_key': key}
            if edge not in child['parents']:
                child['parents'].append(edge)
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
            status = 'truncated'
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        job['ended'] = time.time()
        _write_json(run / 'jobs' / f"{job['id']}.json", job)
        _write_json(run / 'manifest.json', manifest)
    if 'DOC05' in manifest['coverage']:
        priority = {'not scheduled': 0, 'no finding': 1, 'ran': 2,
                    'skipped prerequisite': 3, 'truncated': 4}
        entry = manifest['coverage']['DOC05']
        if priority[status] > priority.get(entry['status'], 0):
            entry['status'] = status
        manifest['coverage']['DOC05']['note'] = 'bounded OOXML/OLE/RTF objects and static VBA source'
    return children


def _can_job(run, manifest, artifact, deadline):
    from .profiles.canlog import parse_can_log
    path = Path(artifact['path'])
    fingerprint = hashlib.sha256(Path(parse_can_log.__code__.co_filename).read_bytes()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:can-log.v1:{fingerprint}".encode()).hexdigest()
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
        manifest['warnings'].extend(warnings)
    else:
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


def _packets_job(run, manifest, artifact, deadline):
    from .profiles import packets
    path = Path(artifact['path'])
    module_hash = hashlib.sha256(Path(packets.__file__).read_bytes()).hexdigest()
    try:
        tool_hash = _hash(Path(packets.TSHARK), deadline)
    except OSError:
        tool_hash = None
    fingerprint = hashlib.sha256(f'{module_hash}:{tool_hash}'.encode()).hexdigest()
    key = hashlib.sha256(f"{artifact['sha256']}:packets.v1:{fingerprint}".encode()).hexdigest()
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
            edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                    'job_key': key}
            if edge not in child['parents']:
                child['parents'].append(edge)
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


def _reusable_children(manifest, job, deadline):
    children = []
    for child_id in job['child_ids']:
        child = next((a for a in manifest['artifacts'] if a['id'] == child_id), None)
        if child is None or not child['complete']:
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


def _current_adapter_fingerprints(deadline):
    import sqlite3
    from .profiles import image_metadata, packets, zsteg
    profiles = Path(__file__).parent / 'profiles'

    def module_hash(name):
        return hashlib.sha256((profiles / f'{name}.py').read_bytes()).hexdigest()

    def executable_hash(path):
        try:
            return _hash(Path(path), deadline)
        except OSError:
            return None

    image_hash = module_hash('image_metadata')
    exif_hash = executable_hash(image_metadata._EXIFTOOL)
    packet_hash = module_hash('packets')
    tshark_hash = executable_hash(packets.TSHARK)
    sqlite_hash = module_hash('sqlite')
    zsteg_hash = module_hash('zsteg')
    zsteg_tool_hash = executable_hash(shutil.which(zsteg.ZSTEG) or zsteg.ZSTEG)
    return {
        'encoding': [module_hash('encoding')],
        'xor-one': [module_hash('xor')],
        'xor-search': [module_hash('xor')],
        'rsa-literals': [module_hash('rsa')],
        'aes-declared': [module_hash('symmetric')],
        'zip': [module_hash('documents')],
        'mime': [module_hash('mime')],
        'pdf': [module_hash('pdf')],
        'office': [_office_fingerprint()],
        'png-tail': [module_hash('images')],
        'zsteg': [hashlib.sha256(f'{zsteg_hash}:{zsteg_tool_hash}'.encode()).hexdigest()],
        'can-log': [module_hash('canlog')],
        'sqlite': [hashlib.sha256(f'{sqlite_hash}:{sqlite3.sqlite_version}'.encode()).hexdigest()],
        'packets': [hashlib.sha256(f'{packet_hash}:{tshark_hash}'.encode()).hexdigest()],
        'image-metadata': [hashlib.sha256(f'{image_hash}:{exif_hash}:views={mode}'.encode()).hexdigest()
                           for mode in (False, True)],
    }


def _scan_artifact(manifest, artifact, deadline, patterns, data=None):
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
                                             artifact['id'], patterns, deadline)
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
    current_findings = [f for f in manifest['findings'] if f.get('current', True)]
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
            lines.append(f"- {item['kind_evidence']}: {json.dumps(item['path'])}; {item['size']} bytes; "
                         f"SHA-256 {item['sha256'] or 'incomplete'}; "
                         f"locator {json.dumps(item['source_locator'], ensure_ascii=True)}")
    for item in manifest.get('intelligence', []):
        if item['current']:
            lines.append(f"- {json.dumps(item['tag'], ensure_ascii=True)} "
                         f"({json.dumps(item['group'], ensure_ascii=True)}): "
                         f"{json.dumps(item['value'], ensure_ascii=True)} "
                         f"from artifact {item['artifact_id']}")
    for warning in manifest['warnings']:
        lines.append(f'- Limit or prerequisite: {warning}')
    historical = sum(not f.get('current', True) for f in manifest['findings'])
    if historical:
        lines.append(f'- {historical} earlier candidate(s) belong to changed inputs; retained in findings.json.')
    lines += ['', '## Family coverage', '', '| Family | Status | Note |', '| --- | --- | --- |']
    for family, entry in manifest['coverage'].items():
        lines.append(f"| {family} | {entry['status']} | {entry['note']} |")
    _write_text(run / 'report.md', '\n'.join(lines) + '\n')


def _execute(run, manifest, budget, hints, hint_hash, hints_path):
    from .profiles.encoding import decode
    from .profiles.xor import recover_repeating_key, recover_single_byte
    from .profiles.documents import extract_zip
    from .profiles.images import extract_png_tail
    from .profiles.mime import parse_mime
    from .profiles.pdf import extract_pdf
    deadline = time.monotonic() + budget
    passwords, password_hash = _passwords(hints, hints_path)
    rsa_parameters, rsa_hash = _rsa_parameters(hints, hints_path)
    symmetric_parameters, symmetric_hash = _symmetric_parameters(hints)
    manifest.setdefault('history_warnings', []).extend(manifest['warnings'])
    manifest.setdefault('intelligence', [])
    manifest['warnings'] = []
    _upgrade_lineage(manifest)
    manifest['coverage'] = _coverage(manifest['category'])
    if manifest['execute_local']:
        manifest['warnings'].append('local execution requested but no execution adapter is implemented')
    manifest['budget_seconds'] = budget
    manifest['hint_sha256'] = hint_hash
    manifest['password_file_sha256'] = password_hash
    manifest['candidate_pattern_sha256'] = hashlib.sha256(
        json.dumps(hints.get('flag_patterns', []), ensure_ascii=False).encode()).hexdigest()
    manifest['rsa_parameters_sha256'] = rsa_hash
    manifest['symmetric_parameters_sha256'] = symmetric_hash
    manifest['current_adapter_fingerprints'] = _current_adapter_fingerprints(deadline)
    manifest['status'] = 'running'
    _write_json(run / 'manifest.json', manifest)
    active = []
    for path in _sources(manifest['input_path'], allow_empty=True, exclude=run.parent,
                         excluded_files=_private_paths(hints_path, hints)):
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
    _refresh_current(manifest, {artifact['id'] for artifact in active})
    if not active:
        manifest['warnings'].append('no regular source files remain in the selected directory')
    def routed_domain(item):
        if manifest['category'] != 'auto':
            return manifest['category']
        return {'sqlite': 'disk_memory', 'can_log': 'can_misc',
                'pcap': 'packets', 'pcapng': 'packets',
                'png': 'images', 'bmp': 'images', 'jpeg': 'images', 'gif': 'images', 'tiff': 'images',
                'zip': 'documents', 'mime': 'documents', 'pdf': 'documents',
                'office': 'documents'}.get(
                    item['kind_evidence'], 'encoding')

    if manifest['category'] == 'auto':
        groups = {}
        for item in active:
            groups.setdefault(routed_domain(item), []).append(item)
        order = ('disk_memory', 'can_misc', 'encoding', 'images', 'documents', 'packets')
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
    if encoding_selected:
        _rsa_job(run, manifest, rsa_parameters, rsa_hash, deadline)
        queue.extend((child, child['depth']) for child in
                     _symmetric_job(run, manifest, symmetric_parameters, symmetric_hash, deadline))
    documents_selected = manifest['category'] in ('auto', 'documents')
    images_selected = manifest['category'] in ('auto', 'images')
    metadata_selected = manifest['category'] in ('auto', 'images', 'osint')
    can_selected = manifest['category'] in ('auto', 'can_misc')
    packets_selected = manifest['category'] in ('auto', 'packets')
    disk_selected = manifest['category'] in ('auto', 'disk_memory')
    while queue and time.monotonic() < overall_deadline:
        artifact, depth = queue.popleft()
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
        if images_selected and artifact['kind_evidence'] == 'png':
            fingerprint = hashlib.sha256(Path(extract_png_tail.__code__.co_filename).read_bytes()).hexdigest()
            key = hashlib.sha256(f"{artifact['sha256']}:png-tail.v1:{fingerprint}".encode()).hexdigest()
            if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                seen.setdefault(key, artifact['id'])
                old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                reusable = _reusable_children(manifest, old, deadline) if old else None
                if old and reusable is None:
                    old['status'] = 'invalidated'
                if reusable is not None:
                    for child in reusable:
                        edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                                'job_key': key}
                        if edge not in child['parents']:
                            child['parents'].append(edge)
                        queue.append((child, depth + 1))
                    if 'IMG01' in manifest['coverage']:
                        manifest['coverage']['IMG01']['status'] = 'ran' if reusable else 'no finding'
                        manifest['coverage']['IMG01']['note'] = 'validated trailing ZIP in PNG only'
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'png-tail',
                           'input_ids': [artifact['id']], 'operation': 'validated PNG trailing ZIP',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {},
                           'cwd': str(run), 'limits': {'output_bytes': MAX_CHILD},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    try:
                        result = _run_image(path, min(MAX_CHILD, MAX_DERIVED - manifest['derived_bytes']),
                                            min(30, max(.01, deadline - time.monotonic())))
                        if _hash(path, deadline) != artifact['sha256']:
                            raise RuntimeError('PNG changed before tail publication')
                        if result:
                            data, evidence = result
                            child = _store_child(run, manifest, artifact, data,
                                                 f"PNG tail at byte {evidence['offset']}", deadline,
                                                 source_locator={'image_offset': evidence['offset'],
                                                                 'iend_offset': evidence['iend_offset']},
                                                 force_record=True, producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                        job['status'] = 'complete'
                        if 'IMG01' in manifest['coverage']:
                            manifest['coverage']['IMG01']['status'] = 'ran' if job['child_ids'] else 'no finding'
                            manifest['coverage']['IMG01']['note'] = 'validated trailing ZIP in PNG only'
                    except WorkLimit as error:
                        job['status'] = 'truncated'
                        job['warning'] = str(error)
                        manifest['warnings'].append(str(error))
                        if 'IMG01' in manifest['coverage']:
                            manifest['coverage']['IMG01']['status'] = 'truncated'
                            manifest['coverage']['IMG01']['note'] = 'PNG trailing ZIP exceeds output bound'
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"PNG job failed: {type(error).__name__}")
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            if images_selected and time.monotonic() < deadline:
                for child in _zsteg_job(run, manifest, artifact, deadline):
                    queue.append((child, depth + 1))
            if metadata_selected and time.monotonic() < deadline:
                _image_metadata_job(run, manifest, artifact, deadline, make_views=True)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if images_selected and artifact['kind_evidence'] == 'bmp':
            for child in _zsteg_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            if time.monotonic() < deadline:
                _image_metadata_job(run, manifest, artifact, deadline, make_views=True)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if metadata_selected and artifact['kind_evidence'] in ('png', 'jpeg', 'gif', 'tiff'):
            _image_metadata_job(run, manifest, artifact, deadline,
                                make_views=manifest['category'] != 'osint')
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
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
                        edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                                'job_key': key}
                        if edge not in child['parents']:
                            child['parents'].append(edge)
                        child['current'] = True
                        queue.append((child, depth + 1))
                    manifest['warnings'].extend(old.get('warnings', []))
                    if 'DOC01' in manifest['coverage']:
                        manifest['coverage']['DOC01']['status'] = 'ran' if reusable else 'no finding'
                        manifest['coverage']['DOC01']['note'] = 'safe ZIP members only'
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
                        if 'DOC01' in manifest['coverage']:
                            manifest['coverage']['DOC01']['status'] = 'ran' if records else 'no finding'
                            manifest['coverage']['DOC01']['note'] = 'safe ZIP members only'
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
                    finally:
                        shutil.rmtree(staging, ignore_errors=True)
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if documents_selected and artifact['kind_evidence'] == 'office':
            for child in _office_job(run, manifest, artifact, deadline):
                queue.append((child, depth + 1))
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
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
                        edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                                'job_key': key}
                        if edge not in child['parents']:
                            child['parents'].append(edge)
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
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
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
                        edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                                'job_key': key}
                        if edge not in child['parents']:
                            child['parents'].append(edge)
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
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if can_selected and artifact['kind_evidence'] == 'can_log':
            _can_job(run, manifest, artifact, deadline)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if packets_selected and artifact['kind_evidence'] in ('pcap', 'pcapng'):
            _packets_job(run, manifest, artifact, deadline)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if disk_selected and artifact['kind_evidence'] == 'sqlite':
            _sqlite_job(run, manifest, artifact, deadline, queue, depth)
            _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []))
            continue
        if manifest['category'] == 'packets' and artifact['kind_evidence'] not in ('pcap', 'pcapng'):
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
        data = None
        if path.stat().st_size <= MAX_READ:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact['sha256']:
                manifest['warnings'].append(f"{artifact['id']}: bytes changed before processing")
                continue
        elif encoding_selected and artifact['kind_evidence'] in ('text', 'gzip', 'binary'):
            manifest['warnings'].append(f"{artifact['id']}: decode input limit is 8 MiB")
        if data is not None and encoding_selected and artifact['kind_evidence'] in ('text', 'gzip', 'binary'):
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
                        operation = child['parents'][0]['operation']
                        edge = {'id': artifact['id'], 'operation': operation, 'job_key': key}
                        if edge not in child['parents']:
                            child['parents'].append(edge)
                        child['current'] = True
                        reused_operations.append(operation)
                        queue.append((child, depth + 1))
                    _mark_encoding_coverage(manifest, reused_operations)
                else:
                    job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'encoding',
                           'input_ids': [artifact['id']], 'operation': 'stdlib finite decode',
                           'tool_fingerprint': fingerprint, 'data_fingerprints': {},
                           'cwd': str(run), 'limits': {'output_bytes': MAX_CHILD},
                           'status': 'running', 'child_ids': [], 'started': time.time()}
                    manifest['jobs'].append(job)
                    _write_json(run / 'manifest.json', manifest)
                    try:
                        results = _run_decode(data, min(MAX_CHILD, MAX_DERIVED - manifest['derived_bytes']),
                                              min(30, max(.01, deadline - time.monotonic())))
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
                            child = _store_child(run, manifest, artifact, decoded, operation, deadline,
                                                 source_locator=locator, producer_key=key)
                            if child:
                                job['child_ids'].append(child['id'])
                                queue.append((child, depth + 1))
                                produced.append(operation)
                        job['status'] = 'complete'
                        _mark_encoding_coverage(manifest, produced)
                    except Exception as error:
                        job['status'] = 'failed'
                        job['warning'] = f'{type(error).__name__}: {error}'
                        manifest['warnings'].append(f"encoding job failed: {type(error).__name__}")
                    job['ended'] = time.time()
                    _write_json(run / 'jobs' / f"{job['id']}.json", job)
                    _write_json(run / 'manifest.json', manifest)
        if (encoding_selected and artifact['kind_evidence'] in ('text', 'binary')
                and 'xor_key_hex' not in artifact['source_locator']):
            if data is None or len(data) > 1024 * 1024:
                manifest['warnings'].append(f"{artifact['id']}: XOR input limit is 1 MiB")
                if 'ENC05' in manifest['coverage'] and manifest['coverage']['ENC05']['status'] != 'ran':
                    manifest['coverage']['ENC05']['status'] = 'truncated'
                    manifest['coverage']['ENC05']['note'] = 'XOR input limit'
            elif len(data) >= 16:
                fingerprint = hashlib.sha256(Path(recover_single_byte.__code__.co_filename).read_bytes()).hexdigest()
                key = hashlib.sha256(f"{artifact['sha256']}:xor-search.v1:{fingerprint}:8".encode()).hexdigest()
                if key not in seen or not _descends_from(manifest, artifact['id'], seen[key]):
                    seen.setdefault(key, artifact['id'])
                    old = next((j for j in manifest['jobs'] if j['key'] == key and j['status'] == 'complete'), None)
                    reusable = _reusable_children(manifest, old, deadline) if old else None
                    if old and reusable is None:
                        old['status'] = 'invalidated'
                    if reusable is not None:
                        for child in reusable:
                            edge = {'id': artifact['id'], 'operation': child['parents'][0]['operation'],
                                    'job_key': key}
                            if edge not in child['parents']:
                                child['parents'].append(edge)
                            queue.append((child, depth + 1))
                        if 'ENC05' in manifest['coverage']:
                            manifest['coverage']['ENC05']['status'] = 'ran' if reusable else 'no finding'
                            manifest['coverage']['ENC05']['note'] = 'single-byte and repeating-key candidates'
                    else:
                        job = {'id': uuid.uuid4().hex, 'key': key, 'adapter_id': 'xor-search',
                               'input_ids': [artifact['id']], 'operation': 'bounded XOR key search',
                               'tool_fingerprint': fingerprint, 'data_fingerprints': {}, 'cwd': str(run),
                               'limits': {'input_bytes': 1024 * 1024, 'candidates_per_method': 8},
                               'status': 'running', 'child_ids': [], 'started': time.time()}
                        manifest['jobs'].append(job)
                        _write_json(run / 'manifest.json', manifest)
                        try:
                            candidates = _run_xor(data, min(30, max(.01, deadline - time.monotonic())))
                            for candidate in candidates:
                                if candidate['data'] == data:
                                    continue
                                key_hex = candidate['key_hex']
                                repeated = candidate.get('key_length', 1) > 1
                                operation = f"{'repeating-key' if repeated else 'single-byte'} XOR key 0x{key_hex}"
                                locator = {'xor_key_hex': key_hex, 'xor_key_length': len(bytes.fromhex(key_hex))}
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
                                        'next_action': 'Verify the assumed key and recovered text against the challenge.'})
                            job['status'] = 'complete'
                            if 'ENC05' in manifest['coverage']:
                                manifest['coverage']['ENC05']['status'] = 'ran' if job['child_ids'] else 'no finding'
                                manifest['coverage']['ENC05']['note'] = 'single-byte and repeating-key candidates'
                        except Exception as error:
                            job['status'] = 'failed'
                            job['warning'] = f'{type(error).__name__}: {error}'
                            manifest['warnings'].append(f"XOR job failed: {type(error).__name__}")
                        job['ended'] = time.time()
                        _write_json(run / 'jobs' / f"{job['id']}.json", job)
                        _write_json(run / 'manifest.json', manifest)
        _scan_artifact(manifest, artifact, deadline, hints.get('flag_patterns', []), data)
    if queue or time.monotonic() >= overall_deadline:
        manifest['warnings'].append('overall work budget ended before all artifacts were processed')
    _refresh_current(manifest, {artifact['id'] for artifact in active})
    incomplete = any(a['sha256'] is None for a in active) or bool(manifest['warnings'])
    pending = any(x['status'] == 'not scheduled' and x['delivery_stage'] == 'baseline'
                  for x in manifest['coverage'].values())
    manifest['status'] = 'partial' if incomplete or pending else 'complete'
    _write_json(run / 'findings.json', manifest['findings'])
    _write_json(run / 'manifest.json', manifest)
    _render_report(run, manifest)
    _event(run, 'checkpoint', status=manifest['status'])
    return manifest['status']


def _locked_execute(run, manifest, budget, hints, hint_hash, hints_path):
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
        return _execute(run, manifest, budget, hints, hint_hash, hints_path)
    finally:
        os.close(lock)


def analyze(path, *, category='auto', budget=300, hints_path=None, runs_root=None, execute_local=False):
    category = category_name(category)
    if not 0 < budget <= 3600:
        raise InvalidInput('budget must be between 0 and 3600 seconds')
    root = Path(runs_root) if runs_root else ROOT / '.autosolve' / 'runs'
    if Path(path).absolute().is_dir() and Path(path).absolute() == root.absolute():
        raise InvalidInput('runs root must differ from the analyzed directory')
    hints, hint_hash = load_hints(hints_path)
    _passwords(hints, hints_path)
    _sources(path, exclude=root, excluded_files=_private_paths(hints_path, hints))
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    manifest = {'schema_version': SCHEMA, 'input_path': str(Path(path).absolute()),
                'category': category, 'execute_local': bool(execute_local),
                'lineage_schema': 2,
                'created': time.time(), 'status': 'new', 'artifacts': [], 'jobs': [],
                'findings': [], 'intelligence': [], 'coverage': _coverage(category), 'derived_bytes': 0,
                'warnings': []}
    status = _locked_execute(run, manifest, budget, hints, hint_hash, hints_path)
    return run, status


def resume(run_path, *, budget=300, hints_path=None):
    run = Path(run_path).absolute()
    if run.is_symlink():
        raise InvalidInput('run directory must not be a symlink')
    try:
        manifest = json.loads((run / 'manifest.json').read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidInput(f'run manifest unreadable: {error}') from error
    if manifest.get('schema_version') != SCHEMA:
        raise InvalidInput('unsupported run schema; preserve this run and export its files manually')
    if not 0 < budget <= 3600:
        raise InvalidInput('budget must be between 0 and 3600 seconds')
    hints, hint_hash = load_hints(hints_path)
    _passwords(hints, hints_path)
    if hint_hash is None and manifest.get('hint_sha256') is not None:
        raise InvalidInput('resume requires the prior hints file or a replacement')
    status = _locked_execute(run, manifest, budget, hints, hint_hash, hints_path)
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
    return [{'id': row['id'], 'domain': row['domain'], 'stage': row['delivery_stage'],
             'status': 'partial' if row['id'] in {'ENC01', 'ENC02', 'ENC03', 'ENC05', 'ENC06', 'ENC07', 'ENC08', 'DOC01', 'DOC02', 'DOC04', 'DOC06', 'IMG01', 'IMG04', 'OS01', 'CAN01', 'NET01', 'DF04', 'AIC01', 'AIC02'}
             else 'not implemented'} for row in CATALOG
            if category == 'auto' or row['domain'] == category]
