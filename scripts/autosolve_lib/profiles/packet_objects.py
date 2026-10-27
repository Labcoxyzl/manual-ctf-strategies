"""Bounded HTTP object export from an offline capture, with response references."""

import hashlib
import json
import os
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path


TSHARK = (shutil.which(os.environ.get('AUTOSOLVE_TSHARK', 'tshark'))
          or os.environ.get('AUTOSOLVE_TSHARK') or '/usr/bin/tshark')
FIELDS = ('frame.number', 'frame.cap_len', 'frame.len', 'tcp.stream',
          'http.request.uri', 'http.response.code', 'http.response_for.uri', 'http.request_in',
          'http.content_length_header', 'http.content_encoding',
          'http.transfer_encoding', 'http.file_data')


def _run(argv: list[str], deadline: float, max_output: int,
         object_dir: Path | None = None, max_objects: int = 0,
         max_total_bytes: int = 0) -> tuple[bytes, str | None]:
    """Bound a TShark process and its output; discard results on early stop."""
    def limits():
        if object_dir is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_total_bytes, max_total_bytes))

    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   preexec_fn=limits)
    except OSError as error:
        return b'', f'TShark unavailable: {error}'
    output = bytearray()
    errors = bytearray()
    selector = selectors.DefaultSelector()
    reason = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                reason = 'TShark timed out; HTTP export incomplete'
                break
            if object_dir is not None:
                entries = list(object_dir.iterdir())
                if len(entries) > max_objects or sum(entry.stat(follow_symlinks=False).st_size
                                                       for entry in entries) > max_total_bytes:
                    reason = 'HTTP object count or byte limit reached; export incomplete'
                    break
            for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > max_output:
                    reason = 'TShark output limit reached; HTTP export incomplete'
                    break
                key.data.extend(chunk)
            if reason:
                break
        if reason is None and process.wait(timeout=max(.01, deadline - time.monotonic())):
            detail = errors.decode('utf-8', 'replace').strip().splitlines()
            if object_dir is not None and process.returncode == -signal.SIGXFSZ:
                reason = 'HTTP object byte limit reached; export incomplete'
            else:
                reason = f'TShark export failed: {(detail[0] if detail else "unknown error")[:300]}'
    except subprocess.TimeoutExpired:
        reason = 'TShark timed out; HTTP export incomplete'
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
    return (bytes(output), None) if reason is None else (b'', reason)


def export_http_objects(path: Path, output_dir: Path, *, timeout: float,
                        max_objects: int = 32, max_total_bytes: int = 64 * 1024 * 1024,
                        max_output: int = 32 * 1024 * 1024,
                        max_source_bytes: int = 256 * 1024 * 1024) -> tuple[list[dict], list[str]]:
    """Return exact exported files whose bytes match a frame-linked HTTP body."""
    if min(timeout, max_objects, max_total_bytes, max_output, max_source_bytes) <= 0:
        raise ValueError('HTTP export limits must be positive')
    path = Path(path)
    output_dir = Path(output_dir)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_source_bytes:
        return [], ['capture unavailable, symlinked, or exceeds HTTP source byte limit']
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('HTTP output directory must be separate and not a symlink')
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError('HTTP output directory must be empty')
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    objects = output_dir / 'objects'
    objects.mkdir(mode=0o700)
    deadline = time.monotonic() + timeout
    source = str(path.resolve())
    base = [TSHARK, '-r', source, '-n', '-o', 'tcp.try_heuristic_first:TRUE']
    raw, error = _run(base + ['-T', 'ek', *(part for field in FIELDS
                                                for part in ('-e', field))],
                      deadline, max_output)
    if error:
        return [], [error]
    responses = []
    warnings = []
    saw_http = False
    try:
        for line in raw.splitlines():
            item = json.loads(line)
            fields = item.get('layers')
            if fields is None:
                continue
            if not isinstance(fields, dict):
                raise ValueError('invalid TShark row')
            saw_http |= any(key in fields for key in ('http_request_uri', 'http_response_code'))

            def one(field):
                values = fields.get(field.replace('.', '_'), [])
                if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                    raise ValueError('invalid TShark field')
                return values[0] if len(values) == 1 else ''

            bodies = fields.get('http_file_data', [])
            if len(bodies) > 1:
                warnings.append(f"frame {one('frame.number')}: multiple HTTP bodies unpaired")
                continue
            body = one('http.file_data')
            if not body:
                continue
            data = bytes.fromhex(body)
            length = one('http.content_length_header')
            encoding = one('http.content_encoding')
            transfer = one('http.transfer_encoding')
            if length and not length.isdecimal():
                warnings.append(f"frame {one('frame.number')}: invalid HTTP Content-Length")
                continue
            if length and not encoding and not transfer and len(data) != int(length):
                warnings.append(f"frame {one('frame.number')}: HTTP Content-Length mismatch")
                continue
            if int(one('frame.cap_len')) < int(one('frame.len')):
                warnings.append(f"frame {one('frame.number')}: truncated packet")
                continue
            responses.append({'sha256': hashlib.sha256(data).hexdigest(),
                              'size': len(data), 'packet': int(one('frame.number')),
                              'tcp_stream': int(one('tcp.stream')) if one('tcp.stream') else None,
                              'request_packet': int(one('http.request_in')) if one('http.request_in') else None,
                              'uri': one('http.response_for.uri') or None,
                              'status': int(one('http.response.code')) if one('http.response.code') else None,
                              'encoding': encoding or None,
                              'transfer_encoding': transfer or None,
                              'length_verified': bool(length and not encoding and not transfer)})
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        return [], [f'invalid TShark HTTP metadata; export incomplete: {error}']
    if not responses:
        return [], warnings or (['no complete frame-linked HTTP body found'] if saw_http else [])
    _, error = _run(base + ['-Q', '--export-objects', f'http,{objects}'], deadline,
                    max_output, objects, max_objects, max_total_bytes)
    if error:
        shutil.rmtree(objects)
        return [], warnings + [error]
    records = []
    total = 0
    entries = sorted(objects.iterdir())
    if len(entries) > max_objects:
        return [], warnings + ['HTTP object count limit reached; export incomplete']
    for index, item in enumerate(entries):
        name = item.name
        info = item.lstat()
        if (not stat.S_ISREG(info.st_mode) or '/' in name or '\\' in name or
                name in ('.', '..') or any(ord(char) < 32 for char in name)):
            warnings.append(f'object {index}: unsafe exported filename or file type')
            continue
        if info.st_size > max_total_bytes - total:
            warnings.append('HTTP object byte limit reached; export incomplete')
            break
        digest = hashlib.sha256()
        with item.open('rb') as reader:
            while chunk := reader.read(65536):
                digest.update(chunk)
        total += info.st_size
        matches = [row for row in responses if row['sha256'] == digest.hexdigest()
                   and row['size'] == info.st_size]
        if not matches:
            warnings.append(f'object {index}: no exact frame-linked HTTP body match')
            item.unlink()
            continue
        locators = [{'packet': row['packet'], 'tcp_stream': row['tcp_stream'],
                     'request_packet': row['request_packet'], 'uri': row['uri']}
                    for row in matches]
        row = matches[0]
        records.append({'path': item, 'name': name, 'index': index,
                        'sha256': digest.hexdigest(), 'size': info.st_size,
                        'protocol': 'http', 'packet': row['packet'] if len(matches) == 1 else None,
                        'tcp_stream': row['tcp_stream'] if len(matches) == 1 else None,
                        'source_locator': locators[0] if len(matches) == 1 else None,
                        'source_locators': locators, 'verified': True,
                        'length_verified': all(match['length_verified'] for match in matches)})
        if len(matches) > 1:
            warnings.append(f'object {index}: identical body in multiple HTTP responses; references ambiguous')
        if not records[-1]['length_verified']:
            warnings.append(f'object {index}: wire completeness not independently verified')
    return records, warnings
