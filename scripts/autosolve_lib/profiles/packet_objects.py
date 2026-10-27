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
import zlib
from pathlib import Path

from .packet_streams import reassemble_tcp


TSHARK = (shutil.which(os.environ.get('AUTOSOLVE_TSHARK', 'tshark'))
          or os.environ.get('AUTOSOLVE_TSHARK') or '/usr/bin/tshark')
FIELDS = ('frame.number', 'frame.cap_len', 'frame.len', 'tcp.stream',
          'http.request.method', 'http.request.uri', 'http.response.code',
          'http.response_for.uri', 'http.request_in',
          'http.content_length_header', 'http.content_encoding',
          'http.transfer_encoding', 'http.file_data')


def _chunked_gzip_body(wire: bytes, max_bytes: int, status: int) -> bytes | None:
    """Verify one whole HTTP response, its chunk framing, and gzip checksum."""
    if len(wire) > max_bytes or not wire.startswith(b'HTTP/1.'):
        return None
    header_end = wire.find(b'\r\n\r\n', 0, 16384)
    if header_end < 0:
        return None
    header = wire[:header_end].split(b'\r\n')
    if (not header[0].startswith((b'HTTP/1.0 ', b'HTTP/1.1 ')) or
            header[0].split(b' ')[1] != str(status).encode()):
        return None
    fields = {}
    for line in header[1:]:
        if b':' not in line or line[:1] in (b' ', b'\t'):
            return None
        name, value = line.split(b':', 1)
        if (not name or any(not (48 <= char <= 57 or 65 <= char <= 90 or
                                 97 <= char <= 122 or char == 45) for char in name) or
                any(char < 32 and char != 9 or char == 127 for char in value)):
            return None
        key = name.strip().lower()
        if (not key or (key in fields and key in
                        (b'transfer-encoding', b'content-encoding', b'content-length'))):
            return None
        fields[key] = value.strip().lower()
    if (fields.get(b'transfer-encoding') != b'chunked' or
            fields.get(b'content-encoding') != b'gzip' or b'content-length' in fields):
        return None
    cursor = header_end + 4
    compressed = bytearray()
    terminal = False
    while cursor < len(wire):
        end = wire.find(b'\r\n', cursor, min(len(wire), cursor + 1024))
        if end < 0:
            return None
        size_field = wire[cursor:end]
        if not size_field or any(value not in b'0123456789abcdefABCDEF' for value in size_field):
            return None
        size = int(size_field, 16)
        cursor = end + 2
        if size == 0:
            while True:
                end = wire.find(b'\r\n', cursor, min(len(wire), cursor + 16384))
                if end < 0:
                    return None
                trailer = wire[cursor:end]
                cursor = end + 2
                if not trailer:
                    break
                if b':' not in trailer or trailer[:1] in (b' ', b'\t'):
                    return None
                name, value = trailer.split(b':', 1)
                if (not name or any(not (48 <= char <= 57 or 65 <= char <= 90 or
                                         97 <= char <= 122 or char == 45) for char in name) or
                        any(char < 32 and char != 9 or char == 127 for char in value)):
                    return None
            terminal = True
            break
        if size > max_bytes - len(compressed) or cursor + size + 2 > len(wire):
            return None
        compressed.extend(wire[cursor:cursor + size])
        cursor += size
        if wire[cursor:cursor + 2] != b'\r\n':
            return None
        cursor += 2
    if not terminal or cursor != len(wire):
        return None
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(bytes(compressed), max_bytes + 1)
        if (len(decoded) > max_bytes or not decoder.eof or decoder.unused_data or
                decoder.unconsumed_tail):
            return None
        return decoded
    except zlib.error:
        return None


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
    base = [TSHARK, '-r', source, '-n', '-o', 'tcp.try_heuristic_first:TRUE',
            '-o', 'tcp.reassemble_out_of_order:TRUE']
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
            response_code = one('http.response.code')
            if not response_code or one('http.request.method'):
                warnings.append(f"frame {one('frame.number')}: HTTP body lacks unambiguous response evidence")
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
                              'status': int(response_code),
                              'encoding': encoding or None,
                              'transfer_encoding': transfer or None,
                              'length_verified': bool(length and not encoding and not transfer)})
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        return [], [f'invalid TShark HTTP metadata; export incomplete: {error}']
    if not responses:
        return [], warnings or (['no complete frame-linked HTTP body found'] if saw_http else [])
    directions, stream_warnings = reassemble_tcp(
        path, timeout=max(.01, deadline - time.monotonic()), max_output=max_output,
        max_streams=128, max_bytes=min(max_source_bytes, max_total_bytes * 2))
    if not directions:
        return [], warnings + stream_warnings + ['TCP direction check unavailable; HTTP export withheld']
    checked = []
    for response in responses:
        matches = [item for item in directions if item['stream'] == response['tcp_stream']
                   and response['packet'] in item['frames']]
        if len(matches) != 1:
            warnings.append(f"frame {response['packet']}: TCP response direction ambiguous or unavailable")
            continue
        direction = matches[0]
        unsafe = {'missing TCP segment', 'contradictory retransmission',
                  'packet capture truncated', 'connection reset', 'payload after FIN',
                  'inconsistent SYN sequence', 'inconsistent FIN sequence',
                  'sequence or byte limit reached', 'byte limit reached'}
        if unsafe.intersection(direction['reasons']):
            warnings.append(f"frame {response['packet']}: TCP response direction incomplete or "
                            f"conflicting ({', '.join(direction['reasons'])})")
            continue
        maximum = 0
        reordered = False
        ranges = []
        for segment in direction['segments']:
            start = (segment['start'] - direction['sequence_start']) & 0xffffffff
            end = (segment['end'] - direction['sequence_start']) & 0xffffffff
            if start < maximum and not any(low <= start and end <= high
                                           for low, high in ranges):
                reordered = True
            maximum = max(maximum, end)
            ranges.append((start, end))
        covered = 0
        gap = False
        for start, end in sorted(ranges):
            if start > covered:
                gap = True
                break
            covered = max(covered, end)
        if gap:
            warnings.append(f"frame {response['packet']}: TCP response direction has missing bytes")
            continue
        if reordered and not direction['complete']:
            warnings.append(f"frame {response['packet']}: reordered TCP response lacks complete direction")
            continue
        if (response['transfer_encoding'] == 'chunked' and
                response['encoding'] == 'gzip' and direction['complete']):
            decoded = _chunked_gzip_body(direction['data'], max_total_bytes,
                                         response['status'])
            if decoded is not None and (len(decoded), hashlib.sha256(decoded).hexdigest()) == (
                    response['size'], response['sha256']):
                response['wire_verification'] = 'chunked-gzip-wire'
        if response['length_verified']:
            response['wire_verification'] = 'Content-Length'
        checked.append(response)
    responses = checked
    if not responses:
        return [], warnings or ['no independently checked HTTP response body found']
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
                        'length_verified': all(match['length_verified'] for match in matches),
                        'wire_verification': (matches[0].get('wire_verification')
                                              if len(matches) == 1 else None)})
        if len(matches) > 1:
            warnings.append(f'object {index}: identical body in multiple HTTP responses; references ambiguous')
        if not records[-1]['wire_verification']:
            warnings.append(f'object {index}: wire completeness not independently verified')
    return records, warnings
