"""Bounded HTTP response recovery from a local TLS capture and explicit key log."""

import hashlib
import json
import shutil
import stat
import time
from pathlib import Path

from .packet_objects import TSHARK, _run


FIELDS = ('frame.number', 'frame.protocols', 'frame.cap_len', 'frame.len',
          'tcp.stream', 'http.request.method', 'http.request.uri',
          'http.response.code', 'http.response_for.uri', 'http.request_in',
          'http.content_length_header', 'http.content_encoding',
          'http.transfer_encoding', 'http.file_data', 'data.data')


def decrypt_tls_http(path: Path, keylog: Path | None, output_dir: Path, *, timeout: float,
                     max_objects: int = 32, max_total_bytes: int = 64 * 1024 * 1024,
                     max_output: int = 32 * 1024 * 1024,
                     max_source_bytes: int = 256 * 1024 * 1024,
                     max_keylog_bytes: int = 1024 * 1024) -> tuple[list[dict], list[str]]:
    """Return exact decrypted HTTP bodies with packet and stream provenance."""
    if min(timeout, max_objects, max_total_bytes, max_output, max_source_bytes,
           max_keylog_bytes) <= 0:
        raise ValueError('TLS limits must be positive')
    if keylog is None:
        return [], ['TLS key log missing; encrypted bytes were not decoded']
    path, keylog, output_dir = Path(path), Path(keylog), Path(output_dir)
    for name, source, limit in (('capture', path, max_source_bytes),
                                ('TLS key log', keylog, max_keylog_bytes)):
        if source.is_symlink() or not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
            return [], [f'{name} unavailable or symlinked']
        if source.stat().st_size > limit:
            return [], [f'{name} byte limit reached']
    if keylog.read_bytes().lstrip().startswith(b'-----BEGIN'):
        return [], ['server private key is not a TLS key log; forward-secret TLS requires session secrets']
    if output_dir.is_symlink() or output_dir.resolve() in (path.resolve(), keylog.resolve()):
        raise ValueError('TLS output directory must be separate and not a symlink')
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError('TLS output directory must be empty')
    created_output_dir = not output_dir.exists()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    argv = [TSHARK, '-r', str(path.resolve()), '-n',
            '-o', f'tls.keylog_file:{keylog.resolve()}',
            '-o', 'http.decompress_body:FALSE', '-T', 'ek',
            *(part for field in FIELDS for part in ('-e', field))]
    raw, error = _run(argv, time.monotonic() + timeout, max_output)
    if error:
        return [], [error.replace(str(keylog.resolve()), '<TLS key log>')
                    .replace('HTTP export', 'TLS decryption')]

    records, warnings, written_paths = [], [], []
    total, saw_tls, saw_http = 0, False, False
    try:
        for line in raw.splitlines():
            item = json.loads(line)
            fields = item.get('layers')
            if fields is None:
                continue
            if not isinstance(fields, dict):
                raise ValueError('invalid TShark row')

            def one(name):
                values = fields.get(name.replace('.', '_'), [])
                if not isinstance(values, list) or len(values) > 1 or any(
                        not isinstance(value, str) for value in values):
                    raise ValueError(f'ambiguous {name}')
                return values[0] if values else ''

            protocols = one('frame.protocols').split(':')
            if 'tls' not in protocols:
                continue
            saw_tls = True
            saw_http |= 'http' in protocols
            body = one('http.file_data') or (one('data.data') if 'data' in protocols else '')
            if not body:
                continue
            packet = int(one('frame.number'))
            if not one('http.response.code'):
                warnings.append(f'frame {packet}: decrypted HTTP data lacks a response reference')
                continue
            if int(one('frame.cap_len')) < int(one('frame.len')):
                warnings.append(f'frame {packet}: packet capture truncated')
                continue
            data = bytes.fromhex(body)
            length = one('http.content_length_header')
            transfer = one('http.transfer_encoding')
            if length and (not length.isdecimal() or
                           not transfer and len(data) != int(length)):
                warnings.append(f'frame {packet}: decrypted HTTP Content-Length mismatch')
                continue
            if len(records) >= max_objects or len(data) > max_total_bytes - total:
                warnings.append('TLS object count or byte limit reached; export incomplete')
                break
            name = f'decrypted-{packet}-{len(records)}.bin'
            destination = output_dir / name
            with destination.open('xb') as writer:
                written_paths.append(destination)
                writer.write(data)
            destination.chmod(0o600)
            total += len(data)
            stream = one('tcp.stream')
            locator = {'packet': packet, 'tcp_stream': int(stream) if stream else None,
                       'request_packet': int(one('http.request_in')) if one('http.request_in') else None,
                       'uri': one('http.response_for.uri') or None}
            records.append({'path': destination, 'name': name, 'index': len(records),
                            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                            'protocol': 'https', 'packet': packet,
                            'tcp_stream': locator['tcp_stream'],
                            'source_locator': locator, 'source_locators': [locator],
                            'verified': True,
                            'length_verified': bool(length and not transfer),
                            'decrypted_fields': {'http.response.code': one('http.response.code'),
                                                 'http.response_for.uri': locator['uri']}})
            if not records[-1]['length_verified']:
                warnings.append(f'frame {packet}: decrypted body length not independently verified')
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        if created_output_dir:
            shutil.rmtree(output_dir)
        else:
            for destination in written_paths:
                destination.unlink(missing_ok=True)
        return [], [f'invalid TShark TLS output; decryption incomplete: {error}']
    if not records:
        warnings.append('no matching decrypted HTTP response body found' if saw_tls else
                        'no TLS packets found in capture')
    return records, warnings
