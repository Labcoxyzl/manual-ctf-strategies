"""Bounded, cancellable candidate scans over original and derived bytes."""

import hashlib
import io
import multiprocessing
import os
from pathlib import Path
import re
import resource
import time


CHUNK = 1024 * 1024
MAX_MATCH = 4096
MAX_SCAN = 64 * 1024 * 1024
MAX_UNIQUE = 128
MAX_LOCATIONS = 64
MAX_BLOCK_HITS = 4096


def _worker(data, patterns, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    hits = []
    oversized = False
    limited = False
    zero_width = False
    expressions = [(pattern.encode(), 'user pattern') for pattern in patterns] if patterns else [
        (rb'[ -~]{6,128}', 'printable text')]
    try:
        for expression, label in expressions:
            compiled = re.compile(expression)
            if any((probe_match := compiled.search(probe)) is not None and
                   probe_match.start() == probe_match.end()
                   for probe in (b'', b'A', b'0', b'\x00')):
                zero_width = True
                continue
            empty_count = 0
            for match in compiled.finditer(data):
                if match.start() == match.end():
                    zero_width = True
                    empty_count += 1
                    if empty_count >= MAX_BLOCK_HITS:
                        limited = True
                        break
                    continue
                if match.end() - match.start() > MAX_MATCH:
                    oversized = True
                    continue
                hits.append((match.start(), match.end(), match.group(), label))
                if len(hits) >= MAX_BLOCK_HITS:
                    limited = True
                    break
            if limited:
                break
        pipe.send((hits, oversized, limited, zero_width))
    finally:
        pipe.close()


def _scan_block(data, patterns, timeout):
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=_worker, args=(data, patterns, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout):
            return None, 'candidate pattern scan timed out'
        try:
            return parent.recv(), None
        except EOFError:
            return None, 'candidate pattern scan failed'
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join()
        parent.close()


def scan_candidates(source: bytes | Path, artifact_id: str, patterns: list[str],
                    deadline: float, max_scan: int = MAX_SCAN,
                    private_crib: bytes = b'') -> tuple[list[dict], list[str]]:
    """Scan raw bytes; every finding keeps exact offsets and a source artifact id."""
    if isinstance(source, bytes):
        stream = io.BytesIO(source)
        size = len(source)
    else:
        path = Path(source)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stream = os.fdopen(fd, 'rb')
        size = os.fstat(fd).st_size
    findings = {}
    warnings = []
    scanned = 0
    try:
        stop = min(size, max_scan)
        for start in range(0, stop, CHUNK):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warnings.append(f'candidate scan work budget ended after {scanned} bytes')
                break
            core_end = min(start + CHUNK, stop)
            segment_start = max(0, start - MAX_MATCH + 1)
            read_end = min(size, core_end + MAX_MATCH - 1)
            stream.seek(segment_start)
            actual = stream.read(read_end - segment_start)
            if len(actual) != read_end - segment_start:
                warnings.append(f'candidate scan input changed after {scanned} bytes')
                break
            # The sentinel prevents a regex $ anchor from matching an artificial chunk end.
            segment = actual if read_end == size else actual + b'\x00'
            result, error = _scan_block(segment, patterns, min(1.0, remaining))
            if error:
                warnings.append(f'{error} after {scanned} bytes')
                break
            hits, oversized, limited, zero_width = result
            for local_start, local_end, value, label in hits:
                absolute = segment_start + local_start
                if not start <= absolute < core_end or local_end > len(actual):
                    continue
                key = value
                if key not in findings:
                    if len(findings) >= MAX_UNIQUE:
                        warnings.append(f'candidate value limit reached after {core_end} bytes')
                        break
                    findings[key] = {
                        'state': 'candidate', 'artifact_id': artifact_id,
                        'source_locator': {'offset': absolute}, 'locations': [absolute],
                        'encoding': 'raw bytes', 'match_bytes': len(value),
                        'match_sha256': hashlib.sha256(value).hexdigest(),
                        # A partial regex match can expose a crib fragment, so hide every preview.
                        'evidence': ('[preview withheld for private known plaintext]' if private_crib
                                     else repr(value[:128])),
                        'operation': label,
                        'next_action': 'Verify against the challenge oracle.'}
                elif len(findings[key]['locations']) < MAX_LOCATIONS:
                    findings[key]['locations'].append(absolute)
                elif 'candidate location limit reached' not in warnings:
                    warnings.append('candidate location limit reached; later offsets omitted')
            scanned = core_end
            if oversized:
                warnings.append('candidate match exceeded the 4096-byte length limit')
            if limited:
                warnings.append(f'candidate block match limit reached after {scanned} bytes')
            if zero_width and 'zero-width pattern matches were skipped' not in warnings:
                warnings.append('zero-width pattern matches were skipped')
            if len(findings) >= MAX_UNIQUE:
                break
        if size > scanned and not any('budget ended' in w or 'timed out' in w or 'input changed' in w
                                      or 'value limit' in w for w in warnings):
            warnings.append(f'candidate scan covered first {scanned} of {size} bytes')
        if any('(?<=' in pattern or '(?<!' in pattern for pattern in patterns):
            warnings.append('regex lookbehind beyond 4095 bytes of chunk context is unsupported')
        return list(findings.values()), warnings
    finally:
        stream.close()
