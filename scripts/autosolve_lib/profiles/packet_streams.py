"""Bounded, byte-exact TCP directions from an offline TShark capture."""

import json
import os
import selectors
import subprocess
import time
from pathlib import Path

from .packets import TSHARK


FIELDS = ('frame.number', 'frame.cap_len', 'frame.len', 'ip.src', 'ip.dst',
          'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.stream',
          'tcp.seq_raw', 'tcp.len', 'tcp.payload', 'tcp.flags.syn',
          'tcp.flags.fin', 'tcp.flags.reset')


def _tshark_rows(path: Path, timeout: float, max_output: int):
    argv = [TSHARK, '-r', str(path.resolve()), '-n', '-T', 'ek',
            *(part for field in FIELDS for part in ('-e', field))]
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        return [], [f'TShark unavailable: {error}']
    output, errors = bytearray(), bytearray()
    warning = None
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = 'TShark timed out; TCP streams incomplete'
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > max_output:
                    warning = 'TShark output limit reached; TCP streams incomplete'
                    break
                key.data.extend(chunk)
            if warning:
                break
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if warning:
        return [], [warning]
    if process.returncode:
        detail = errors.decode('utf-8', 'replace').strip().splitlines()
        return [], [f'TShark exited {process.returncode}; TCP streams incomplete: '
                    f'{detail[0][:200] if detail else "unknown error"}']
    rows = []
    try:
        for line in output.splitlines():
            item = json.loads(line)
            if 'index' in item:
                continue
            layers = item['layers']
            if not isinstance(layers, dict):
                raise ValueError('invalid layers')

            def one(name):
                values = layers.get(name.replace('.', '_'), [])
                if not isinstance(values, list) or len(values) > 1 or any(
                        not isinstance(value, str) for value in values):
                    raise ValueError(f'ambiguous {name}')
                return values[0] if values else ''

            stream = one('tcp.stream')
            if not stream:
                continue
            source = one('ipv6.src') or one('ip.src')
            target = one('ipv6.dst') or one('ip.dst')
            payload = bytes.fromhex(one('tcp.payload'))
            length = int(one('tcp.len') or 0)
            if not source or not target or len(payload) != length:
                raise ValueError('missing endpoint or TCP payload length mismatch')
            rows.append({
                'frame': int(one('frame.number')), 'stream': int(stream),
                'endpoint': (source, int(one('tcp.srcport'))),
                'target': (target, int(one('tcp.dstport'))),
                'seq': int(one('tcp.seq_raw')), 'payload': payload,
                'syn': one('tcp.flags.syn') == 'True',
                'fin': one('tcp.flags.fin') == 'True',
                'rst': one('tcp.flags.reset') == 'True',
                'truncated': int(one('frame.cap_len')) < int(one('frame.len')),
            })
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
        return [], [f'invalid TShark JSON output; TCP streams incomplete: {error}']
    return rows, []


def _direction(rows, stream, direction, source, tool, max_bytes):
    first = rows[0]
    syns = [item['seq'] for item in rows if item['syn']]
    base = (syns[0] + 1) & 0xffffffff if syns else min(item['seq'] for item in rows)
    reasons = []
    if not syns:
        reasons.append('SYN not captured')
    if any(seq != syns[0] for seq in syns):
        reasons.append('inconsistent SYN sequence')
    if any(item['rst'] for item in rows):
        reasons.append('connection reset')
    if any(item['truncated'] for item in rows):
        reasons.append('packet capture truncated')
    ranges, fins, conflicts, retransmissions = [], [], [], []
    for item in rows:
        start = (item['seq'] + int(item['syn']) - base) & 0xffffffff
        end = start + len(item['payload'])
        if start > max_bytes or end > max_bytes:
            reasons.append('sequence or byte limit reached')
            continue
        if item['payload']:
            ranges.append((start, end, item))
        if item['fin']:
            fins.append(end)
    expected = fins[0] if fins else None
    if not fins:
        reasons.append('FIN not captured')
    elif any(end != expected for end in fins):
        reasons.append('inconsistent FIN sequence')
    elif any(end > expected for _, end, _ in ranges):
        reasons.append('payload after FIN')
    if expected is not None and expected > max_bytes:
        reasons.append('byte limit reached')
    length = min(max_bytes, max([end for _, end, _ in ranges] + fins + [0]))
    data, seen = bytearray(length), bytearray(length)
    segments = []
    for start, end, item in ranges:
        payload = item['payload']
        overlap = False
        for offset, value in enumerate(payload, start):
            if seen[offset]:
                overlap = True
                if data[offset] != value and item['frame'] not in conflicts:
                    conflicts.append(item['frame'])
            else:
                seen[offset] = 1
                data[offset] = value
        if overlap and item['frame'] not in conflicts:
            retransmissions.append(item['frame'])
        segments.append({'frame': item['frame'],
                         'start': (base + start) & 0xffffffff,
                         'end': (base + end) & 0xffffffff})
    gaps = []
    if expected is not None and expected <= length:
        start = None
        for offset in range(expected):
            if not seen[offset] and start is None:
                start = offset
            elif seen[offset] and start is not None:
                gaps.append({'start': (base + start) & 0xffffffff,
                             'end': (base + offset) & 0xffffffff})
                start = None
        if start is not None:
            gaps.append({'start': (base + start) & 0xffffffff,
                         'end': (base + expected) & 0xffffffff})
    if gaps:
        reasons.append('missing TCP segment')
    if conflicts:
        reasons.append('contradictory retransmission')
    result = {
        'source': source, 'tool': tool, 'stream': stream, 'direction': direction,
        'locator': f'tcp.stream {stream} direction {direction}',
        'src_address': first['endpoint'][0], 'src_port': first['endpoint'][1],
        'dst_address': first['target'][0], 'dst_port': first['target'][1],
        'frames': [item['frame'] for item in rows], 'segments': segments,
        'sequence_start': base, 'sequence_end': (base + (expected if expected is not None
                                                        else length)) & 0xffffffff,
        'gaps': gaps, 'conflicts': conflicts, 'retransmissions': retransmissions,
        'complete': not reasons, 'reasons': reasons,
    }
    if not reasons:
        result['data'] = bytes(data[:expected])
    return result


def reassemble_tcp(path: Path, *, timeout: float, max_output: int,
                   max_streams: int, max_bytes: int) -> tuple[list[dict], list[str]]:
    """Return exact bytes only for SYN-to-FIN directions with no gaps or conflicts."""
    if min(timeout, max_output, max_streams, max_bytes) <= 0:
        raise ValueError('TCP stream limits must be positive')
    rows, warnings = _tshark_rows(path, timeout, max_output)
    if warnings:
        return [], warnings
    streams = {}
    for row in rows:
        if row['stream'] not in streams and len(streams) >= max_streams:
            if 'TCP stream count limit reached; later streams omitted' not in warnings:
                warnings.append('TCP stream count limit reached; later streams omitted')
            continue
        streams.setdefault(row['stream'], []).append(row)
    result = []
    remaining_bytes = max_bytes
    for stream, packets in sorted(streams.items()):
        endpoints = []
        for packet in packets:
            if packet['endpoint'] not in endpoints:
                endpoints.append(packet['endpoint'])
        targets = {endpoint: {packet['target'] for packet in packets
                              if packet['endpoint'] == endpoint}
                   for endpoint in endpoints}
        inconsistent = len(endpoints) > 2 or any(len(items) != 1 for items in targets.values())
        if len(endpoints) == 2:
            inconsistent |= any(targets[endpoint] != {endpoints[1 - index]}
                                for index, endpoint in enumerate(endpoints))
        if inconsistent:
            warnings.append(f'TCP stream {stream}: inconsistent endpoints; no bytes published')
            continue
        for direction, endpoint in enumerate(endpoints):
            group = [packet for packet in packets if packet['endpoint'] == endpoint]
            item = _direction(group, stream, direction, str(path.resolve()), TSHARK,
                              remaining_bytes)
            result.append(item)
            if item['complete']:
                remaining_bytes -= len(item['data'])
            if any(reason in item['reasons'] for reason in
                   ('missing TCP segment', 'contradictory retransmission',
                    'sequence or byte limit reached', 'byte limit reached')):
                warnings.append(f"TCP stream {stream} direction {direction} incomplete: "
                                f"{', '.join(item['reasons'])}")
    return result, warnings
