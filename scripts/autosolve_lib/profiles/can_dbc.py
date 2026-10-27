"""Apply a supplied DBC/ARXML to normalized offline CAN frames."""

import hashlib
import json
import math
import os
import stat
import time
from pathlib import Path


def decode_can_frames(frames: list[dict], database_path: Path, *, max_frames: int,
                      max_db_bytes: int, max_output_bytes: int,
                      timeout: float) -> tuple[list[dict], list[str]]:
    """Return source-linked signal records; unknown or undecodable frames stay raw."""
    if min(max_frames, max_db_bytes, max_output_bytes) < 0 or timeout <= 0:
        raise ValueError('CAN limits must be nonnegative and timeout positive')
    deadline = time.monotonic() + timeout
    rows: list[dict] = []
    warnings: list[str] = []
    budget = max_output_bytes

    def append(frame: dict, status: str, **details) -> bool:
        nonlocal budget
        row = {'frame': frame, 'status': status, 'signals': [], **details}
        size = len(json.dumps(row, ensure_ascii=False, allow_nan=False).encode('utf-8'))
        if size > budget:
            warnings.append(f'CAN signal output byte limit reached ({max_output_bytes})')
            return False
        rows.append(row)
        budget -= size
        return True

    def retain(status: str, reason: str) -> tuple[list[dict], list[str]]:
        warnings.append(reason)
        for frame in frames[:max_frames]:
            if not append(frame, status):
                break
        if len(frames) > max_frames:
            warnings.append(f'CAN signal frame limit reached ({max_frames})')
        return rows, warnings

    path = Path(database_path)
    kind = path.suffix.lower().lstrip('.')
    if kind not in ('dbc', 'arxml'):
        return retain('database_error', 'CAN signal database must be DBC or ARXML')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                return retain('database_error', 'CAN signal database must be a regular file')
            if before.st_size > max_db_bytes:
                return retain('database_error', f'CAN signal database byte limit reached ({max_db_bytes})')
            raw = source.read(max_db_bytes + 1)
            after = os.fstat(source.fileno())
        if len(raw) > max_db_bytes:
            return retain('database_error', f'CAN signal database byte limit reached ({max_db_bytes})')
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return retain('database_error', 'CAN signal database changed during reading')
    except OSError:
        return retain('database_error', 'CAN signal database must be a regular file')

    try:
        import cantools
    except ImportError:
        return retain('unavailable', 'cantools unavailable for CAN signal decoding')
    try:
        # cantools uses cp1252 for DBC and UTF-8 for ARXML by default.
        database = cantools.database.load_string(raw.decode('cp1252' if kind == 'dbc' else 'utf-8-sig'),
                                                  database_format=kind)
    except Exception as error:
        return retain('database_error', f'CAN signal database parse failed ({type(error).__name__})')
    database_hash = hashlib.sha256(raw).hexdigest()

    for frame in frames[:max_frames]:
        if time.monotonic() >= deadline:
            warnings.append('CAN signal decoding time limit reached')
            break
        line = frame.get('source_line', '?')
        try:
            frame_id = int(frame['can_id'], 16)
            data = bytes.fromhex(frame['payload_hex'])
            extended = frame['extended']
            if type(extended) is not bool or frame_id < 0 or frame_id > (0x1FFFFFFF if extended else 0x7FF):
                raise ValueError('CAN ID/frame format mismatch')
            if len(data) != frame['payload_length']:
                raise ValueError('payload length mismatch')
        except (KeyError, TypeError, ValueError) as error:
            warnings.append(f'line {line}: invalid normalized CAN frame ({error})')
            if not append(frame, 'invalid_frame', database_sha256=database_hash):
                break
            continue
        details = {'database_sha256': database_hash}
        if frame.get('frame_type') == 'remote':
            if not append(frame, 'remote', **details):
                break
            continue
        try:
            message = database.get_message_by_frame_id(frame_id,
                                                       force_extended_id=extended)
        except KeyError:
            warnings.append(f'line {line}: unknown ID {frame["can_id"]} in supplied {kind.upper()}')
            if not append(frame, 'unknown_id', **details):
                break
            continue
        details['message'] = message.name
        if message.length != len(data):
            warnings.append(f'line {line}: {message.name} length mismatch: '
                            f'{len(data)} bytes in frame, {message.length} in {kind.upper()}')
            if not append(frame, 'length_mismatch', **details):
                break
            continue
        if bool(message.is_fd) != (frame.get('frame_type') == 'fd'):
            warnings.append(f'line {line}: {message.name} CAN FD/frame type mismatch')
            if not append(frame, 'frame_type_mismatch', **details):
                break
            continue
        try:
            raw_values = message.decode(data, decode_choices=False, scaling=False,
                                        allow_truncated=False, allow_excess=False)
            values = message.decode(data, decode_choices=False, scaling=True,
                                    allow_truncated=False, allow_excess=False)
        except Exception as error:
            warnings.append(f'line {line}: {message.name} decode failed ({type(error).__name__})')
            if not append(frame, 'decode_error', **details):
                break
            continue
        signals = []
        out_of_range = []
        nonfinite = False
        for signal in message.signals:
            if signal.name not in raw_values:
                continue
            value = values[signal.name]
            if any(isinstance(number, float) and not math.isfinite(number)
                   for number in (raw_values[signal.name], value)):
                nonfinite = True
                break
            if ((signal.minimum is not None and value < signal.minimum)
                    or (signal.maximum is not None and value > signal.maximum)):
                out_of_range.append(signal.name)
            signals.append({'name': signal.name, 'raw': raw_values[signal.name],
                            'value': value, 'unit': signal.unit or None,
                            'start': signal.start, 'length': signal.length,
                            'byte_order': signal.byte_order, 'signed': signal.is_signed,
                            'is_multiplexer': signal.is_multiplexer,
                            'multiplexer_signal': signal.multiplexer_signal,
                            'multiplexer_ids': signal.multiplexer_ids,
                            'multiplexer_value': raw_values.get(signal.multiplexer_signal)})
        if nonfinite:
            warnings.append(f'line {line}: {message.name} nonfinite signal value')
            if not append(frame, 'decode_error', database_sha256=database_hash, message=message.name):
                break
            continue
        details['signals'] = signals
        if out_of_range:
            warnings.append(f'line {line}: {message.name} signal out of range: '
                            f'{", ".join(out_of_range)}')
        if not append(frame, 'out_of_range' if out_of_range else 'decoded', **details):
            break
    if len(frames) > max_frames:
        warnings.append(f'CAN signal frame limit reached ({max_frames})')
    return rows, warnings
