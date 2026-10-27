"""Bounded, offline normalization of candump, ASC, and BLF logs."""

import io
import math
import os
import re
import stat
import struct
import zlib
from pathlib import Path


_TIME = r"\d+(?:\.\d+)?"
_STAMPED = re.compile(rf"^\(({_TIME})\)\s+(\S+)\s+(.+)$")
_ASC_ROW = re.compile(rf"^({_TIME})\s+(\S+)\s+(.+)$")
_LONG = re.compile(r"^([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})\s+\[(\d{1,2})\]\s*(.*)$")
_UNSTAMPED = re.compile(r"^\S+\s+(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})(?:#|\s+\[)")
_HEX = re.compile(r"[0-9A-Fa-f]+\Z")
_FD_LENGTHS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64)
_BLF_EXPANDED_LIMIT = 32 * 1024 * 1024
_BLF_FD64 = struct.Struct('<BBBBLLLLLLLHBBL')
_BLF_BODY_SIZES = {1: struct.calcsize('<HBBL8s'),
                   86: struct.calcsize('<HBBL8s'),
                   73: struct.calcsize('<HHLBBBxLLH2x8s'),
                   100: struct.calcsize('<HBBLLBBB5x64s'),
                   101: _BLF_FD64.size}


def _id(token: str, *, asc: bool = False, base: int = 16) -> tuple[str, bool]:
    extended = token.lower().endswith("x") if asc else len(token) == 8
    digits = token[:-1] if asc and extended else token
    if not digits or (not _HEX.fullmatch(digits) if base == 16 else not digits.isdecimal()):
        raise ValueError("invalid CAN ID")
    if not asc and len(digits) not in (3, 8):
        raise ValueError("invalid CAN ID width")
    identifier = int(digits, base)
    if identifier > (0x1FFFFFFF if extended else 0x7FF):
        raise ValueError("CAN ID out of range")
    return f"{identifier:0{8 if extended else 3}X}", extended


def _bytes(tokens: list[str], *, base: int) -> str:
    data = []
    for token in tokens:
        if ((base == 16 and (len(token) > 2 or not _HEX.fullmatch(token)))
                or (base == 10 and not token.isdecimal())):
            raise ValueError("invalid payload byte")
        value = int(token, base)
        if value > 255:
            raise ValueError("payload byte out of range")
        data.append(value)
    return bytes(data).hex().upper()


def _compact_bytes(data: str, *, fd: bool = False) -> str:
    if fd and data.startswith("."):
        data = data[1:]
    if data and not re.fullmatch(r"[0-9A-Fa-f]{2}(?:\.?[0-9A-Fa-f]{2})*", data):
        raise ValueError("invalid compact CAN payload")
    return data.replace(".", "").upper()


def _record(timestamp: str, basis: str, bus: str, can_id: str, extended: bool,
            dlc: int, payload_hex: str, frame_type: str, source_line: int,
            raw_line: str, format_name: str, *, date_header: str | None = None,
            direction: str | None = None, fd_flags: int | None = None,
            dlc_basis: str = "declared") -> dict:
    return {"timestamp": timestamp, "timestamp_basis": basis,
            "date_header": date_header, "bus": bus, "can_id": can_id,
            "extended": extended, "dlc": dlc, "dlc_basis": dlc_basis,
            "payload_hex": payload_hex, "payload_length": len(payload_hex) // 2,
            "frame_type": frame_type, "fd_flags": fd_flags,
            "direction": direction, "format": format_name,
            "source_line": source_line, "raw_line": raw_line}


def _stamped(line: str, number: int) -> dict:
    match = _STAMPED.fullmatch(line)
    if not match:
        raise ValueError("malformed timestamped CAN row")
    timestamp, bus, body = match.groups()
    body = re.sub(r"\s+[RT]$", "", body)
    basis = "unix_epoch" if int(timestamp.split(".", 1)[0]) >= 1_000_000_000 else "unknown"
    if "#" in body:
        identifier, data = body.split("#", 1)
        can_id, extended = _id(identifier)
        if data.startswith("#"):
            if len(data) < 2 or data[1] not in "0123456789abcdefABCDEF":
                raise ValueError("invalid CAN FD flags")
            flags = int(data[1], 16)
            payload = _compact_bytes(data[2:], fd=True)
            length = len(payload) // 2
            if length > 64:
                raise ValueError("CAN FD payload exceeds 64 bytes")
            dlc = next(code for code, wire_length in enumerate(_FD_LENGTHS)
                       if wire_length >= length)
            return _record(timestamp, basis, bus, can_id, extended, dlc,
                           payload, "fd", number, line, "candump",
                           fd_flags=flags, dlc_basis="inferred_from_length")
        if data.upper().startswith("R"):
            if not re.fullmatch(r"[Rr][0-8]?", data):
                raise ValueError("invalid remote-frame DLC")
            return _record(timestamp, basis, bus, can_id, extended,
                           int(data[1:] or "0"), "", "remote", number, line, "candump")
        payload = _compact_bytes(data)
        if len(payload) > 16:
            raise ValueError("classic CAN payload exceeds 8 bytes")
        return _record(timestamp, basis, bus, can_id, extended, len(payload) // 2,
                       payload, "data", number, line, "candump")

    match = _LONG.fullmatch(body)
    if not match:
        raise ValueError("malformed can-utils long row")
    identifier, length_text, tail = match.groups()
    can_id, extended = _id(identifier)
    length = int(length_text)
    if length > 64:
        raise ValueError("declared CAN length exceeds 64 bytes")
    if tail == "remote request":
        if length > 8:
            raise ValueError("remote-frame DLC exceeds 8")
        payload, frame_type, dlc, dlc_basis = "", "remote", length, "declared"
    else:
        payload_tokens = tail.split("'", 1)[0].split()
        payload = _bytes(payload_tokens, base=16)
        if len(payload_tokens) != length:
            raise ValueError("declared length differs from payload length")
        frame_type = "fd" if length > 8 else "data"
        dlc = next(code for code, wire_length in enumerate(_FD_LENGTHS)
                   if wire_length >= length) if length > 8 else length
        dlc_basis = "inferred_from_length" if length > 8 else "declared"
    return _record(timestamp, basis, bus, can_id, extended, dlc, payload,
                   frame_type, number, line, "can_utils_long", dlc_basis=dlc_basis)


def _asc(line: str, number: int, *, base: int, basis: str,
         date_header: str | None) -> dict:
    match = _ASC_ROW.fullmatch(line)
    if not match:
        raise ValueError("malformed ASC row")
    timestamp, channel, rest = match.groups()
    fields = rest.split()
    if channel.upper() == "CANFD":
        if len(fields) < 7 or not fields[0].isdecimal() or fields[1] not in ("Rx", "Tx"):
            raise ValueError("malformed ASC CAN FD row")
        bus, direction, identifier = fields[:3]
        can_id, extended = _id(identifier, asc=True, base=base)
        if fields[3] not in ("0", "1") or fields[4] not in ("0", "1"):
            raise ValueError("invalid ASC CAN FD flags")
        try:
            dlc = int(fields[5], base)
            length = int(fields[6], 10)
        except ValueError as error:
            raise ValueError("invalid ASC CAN FD length") from error
        if dlc > 15 or length != _FD_LENGTHS[dlc]:
            raise ValueError("ASC CAN FD DLC/data length mismatch")
        tail = fields[7:]
        if len(tail) not in (length, length + 8):
            raise ValueError("ASC CAN FD payload length mismatch")
        if len(tail) == length + 8 and not all(_HEX.fullmatch(token)
                                                for token in tail[length:]):
            raise ValueError("invalid ASC CAN FD metadata")
        payload = _bytes(tail[:length], base=base)
        flags = int(fields[3]) | (int(fields[4]) << 1)
        return _record(timestamp, basis, bus, can_id, extended, dlc, payload,
                       "fd", number, line, "asc", date_header=date_header,
                       direction=direction, fd_flags=flags)

    if not channel.isdecimal() or len(fields) < 4 or fields[1] not in ("Rx", "Tx"):
        raise ValueError("malformed ASC classic CAN row")
    identifier, direction, kind, length_text = fields[:4]
    can_id, extended = _id(identifier, asc=True, base=base)
    try:
        dlc = int(length_text, base)
    except ValueError as error:
        raise ValueError("invalid ASC DLC") from error
    if dlc > 8:
        raise ValueError("classic CAN DLC exceeds 8")
    if kind.lower() not in ("d", "r"):
        raise ValueError("unsupported ASC frame type")
    payload_tokens = fields[4:]
    if len(payload_tokens) != (0 if kind.lower() == "r" else dlc):
        raise ValueError("ASC declared length differs from payload length")
    payload = _bytes(payload_tokens, base=base)
    return _record(timestamp, basis, channel, can_id, extended, dlc, payload,
                   "remote" if kind.lower() == "r" else "data", number, line,
                   "asc", date_header=date_header, direction=direction)


def _blf(raw: bytes, max_frames: int) -> tuple[list[dict], list[str]]:
    try:
        import can
        from can.io.blf import BLFParseError, BLFReader
    except ImportError:
        return [], ['BLF parser unavailable: python-can 4.6.1 is required']
    version = tuple(int(part) for part in getattr(can, '__version__', '').split('.')[:3]
                    if part.isdecimal())
    if version < (4, 6, 1):
        return [], ['BLF parser too old: python-can 4.6.1 or newer is required']

    # BLFReader can silently swallow incomplete object tails and unbounded zlib expansion.
    if len(raw) < 144 or raw[:4] != b'LOGG':
        return [], ['BLF header missing or truncated']
    header_size = int.from_bytes(raw[4:8], 'little')
    file_size = int.from_bytes(raw[16:24], 'little')
    object_count = int.from_bytes(raw[32:36], 'little')
    if header_size < 144 or header_size > len(raw) or file_size != len(raw):
        return [], ['BLF header size mismatch or truncated file']
    expanded = bytearray()
    pos = header_size
    try:
        while pos < len(raw):
            if len(raw) - pos < 32:
                raise ValueError('truncated container')
            signature, head_size, _, size, kind = struct.unpack_from('<4sHHLL', raw, pos)
            if (signature != b'LOBJ' or head_size != 16 or kind != 10
                    or size < 32 or pos + size > len(raw)):
                raise ValueError('invalid or truncated container')
            method, expected = struct.unpack_from('<H6xL', raw, pos + 16)
            compressed = raw[pos + 32:pos + size]
            if expected > _BLF_EXPANDED_LIMIT - len(expanded):
                raise ValueError('expanded byte limit reached')
            if method == 0:
                data = compressed
            elif method == 2:
                decoder = zlib.decompressobj()
                data = decoder.decompress(compressed, expected + 1)
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise ValueError('truncated or overlong compressed container')
            else:
                raise ValueError('unsupported compression method')
            if len(data) != expected:
                raise ValueError('container length mismatch or truncated data')
            expanded.extend(data)
            pos += size + size % 4
            if pos > len(raw):
                raise ValueError('truncated container padding')

        pos = 0
        seen = 0
        skipped = 0
        can_objects = []
        while pos < len(expanded):
            if expanded[pos:pos + 4] != b'LOBJ':
                next_object = expanded.find(b'LOBJ', pos, pos + 8)
                if next_object < 0 and (len(expanded) - pos <= 7
                                        and not expanded[pos:].strip(b'\0')):
                    break
                if next_object < 0 or expanded[pos:next_object].strip(b'\0'):
                    raise ValueError('invalid object boundary')
                pos = next_object
            if len(expanded) - pos < 16:
                raise ValueError('truncated object header')
            _, head_size, version, size, kind = struct.unpack_from('<4sHHLL', expanded, pos)
            expected_header = 32 if version == 1 else 40 if version == 2 else None
            if (head_size != expected_header or size < head_size
                    or pos + size > len(expanded)):
                raise ValueError('invalid object header or truncated object')
            if kind in _BLF_BODY_SIZES and size - head_size < _BLF_BODY_SIZES[kind]:
                raise ValueError('truncated CAN object body')
            if kind == 100:
                fields = struct.unpack_from('<HBBLLBBB5x64s', expanded, pos + head_size)
                if fields[2] > 15 or fields[7] > _FD_LENGTHS[fields[2]]:
                    raise ValueError('invalid CAN FD length')
            if kind == 101:
                fields = _BLF_FD64.unpack_from(expanded, pos + head_size)
                dlc_code, valid_bytes, ext_data_offset = fields[1], fields[2], fields[13]
                data_end = ext_data_offset or size
                if (dlc_code > 15 or valid_bytes > _FD_LENGTHS[dlc_code] or
                        data_end > size or
                        valid_bytes > data_end - head_size - _BLF_FD64.size):
                    raise ValueError('CAN FD payload padded by reader')
            if kind not in (1, 86, 73, 100, 101):
                skipped += 1
            else:
                can_objects.append(seen + 1)
            seen += 1
            pos += size
            while pos < len(expanded) and expanded[pos] == 0 and pos % 4:
                pos += 1
        if seen != object_count:
            raise ValueError('object count mismatch or truncated objects')
        with BLFReader(io.BytesIO(raw)) as reader:
            frames = []
            warnings = []
            timestamp_basis = 'unix_epoch' if reader.start_timestamp > 0 else 'unknown'
            emitted = 0
            limited = False
            for number, message in enumerate(reader, 1):
                if len(frames) >= max_frames:
                    warnings.append(f'BLF frame limit reached ({max_frames})')
                    limited = True
                    break
                emitted = number
                if number > len(can_objects):
                    raise ValueError('reader emitted more CAN objects than source declares')
                if message.is_error_frame:
                    warnings.append(f'BLF message {number}: error frame skipped')
                    continue
                extended = message.is_extended_id
                identifier = message.arbitration_id
                data = bytes(message.data)
                dlc = message.dlc
                if (not math.isfinite(message.timestamp) or message.timestamp < 0
                        or not isinstance(message.channel, int) or message.channel < 0
                        or identifier < 0 or identifier > (0x1FFFFFFF if extended else 0x7FF)
                        or message.is_fd and (dlc not in _FD_LENGTHS or len(data) > dlc)
                        or not message.is_fd and (dlc > 8 or len(data) != (0 if message.is_remote_frame else dlc))
                        or message.is_remote_frame and data):
                    warnings.append(f'BLF message {number}: invalid CAN frame skipped')
                    continue
                code = _FD_LENGTHS.index(dlc) if message.is_fd else dlc
                frame = _record(str(message.timestamp), timestamp_basis,
                                f'can{message.channel}',
                                f'{identifier:0{8 if extended else 3}X}', extended,
                                code, data.hex().upper(),
                                'remote' if message.is_remote_frame else 'fd' if message.is_fd else 'data',
                                None, None, 'blf', direction='Rx' if message.is_rx else 'Tx',
                                fd_flags=(1 | int(message.bitrate_switch) << 1
                                          | int(message.error_state_indicator) << 2)
                                if message.is_fd else None,
                                dlc_basis='inferred_from_length' if message.is_fd else 'declared')
                frame['source_object'] = can_objects[number - 1]
                if message.is_fd:
                    frame['fd_flags_basis'] = 'blf_wire_edl_brs_esi'
                frames.append(frame)
            if not limited and emitted != len(can_objects):
                raise ValueError('reader skipped CAN objects')
            if skipped:
                warnings.append(f'BLF skipped {skipped} non-CAN objects')
            return frames, warnings
    except (OSError, ValueError, struct.error, zlib.error, BLFParseError) as error:
        return [], [f'BLF invalid or truncated: {error}']


def parse_can_log(path: Path, *, max_frames: int,
                  max_bytes: int) -> tuple[list[dict], list[str]]:
    """Preserve supported offline frames; report every rejected data row."""
    if max_frames < 0 or max_bytes < 0:
        raise ValueError("CAN limits must be nonnegative")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("CAN source must be a regular file")
        if before.st_size > max_bytes:
            return [], [f"CAN source byte limit reached ({max_bytes})"]
        raw = source.read(max_bytes + 1)
        after = os.fstat(source.fileno())
    if len(raw) > max_bytes:
        return [], [f"CAN source byte limit reached ({max_bytes})"]
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return [], ["CAN source changed during reading"]
    if raw.startswith(b'LOGG') or path.suffix.lower() == '.blf':
        return _blf(raw, max_frames)
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        return [], [f"CAN source has invalid text encoding: {error}"]

    frames: list[dict] = []
    warnings: list[str] = []
    base = 16
    basis = "unknown"
    date_header = None
    for number, original in enumerate(lines, 1):
        line = original.strip()
        if not line or line.startswith("//"):
            continue
        if line.lower().startswith("date "):
            date_header = line[5:]
            continue
        if line.lower().startswith("begin triggerblock "):
            date_header = line[19:]
            continue
        header = re.fullmatch(r"base\s+(hex|dec)(?:\s+timestamps\s+(absolute|relative))?",
                              line, re.IGNORECASE)
        if header:
            base = 16 if header[1].lower() == "hex" else 10
            stamp_kind = header[2].lower() if header[2] else None
            basis = "local_date_offset" if stamp_kind == "absolute" else (
                "relative_delta" if stamp_kind == "relative" else "unknown")
            continue
        if re.fullmatch(r"(?:no\s+)?internal events logged|end triggerblock",
                        line, re.IGNORECASE):
            continue
        if re.match(r"^\d+(?:\.\d+)?\s+Start of measurement$", line,
                    re.IGNORECASE):
            continue
        if len(frames) >= max_frames:
            warnings.append(f"line {number}: CAN frame limit reached ({max_frames})")
            break
        try:
            if line.startswith("("):
                frame = _stamped(line, number)
            elif _UNSTAMPED.match(line):
                frame = _stamped(f"(0) {line}", number)
                frame['timestamp'] = None
                frame['timestamp_basis'] = 'unknown'
                frame['format'] = 'candump_unstamped'
            else:
                frame = _asc(line, number, base=base, basis=basis,
                             date_header=date_header)
        except ValueError as error:
            warnings.append(f"line {number}: {error}")
            continue
        frame["raw_line"] = original
        frames.append(frame)
    return frames, warnings


def _worker_main():
    import json
    import resource
    import sys
    from multiprocessing.connection import Connection

    max_frames, max_bytes, request_limit, output_limit, pipe_fd = sys.argv[1:]
    pipe = Connection(int(pipe_fd), readable=False, writable=True)
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        request = sys.stdin.buffer.read(int(request_limit) + 1)
        if len(request) > int(request_limit):
            raise ValueError('CAN source path exceeds worker request limit')
        path = json.loads(request)
        if not isinstance(path, str):
            raise ValueError('CAN source path must be text')
        frames, warnings = parse_can_log(Path(path), max_frames=int(max_frames),
                                         max_bytes=int(max_bytes))
        result = json.dumps({'state': 'ok', 'frames': frames, 'warnings': warnings},
                            ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if len(result) > int(output_limit):
            result = b'{"state":"limit"}'
        pipe.send_bytes(result)
    except Exception as error:
        reason = str(error).replace('\n', ' ')[:256]
        pipe.send_bytes(json.dumps({'state': 'error',
                                    'error': f'{type(error).__name__}: {reason}'},
                                   ensure_ascii=True).encode('ascii'))
    finally:
        pipe.close()
