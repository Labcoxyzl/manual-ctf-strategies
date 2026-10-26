"""Bounded, offline normalization of candump and common ASC text logs."""

import os
import re
import stat
from pathlib import Path


_TIME = r"\d+(?:\.\d+)?"
_STAMPED = re.compile(rf"^\(({_TIME})\)\s+(\S+)\s+(.+)$")
_ASC_ROW = re.compile(rf"^({_TIME})\s+(\S+)\s+(.+)$")
_LONG = re.compile(r"^([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})\s+\[(\d{1,2})\]\s*(.*)$")
_UNSTAMPED = re.compile(r"^\S+\s+(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})(?:#|\s+\[)")
_HEX = re.compile(r"[0-9A-Fa-f]+\Z")
_FD_LENGTHS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64)


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
