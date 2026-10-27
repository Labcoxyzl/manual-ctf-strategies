#!/usr/bin/env python3
"""Read one AndroidX Preferences DataStore key from a local .preferences_pb file.

Supports boolean, int32, int64 and string values. The format is AndroidX's
PreferenceMap, not an app-defined Proto DataStore schema:
https://android.googlesource.com/platform/frameworks/support/+/refs/heads/androidx-main/datastore/datastore-preferences-proto/src/main/proto/preferences.proto
"""
import argparse
import json
import os
import stat
import sys

MAX_BYTES = 1024 * 1024


def varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("protobuf varint exceeds 64 bits")
        value |= (byte & 0x7f) << (7 * index)
        if not byte & 0x80:
            if index and byte == 0:
                raise ValueError("noncanonical protobuf varint")
            return value, offset
    raise ValueError("protobuf varint exceeds 10 bytes")


def fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0 or wire not in (0, 1, 2, 5):
            raise ValueError("unsupported protobuf field or wire type")
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            length, offset = varint(data, offset)
            if length > len(data) - offset:
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        else:
            length = 8 if wire == 1 else 4
            if length > len(data) - offset:
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        yield number, wire, value


def signed(value, bits):
    if bits == 32:
        low = value & 0xffffffff
        result = low - (1 << 32) if low & (1 << 31) else low
        if result < 0 and value not in (low, (1 << 64) + result):
            raise ValueError("invalid int32 encoding")
        if result >= 0 and value != result:
            raise ValueError("invalid int32 encoding")
        return result
    return value - (1 << 64) if value & (1 << 63) else value


def parse_value(data, selected):
    items = list(fields(data))
    if len(items) != 1:
        raise ValueError("preference must contain exactly one value field")
    number, wire, value = items[0]
    if number == 1 and wire == 0:
        if value not in (0, 1):
            raise ValueError("invalid boolean encoding")
        return "boolean", bool(value)
    if number in (3, 4) and wire == 0:
        return ("integer" if number == 3 else "long"), signed(value, 32 if number == 3 else 64)
    if number == 5 and wire == 2:
        return "string", value.decode("utf-8")
    if (number, wire) in ((2, 5), (6, 2), (7, 1), (8, 2)):
        if selected:
            raise ValueError("selected key has an unsupported preference value type")
        if number == 6:
            for member_number, member_wire, member in fields(value):
                if (member_number, member_wire) != (1, 2):
                    raise ValueError("unsupported StringSet field")
                member.decode("utf-8")
        return None
    raise ValueError("unsupported preference value type")


def select_key(data, key):
    selected = None
    seen = set()
    for number, wire, entry in fields(data):
        if (number, wire) != (1, 2):
            raise ValueError("unsupported PreferenceMap field")
        name = value = None
        for item_number, item_wire, item in fields(entry):
            if (item_number, item_wire) == (1, 2) and name is None:
                name = item.decode("utf-8")
            elif (item_number, item_wire) == (2, 2) and value is None:
                value = item
            else:
                raise ValueError("duplicate or unsupported map entry field")
        if name is None or value is None:
            raise ValueError("incomplete preference map entry")
        if name in seen:
            raise ValueError("duplicate preference key")
        seen.add(name)
        parsed = parse_value(value, name == key)
        if name == key:
            selected = parsed
    if selected is None:
        raise ValueError("key absent in this copy; app-state absence is not established")
    return selected


def read_file(path):
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise ValueError("input must be a regular file, not a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular file")
        if before.st_size > MAX_BYTES:
            raise ValueError("input exceeds 1 MiB")
        data = source.read(MAX_BYTES + 1)
        after = os.fstat(source.fileno())
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds 1 MiB")
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("input changed during read; use a stable copy")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="local AndroidX Preferences DataStore .preferences_pb copy")
    parser.add_argument("key", help="exact preference key to inspect")
    args = parser.parse_args()
    try:
        kind, value = select_key(read_file(args.file), args.key)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Failed: {error}", file=sys.stderr)
        return 1
    print(f"type: {kind}\nvalue: {json.dumps(value, ensure_ascii=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
