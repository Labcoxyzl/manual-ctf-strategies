#!/usr/bin/env python3
"""Editable read-only parser for a synthetic <4sI record: magic then uint32."""
import argparse
import os
import stat
import struct
import sys

RECORD = struct.Struct("<4sI")  # Explicit little endian, standard sizes, no padding.
MAGIC = b"CTF!"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--offset", type=lambda value: int(value, 0), default=0,
                        help="decimal or 0x-prefixed byte offset")
    args = parser.parse_args()
    if args.offset < 0:
        parser.error("--offset must be nonnegative")
    try:
        if not stat.S_ISREG(os.stat(args.file).st_mode):
            raise ValueError("input must be a regular file")
        with os.fdopen(os.open(args.file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("input must be a regular file")
            size = info.st_size
            if args.offset > size or RECORD.size > size - args.offset:
                raise ValueError(f"need {RECORD.size} bytes at offset {args.offset}; file has {size}")
            source.seek(args.offset)
            data = source.read(RECORD.size)
        if len(data) != RECORD.size:
            raise ValueError("record became truncated while reading")
        magic, value = RECORD.unpack(data)
        if magic != MAGIC:
            raise ValueError(f"unexpected magic {magic!r}")
        print(f"offset={args.offset} magic={magic!r} value={value}")
        return 0
    except (OSError, ValueError, OverflowError) as error:
        print(f"Failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
