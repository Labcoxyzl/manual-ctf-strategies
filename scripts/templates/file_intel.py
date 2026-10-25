#!/usr/bin/env python3
"""Read-only first look at a regular local file; never executes or extracts."""
import argparse
import os
from pathlib import Path
import re
import stat
import sys

SAMPLE_LIMIT = 1024 * 1024
STRING_LIMIT = 20
DISPLAY_LIMIT = 100


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    args = parser.parse_args()
    try:
        path = Path(args.file)
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("input must be a regular file")
        with path.open("rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("input must be a regular file")
            data = source.read(SAMPLE_LIMIT)
        print(f"File: {str(path)!r}")
        print(f"Size: {info.st_size} bytes; examined: {len(data)} bytes")
        print(f"Sample limit: {SAMPLE_LIMIT} bytes; sample truncated: {info.st_size > len(data)}")
        print("Hex preview: first 64 examined bytes (offsets in hexadecimal)")
        for offset in range(0, min(64, len(data)), 16):
            print(f"{offset:08x}: {data[offset:offset + 16].hex(' ')}")
        print("ASCII strings: printable bytes 0x20..0x7e, minimum 4 bytes; offsets in hexadecimal")
        count = 0
        more = False
        for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
            if count == STRING_LIMIT:
                more = True
                break
            value = match.group()
            display = repr(value[:DISPLAY_LIMIT].decode("ascii"))
            truncated = len(value) > DISPLAY_LIMIT or len(display) > DISPLAY_LIMIT
            display = display[:DISPLAY_LIMIT]
            suffix = " [display truncated]" if truncated else ""
            if info.st_size > len(data) and match.end() == len(data):
                suffix += " [string reaches sample boundary; continuation unknown]"
            print(f"{match.start():08x}: {display}{suffix}")
            count += 1
        print(f"Strings shown: {count}; line limit: {STRING_LIMIT}; display limit: {DISPLAY_LIMIT} characters per string")
        print(f"Additional strings in sample omitted: {more}")
        return 0
    except (OSError, ValueError) as error:
        print(f"Failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
