#!/usr/bin/env python3
"""Decode a JWT from a local file; this does not verify its signature or claims."""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_TOKEN_BYTES = 16384


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def decode_json(part):
    if not part or not re.fullmatch(rb"[A-Za-z0-9_-]+", part):
        raise ValueError("header and payload must use base64url")
    decoded = base64.b64decode(part + b"=" * (-len(part) % 4), altchars=b"-_", validate=True)
    value = json.loads(decoded.decode("utf-8"), object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("header and payload must be JSON objects")
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="private local text file containing one compact JWT")
    args = parser.parse_args()
    try:
        path = Path(args.file)
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as source:
            source_stat = os.fstat(source.fileno())
            if not stat.S_ISREG(source_stat.st_mode):
                raise ValueError("input must be a regular file")
            if source_stat.st_size > MAX_TOKEN_BYTES:
                raise ValueError(f"token file exceeds {MAX_TOKEN_BYTES} bytes")
            token = source.read(MAX_TOKEN_BYTES + 1).strip()
        if len(token) > MAX_TOKEN_BYTES:
            raise ValueError(f"token exceeds {MAX_TOKEN_BYTES} bytes")
        parts = token.split(b".")
        if len(parts) != 3:
            raise ValueError("expected three JWT parts; encrypted JWE tokens are unsupported")
        header, payload = map(decode_json, parts[:2])
        if parts[2]:
            if not re.fullmatch(rb"[A-Za-z0-9_-]+", parts[2]):
                raise ValueError("signature must use base64url")
            base64.b64decode(parts[2] + b"=" * (-len(parts[2]) % 4), altchars=b"-_", validate=True)
        print("Header:", json.dumps(header, indent=2, ensure_ascii=False, sort_keys=True))
        print("Payload:", json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        print("Decoded only; signature and claims are unverified.")
        return 0
    except (OSError, ValueError, binascii.Error, UnicodeError) as error:
        print(f"Failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
