#!/usr/bin/env python3
"""Copy and edit for one challenge; the default only sends a harmless line."""
import argparse
import math
import sys
import time
from pathlib import Path


PROMPT = b"> "
PAYLOAD = b"hello"
MAX_READ = 4096


def receive_until(tube, delimiter, timeout):
    """Require the delimiter within a byte limit and a total time limit."""
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) < MAX_READ:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"waiting for {delimiter!r}; received {bytes(data)!r}")
        chunk = tube.recv(1, timeout=remaining)
        if not chunk:
            raise TimeoutError(f"waiting for {delimiter!r}; received {bytes(data)!r}")
        data.extend(chunk)
        if data.endswith(delimiter):
            return bytes(data)
    raise ValueError(f"delimiter {delimiter!r} absent within {MAX_READ} bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--local", metavar="BINARY", help="run this local executable")
    target.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="connect once over TCP")
    parser.add_argument("--timeout", type=float, default=5.0, help="seconds per receive stage (default: 5)")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    if args.remote:
        try:
            port = int(args.remote[1])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            parser.error("PORT must be an integer from 1 to 65535")

    try:
        from pwn import context, process, remote
        from pwnlib.exception import PwnlibException
    except ImportError:
        parser.error(f"pwntools is unavailable for {sys.executable}; use an interpreter with a working pwntools installation")
    context.log_level = "error"
    try:
        tube = (process([str(Path(args.local).resolve())], timeout=args.timeout)
                if args.local else remote(args.remote[0], port, timeout=args.timeout))
        with tube:
            receive_until(tube, PROMPT, args.timeout)
            # sendline adds a newline; change to send for a raw binary protocol.
            tube.sendline(PAYLOAD)
            reply = receive_until(tube, b"\n", args.timeout)
            print(f"Reply: {reply!r}")
        return 0
    except (EOFError, OSError, TimeoutError, ValueError, PwnlibException) as error:
        print(f"Failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
