#!/usr/bin/env python3
"""Extract a known number of bytes from 8-bit PCM WAV sample LSBs."""
import argparse
import os
from pathlib import Path
import stat
import sys
import wave

MAX_SOURCE = 16 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024


def extract(source_path, bits_per_sample, byte_count):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(source_path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("source must be a regular, non-symlink file")
        if info.st_size > MAX_SOURCE:
            raise ValueError("source exceeds 16 MiB")
        with wave.open(source, "rb") as wav:
            if wav.getsampwidth() != 1 or wav.getcomptype() != "NONE":
                raise ValueError("source must be uncompressed 8-bit PCM WAV")
            sample_count = (byte_count * 8 + bits_per_sample - 1) // bits_per_sample
            channels = wav.getnchannels()
            if sample_count > wav.getnframes() * channels:
                raise ValueError("requested bytes exceed WAV sample capacity")
            samples = wav.readframes((sample_count + channels - 1) // channels)
            if len(samples) < sample_count:
                raise ValueError("WAV sample data is truncated")
    result = bytearray()
    pending = 0
    pending_bits = 0
    mask = (1 << bits_per_sample) - 1
    for sample in samples[:sample_count]:
        # The sample's low bits and each payload byte are read most significant bit first.
        pending = (pending << bits_per_sample) | (sample & mask)
        pending_bits += bits_per_sample
        if pending_bits >= 8:
            pending_bits -= 8
            result.append((pending >> pending_bits) & 0xff)
            pending &= (1 << pending_bits) - 1
            if len(result) == byte_count:
                break
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="copied, regular 8-bit PCM WAV file")
    parser.add_argument("output", help="new file inside an existing private directory")
    parser.add_argument("--bits", type=int, required=True, choices=range(1, 9), metavar="1..8")
    parser.add_argument("--bytes", type=int, required=True, help="exact number of payload bytes to recover")
    args = parser.parse_args()
    if not 1 <= args.bytes <= MAX_OUTPUT:
        parser.error("--bytes must be between 1 and 1048576")
    try:
        output = Path(args.output)
        if not output.is_absolute() or output.name in ("", ".", ".."):
            raise ValueError("output must be an absolute new path in a private directory")
        data = extract(args.source, args.bits, args.bytes)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(directory).st_mode & 0o077:
                raise ValueError("output directory must not be accessible by group or others")
            fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as destination:
                    destination.write(data)
            except BaseException:
                os.unlink(output.name, dir_fd=directory)
                raise
        finally:
            os.close(directory)
        print(f"Recovered {len(data)} bytes to {output}; validate format/content separately.")
        return 0
    except (OSError, ValueError, EOFError, wave.Error) as error:
        print(f"Failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
