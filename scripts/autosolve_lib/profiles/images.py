"""Bounded inspection of appended image containers."""

import io
import os
import struct
import zipfile
import zlib
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class OutputLimit(ValueError):
    """A supported PNG tail was present but exceeded the configured output bound."""


def extract_png_tail(path: Path, max_output: int) -> tuple[bytes, dict] | None:
    """Return a ZIP appended immediately after a structurally valid PNG IEND."""
    if max_output < 0:
        raise ValueError("output limit must be nonnegative")

    with path.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        if source.read(8) != PNG_SIGNATURE:
            return None

        chunks = 0
        seen_idat = False
        while source.tell() + 12 <= size:
            chunk_start = source.tell()
            chunk_header = source.read(8)
            if len(chunk_header) != 8:
                return None
            length, kind = struct.unpack(">I4s", chunk_header)
            if (not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in kind)
                    or length > size - source.tell() - 4):
                return None
            if chunks == 0 and (kind != b"IHDR" or length != 13):
                return None
            if chunks and kind == b"IHDR":
                return None
            if kind == b"IEND" and (length != 0 or not seen_idat):
                return None

            crc = zlib.crc32(kind)
            remaining = length
            header = b""
            while remaining:
                block = source.read(min(remaining, 65536))
                if not block:
                    return None
                if kind == b"IHDR":
                    header += block
                crc = zlib.crc32(block, crc)
                remaining -= len(block)
            checksum = source.read(4)
            if len(checksum) != 4 or struct.unpack(">I", checksum)[0] != crc:
                return None

            if kind == b"IHDR":
                width, height, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", header)
                if (not width or not height or (depth, colour) not in {
                        (1, 0), (2, 0), (4, 0), (8, 0), (16, 0),
                        (8, 2), (16, 2), (1, 3), (2, 3), (4, 3), (8, 3),
                        (8, 4), (16, 4), (8, 6), (16, 6)}
                        or compression or filtering or interlace not in (0, 1)):
                    return None
            seen_idat = seen_idat or kind == b"IDAT"
            chunks += 1
            if kind == b"IEND":
                offset = source.tell()
                tail_size = size - offset
                if not tail_size:
                    return None
                if tail_size > max_output:
                    if source.read(4).startswith((b"PK\x03\x04", b"PK\x05\x06")):
                        raise OutputLimit(f"PNG trailing ZIP exceeds {max_output} output bytes")
                    return None
                tail = source.read(tail_size)
                if len(tail) != tail_size or not tail.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                    return None
                try:
                    with zipfile.ZipFile(io.BytesIO(tail)) as archive:
                        # The ZIP end record must account for the entire tail.
                        end = tail.rfind(b"PK\x05\x06")
                        if (end < 0 or end + 22 > len(tail)
                                or end + 22 + int.from_bytes(tail[end + 20:end + 22], "little") != len(tail)):
                            return None
                        for member in archive.infolist():
                            start = member.header_offset
                            if (start < 0 or start + 30 > archive.start_dir
                                    or tail[start:start + 4] != b"PK\x03\x04"):
                                return None
                            name_length, extra_length = struct.unpack_from("<HH", tail, start + 26)
                            if (start + 30 + name_length + extra_length
                                    + member.compress_size > archive.start_dir):
                                return None
                    return tail, {"kind": "zip", "offset": offset,
                                  "iend_offset": chunk_start, "iend_crc_validated": True,
                                  "png_chunks": chunks}
                except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError):
                    return None
        return None
