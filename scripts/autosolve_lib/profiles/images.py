"""Bounded inspection of appended image containers."""

import io
import os
import struct
import zipfile
import zlib
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class OutputLimit(ValueError):
    """A supported image tail was present but exceeded the configured output bound."""


def _valid_zip(tail: bytes, max_output: int) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(tail)) as archive:
            end = tail.rfind(b"PK\x05\x06")
            if (end < 0 or end + 22 > len(tail)
                    or end + 22 + int.from_bytes(tail[end + 20:end + 22], "little") != len(tail)):
                return False
            members = archive.infolist()
            if (members and min(member.header_offset for member in members) != 0
                    or not members and end != 0):
                return False
            if len(members) > 1024:
                raise OutputLimit('ZIP member count exceeds 1024')
            expanded = 0
            for member in members:
                start = member.header_offset
                if (start < 0 or start + 30 > archive.start_dir or start + 30 > len(tail)
                        or tail[start:start + 4] != b"PK\x03\x04"):
                    return False
                name_length, extra_length = struct.unpack_from("<HH", tail, start + 26)
                if (start + 30 + name_length + extra_length
                        + member.compress_size > archive.start_dir):
                    return False
                if member.flag_bits & 1:
                    continue  # Password-protected members remain structural leads.
                if expanded + member.file_size > max_output:
                    raise OutputLimit(f'ZIP member bytes exceed {max_output} output bytes')
                with archive.open(member) as stream:
                    while chunk := stream.read(65536):
                        expanded += len(chunk)
                        if expanded > max_output:
                            raise OutputLimit(f'ZIP member bytes exceed {max_output} output bytes')
            return True
    except OutputLimit:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, struct.error,
            EOFError, RuntimeError, NotImplementedError, zlib.error):
        return False


def _plausible_zip_at(source, offset: int, size: int) -> bool:
    """Check bounded ZIP footer and first local record before reporting a size limit."""
    footer_start = max(offset, size - 65557)
    source.seek(footer_start)
    footer = source.read(size - footer_start)
    end = footer.rfind(b"PK\x05\x06")
    if (end < 0 or end + 22 > len(footer)
            or footer_start + end + 22 + int.from_bytes(footer[end + 20:end + 22], "little") != size):
        return False
    try:
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            if not members:
                return footer_start + end == offset
            if min(member.header_offset for member in members) != offset:
                return False
            source.seek(offset)
            return source.read(4) == b"PK\x03\x04"
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, struct.error):
        return False


def _find_zip_tail(source, size: int, max_output: int, image_kind: str) -> tuple[bytes, dict] | None:
    gap_start = source.tell()
    window = source.read(min(size - gap_start, 65536 + 4))
    cursor = attempts = 0
    over_limit = False
    while (candidate := window.find(b"PK", cursor)) >= 0 and candidate <= 65536:
        cursor = candidate + 2
        if window[candidate:candidate + 4] not in (b"PK\x03\x04", b"PK\x05\x06"):
            continue
        attempts += 1
        if attempts > 16:
            raise OutputLimit(f"{image_kind} trailing ZIP candidate limit reached")
        offset = gap_start + candidate
        tail_size = size - offset
        if tail_size > max_output:
            over_limit = over_limit or _plausible_zip_at(source, offset, size)
            continue
        source.seek(offset)
        tail = source.read(tail_size)
        if len(tail) != tail_size or not _valid_zip(tail, max_output):
            continue
        padding = candidate - len(window[:candidate].lstrip(b"\x00 \t\r\n"))
        return tail, {"offset": offset, "padding_bytes": padding, "gap_bytes": candidate}
    if over_limit:
        raise OutputLimit(f"{image_kind} trailing ZIP exceeds {max_output} output bytes")
    return None


def extract_image_tail(path: Path, max_output: int) -> tuple[bytes, dict] | None:
    """Return a validated ZIP appended to a PNG or JPEG image."""
    with path.open("rb") as source:
        head = source.read(8)
    if head == PNG_SIGNATURE:
        return extract_png_tail(path, max_output)
    if head.startswith(b"\xff\xd8\xff"):
        return extract_jpeg_tail(path, max_output)
    return None


def extract_jpeg_tail(path: Path, max_output: int) -> tuple[bytes, dict] | None:
    """Return a ZIP within a bounded gap after a decoded JPEG EOI."""
    if max_output < 0:
        raise ValueError("output limit must be nonnegative")
    with path.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        if source.read(2) != b"\xff\xd8":
            return None
        seen_frame = seen_scan = in_scan = False
        while source.tell() < size:
            if source.read(1) != b"\xff":
                if in_scan:
                    continue
                return None
            marker = source.read(1)
            while marker == b"\xff":
                marker = source.read(1)
            if not marker:
                return None
            code = marker[0]
            if code == 0 and in_scan:
                continue
            if 0xd0 <= code <= 0xd7 and in_scan:
                continue
            if code == 0xd9:
                if not (seen_frame and seen_scan):
                    return None
                eoi_offset = source.tell() - 2
                result = _find_zip_tail(source, size, max_output, "JPEG")
                if result is None:
                    return None
                tail, evidence = result
                from PIL import Image
                try:
                    with Image.open(path) as image:
                        if image.format != 'JPEG':
                            return None
                        image.draft('L', (1, 1))
                        image.load()
                except (OSError, ValueError, SyntaxError, Image.DecompressionBombError):
                    return None
                return tail, {"kind": "zip", **evidence, "eoi_offset": eoi_offset,
                              "jpeg_markers_validated": True}
            if code in (0x00, 0xd8) or 0xd0 <= code <= 0xd7 or code == 0x01:
                return None
            length_bytes = source.read(2)
            if len(length_bytes) != 2:
                return None
            length = int.from_bytes(length_bytes, "big")
            if length < 2 or length - 2 > size - source.tell():
                return None
            if code in (0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
                        0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf):
                if length < 8 or seen_frame:
                    return None
                seen_frame = True
            if code == 0xda:
                if length < 6 or not seen_frame:
                    return None
                seen_scan = True
            source.seek(length - 2, os.SEEK_CUR)
            in_scan = code == 0xda
    return None


def extract_png_tail(path: Path, max_output: int) -> tuple[bytes, dict] | None:
    """Return a ZIP within a bounded gap after a structurally valid PNG IEND."""
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
                result = _find_zip_tail(source, size, max_output, "PNG")
                if result is None:
                    return None
                tail, evidence = result
                return tail, {"kind": "zip", **evidence, "iend_offset": chunk_start,
                              "iend_crc_validated": True, "png_chunks": chunks}
        return None
