"""Finite, strict byte transformations for the autosolve artifact queue."""

import base64
import binascii
import bz2
import io
import lzma
import re
import urllib.parse
import zlib


_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_NUMERIC = (
    (rb"(?:dec|decimal):\s*(?:\d{1,3})(?:[\s,]+\d{1,3})+", 10, "decimal-bytes", True),
    (rb"(?:hex):\s*(?:[0-9a-f]{2})(?:[\s,]+[0-9a-f]{2})+", 16, "hex-bytes", True),
    (rb"(?:bin|binary):\s*(?:[01]{8})(?:[\s,]+[01]{8})+", 2, "binary-bytes", True),
    (rb"(?:0x[0-9a-f]{2})(?:[\s,]+0x[0-9a-f]{2})+", 16, "hex-bytes", False),
)


def _bit_blocks(data: bytes, max_output: int) -> list[tuple[bytes, str]]:
    candidates = []
    start = rows = bit_count = 0
    bits = bytearray()
    oversized = False
    line_number = 0

    def finish(end: int) -> None:
        if rows >= 2 and bit_count % 8 == 0 and not oversized:
            value = bytes(int(bits[index:index + 8], 2) for index in range(0, bit_count, 8))
            candidates.append((value, f"bit-text lines:{start}-{end} bits:{bit_count}"))

    for line_number, line in enumerate(io.BytesIO(data), 1):
        line = line.removesuffix(b"\n")
        if re.fullmatch(rb"[01 \t\r\f\v]+", line):
            count = line.count(b"0") + line.count(b"1")
            if count >= 8:
                if rows == 0:
                    start = line_number
                rows += 1
                bit_count += count
                if bit_count <= max_output * 8:
                    bits.extend(line.translate(None, b" \t\r\f\v"))
                else:
                    oversized = True
                continue
        finish(line_number - 1)
        start = rows = bit_count = 0
        bits.clear()
        oversized = False
    finish(line_number)
    return candidates


def _decompress(data: bytes, max_output: int, kind: str) -> tuple[bytes, str] | None:
    output = bytearray()
    member_sizes = []
    remaining = data
    try:
        while remaining:
            if kind == "gzip":
                decoder = zlib.decompressobj(31)
            elif kind == "zlib":
                decoder = zlib.decompressobj()
            elif kind == "bzip2":
                decoder = bz2.BZ2Decompressor()
            else:
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
            part = decoder.decompress(remaining, max_output - len(output) + 1)
            if len(output) + len(part) > max_output or not decoder.eof:
                return None
            output.extend(part)
            member_sizes.append(len(part))
            remaining = decoder.unused_data
    except (EOFError, OSError, ValueError, zlib.error, lzma.LZMAError):
        return None
    label = kind if len(member_sizes) == 1 else f"{kind} members:{','.join(map(str, member_sizes))}"
    return bytes(output), label


def decode(data: bytes, max_output: int) -> list[tuple[bytes, str]]:
    """Return exact one-step transformations; the caller owns recursion and trust decisions."""
    if max_output < 1:
        return []
    candidates: list[tuple[bytes, str]] = []
    wrapped = data.replace(b"\r", b"").replace(b"\n", b"")
    for name, decoder, encoder, max_length in (
        ("base16", lambda value: base64.b16decode(value, casefold=True), base64.b16encode, 2 * max_output),
        ("base32", lambda value: base64.b32decode(value, casefold=True), base64.b32encode, 8 * ((max_output + 4) // 5)),
        ("base64", lambda value: base64.b64decode(value, validate=True), base64.b64encode, 4 * ((max_output + 2) // 3)),
    ):
        if not wrapped or len(wrapped) > max_length:
            continue
        try:
            value = decoder(wrapped)
            canonical = wrapped.upper() if name != "base64" else wrapped
            if encoder(value) == canonical:
                if value != data and len(value) <= max_output:
                    candidates.append((value, name))
        except (binascii.Error, ValueError):
            pass

    if b"-" in wrapped or b"_" in wrapped:
        if re.fullmatch(rb"[A-Za-z0-9_-]+={0,2}", wrapped) and len(wrapped) <= 4 * ((max_output + 2) // 3):
            try:
                padded = wrapped + b"=" * (-len(wrapped) % 4)
                value = base64.b64decode(padded.translate(bytes.maketrans(b"-_", b"+/")), validate=True)
                canonical = base64.urlsafe_b64encode(value)
                if wrapped in (canonical, canonical.rstrip(b"=")) and len(value) <= max_output:
                    candidates.append((value, "base64url"))
            except (binascii.Error, ValueError):
                pass

    if b"%" in data and not re.search(rb"%(?![0-9a-fA-F]{2})", data):
        value = urllib.parse.unquote_to_bytes(data)
        if value != data and len(value) <= max_output:
            candidates.append((value, "url"))

    kind = None
    if data.startswith(b"\x1f\x8b"):
        kind = "gzip"
    elif len(data) >= 2 and data[0] & 15 == 8 and (data[0] << 8 | data[1]) % 31 == 0:
        kind = "zlib"
    elif data.startswith(b"BZh"):
        kind = "bzip2"
    elif data.startswith(b"\xfd7zXZ\x00"):
        kind = "xz"
    if kind:
        result = _decompress(data, max_output, kind)
        if result is not None and result[0] != data:
            candidates.append(result)

    if len(data) <= max_output and any(65 <= byte <= 90 or 97 <= byte <= 122 for byte in data):
        if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data):
            candidates.append((data.translate(_ROT13), "rot13"))

    for pattern, base, label, prefixed in _NUMERIC:
        if re.fullmatch(pattern, data.strip(), re.IGNORECASE):
            values = data.partition(b":")[2] if prefixed else data
            tokens = re.split(rb"[\s,]+", values.strip())
            try:
                value = bytes(int(token, base) for token in tokens)
            except ValueError:
                continue
            if len(value) <= max_output:
                candidates.append((value, label))
    candidates.extend(_bit_blocks(data, max_output))
    return candidates
