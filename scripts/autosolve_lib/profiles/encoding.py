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
_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ENGLISH_WORDS = frozenset(
    b"hello world meet noon bring map secret message attack dawn flag code password "
    b"open door find hidden quick brown fox jumps over lazy dog the this that and "
    b"with from your have clue answer treasure cipher decode tomorrow today".split()
)
_NUMERIC = (
    (rb"(?:dec|decimal):\s*(?:\d{1,3})(?:[\s,]+\d{1,3})+", 10, "decimal-bytes", True),
    (rb"(?:hex):\s*(?:[0-9a-f]{2})(?:[\s,]+[0-9a-f]{2})+", 16, "hex-bytes", True),
    (rb"(?:bin|binary):\s*(?:[01]{8})(?:[\s,]+[01]{8})+", 2, "binary-bytes", True),
    (rb"(?:0x[0-9a-f]{2})(?:[\s,]+0x[0-9a-f]{2})+", 16, "hex-bytes", False),
)


def declared_classical(data: bytes, max_output: int, parameters: list[dict]) -> list[tuple[bytes, str]]:
    """Apply only explicitly supplied classical keys; each output remains a candidate."""
    if not data or len(data) > max_output:
        return []
    results = []
    for index, record in enumerate(parameters):
        family = record['family']
        if family == 'vigenere' and 'key' in record:
            key = record['key'].upper().encode('ascii')
            output = bytearray()
            cursor = 0
            for value in data:
                base = 65 if 65 <= value <= 90 else 97 if 97 <= value <= 122 else None
                if base is None:
                    output.append(value)
                else:
                    output.append(base + (value - base - (key[cursor % len(key)] - 65)) % 26)
                    cursor += 1
            results.append((bytes(output), f"vigenere:parameter_index={index}"))
        elif family == 'rail_fence' and 'rails' in record and record['rails'] <= len(data):
            rails = record['rails']
            counts = [0] * rails
            rail, direction = 0, 1
            for _ in data:
                counts[rail] += 1
                if rail == 0:
                    direction = 1
                elif rail == rails - 1:
                    direction = -1
                rail += direction
            offsets = [sum(counts[:index]) for index in range(rails)]
            output = bytearray(len(data))
            rail, direction = 0, 1
            for index in range(len(data)):
                output[index] = data[offsets[rail]]
                offsets[rail] += 1
                if rail == 0:
                    direction = 1
                elif rail == rails - 1:
                    direction = -1
                rail += direction
            results.append((bytes(output), f"rail_fence:rails={rails}"))
    return results


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


def _decompress(data: bytes, max_output: int, kind: str) -> tuple[tuple[bytes, str] | None, dict]:
    output = bytearray()
    members = []
    remaining = data
    record = {'kind': kind, 'status': 'complete', 'trailing_bytes': 0, 'members': members}
    signature = {'gzip': b'\x1f\x8b', 'bzip2': b'BZh', 'xz': b'\xfd7zXZ\x00'}.get(kind)
    while remaining:
        if members:
            if kind == 'xz' and remaining.startswith(b'\x00'):
                padding = len(remaining) - len(remaining.lstrip(b'\x00'))
                if padding % 4:
                    record['status'] = 'invalid'
                    record['trailing_bytes'] = len(remaining)
                    return None, record
                record['padding_bytes'] = record.get('padding_bytes', 0) + padding
                remaining = remaining[padding:]
                if not remaining:
                    break
            if kind == 'zlib':
                matches = (len(remaining) >= 2 and remaining[0] & 15 == 8 and
                           (remaining[0] << 8 | remaining[1]) % 31 == 0)
                partial = len(remaining) == 1 and remaining[0] & 15 == 8
            else:
                matches = remaining.startswith(signature)
                partial = signature.startswith(remaining)
            if not matches:
                record['status'] = 'truncated' if partial else 'trailing'
                record['trailing_bytes'] = len(remaining)
                if partial:
                    return None, record
                break
        if len(members) >= 256:
            record['status'] = 'limit'
            record['limit_reason'] = 'compressed member count exceeds 256'
            return None, record
        try:
            if kind == "gzip":
                decoder = zlib.decompressobj(31)
            elif kind == "zlib":
                decoder = zlib.decompressobj()
            elif kind == "bzip2":
                decoder = bz2.BZ2Decompressor()
            else:
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
            part = decoder.decompress(remaining, max_output - len(output) + 1)
        except (EOFError, OSError, ValueError, zlib.error, lzma.LZMAError):
            record['status'] = 'invalid'
            return None, record
        if len(output) + len(part) > max_output:
            record['status'] = 'limit'
            record['limit_reason'] = 'decoded output exceeds per-artifact byte limit'
            return None, record
        if not decoder.eof:
            record['status'] = 'truncated'
            return None, record
        start = len(data) - len(remaining)
        members.append({'input_start': start, 'input_end': len(data) - len(decoder.unused_data),
                        'output_start': len(output), 'output_end': len(output) + len(part)})
        output.extend(part)
        remaining = decoder.unused_data
    sizes = ','.join(str(member['output_end'] - member['output_start']) for member in members)
    label = kind if len(members) == 1 else f'{kind} members:{sizes}'
    if record['trailing_bytes']:
        label += f" trailing:{record['trailing_bytes']}"
    return (bytes(output), label), record


def _classical_score(data: bytes) -> int:
    if re.search(rb"(?i)\b(?:flag|ctf)\{[^\r\n{}]{2,128}\}", data):
        return 100
    matched = [len(word) for word in re.findall(rb"[a-z]+", data.lower())
               if word in _ENGLISH_WORDS]
    return sum(matched) if len(matched) >= 2 and sum(matched) >= 10 else 0


def _classical(data: bytes, max_output: int) -> list[tuple[bytes, str]]:
    # shortcut: classical hypotheses are for short printable text; longer texts need a streaming scorer.
    if not 6 <= len(data) <= min(4096, max_output):
        return []
    if sum(65 <= byte <= 90 or 97 <= byte <= 122 for byte in data) < 6:
        return []
    try:
        printable = all(char.isprintable() or char in "\t\n\r" for char in data.decode("utf-8"))
    except UnicodeDecodeError:
        return []
    if not printable:
        return []
    original_score = _classical_score(data)
    ranked = []
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        inverse = pow(a, -1, 26)
        for b in range(26):
            if (a, b) in ((1, 0), (1, 13)):
                continue
            mapping = bytes((inverse * (index - b)) % 26 + offset
                            for offset in (65, 97) for index in range(26))
            value = data.translate(bytes.maketrans(_ALPHABET, mapping))
            score = _classical_score(value)
            if score <= original_score or score == 0:
                continue
            if a == 1:
                label = f"caesar-shift:{-b}"
            elif (a, b) == (25, 25):
                label = "atbash"
            else:
                label = f"affine-decrypt:a={a},b={b}"
            ranked.append((score, value, label))
    ranked.sort(key=lambda row: (-row[0], row[2]))
    candidates = [(value, f"{label} (hypothesis; score={score})")
                  for score, value, label in ranked[:4]]
    words = re.findall(rb"[A-Za-z]{2,}", data)
    if not ranked and len(data) <= 128 and original_score == 0 and (
            any(byte >= 128 for byte in data) or len(words) >= 3):
        # shortcut: short structured text gets all Caesar shifts; unknown affine keys need a language clue.
        seen = {value for value, _ in candidates}
        for shift in range(1, 26):
            mapping = bytes((index - shift) % 26 + offset
                            for offset in (65, 97) for index in range(26))
            value = data.translate(bytes.maketrans(_ALPHABET, mapping))
            if value not in seen:
                candidates.append((value, f"caesar-shift:-{shift} (hypothesis; unranked)"))
    return candidates


def decode(data: bytes, max_output: int, diagnostics: list[dict] | None = None) -> list[tuple[bytes, str]]:
    """Return exact one-step transformations; the caller owns recursion and trust decisions."""
    kind = None
    if data.startswith(b"\x1f\x8b"):
        kind = "gzip"
    elif len(data) >= 2 and data[0] & 15 == 8 and (data[0] << 8 | data[1]) % 31 == 0:
        kind = "zlib"
    elif data.startswith(b"BZh"):
        kind = "bzip2"
    elif data.startswith(b"\xfd7zXZ\x00"):
        kind = "xz"
    if max_output < 1:
        if kind and diagnostics is not None:
            diagnostics.append({'kind': kind, 'status': 'limit', 'trailing_bytes': 0,
                                'members': [], 'limit_reason': 'decoded output budget exhausted'})
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

    if kind:
        result, diagnostic = _decompress(data, max_output, kind)
        if diagnostics is not None:
            diagnostics.append(diagnostic)
        if result is not None and result[0] != data:
            candidates.append(result)

    if len(data) <= max_output and any(65 <= byte <= 90 or 97 <= byte <= 122 for byte in data):
        if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data):
            candidates.append((data.translate(_ROT13), "rot13"))

    candidates.extend(_classical(data, max_output))

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
