"""Bounded XOR guesses using printable and English-frequency evidence."""

import re
from collections import Counter


_COMMON_WORDS = frozenset(
    b"a about after all an and are as at be but by can data do file for from have "
    b"hello in into is it key line message not of on one or our out read secret "
    b"some text that the their there these this to two was we were what when which "
    b"with world would you your".split()
)
_WORDS = re.compile(rb"[A-Za-z]{2,}")
_FLAG_TOKEN = re.compile(rb"[A-Za-z][A-Za-z0-9_]{2,31}\{[A-Za-z0-9_!@#$%^&*()+,./:=?+-]{6,128}\}\r?\n?")
MIN_FLAG_TOKEN_BYTES = 3 + 2 + 6  # minimum prefix, braces, and body in _FLAG_TOKEN
_MAX_INPUT = 1 << 20
_ENGLISH = b" etaoinshrdlcumwfgypbvkjxqz"
_LETTER_SCORE = {byte: 2.5 - rank * 0.08 for rank, byte in enumerate(_ENGLISH)}
_BYTE_SCORE = tuple(
    _LETTER_SCORE.get(byte, _LETTER_SCORE.get(byte + 32, -0.5) - 0.6)
    if 65 <= byte <= 90 or 97 <= byte <= 122 or byte == 32
    else 0.1 if byte in (9, 10, 13) or 33 <= byte <= 126 else -5.0
    for byte in range(256)
)


def recover_single_byte(data: bytes, *, max_candidates: int = 8) -> list[dict]:
    """Exhaust all 256 keys and rank English or flag-shaped candidates, never validation."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > _MAX_INPUT:
        raise ValueError("single-byte XOR input exceeds 1 MiB")
    if len(data) < MIN_FLAG_TOKEN_BYTES or max_candidates <= 0:
        return []

    counts = Counter(data)
    candidates = []
    for key in range(256):
        printable = sum(count for byte, count in counts.items()
                        if 32 <= byte ^ key <= 126 or byte ^ key in (9, 10, 13))
        letters = sum(count for byte, count in counts.items()
                      if 65 <= byte ^ key <= 90 or 97 <= byte ^ key <= 122)
        if printable / len(data) < 0.8 or (len(data) > 164 and letters / len(data) < 0.35):
            continue
        recovered = data.translate(bytes(byte ^ key for byte in range(256)))
        flag_shaped = len(data) <= 164 and _FLAG_TOKEN.fullmatch(recovered) is not None
        words = [match.group().lower() for match in _WORDS.finditer(recovered)]
        common = sum(word in _COMMON_WORDS for word in words)
        if not flag_shaped and (len(data) < 16 or letters / len(data) < 0.35 or
                                len(words) < 3 or common < 2):
            continue
        candidates.append({
            "data": recovered,
            "key_hex": f"{key:02x}",
            "score": round((1000 if flag_shaped else common * 10) +
                           printable / len(data) + letters / len(data), 4),
            "rationale": (f"{printable}/{len(data)} printable bytes; flag-shaped token; key unverified"
                          if flag_shaped else
                          f"{printable}/{len(data)} printable bytes; {common} common English words"),
            "state": "candidate",
        })
    candidates.sort(key=lambda candidate: (-candidate["score"], candidate["key_hex"]))
    return candidates[:min(max_candidates, 256)]


def recover_repeating_key(data: bytes, *, max_key_bytes: int = 16,
                          max_candidates: int = 8) -> list[dict]:
    """Rank repeating-XOR keys of 2–16 bytes from English text evidence."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > _MAX_INPUT:
        raise ValueError("repeating-key XOR input exceeds 1 MiB")
    if len(data) < 64 or max_key_bytes < 2 or max_candidates <= 0:
        return []

    sample = data[:8192]
    candidates = []
    seen = set()
    for length in range(2, min(16, max_key_bytes, len(sample) // 12) + 1):
        ranked = [sorted(range(256), key=lambda guess: sum(_BYTE_SCORE[byte ^ guess]
                          for byte in sample[offset::length]), reverse=True)[:3]
                  for offset in range(length)]
        initial = bytes(options[0] for options in ranked)

        def word_score(key):
            decoded = bytes(byte ^ key[index % length] for index, byte in enumerate(sample))
            common = sum(match.group().lower() in _COMMON_WORDS
                         for match in _WORDS.finditer(decoded))
            printable = sum(32 <= byte <= 126 for byte in decoded)
            return common, printable, sum(_BYTE_SCORE[byte] for byte in decoded)

        refined = initial
        for _ in range(2):
            for offset, options in enumerate(ranked):
                refined = max((refined[:offset] + bytes((guess,)) + refined[offset + 1:]
                               for guess in options), key=word_score)
        for key in (initial, refined):
            if any(key == key[:period] * (length // period)
                   for period in range(1, length) if length % period == 0):
                continue
            if key in seen:
                continue
            seen.add(key)
            recovered = bytes(byte ^ key[index % length] for index, byte in enumerate(data))
            printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in recovered)
            words = [match.group().lower() for match in _WORDS.finditer(recovered)]
            common = sum(word in _COMMON_WORDS for word in words)
            if printable / len(data) < 0.85 or common < max(3, len(data) // 48):
                continue
            candidates.append({
                "data": recovered,
                "key_hex": key.hex(),
                "key_length": length,
                "score": round(common * 10 + printable / len(data), 4),
                "rationale": f"{printable}/{len(data)} printable bytes; {common} common English words; "
                             f"{length}-byte repeating key inferred by character frequency "
                             "and English word coherence",
                "state": "candidate",
            })
    candidates.sort(key=lambda candidate: (-candidate["score"], candidate["key_hex"]))
    return candidates[:min(max_candidates, 256)]


def recover_repeating_crib(data: bytes, crib: bytes, *, max_key_bytes: int = 16,
                           max_candidates: int = 8) -> list[dict]:
    """Derive candidate keys from a literal crib with five repeated-key checks."""
    if not isinstance(data, bytes) or not isinstance(crib, bytes):
        raise TypeError("data and crib must be bytes")
    if len(data) > _MAX_INPUT or len(crib) > 256:
        raise ValueError("XOR crib search exceeds its input limit")
    if len(crib) < 6 or len(data) < len(crib) or max_key_bytes < 1 or max_candidates <= 0:
        return []

    candidates = []
    seen = set()
    for length in range(1, min(16, max_key_bytes, len(crib) - 5) + 1):
        differences = tuple(crib[index] ^ crib[index + length] for index in range(5))
        for offset in range(len(data) - len(crib) + 1):
            if data[offset] ^ data[offset + length] != differences[0]:
                continue
            if any(data[offset + index] ^ data[offset + index + length] != differences[index]
                   for index in range(1, 5)):
                continue
            stream = bytes(data[offset + index] ^ crib[index] for index in range(length))
            if any(data[offset + index] ^ crib[index] != stream[index % length]
                   for index in range(length, len(crib))):
                continue
            key = bytes(stream[(index - offset) % length] for index in range(length))
            if key in seen:
                continue
            seen.add(key)
            recovered = bytes(byte ^ key[index % length] for index, byte in enumerate(data))
            candidates.append({
                "data": recovered,
                "key_hex": key.hex(),
                "key_length": length,
                "crib_offset": offset,
                "crib_key_phase": offset % length,
                "score": len(crib) - length,
                "rationale": f"literal {len(crib)}-byte crib matched at offset {offset}; "
                             f"key index {offset % length} at crib offset; "
                             f"{len(crib) - length} repeating-key bytes checked; "
                             "full plaintext remains unverified",
                "state": "candidate",
            })
            if len(candidates) >= max_candidates:
                return candidates
    return candidates
