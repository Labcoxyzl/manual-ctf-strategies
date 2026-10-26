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
    """Exhaust all 256 keys and return ranked English-looking candidates, never validation."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > _MAX_INPUT:
        raise ValueError("single-byte XOR input exceeds 1 MiB")
    if len(data) < 16 or max_candidates <= 0:
        return []

    counts = Counter(data)
    candidates = []
    for key in range(256):
        printable = sum(count for byte, count in counts.items()
                        if 32 <= byte ^ key <= 126 or byte ^ key in (9, 10, 13))
        letters = sum(count for byte, count in counts.items()
                      if 65 <= byte ^ key <= 90 or 97 <= byte ^ key <= 122)
        if printable / len(data) < 0.8 or letters / len(data) < 0.35:
            continue
        recovered = data.translate(bytes(byte ^ key for byte in range(256)))
        words = [match.group().lower() for match in _WORDS.finditer(recovered)]
        common = sum(word in _COMMON_WORDS for word in words)
        if len(words) < 3 or common < 2:
            continue
        candidates.append({
            "data": recovered,
            "key_hex": f"{key:02x}",
            "score": round(common * 10 + printable / len(data) + letters / len(data), 4),
            "rationale": f"{printable}/{len(data)} printable bytes; {common} common English words",
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
        key = bytes(max(range(256), key=lambda guess: sum(_BYTE_SCORE[byte ^ guess]
                           for byte in sample[offset::length])) for offset in range(length))
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
                         f"{length}-byte repeating key inferred by character frequency",
            "state": "candidate",
        })
    candidates.sort(key=lambda candidate: (-candidate["score"], candidate["key_hex"]))
    return candidates[:min(max_candidates, 256)]
