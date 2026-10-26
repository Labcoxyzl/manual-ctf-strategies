import base64
import bz2
import gzip
import lzma
import unittest
import zlib

from scripts.autosolve_lib.profiles.encoding import decode


class EncodingTests(unittest.TestCase):
    def test_strict_base_decoding_preserves_alternatives_and_binary_bytes(self):
        self.assertIn((b"AB", "base16"), decode(b"4142", 3))
        self.assertIn((base64.b64decode(b"4142"), "base64"), decode(b"4142", 3))
        self.assertIn((b"foo", "base32"), decode(b"MZXW6===", 3))
        self.assertIn((b"foo", "base32"), decode(b"mzxw6===\r\n", 3))
        self.assertIn((b"\xfb\xef\xff", "base64url"), decode(b"--__", 3))
        self.assertIn((b"\xfb\xff", "base64url"), decode(b"-_8", 2))
        self.assertFalse(any(label == "base64url" for _, label in decode(b"-_8==", 100)))
        self.assertIn((b"hello", "base64"), decode(b"aGVs\nbG8=", 5))
        self.assertIn((b"\xc3\xa9\x00", "url"), decode(b"%c3%a9%00", 3))

    def test_invalid_base_and_url_text_is_not_silently_repaired(self):
        for source in (b"aGVsbG8", b"aGVsbG8==", b"aGVs!bG8=", b"aR=="):
            with self.subTest(source=source):
                self.assertFalse(any(label == "base64" for _, label in decode(source, 100)))
        self.assertFalse(any(label == "base32" for _, label in decode(b"MZXW6==", 100)))
        self.assertFalse(any(label == "url" for _, label in decode(b"%4G", 100)))
        self.assertFalse(any(label == "url" for _, label in decode(b"%41%", 100)))

    def test_supported_compression_returns_exact_bytes_and_member_sizes(self):
        payload = b"independent oracle\x00\xff"
        for label, compressed in (
            ("gzip", gzip.compress(payload)),
            ("zlib", zlib.compress(payload)),
            ("bzip2", bz2.compress(payload)),
            ("xz", lzma.compress(payload)),
        ):
            with self.subTest(label=label):
                self.assertIn((payload, label), decode(compressed, len(payload)))
                self.assertFalse(any(name.startswith(label) for _, name in decode(compressed[:-1], len(payload))))
                self.assertFalse(any(name.startswith(label) for _, name in decode(compressed + b"trailing", len(payload))))

        double = gzip.compress(b"one") + gzip.compress(b"two")
        self.assertIn((b"onetwo", "gzip members:3,3"), decode(double, 6))

    def test_three_layer_chain_reaches_independent_oracle(self):
        oracle = b"\x00\xff\xc3\xa9 challenge bytes"
        packed = gzip.compress(oracle)
        encoded = base64.b64encode(packed)
        source = b"".join(f"%{byte:02X}".encode() for byte in encoded)
        first = next(value for value, label in decode(source, 200) if label == "url")
        second = next(value for value, label in decode(first, 200) if label == "base64")
        third = next(value for value, label in decode(second, 200) if label == "gzip")
        self.assertEqual(third, oracle)

    def test_compression_expansion_limit_never_returns_prefix(self):
        bomb = zlib.compress(b"A" * 100_000)
        self.assertFalse(any(name == "zlib" for _, name in decode(bomb, 64)))
        self.assertFalse(any(name == "zlib" for _, name in decode(bomb, 0)))
        self.assertFalse(any(name == "base16" for _, name in decode(b"4142", 1)))

    def test_rot13_and_explicit_numeric_bytes_only(self):
        self.assertIn((b"Hello, World!", "rot13"), decode(b"Uryyb, Jbeyq!", 100))
        self.assertIn((b"Hi!", "decimal-bytes"), decode(b"dec: 72 105 33", 100))
        self.assertIn((b"Hi!", "hex-bytes"), decode(b"0x48 0x69 0x21", 100))
        self.assertIn((b"Hi!", "binary-bytes"), decode(b"bin: 01001000 01101001 00100001", 100))
        self.assertFalse(any(name == "decimal-bytes" for _, name in decode(b"72 105 33", 100)))
        self.assertFalse(any(name == "decimal-bytes" for _, name in decode(b"dec: 72 256 33", 100)))

    def test_multiline_bits_skip_header_and_preserve_line_evidence(self):
        source = b"Decoded data:\n01001000\n01101001\nEnd of record\n"
        self.assertIn((b"Hi", "bit-text lines:2-3 bits:16"), decode(source, 2))

    def test_multiline_bits_allow_byte_boundaries_across_rows(self):
        source = b"notes\r\n1111 1111 0000\r\n 0000 1100 0011 \r\nsummary\r\n"
        self.assertIn((b"\xff\x00\xc3", "bit-text lines:2-3 bits:24"), decode(source, 3))
        self.assertFalse(any(name.startswith("bit-text") for _, name in decode(source, 2)))

    def test_separate_multiline_blocks_keep_distinct_ranges(self):
        source = b"01001000\n01101001\nsection break\n01000001\n01000010"
        bit_results = [(value, label) for value, label in decode(source, 100) if label.startswith("bit-text")]
        self.assertEqual(bit_results, [
            (b"Hi", "bit-text lines:1-2 bits:16"),
            (b"AB", "bit-text lines:4-5 bits:16"),
        ])

    def test_multiline_bits_reject_short_mixed_and_numeric_prose(self):
        for source in (
            b"0100\n1000\n",
            b"01001000\n01x01001\n01101001\n",
            b"01001000\n0110100\n",
            b"Count: 10101010\nValue: 11110000\n",
            b"10101010\n",
            b"",
        ):
            with self.subTest(source=source):
                self.assertFalse(any(name.startswith("bit-text") for _, name in decode(source, 16)))
