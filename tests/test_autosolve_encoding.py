import base64
import bz2
import gzip
import lzma
import unittest
import zlib

from scripts.autosolve_lib.profiles.encoding import decode, declared_classical


class EncodingTests(unittest.TestCase):
    def test_declared_classical_keys_recover_independent_ciphertexts(self):
        cases = (
            (b'Avfb th kim hzu czbrxf iyhvs anbjfb.',
             {'family': 'vigenere', 'key': 'ORBIT'}, b'Meet at the old bridge after sunset.'),
            ('Do wdogw sdlá plbc pd dfwbew, xffhz sz qsfzd fzbc.'.encode(),
             {'family': 'vigenere', 'key': 'SOL'},
             'La llave está bajo el puente, junto al farol rojo.'.encode()),
            (b'Bgel p mi.rn h ivrcmasa ingtitseostdh',
             {'family': 'rail_fence', 'rails': 3}, b'Bring the silver compass at midnight.'),
            (b'P wenitn octd wlefo  ar rd histtlc ae ieewo.esoltesecro,e pch kdbnbs hidalhtorneeeietn',
             {'family': 'rail_fence', 'rails': 4},
             b'Please follow the eastern corridor, then inspect the locked cabinet beside the window.'),
        )
        for wire, parameter, expected in cases:
            with self.subTest(parameter=parameter):
                results = declared_classical(wire, len(expected), [parameter])
                self.assertTrue(any(data == expected and label.startswith(parameter['family'] + ':')
                                    for data, label in results))
                self.assertEqual(declared_classical(wire, 4, [parameter]), [])

    def test_declared_vigenere_labels_do_not_expose_short_keys(self):
        results = declared_classical(b'IFMMP', 5, [
            {'family': 'vigenere', 'key': 'A'},
            {'family': 'vigenere', 'key': 'B'},
        ])
        self.assertEqual([label for _, label in results], [
            'vigenere:parameter_index=0', 'vigenere:parameter_index=1'])

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
                self.assertIn((payload, f"{label} trailing:8"),
                              decode(compressed + b"trailing", len(payload)))

        double = gzip.compress(b"one") + gzip.compress(b"two")
        self.assertIn((b"onetwo", "gzip members:3,3"), decode(double, 6))

    def test_concatenated_members_and_trailing_bytes_have_exact_boundaries(self):
        for kind, compress in (("gzip", gzip.compress), ("zlib", zlib.compress),
                               ("bzip2", bz2.compress), ("xz", lzma.compress)):
            with self.subTest(kind=kind):
                first, second = compress(b"left\x00"), compress(b"\xffright")
                diagnostics = []
                decoded = decode(first + second + b"TAIL", 11, diagnostics)
                self.assertIn((b"left\x00\xffright", f"{kind} members:5,6 trailing:4"), decoded)
                self.assertEqual(diagnostics, [{
                    'kind': kind, 'status': 'trailing', 'trailing_bytes': 4,
                    'members': [
                        {'input_start': 0, 'input_end': len(first),
                         'output_start': 0, 'output_end': 5},
                        {'input_start': len(first), 'input_end': len(first) + len(second),
                         'output_start': 5, 'output_end': 11},
                    ],
                }])

    def test_xz_aligned_stream_padding_keeps_members_and_offsets(self):
        first, second = lzma.compress(b'left'), lzma.compress(b'right')
        diagnostics = []
        decoded = decode(first + b'\x00' * 4 + second + b'\x00' * 8, 9, diagnostics)
        self.assertIn((b'leftright', 'xz members:4,5'), decoded)
        self.assertEqual(diagnostics, [{
            'kind': 'xz', 'status': 'complete', 'trailing_bytes': 0,
            'padding_bytes': 12,
            'members': [
                {'input_start': 0, 'input_end': len(first),
                 'output_start': 0, 'output_end': 4},
                {'input_start': len(first) + 4, 'input_end': len(first) + 4 + len(second),
                 'output_start': 4, 'output_end': 9},
            ],
        }])

    def test_xz_misaligned_padding_cannot_validate_joined_streams(self):
        first, second = lzma.compress(b'left'), lzma.compress(b'right')
        for wire in (first + b'\x00' * 3 + second, first + b'\x00' * 5):
            with self.subTest(length=len(wire)):
                diagnostics = []
                self.assertFalse(any(label.startswith('xz') for _, label in
                                     decode(wire, 100, diagnostics)))
                self.assertEqual(diagnostics[0]['status'], 'invalid')
                self.assertEqual(len(diagnostics[0]['members']), 1)

    def test_incomplete_following_member_and_expansion_limit_never_publish_prefix(self):
        first, second = gzip.compress(b"first"), gzip.compress(b"second")
        diagnostics = []
        self.assertFalse(any(name.startswith("gzip") for _, name in
                             decode(first + second[:-2], 100, diagnostics)))
        self.assertEqual(diagnostics[0]['status'], 'truncated')
        self.assertEqual(len(diagnostics[0]['members']), 1)
        diagnostics.clear()
        self.assertFalse(any(name.startswith("gzip") for _, name in
                             decode(first + second, 10, diagnostics)))
        self.assertEqual(diagnostics[0]['status'], 'limit')

    def test_empty_member_chain_has_finite_member_limit(self):
        diagnostics = []
        self.assertFalse(any(label.startswith('gzip') for _, label in
                             decode(gzip.compress(b'') * 257, 1, diagnostics)))
        self.assertEqual(diagnostics[0]['status'], 'limit')
        self.assertEqual(len(diagnostics[0]['members']), 256)

    def test_zero_output_budget_reports_compression_limit(self):
        diagnostics = []
        self.assertEqual(decode(gzip.compress(b'payload'), 0, diagnostics), [])
        self.assertEqual(diagnostics[0]['status'], 'limit')

    def test_compression_then_base64_order_reaches_exact_bytes(self):
        oracle = b'ENC{reverse_order}\x00\xff'
        compressed = gzip.compress(base64.b64encode(oracle), mtime=0)
        text = next(value for value, label in decode(compressed, 1024) if label == 'gzip')
        self.assertIn((oracle, 'base64'), decode(text, 1024))

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

    def test_classical_candidates_preserve_case_punctuation_and_parameters(self):
        for source, oracle, label in (
            (b"Tlla ha uvvu, iypun aol thw.", b"Meet at noon, bring the map.", "caesar-shift:-7"),
            (b"Svool, Dliow!", b"Hello, World!", "atbash"),
            (b"Rclla, Oaplx!", b"Hello, World!", "affine-decrypt:a=5,b=8"),
        ):
            with self.subTest(label=label):
                self.assertTrue(any(value == oracle and operation.startswith(label) and
                                    "hypothesis" in operation for value, operation in decode(source, 100)))

    def test_classical_flag_candidate_with_short_mixed_text(self):
        source = b"JXGU{Ue_2-Yzqh!}"
        self.assertTrue(any(value == b"FLAG{Go_2-Exit!}" and
                            operation.startswith("affine-decrypt:a=11,b=6") for value, operation in
                            decode(source, 100)))

    def test_classical_ascii_alphabet_preserves_non_english_utf8_payload(self):
        source = "SZH{Sihé_ñ}".encode()
        self.assertTrue(any(value == "CTF{Café_ñ}".encode() and
                            operation.startswith("affine-decrypt:a=5,b=8") for value, operation in
                            decode(source, 100)))

    def test_classical_caesar_retains_spanish_prose_as_bounded_hypothesis(self):
        source = "¡Nurg, ykñux! Bgsuy gr iglé.".encode()
        expected = "¡Hola, señor! Vamos al café.".encode()
        classical = [(value, operation) for value, operation in decode(source, 100)
                     if operation.startswith(("caesar-shift:", "affine-decrypt:", "atbash "))]
        self.assertTrue(any(value == expected and operation.startswith("caesar-shift:-6") and
                            "hypothesis" in operation for value, operation in classical))
        self.assertLessEqual(len(classical), 29)
        self.assertEqual(len({value for value, _ in classical}), len(classical))

    def test_classical_caesar_retains_short_ascii_non_english_prose(self):
        source = b"Qxuj, jvrpxb! Ejvxb ju yjazdn."
        expected = b"Hola, amigos! Vamos al parque."
        classical = [(value, operation) for value, operation in decode(source, 100)
                     if operation.startswith("caesar-shift:")]
        self.assertTrue(any(value == expected and operation.startswith("caesar-shift:-9") and
                            "hypothesis" in operation for value, operation in classical))
        self.assertLessEqual(len(classical), 25)

    def test_classical_candidates_are_bounded_and_avoid_unrelated_text(self):
        for source in (b"The quick brown fox jumps over the lazy dog.",
                       b"qzxjvknpmrtsbcyglqzxjvknpmrtsbcygl"):
            classical = [label for _, label in decode(source, 100)
                         if label.startswith(("caesar-shift:", "affine-decrypt:", "atbash"))]
            self.assertEqual(classical, [], source)
        self.assertLessEqual(len(decode(b"Tlla ha uvvu, iypun aol thw.", 100)), 6)
        self.assertFalse(any(label.startswith("affine-decrypt:") for _, label in
                             decode(b"JXGU{Ue_2-Yzqh!}", 4)))

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
