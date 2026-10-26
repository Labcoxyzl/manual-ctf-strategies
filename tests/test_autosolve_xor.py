import random
import unittest

from scripts.autosolve_lib.profiles.xor import recover_repeating_key, recover_single_byte


class XorTests(unittest.TestCase):
    def test_repeating_key_recovers_exact_bytes_and_key(self):
        plaintext = (b"The message is in the file and the key is in the data. "
                     b"Read the last line of the report to find the answer. ") * 5
        key = b"ICE"
        ciphertext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plaintext))
        candidates = recover_repeating_key(ciphertext)
        self.assertTrue(any(row["data"] == plaintext and row["key_hex"] == key.hex()
                            for row in candidates))
        self.assertTrue(all(row["state"] == "candidate" and "English" in row["rationale"]
                            for row in candidates))

    def test_repeating_key_held_out_phase_length_and_binary_edges(self):
        plaintext = (b"\x00\xff\x01" +
                     (b"Our team will read the next line and check the secret in the file. " * 8) +
                     b"\x00\x80")
        key = b"GREEN-7"
        start = 5
        ciphertext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plaintext))
        candidates = recover_repeating_key(ciphertext[start:])
        rotated_key = key[start:] + key[:start]
        self.assertTrue(any(row["data"] == plaintext[start:] and
                            row["key_hex"] == rotated_key.hex() for row in candidates))

    def test_repeating_key_random_stream_has_no_english_claim(self):
        rng = random.Random(2026)
        plaintext = b"The key for this message changes on every byte and this is the file. " * 5
        ciphertext = bytes(byte ^ rng.randrange(256) for byte in plaintext)
        self.assertEqual(recover_repeating_key(ciphertext), [])
        self.assertEqual(recover_repeating_key(b"short"), [])
        with self.assertRaises(ValueError):
            recover_repeating_key(b"A" * ((1 << 20) + 1))

    def test_independent_single_byte_keys_and_exact_bytes(self):
        for key, plaintext in (
            (0x00, b"Please read this message: the answer is in the last line.\n"),
            (0xA7, b"The quick report is ready; read the file and send it with the data.\r\n"),
            (0xFF, b"\x00\xffThe first line of this text is a message. The key is in the file.\n\x00"),
        ):
            with self.subTest(key=key):
                ciphertext = bytes(byte ^ key for byte in plaintext)
                candidates = recover_single_byte(ciphertext)
                self.assertTrue(candidates)
                self.assertEqual(candidates[0]["data"], plaintext)
                self.assertEqual(candidates[0]["key_hex"], f"{key:02x}")
                self.assertEqual(candidates[0]["state"], "candidate")
                self.assertIn("common English words", candidates[0]["rationale"])

    def test_misleading_space_frequency_does_not_hide_correct_candidate(self):
        plaintext = b"XXXX XXXX XXXX The file is ready and the message is in this text."
        ciphertext = bytes(byte ^ 0x56 for byte in plaintext)
        self.assertTrue(any(candidate["data"] == plaintext for candidate in recover_single_byte(ciphertext)))

    def test_random_and_otp_like_data_do_not_produce_english_claims(self):
        rng = random.Random(2016)
        for source in (
            bytes(rng.randrange(256) for _ in range(512)),
            bytes(byte ^ rng.randrange(256) for byte in
                  b"This message has ordinary English words and a different key for each byte."),
        ):
            with self.subTest(length=len(source)):
                self.assertEqual(recover_single_byte(source), [])

    def test_limits(self):
        self.assertEqual(recover_single_byte(b"short"), [])
        self.assertEqual(recover_single_byte(b"This text is in the file and this is the line.", max_candidates=0), [])
        with self.assertRaises(ValueError):
            recover_single_byte(b"A" * ((1 << 20) + 1))


if __name__ == "__main__":
    unittest.main()
