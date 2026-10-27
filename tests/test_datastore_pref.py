"""Independent wire fixtures for the AndroidX PreferenceMap schema."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/templates/datastore_pref.py"


def number(value):
    output = bytearray()
    while value > 0x7f:
        output.append((value & 0x7f) | 0x80)
        value >>= 7
    return bytes(output + bytes([value]))


def blob(tag, value):
    return bytes([tag]) + number(len(value)) + value


def entry(key, value):
    return blob(0x0a, blob(0x0a, key.encode("utf-8")) + blob(0x12, value))


class DataStorePreferenceTests(unittest.TestCase):
    def run_reader(self, data, key="mode", code=0):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.preferences_pb"
            path.write_bytes(data)
            result = self.invoke(path, key, code)
            self.assertEqual(path.read_bytes(), data)
            return result

    def invoke(self, path, key="mode", code=0):
        result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), str(path), key],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_reads_exact_scalar_and_hides_other_keys(self):
        other = entry("private", blob(0x2a, b"HIDDEN_OTHER_VALUE"))
        samples = (
            (b"\x08\x01", b"type: boolean\nvalue: true\n"),
            (b"\x08\x00", b"type: boolean\nvalue: false\n"),
            (b"\x18\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01", b"type: integer\nvalue: -2\n"),
            (b"\x18\xfe\xff\xff\xff\x0f", b"type: integer\nvalue: -2\n"),
            (b"\x20\xfd\xff\xff\xff\xff\xff\xff\xff\xff\x01", b"type: long\nvalue: -3\n"),
            (blob(0x2a, b"ready\n\xe2\x9c\x93"), b'type: string\nvalue: "ready\\n\\u2713"\n'),
        )
        for value, expected in samples:
            with self.subTest(expected=expected):
                result = self.run_reader(other + entry("mode", value))
                self.assertEqual(result.stdout, expected)
                self.assertNotIn(b"HIDDEN_OTHER_VALUE", result.stdout + result.stderr)

    def test_skips_known_unsupported_values_on_other_keys(self):
        selected = entry("mode", blob(0x2a, b"ready"))
        others = (
            b"\x15\x00\x00\x80\x3f",  # float
            b"\x39\x00\x00\x00\x00\x00\x00\xf0\x3f",  # double
            blob(0x32, blob(0x0a, b"hidden")),  # string set
            blob(0x42, b"hidden"),  # bytes
        )
        for value in others:
            with self.subTest(value=value):
                result = self.run_reader(entry("private", value) + selected)
                self.assertEqual(result.stdout, b'type: string\nvalue: "ready"\n')
                self.assertNotIn(b"hidden", result.stdout + result.stderr)

    def test_missing_key_is_inconclusive(self):
        result = self.run_reader(entry("other", b"\x08\x01"), code=1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"app-state absence is not established", result.stderr)

    def test_rejects_truncation_ambiguity_and_unsupported_types(self):
        good = entry("mode", blob(0x2a, b"ready"))
        bad = (
            good[:-1],
            good + b"\x80",
            good + entry("mode", b"\x08\x01"),
            entry("mode", b"\x08\x00\x08\x01"),
            entry("mode", b"\x18\x01\x2a\x01x"),
            entry("mode", b"\x35\x00\x00\x80\x3f"),  # float, outside the narrow reader
            entry("mode", blob(0x32, b"")),  # string set
            entry("mode", blob(0x42, b"raw")),  # byte array
            entry("mode", b"\x08\x02"),
            entry("mode", b"\x18\x80\x80\x80\x80\x10"),  # int32 overflow
            blob(0x0a, blob(0x0a, b"mode") + blob(0x0a, b"mode") + blob(0x12, b"\x08\x01")),
            good + b"\x12\x00",  # unknown root field
            good + entry("other", b"\x08\x01\x08\x00"),  # malformed later key
            good + entry("other", blob(0x32, b"\x0a\x02\xff\xff")),  # invalid string set
            good + entry("other", b"\x4a\x00"),  # unknown type
        )
        for malformed in bad:
            with self.subTest(malformed=malformed[:32]):
                result = self.run_reader(malformed, code=1)
                self.assertEqual(result.stdout, b"")

    def test_regular_file_bound_and_path_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "settings.preferences_pb"
            target_size = 1024 * 1024
            length = target_size - 15  # three-byte length prefixes at this size
            exact = entry("x", blob(0x2a, b"A" * length))
            self.assertEqual(len(exact), target_size)
            path.write_bytes(exact)
            result = self.invoke(path, "x")
            self.assertIn(b"type: string", result.stdout)
            path.write_bytes(exact + b"\x00")
            result = self.invoke(path, "x", code=1)
            self.assertIn(b"exceeds 1 MiB", result.stderr)
            link = root / "link"
            link.symlink_to(path)
            self.assertEqual(self.invoke(link, "x", code=1).stdout, b"")
            self.assertIn(b"Is a directory", self.invoke(root, "x", code=1).stderr)
            if hasattr(os, "mkfifo"):
                pipe = root / "pipe"
                os.mkfifo(pipe)
                self.assertIn(b"regular file", self.invoke(pipe, "x", code=1).stderr)


if __name__ == "__main__":
    unittest.main()
