import base64
import hashlib
import io
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.documents import extract_zip


# ZIPCrypto fixture generated once with 7z; tests need only the Python standard library.
ENCRYPTED_ZIP = base64.b64decode(
    "UEsDBBQAAQAAAHMDW11Aa66oIAAAABQAAAAKAAAAaW5zaWRlLnR4dB53GdJjYsQ+Fr/EJ8MCg7qabM0B+eaa0BtgkNnA4zPGUEsBAj8DFAABAAAAcwNbXUBrrqggAAAAFAAAAAoAJAAAAAAAAAAggKSBAAAAAGluc2lkZS50eHQKACAAAAAAAAEAGAD0Qz5Lb2XdAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAEAAQBcAAAASAAAAAAA"
)


class ZipExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "input.zip"
        self.output = self.root / "staged"

    def _extract(self, **kwargs):
        return extract_zip(self.archive, self.output, max_members=16,
                           max_total_bytes=1024, **kwargs)

    def test_regular_unicode_member_and_source_are_preserved(self):
        payload = b"payload\x00\xff"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("subdir/\u00e9vidence.txt", payload)
        original = self.archive.read_bytes()
        records, warnings_found = self._extract()
        self.assertEqual(warnings_found, [])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["member"], record["index"], record["size"]),
                         ("subdir/\u00e9vidence.txt", 0, len(payload)))
        self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(record["path"].read_bytes(), payload)
        self.assertEqual(record["path"].parent, self.output)
        self.assertEqual(self.archive.read_bytes(), original)
        self.assertEqual(set(self.output.iterdir()), {record["path"]})

    def test_unsafe_paths_and_special_modes_are_skipped(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            for name in ("../escape", "/absolute", "C:/drive", "a\\windows", "a/./dot"):
                archive.writestr(name, b"bad")
            for kind in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO):
                member = zipfile.ZipInfo(f"special-{kind}")
                member.create_system = 3
                member.external_attr = (kind | 0o777) << 16
                archive.writestr(member, b"target")
            archive.writestr("okay", b"good")
        records, warnings_found = self._extract()
        self.assertEqual([record["member"] for record in records], ["okay"])
        self.assertEqual(len(warnings_found), 8)
        self.assertEqual(len(list(self.output.iterdir())), 1)
        self.assertFalse((self.root / "escape").exists())

    def test_duplicate_names_keep_distinct_indices_and_bytes(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w") as archive:
                archive.writestr("same.txt", b"first")
                archive.writestr("same.txt", b"second")
        records, warnings_found = self._extract()
        self.assertEqual(warnings_found, [])
        self.assertEqual([(item["member"], item["index"], item["path"].read_bytes())
                          for item in records],
                         [("same.txt", 0, b"first"), ("same.txt", 1, b"second")])
        self.assertNotEqual(records[0]["path"], records[1]["path"])

    def test_member_and_expansion_limits_leave_no_partial_file(self):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb", b"A" * 10_000)
            archive.writestr("small", b"ok")
        records, warnings_found = extract_zip(self.archive, self.output,
                                               max_members=1, max_total_bytes=8)
        self.assertEqual(records, [])
        self.assertIn("expanded byte limit", warnings_found[0])
        self.assertIn("member limit", warnings_found[1])
        self.assertEqual(list(self.output.iterdir()), [])

        # A false small header cannot bypass the limit on bytes actually read.
        with patch.object(zipfile.ZipFile, "open", return_value=io.BytesIO(b"B" * 20)):
            records, warnings_found = extract_zip(self.archive, self.output,
                                                   max_members=2, max_total_bytes=8)
        self.assertEqual(records, [])
        self.assertTrue(all("expanded byte limit" in warning for warning in warnings_found))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_missing_wrong_and_correct_passwords(self):
        self.archive.write_bytes(ENCRYPTED_ZIP)
        records, warnings_found = self._extract()
        self.assertEqual(records, [])
        self.assertIn("password required", warnings_found[0])
        records, warnings_found = self._extract(password=b"wrong")
        self.assertEqual(records, [])
        self.assertTrue(any("password" in warning.lower() for warning in warnings_found))
        self.assertEqual(list(self.output.iterdir()), [])
        records, warnings_found = self._extract(password=b"correct horse")
        self.assertEqual(warnings_found, [])
        self.assertEqual(records[0]["path"].read_bytes(), b"verified zip payload")

    def test_crc_failure_does_not_publish_partial_member(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("data", b"marker-value")
        raw = self.archive.read_bytes()
        self.archive.write_bytes(raw.replace(b"marker-value", b"broken-value", 1))
        records, warnings_found = self._extract()
        self.assertEqual(records, [])
        self.assertIn("CRC", warnings_found[0])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_invalid_archive_and_output_symlink(self):
        self.archive.write_bytes(b"not a ZIP")
        records, warnings_found = self._extract()
        self.assertEqual(records, [])
        self.assertIn("invalid ZIP archive", warnings_found[0])
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self._extract()
        with self.assertRaisesRegex(ValueError, "differ from source"):
            extract_zip(self.archive, self.root, max_members=16, max_total_bytes=1024)


if __name__ == "__main__":
    unittest.main()
