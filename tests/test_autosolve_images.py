import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from scripts.autosolve_lib.profiles.images import OutputLimit, extract_png_tail


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data)))


def sample_png() -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixel = zlib.compress(b"\x00\xff\x00\x00")
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header)
            + png_chunk(b"IDAT", pixel) + png_chunk(b"IEND", b""))


class PngTailTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "input.data"
        self.png = sample_png()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as writer:
            writer.writestr("inside.txt", b"independent oracle")
        self.zip = archive.getvalue()

    def test_exact_zip_and_png_provenance(self):
        original = self.png + self.zip
        self.path.write_bytes(original)
        extracted = extract_png_tail(self.path, len(self.zip))
        self.assertIsNotNone(extracted)
        data, evidence = extracted
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence["kind"], "zip")
        self.assertEqual(evidence["offset"], len(self.png))
        self.assertEqual(evidence["iend_offset"], len(self.png) - 12)
        self.assertTrue(evidence["iend_crc_validated"])
        self.assertEqual(evidence["png_chunks"], 3)
        self.assertEqual(self.path.read_bytes(), original)

    def test_rejects_clean_random_and_truncated_zip(self):
        for data in (self.png, self.png + b"PK\x03\x04random",
                     self.png + self.zip[:-5], self.png + b"junk" + self.zip):
            with self.subTest(data=data[-12:]):
                self.path.write_bytes(data)
                self.assertIsNone(extract_png_tail(self.path, 10000))

    def test_rejects_bad_png_chunk_crc_and_truncation(self):
        corrupted = bytearray(self.png + self.zip)
        corrupted[29] ^= 1  # IHDR CRC
        for data in (bytes(corrupted), self.png[:-1] + self.zip,
                     self.png[:8] + png_chunk(b"IEND", b"") + self.zip,
                     b"not a PNG" + self.zip):
            with self.subTest(data=data[:32]):
                self.path.write_bytes(data)
                self.assertIsNone(extract_png_tail(self.path, 10000))

    def test_rejects_output_over_limit_and_garbage_after_zip(self):
        self.path.write_bytes(self.png + self.zip)
        with self.assertRaises(OutputLimit):
            extract_png_tail(self.path, len(self.zip) - 1)
        self.path.write_bytes(self.png + self.zip + b"extra")
        self.assertIsNone(extract_png_tail(self.path, len(self.zip) + 5))
        with self.assertRaises(ValueError):
            extract_png_tail(self.path, -1)

    def test_rejects_corrupt_local_zip_record(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as writer:
            writer.writestr("first", b"one")
            writer.writestr("second", b"two")
        corrupted = bytearray(archive.getvalue())
        second = corrupted.find(b"PK\x03\x04", 4)
        corrupted[second:second + 4] = b"NOPE"
        self.path.write_bytes(self.png + corrupted)
        self.assertIsNone(extract_png_tail(self.path, 10000))


if __name__ == "__main__":
    unittest.main()
