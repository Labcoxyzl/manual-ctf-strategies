import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from scripts.autosolve_lib.profiles.images import OutputLimit, extract_jpeg_tail, extract_png_tail


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

    def test_zip_after_binary_gap_and_decoy_signature(self):
        gap = b'CFG\xffPK\x03\x04decoy\x7f'
        original = self.png + gap + self.zip
        self.path.write_bytes(original)
        data, evidence = extract_png_tail(self.path, len(original))
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence['offset'], len(self.png) + len(gap))
        self.assertEqual(evidence['iend_offset'], len(self.png) - 12)
        self.assertEqual(evidence['gap_bytes'], len(gap))
        self.assertEqual(evidence['padding_bytes'], 0)
        self.assertTrue(evidence['iend_crc_validated'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_rejects_clean_random_and_truncated_zip(self):
        for data in (self.png, self.png + b"PK\x03\x04random",
                     self.png + self.zip[:-5],
                     self.png + b'CFG\xffPK\x03\x04decoy' + self.zip[:-5],
                     self.png + b'CFG\xffPK\x03\x04random'):
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

    def test_oversized_decoy_is_no_finding_but_real_gap_zip_is_truncated(self):
        self.path.write_bytes(self.png + b'\x01PK\x03\x04' + b'J' * 200)
        self.assertIsNone(extract_png_tail(self.path, 100))
        self.path.write_bytes(self.png + b'\x01' + self.zip)
        with self.assertRaises(OutputLimit):
            extract_png_tail(self.path, len(self.zip) - 1)

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


class JpegTailTests(unittest.TestCase):
    def setUp(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'image.bin'
        output = io.BytesIO()
        Image.new('RGB', (2, 2), (20, 80, 140)).save(output, format='JPEG')
        self.jpeg = output.getvalue()
        comment = b'independent JPEG comment'
        self.jpeg = (self.jpeg[:2] + b'\xff\xfe' + struct.pack('>H', len(comment) + 2)
                     + comment + self.jpeg[2:])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as writer:
            writer.writestr('oracle.bin', b'JPEG_ORACLE\x00\xff')
        self.zip = archive.getvalue()

    def test_exact_zip_after_bounded_padding_and_comment(self):
        padding = b'\x00 \t\r\n'
        original = self.jpeg + padding + self.zip
        self.path.write_bytes(original)
        data, evidence = extract_jpeg_tail(self.path, len(self.zip))
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence['offset'], len(self.jpeg) + len(padding))
        self.assertEqual(evidence['eoi_offset'], len(self.jpeg) - 2)
        self.assertEqual(evidence['padding_bytes'], len(padding))
        self.assertTrue(evidence['jpeg_markers_validated'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_exact_zip_after_binary_gap_and_decoy_signature(self):
        gap = b'\x01\xfePK\x03\x04decoy\x7f'
        original = self.jpeg + gap + self.zip
        self.path.write_bytes(original)
        data, evidence = extract_jpeg_tail(self.path, len(original))
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence['offset'], len(self.jpeg) + len(gap))
        self.assertEqual(evidence['eoi_offset'], len(self.jpeg) - 2)
        self.assertEqual(evidence['gap_bytes'], len(gap))
        self.assertEqual(evidence['padding_bytes'], 0)
        self.assertEqual(extract_jpeg_tail(self.path, len(self.zip))[0], self.zip)
        self.assertEqual(self.path.read_bytes(), original)

    def test_zip_at_gap_window_boundary(self):
        gap = b'X' * 65536
        self.path.write_bytes(self.jpeg + gap + self.zip)
        data, evidence = extract_jpeg_tail(self.path, len(self.zip))
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence['gap_bytes'], len(gap))

    def test_padding_counts_only_leading_zero_or_whitespace(self):
        gap = b'\x00\nCFG\xff'
        self.path.write_bytes(self.jpeg + gap + self.zip)
        data, evidence = extract_jpeg_tail(self.path, len(self.zip))
        self.assertEqual(data, self.zip)
        self.assertEqual(evidence['gap_bytes'], len(gap))
        self.assertEqual(evidence['padding_bytes'], 2)

    def test_rejects_signature_like_truncated_and_malformed_inputs(self):
        malformed = bytearray(self.jpeg)
        malformed[4:6] = b'\xff\xff'  # impossible comment segment length
        for data in (self.jpeg, self.jpeg + b'\x00PK\x03\x04random',
                     self.jpeg + b'\x01\xfePK\x03\x04decoy\x7f' + self.zip[:-5],
                     self.jpeg + b'\x00' + self.zip[:-5],
                     self.jpeg[:-2] + b'\x00' + self.zip,
                     bytes(malformed) + self.zip,
                     b'\xff\xd8\xff\xd9' + self.zip,
                     bytes.fromhex('ffd8 ffc0 0008 080001000101 ffda 0006 01010000 ffd9') + self.zip,
                     self.jpeg + b'\x00' * 65537 + self.zip):
            with self.subTest(data=data[:12], size=len(data)):
                self.path.write_bytes(data)
                self.assertIsNone(extract_jpeg_tail(self.path, len(data)))

    def test_output_bound_and_bad_zip_end(self):
        self.path.write_bytes(self.jpeg + self.zip)
        with self.assertRaises(OutputLimit):
            extract_jpeg_tail(self.path, len(self.zip) - 1)
        self.path.write_bytes(self.jpeg + self.zip + b'junk')
        self.assertIsNone(extract_jpeg_tail(self.path, len(self.zip) + 4))
        with self.assertRaises(ValueError):
            extract_jpeg_tail(self.path, -1)

    def test_rejects_valid_directory_with_corrupt_member_crc(self):
        corrupt = bytearray(self.zip)
        corrupt[corrupt.index(b'JPEG_ORACLE')] ^= 1
        self.path.write_bytes(self.jpeg + corrupt)
        self.assertIsNone(extract_jpeg_tail(self.path, len(corrupt)))

    def test_reports_expanded_zip_output_limit(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as writer:
            writer.writestr('large.bin', b'A' * 100000)
        tail = archive.getvalue()
        self.path.write_bytes(self.jpeg + tail)
        with self.assertRaises(OutputLimit):
            extract_jpeg_tail(self.path, len(tail))

    def test_oversized_pk_decoy_is_no_finding(self):
        self.path.write_bytes(self.jpeg + b'\x01PK\x03\x04' + b'J' * 200)
        self.assertIsNone(extract_jpeg_tail(self.path, 100))


if __name__ == "__main__":
    unittest.main()
