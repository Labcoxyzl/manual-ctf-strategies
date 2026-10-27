"""Independent printed clue and bounded OCR controls."""

import base64
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image, ImageDraw, ImageFont

from scripts.autosolve_lib.profiles import ocr
from scripts.autosolve_lib.profiles.encoding import decode
from scripts.autosolve_lib import setup as capabilities
from scripts.autosolve_lib import core


class OCRTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    @unittest.skipUnless(shutil.which(ocr.TESSERACT), "Tesseract required")
    def test_independent_split_base64_clue_routes_to_exact_decode(self):
        clue = b"ROUTE NORTH 581"
        encoded = base64.b64encode(clue).decode()
        image = Image.new("RGB", (480, 240), "white")
        draw = ImageDraw.Draw(image)
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 32)
        for y, text in ((24, "BASE64 CLUE"), (90, encoded[:10]), (145, encoded[10:])):
            draw.text((30, y), text, fill="black", font=font)
        source = self.root / "printed.png"
        image.save(source)
        before = source.read_bytes()
        records, notices = ocr.extract_printed_text(source)
        self.assertEqual(notices, [])
        self.assertEqual(source.read_bytes(), before)
        self.assertTrue(any(row["kind"] == "printed text" and b"BASE64 CLUE" in row["data"]
                            for row in records), records)
        candidates = [row for row in records if row["kind"] == "OCR Base64 candidate"]
        self.assertEqual(len(candidates), 1, records)
        self.assertEqual(candidates[0]["data"], encoded.encode())
        self.assertEqual((candidates[0]["line_start"], candidates[0]["line_end"]), (2, 3))
        self.assertIn((clue, "base64"), decode(candidates[0]["data"], 100))

    def test_missing_engine_blank_image_and_limits_are_honest(self):
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        if shutil.which(ocr.TESSERACT):
            records, notices = ocr.extract_printed_text(source)
            self.assertEqual(records, [])
            self.assertEqual(notices, [])
        with mock.patch.object(ocr, "TESSERACT", "/missing/tesseract"):
            records, notices = ocr.extract_printed_text(source)
        self.assertEqual(records, [])
        self.assertIn("unavailable", notices[0])
        with mock.patch.object(ocr, "MAX_PIXELS", 100):
            records, notices = ocr.extract_printed_text(source)
        self.assertEqual(records, [])
        self.assertIn("pixel/frame limit", notices[0])
        oversized = self.root / "oversized.png"
        oversized.write_bytes(b"x" * 101)
        with mock.patch.object(ocr, "MAX_SOURCE_BYTES", 100):
            self.assertIn("byte limit", ocr.extract_printed_text(oversized)[1][0])
        with self.assertRaises(ValueError):
            ocr.extract_printed_text(source, timeout=0)

    @unittest.skipUnless(shutil.which(ocr.TESSERACT), "Tesseract required")
    def test_output_budget_withholds_partial_text(self):
        source = self.root / "text.png"
        image = Image.new("RGB", (450, 100), "white")
        ImageDraw.Draw(image).text((15, 15), "VISIBLE PRINTED MESSAGE", fill="black",
                                   font=ImageFont.truetype(
                                       "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 24))
        image.save(source)
        rows, notices = ocr.extract_printed_text(source, max_bytes=4)
        self.assertEqual(rows, [])
        self.assertIn("output byte limit", notices[0])

    @unittest.skipUnless(shutil.which(ocr.TESSERACT), "Tesseract required")
    def test_doctor_runs_real_ocr_probe_and_missing_engine_is_unavailable(self):
        operation, engine = capabilities._ocr_probe(True)
        self.assertEqual(operation["functional_probe"], "passed")
        self.assertEqual(engine["status"], "ready")
        with mock.patch.object(ocr, "TESSERACT", "/missing/tesseract"):
            operation, engine = capabilities._ocr_probe(True)
        self.assertEqual(operation["status"], "unavailable")
        self.assertFalse(engine["found"])

    def test_misbehaving_engine_cannot_publish_oversized_output(self):
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        fake = self.root / "large-output"
        fake.write_text("#!/usr/bin/env python3\nprint('X' * 100000)\n")
        fake.chmod(0o755)
        with mock.patch.object(ocr, "TESSERACT", str(fake)):
            rows, notices = ocr.extract_printed_text(source)
        self.assertEqual(rows, [])
        self.assertIn("output byte limit", notices[0])

    def test_labeled_base64_uses_complete_contiguous_lines(self):
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        clue = b"COMPLETE CLUE 742"
        encoded = base64.b64encode(clue).decode()
        fake = self.root / "printed-output"
        second_line = encoded[12:15] + " " + encoded[15:]
        fake.write_text("#!/usr/bin/env python3\n"
                        f"print('BASE64 CLUE\\n{encoded[:12]}\\n{second_line}')\n")
        fake.chmod(0o755)
        with mock.patch.object(ocr, "TESSERACT", str(fake)):
            rows, notices = ocr.extract_printed_text(source)
        self.assertEqual(notices, [])
        self.assertEqual([row["data"] for row in rows if row["kind"] == "OCR Base64 candidate"],
                         [encoded.encode()])

    def test_unrelated_spaced_words_are_not_joined_as_base64(self):
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        fake = self.root / "prose-output"
        fake.write_text("#!/usr/bin/env python3\n"
                        "print('BASE64 CLUE\\nOPEN EAST\\nLOOK WEST')\n")
        fake.chmod(0o755)
        with mock.patch.object(ocr, "TESSERACT", str(fake)):
            rows, notices = ocr.extract_printed_text(source)
        self.assertEqual(notices, [])
        self.assertEqual([row["kind"] for row in rows], ["printed text"])

    def test_traineddata_change_invalidates_ocr_adapter_fingerprint(self):
        data_dir = self.root / "tessdata"
        data_dir.mkdir()
        trained = data_dir / "eng.traineddata"
        trained.write_bytes(b"first English model")
        fake = self.root / "tesseract"
        fake.write_text("#!/usr/bin/env python3\n"
                        f"print('List of available languages in \"{data_dir}\" (1):')\n"
                        "print('eng')\n")
        fake.chmod(0o755)
        with mock.patch.object(ocr, "TESSERACT", str(fake)):
            self.assertEqual(ocr.english_traineddata_path(), trained)
            first = core._current_adapter_fingerprints(time.monotonic() + 20)["ocr"]
            trained.write_bytes(b"second English model")
            second = core._current_adapter_fingerprints(time.monotonic() + 20)["ocr"]
            trained.unlink()
            unavailable = core._current_adapter_fingerprints(time.monotonic() + 20)["ocr"]
        self.assertNotEqual(first, second)
        self.assertEqual(unavailable, [])

    def test_probe_and_extraction_do_not_create_default_temporary_files(self):
        data_dir = self.root / "tessdata"
        data_dir.mkdir()
        trained = data_dir / "eng.traineddata"
        trained.write_bytes(b"English model")
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        fake = self.root / "tesseract"
        fake.write_text("#!/usr/bin/env python3\n"
                        "import sys\n"
                        f"print('List of available languages in \"{data_dir}\" (1):' "
                        "if '--list-langs' in sys.argv else 'PRINTED CLUE')\n"
                        "if '--list-langs' in sys.argv: print('eng')\n")
        fake.chmod(0o755)
        with (mock.patch.object(ocr, "TESSERACT", str(fake)),
              mock.patch("tempfile.TemporaryFile", side_effect=AssertionError("unscoped temp"))):
            self.assertEqual(ocr.english_traineddata_path(), trained)
            rows, notices = ocr.extract_printed_text(source)
        self.assertEqual(notices, [])
        self.assertEqual([row["data"] for row in rows], [b"PRINTED CLUE\n"])

    def test_unavailable_anonymous_output_withholds_ocr(self):
        source = self.root / "blank.png"
        Image.new("RGB", (80, 80), "white").save(source)
        fake = self.root / "tesseract"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        with (mock.patch.object(ocr, "TESSERACT", str(fake)),
              mock.patch.object(ocr.os, "memfd_create", side_effect=OSError("unsupported"))):
            self.assertIsNone(ocr.english_traineddata_path())
            rows, notices = ocr.extract_printed_text(source)
        self.assertEqual(rows, [])
        self.assertIn("Tesseract failed", notices[0])


if __name__ == "__main__":
    unittest.main()
