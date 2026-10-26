import hashlib
import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.pdf import extract_pdf


def handwritten_pdf(text: bytes = b"PDF ORACLE 42", *, scanned: bool = False) -> bytes:
    """Build a tiny PDF independently of the parser under test."""
    if scanned:
        contents = b"q 1 0 0 1 10 10 cm /Im0 Do Q\n"
        resources = b"<< /XObject << /Im0 6 0 R >> >>"
        image = b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 1 >>\nstream\n\x80\nendstream"
    else:
        contents = b"BT /F1 12 Tf 10 50 Td (" + text + b") Tj ET\n"
        resources = b"<< /Font << /F1 4 0 R >> >>"
        image = None
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources "
        + resources + b" /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(contents)).encode() + b" >>\nstream\n" + contents + b"endstream",
    ]
    if image is not None:
        objects.append(image)
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(data))
        data += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(data)
    data += f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode()
    for offset in offsets[1:]:
        data += f"{offset:010d} 00000 n \n".encode()
    data += (f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").encode()
    return bytes(data)


def object_stream_pdf() -> bytes:
    """Pack catalog, pages, and page into a PDF 1.5 object stream."""
    catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
    pages = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    page = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>")
    header = f"1 0 2 {len(catalog) + 1} 3 {len(catalog) + len(pages) + 2} ".encode()
    packed = header + catalog + b" " + pages + b" " + page
    contents = b"BT /F1 12 Tf 10 50 Td (PACKED OBJECT) Tj ET\n"
    objects = {
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        6: b"<< /Length " + str(len(contents)).encode() + b" >>\nstream\n" + contents + b"endstream",
        7: (b"<< /Type /ObjStm /N 3 /First " + str(len(header)).encode()
            + b" /Length " + str(len(packed)).encode() + b" >>\nstream\n"
            + packed + b"\nendstream"),
    }
    data = bytearray(b"%PDF-1.5\n")
    offsets = {}
    for object_id, obj in objects.items():
        offsets[object_id] = len(data)
        data += f"{object_id} 0 obj\n".encode() + obj + b"\nendobj\n"
    offsets[4] = len(data)
    entries = [(0, 0, 65535), (2, 7, 0), (2, 7, 1), (2, 7, 2)]
    entries += [(1, offsets[index], 0) for index in range(4, 8)]
    xref_data = b"".join(bytes([kind]) + value.to_bytes(4, "big")
                         + generation.to_bytes(2, "big")
                         for kind, value, generation in entries)
    xref = (b"<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Length "
            + str(len(xref_data)).encode() + b" >>\nstream\n"
            + xref_data + b"\nendstream")
    data += b"4 0 obj\n" + xref + b"\nendobj\n"
    data += f"startxref\n{offsets[4]}\n%%EOF\n".encode()
    return bytes(data)


def incremental_pdf() -> bytes:
    data = bytearray(handwritten_pdf())
    previous = int(re.search(rb"startxref\n(\d+)", data).group(1))
    contents = b"BT /F1 12 Tf 10 50 Td (UPDATED ORACLE) Tj ET\n"
    offset = len(data)
    data += (b"5 0 obj\n<< /Length " + str(len(contents)).encode()
             + b" >>\nstream\n" + contents + b"endstream\nendobj\n")
    xref = len(data)
    data += (f"xref\n5 1\n{offset:010d} 00000 n \ntrailer\n"
             f"<< /Size 6 /Root 1 0 R /Prev {previous} >>\n"
             f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(data)


class PdfExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.pdf"
        self.output = self.root / "staged"

    def extract(self, *, max_pages=4, max_total_bytes=4096):
        return extract_pdf(self.source, self.output, max_pages=max_pages,
                           max_total_bytes=max_total_bytes)

    def check_record(self, record, oracle):
        self.assertEqual(record["path"].read_bytes(), oracle)
        self.assertEqual(record["size"], len(oracle))
        self.assertEqual(record["sha256"], hashlib.sha256(oracle).hexdigest())
        self.assertEqual(record["path"].parent, self.output)

    def test_handwritten_text_and_decoded_stream_keep_exact_oracles(self):
        self.source.write_bytes(handwritten_pdf())
        original = self.source.read_bytes()
        records, warnings = self.extract()
        self.assertEqual(warnings, [])
        text = next(item for item in records if item["kind"] == "text")
        stream = next(item for item in records if item["kind"] == "stream")
        self.check_record(text, b"PDF ORACLE 42")
        self.check_record(stream, b"BT /F1 12 Tf 10 50 Td (PDF ORACLE 42) Tj ET\n")
        self.assertIn("page 1 object 3 0", text["locator"])
        self.assertEqual(stream["locator"], "object 5 0")
        self.assertEqual(self.source.read_bytes(), original)

    def test_duplicate_unicode_attachments_preserve_name_and_bytes(self):
        from pypdf import PdfWriter

        writer = PdfWriter(clone_from=io.BytesIO(handwritten_pdf()))
        for payload in (b"first\x00", b"second\xff"):
            writer.add_attachment(filename="\u00e9/../same.bin", data=payload)
        with self.source.open("wb") as target:
            writer.write(target)
        records, warnings = self.extract()
        self.assertEqual(warnings, [])
        attachments = [item for item in records if item["kind"] == "attachment"]
        self.assertEqual(len(attachments), 2)
        for index, payload in enumerate((b"first\x00", b"second\xff")):
            record = attachments[index]
            self.check_record(record, payload)
            self.assertEqual(record["name"], "\u00e9/../same.bin")
            self.assertEqual(record["index"], index)
            self.assertIn("object", record["locator"])
        self.assertNotEqual(attachments[0]["locator"], attachments[1]["locator"])
        self.assertEqual(set(self.output.iterdir()), {item["path"] for item in records})
        self.assertFalse((self.root / "same.bin").exists())

    def test_held_out_core_pdfs_match_object_and_attachment_oracles(self):
        examples = Path(__file__).resolve().parents[1] / "examples" / "core"
        for filename, stream_id in (("attachment.pdf", 7), ("streams.pdf", 4)):
            with self.subTest(filename=filename):
                self.source.write_bytes((examples / filename).read_bytes())
                records, _ = self.extract()
                stream = next(item for item in records if item["kind"] == "stream")
                self.check_record(stream, b"% TRAINING-STREAM\n")
                self.assertEqual(stream["object_id"], stream_id)
                if filename == "attachment.pdf":
                    attachment = next(item for item in records if item["kind"] == "attachment")
                    self.check_record(attachment, b"TRAINING-BYTES\x00\xff\n")
                    self.assertEqual(attachment["object_id"], 6)

    def test_object_stream_and_incremental_update_variations(self):
        for source, text_oracle, stream_id in (
                (object_stream_pdf(), b"PACKED OBJECT", 6),
                (incremental_pdf(), b"UPDATED ORACLE", 5)):
            with self.subTest(text_oracle=text_oracle):
                self.source.write_bytes(source)
                records, warnings = self.extract()
                self.assertFalse(any("parse failed" in warning for warning in warnings))
                text = next(item for item in records if item["kind"] == "text")
                self.check_record(text, text_oracle)
                self.assertEqual(text["object_id"], 3)
                stream = next(item for item in records if item["kind"] == "stream"
                              and item["object_id"] == stream_id)
                self.assertIn(text_oracle, stream["path"].read_bytes())

    def test_malformed_encrypted_and_scanned_report_limits(self):
        from pypdf import PdfWriter

        self.source.write_bytes(b"%PDF-1.4\ntruncated")
        records, warnings = self.extract()
        self.assertEqual(records, [])
        self.assertTrue(any("PDF parse failed" in warning for warning in warnings))
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.encrypt("private")
        with self.source.open("wb") as target:
            writer.write(target)
        records, warnings = self.extract()
        self.assertEqual(records, [])
        self.assertIn("encrypted PDF", warnings[0])
        self.source.write_bytes(handwritten_pdf(scanned=True))
        records, warnings = self.extract()
        self.assertFalse(any(item["kind"] == "text" for item in records))
        self.assertTrue(any("no extractable text" in warning for warning in warnings))
        self.assertFalse(any(item["object_id"] == 6 for item in records))

    def test_page_and_byte_limits_and_output_path_guard(self):
        self.source.write_bytes(handwritten_pdf())
        records, warnings = self.extract(max_pages=0, max_total_bytes=3)
        self.assertEqual(records, [])
        self.assertTrue(any("page limit" in warning for warning in warnings))
        self.assertTrue(any("decoded byte limit" in warning for warning in warnings))
        self.assertFalse(self.output.exists())
        records, warnings = self.extract(max_total_bytes=45)
        self.assertEqual([item["kind"] for item in records], ["text"])
        self.assertTrue(any("decoded byte limit" in warning for warning in warnings))
        for item in records:
            item["path"].unlink()
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.extract()
        with self.assertRaisesRegex(ValueError, "differ from source"):
            extract_pdf(self.source, self.root, max_pages=1, max_total_bytes=1024)
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            self.extract(max_pages=-1)

    def test_optional_parser_is_reported_without_import_side_effects(self):
        with patch.dict("sys.modules", {"pypdf": None}):
            records, warnings = self.extract()
        self.assertEqual(records, [])
        self.assertIn("pypdf is not installed", warnings[0])


if __name__ == "__main__":
    unittest.main()
