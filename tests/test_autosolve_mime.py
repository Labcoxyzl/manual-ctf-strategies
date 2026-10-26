import base64
import hashlib
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from scripts.autosolve_lib.profiles.mime import MAX_NESTING, parse_mime


class MimeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "mail.eml"
        self.output = self.root / "staged"

    def parse(self, **limits):
        return parse_mime(self.source, self.output, max_parts=limits.get("max_parts", 32),
                          max_total_bytes=limits.get("max_total_bytes", 4096))

    def test_nested_message_and_binary_attachment_preserve_decoded_bytes(self):
        inner = EmailMessage()
        inner.set_content("inner body")
        inner.add_attachment(b"inner\x00\xff", maintype="application",
                             subtype="octet-stream", filename="inner.bin")
        outer = EmailMessage()
        outer.set_content("outer body")
        outer.add_attachment(b"\x00\xff\r\n", maintype="application",
                             subtype="octet-stream", filename="../escape.bin")
        outer.add_attachment(inner)
        original = outer.as_bytes()
        self.source.write_bytes(original)

        records, warnings = self.parse()
        self.assertEqual(warnings, [])
        self.assertEqual([item["part_path"] for item in records],
                         ["0.0", "0.1", "0.2.0.0", "0.2.0.1"])
        self.assertEqual([item["path"].read_bytes() for item in records],
                         [b"outer body\n", b"\x00\xff\r\n", b"inner body\n", b"inner\x00\xff"])
        self.assertEqual(records[1]["filename"], "../escape.bin")
        self.assertEqual(records[1]["media_type"], "application/octet-stream")
        self.assertEqual(records[1]["sha256"], hashlib.sha256(b"\x00\xff\r\n").hexdigest())
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse((self.root / "escape.bin").exists())
        self.assertEqual(set(self.output.iterdir()), {item["path"] for item in records})

    def test_heldout_multipart_duplicate_names_and_quoted_printable(self):
        # Authored as raw wire bytes, independent of EmailMessage generation.
        self.source.write_bytes(
            b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="x7"\r\n\r\n'
            b'--x7\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Disposition: attachment; filename="same.bin"\r\n'
            b'Content-Transfer-Encoding: quoted-printable\r\n\r\n=00=FF=41\r\n'
            b'--x7\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Disposition: attachment; filename="same.bin"\r\n'
            b'Content-Transfer-Encoding: base64\r\n\r\nAAFC\r\n--x7--\r\n'
        )
        records, warnings = self.parse()
        self.assertEqual(warnings, [])
        self.assertEqual([(r["index"], r["part_path"], r["filename"])
                          for r in records], [(1, "0.0", "same.bin"), (2, "0.1", "same.bin")])
        self.assertEqual([r["path"].read_bytes() for r in records],
                         [b"\x00\xffA", b"\x00\x01B"])
        self.assertNotEqual(records[0]["path"], records[1]["path"])

    def test_base64_wrapped_message_is_decoded_then_traversed(self):
        # Some senders use a transfer encoding on message/rfc822 despite its structural type.
        nested = (b"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n"
                  b"Content-Disposition: attachment; filename=proof.bin\r\n\r\nproof\x00")
        self.source.write_bytes(
            b"MIME-Version: 1.0\r\nContent-Type: message/rfc822\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(nested)
        )
        records, warnings = self.parse()
        self.assertEqual(warnings, [])
        self.assertEqual([(item["part_path"], item["path"].read_bytes())
                          for item in records], [("0", nested), ("0.0", b"proof\x00")])

        self.source.write_bytes(
            b"Content-Type: message/rfc822\nContent-Transfer-Encoding: base64\n\nYQ$="
        )
        records, warnings = self.parse()
        self.assertEqual(records, [])
        self.assertTrue(any("invalid base64" in note for note in warnings))

    def test_invalid_transfer_encodings_skip_parts_and_report_reason(self):
        self.source.write_bytes(
            b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n'
            b'--x\nContent-Transfer-Encoding: base64\n\nYQ$=\n'
            b'--x\nContent-Transfer-Encoding: quoted-printable\n\nabc=G0\n'
            b'--x\nContent-Transfer-Encoding: x-custom\n\nopaque\n'
            b'--x\nContent-Transfer-Encoding: base64\n\nY29tcGxldGU=\n--x--\n'
        )
        records, warnings = self.parse()
        self.assertEqual([r["path"].read_bytes() for r in records], [b"complete"])
        self.assertTrue(any("invalid base64" in note for note in warnings))
        self.assertTrue(any("invalid quoted-printable" in note for note in warnings))
        self.assertTrue(any("unsupported transfer encoding" in note for note in warnings))
        self.assertEqual(set(self.output.iterdir()), {records[0]["path"]})

    def test_truncated_multipart_and_limits_are_explicit(self):
        self.source.write_bytes(
            b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n'
            b'--x\nContent-Type: text/plain\n\nfirst\n'
            b'--x\nContent-Type: text/plain\n\nsecond\n'
        )
        records, warnings = self.parse(max_parts=2, max_total_bytes=5)
        self.assertEqual([r["path"].read_bytes() for r in records], [b"first"])
        self.assertTrue(any("CloseBoundaryNotFoundDefect" in note for note in warnings))
        self.assertTrue(any("part limit reached" in note for note in warnings))
        records, warnings = self.parse(max_total_bytes=4)
        self.assertEqual(records, [])
        self.assertTrue(any("decoded byte limit reached" in note for note in warnings))

    def test_deep_nesting_is_bounded(self):
        header = b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b0\n\n"
        body = b""
        for depth in range(MAX_NESTING + 1):
            body += (f"--b{depth}\nContent-Type: multipart/mixed; "
                     f"boundary=b{depth + 1}\n\n").encode()
        body += (f"--b{MAX_NESTING + 1}\nContent-Type: text/plain\n\n"
                 "hidden\n").encode()
        for depth in reversed(range(MAX_NESTING + 2)):
            body += f"--b{depth}--\n".encode()
        self.source.write_bytes(header + body)
        records, warnings = self.parse()
        self.assertEqual(records, [])
        self.assertTrue(any("nesting limit reached" in note for note in warnings))

    def test_source_limit_and_unsafe_paths(self):
        self.source.write_bytes(b"X" * (1024 * 1024 + 1))
        records, warnings = self.parse(max_total_bytes=0)
        self.assertEqual(records, [])
        self.assertIn("source byte limit", warnings[0])
        self.assertFalse(self.output.exists())
        with self.assertRaisesRegex(ValueError, "differ from source"):
            parse_mime(self.source, self.root, max_parts=1, max_total_bytes=0)
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.parse()
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            parse_mime(self.source, self.root / "other", max_parts=-1,
                       max_total_bytes=0)


if __name__ == "__main__":
    unittest.main()
