"""Independent black-box contract tests; fixtures are authored here, never imported.

Run with Python 3.10+ on Linux: python -m unittest discover -s tests -p
test_toolkit_acceptance.py. Only the public CLI is exercised. Real image tests
need installed file/ExifTool; controlled missing-tool tests always run.
"""

import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib


CLI = Path(__file__).resolve().parents[1] / "scripts" / "ctf.py"
REAL_FILE = shutil.which("file")
REAL_EXIFTOOL = shutil.which("exiftool")


def classic_zip(name=b"opaque.dat", payload=b"abc", *, encrypted=False, comment=b""):
    """Build a stored classic ZIP, optionally with traditional PKZIP encryption."""
    flags = int(encrypted)
    crc = zlib.crc32(payload)
    stored = payload
    if encrypted:
        keys = [0x12345678, 0x23456789, 0x34567890]

        def update(value):
            def crc_byte(key, byte):
                value = key ^ byte
                for _ in range(8):
                    value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
                return value
            keys[0] = crc_byte(keys[0], value)
            keys[1] = ((keys[1] + (keys[0] & 255)) * 134775813 + 1) & 0xFFFFFFFF
            keys[2] = crc_byte(keys[2], keys[1] >> 24)

        for value in b"fixture-only":
            update(value)
        ciphertext = bytearray()
        for value in bytes(range(11)) + bytes([crc >> 24]) + payload:
            mask = keys[2] | 2
            ciphertext.append(value ^ ((mask * (mask ^ 1) >> 8) & 255))
            update(value)
        stored = bytes(ciphertext)
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, flags, 0, 0, 0,
                        crc, len(stored), len(payload), len(name), 0)
    body = local + name + stored
    central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, flags, 0, 0, 0,
                          crc, len(stored), len(payload), len(name), 0, 0, 0, 0, 0, 0)
    directory = central + name
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1,
                      len(directory), len(body), len(comment))
    return body + directory + end + comment


def jpeg(*, gps=False):
    """An authored 8x8 grayscale JPEG with a single DC-zero/EOB block."""
    def segment(marker, data):
        return bytes((255, marker)) + struct.pack(">H", len(data) + 2) + data

    # TIFF root has either no tags or a pointer to a five-entry GPS directory.
    tiff = b"II" + struct.pack("<HI", 42, 8)
    if gps:
        tiff += struct.pack("<H", 1) + struct.pack("<HHII", 0x8825, 4, 1, 26) + b"\0" * 4
        rational_offset = 26 + 2 + 5 * 12 + 4
        entries = [struct.pack("<HHI4s", 0, 1, 4, b"\x02\x03\0\0"),
                   struct.pack("<HHI4s", 1, 2, 2, b"S\0\0\0"),
                   struct.pack("<HHII", 2, 5, 3, rational_offset),
                   struct.pack("<HHI4s", 3, 2, 2, b"E\0\0\0"),
                   struct.pack("<HHII", 4, 5, 3, rational_offset + 24)]
        tiff += struct.pack("<H", 5) + b"".join(entries) + b"\0" * 4
        tiff += struct.pack("<12I", 12, 1, 34, 1, 56, 1, 98, 1, 7, 1, 6, 1)
    else:
        tiff += b"\0" * 6
    quant = segment(0xDB, b"\0" + bytes([1] * 64))
    frame = segment(0xC0, b"\x08\x00\x08\x00\x08\x01\x01\x11\x00")
    codes = bytes([1] + [0] * 15) + b"\0"
    huffman = segment(0xC4, b"\0" + codes + b"\x10" + codes)
    scan = segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    return b"\xff\xd8" + segment(0xE1, b"Exif\0\0" + tiff) + quant + frame + huffman + scan + b"\x3f\xff\xd9"


class ToolkitAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="toolkit acceptance ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def run_cli(self, *args, code=0, status="complete", env=None):
        result = subprocess.run([sys.executable, str(CLI), *map(str, args), "--json"],
                                cwd=self.root, env=env, capture_output=True, text=True,
                                timeout=36)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], status, report)
        self.assertTrue({"operation", "status", "parameters", "facts", "scope",
                         "notices", "next_actions"}.issubset(report))
        self.assertLessEqual(len(report["next_actions"]), 2)
        return report

    def tools_env(self, file_body=None, exif_body=None, real_file=False):
        directory = self.root / "controlled tools"
        directory.mkdir(exist_ok=True)
        if real_file and REAL_FILE:
            (directory / "file").symlink_to(REAL_FILE)
        for name, body in (("file", file_body), ("exiftool", exif_body)):
            if body is not None:
                executable = directory / name
                executable.write_text("#!" + sys.executable + "\n" + body)
                executable.chmod(0o700)
        return dict(os.environ, PATH=str(directory))

    def test_bits_group_significance_and_widths(self):
        # Deliberately asymmetric groups distinguish within-group from stream reversal.
        for width, groups in ((1, [0, 1, 1, 0]), (2, [2, 1, 3]), (3, [1, 6, 3, 4]),
                              (4, [3, 9, 12]), (5, [17, 3, 30]), (6, [39, 24, 52]),
                              (7, [69, 3, 112]), (8, [0x12, 0x93, 0xE0])):
            for order in ("msb", "lsb"):
                with self.subTest(width=width, order=order):
                    encoded = [format(value, "0%db" % width) for value in groups]
                    if order == "lsb":
                        encoded = [group[::-1] for group in encoded]
                    out = self.root / (str(width) + order)
                    report = self.run_cli("bits", "--text", "\t \r\n".join(encoded),
                                          "--width", width, "--order", order, "--out", out)
                    self.assertEqual(out.read_bytes(), bytes(groups))
                    facts = report["facts"]["transform"]
                    self.assertEqual(facts["selected_bits"], width * len(groups))
                    self.assertEqual(facts["groups"], len(groups))

    def test_bits_selected_crlf_payload_and_reproducibility(self):
        source = self.write("framed π.txt", b"count 2026 ID 101\r\n00101\r\n11010\r\ntrailer 111\r\n")
        args = ("bits", "--file", source, "--lines", "2:3", "--width", "5")
        first = self.run_cli(*args)
        self.assertEqual(first, self.run_cli(*args))
        self.assertEqual(first["facts"]["transform"]["preview_hex"], "051a")
        self.assertIn("2", str(first["facts"]["transform"]["selected_lines"]))
        self.run_cli("bits", "--file", source, code=2, status="invalid_input")

    def test_bits_cross_chunk_and_complete_validation(self):
        expected = bytes((value * 73 + 19) % 256 for value in range(11011))
        bits = "".join(format(value, "08b") for value in expected)
        wrapped = "\n".join(bits[i:i + 71] for i in range(0, len(bits), 71)).encode()
        source = self.write("wrapped.bin", wrapped)
        out = self.root / "decoded.bin"
        result = self.run_cli("bits", "--file", source, "--out", out)
        self.assertEqual(out.read_bytes(), expected)
        self.assertEqual(result["facts"]["transform"]["preview_hex"], expected[:64].hex())
        source.write_bytes(wrapped + b"Z")
        self.run_cli("bits", "--file", source, code=2, status="invalid_input")

    def test_bits_invalid_empty_remainder_and_selection(self):
        for text in ("", " \t\r\n", "0001010", "01000001\u00a001000010", "001x1000"):
            with self.subTest(text=repr(text)):
                out = self.root / "must not exist"
                report = self.run_cli("bits", "--text", text, "--out", out,
                                      code=2, status="invalid_input")
                self.assertFalse(out.exists())
                self.assertTrue(report["notices"])
        source = self.write("lines", b"01000100\n\n10101010\n")
        for selection in ("2:2", "9:10", "3:2", "0:1"):
            with self.subTest(selection=selection):
                self.run_cli("bits", "--file", source, "--lines", selection,
                             code=2, status="invalid_input")

    def test_bits_invalid_position_in_selected_source(self):
        source = self.write("position.txt", b"header 010 2026\n101\n00Q\n")
        report = self.run_cli("bits", "--file", source, "--lines", "2:3", "--width", "3",
                              code=2, status="invalid_input")
        diagnostic = " ".join(report["notices"])
        self.assertIn("source byte %d" % (source.read_bytes().index(b"Q") + 1), diagnostic)
        self.assertIn("line 3", diagnostic)
        self.assertIn("column 3", diagnostic)

    def test_xor_reference_short_large_single_and_repeated_key(self):
        for size, key in ((17, bytes.fromhex("c5")), (196619, bytes.fromhex("13e700a94d"))):
            with self.subTest(size=size):
                source_bytes = bytes((i * i + 47 * i + 211) % 256 for i in range(size))
                reference = bytes(a ^ b for a, b in zip(source_bytes, itertools.cycle(key)))
                source = self.write("source " + str(size), source_bytes)
                out = self.root / ("out " + str(size))
                key_text = " \t\n".join(format(b, "02x") for b in key)
                report = self.run_cli("xor", "--file", source, "--key-hex", key_text, "--out", out)
                self.assertEqual(out.read_bytes(), reference)
                self.assertEqual(source.read_bytes(), source_bytes)
                self.assertEqual(report["facts"]["transform"]["output_bytes"], size)
                self.assertEqual(report["facts"]["transform"]["preview_hex"], reference[:64].hex())
                restored = self.root / ("restored " + str(size))
                self.run_cli("xor", "--file", out, "--key-hex", key_text, "--out", restored)
                self.assertEqual(restored.read_bytes(), source_bytes)
                self.assertEqual(set(report["parameters"]), {"file", "key_bytes", "out"})
                self.assertEqual(report["parameters"]["key_bytes"], len(key))

    def test_xor_empty_and_invalid_keys(self):
        source = self.write("empty", b"")
        out = self.root / "empty result"
        report = self.run_cli("xor", "--file", source, "--key-hex", "a1", "--out", out)
        self.assertEqual(out.read_bytes(), b"")
        self.assertEqual(report["facts"]["transform"]["output_bytes"], 0)
        self.assertEqual(report["facts"]["transform"]["preview_hex"], "")
        for key in ("", " \t", "a", "00:z1", "ab\u00a0cd", "0x12"):
            with self.subTest(key=repr(key)):
                destination = self.root / "invalid result"
                self.run_cli("xor", "--file", source, "--key-hex", key,
                             "--out", destination, code=2, status="invalid_input")
                self.assertFalse(destination.exists())

    def test_output_preservation_collisions_aliases_and_symlinks(self):
        source = self.write("source", b"00101101")
        existing = self.write("existing", b"must survive\xff")
        hardlink = self.root / "hard alias"
        os.link(source, hardlink)
        symlink = self.root / "symbolic alias"
        symlink.symlink_to(source)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "absent target")
        directory = self.root / "directory"
        directory.mkdir()
        before = source.read_bytes(), existing.read_bytes()
        initial = {p.name for p in self.root.iterdir()}
        for operation, extra in (("bits", ()), ("xor", ("--key-hex", "72"))):
            for destination in (source, existing, hardlink, symlink, dangling, directory):
                with self.subTest(operation=operation, destination=destination.name):
                    self.run_cli(operation, "--file", source, *extra, "--out", destination,
                                 code=2, status="invalid_input")
        self.assertEqual((source.read_bytes(), existing.read_bytes()), before)
        self.assertEqual({p.name for p in self.root.iterdir()}, initial)
        self.assertTrue(dangling.is_symlink())

    def test_dash_filename_and_nonregular_inputs(self):
        self.write("-payload π", b"10010011")
        self.assertEqual(self.run_cli("bits", "--file=-payload π")["facts"]["transform"]["preview_hex"], "93")
        for operation, extra in (("bits", ()), ("xor", ("--key-hex", "11")), ("inspect", ())):
            for path in (self.root / "missing", self.root):
                with self.subTest(operation=operation, path=path):
                    self.run_cli(operation, "--file", path, *extra, code=2, status="invalid_input")

    @unittest.skipUnless(REAL_FILE, "installed file required for complete inspection")
    def test_plain_zip_misleading_extension_hash_and_no_extraction(self):
        archive = self.write("looks like photo.jpg", classic_zip(b"../escape.txt", b"\x00\xffpayload"))
        before = set(self.root.iterdir())
        report = self.run_cli("inspect", "--file", archive, "--sha256")
        facts = report["facts"]
        self.assertEqual(facts["sha256"]["value"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(facts["zip"]["member_count"], 1)
        self.assertEqual(facts["zip"]["encrypted_members"], 0)
        self.assertEqual(facts["zip"]["expanded_bytes"], 9)
        self.assertEqual(facts["zip"]["rows"][0]["name"], "../escape.txt")
        self.assertEqual(set(self.root.iterdir()), before)

    @unittest.skipUnless(REAL_FILE, "installed file required for complete inspection")
    def test_encrypted_zip_is_not_corruption(self):
        archive = self.write("encrypted.zip", classic_zip(b"locked.bin", bytes(range(32)), encrypted=True))
        with zipfile.ZipFile(archive) as handle:
            self.assertEqual(handle.read("locked.bin", pwd=b"fixture-only"), bytes(range(32)))
        facts = self.run_cli("inspect", "--file", archive)["facts"]["zip"]
        self.assertEqual(facts["encrypted_members"], 1)
        self.assertTrue(facts["rows"][0]["encrypted"])

    @unittest.skipUnless(REAL_FILE, "installed file required for complete inspection")
    def test_zip_comment_signature_is_not_the_real_directory_end(self):
        archive = self.write("comment.zip", classic_zip(comment=b"review PK\x05\x06" + b"\0" * 30))
        self.assertEqual(self.run_cli("inspect", "--file", archive)["facts"]["zip"]["member_count"], 1)

    def test_zip_corruption_and_lying_count(self):
        original = classic_zip()
        wrong_count = bytearray(original)
        struct.pack_into("<HH", wrong_count, len(wrong_count) - 22 + 8, 2, 2)
        for data in (original[:-8], bytes(wrong_count)):
            with self.subTest(data=data[-22:].hex()):
                archive = self.write("broken.zip", data)
                self.run_cli("inspect", "--file", archive, code=2, status="invalid_input")

    def test_zip_unsupported_layouts_are_distinct_from_corruption(self):
        original = classic_zip()
        multidisk = bytearray(original)
        struct.pack_into("<H", multidisk, len(multidisk) - 22 + 4, 1)
        zip64 = bytearray(original)
        struct.pack_into("<HH", zip64, len(zip64) - 22 + 8, 0xFFFF, 0xFFFF)
        for variant in (b"MZ" + b"\0" * 64 + original, multidisk, zip64):
            with self.subTest(prefix=bytes(variant[:4]), tail=bytes(variant[-22:])):
                archive = self.write("unsupported.zip", variant)
                report = self.run_cli("inspect", "--file", archive, code=3, status="partial")
                self.assertTrue(any("7" in action for action in report["next_actions"]))

    @unittest.skipUnless(REAL_FILE, "installed file required for complete inspection")
    def test_zip_preview_limit_is_not_incomplete_scan(self):
        archive = self.root / "many.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for i in range(109):
                handle.writestr("member-%03d" % i, bytes([i]) * (i % 7))
        facts = self.run_cli("inspect", "--file", archive)["facts"]["zip"]
        self.assertEqual(facts["member_count"], 109)
        self.assertEqual(facts["expanded_bytes"], sum(i % 7 for i in range(109)))
        self.assertEqual(len(facts["rows"]), 100)
        self.assertTrue(facts["rows_truncated"])

    def test_zip_member_budget(self):
        archive = self.root / "over-budget.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for i in range(10001):
                handle.writestr(str(i), b"")
        self.run_cli("inspect", "--file", archive, code=1, status="partial")

    @unittest.skipUnless(REAL_FILE and REAL_EXIFTOOL, "installed file and ExifTool required")
    def test_jpeg_with_and_without_gps_despite_extensions(self):
        for has_gps in (False, True):
            with self.subTest(gps=has_gps):
                image = self.write("image-%s.zip" % has_gps, jpeg(gps=has_gps))
                report = self.run_cli("inspect", "--file", image)
                facts = report["facts"]
                self.assertIn("jpeg", str(facts["classification"]).lower())
                self.assertNotIn("zip", facts)
                metadata = facts["image"]
                self.assertEqual(metadata["gps_present"], has_gps)
                self.assertEqual(metadata["tags"]["ImageWidth"], 8)
                if has_gps:
                    self.assertAlmostEqual(metadata["tags"]["GPSLatitude"], -(12 + 34 / 60 + 56 / 3600))
                    self.assertAlmostEqual(metadata["tags"]["GPSLongitude"], 98 + 7 / 60 + 6 / 3600)

    def test_doctor_bytes_and_missing_tools(self):
        env = self.tools_env()
        self.assertTrue(self.run_cli("doctor", "--workflow", "bytes", env=env)["facts"]["runtime"]["eligible"])
        report = self.run_cli("doctor", "--workflow", "inspect", env=env, code=3, status="partial")
        self.assertFalse(report["facts"]["tools"]["file"]["present"])
        self.assertFalse(report["facts"]["tools"]["exiftool"]["present"])
        source = self.write("data.png", b"ordinary non-image text\n")
        report = self.run_cli("inspect", "--file", source, env=env, code=3, status="partial")
        self.assertIn("unknown", str(report["facts"]["classification"]).lower())
        self.assertEqual(report["facts"]["input"]["size_bytes"], 24)

    @unittest.skipUnless(REAL_FILE, "installed file needed to isolate ExifTool absence")
    def test_missing_exiftool_applies_only_to_images(self):
        env = self.tools_env(real_file=True)
        text = self.write("plain.jpg", b"not a jpeg\n")
        self.run_cli("inspect", "--file", text, env=env)
        image = self.write("actual.data", jpeg())
        self.run_cli("inspect", "--file", image, env=env, code=3, status="partial")

    def test_present_but_unsupported_tools(self):
        body = ("import sys\n"
                "if '--version' in sys.argv or '-ver' in sys.argv:\n"
                "    print('12.00')\n"
                "else:\n"
                "    print('unrecognized option: needed feature', file=sys.stderr)\n"
                "    sys.exit(2)\n")
        env = self.tools_env(file_body=body, exif_body=body)
        report = self.run_cli("doctor", "--workflow", "inspect", env=env, code=3, status="partial")
        self.assertTrue(report["facts"]["tools"]["file"]["present"])
        self.assertFalse(report["facts"]["tools"]["file"]["needed_feature"])

    def test_subprocess_output_limit(self):
        env = self.tools_env(file_body="import sys\nsys.stdout.write('X' * (2 * 1024 * 1024))\n")
        source = self.write("ordinary", b"test")
        report = self.run_cli("inspect", "--file", source, env=env, code=1, status="partial")
        self.assertLess(len(json.dumps(report)), 10000)

    def test_subprocess_timeout(self):
        env = self.tools_env(file_body="import time\ntime.sleep(15)\n")
        source = self.write("ordinary", b"bounded timeout")
        report = self.run_cli("inspect", "--file", source, env=env, code=1, status="partial")
        self.assertTrue(any("time" in notice.lower() for notice in report["notices"]))


if __name__ == "__main__":
    unittest.main()
