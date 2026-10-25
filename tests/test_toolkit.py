#!/usr/bin/env python3
"""Development contracts: independent byte references and preservation/failure controls."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "ctf.py"
FIXTURES = Path(__file__).parent / "fixtures" / "toolkit" / "development"
spec = importlib.util.spec_from_file_location("ctf", CLI)
ctf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctf)


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="toolkit development ")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments, code=0, env=None, cwd=None):
        completed = subprocess.run([sys.executable, str(CLI), *map(str, arguments), "--json"],
                                   capture_output=True, env=env, cwd=cwd, timeout=35)
        self.assertEqual(completed.returncode, code, completed.stdout + completed.stderr)
        self.assertEqual(completed.stderr, b"")
        result = json.loads(completed.stdout)
        self.assertLessEqual(len(result["next_actions"]), 2)
        return result

    def write(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def make_zip(self, count=2, comment=b""):
        path = self.directory / "archive with spaces.bin"
        with zipfile.ZipFile(path, "w") as archive:
            for index in range(count):
                info = zipfile.ZipInfo("entry{}.txt".format(index), (2020, 1, 1, 0, 0, 0))
                archive.writestr(info, b"abc")
            archive.comment = comment
        return path

    def test_executable_inspection_routes_without_execution(self):
        source = self.write("sample.exe", b"MZ" + b"\x00" * 126)
        before = source.read_bytes()
        fake = self.write("file", ("#!" + sys.executable + "\nprint('application/vnd.microsoft.portable-executable')\n").encode())
        fake.chmod(0o700)
        report = self.run_cli("inspect", "--file", source, env={**os.environ, "PATH": str(self.directory)})
        self.assertEqual(report["facts"]["classification"]["value"], "application/vnd.microsoft.portable-executable")
        self.assertTrue(any("headers, sections, imports" in action for action in report["next_actions"]))
        self.assertEqual(source.read_bytes(), before)

    def test_php_markers_are_bounded_lexical_evidence(self):
        source = self.write("sample.php", b"<?php eval(hex2bin('4142'));" + b" /* base64_decode('QQ==') */" * 25)
        before = source.read_bytes()
        fake = self.write("file", ("#!" + sys.executable + "\nprint('text/x-php')\n").encode())
        fake.chmod(0o700)
        report = self.run_cli("inspect", "--file", source, env={**os.environ, "PATH": str(self.directory)})
        hints = report["facts"]["php_markers"]
        self.assertEqual(hints["matches"][:2], [{"name": "eval", "offset": 6}, {"name": "hex2bin", "offset": 11}])
        self.assertEqual(len(hints["matches"]), 20)
        self.assertTrue(hints["truncated"])
        self.assertIn("lexical", hints["source"])
        self.assertTrue(any("do not eval" in action for action in report["next_actions"]))
        self.assertEqual(source.read_bytes(), before)

    def test_zip_member_offset_must_precede_directory(self):
        source = self.make_zip(count=1)
        original = source.read_bytes()
        cd = original.index(b"PK\x01\x02")
        for position in (cd - 1, cd, len(original), len(original) + 100):
            data = bytearray(original)
            struct.pack_into("<I", data, cd + 42, position)
            source.write_bytes(data)
            report = self.run_cli("inspect", "--file", source, code=2)
            self.assertEqual(report["status"], "invalid_input")
            self.assertEqual(source.read_bytes(), data)
        source.write_bytes(original)
        self.assertEqual(self.run_cli("inspect", "--file", source)["facts"]["zip"]["member_count"], 1)

    def test_help_example_and_bit_orders(self):
        result = self.run_cli("bits", "--text", "01000001")
        self.assertEqual(result["facts"]["transform"]["preview_hex"], "41")
        result = self.run_cli("bits", "--text", "01000001", "--order", "lsb")
        self.assertEqual(result["facts"]["transform"]["preview_hex"], "82")
        for width in range(1, 9):
            for order in ("msb", "lsb"):
                text = "10" * width
                expected = bytes(int(text[i:i + width][::1 if order == "msb" else -1], 2) for i in range(0, len(text), width))
                result = self.run_cli("bits", "--text", text, "--width", width, "--order", order)
                self.assertEqual(result["facts"]["transform"]["preview_hex"], expected.hex())

    def test_framed_and_wrapped_bits(self):
        for filename, extra, expected in (("framed-bits.txt", ["--lines", "2:3"], b"OK"),
                                          ("wrapped-bits.txt", [], b"\x00\xff\xa5")):
            output = self.directory / filename
            result = self.run_cli("bits", "--file", FIXTURES / filename, *extra, "--out", output)
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(result["facts"]["transform"]["groups"], len(expected))
        self.run_cli("bits", "--file", FIXTURES / "framed-bits.txt", code=2)

    def test_bit_errors_report_positions_and_do_not_publish(self):
        for text, extra, fragment in (("0100000!", [], "byte 8, line 1, column 8"),
                                       ("0100000", [], "remainder bits"), (" \n", [], "no binary"),
                                       ("01000001", ["--lines", "2:3"], "beyond"),
                                       ("01000001", ["--lines", "2:1"], "must not exceed"),
                                       ("0100\u00a00001", [], "ASCII whitespace")):
            output = self.directory / "invalid.bin"
            result = self.run_cli("bits", "--text", text, *extra, "--out", output, code=2)
            self.assertIn(fragment, " ".join(result["notices"]))
            self.assertFalse(output.exists())
            self.assertFalse(list(self.directory.glob(".ctf-*")))

    def test_bits_chunk_boundary_and_late_invalid(self):
        text = b"01010101" * 8192 + b"\n11110000"
        source = self.write("chunk.txt", text)
        output = self.directory / "decoded.bin"
        result = self.run_cli("bits", "--file", source, "--out", output)
        self.assertEqual(output.read_bytes(), b"U" * 8192 + b"\xf0")
        self.assertEqual(result["facts"]["transform"]["output_bytes"], 8193)
        source.write_bytes(text + b"!")
        self.run_cli("bits", "--file", source, code=2)

    def test_xor_binary_references_roundtrip_and_empty(self):
        for payload in (bytes(range(256)) * 513, b"\x00\xff\x80\x01\x81", b""):
            for key in (b"\x8c", b"\x01\x23\x45"):
                source = self.write("source.bin", payload)
                output = self.directory / "encoded.bin"
                restored = self.directory / "restored.bin"
                result = self.run_cli("xor", "--file", source, "--key-hex", key.hex(), "--out", output)
                expected = bytes(a ^ b for a, b in zip(payload, (key * (len(payload) // len(key) + 1))))
                self.assertEqual(output.read_bytes(), expected)
                self.assertEqual(result["facts"]["transform"]["output_bytes"], len(payload))
                self.assertNotIn("key_hex", result["parameters"])
                self.run_cli("xor", "--file", output, "--key-hex", key.hex(), "--out", restored)
                self.assertEqual(restored.read_bytes(), payload)
                output.unlink()
                restored.unlink()

    def test_keys_and_output_collisions(self):
        source = self.write("input.bin", b"abc")
        result = self.run_cli("xor", "--file", source, "--key-hex", " 01\t02\n")
        self.assertEqual(result["facts"]["transform"]["preview_hex"], "606062")
        for key in ("", "0", "zz", "01\u00a002", "0x12"):
            self.run_cli("xor", "--file", source, "--key-hex", key, code=2)
        alias = self.directory / "alias"
        os.link(source, alias)
        symlink = self.directory / "symlink"
        symlink.symlink_to(source)
        broken = self.directory / "broken"
        broken.symlink_to(self.directory / "absent")
        for target in (source, alias, symlink, broken, self.directory):
            self.run_cli("xor", "--file", source, "--key-hex", "01", "--out", target, code=2)
        self.assertEqual(source.read_bytes(), b"abc")

    def test_unicode_dash_paths_and_determinism(self):
        source = self.write("-snow 雪.bin", b"\x80\x00\xff")
        first = self.run_cli("xor", "--file=" + source.name, "--key-hex", "ff", cwd=self.directory)
        second = self.run_cli("xor", "--file=" + source.name, "--key-hex", "ff", cwd=self.directory)
        self.assertEqual(first, second)
        self.assertEqual(first["facts"]["transform"]["preview_hex"], "7fff00")

    def test_missing_nonregular_and_source_budget(self):
        for path in (self.directory / "absent", self.directory):
            self.run_cli("inspect", "--file", path, code=2)
        fifo = self.directory / "pipe"
        os.mkfifo(fifo)
        self.run_cli("bits", "--file", fifo, code=2)
        source = self.write("large", b"")
        with source.open("wb") as output:
            output.truncate(ctf.SOURCE_LIMIT + 1)
        self.run_cli("xor", "--file", source, "--key-hex", "01", code=1)

    def test_inspection_hash_and_missing_capability(self):
        source = self.write("not-an-image.jpg", b"some plain text\n")
        result = self.run_cli("inspect", "--file", source, "--sha256")
        self.assertEqual(result["facts"]["sha256"]["value"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertNotIn("image", result["facts"])
        environment = dict(os.environ, PATH=str(self.directory))
        result = self.run_cli("inspect", "--file", source, env=environment, code=3)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["facts"]["classification"]["value"], "unknown")
        self.run_cli("doctor", "--workflow", "bytes", env=environment)
        result = self.run_cli("doctor", "--workflow", "inspect", env=environment, code=3)
        self.assertFalse(result["facts"]["tools"]["file"]["present"])

    def test_real_tools_image_and_doctor(self):
        if not ctf.shutil.which("file") or not ctf.shutil.which("exiftool"):
            self.skipTest("Optional local file/ExifTool tools unavailable; missing states are tested separately")
        source = self.write("image-misleading.txt", ctf.png_probe())
        result = self.run_cli("inspect", "--file", source)
        self.assertEqual(result["facts"]["image"]["tags"]["ImageWidth"], 1)
        self.assertFalse(result["facts"]["image"]["gps_present"])
        self.run_cli("doctor", "--workflow", "inspect")

    def test_jpeg_metadata_with_and_without_gps(self):
        if not ctf.shutil.which("file") or not ctf.shutil.which("exiftool"):
            self.skipTest("Optional image tools unavailable")
        def segment(marker, data):
            return b"\xff" + bytes([marker]) + struct.pack(">H", len(data) + 2) + data
        def jpeg(gps):
            exif = b""
            if gps:
                tiff = b"II" + struct.pack("<HI", 42, 8)
                tiff += struct.pack("<H", 1) + struct.pack("<HHII", 0x8825, 4, 1, 26) + b"\0" * 4
                tiff += struct.pack("<H", 4)
                tiff += struct.pack("<HHI4s", 1, 2, 2, b"N\0\0\0")
                tiff += struct.pack("<HHII", 2, 5, 3, 80)
                tiff += struct.pack("<HHI4s", 3, 2, 2, b"E\0\0\0")
                tiff += struct.pack("<HHII", 4, 5, 3, 104) + b"\0" * 4
                tiff += struct.pack("<12I", 12, 1, 30, 1, 0, 1, 34, 1, 15, 1, 0, 1)
                exif = segment(0xe1, b"Exif\0\0" + tiff)
            # Authored one-pixel grayscale JPEG: one zero DC coefficient and an EOB.
            tables = bytes([0, 1] + [0] * 15 + [0, 0x10, 1] + [0] * 15 + [0])
            return (b"\xff\xd8" + exif + segment(0xdb, b"\0" + b"\1" * 64)
                    + segment(0xc0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00")
                    + segment(0xc4, tables) + segment(0xda, b"\x01\x01\x00\x00\x3f\x00")
                    + b"\x3f\xff\xd9")
        for gps in (False, True):
            path = self.write("photo.bin", jpeg(gps))
            result = self.run_cli("inspect", "--file", path)
            self.assertEqual(result["facts"]["image"]["gps_present"], gps)
            if gps:
                self.assertEqual(result["facts"]["image"]["tags"]["GPSLatitude"], 12.5)
                self.assertEqual(result["facts"]["image"]["tags"]["GPSLongitude"], 34.25)

    def test_unsupported_feature_and_partial_failure_precedence(self):
        executable = self.write("file", ("#!" + sys.executable + "\nimport sys\nprint('unrecognized option',file=sys.stderr)\nsys.exit(1)\n").encode())
        executable.chmod(0o700)
        source = self.write("image", ctf.png_probe())
        env = dict(os.environ, PATH=str(self.directory))
        result = self.run_cli("inspect", "--file", source, env=env, code=3)
        self.assertEqual(result["status"], "partial")
        executable.write_text("#!" + sys.executable + "\nimport sys\nprint('read failure',file=sys.stderr)\nsys.exit(1)\n")
        result = self.run_cli("inspect", "--file", source, env=env, code=1)
        self.assertEqual(result["status"], "partial")
        self.assertGreaterEqual(len(result["notices"]), 2)

    def test_inspect_aggregate_read_limit_and_fsync_mutation(self):
        source = self.write("input", b"plain text" * 10)
        capture = io.StringIO()
        with mock.patch.object(ctf, "SOURCE_LIMIT", 210), mock.patch("sys.stdout", capture):
            code = ctf.main(["inspect", "--file", str(source), "--sha256", "--json"])
        self.assertEqual(code, 0)
        with mock.patch.object(ctf, "SOURCE_LIMIT", 150), mock.patch("sys.stdout", io.StringIO()):
            code = ctf.main(["inspect", "--file", str(source), "--sha256", "--json"])
        self.assertEqual(code, 1)
        destination = self.directory / "output"
        real_fsync = os.fsync
        def mutate_during_fsync(fd):
            real_fsync(fd)
            source.write_bytes(b"changed!")
        with mock.patch.object(ctf.os, "fsync", mutate_during_fsync), mock.patch("sys.stdout", io.StringIO()):
            code = ctf.main(["xor", "--file", str(source), "--key-hex", "01", "--out", str(destination), "--json"])
        self.assertEqual(code, 1)
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.directory.glob(".ctf-*")))

    def test_zip_normal_empty_and_display_limit(self):
        for count in (0, 2, 101):
            path = self.make_zip(count)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            result = self.run_cli("inspect", "--file", path)
            metadata = result["facts"]["zip"]
            self.assertEqual(metadata["member_count"], count)
            self.assertEqual(metadata["expanded_bytes"], count * 3)
            self.assertEqual(len(metadata["rows"]), min(count, 100))
            self.assertEqual(metadata["rows_truncated"], count > 100)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_zip_comments_lying_count_corrupt_and_encryption_fact(self):
        # The second signature is comment data, even when it could mimic an EOF-reaching empty EOCD.
        fake = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
        path = self.make_zip(2, b"comment " + fake)
        result = self.run_cli("inspect", "--file", path)
        self.assertEqual(result["facts"]["zip"]["member_count"], 2)
        path = self.make_zip(2)
        raw = bytearray(path.read_bytes())
        eocd = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", raw, eocd + 8, 1, 1)
        path.write_bytes(raw)
        self.run_cli("inspect", "--file", path, code=2)
        path = self.make_zip(2)
        raw = bytearray(path.read_bytes())
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, central + 8, 1)
        path.write_bytes(raw)
        result = self.run_cli("inspect", "--file", path)
        self.assertEqual(result["facts"]["zip"]["encrypted_members"], 1)
        path.write_bytes(b"PK\x03\x04truncated")
        self.run_cli("inspect", "--file", path, code=2)

    def test_zip_eocd_signature_inside_stored_member(self):
        # Regression derived from independent review: member bytes can mimic an EOF-reaching EOCD.
        name = "member.bin"
        for fake_directory_size, fake_offset, fake_count in ((0, 0, 0), (4, 36, 0),
                                                            (0, 0, 10001), (0, 40, 10001)):
            payload = bytearray(struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, fake_count, fake_count,
                                            fake_directory_size, fake_offset, 82) + b"body")
            path = self.directory / "embedded-record.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), payload)
            with zipfile.ZipFile(path) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read(name), payload)
            result = self.run_cli("inspect", "--file", path)
            self.assertEqual(result["facts"]["zip"]["member_count"], 1)
            self.assertEqual(result["facts"]["zip"]["rows"][0]["name"], name)

    def test_zip_unsupported_and_budgets(self):
        path = self.make_zip()
        original = path.read_bytes()
        for offset, value, code in ((4, 1, 3), (10, 0xffff, 3), (8, 10001, 1)):
            raw = bytearray(original)
            eocd = raw.rfind(b"PK\x05\x06")
            if offset == 8:
                struct.pack_into("<HH", raw, eocd + 8, value, value)
            else:
                struct.pack_into("<H", raw, eocd + offset, value)
            path.write_bytes(raw)
            self.run_cli("inspect", "--file", path, code=code)
        path.write_bytes(b"MZ stub" + original)
        result = self.run_cli("inspect", "--file", path, code=3)
        self.assertIn("SFX", " ".join(result["notices"]))

    def test_zip_genuine_member_and_consumed_byte_limits_still_stop(self):
        path = self.make_zip(10001)
        result = self.run_cli("inspect", "--file", path, code=1)
        self.assertIn("10,000 members", " ".join(result["notices"]))
        path = self.make_zip(2)
        data = path.read_bytes()
        with mock.patch.object(ctf, "SOURCE_LIMIT", len(data)):
            with self.assertRaisesRegex(ctf.WorkLimit, "source-byte limit"):
                ctf.zip_metadata(io.BytesIO(data), len(data), data[:65536], ctf.Budget())

    def test_process_output_timeout_and_argument_arrays(self):
        budget = ctf.Budget()
        with mock.patch.object(ctf, "TOOL_LIMIT", 1024):
            with self.assertRaisesRegex(ctf.Problem, "output truncated"):
                ctf.run_tool([sys.executable, "-c", "import os; os.write(1,b'x'*2000)"], budget)
        with mock.patch.object(ctf, "TOOL_TIMEOUT", 0.1):
            with self.assertRaisesRegex(ctf.Problem, "timeout"):
                ctf.run_tool([sys.executable, "-c", "import time; time.sleep(10)"], ctf.Budget())
        code, output, _ = ctf.run_tool([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(touch nope); test"], ctf.Budget())
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), b"$(touch nope); test")

    def test_changed_input_never_publishes(self):
        source = self.write("input", b"A" * (ctf.CHUNK + 1))
        output = self.directory / "output"
        args = ctf.parser().parse_args(["xor", "--file", str(source), "--key-hex", "01", "--out", str(output)])
        original_write = ctf.Output.write
        changed = False
        def mutate(sink, data):
            nonlocal changed
            original_write(sink, data)
            if not changed:
                source.write_bytes(b"B" * (ctf.CHUNK + 1))
                changed = True
        result = {"parameters": {}, "facts": {}, "scope": [], "notices": []}
        with mock.patch.object(ctf.Output, "write", mutate):
            with self.assertRaisesRegex(ctf.Problem, "changed"):
                ctf.xor(args, result, ctf.Budget())
        self.assertFalse(output.exists())
        self.assertFalse(list(self.directory.glob(".ctf-*")))

    def test_publication_race_preserves_existing_destination(self):
        destination = self.directory / "output"
        sink = ctf.Output(str(destination))
        try:
            sink.write(b"new")
            destination.write_bytes(b"owner")
            with self.assertRaises(ctf.Problem):
                sink.publish()
            self.assertEqual(destination.read_bytes(), b"owner")
        finally:
            sink.close()
        self.assertFalse(list(self.directory.glob(".ctf-*")))

    def test_ctrl_c_removes_staging_file(self):
        source = self.write("cancel-source", b"")
        with source.open("wb") as output:
            output.truncate(ctf.SOURCE_LIMIT)
        destination = self.directory / "cancel-output"
        process = subprocess.Popen([sys.executable, str(CLI), "xor", "--file", str(source), "--key-hex", "12", "--out", str(destination), "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not list(self.directory.glob(".ctf-*")) and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(list(self.directory.glob(".ctf-*")))
            process.send_signal(signal.SIGINT)
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130, out + err)
            self.assertEqual(json.loads(out)["status"], "failed")
            self.assertFalse(destination.exists())
            self.assertFalse(list(self.directory.glob(".ctf-*")))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_constructor_cancellation_cleans_allocated_staging_file(self):
        source = self.write("cancel-input", b"preserve")
        destination = self.directory / "cancel-output"
        real_fdopen = os.fdopen
        def interrupt_output(fd, mode):
            if mode == "wb":
                raise KeyboardInterrupt()
            return real_fdopen(fd, mode)
        with mock.patch.object(ctf.os, "fdopen", interrupt_output), mock.patch("sys.stdout", io.StringIO()):
            code = ctf.main(["xor", "--file", str(source), "--key-hex", "01", "--out", str(destination), "--json"])
        self.assertEqual(code, 130)
        self.assertEqual(source.read_bytes(), b"preserve")
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.directory.glob(".ctf-*")))

    def test_non_zip_archive_gets_observed_format_manual_route(self):
        if not ctf.shutil.which("file"):
            self.skipTest("Classification tool unavailable")
        path = self.directory / "archive.bin"
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("demo.txt")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"demo"))
        result = self.run_cli("inspect", "--file", path)
        self.assertEqual(result["facts"]["classification"]["value"], "application/x-tar")
        self.assertIn("kali-2", result["next_actions"][0])
        self.assertIn("structure was not inspected", " ".join(result["scope"]))
        self.assertNotIn("zip", result["facts"])
        path.write_bytes(b"ordinary text")
        result = self.run_cli("inspect", "--file", path)
        self.assertEqual(result["next_actions"], [])

    def test_runtime_and_json_before_command(self):
        completed = subprocess.run([sys.executable, str(CLI), "--json", "doctor", "--workflow", "bytes"], capture_output=True)
        self.assertEqual(completed.returncode, 0)
        json.loads(completed.stdout)
        for runtime in ((3, 9), (3, 10)):
            capture = io.StringIO()
            with mock.patch.object(ctf.sys, "version_info", runtime), mock.patch("sys.stdout", capture):
                code = ctf.main(["doctor", "--workflow", "bytes", "--json"])
            self.assertEqual(code, 3 if runtime < (3, 10) else 0)
        with mock.patch.object(ctf.sys, "platform", "win32"), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(ctf.main(["doctor", "--workflow", "bytes", "--json"]), 3)


if __name__ == "__main__":
    unittest.main()
