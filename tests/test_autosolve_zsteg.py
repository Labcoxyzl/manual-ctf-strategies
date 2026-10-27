import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image

from scripts.autosolve_lib.profiles import zsteg


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class ZstegScratchTests(unittest.TestCase):
    def test_tool_child_uses_supplied_local_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            code = ('import tempfile; f=tempfile.NamedTemporaryFile(delete=False); '
                    'print(f.name); f.close()')
            output, warning = zsteg._run([sys.executable, '-c', code],
                                          time.monotonic() + 5, 4096, False,
                                          scratch_dir=scratch)
            self.assertIsNone(warning)
            self.assertTrue(Path(output.decode().strip()).is_relative_to(scratch))


def carrier(path: Path, payload: bytes, *, bits: int, channels: str,
            traversal: str = "xy", mode: str = "RGB", bit_order: str = "lsb",
            bit_offset: int = 0) -> None:
    width, height = 17, 16
    names = "RGBA" if mode == "RGBA" else "RGB"
    pixels = [[32, 96, 160, 224][:len(names)] for _ in range(width * height)]
    positions = ((x, y) for y in range(height) for x in range(width)) if traversal == "xy" else (
        (x, y) for x in range(width) for y in range(height))
    shifts = range(7, -1, -1) if bit_order == "lsb" else range(8)
    bits_in = [(byte >> shift) & 1 for byte in payload for shift in shifts]
    cursor = 0
    for x, y in positions:
        for channel in channels.upper():
            if cursor >= len(bits_in):
                break
            value = 0
            for _ in range(bits):
                value = (value << 1) | (bits_in[cursor] if cursor < len(bits_in) else 0)
                cursor += 1
            index = names.index(channel)
            mask = ((1 << bits) - 1) << bit_offset
            pixels[y * width + x][index] = (pixels[y * width + x][index] & ~mask) | (value << bit_offset)
    image = Image.new(mode, (width, height))
    image.putdata([tuple(pixel) for pixel in pixels])
    image.save(path)


@unittest.skipUnless(shutil.which("zsteg"), "zsteg is not installed")
class ZstegTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def inspect(self, source: Path, suffix: str):
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = zsteg.inspect_lsb(source, self.root / suffix, max_pixels=1000,
                                    max_total_bytes=100000, timeout=20)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        return result

    def test_one_bit_red_and_two_bit_bgr_extract_exact_tool_bytes(self):
        cases = (("red.png", b"ONE-BIT-ORACLE\n", 1, "r", "b1,r,lsb,xy"),
                 ("rgb.png", b"RGB-PLANE-ORACLE\n", 1, "rgb", "b1,rgb,lsb,xy"),
                 ("bgr.bmp", b"TWO-BIT-BGR-ORACLE\n", 2, "bgr", "b2,bgr,lsb,xy"))
        for filename, payload, bits, channels, selector in cases:
            with self.subTest(selector=selector):
                source = self.root / filename
                carrier(source, payload, bits=bits, channels=channels)
                records, warnings = self.inspect(source, filename + "-staged")
                selected = [row for row in records if row["selector"] == selector]
                self.assertEqual(len(selected), 1, (records, warnings))
                self.assertEqual(selected[0]["path"].read_bytes(), payload)
                self.assertEqual(selected[0]["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(selected[0]["finding_kind"], "text")
                self.assertEqual(selected[0]["source"], str(source.resolve()))

    def test_alpha_channel_yx_traversal_and_clean_negative(self):
        source = self.root / "alpha.png"
        payload = b"ALPHA-TRAVERSAL\n"
        carrier(source, payload, bits=1, channels="a", traversal="yx", mode="RGBA")
        records, warnings = self.inspect(source, "alpha-staged")
        selected = [row for row in records if row["selector"] == "b1,a,lsb,yx"]
        self.assertEqual(len(selected), 1, (records, warnings))
        self.assertEqual(selected[0]["path"].read_bytes(), payload)

        reversed_bits = self.root / "msb.png"
        carrier(reversed_bits, b"MSB-ORDER-ORACLE\n", bits=1, channels="g",
                bit_order="msb")
        records, warnings = self.inspect(reversed_bits, "msb-staged")
        selected = [row for row in records if row["selector"] == "b1,g,msb,xy"]
        self.assertEqual(len(selected), 1, (records, warnings))
        self.assertEqual(selected[0]["path"].read_bytes(), b"MSB-ORDER-ORACLE\n")

        clean = self.root / "clean.png"
        Image.new("RGB", (17, 16), (32, 96, 160)).save(clean)
        records, warnings = self.inspect(clean, "clean-staged")
        self.assertEqual(records, [], warnings)

    def test_blue_second_plane_bmp_extracts_exact_candidate(self):
        source = self.root / "blue-second-plane.bmp"
        payload = b"SECOND-PLANE-ORACLE\n"
        carrier(source, payload, bits=1, channels="b", bit_offset=1)
        records, warnings = self.inspect(source, "blue-second-plane-staged")
        selected = [row for row in records if row["selector"] == "b10,b,lsb,xy"]
        self.assertEqual(len(selected), 1, (records, warnings))
        self.assertEqual(selected[0]["path"].read_bytes(), payload)
        self.assertEqual(selected[0]["source"], str(source.resolve()))
        self._cli_case("bmp", payload, 1, "b", "b10,b,lsb,xy", bit_offset=1)

    def test_noisy_second_plane_is_never_validated(self):
        source = self.root / "noise.bmp"
        generator = random.Random(20261027)
        image = Image.new("RGB", (17, 16))
        image.putdata([tuple(generator.randrange(256) for _ in range(3)) for _ in range(272)])
        image.save(source)
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
             "--category", "images", "--budget", "30", "--runs-root", str(self.root / "runs-noise")],
            capture_output=True, timeout=35)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)["run"]) / "manifest.json").read_text())
        self.assertFalse(any(finding["state"] == "challenge_accepted"
                             for finding in manifest["findings"]))
        self.assertFalse(any(Path(item["path"]).read_bytes().startswith(b"SECOND-PLANE-ORACLE")
                             for item in manifest["artifacts"] if item["id"] != manifest["artifacts"][0]["id"]))

    def test_limits_missing_tool_and_separate_staging(self):
        source = self.root / "small.png"
        carrier(source, b"BOUNDARY-ORACLE\n", bits=1, channels="r")
        records, warnings = zsteg.inspect_lsb(source, self.root / "oversize",
                                               max_pixels=1, max_total_bytes=100000,
                                               timeout=2)
        self.assertEqual(records, [])
        self.assertIn("pixel limit", warnings[0])
        self.assertFalse((self.root / "oversize").exists())
        with mock.patch.object(zsteg, "ZSTEG", "/does/not/exist/zsteg"):
            records, warnings = self.inspect(source, "missing")
        self.assertEqual(records, [])
        self.assertIn("unavailable", warnings[0])
        with self.assertRaises(ValueError):
            zsteg.inspect_lsb(source, self.root, max_pixels=1000,
                              max_total_bytes=100000, timeout=2)
        with self.assertRaises(ValueError):
            zsteg.inspect_lsb(source, self.root / "unused", max_pixels=1000,
                              max_total_bytes=100000, timeout=0)

    def test_extraction_byte_budget_prevents_partial_publishing(self):
        source = self.root / "budget.png"
        carrier(source, b"BUDGET-ORACLE\n", bits=1, channels="r")
        records, warnings = zsteg.inspect_lsb(source, self.root / "tiny",
                                               max_pixels=1000, max_total_bytes=4,
                                               timeout=20)
        self.assertEqual(records, [])
        self.assertTrue(any("output limit" in warning for warning in warnings), warnings)
        self.assertEqual(list((self.root / "tiny").glob("*")), [])

    def test_process_timeout_reports_incomplete_inspection(self):
        source = self.root / "timeout.png"
        carrier(source, b"TIMEOUT-ORACLE\n", bits=1, channels="r")
        slow = self.root / "slow-zsteg"
        slow.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n")
        slow.chmod(0o700)
        with mock.patch.object(zsteg, "ZSTEG", str(slow)):
            records, warnings = zsteg.inspect_lsb(
                source, self.root / "timeout-staged", max_pixels=1000,
                max_total_bytes=100000, timeout=0.1)
        self.assertEqual(records, [])
        self.assertIn("timed out", warnings[0])
        self.assertFalse((self.root / "timeout-staged").exists())

    def test_public_cli_retains_selector_lineage_and_resume(self):
        with self.subTest(format="PNG"):
            self._cli_case("png", b"CLI-RED-ORACLE\n", 1, "r", "b1,r,lsb,xy")
        with self.subTest(format="BMP"):
            self._cli_case("bmp", b"CLI-BGR-ORACLE\n", 2, "bgr", "b2,bgr,lsb,xy")

    def _cli_case(self, suffix, payload, bits, channels, selector, bit_offset=0):
        source = self.root / f"cli-{suffix}.{suffix}"
        carrier(source, payload, bits=bits, channels=channels, bit_offset=bit_offset)
        before = source.read_bytes()
        command = [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
                   "--category", "images", "--budget", "30", "--runs-root",
                   str(self.root / f"runs-{suffix}")]
        result = subprocess.run(command, capture_output=True, timeout=35)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        found = [item for item in manifest["artifacts"]
                 if item["source_locator"].get("zsteg_selector") == selector]
        self.assertEqual(len(found), 1)
        self.assertEqual(Path(found[0]["path"]).read_bytes(), payload)
        self.assertEqual(found[0]["parents"][0]["id"], manifest["artifacts"][0]["id"])
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "zsteg"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(found[0]["parents"][0]["job_key"], jobs[0]["key"])
        self.assertEqual(manifest["coverage"]["IMG02"]["status"], "ran")
        self.assertTrue(any(finding["state"] == "candidate" and
                            finding["source_locator"].get("zsteg_selector") == selector
                            for finding in manifest["findings"]))
        self.assertFalse(any(finding["state"] == "challenge_accepted"
                             for finding in manifest["findings"]))
        resume = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", "resume",
                                 str(run), "--budget", "30"], capture_output=True, timeout=35)
        self.assertEqual(resume.returncode, 3, resume.stderr + resume.stdout)
        resumed = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in resumed["jobs"] if job["adapter_id"] == "zsteg"]), 1)
        self.assertTrue(next(item for item in resumed["artifacts"]
                             if item["id"] == found[0]["id"])["current"])
        self.assertEqual(source.read_bytes(), before)

    def test_public_cli_reports_missing_zsteg_prerequisite(self):
        source = self.root / "missing.png"
        carrier(source, b"MISSING-TOOL-ORACLE\n", bits=1, channels="r")
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
             "--category", "images", "--budget", "10", "--runs-root", str(self.root / "runs-missing")],
            capture_output=True, timeout=20,
            env={**os.environ, "AUTOSOLVE_ZSTEG": "/does/not/exist/zsteg"})
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["IMG02"]["status"], "skipped prerequisite")


if __name__ == "__main__":
    unittest.main()
