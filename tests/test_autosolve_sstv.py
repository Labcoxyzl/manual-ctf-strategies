import hashlib
import json
import math
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import wave
from pathlib import Path
from unittest import mock
import sys

from scripts.autosolve_lib.profiles import sstv


ROOT = Path(__file__).resolve().parents[1]
DECODER = Path(os.environ.get("AUTOSOLVE_SSTV", ROOT / "tools/python/PySSTV/bin/sstv"))
ENCODER_PYTHON = ROOT / "tools/python/PySSTV/bin/python"
MARTIN = ROOT / "tools/python/sstv-decoder/test/data/m1.ogg"


class SSTVTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_missing_wrong_decoder_and_source_bounds(self):
        source = self.root / "noise.wav"
        with wave.open(str(source), "wb") as wav:
            wav.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
            wav.writeframes(b"\x00\x00" * 16000)
        with mock.patch.object(sstv, "SSTV", "/missing/decoder"):
            rows, warnings = sstv.decode_sstv(source, self.root / "out", timeout=2,
                                               max_bytes=1024)
        self.assertEqual(rows, [])
        self.assertIn("unavailable", warnings[0])
        wrong = self.root / "wrong-sstv"
        wrong.write_text("#!/bin/sh\necho 'PySSTV encoder'\n")
        wrong.chmod(0o700)
        with mock.patch.object(sstv, "SSTV", str(wrong)):
            self.assertFalse(sstv.decoder_available())
            from scripts.autosolve_lib import setup
            readiness = setup.doctor(["audio_video"], self_test=False)
        self.assertEqual(readiness["engines"]["sstv"]["status"], "unavailable")
        self.assertEqual(readiness["operations"]["audio_video.sstv"]["status"], "unavailable")
        self.assertEqual(readiness["operations"]["audio_video.sstv"]["reason"],
                         "approved_sstv_decoder_or_ffmpeg_missing")
        with mock.patch.object(sstv, "MAX_SOURCE_BYTES", 10):
            rows, warnings = sstv.decode_sstv(source, self.root / "out", timeout=2,
                                               max_bytes=1024)
        self.assertEqual(rows, [])
        self.assertIn("byte limit", warnings[0])
        with self.assertRaises(ValueError):
            sstv.decode_sstv(source, self.root / "out", timeout=0, max_bytes=1024)

    def test_missing_fixture_reason_when_decoder_is_compatible(self):
        from scripts.autosolve_lib import setup
        with (mock.patch.object(setup, "__file__", str(self.root / "scripts/autosolve_lib/setup.py")),
              mock.patch.object(setup.shutil, "which", return_value="/synthetic/available"),
              mock.patch.object(sstv, "decoder_available", return_value=True)):
            operation, _ = setup._sstv_probe(True)
        self.assertEqual((operation["status"], operation["functional_probe"], operation["reason"]),
                         ("partial", "not_run", "sstv_probe_fixture_missing"))

    @unittest.skipUnless(DECODER.is_file() and shutil.which("ffmpeg"),
                         "approved decoder and FFmpeg required")
    def test_packaged_robot_doctor_and_decode_failure(self):
        from scripts.autosolve_lib import setup
        fixture = ROOT / "tests/fixtures/toolkit/audio/robot36.wav"
        self.assertTrue(fixture.is_file())
        with mock.patch.object(sstv, "SSTV", str(DECODER)):
            operation = setup.doctor(["audio_video"], self_test=True)["operations"]["audio_video.sstv"]
            self.assertEqual((operation["status"], operation["functional_probe"], operation["reason"]),
                             ("ready", "passed", None))
            with mock.patch.object(sstv, "decode_sstv", return_value=([], ["bad fixture"])):
                operation, _ = setup._sstv_probe(True)
            self.assertEqual((operation["status"], operation["functional_probe"], operation["reason"]),
                             ("partial", "failed", "sstv_probe_failed"))

    @unittest.skipUnless(DECODER.is_file() and MARTIN.is_file() and shutil.which("ffmpeg"),
                         "approved decoder, Martin fixture and FFmpeg required")
    def test_real_martin_decode_and_non_sstv_negative(self):
        with mock.patch.object(sstv, "SSTV", str(DECODER)):
            self.assertTrue(sstv.decoder_available())
            before = hashlib.sha256(MARTIN.read_bytes()).hexdigest()
            rows, warnings = sstv.decode_sstv(MARTIN, self.root / "stage", timeout=20,
                                               max_bytes=1024 * 1024)
            self.assertEqual(warnings, [])
            self.assertEqual(len(rows), 1)
            record = rows[0]
            self.assertEqual(record["mode"], "Martin 1")
            self.assertEqual((record["width"], record["height"]), (320, 256))
            self.assertEqual(record["sha256"], hashlib.sha256(record["path"].read_bytes()).hexdigest())
            self.assertEqual(record["source"], str(MARTIN.resolve()))
            self.assertIn("recording 0-", record["locator"])
            self.assertEqual(before, hashlib.sha256(MARTIN.read_bytes()).hexdigest())
            silent = self.root / "silence.wav"
            with wave.open(str(silent), "wb") as wav:
                wav.setparams((1, 2, 11025, 0, "NONE", "not compressed"))
                wav.writeframes(b"\x00\x00" * 22050)
            rows, warnings = sstv.decode_sstv(silent, self.root / "negative", timeout=10,
                                               max_bytes=1024 * 1024)
            self.assertEqual(rows, [])
            self.assertTrue(any("VIS" in message or "header" in message for message in warnings), warnings)

    @unittest.skipUnless(DECODER.is_file() and ENCODER_PYTHON.is_file() and shutil.which("ffmpeg"),
                         "approved decoder, independent PySSTV encoder and FFmpeg required")
    def test_held_out_robot_resampled_silence_and_truncated_tail(self):
        source = self.root / "robot.wav"
        oracle = self.root / "oracle.png"
        script = (
            "from PIL import Image, ImageDraw\n"
            "from pysstv.color import Robot36\n"
            "import sys\n"
            "image=Image.new('RGB',(320,240),'white')\n"
            "draw=ImageDraw.Draw(image)\n"
            "draw.rectangle((30,30,290,210),fill='red')\n"
            "draw.rectangle((80,80,240,160),fill='blue')\n"
            "image.save(sys.argv[2])\n"
            "with open(sys.argv[1],'wb') as output: Robot36(image,8000,16).write_wav(output)\n"
        )
        subprocess.run([str(ENCODER_PYTHON), "-c", script, str(source), str(oracle)],
                       check=True, capture_output=True, timeout=15)
        with wave.open(str(source), "rb") as wav:
            params = wav.getparams()
            content = wav.readframes(wav.getnframes())
        lead = b"\x00\x00" * (params.framerate // 2)
        tail = b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 1900 * i / params.framerate)))
                        for i in range(params.framerate * 3))
        with wave.open(str(source), "wb") as wav:
            wav.setparams(params)
            wav.writeframes(lead + content + tail)
        with mock.patch.object(sstv, "SSTV", str(DECODER)):
            rows, warnings = sstv.decode_sstv(source, self.root / "stage", timeout=20,
                                               max_bytes=1024 * 1024)
            self.assertEqual(warnings, [])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mode"], "Robot 36")
            from PIL import Image, ImageChops, ImageStat
            with Image.open(rows[0]["path"]) as decoded, Image.open(oracle) as expected:
                error = ImageStat.Stat(ImageChops.difference(decoded.convert("RGB"), expected)).mean
            self.assertLess(max(error), 40, error)
            truncated = self.root / "truncated.wav"
            with wave.open(str(truncated), "wb") as wav:
                wav.setparams(params)
                wav.writeframes(lead + content[:len(content) // 2])
            rows, warnings = sstv.decode_sstv(truncated, self.root / "partial", timeout=20,
                                               max_bytes=1024 * 1024)
            self.assertEqual(rows, [])
            self.assertTrue(any("truncated" in message or "exited" in message for message in warnings), warnings)

    @unittest.skipUnless(DECODER.is_file() and MARTIN.is_file() and shutil.which("ffmpeg"),
                         "approved decoder, Martin fixture and FFmpeg required")
    def test_public_cli_image_lineage_resume_and_missing_decoder(self):
        script = ROOT / "scripts/autosolve.py"

        def cli(env, *arguments):
            result = subprocess.run([sys.executable, "-B", str(script), "--json",
                                     *map(str, arguments)], capture_output=True,
                                    timeout=60, env={**os.environ, "AUTOSOLVE_SSTV": env})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        run = Path(cli(str(DECODER), "analyze", MARTIN, "--category", "audio_video",
                       "--budget", "30", "--runs-root", self.root / "runs")["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["AV04"]["status"], "ran")
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "sstv"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "complete")
        children = [item for item in manifest["artifacts"] if item["id"] in jobs[0]["child_ids"]]
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0]["kind_evidence"], "png")
        self.assertEqual(children[0]["parents"][0]["job_key"], jobs[0]["key"])
        self.assertEqual(children[0]["source_locator"]["mode"], "Martin 1")
        self.assertEqual(children[0]["sha256"], hashlib.sha256(Path(children[0]["path"]).read_bytes()).hexdigest())
        self.assertTrue(any(job["adapter_id"] == "qr" and
                            children[0]["id"] in job["input_ids"] for job in manifest["jobs"]))

        cli(str(DECODER), "resume", run, "--budget", "10")
        resumed = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in resumed["jobs"] if job["adapter_id"] == "sstv"]), 1)
        missing = Path(cli("/missing/decoder", "analyze", MARTIN, "--category",
                           "audio_video", "--budget", "10", "--runs-root",
                           self.root / "missing-runs")["run"])
        no_decoder = json.loads((missing / "manifest.json").read_text())
        self.assertEqual(no_decoder["coverage"]["AV04"]["status"], "skipped prerequisite")
        self.assertFalse(any(job["adapter_id"] == "sstv" for job in no_decoder["jobs"]))


if __name__ == "__main__":
    unittest.main()
