import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import wave
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import stegseek
from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class StegseekTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_private_stub_password_index_and_limits(self):
        source = self.root / "source.jpg"
        source.write_bytes(b"\xff\xd8\xff" + b"a" * 200)
        stub = self.root / "stegseek-stub"
        stub.write_text("#!/usr/bin/env python3\n"
                        "import pathlib, sys\n"
                        "word = pathlib.Path(sys.argv[-2]).read_bytes().strip()\n"
                        "if word == b'right':\n"
                        "    pathlib.Path(sys.argv[-1]).write_bytes(b'PAYLOAD')\n"
                        "    sys.exit(0)\n"
                        "sys.exit(1)\n")
        stub.chmod(0o700)
        with mock.patch.object(stegseek, "STEGSEEK", str(stub)):
            records, warnings = stegseek.extract_steghide(
                source, self.root / "stage", passwords=[b"wrong", b"right"],
                max_total_bytes=64, timeout=2)
        self.assertEqual(warnings, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["password_index"], 1)
        self.assertEqual(records[0]["path"].read_bytes(), b"PAYLOAD")
        self.assertEqual(records[0]["sha256"], hashlib.sha256(b"PAYLOAD").hexdigest())
        self.assertEqual(records[0]["source"], str(source.resolve()))
        self.assertEqual(source.read_bytes(), b"\xff\xd8\xff" + b"a" * 200)
        with mock.patch.object(stegseek, "STEGSEEK", str(stub)):
            records, warnings = stegseek.extract_steghide(
                source, self.root / "limited", passwords=[b"right"],
                max_total_bytes=3, timeout=2)
        self.assertEqual(records, [])
        self.assertTrue(any("byte limit" in warning for warning in warnings), warnings)
        self.assertEqual(list((self.root / "limited").glob("stegseek-*")), [])

    def test_negative_missing_tool_and_validation(self):
        source = self.root / "cover.jpg"
        source.write_bytes(b"\xff\xd8\xff" + b"x" * 20)
        missing = self.root / "missing"
        with mock.patch.object(stegseek, "STEGSEEK", str(missing)):
            records, warnings = stegseek.extract_steghide(
                source, self.root / "stage", passwords=[b"hint"],
                max_total_bytes=100, timeout=2)
        self.assertEqual(records, [])
        self.assertIn("unavailable", warnings[0])
        records, warnings = stegseek.extract_steghide(
            source, self.root / "unused", passwords=[], max_total_bytes=100, timeout=2)
        self.assertEqual(records, [])
        self.assertIn("requires", warnings[0])
        with self.assertRaises(ValueError):
            stegseek.extract_steghide(source, self.root, passwords=[b"hint"],
                                      max_total_bytes=100, timeout=2)
        with self.assertRaises(ValueError):
            stegseek.extract_steghide(source, self.root / "unused", passwords=[b"a\nb"],
                                      max_total_bytes=100, timeout=2)

    def test_timeout_is_distinct(self):
        source = self.root / "source.jpg"
        source.write_bytes(b"\xff\xd8\xff" + b"x" * 20)
        stub = self.root / "slow-stub"
        stub.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n")
        stub.chmod(0o700)
        with mock.patch.object(stegseek, "STEGSEEK", str(stub)):
            records, warnings = stegseek.extract_steghide(
                source, self.root / "stage", passwords=[b"hint"],
                max_total_bytes=100, timeout=0.1)
        self.assertEqual(records, [])
        self.assertIn("timed out", warnings[0])

    def test_seed_probe_classifies_only_supported_completed_searches(self):
        stub = self.root / "stegseek-seed-stub"
        stub.write_text("#!/usr/bin/env python3\n"
                        "import pathlib, sys, time\n"
                        "a = sys.argv[1:]\n"
                        "if a == ['--version']:\n"
                        "    print('StegSeek 0.5' if pathlib.Path(sys.argv[0]).with_suffix('.old').exists() else 'StegSeek 0.6',\n"
                        "          file=sys.stderr if pathlib.Path(sys.argv[0]).with_suffix('.stderr').exists() else sys.stdout)\n"
                        "    sys.exit(0)\n"
                        "if '--seed' not in a: sys.exit(1)\n"
                        "source = pathlib.Path(a[-2]).name\n"
                        "if source == 'slow.jpg': time.sleep(2)\n"
                        "if source == 'encrypted.jpg':\n"
                        "    pathlib.Path(a[-1]).write_bytes(b'UNVERIFIED-SEED-BYTES')\n"
                        "    sys.exit(0)\n"
                        "if source == 'unknown.jpg':\n"
                        "    print('error: unsupported input', file=sys.stderr)\n"
                        "    sys.exit(1)\n"
                        "if pathlib.Path(sys.argv[0]).with_suffix('.banner').exists():\n"
                        "    print('StegSeek 0.6 - https://github.com/RickdeJager/StegSeek\\n', file=sys.stderr)\n"
                        "    print('[!] error: Could not find a valid seed.', file=sys.stderr)\n"
                        "    sys.exit(1)\n"
                        "print('error: Could not find a valid seed.', file=sys.stderr)\n"
                        "sys.exit(1)\n")
        stub.chmod(0o700)
        with mock.patch.object(stegseek, "STEGSEEK", str(stub)):
            for name, expected in (("clean.jpg", "no_seed"),
                                   ("benign.jpg", "no_seed"),
                                   ("encrypted.jpg", "possible_seed"),
                                   ("unknown.jpg", "inconclusive")):
                source = self.root / name
                source.write_bytes(b"\xff\xd8\xff" + b"x" * 20)
                stage = self.root / name.replace('.jpg', '')
                self.assertEqual(stegseek.probe_seed(source, stage, timeout=1), expected)
                self.assertEqual(list(stage.iterdir()), [])
            (self.root / "stegseek-seed-stub.old").touch()
            self.assertEqual(stegseek.probe_seed(self.root / "clean.jpg", self.root / "old",
                                                 timeout=1), "unsupported")
            (self.root / "stegseek-seed-stub.old").unlink()
            (self.root / "stegseek-seed-stub.stderr").touch()
            self.assertEqual(stegseek.probe_seed(self.root / "clean.jpg", self.root / "version-stderr",
                                                 timeout=1), "no_seed")
            (self.root / "stegseek-seed-stub.stderr").unlink()
            (self.root / "stegseek-seed-stub.banner").touch()
            self.assertEqual(stegseek.probe_seed(self.root / "clean.jpg", self.root / "banner-error",
                                                 timeout=1), "no_seed")
            (self.root / "stegseek-seed-stub.banner").unlink()
            slow = self.root / "slow.jpg"
            slow.write_bytes(b"\xff\xd8\xff" + b"x" * 20)
            self.assertEqual(stegseek.probe_seed(slow, self.root / "slow", timeout=0.2),
                             "timed_out")

    def test_public_cli_seed_hint_distinguishes_clean_and_missing_password(self):
        stub = self.root / "stegseek-seed-cli-stub"
        stub.write_text("#!/usr/bin/env python3\n"
                        "import os, pathlib, sys\n"
                        "a = sys.argv[1:]\n"
                        "if a == ['--version']: print('StegSeek 0.6'); sys.exit(0)\n"
                        "if '--seed' in a:\n"
                        "    pathlib.Path(os.environ['SEED_LOG']).write_text('ran')\n"
                        "    if pathlib.Path(a[-2]).name == 'encrypted.jpg':\n"
                        "        pathlib.Path(a[-1]).write_bytes(b'UNVERIFIED-SEED-BYTES')\n"
                        "        sys.exit(0)\n"
                        "    print('error: Could not find a valid seed.', file=sys.stderr)\n"
                        "    sys.exit(1)\n"
                        "sys.exit(1)\n")
        stub.chmod(0o700)
        password = self.root / "private-passwords.txt"
        password.write_text("wrong-password\n")
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"password_file": str(password), "stegseek_seed": True}))
        env = os.environ.copy()
        env.update(AUTOSOLVE_STEGSEEK=str(stub), SEED_LOG=str(self.root / "seed.log"))

        for name, expected in (("clean.jpg", "no_seed"),
                               ("encrypted.jpg", "possible_seed")):
            source = self.root / name
            source.write_bytes(b"\xff\xd8\xff" + b"x" * 100)
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
                 "--category", "images", "--budget", "60", "--hints", str(hints),
                 "--runs-root", str(self.root / "runs")], env=env,
                capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            run = Path(json.loads(result.stdout)["run"])
            manifest = json.loads((run / "manifest.json").read_text())
            jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "stegseek"]
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["seed_outcome"], expected)
            self.assertEqual(manifest["coverage"]["IMG03"]["status"], "no finding")
            self.assertIn("no supported Steghide seed" if expected == "no_seed"
                          else "possible Steghide seed metadata",
                          manifest["coverage"]["IMG03"]["note"])
            self.assertFalse(any(item["current"] and item["source_locator"].get("stego_engine")
                                 == "stegseek" for item in manifest["artifacts"]))
            self.assertFalse(any(item["current"] and item["state"] == "challenge_accepted"
                                 for item in manifest["findings"]))
            self.assertEqual(source.read_bytes(), b"\xff\xd8\xff" + b"x" * 100)
            report = (run / "report.md").read_text()
            self.assertNotIn("wrong-password", report)
            self.assertNotIn("UNVERIFIED-SEED-BYTES", report)
            self.assertTrue((self.root / "seed.log").is_file())
            (self.root / "seed.log").unlink()

        source = self.root / "budget.jpg"
        source.write_bytes(b"\xff\xd8\xff" + b"x" * 100)
        short = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
             "--category", "images", "--budget", "8", "--hints", str(hints),
             "--runs-root", str(self.root / "runs")], env=env,
            capture_output=True, timeout=20)
        self.assertEqual(short.returncode, 3, short.stderr + short.stdout)
        run = Path(json.loads(short.stdout)["run"])
        before = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in before["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["seed_outcome"], "not_run_budget")
        self.assertEqual(jobs[0]["status"], "truncated")
        self.assertEqual(before["coverage"]["IMG03"]["status"], "truncated")
        self.assertFalse((self.root / "seed.log").exists())

        resumed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "resume", str(run),
             "--budget", "60", "--hints", str(hints)], env=env,
            capture_output=True, timeout=20)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in after["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[-1]["seed_outcome"], "no_seed")
        self.assertEqual(jobs[-1]["status"], "complete")
        self.assertEqual(after["coverage"]["IMG03"]["status"], "no finding")
        self.assertTrue((self.root / "seed.log").exists())
        (self.root / "seed.log").unlink()

        hints.write_text(json.dumps({"password_file": str(password)}))
        default = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
             "--category", "images", "--budget", "60", "--hints", str(hints),
             "--runs-root", str(self.root / "runs")], env=env,
            capture_output=True, timeout=20)
        self.assertEqual(default.returncode, 3, default.stderr + default.stdout)
        run = Path(json.loads(default.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 1)
        self.assertNotIn("seed_outcome", jobs[0])
        self.assertEqual(manifest["coverage"]["IMG03"]["status"], "no finding")
        self.assertFalse((self.root / "seed.log").exists())

    def test_public_cli_password_timeout_is_retried_on_resume(self):
        source = self.root / "source.jpg"
        source.write_bytes(b"\xff\xd8\xff" + b"x" * 100)
        stub = self.root / "slow-crack"
        stub.write_text("#!/usr/bin/env python3\nimport os, time\n"
                        "time.sleep(float(os.environ.get('STEGSEEK_DELAY', '0')))\n"
                        "raise SystemExit(1)\n")
        stub.chmod(0o700)
        password = self.root / "passwords.txt"
        password.write_text("wrong\n")
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"password_file": str(password)}))
        env = os.environ.copy()
        env["AUTOSOLVE_STEGSEEK"] = str(stub)
        env["STEGSEEK_DELAY"] = "2"
        first = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "analyze", str(source),
             "--category", "images", "--budget", "1", "--hints", str(hints),
             "--runs-root", str(self.root / "runs")], env=env,
            capture_output=True, timeout=10)
        self.assertEqual(first.returncode, 3, first.stderr + first.stdout)
        run = Path(json.loads(first.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "truncated")

        env["STEGSEEK_DELAY"] = "0"
        resumed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--json", "resume", str(run),
             "--budget", "4", "--hints", str(hints)], env=env,
            capture_output=True, timeout=10)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[-1]["status"], "complete")
        self.assertEqual(manifest["coverage"]["IMG03"]["status"], "no finding")


@unittest.skipUnless(shutil.which("stegseek") and shutil.which("steghide"),
                     "stegseek and steghide are required for real fixture")
class RealStegseekTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _cover(self, suffix):
        if suffix == "wav":
            path = self.root / "cover.wav"
            with wave.open(str(path), "wb") as output:
                output.setnchannels(1)
                output.setsampwidth(2)
                output.setframerate(8000)
                output.writeframes(random.Random(13).randbytes(32000))
            return path
        from PIL import Image
        path = self.root / "cover.jpg"
        Image.frombytes("RGB", (256, 256), random.Random(13).randbytes(256 * 256 * 3)).save(
            path, quality=90)
        return path

    def test_doctor_reports_real_stegseek_probe(self):
        result = capabilities.doctor(["images"], self_test=True)
        self.assertEqual(result["operations"]["images.stegseek"]["functional_probe"], "passed")
        self.assertEqual(result["engines"]["stegseek"]["status"], "ready")

    def test_encrypted_and_unencrypted_jpeg_wav(self):
        for suffix, encrypted in (("jpg", True), ("wav", False)):
            with self.subTest(suffix=suffix):
                cover = self._cover(suffix)
                original = cover.read_bytes()
                payload = self.root / "message.bin"
                content = f"REAL-STEGO-{suffix}".encode()
                payload.write_bytes(content)
                stego = self.root / f"stego.{suffix}"
                argv = ["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
                        "-sf", str(stego), "-p", "fixture-secret", "-f", "-q"]
                if not encrypted:
                    argv.extend(["-e", "none"])
                subprocess.run(argv, check=True, capture_output=True, timeout=10)
                records, warnings = stegseek.extract_steghide(
                    stego, self.root / f"stage-{suffix}",
                    passwords=[b"incorrect", b"fixture-secret"],
                    max_total_bytes=1024, timeout=10)
                self.assertEqual(warnings, [])
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["password_index"], 1)
                self.assertEqual(records[0]["path"].read_bytes(), content)
                self.assertEqual(cover.read_bytes(), original)

    def test_wrong_password_and_clean_carrier_are_unvalidated(self):
        cover = self._cover("jpg")
        payload = self.root / "payload.bin"
        payload.write_bytes(b"SECRET")
        stego = self.root / "stego.jpg"
        subprocess.run(["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
                        "-sf", str(stego), "-p", "fixture-secret", "-f", "-q"],
                       check=True, capture_output=True, timeout=10)
        for source in (cover, stego):
            with self.subTest(source=source.name):
                records, warnings = stegseek.extract_steghide(
                    source, self.root / f"stage-{source.name}", passwords=[b"incorrect"],
                    max_total_bytes=1024, timeout=10)
                self.assertEqual(records, [])
                self.assertIn("no supplied passphrase", warnings[0])

    def test_public_cli_private_password_resume_and_retirement(self):
        cover = self._cover("jpg")
        payload = self.root / "message.bin"
        content = b"PUBLIC-STEGO-ORACLE\x00"
        payload.write_bytes(content)
        source = self.root / "stego.jpg"
        subprocess.run(["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
                        "-sf", str(source), "-p", "fixture-secret", "-f", "-q"],
                       check=True, capture_output=True, timeout=10)
        original = hashlib.sha256(source.read_bytes()).hexdigest()
        password_file = self.root / "private-passwords.txt"
        password_file.write_text("wrong\nfixture-secret\n")
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"password_file": str(password_file)}))

        def call(*arguments):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, arguments)],
                                    capture_output=True, timeout=40)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        run = Path(call("analyze", source, "--category", "images", "--budget", "30",
                        "--runs-root", self.root / "runs")["run"])
        no_hints = json.loads((run / "manifest.json").read_text())
        self.assertEqual(no_hints["coverage"]["IMG03"]["status"], "skipped prerequisite")

        call("resume", run, "--hints", hints, "--budget", "30")
        found = json.loads((run / "manifest.json").read_text())
        rows = [item for item in found["artifacts"]
                if item["source_locator"].get("stego_engine") == "stegseek" and item["current"]]
        self.assertEqual(len(rows), 1)
        self.assertEqual(Path(rows[0]["path"]).read_bytes(), content)
        self.assertEqual(rows[0]["source_locator"]["password_index"], 1)
        self.assertEqual(rows[0]["source_locator"]["password_file_sha256"],
                         hashlib.sha256(password_file.read_bytes()).hexdigest())
        jobs = [job for job in found["jobs"] if job["adapter_id"] == "stegseek"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(rows[0]["parents"][0]["job_key"], jobs[0]["key"])
        self.assertEqual(found["coverage"]["IMG03"]["status"], "ran")
        self.assertNotIn("fixture-secret", (run / "report.md").read_text())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

        password_file.write_text("wrong\n")
        call("resume", run, "--hints", hints, "--budget", "30")
        retired = json.loads((run / "manifest.json").read_text())
        old = next(item for item in retired["artifacts"] if item["id"] == rows[0]["id"])
        self.assertFalse(old["current"])
        self.assertEqual(retired["coverage"]["IMG03"]["status"], "no finding")
        self.assertFalse(any(item["current"] and item["source_locator"].get("stego_engine") == "stegseek"
                             for item in retired["artifacts"]))

        password_file.write_text("wrong\nfixture-secret\n")
        call("resume", run, "--hints", hints, "--budget", "30")
        restored = json.loads((run / "manifest.json").read_text())
        self.assertTrue(next(item for item in restored["artifacts"] if item["id"] == rows[0]["id"])["current"])
        self.assertEqual(len([job for job in restored["jobs"] if job["adapter_id"] == "stegseek"]), 2)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_public_cli_wav_carrier_in_images_profile(self):
        cover = self._cover("wav")
        payload = self.root / "message.bin"
        payload.write_bytes(b"WAV-STEGO-ORACLE")
        source = self.root / "stego.wav"
        subprocess.run(["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
                        "-sf", str(source), "-p", "wav-secret", "-e", "none", "-f", "-q"],
                       check=True, capture_output=True, timeout=10)
        password_file = self.root / "passwords.txt"
        password_file.write_text("wav-secret\n")
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"password_file": str(password_file)}))
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", "analyze",
                                 str(source), "--category", "images", "--hints", str(hints),
                                 "--budget", "20", "--runs-root", str(self.root / "runs")],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["IMG03"]["status"], "ran")
        self.assertTrue(any(item["current"] and item["source_locator"].get("stego_engine") == "stegseek"
                            and Path(item["path"]).read_bytes() == b"WAV-STEGO-ORACLE"
                            for item in manifest["artifacts"]))

    def test_public_cli_clean_carrier_does_not_hide_other_success(self):
        cover = self._cover("jpg")
        payload = self.root / "message.bin"
        payload.write_bytes(b"MIXED-STEGO-ORACLE")
        carriers = self.root / "carriers"
        carriers.mkdir()
        shutil.copyfile(cover, carriers / "clean.jpg")
        subprocess.run(["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
                        "-sf", str(carriers / "stego.jpg"), "-p", "fixture-secret", "-f", "-q"],
                       check=True, capture_output=True, timeout=10)
        password_file = self.root / "passwords.txt"
        password_file.write_text("fixture-secret\n")
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"password_file": str(password_file)}))
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", "analyze",
                                 str(carriers), "--category", "images", "--hints", str(hints),
                                 "--budget", "30", "--runs-root", str(self.root / "runs")],
                                capture_output=True, timeout=40)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["IMG03"]["status"], "ran")
        self.assertTrue(any(item["current"] and item["source_locator"].get("stego_engine") == "stegseek"
                            and Path(item["path"]).read_bytes() == b"MIXED-STEGO-ORACLE"
                            for item in manifest["artifacts"]))
