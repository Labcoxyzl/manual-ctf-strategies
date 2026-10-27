"""Check the WAV template against a carrier made by stego-lsb 1.7.3."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import wave


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/templates/wav_lsb.py"
ORACLE = ROOT / "tests/fixtures/toolkit/audio/wav-lsb-embedded.wav"
NON_DIVISOR_ORACLE = ROOT / "tests/fixtures/toolkit/audio/wav-lsb-n3.wav"
EXPECTED = b"CTF-LSB-OK\n"


class WavLsbTests(unittest.TestCase):
    def run_script(self, source, output, *options, code=0):
        result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), str(source),
                                 str(output), *options], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, code, result.stderr)
        return result

    def test_oracle_controls_and_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            carrier = root / "copy.wav"
            shutil.copyfile(ORACLE, carrier)
            original = carrier.read_bytes()
            options = ("--bits", "1", "--bytes", str(len(EXPECTED)))
            output = private / "payload.bin"
            self.run_script(carrier, output, *options)
            self.assertEqual(output.read_bytes(), EXPECTED)
            self.assertEqual(carrier.read_bytes(), original)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"File exists", self.run_script(carrier, output, *options, code=1).stderr)

            wrong = private / "wrong.bin"
            self.run_script(carrier, wrong, "--bits", "2", "--bytes", str(len(EXPECTED)))
            self.assertNotEqual(wrong.read_bytes(), EXPECTED)

            n3 = private / "n3.bin"
            self.run_script(NON_DIVISOR_ORACLE, n3, "--bits", "3", "--bytes", "5")
            self.assertEqual(n3.read_bytes(), bytes.fromhex("01aefb8007"))

            clean = root / "clean.wav"
            with wave.open(str(clean), "wb") as wav:
                wav.setparams((1, 1, 8000, 2048, "NONE", "not compressed"))
                wav.writeframes(b"\x80" * 2048)
            blank = private / "blank.bin"
            self.run_script(clean, blank, *options)
            self.assertEqual(blank.read_bytes(), b"\0" * len(EXPECTED))

            huge = root / "huge.wav"
            with huge.open("wb") as output_file:
                output_file.truncate(16 * 1024 * 1024 + 1)
            self.assertIn(b"exceeds 16 MiB", self.run_script(huge, private / "huge.bin", *options, code=1).stderr)
            self.assertIn(b"capacity", self.run_script(carrier, private / "too-many.bin", "--bits", "1", "--bytes", "257", code=1).stderr)
            self.assertIn(b"--bytes must", self.run_script(carrier, private / "unbounded.bin", "--bits", "1", "--bytes", "1048577", code=2).stderr)

            link = root / "link.wav"
            link.symlink_to(carrier)
            self.assertEqual(self.run_script(link, private / "link.bin", *options, code=1).returncode, 1)
            truncated = root / "truncated.wav"
            truncated.write_bytes(original[:48])
            self.assertIn(b"truncated", self.run_script(truncated, private / "truncated.bin", *options, code=1).stderr)
            target = root / "keep.bin"
            target.write_bytes(b"keep")
            (private / "output-link.bin").symlink_to(target)
            self.run_script(carrier, private / "output-link.bin", *options, code=1)
            self.assertEqual(target.read_bytes(), b"keep")
            parent_link = root / "private-link"
            parent_link.symlink_to(private, target_is_directory=True)
            self.run_script(carrier, parent_link / "parent-link.bin", *options, code=1)
            self.assertFalse((private / "parent-link.bin").exists())
            public = root / "public"
            public.mkdir(mode=0o755)
            self.assertEqual(self.run_script(carrier, public / "out.bin", *options, code=1).returncode, 1)
            self.assertFalse((private / "huge.bin").exists())
            self.assertFalse((private / "too-many.bin").exists())
            self.assertFalse((private / "link.bin").exists())
            self.assertFalse((private / "truncated.bin").exists())


if __name__ == "__main__":
    unittest.main()
