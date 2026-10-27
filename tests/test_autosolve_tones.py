import math
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import wave
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import tones


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"
FREQUENCIES = {"1": (697, 1209), "2": (697, 1336), "3": (697, 1477),
               "4": (770, 1209), "5": (770, 1336), "6": (770, 1477),
               "7": (852, 1209), "8": (852, 1336), "9": (852, 1477),
               "0": (941, 1336), "*": (941, 1209), "#": (941, 1477)}


def waveform(path, sequence="12", *, rate=22050, channel=0, amplitude=0.35,
             silence=0.10):
    samples = bytearray()
    for symbol in sequence:
        low, high = FREQUENCIES[symbol]
        for index in range(round(0.20 * rate)):
            value = int(32767 * amplitude * (math.sin(2 * math.pi * low * index / rate) +
                                              math.sin(2 * math.pi * high * index / rate)) / 2)
            frame = (value, 0) if channel == 0 else (0, value)
            samples.extend(struct.pack("<hh", *frame))
        samples.extend(b"\0\0\0\0" * round(silence * rate))
    with wave.open(str(path), "wb") as out:
        out.setparams((2, 2, rate, 0, "NONE", "not compressed"))
        out.writeframes(samples)


class TonesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def fake_decoder(self, body):
        tool = self.root / "multimon-ng"
        tool.write_text("#!/usr/bin/env python3\n" + body)
        tool.chmod(0o700)
        return str(tool)

    def test_normalization_channel_mapping_and_raw_mode_evidence(self):
        source = self.root / "tones.wav"
        waveform(source, "12", rate=16000, channel=1)
        before = source.read_bytes()
        fake = self.fake_decoder(
            "import pathlib,struct,sys\n"
            "mode=sys.argv[sys.argv.index('-a')+1]\n"
            "pcm=pathlib.Path(sys.argv[-1]).read_bytes()\n"
            "values=struct.unpack('<'+str(len(pcm)//2)+'h',pcm)\n"
            "assert 13000 < len(values) < 13500\n"
            "if max(map(abs,values)) > 500:\n"
            " if mode=='DTMF': print('DTMF: 1\\nDTMF: 2')\n"
            " elif mode=='MORSE_CW': print('SOS  ?')\n"
            " else: print('AFSK1200: fm TEST to DEST\\nRAW PAYLOAD')\n")
        with mock.patch.object(tones, "MULTIMON", fake):
            records, warnings = tones.inspect_tones(source, timeout=5, max_output=4096)
        self.assertEqual(warnings, [])
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual([row["symbol"] for row in records if row["mode"] == "DTMF"], ["1", "2"])
        self.assertTrue(all(row["channel"] == 1 for row in records))
        self.assertEqual(next(row for row in records if row["mode"] == "MORSE_CW")["raw_output"], "SOS  ?\n")
        self.assertIn("RAW PAYLOAD", next(row for row in records if row["mode"] == "AFSK1200")["raw_output"])
        self.assertTrue(all(row["event_time_seconds"] is None and row["certainty"] == "decoder_candidate"
                            for row in records))

    def test_invalid_input_missing_decoder_and_no_guessed_symbols(self):
        source = self.root / "silence.wav"
        waveform(source, "1", channel=0)
        with mock.patch.object(tones, "MULTIMON", "/missing/multimon-ng"):
            records, warnings = tones.inspect_tones(source, timeout=2, max_output=1024)
        self.assertEqual(records, [])
        self.assertIn("unavailable", warnings[0])
        fake = self.fake_decoder("print('DTMF: 1\\nDTMF: HELLO\\nnoise')\n")
        with mock.patch.object(tones, "MULTIMON", fake):
            records, _ = tones.inspect_tones(source, timeout=2, max_output=1024,
                                              modes=("DTMF",))
        self.assertEqual([row["symbol"] for row in records], ["1", "1"])
        self.assertTrue(all("HELLO" not in row["raw_output"] for row in records))
        with self.assertRaises(ValueError):
            tones.inspect_tones(source, timeout=2, max_output=1024, modes=("CCIR476",))
        with self.assertRaises(ValueError):
            tones.inspect_tones(source, timeout=0, max_output=1024)
        bad = self.root / "bad.wav"
        bad.write_bytes(b"not wav")
        self.assertEqual(tones.inspect_tones(bad, timeout=2, max_output=1024)[0], [])

    def test_subprocess_timeout_and_output_bound(self):
        source = self.root / "tone.wav"
        waveform(source, "1")
        slow = self.fake_decoder("import time\ntime.sleep(5)\n")
        with mock.patch.object(tones, "MULTIMON", slow):
            records, warnings = tones.inspect_tones(source, timeout=0.3, max_output=1024,
                                                      modes=("DTMF",))
        self.assertEqual(records, [])
        self.assertTrue(any("timed out" in warning for warning in warnings), warnings)
        noisy = self.fake_decoder("print('DTMF: 1\\n'*10000)\n")
        with mock.patch.object(tones, "MULTIMON", noisy):
            records, warnings = tones.inspect_tones(source, timeout=2, max_output=32,
                                                      modes=("DTMF",))
        self.assertEqual(records, [])
        self.assertTrue(any("output limit" in warning for warning in warnings), warnings)

    def test_public_cli_wav_lineage_resume_and_tool_change(self):
        source = self.root / "cli.wav"
        waveform(source, "12", rate=16000, channel=1)
        fake = self.fake_decoder(
            "import pathlib,struct,sys\n"
            "mode=sys.argv[sys.argv.index('-a')+1]\n"
            "pcm=pathlib.Path(sys.argv[-1]).read_bytes()\n"
            "values=struct.unpack('<'+str(len(pcm)//2)+'h',pcm)\n"
            "if mode=='DTMF' and max(map(abs,values)) > 500: print('DTMF: 1\\nDTMF: 2')\n")
        env = {**os.environ, "AUTOSOLVE_MULTIMON": fake}

        def cli(*args):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                    capture_output=True, timeout=45, env=env)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        run = Path(cli("analyze", source, "--category", "audio_video", "--budget", "20",
                       "--runs-root", self.root / "runs")["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "tones"]
        self.assertEqual(len(jobs), 1, manifest["warnings"])
        self.assertEqual(jobs[0]["status"], "complete", manifest["warnings"])
        self.assertEqual(manifest["coverage"]["AV02"]["status"], "ran")
        self.assertEqual(manifest["coverage"]["AV03"]["status"], "no finding")
        sequence = [row for row in manifest["intelligence"]
                    if row["tag"] == "DTMF sequence" and row["current"]]
        self.assertEqual([(row["group"], row["value"]) for row in sequence],
                         [("channel 1", "12")])
        records = json.loads(Path(jobs[0]["records_path"]).read_text())
        self.assertEqual([row["symbol"] for row in records], ["1", "2"])
        self.assertTrue(all(row["source"] == str(source.resolve()) for row in records))

        cli("resume", run, "--budget", "10")
        resumed = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in resumed["jobs"] if job["adapter_id"] == "tones"]), 1)

        Path(fake).write_text("#!/usr/bin/env python3\nprint('DTMF: 3')\n")
        Path(fake).chmod(0o700)
        cli("resume", run, "--budget", "10")
        changed = json.loads((run / "manifest.json").read_text())
        tone_jobs = [job for job in changed["jobs"] if job["adapter_id"] == "tones"]
        self.assertEqual(len(tone_jobs), 2)
        old_rows = [row for row in changed["intelligence"] if row.get("job_id") == jobs[0]["id"]]
        self.assertTrue(old_rows and all(not row["current"] for row in old_rows))
        self.assertTrue(any(row["tag"] == "DTMF sequence" and row["value"] == "3" and row["current"]
                            for row in changed["intelligence"]))

    def test_doctor_missing_multimon_does_not_claim_readiness(self):
        from scripts.autosolve_lib import setup
        with mock.patch.object(tones, "MULTIMON", "/missing/multimon-ng"):
            result = setup.doctor(["audio_video"], self_test=True)
        self.assertFalse(result["engines"]["multimon"]["found"])
        self.assertEqual(result["engines"]["multimon"]["status"], "unavailable")
        self.assertEqual(result["operations"]["audio_video.dtmf"]["status"], "unavailable")
        self.assertEqual(result["operations"]["audio_video.morse_afsk"]["status"], "unavailable")
        self.assertEqual(result["operations"]["audio_video.morse_afsk"]["reason"],
                         "multimon-ng_or_ffmpeg_missing")

    def test_doctor_missing_morse_fixture_is_distinct_from_tool_failure(self):
        from scripts.autosolve_lib import setup
        fake_module = self.root / "a" / "b" / "setup.py"
        with mock.patch.object(setup, "__file__", str(fake_module)), \
             mock.patch.object(setup.shutil, "which", return_value="/fake/tool"), \
             mock.patch.object(tones, "inspect_tones", return_value=([], [])):
            dtmf, narrow, engine = setup._tone_probe(True)
        self.assertEqual(narrow["status"], "partial")
        self.assertEqual(narrow["functional_probe"], "not_run")
        self.assertEqual(narrow["reason"], "morse_afsk_probe_fixture_missing")
        self.assertEqual(dtmf["functional_probe"], "failed")
        self.assertTrue(engine["found"])

    def test_doctor_rejects_positive_decoder_output_on_silent_control(self):
        from scripts.autosolve_lib import setup
        def fake_inspect(path, *, modes, **_):
            if modes == ("DTMF",):
                return ([{"symbol": "1"}, {"symbol": "2"}], [])
            if Path(path).name == "morse-sos.wav" and modes == ("MORSE_CW",):
                return ([{"mode": "MORSE_CW", "raw_output": "SOS \n"}], [])
            if Path(path).name == "afsk-hello.wav" and modes == ("AFSK1200",):
                return ([{"mode": "AFSK1200",
                          "raw_output": "AFSK1200: fm TEST to DEST UI pid=F0\nHELLO\n"}], [])
            if Path(path).name == "silence.wav":
                return ([{"mode": "MORSE_CW", "raw_output": "SOS\n"}], [])
            return ([], ["no supported tone decoder output"])
        with mock.patch.object(setup.shutil, "which", return_value="/fake/tool"), \
             mock.patch.object(tones, "inspect_tones", side_effect=fake_inspect):
            dtmf, narrow, _ = setup._tone_probe(True)
        self.assertEqual(dtmf["status"], "ready")
        self.assertEqual(narrow["status"], "partial")
        self.assertEqual(narrow["functional_probe"], "failed")
        self.assertEqual(narrow["reason"], "morse_afsk_probe_failed")


@unittest.skipUnless(shutil.which("multimon-ng") and shutil.which("ffmpeg"),
                     "approved multimon-ng and ffmpeg required for real waveform decode")
class RealToneDecoderTests(unittest.TestCase):
    def test_doctor_proves_morse_afsk_with_independent_controls(self):
        from scripts.autosolve_lib import setup
        dtmf, narrow, engine = setup._tone_probe(True)
        self.assertEqual(dtmf["status"], "ready")
        self.assertEqual(narrow, {"implemented": True, "functional_probe": "passed",
                                  "status": "ready", "reason": None})
        self.assertEqual(engine["status"], "ready")

    def test_independent_dtmf_waveform_and_held_out_channel(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "dtmf.wav"
            waveform(source, "12#", rate=16000, channel=1, amplitude=0.22, silence=0.16)
            rows, warnings = tones.inspect_tones(source, timeout=10, max_output=4096,
                                                  modes=("DTMF",))
            self.assertEqual("".join(row["symbol"] for row in rows if row["channel"] == 1),
                             "12#", warnings)
            self.assertEqual([row for row in rows if row["channel"] == 0], [])


if __name__ == "__main__":
    unittest.main()
