import hashlib
import io
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import wave
from pathlib import Path

from PIL import Image

from scripts.autosolve_lib.profiles import qr as qr_profile
from scripts.autosolve_lib.profiles.media import inspect_media


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class MediaProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_cli(self, *args, env=None):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                capture_output=True, timeout=45, env=env)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        response = json.loads(result.stdout)
        return Path(response["run"]), json.loads((Path(response["run"]) / "manifest.json").read_text())

    def test_stereo_views_preserve_channel_mapping_and_reverse(self):
        source = self.root / "independent.wav"
        with wave.open(str(source), "wb") as writer:
            writer.setnchannels(2)
            writer.setsampwidth(2)
            writer.setframerate(8000)
            writer.writeframes(b"".join(struct.pack(
                "<hh", int(8000 * math.sin(2 * math.pi * 440 * index / 8000)), 0)
                for index in range(8000)))
        original = hashlib.sha256(source.read_bytes()).hexdigest()

        records, warnings = inspect_media(source, self.root / "audio-stage",
                                          timeout=15, max_bytes=2_000_000)

        self.assertEqual(warnings, [])
        self.assertEqual(records[0]["stream_type"], "audio")
        self.assertEqual(records[0]["metadata"]["channels"], 2)
        self.assertEqual(records[0]["duration_seconds"], 1)
        views = {(record["channel"], record["view"]): record for record in records
                 if record["kind"] == "audio_view"}
        self.assertEqual(set(views), {(channel, view) for channel in (0, 1)
                                      for view in ("channel", "reversed", "waveform", "spectrogram")})
        with wave.open(io.BytesIO(views[0, "channel"]["path"].read_bytes())) as left:
            raw = left.readframes(32000)
            left_samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        with wave.open(io.BytesIO(views[1, "channel"]["path"].read_bytes())) as right:
            raw = right.readframes(32000)
            right_samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        with wave.open(io.BytesIO(views[0, "reversed"]["path"].read_bytes())) as reversed_audio:
            raw = reversed_audio.readframes(32000)
            reversed_samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        self.assertGreater(max(map(abs, left_samples)), 7000)
        self.assertEqual(set(right_samples), {0})
        self.assertAlmostEqual(reversed_samples[0], left_samples[-1], delta=500)
        for channel in (0, 1):
            for view, minimum in (("waveform", (1024, 256)), ("spectrogram", (1024, 512))):
                with Image.open(views[channel, view]["path"]) as image:
                    self.assertGreaterEqual(image.width, minimum[0])
                    self.assertGreaterEqual(image.height, minimum[1])
                    self.assertEqual(image.size,
                                     (views[channel, view]["width"], views[channel, view]["height"]))
            for view in ("channel", "reversed", "waveform", "spectrogram"):
                row = views[channel, view]
                self.assertEqual((row["start_seconds"], row["end_seconds"]), (0.0, 1.0))
                self.assertEqual(row["sha256"], hashlib.sha256(row["path"].read_bytes()).hexdigest())
                self.assertIn(f"channel {channel}", row["locator"])
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

        _, manifest = self.run_cli("analyze", source, "--category", "audio_video",
                                   "--budget", 15, "--runs-root", self.root / "runs")
        self.assertEqual(manifest["coverage"]["AV01"]["status"], "ran")
        self.assertEqual(manifest["coverage"]["AV06"]["status"], "no finding")
        self.assertEqual(len([job for job in manifest["jobs"] if job["adapter_id"] == "media"]), 1)
        self.assertTrue(any(artifact["source_locator"].get("channel") == 0 and
                            artifact["source_locator"].get("view") == "reversed"
                            for artifact in manifest["artifacts"]))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_full_frame_video_and_subtitle_then_sparse_sampling(self):
        for index in range(10):
            Image.new("RGB", (32, 32), "red" if index == 9 else "blue").save(
                self.root / f"frame{index:02d}.png")
        subtitle = self.root / "caption.srt"
        subtitle.write_text("1\n00:00:00,200 --> 00:00:01,200\nSUBTITLE_ORACLE\n")
        source = self.root / "independent.mkv"
        subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                        "-framerate", "5", "-i", str(self.root / "frame%02d.png"),
                        "-i", str(subtitle), "-map", "0:v", "-map", "1:s",
                        "-c:v", "ffv1", "-c:s", "srt", str(source)],
                       check=True, capture_output=True, timeout=15)
        original = hashlib.sha256(source.read_bytes()).hexdigest()

        records, warnings = inspect_media(source, self.root / "full-stage", timeout=15,
                                          max_bytes=1_000_000, max_frames=10,
                                          full_frames=True)
        frames = [record for record in records if record["kind"] == "video_frame"]
        subtitles = [record for record in records if record["kind"] == "subtitle_text"]
        self.assertEqual(warnings, [])
        self.assertEqual(len(frames), 10)
        self.assertEqual([round(row["sampled_seconds"], 1) for row in frames],
                         [index / 5 for index in range(10)])
        self.assertEqual({row["sampling_mode"] for row in frames}, {"full-frame"})
        with Image.open(frames[-1]["path"]) as image:
            self.assertGreater(image.convert("RGB").getpixel((16, 16))[0], 200)
        self.assertEqual(len(subtitles), 1)
        self.assertIn(b"SUBTITLE_ORACLE", subtitles[0]["path"].read_bytes())

        sparse, sparse_warnings = inspect_media(source, self.root / "sample-stage",
                                                timeout=15, max_bytes=1_000_000,
                                                max_frames=3)
        sampled = [record for record in sparse if record["kind"] == "video_frame"]
        self.assertEqual(len(sampled), 3)
        self.assertTrue(any("sampled 3" in row and
                            ("of 10 frames" in row or "frame count unknown" in row)
                            for row in sparse_warnings))
        self.assertEqual({row["sampling_mode"] for row in sampled}, {"sampled"})
        self.assertLess(sampled[-1]["sampled_seconds"], 2.0)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_nonzero_stream_start_keeps_absolute_frame_times(self):
        for index, colour in enumerate(("red", "blue", "green")):
            Image.new("RGB", (16, 16), colour).save(self.root / f"offset{index:02d}.png")
        source = self.root / "offset.mkv"
        subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                        "-framerate", "1", "-i", str(self.root / "offset%02d.png"),
                        "-c:v", "ffv1", "-output_ts_offset", "5", str(source)],
                       check=True, capture_output=True, timeout=15)
        records, warnings = inspect_media(source, self.root / "offset-stage",
                                          timeout=10, max_bytes=100000,
                                          max_frames=8, full_frames=True)
        frames = [record for record in records if record["kind"] == "video_frame"]
        self.assertEqual(warnings, [])
        self.assertEqual([row["sampled_seconds"] for row in frames], [5.0, 6.0, 7.0])
        self.assertEqual([row["requested_seconds"] for row in frames], [5.0, 6.0, 7.0])

    def test_corrupt_and_silent_negative_controls(self):
        invalid = self.root / "bad.mkv"
        invalid.write_bytes(b"not a media stream")
        records, warnings = inspect_media(invalid, self.root / "bad-stage",
                                          timeout=5, max_bytes=10000)
        self.assertEqual(records, [])
        self.assertTrue(warnings)
        self.assertFalse((self.root / "bad-stage").exists())

        silent = self.root / "silent.wav"
        with wave.open(str(silent), "wb") as writer:
            writer.setnchannels(1)
            writer.setsampwidth(2)
            writer.setframerate(8000)
            writer.writeframes(b"\x00\x00" * 800)
        records, warnings = inspect_media(silent, self.root / "silent-stage",
                                          timeout=10, max_bytes=500000)
        self.assertTrue(any(row["kind"] == "audio_view" for row in records))
        self.assertFalse(any("transcript" in row or "flag" in row for row in records))
        self.assertEqual(warnings, [])
        with self.assertRaises(ValueError):
            inspect_media(silent, self.root, timeout=10, max_bytes=500000)

    def test_cli_video_qr_and_subtitle_keep_time_provenance_on_resume(self):
        if qr_profile._decoder()[0] is None:
            self.skipTest("QR decoder required for video payload assertions")
        try:
            import cv2
        except ImportError:
            self.skipTest("independent OpenCV QR fixture generator unavailable")
        qr = cv2.QRCodeEncoder_create().encode("AV06_ORACLE")
        symbol = Image.fromarray(qr).resize((256, 256), Image.Resampling.NEAREST)
        for index in range(10):
            (symbol if index == 9 else Image.new("RGB", (256, 256), "white")).save(
                self.root / f"qrframe{index:02d}.png")
        subtitle = self.root / "qr-caption.srt"
        subtitle.write_text("1\n00:00:00,200 --> 00:00:01,200\nCAPTION_ORACLE\n")
        source = self.root / "qr-video.mkv"
        subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                        "-framerate", "5", "-i", str(self.root / "qrframe%02d.png"),
                        "-i", str(subtitle), "-map", "0:v", "-map", "1:s",
                        "-c:v", "ffv1", "-c:s", "srt", str(source)],
                       check=True, capture_output=True, timeout=15)
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        run, manifest = self.run_cli("analyze", source, "--category", "audio_video",
                                     "--budget", 30, "--runs-root", self.root / "runs")
        self.assertEqual(manifest["coverage"]["AV06"]["status"], "ran")
        frames = [row for row in manifest["artifacts"]
                  if row["source_locator"].get("media_kind") == "video_frame"]
        self.assertEqual(len(frames), 10)
        self.assertEqual(frames[-1]["source_locator"]["sampled_seconds"], 1.8)
        self.assertTrue(any(Path(row["path"]).read_bytes() == b"AV06_ORACLE" and
                            row["source_locator"].get("media_frame", {}).get("sampled_seconds") == 1.8
                            for row in manifest["artifacts"] if row["depth"] >= 2))
        self.assertTrue(any(b"CAPTION_ORACLE" in Path(row["path"]).read_bytes()
                            for row in manifest["artifacts"]
                            if row["source_locator"].get("media_kind") == "subtitle_text"))
        _, automatic = self.run_cli("analyze", source, "--category", "auto",
                                    "--budget", 30, "--runs-root", self.root / "auto-runs")
        self.assertTrue(any(Path(row["path"]).read_bytes() == b"AV06_ORACLE"
                            for row in automatic["artifacts"] if row["depth"] >= 2 and row["size"] < 100))
        self.assertLess(len(automatic["artifacts"]), 100)
        jobs = len(manifest["jobs"])
        _, resumed = self.run_cli("resume", run, "--budget", 30)
        self.assertEqual(len(resumed["jobs"]), jobs)
        self.assertTrue(all(row["current"] for row in resumed["artifacts"] if row["depth"] > 0))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

        original = source.read_bytes()
        source.write_bytes(b"not a media stream")
        _, changed = self.run_cli("resume", run, "--budget", 10)
        self.assertFalse(any(row["current"] for row in changed["intelligence"]
                             if row["tag"] == "Media stream"))
        source.write_bytes(original)
        _, restored = self.run_cli("resume", run, "--budget", 30)
        latest_root = next(row for row in reversed(restored["artifacts"])
                           if row["depth"] == 0 and row["current"])
        self.assertTrue(any(row["current"] and row["artifact_id"] == latest_root["id"]
                            for row in restored["intelligence"] if row["tag"] == "Media stream"))
        self.assertGreater(len(restored["jobs"]), jobs)

    def test_missing_ffmpeg_is_skipped_without_false_result(self):
        source = self.root / "source.wav"
        with wave.open(str(source), "wb") as writer:
            writer.setnchannels(1)
            writer.setsampwidth(2)
            writer.setframerate(8000)
            writer.writeframes(b"\x00\x00" * 800)
        env = dict(os.environ, AUTOSOLVE_FFMPEG=str(self.root / "missing-ffmpeg"))
        _, manifest = self.run_cli("analyze", source, "--category", "audio_video",
                                   "--runs-root", self.root / "runs", env=env)
        self.assertEqual(manifest["coverage"]["AV01"]["status"], "skipped prerequisite")
        self.assertEqual(manifest["coverage"]["AV06"]["status"], "skipped prerequisite")
        self.assertFalse(any(job["adapter_id"] == "media" for job in manifest["jobs"]))

    def test_doctor_media_probe_is_functional(self):
        from scripts.autosolve_lib.setup import doctor
        result = doctor(["audio_video"], self_test=True)
        self.assertEqual(result["operations"]["audio_video.media"]["functional_probe"], "passed")
        self.assertEqual(result["engines"]["ffmpeg"]["status"], "ready")


if __name__ == "__main__":
    unittest.main()
