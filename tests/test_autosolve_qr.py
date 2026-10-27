"""QR fixtures were generated with OpenCV's encoder, independent of both readers."""

import base64
import hashlib
import io
import random
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image, ImageOps

from scripts.autosolve_lib.profiles import qr
from scripts.autosolve_lib import setup as capabilities


_QR_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAPoAAAD6CAAAAACthwXhAAACXUlEQVR4nO3dwWrDQAwA0br0/385PS6FjSxVsh2YecdSJxn2Itbx5nh9UX0//QGeYzqR6USmE5lOZDqR6USmE5lOZDrRz+6Px8hLr12/+ut1ro1fbwGvuulEphOZTmQ60XaaW+r3YXfT1242i/923WdZwKtuOpHpRKYTmU50Ms0t8WTUmbSmp7Ts64FX3XQi04lMJzKdKD3NXacz13WAV910ItOJTCcynejmaW7mnusM8KqbTmQ6kelEphOlp7np+WrmGYkO8KqbTmQ6kelEphOdTHMzT5Rm9+Hid5v5LAt41U0nMp3IdCLTiY477mk+tfsWA6+66USmE5lOZDpR+ry5eAct3nOrX7v7LNPPzYJX3XQi04lMJzKdaPy8ud0V8Qy3U7/nWv8eHnjVTScynch0ItOJxr831zkLrr5L13k38KqbTmQ6kelEphP9Y2+ufj80viJ+t7rsiSfgVTedyHQi04lMJ2r9FsRuburcI93p7Oa5N/eG6USmE5lOZDrRY8+0XnfeXHauA6+66USmE5lOZDrRdpqbOdmt/jxE9n5t54oFvOqmE5lOZDqR6UQn09z0qSC7/9u57n0X8KqbTmQ6kelEphO1vje3dO59dn4Bon6m3QJeddOJTCcynch0ovQ0N6P+bbl477DzZCx41U0nMp3IdCLTiW6Z5ur7ZtkduewZdO7N/WE6kelEphOZTpSe5jrPvs48VVF/D08oecN0ItOJTCcynWj8tyDq4ucX6mfaZYFX3XQi04lMJzKd6Jbz5j4TeNVNJzKdyHQi04lMJzKdyHQi04lMJ/oFNOVUDKAeBnAAAAAASUVORK5CYII=")
_PAYLOAD = b"QR-ORACLE-123"
# ZXing JS independent blackbox specimen: docs/resources/blackbox/datamatrix/abcdefg-64x64.png
# https://github.com/zxing-js/library/blob/master/docs/resources/blackbox/datamatrix/abcdefg-64x64.png
_DM_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAgwAAAIMAQMAAACjSGZMAAAABlBMVEX///8AAABVwtN+AAAD3klEQVR4Xu3bwW6EMAwE0Ej8/x8jUe3YnkmWU9VLNRqKWBDmcbFknKTrv23Zrvtvf7ZEiOdeH+16sNVV38F+f85x+3McAFcwHIkQTx2Kn8cXzzp8nkQ8iEEtiRAIgAIGO9OrToFV1BoNJMJNiRDrUuLs9UkpBxFR+0nbnkQIxT7QlGjAJ9UQO6UKITw4EiEg750Bv00AQZ67zCjty5IIgbuVLnuC7d3BvAoea9CkpCkRYrpdhuqjRNWnd1WsQZYlEQLgUWBgMYqZ9SpRfJ8jEeJhWvECtn6m/jALETcv9SRCtACnnlNVANo0lBHBFGJJhNDnxubqghSiREMAYEmEUDI1904tKgPDxjUOrkSISyMdSqSKH4iFSm8o2ZQI8bfttiRCZM3BmwjBWsMO9tn9Y5BMM/nYWSbsiBDUjxy5gWs6lv4xKna14EmEaBA+NF2v10BIR0yWwbAkQkArgAyIl6GeB1vdX5ZECDwNQlNqoCHzybbVF7PhsSRCqKzA5jVBRM7O1TyQoHgSIaDzmcmeOgL4WlosfUG0JEIA1M7Uwq46wx/gu2xKhAB2LOThZD1jeZu9LXlPIgQ/U1SSIG2vAA7rmMCl5EiE2BKqcYlXWUwjNTi8bUqEgN+uMkpLhfmwlvTszbAjEQLid704/imNSifh/h6AjkQIBJ4j5Ko3ohQxBYMvtyNCZP1FiKy/+AURQv3AOfmmpcJ7rdrG0xnmSoQo8Ws0tHUNlx9NjsZBPIkQ6l/KecpreS7vCZ1rJpknEQIqn0HMe1JWE/jtqtdxJEJA0kGPTRki3VILmo5xJEJAYpK96lA7DAcPhcGeRAg4LBHUocLVR0hJusLBkwhxrt/Qow9BEK/l5UxJSyLEMfkKhY2voP0+C0Dd8iZCTE7hRy1vA2qF4ehFy5QI0ewxNKYq8Jp8Y+PDN1oSIY7c0gl0lYMClWMDL08iBNRGz5UcyizuLENa0OFKhJinyah52QfH1OOobOHEigiR9Rchsv7il0QIfXqoe9gGwHDJZV91dUzYexIh1MksIGeH0NKqTQvOyS1PIgTdyZ3ONcoX7U46KLQ8iRDMKTYI5z8jMcNosPsFYEqEALl3Lrs/Nvvf42sVmiERQtXijFEfCwNEGf2KCVquRAh4nIiFomrUOhOwIzRG4kmEYCYx/lwLpjT6WhDUkisRQlmkaXhtE3l19LyCqWVJhAAJCOjZpbTGiHrRYBBciRBqXSCVVZhOSGuOnrofEQIUa03pTR89bne4OALg0ZAIoUGxSSU+2KyWjiqzWgbvSITQMzQQ1d4508I+gQpASyLEa8uyhRD/bcv2AwvOPZsVHqB9AAAAAElFTkSuQmCC")
_DM_PAYLOAD = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(),./\\" * 3


class QRTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def inspect(self, source, **limits):
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        records, notices = qr.decode_symbols(source, max_pixels=limits.get("pixels", 1_000_000),
                                              max_total_bytes=limits.get("bytes", 100_000),
                                              timeout=limits.get("timeout", 10))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        return records, notices

    @unittest.skipUnless(qr._decoder()[0], "QR decoder required")
    def test_exact_payload_position_and_multiple_copies(self):
        with Image.open(io.BytesIO(_QR_PNG)) as qr_image:
            canvas = Image.new("RGB", (600, 300), "white")
            canvas.paste(qr_image.convert("RGB"), (20, 20))
            canvas.paste(qr_image.convert("RGB"), (330, 20))
        source = self.root / "two.png"
        canvas.save(source)
        records, notices = self.inspect(source)
        self.assertEqual(len(records), 2, notices)
        self.assertEqual([row["payload"] for row in records], [_PAYLOAD] * 2)
        self.assertEqual({row["format"] for row in records},
                         {"QRCODE"} if records[0]["decoder"] == "pyzbar" else {"QR Code"})
        self.assertEqual({row["frame"] for row in records}, {0})
        centers = sorted(sum(point[0] for point in row["position"]) / len(row["position"])
                         for row in records)
        self.assertLess(centers[0], 300)
        self.assertGreater(centers[1], 300)
        self.assertTrue(all(row["source"] == str(source.resolve()) for row in records))

    @unittest.skipUnless(qr._decoder()[0], "QR decoder required")
    def test_rotated_inverted_palette_frame_and_clean_negative(self):
        with Image.open(io.BytesIO(_QR_PNG)) as qr_image:
            altered = ImageOps.invert(qr_image.convert("L")).rotate(90, expand=True).convert("P")
        source = self.root / "rotated.gif"
        Image.new("P", altered.size, "white").save(source, save_all=True,
                                                     append_images=[altered], duration=[10, 30])
        records, notices = self.inspect(source)
        self.assertTrue(any(row["payload"] == _PAYLOAD and row["frame"] == 1 and
                            row["inverted"] for row in records),
                        (records, notices))

        palette = self.root / "palette.png"
        altered.save(palette)
        records, notices = self.inspect(palette)
        self.assertTrue(any(row["payload"] == _PAYLOAD and row["source_mode"] == "P"
                            for row in records), (records, notices))

        noise = self.root / "noise.png"
        rng = random.Random(12)
        Image.frombytes("L", (96, 96), rng.randbytes(96 * 96)).save(noise)
        records, _ = self.inspect(noise)
        self.assertEqual(records, [])

        damaged = self.root / "damaged.png"
        with Image.open(io.BytesIO(_QR_PNG)) as qr_image:
            damaged_image = qr_image.convert("L")
            damaged_image.paste(255, (0, 0, 200, 200))
            damaged_image.save(damaged)
        records, _ = self.inspect(damaged)
        self.assertEqual(records, [])

    @unittest.skipUnless(qr._decoder()[0], "QR decoder required")
    def test_limits_and_malformed_image(self):
        source = self.root / "qr.png"
        source.write_bytes(_QR_PNG)
        self.assertEqual(self.inspect(source, pixels=10)[0], [])
        self.assertTrue(any("pixel limit" in notice for notice in self.inspect(source, pixels=10)[1]))
        self.assertEqual(self.inspect(source, bytes=1)[0], [])
        self.assertTrue(any("output byte limit" in notice for notice in self.inspect(source, bytes=1)[1]))
        self.assertEqual(self.inspect(source, timeout=1e-12)[0], [])
        self.assertTrue(any("time limit" in notice for notice in self.inspect(source, timeout=1e-12)[1]))
        malformed = self.root / "bad.png"
        malformed.write_bytes(b"not an image")
        self.assertEqual(self.inspect(malformed)[0], [])
        self.assertTrue(any("rejected" in notice for notice in self.inspect(malformed)[1]))
        if qr._decoder()[0] == "pyzbar":
            unsupported = self.root / "datamatrix.png"
            unsupported.write_bytes(_DM_PNG)
            records, notices = self.inspect(unsupported)
            self.assertEqual(records, [])
            self.assertTrue(any("DataMatrix" in notice for notice in notices))

    def test_invalid_limits_and_missing_decoder(self):
        source = self.root / "qr.png"
        source.write_bytes(_QR_PNG)
        with self.assertRaises(ValueError):
            qr.decode_symbols(source, max_pixels=0, max_total_bytes=10, timeout=1)
        with self.assertRaises(ValueError):
            qr.decode_symbols(source, max_pixels=1000, max_total_bytes=10, timeout=0)
        with mock.patch.object(qr, "_decoder", return_value=(None, None)):
            records, notices = self.inspect(source)
        self.assertEqual(records, [])
        self.assertIn("unavailable", notices[0])
        if qr._decoder()[0] is None:
            script = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"
            result = subprocess.run([sys.executable, "-B", str(script), "--json", "analyze",
                                     str(source), "--category", "images", "--budget", "10",
                                     "--runs-root", str(self.root / "runs")],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            run = Path(json.loads(result.stdout)["run"])
            manifest = json.loads((run / "manifest.json").read_text())
            self.assertEqual(manifest["coverage"]["IMG05"]["status"], "skipped prerequisite")
            self.assertFalse(any(job["adapter_id"] == "qr" for job in manifest["jobs"]))

    @unittest.skipUnless(qr._decoder()[0] == "zxingcpp", "zxing-cpp required for DataMatrix")
    def test_independent_datamatrix_exact_bytes(self):
        source = self.root / "datamatrix.png"
        source.write_bytes(_DM_PNG)
        records, notices = self.inspect(source)
        self.assertEqual(len(records), 1, notices)
        self.assertEqual(records[0]["payload"], _DM_PAYLOAD)
        self.assertEqual(records[0]["format"], "Data Matrix")
        self.assertEqual(records[0]["position"], [(6, 6), (517, 6), (517, 517), (6, 517)])

    @unittest.skipUnless(qr._decoder()[0], "QR decoder required")
    def test_public_cli_publishes_exact_symbol_artifact_and_candidate(self):
        source = self.root / "challenge.png"
        source.write_bytes(_QR_PNG)
        hints = self.root / "hints.json"
        hints.write_text(json.dumps({"flag_patterns": ["QR-ORACLE-123"]}))
        script = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"
        command = [sys.executable, "-B", str(script), "--json", "analyze", str(source),
                   "--category", "images", "--hints", str(hints), "--budget", "30",
                   "--runs-root", str(self.root / "runs")]
        result = subprocess.run(command, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        decoded = [row for row in manifest["artifacts"]
                   if row["source_locator"].get("symbol_format")]
        self.assertEqual(len(decoded), 1)
        self.assertEqual(Path(decoded[0]["path"]).read_bytes(), _PAYLOAD)
        locator = decoded[0]["source_locator"]
        self.assertEqual(locator["frame"], 0)
        self.assertEqual(len(locator["symbol_position"]), 4)
        self.assertTrue(any(job["adapter_id"] == "qr" and job["status"] == "complete" and
                            decoded[0]["id"] in job["child_ids"] for job in manifest["jobs"]))
        self.assertTrue(any(finding["artifact_id"] == decoded[0]["id"] and
                            finding["state"] == "candidate" for finding in manifest["findings"]))
        self.assertFalse(any(finding["state"] == "challenge_accepted" for finding in manifest["findings"]))

        Image.new("RGB", (250, 250), "white").save(source)
        resumed = subprocess.run([sys.executable, "-B", str(script), "--json", "resume", str(run),
                                  "--hints", str(hints), "--budget", "30"],
                                 capture_output=True, timeout=45)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        changed = json.loads((run / "manifest.json").read_text())
        self.assertFalse(next(item for item in changed["artifacts"]
                              if item["id"] == decoded[0]["id"])["current"])
        self.assertFalse(any(item["current"] for item in changed["findings"]
                             if item["artifact_id"] == decoded[0]["id"]))

    def test_doctor_qr_probe_after_pillow_import(self):
        operation, engine = capabilities._qr_probe(True)
        decoder = qr._decoder()[0]
        self.assertEqual(operation["functional_probe"], "passed" if decoder else "not_run")
        self.assertEqual(engine["found"], bool(decoder))
        self.assertEqual(operation["status"],
                         "ready" if decoder == "zxingcpp" else "partial" if decoder else "unavailable")


if __name__ == "__main__":
    unittest.main()
