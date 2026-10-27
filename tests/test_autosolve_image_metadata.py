import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from PIL import Image

from scripts.autosolve_lib.profiles import image_metadata


class ImageMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_exiftool_retains_comment_tag_group_and_source(self):
        source = self.root / "independent.jpg"
        Image.new("RGB", (2, 2), "red").save(source)
        subprocess.run(["/usr/bin/exiftool", "-overwrite_original",
                        "-Comment=metadata oracle", "-EXIF:ImageDescription=scene oracle",
                        str(source)], check=True, capture_output=True)
        before = hashlib.sha256(source.read_bytes()).hexdigest()

        findings, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        self.assertTrue(any(row["tag"] == "Comment" and row["value"] == "metadata oracle"
                            and row["group"] and row["source_tag"].endswith(":Comment")
                            and row["source"] == str(source) for row in findings))
        self.assertTrue(any(row["tag"] == "ImageDescription"
                            and row["value"] == "scene oracle" and row["group"] == "IFD0"
                            for row in findings))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_gps_sign_and_conflicting_time_basis_are_labeled_without_changing_raw_tags(self):
        source = self.root / "metadata.jpg"
        Image.new("RGB", (2, 2), "red").save(source)
        subprocess.run(["/usr/bin/exiftool", "-overwrite_original",
                        "-GPSLatitude=12.345678", "-GPSLatitudeRef=S",
                        "-GPSLongitude=103.456789", "-GPSLongitudeRef=E",
                        "-DateTimeOriginal=2022:01:02 03:04:05",
                        "-OffsetTimeOriginal=+07:00",
                        "-XMP:DateCreated=2033:06:07 08:09:10+09:00",
                        str(source)], check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        latitude = next(row for row in rows if row["group"].startswith("GPS")
                        and row["tag"] == "GPSLatitude")
        signed = next(row for row in rows if row["group"] == "Composite"
                      and row["tag"] == "GPSLatitude")
        exif_time = next(row for row in rows if row["group"] == "ExifIFD"
                         and row["tag"] == "DateTimeOriginal")
        xmp_time = next(row for row in rows if row["tag"] == "DateCreated")
        self.assertEqual((latitude["value"], signed["value"]), (12.345678, -12.345678))
        self.assertIn("unsigned magnitude", latitude["interpretation"])
        self.assertIn("GPSLatitudeRef", latitude["interpretation"])
        self.assertIn("hemisphere-signed", signed["interpretation"])
        self.assertIn("+07:00", exif_time["interpretation"])
        self.assertIn("capture-time fields conflict", exif_time["interpretation"])
        self.assertIn("capture-time fields conflict", xmp_time["interpretation"])
        self.assertEqual(latitude["source_tag"], "GPS:Copy1:GPSLatitude")

    def test_missing_timezone_and_gps_are_not_invented(self):
        source = self.root / "no-gps.jpg"
        Image.new("RGB", (2, 2), "blue").save(source)
        subprocess.run(["/usr/bin/exiftool", "-overwrite_original",
                        "-DateTimeOriginal=2022:01:02 03:04:05", str(source)],
                       check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        exif_time = next(row for row in rows if row["tag"] == "DateTimeOriginal")
        self.assertIn("timezone unknown", exif_time["interpretation"])
        self.assertFalse(any(row["tag"].startswith("GPS") for row in rows))

    def test_equivalent_capture_instants_in_different_timezones_are_not_conflicts(self):
        source = self.root / "same-instant.jpg"
        Image.new("RGB", (2, 2), "red").save(source)
        subprocess.run(["/usr/bin/exiftool", "-overwrite_original",
                        "-DateTimeOriginal=2022:01:02 03:04:05",
                        "-OffsetTimeOriginal=+07:00",
                        "-XMP:DateCreated=2022:01:01 20:04:05+00:00", str(source)],
                       check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        captures = [row for row in rows if row['tag'] in ('DateTimeOriginal', 'DateCreated')]
        self.assertEqual(len(captures), 2)
        self.assertTrue(all('capture-time fields conflict' not in row['interpretation']
                            for row in captures))

    def test_different_raw_times_with_missing_timezone_are_uncertain(self):
        source = self.root / "mixed-basis.jpg"
        Image.new("RGB", (2, 2), "red").save(source)
        subprocess.run(["/usr/bin/exiftool", "-overwrite_original",
                        "-DateTimeOriginal=2022:01:02 03:04:05",
                        "-XMP:DateCreated=2033:06:07 08:09:10+09:00", str(source)],
                       check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        captures = [row for row in rows if row['tag'] in ('DateTimeOriginal', 'DateCreated')]
        self.assertEqual(len(captures), 2)
        self.assertTrue(all('raw capture-time fields differ' in row['interpretation']
                            and 'timezone unknown' in row['interpretation'] for row in captures))
        self.assertTrue(all('capture-time fields conflict' not in row['interpretation']
                            for row in captures))

    def test_partial_gps_reference_does_not_sign_entire_coordinate_pair(self):
        source = self.root / 'one-ref.jpg'
        Image.new('RGB', (2, 2), 'red').save(source)
        subprocess.run(['/usr/bin/exiftool', '-overwrite_original',
                        '-GPSLatitude=12.345678', '-GPSLatitudeRef=S',
                        '-GPSLongitude=103.456789', str(source)],
                       check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        latitude = next(row for row in rows if row['source_tag'] == 'Composite:GPSLatitude')
        pair = next(row for row in rows if row['source_tag'] == 'Composite:GPSPosition')
        longitude = next(row for row in rows if row['source_tag'] == 'GPS:GPSLongitude')
        self.assertEqual((latitude['value'], pair['value'], longitude['value']),
                         (-12.345678, '-12.345678 103.456789', 103.456789))
        self.assertIn('hemisphere-signed', latitude['interpretation'])
        self.assertIn('sign unknown', longitude['interpretation'])
        self.assertIn('incomplete hemisphere references', pair['interpretation'])
        self.assertNotIn('hemisphere-signed coordinate', pair['interpretation'])

    def test_invalid_exif_offset_does_not_establish_timezone_basis(self):
        source = self.root / 'bad-offset.jpg'
        Image.new('RGB', (2, 2), 'red').save(source)
        subprocess.run(['/usr/bin/exiftool', '-overwrite_original',
                        '-DateTimeOriginal=2022:01:02 03:04:05',
                        '-OffsetTimeOriginal=+25:00', str(source)],
                       check=True, capture_output=True)

        rows, warnings = image_metadata.read_metadata(source)

        self.assertEqual(warnings, [])
        capture = next(row for row in rows if row['tag'] == 'DateTimeOriginal')
        offset = next(row for row in rows if row['tag'] == 'OffsetTimeOriginal')
        self.assertEqual(offset['value'], '+25:00')
        self.assertIn('timezone unknown', capture['interpretation'])
        self.assertIn('invalid OffsetTimeOriginal', capture['interpretation'])
        self.assertNotIn('timezone basis +25:00', capture['interpretation'])

    def test_exiftool_process_is_bounded_and_malformed_input_is_reported(self):
        source = self.root / "invalid.bin"
        source.write_bytes(b"")
        findings, warnings = image_metadata.read_metadata(source)
        self.assertTrue(warnings)
        self.assertTrue(any(row["tag"] == "Error" for row in findings))

        noisy = self.root / "noisy-tool"
        noisy.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * 2000000)\n")
        noisy.chmod(0o700)
        with mock.patch.object(image_metadata, "_EXIFTOOL", str(noisy)):
            self.assertEqual(image_metadata.read_metadata(source)[1],
                             ["ExifTool output limit reached"])

        slow = self.root / "slow-tool"
        slow.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n")
        slow.chmod(0o700)
        with mock.patch.object(image_metadata, "_EXIFTOOL", str(slow)):
            self.assertEqual(image_metadata.read_metadata(source, timeout=0.05)[1],
                             ["ExifTool timed out"])
        with self.assertRaises(ValueError):
            image_metadata.read_metadata(source, timeout=0)

    def test_rgba_alpha_bit_plane_preserves_pixel_mapping(self):
        source = self.root / "alpha.png"
        pixels = [(10, 20, 30, alpha) for alpha in (0, 1, 2, 3, 4, 5, 6, 7)]
        picture = Image.new("RGBA", (4, 2))
        picture.putdata(pixels)
        picture.save(source)
        before = source.read_bytes()

        views, warnings = image_metadata.channel_views(
            source, self.root / "views", max_pixels=8, max_total_bytes=100000)

        self.assertEqual(warnings, [])
        selected = next(row for row in views if row["channel"] == "alpha" and row["bit"] == 0)
        with Image.open(selected["path"]) as output:
            self.assertEqual(list(output.getdata()), [0, 255] * 4)
        self.assertEqual((selected["frame"], selected["source_mode"], selected["source"]),
                         (0, "RGBA", str(source)))
        self.assertTrue(all(row["path"].suffix == ".png" and row["path"].is_file()
                            for row in views))
        self.assertTrue(all("flag" not in row and "solved" not in row for row in views))
        self.assertEqual(source.read_bytes(), before)

    def test_palette_index_16bit_samples_and_late_animation_frame(self):
        palette = self.root / "palette.png"
        picture = Image.frombytes("P", (2, 1), b"\x01\x02")
        colours = [0] * 768
        colours[3:6] = [255, 0, 0]
        colours[6:9] = [0, 255, 0]
        picture.putpalette(colours)
        picture.save(palette)
        views, warnings = image_metadata.channel_views(
            palette, self.root / "palette-views", max_pixels=2, max_total_bytes=100000)
        self.assertEqual(warnings, [])
        indexed = next(row for row in views if row["channel"] == "palette-index" and row["bit"] is None)
        with Image.open(indexed["path"]) as output:
            self.assertEqual(list(output.getdata()), [1, 2])

        sixteen = self.root / "sixteen.png"
        Image.frombytes("I;16", (2, 1), b"\x34\x12\xcd\xab").save(sixteen)
        views, warnings = image_metadata.channel_views(
            sixteen, self.root / "sixteen-views", max_pixels=2, max_total_bytes=100000)
        self.assertEqual(warnings, [])
        for channel, expected in (("sample-high", [0x12, 0xab]),
                                  ("sample-low", [0x34, 0xcd])):
            record = next(row for row in views if row["channel"] == channel and row["bit"] is None)
            with Image.open(record["path"]) as output:
                self.assertEqual(list(output.getdata()), expected)

        animated = self.root / "animated.gif"
        frames = [Image.new("RGB", (2, 1), (index * 20, 0, 0)) for index in range(10)]
        frames[0].save(animated, save_all=True, append_images=frames[1:],
                       duration=[(index + 1) * 10 for index in range(10)], loop=0)
        views, warnings = image_metadata.channel_views(
            animated, self.root / "animation-views", max_pixels=2, max_total_bytes=100000)
        self.assertTrue(any("sampled 8 of 10" in warning for warning in warnings))
        self.assertEqual({row["frame"] for row in views}, {0, 1, 3, 4, 5, 6, 8, 9})
        self.assertTrue(any(row["frame"] == 9 and row["duration_ms"] == 100 for row in views))

    def test_rejects_malformed_oversize_and_unsupported_modes(self):
        source = self.root / "bad.png"
        source.write_bytes(b"not png")
        for fixture in ("malformed", "oversize", "unsupported"):
            if fixture == "oversize":
                Image.new("RGB", (5, 5)).save(source)
            elif fixture == "unsupported":
                source = self.root / "unsupported.tif"
                Image.new("CMYK", (2, 2)).save(source)
            views, warnings = image_metadata.channel_views(
                source, self.root / fixture, max_pixels=4, max_total_bytes=100000)
            self.assertEqual(views, [])
            self.assertTrue(any("rejected" in warning for warning in warnings))
            self.assertEqual(list((self.root / fixture).glob("*.png")), [])

    def test_output_budget_and_separate_staging_directory(self):
        source = self.root / "plain.png"
        Image.new("RGB", (2, 2), "white").save(source)
        first, _ = image_metadata.channel_views(
            source, self.root / "ample", max_pixels=4, max_total_bytes=100000)
        budget = first[0]["size"]
        views, warnings = image_metadata.channel_views(
            source, self.root / "tight", max_pixels=4, max_total_bytes=budget)
        self.assertEqual(len(views), 1)
        self.assertEqual(sum(row["size"] for row in views), budget)
        self.assertIn("image preview byte limit reached", warnings)
        self.assertEqual(list((self.root / "tight").glob(".image-stage-*")), [])
        with self.assertRaises(ValueError):
            image_metadata.channel_views(source, self.root, max_pixels=4, max_total_bytes=100000)
        with self.assertRaises(ValueError):
            image_metadata.channel_views(source, self.root / "other", max_pixels=0, max_total_bytes=100000)


if __name__ == "__main__":
    unittest.main()
