import hashlib
import io
import json
import gzip
import bz2
import lzma
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.autosolve_lib.profiles.tar import extract_tar
from scripts.autosolve_lib import core
from scripts.autosolve_lib import setup as capabilities


class TarExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.tar"
        self.output = self.root / "staged"

    def add(self, archive, name, data=b"", *, kind=tarfile.REGTYPE, link=""):
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = link
        info.size = len(data) if kind == tarfile.REGTYPE else 0
        archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)

    def extract(self, *, max_members=16, max_total_bytes=4096):
        return extract_tar(self.source, self.output, max_members=max_members,
                           max_total_bytes=max_total_bytes)

    def test_regular_unicode_and_duplicate_names_preserve_indices_and_exact_bytes(self):
        with tarfile.open(self.source, "w") as archive:
            self.add(archive, "dir/évidence.bin", b"first\x00\xff")
            self.add(archive, "dir/évidence.bin", b"second")
        original = self.source.read_bytes()
        records, found_warnings = self.extract()
        self.assertEqual(found_warnings, [])
        self.assertEqual([(item["member"], item["index"], item["path"].read_bytes())
                          for item in records],
                         [("dir/évidence.bin", 0, b"first\x00\xff"),
                          ("dir/évidence.bin", 1, b"second")])
        self.assertEqual([item["sha256"] for item in records],
                         [hashlib.sha256(data).hexdigest()
                          for data in (b"first\x00\xff", b"second")])
        self.assertEqual(len({item["path"] for item in records}), 2)
        self.assertEqual(set(self.output.iterdir()), {item["path"] for item in records})
        self.assertEqual(self.source.read_bytes(), original)

    def test_held_out_compression_methods(self):
        for suffix, mode in (("gz", "w:gz"), ("bz2", "w:bz2"), ("xz", "w:xz")):
            with self.subTest(suffix=suffix):
                self.source = self.root / f"input.tar.{suffix}"
                self.output = self.root / f"staged-{suffix}"
                with tarfile.open(self.source, mode) as archive:
                    self.add(archive, "nested/記録.txt", b"TAR{held-out}\n")
                records, found_warnings = self.extract()
                self.assertEqual(found_warnings, [])
                self.assertEqual([(item["member"], item["path"].read_bytes())
                                  for item in records],
                                 [("nested/記録.txt", b"TAR{held-out}\n")])

    def test_unsafe_paths_and_special_members_never_publish(self):
        with tarfile.open(self.source, "w") as archive:
            for name in ("../escape", "/absolute", "C:/drive", "a\\windows", "a/./dot"):
                self.add(archive, name, b"bad")
            for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                         tarfile.BLKTYPE, tarfile.FIFOTYPE):
                self.add(archive, f"special-{kind!r}", kind=kind, link="../escape")
            self.add(archive, "safe.txt", b"safe")
        records, found_warnings = self.extract()
        self.assertEqual([item["member"] for item in records], ["safe.txt"])
        self.assertEqual(len(found_warnings), 10)
        self.assertTrue(all("unsafe" in warning for warning in found_warnings))
        self.assertFalse((self.root / "escape").exists())
        self.assertEqual(set(self.output.iterdir()), {records[0]["path"]})

    def test_limits_stop_before_oversized_member_or_partial_publication(self):
        with tarfile.open(self.source, "w:gz") as archive:
            self.add(archive, "huge", b"A" * 100_000)
            self.add(archive, "later", b"small")
        records, found_warnings = self.extract(max_total_bytes=16)
        self.assertEqual(records, [])
        self.assertIn("expanded byte limit", found_warnings[0])
        self.assertEqual(list(self.output.iterdir()), [])
        records, found_warnings = self.extract(max_members=0)
        self.assertEqual(records, [])
        self.assertIn("member limit", found_warnings[0])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_unsafe_oversized_member_stops_before_decompressing_past_limit(self):
        with tarfile.open(self.source, "w:gz") as archive:
            self.add(archive, "../huge", b"A" * 100_000)
            self.add(archive, "later", b"small")
        records, found_warnings = self.extract(max_total_bytes=16)
        self.assertEqual(records, [])
        self.assertTrue(any("expanded byte limit" in warning for warning in found_warnings))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_corrupt_compressed_footer_is_reported(self):
        with tarfile.open(self.source, "w:gz") as archive:
            self.add(archive, "payload", b"verified member bytes")
        damaged = bytearray(self.source.read_bytes())
        damaged[-5] ^= 0xff
        self.source.write_bytes(damaged)
        records, found_warnings = self.extract()
        self.assertEqual([item["path"].read_bytes() for item in records],
                         [b"verified member bytes"])
        self.assertTrue(any("invalid TAR archive" in warning for warning in found_warnings),
                        found_warnings)

    def test_truncated_member_and_invalid_input_are_reported_without_partial_file(self):
        with tarfile.open(self.source, "w") as archive:
            self.add(archive, "payload", b"B" * 2048)
        self.source.write_bytes(self.source.read_bytes()[:512 + 100])
        records, found_warnings = self.extract()
        self.assertEqual(records, [])
        self.assertTrue(any("invalid" in warning or "truncated" in warning
                            for warning in found_warnings), found_warnings)
        self.assertEqual(list(self.output.iterdir()), [])
        self.source.write_bytes(b"not a TAR")
        records, found_warnings = self.extract()
        self.assertEqual(records, [])
        self.assertIn("invalid TAR archive", found_warnings[0])

    def test_output_directory_and_limits_are_validated(self):
        self.source.write_bytes(b"not a TAR")
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            self.extract(max_total_bytes=-1)
        with self.assertRaisesRegex(ValueError, "source directory"):
            extract_tar(self.source, self.root, max_members=16, max_total_bytes=1024)
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.extract()

    def run_cli(self, *args):
        script = Path(__file__).resolve().parents[1] / "scripts" / "autosolve.py"
        result = subprocess.run([sys.executable, "-B", str(script), "--json", *map(str, args)],
                                capture_output=True, timeout=40)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return Path(json.loads(result.stdout)["run"])

    def test_public_zip_tar_gzip_chain_has_exact_parent_jobs(self):
        oracle = b"TEST{nested_tar_oracle}\x00\xff"
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
            self.add(archive, "inner.gz", gzip.compress(oracle))
        self.source = self.root / "outer.zip"
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("nested/package.tar", tar_bytes.getvalue())
        original = self.source.read_bytes()
        run = self.run_cli("analyze", self.source, "--category", "auto",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "ran")
        jobs = {job["key"]: job for job in manifest["jobs"]}
        tar_child = next(item for item in manifest["artifacts"]
                         if item["kind_evidence"] == "tar" and item["depth"] == 1)
        gzip_child = next(item for item in manifest["artifacts"]
                          if item["kind_evidence"] == "gzip" and item["depth"] == 2)
        final = next(item for item in manifest["artifacts"]
                     if item["current"] and Path(item["path"]).read_bytes() == oracle)
        self.assertEqual(final["depth"], 3)
        self.assertEqual(gzip_child["source_locator"],
                         {"archive_member": "inner.gz", "member_index": 0})
        self.assertEqual(gzip_child["parents"][0]["id"], tar_child["id"])
        self.assertEqual(gzip_child["parents"][0]["operation"], "tar member 0")
        self.assertEqual(jobs[gzip_child["parents"][0]["job_key"]]["adapter_id"], "tar")
        self.assertEqual(self.source.read_bytes(), original)

    def test_public_gzip_tar_zip_chain_records_each_parent_edge(self):
        oracle = b"DOC{gzip_tar_zip_lineage}\x00\xff"
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("deep/answer.bin", oracle)
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
            self.add(archive, "layer/内部.zip", zip_bytes.getvalue())
        self.source = self.root / "opaque.blob"
        self.source.write_bytes(gzip.compress(tar_bytes.getvalue(), mtime=0))
        original = self.source.read_bytes()
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = {job["key"]: job for job in manifest["jobs"]}
        by_id = {item["id"]: item for item in manifest["artifacts"]}
        final = next(item for item in manifest["artifacts"]
                     if item["current"] and Path(item["path"]).read_bytes() == oracle)
        zip_child = by_id[final["parents"][0]["id"]]
        tar_child = by_id[zip_child["parents"][0]["id"]]
        self.assertEqual(Path(tar_child["path"]).read_bytes(), tar_bytes.getvalue())
        self.assertEqual([jobs[item["parents"][0]["job_key"]]["adapter_id"]
                          for item in (final, zip_child, tar_child)],
                         ["zip", "tar", "encoding"])
        self.assertEqual([item["parents"][0]["operation"]
                          for item in (final, zip_child, tar_child)],
                         ["zip member 0", "tar member 0", "gzip"])
        self.assertEqual((final["depth"], zip_child["depth"], tar_child["depth"]),
                         (3, 2, 1))
        self.run_cli("resume", run)
        repeated = json.loads((run / "manifest.json").read_text())
        self.assertTrue(next(item for item in repeated["artifacts"]
                             if item["id"] == final["id"])["current"])
        self.assertEqual(self.source.read_bytes(), original)

    def test_public_bzip2_and_xz_tar_containers_record_compression_edge(self):
        for compression, pack in (("bzip2", bz2.compress), ("xz", lzma.compress)):
            with self.subTest(compression=compression):
                tar_bytes = io.BytesIO()
                with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
                    self.add(archive, "payload", b"DOC{compressed_tar_parent}")
                self.source = self.root / f"opaque-{compression}.blob"
                self.source.write_bytes(pack(tar_bytes.getvalue()))
                run = self.run_cli("analyze", self.source, "--category", "documents",
                                   "--runs-root", self.root / "runs")
                manifest = json.loads((run / "manifest.json").read_text())
                by_id = {item["id"]: item for item in manifest["artifacts"]}
                final = next(item for item in manifest["artifacts"]
                             if item["current"] and Path(item["path"]).read_bytes() ==
                             b"DOC{compressed_tar_parent}")
                tar_child = by_id[final["parents"][0]["id"]]
                self.assertEqual(Path(tar_child["path"]).read_bytes(), tar_bytes.getvalue())
                self.assertEqual(tar_child["parents"][0]["operation"], compression)
                self.assertEqual(final["parents"][0]["operation"], "tar member 0")

    def test_raw_ustar_magic_like_member_names_use_raw_tar_parser(self):
        for prefix in (b"BZh", b"\x1f\x8b", b"\xfd7zXZ\x00"):
            with self.subTest(prefix=prefix):
                self.source = self.root / f"raw-{prefix.hex()}.tar"
                self.output = self.root / f"staged-{prefix.hex()}"
                payload = b"DOC{raw_tar_magic_name}" + prefix
                with tarfile.open(self.source, "w", format=tarfile.USTAR_FORMAT) as archive:
                    self.add(archive, "placeholder.txt", payload)
                raw = bytearray(self.source.read_bytes())
                raw[:len(prefix)] = prefix
                raw[148:156] = b"        "
                checksum = sum(raw[:512])
                raw[148:156] = f"{checksum:06o}\0 ".encode()
                self.source.write_bytes(raw)
                self.assertEqual(core._kind(self.source), "tar")
                records, warnings_found = self.extract()
                self.assertEqual(warnings_found, [])
                self.assertEqual([item["path"].read_bytes() for item in records], [payload])
                run = self.run_cli("analyze", self.source, "--category", "documents",
                                   "--runs-root", self.root / "runs")
                manifest = json.loads((run / "manifest.json").read_text())
                child = next(item for item in manifest["artifacts"]
                             if item["depth"] == 1 and Path(item["path"]).read_bytes() == payload)
                self.assertEqual(child["parents"][0]["operation"], "tar member 0")
                self.assertFalse(any(job["adapter_id"] == "encoding" for job in manifest["jobs"]))
                self.assertEqual(manifest["coverage"]["DOC01"]["status"], "ran")

    def test_malformed_magic_like_tar_header_cannot_publish_member(self):
        with tarfile.open(self.source, "w", format=tarfile.USTAR_FORMAT) as archive:
            self.add(archive, "placeholder.txt", b"DOC{malformed_header}")
        raw = bytearray(self.source.read_bytes())
        raw[:3] = b"BZh"
        self.source.write_bytes(raw)
        self.assertNotEqual(core._kind(self.source), "tar")
        records, warnings_found = self.extract()
        self.assertEqual(records, [])
        self.assertTrue(warnings_found)

    def test_public_documents_zip_tar_gzip_chain_with_no_unrelated_decoding(self):
        oracle = b"DOC{explicit_documents_gzip}\x00\xff"
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
            self.add(archive, "nested/inner.gz", gzip.compress(oracle, mtime=0))
            self.add(archive, "nested/encoded.txt", b"SEVMTE8=")
        self.source = self.root / "outer-documents.zip"
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("nested/package.tar", tar_bytes.getvalue())
        original = self.source.read_bytes()
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = {job["key"]: job for job in manifest["jobs"]}
        final = next(item for item in manifest["artifacts"]
                     if item["current"] and Path(item["path"]).read_bytes() == oracle)
        gzip_child = next(item for item in manifest["artifacts"]
                          if item["id"] == final["parents"][0]["id"])
        tar_child = next(item for item in manifest["artifacts"]
                         if item["id"] == gzip_child["parents"][0]["id"])
        self.assertEqual((final["depth"], gzip_child["depth"], tar_child["depth"]),
                         (3, 2, 1))
        self.assertEqual([jobs[item["parents"][0]["job_key"]]["adapter_id"]
                          for item in (final, gzip_child, tar_child)],
                         ["encoding", "tar", "zip"])
        self.assertEqual(final["parents"][0]["operation"], "gzip")
        self.assertFalse(any(item["depth"] > 2 and Path(item["path"]).read_bytes() == b"HELLO"
                             for item in manifest["artifacts"]))
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "ran")
        self.assertEqual(self.source.read_bytes(), original)

    def test_public_documents_plain_gzip_updates_doc01_coverage(self):
        oracle = b"DOC{direct_gzip}\x00\xff"
        self.source = self.root / "plain.gz"
        self.source.write_bytes(gzip.compress(oracle, mtime=0))
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertTrue(any(item["current"] and item["depth"] == 1
                            and Path(item["path"]).read_bytes() == oracle
                            for item in manifest["artifacts"]))
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "ran")
        self.assertIn("gzip", manifest["coverage"]["DOC01"]["note"])
        self.run_cli("resume", run)
        repeated = json.loads((run / "manifest.json").read_text())
        self.assertEqual(repeated["coverage"]["DOC01"]["status"], "ran")

    def test_public_documents_gzip_limits_mark_doc01_truncated(self):
        self.source = self.root / "output-bomb.gz"
        self.source.write_bytes(gzip.compress(b'A' * (core.MAX_CHILD + 1), mtime=0))
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "truncated")
        self.assertFalse(any(item["depth"] > 0 for item in manifest["artifacts"]))

        self.source = self.root / "oversized.gz"
        with self.source.open("wb") as output:
            output.write(gzip.compress(b"small", mtime=0))
            output.seek(core.MAX_READ)
            output.write(b"\0")
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "truncated")
        self.assertFalse(any(item["depth"] > 0 for item in manifest["artifacts"]))

    def test_public_identical_tar_sources_keep_member_locator_after_retirement(self):
        bundle = self.root / "sources"
        bundle.mkdir()
        first = bundle / "a.tar.gz"
        second = bundle / "b.tar.gz"
        oracle = b"DOC{duplicate_tar_source}\x00\xff"
        with tarfile.open(first, "w:gz") as archive:
            self.add(archive, "nested/évidence.bin", oracle)
        second.write_bytes(first.read_bytes())
        run = self.run_cli("analyze", bundle, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        child = next(item for item in manifest["artifacts"]
                     if item["depth"] == 2 and Path(item["path"]).read_bytes() == oracle)
        decoded_tar = next(item for item in manifest["artifacts"]
                           if item["id"] == child["parents"][0]["id"])
        roots = {Path(item["path"]).name: item["id"] for item in manifest["artifacts"]
                 if item["depth"] == 0}
        self.assertEqual({edge["id"] for edge in decoded_tar["parents"]}, set(roots.values()))
        locator = {"archive_member": "nested/évidence.bin", "member_index": 0}
        self.assertEqual(child["parents"][0]["source_locator"], locator)
        first.unlink()
        self.run_cli("resume", run)
        repeated = json.loads((run / "manifest.json").read_text())
        child = next(item for item in repeated["artifacts"] if item["id"] == child["id"])
        self.assertEqual(child["current_source_locators"], [{
            "parent_id": decoded_tar["id"], "operation": "tar member 0",
            "locator": locator}])
        decoded_tar = next(item for item in repeated["artifacts"]
                           if item["id"] == decoded_tar["id"])
        self.assertEqual({edge["parent_id"] for edge in decoded_tar["current_source_locators"]},
                         {roots["b.tar.gz"]})

    def test_public_compressed_tar_resume_and_source_retirement(self):
        self.source = self.root / "evidence.tar.xz"
        with tarfile.open(self.source, "w:xz") as archive:
            self.add(archive, "d/évidence", b"TEST{tar_resume}")
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        first = json.loads((run / "manifest.json").read_text())
        self.assertEqual(first["artifacts"][0]["kind_evidence"], "tar")
        jobs = [job for job in first["jobs"] if job["adapter_id"] == "tar"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "complete")
        decoded_tar = next(item for item in first["artifacts"] if item["depth"] == 1)
        child = next(item for item in first["artifacts"] if item["depth"] == 2)
        self.assertEqual(child["source_locator"],
                         {"archive_member": "d/évidence", "member_index": 0})
        self.assertEqual(decoded_tar["parents"][0]["operation"], "xz")
        self.assertEqual(child["parents"][0]["operation"], "tar member 0")
        self.assertEqual(Path(child["path"]).read_bytes(), b"TEST{tar_resume}")
        self.run_cli("resume", run)
        repeated = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in repeated["jobs"] if job["adapter_id"] == "tar"]), 1)
        self.source.write_bytes(b"changed")
        self.run_cli("resume", run)
        retired = json.loads((run / "manifest.json").read_text())
        self.assertFalse(next(item for item in retired["artifacts"] if item["id"] == child["id"])["current"])

    def test_plain_gzip_remains_generic_encoding_and_false_tar_header_is_rejected(self):
        self.source = self.root / "ordinary.gz"
        self.source.write_bytes(gzip.compress(b"TEST{plain_gzip}"))
        self.assertEqual(core._kind(self.source), "gzip")
        run = self.run_cli("analyze", self.source, "--category", "auto",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertFalse(any(job["adapter_id"] == "tar" for job in manifest["jobs"]))
        self.assertEqual(manifest["coverage"]["ENC02"]["status"], "ran")
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "ran")
        self.assertTrue(any(item["current"] and item["depth"] > 0
                            and Path(item["path"]).read_bytes() == b"TEST{plain_gzip}"
                            for item in manifest["artifacts"]))
        bogus = bytearray(1024)
        bogus[257:262] = b"ustar"
        self.source.write_bytes(bogus)
        self.assertNotEqual(core._kind(self.source), "tar")

    def test_document_setup_probes_real_tar_extraction(self):
        result = capabilities.doctor(["documents"], self_test=True)
        self.assertEqual(result["operations"]["documents.tar"]["functional_probe"], "passed")

    def test_public_corrupt_tar_footer_is_truncated_with_recovered_bytes(self):
        self.source = self.root / "damaged.tar.gz"
        with tarfile.open(self.source, "w:gz") as archive:
            self.add(archive, "payload", b"TEST{recovered_exactly}")
        damaged = bytearray(self.source.read_bytes())
        damaged[-5] ^= 0xff
        self.source.write_bytes(damaged)
        run = self.run_cli("analyze", self.source, "--category", "documents",
                           "--runs-root", self.root / "runs")
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["DOC01"]["status"], "truncated")
        self.assertTrue(any("invalid TAR archive" in note for note in manifest["warnings"]))
        self.assertTrue(any(item["depth"] == 1 and Path(item["path"]).read_bytes() ==
                            b"TEST{recovered_exactly}" for item in manifest["artifacts"]))
        child = next(item for item in manifest["artifacts"] if item["depth"] == 1)
        self.assertEqual(child["parents"][0]["operation"], "tar member 0 (gzip container)")


if __name__ == "__main__":
    unittest.main()
