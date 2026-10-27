"""Independent, offset-checked ELF and PE static structure fixtures."""

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.autosolve_lib.profiles.binary_static import inspect_binary
from scripts.autosolve_lib import setup as autosolve_setup


ROOT = Path(__file__).resolve().parents[1]
PE_FIXTURE = ROOT / "practice-challenges/33-reverseme/validation/ReverseMe.exe"
SCRIPT = ROOT / "scripts/autosolve.py"


class BinaryStaticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_cli(self, *args):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                capture_output=True, text=True, timeout=35)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return json.loads(result.stdout)

    @unittest.skipUnless(shutil.which("gcc"), "GCC unavailable")
    def test_elf_sections_imports_and_string_offsets(self):
        source = self.root / "sample.c"
        source.write_text('#include <stdio.h>\nint main(void) { puts("REV01_ORACLE_TEXT"); return 0; }\n')
        binary = self.root / "elf-with-pe-extension.exe"
        subprocess.run(["gcc", "-O0", "-fPIE", "-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        report, warnings = inspect_binary(binary, max_strings=1024)
        self.assertEqual(warnings, [])
        self.assertEqual((report["format"], report["architecture"], report["bits"]),
                         ("ELF", "x86-64", 64))
        self.assertTrue(report["mitigations"]["pie"])
        self.assertTrue(report["abi"])
        self.assertTrue(any(row["name"] == ".rodata" for row in report["sections"]))
        self.assertTrue(any(row["name"] == "puts" and row["symbol_file_offset"] > 0
                            for row in report["imports"]))
        raw = binary.read_bytes()
        oracle = next(row for row in report["strings"] if row["value"] == "REV01_ORACLE_TEXT")
        self.assertEqual(raw[oracle["file_offset"]:oracle["file_offset"] + len(oracle["value"])],
                         oracle["value"].encode())
        section = next(row for row in report["sections"] if row["name"] == oracle["section"])
        self.assertEqual(oracle["static_vaddr"], section["static_vaddr"] +
                         oracle["file_offset"] - section["file_offset"])
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), before)

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("strip"), "ELF tools unavailable")
    def test_stripped_pie_and_unsupported_architecture(self):
        source = self.root / "sample.c"
        source.write_text('int main(void) { return 7; }\n')
        binary = self.root / "stripped"
        subprocess.run(["gcc", "-O2", "-fPIE", "-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        subprocess.run(["strip", "--strip-all", str(binary)], check=True, capture_output=True)
        report, _ = inspect_binary(binary)
        self.assertEqual(report["format"], "ELF")
        self.assertTrue(report["mitigations"]["pie"])
        self.assertTrue(report["sections"])
        changed = bytearray(binary.read_bytes())
        struct.pack_into("<H", changed, 18, 0xb7)  # AArch64
        unsupported = self.root / "arm.elf"
        unsupported.write_bytes(changed)
        report, warnings = inspect_binary(unsupported)
        self.assertIsNone(report)
        self.assertIn("unsupported ELF architecture", " ".join(warnings))

    @unittest.skipUnless(PE_FIXTURE.is_file(), "PE fixture unavailable")
    def test_pe_structure_imports_offsets_and_misleading_extension(self):
        binary = self.root / "misleading.txt"
        shutil.copyfile(PE_FIXTURE, binary)
        binary.write_bytes(binary.read_bytes() + "REV01_WIDE_ORACLE".encode("utf-16le"))
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        report, warnings = inspect_binary(binary, max_strings=1024)
        self.assertEqual(warnings, [])
        self.assertEqual((report["format"], report["architecture"], report["bits"]),
                         ("PE", "x86-32", 32))
        self.assertEqual(report["abi"], "Windows PE")
        raw = binary.read_bytes()
        header = struct.unpack_from("<I", raw, 0x3c)[0]
        section_table = header + 24 + struct.unpack_from("<H", raw, header + 20)[0]
        for index, section in enumerate(report["sections"]):
            entry = section_table + 40 * index
            self.assertEqual(section["file_offset"], struct.unpack_from("<I", raw, entry + 20)[0])
            self.assertEqual(section["raw_size"], struct.unpack_from("<I", raw, entry + 16)[0])
        self.assertTrue(any(row["library"] == "KERNEL32.DLL" and
                            row["name"] == "LoadLibraryA" for row in report["imports"]))
        oracle = next(row for row in report["strings"] if row["value"] == "LoadLibraryA")
        self.assertEqual(raw[oracle["file_offset"]:oracle["file_offset"] + len(oracle["value"])],
                         oracle["value"].encode())
        section = next(row for row in report["sections"] if row["name"] == oracle["section"])
        self.assertEqual(oracle["static_vaddr"], section["static_vaddr"] +
                         oracle["file_offset"] - section["file_offset"])
        imp = next(row for row in report["imports"] if row["name"] == "LoadLibraryA")
        self.assertIsNotNone(imp["iat_file_offset"])
        self.assertEqual(imp["iat_rva"], imp["iat_static_vaddr"] - report["image_base"])
        wide = next(row for row in report["strings"] if row["value"] == "REV01_WIDE_ORACLE")
        self.assertEqual(wide["encoding"], "utf-16le")
        self.assertIsNone(wide["static_vaddr"])
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), before)

    @unittest.skipUnless(PE_FIXTURE.is_file(), "PE fixture unavailable")
    def test_pe_unsupported_architecture_and_bounds(self):
        raw = bytearray(PE_FIXTURE.read_bytes())
        pe_offset = struct.unpack_from("<I", raw, 0x3c)[0]
        struct.pack_into("<H", raw, pe_offset + 4, 0xaa64)  # ARM64
        unsupported = self.root / "arm64.exe"
        unsupported.write_bytes(raw)
        report, warnings = inspect_binary(unsupported)
        self.assertIsNone(report)
        self.assertIn("unsupported PE architecture", " ".join(warnings))
        report, warnings = inspect_binary(PE_FIXTURE, max_sections=1)
        self.assertIsNone(report)
        self.assertIn("section count limit", " ".join(warnings))
        report, warnings = inspect_binary(PE_FIXTURE, max_bytes=1024)
        self.assertIsNone(report)
        self.assertIn("byte limit", " ".join(warnings))

    def test_pe64_heldout_section_and_entry_offsets(self):
        raw = bytearray(1024)
        raw[:2] = b"MZ"
        struct.pack_into("<I", raw, 0x3c, 0x80)
        raw[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", raw, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
        optional = 0x98
        for offset, format_, value in ((0, "<H", 0x20b), (16, "<I", 0x1000),
                                       (24, "<Q", 0x140000000), (32, "<I", 0x1000),
                                       (36, "<I", 0x200), (56, "<I", 0x2000),
                                       (60, "<I", 0x200), (68, "<H", 3),
                                       (70, "<H", 0x140), (108, "<I", 16)):
            struct.pack_into(format_, raw, optional + offset, value)
        section = optional + 0xf0
        raw[section:section + 8] = b".text\0\0\0"
        struct.pack_into("<IIIIIIHHI", raw, section + 8,
                         0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
        raw[520:531] = b"PE64_ORACLE"
        target = self.root / "pe64.bin"
        target.write_bytes(raw)
        report, warnings = inspect_binary(target)
        self.assertEqual(warnings, [])
        self.assertEqual((report["architecture"], report["bits"]), ("x86-64", 64))
        self.assertEqual(report["entry_file_offset"], 512)
        self.assertEqual(report["sections"][0]["file_offset"], 0x200)
        self.assertEqual(report["sections"][0]["raw_size"], 0x200)
        self.assertEqual(raw[report["sections"][0]["file_offset"] + 8:
                             report["sections"][0]["file_offset"] + 19], b"PE64_ORACLE")
        oracle = next(row for row in report["strings"] if row["value"] == "PE64_ORACLE")
        self.assertEqual((oracle["file_offset"], oracle["static_vaddr"]),
                         (520, 0x140001008))

    def test_nonexecutable_truncated_and_symlink_are_explicit(self):
        blob = self.root / "blob.exe"
        blob.write_bytes(b"not an executable")
        report, warnings = inspect_binary(blob)
        self.assertIsNone(report)
        self.assertIn("unsupported binary format", " ".join(warnings))
        blob.write_bytes(b"MZ" + b"\0" * 8)
        report, warnings = inspect_binary(blob)
        self.assertIsNone(report)
        self.assertIn("malformed PE", " ".join(warnings))
        link = self.root / "link"
        link.symlink_to(blob)
        self.assertIsNone(inspect_binary(link)[0])
        with self.assertRaises(ValueError):
            inspect_binary(blob, max_strings=0)

    def test_doctor_probes_both_elf_and_pe(self):
        result = autosolve_setup.doctor(["malware_reversing"], self_test=True)
        self.assertEqual(result["operations"]["malware_reversing.binary_static"]["functional_probe"],
                         "passed")
        self.assertEqual(result["engines"]["pefile"]["status"], "ready")
        self.assertEqual(result["engines"]["pyelftools"]["status"], "ready")

    @unittest.skipUnless(PE_FIXTURE.is_file(), "PE fixture unavailable")
    def test_public_cli_pe_job_resume_and_source_change(self):
        source = self.root / "payload.txt"
        original = PE_FIXTURE.read_bytes()
        source.write_bytes(original)
        first = self.run_cli("analyze", source, "--category", "reversing",
                             "--budget", "20", "--runs-root", self.root / "runs")
        run = Path(first["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "binary-static"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "complete")
        self.assertEqual(manifest["coverage"]["REV01"]["status"], "truncated")
        report = json.loads(Path(jobs[0]["report_path"]).read_text())
        self.assertEqual(report["format"], "PE")
        self.assertTrue(any(row["tag"] == "Binary import" and row["value"] == "LoadLibraryA"
                            and row["source_locator"]["iat_file_offset"] is not None
                            for row in manifest["intelligence"]))
        section = next(row for row in manifest["intelligence"]
                       if row["tag"] == "Binary section" and row["group"] == "PE")
        section_line = next(line for line in (run / "report.md").read_text().splitlines()
                            if '"Binary section"' in line and
                            json.dumps(section["value"]) in line)
        self.assertIn(f'"file_offset": {section["source_locator"]["file_offset"]}',
                      section_line)
        self.assertLess(len(section_line), 384)
        self.assertEqual(source.read_bytes(), original)

        self.run_cli("resume", run, "--budget", "10")
        unchanged = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in unchanged["jobs"]
                              if job["adapter_id"] == "binary-static"]), 1)
        source.write_bytes(b"non-executable replacement")
        self.run_cli("resume", run, "--budget", "10")
        changed = json.loads((run / "manifest.json").read_text())
        self.assertFalse(any(row["current"] and row["job_id"] == jobs[0]["id"]
                             for row in changed["intelligence"]))
        self.assertEqual(changed["coverage"]["REV01"]["status"], "skipped prerequisite")

    def test_explicit_reversing_script_reports_rev01_boundary_and_runs_script_profile(self):
        source = self.root / "sample.ps1"
        source.write_text("Write-Output 'HEL' + 'LO'\n")
        first = self.run_cli("analyze", source, "--category", "reversing",
                             "--budget", "20", "--runs-root", self.root / "runs")
        manifest = json.loads((Path(first["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["REV01"]["status"], "skipped prerequisite")
        self.assertTrue(any(job["adapter_id"] == "binary-static" and
                            job["status"] == "complete" for job in manifest["jobs"]))
        self.assertTrue(any(job["adapter_id"] == "rev-powershell" and
                            job["status"] == "complete" for job in manifest["jobs"]))

    @unittest.skipUnless(PE_FIXTURE.is_file() and Path("/bin/true").is_file(),
                         "ELF or PE fixture unavailable")
    def test_public_auto_routes_elf_and_pe(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        shutil.copyfile("/bin/true", inputs / "a.bin")
        shutil.copyfile(PE_FIXTURE, inputs / "b.txt")
        first = self.run_cli("analyze", inputs, "--budget", "20",
                             "--runs-root", self.root / "runs")
        manifest = json.loads((Path(first["run"]) / "manifest.json").read_text())
        reports = [json.loads(Path(job["report_path"]).read_text()) for job in manifest["jobs"]
                   if job["adapter_id"] == "binary-static" and job["status"] == "complete"]
        self.assertEqual({report["format"] for report in reports}, {"ELF", "PE"})
        self.assertEqual(len([job for job in manifest["jobs"] if job["adapter_id"] == "elf"]), 1)
        self.assertIn(manifest["coverage"]["REV01"]["status"], ("ran", "truncated"))


if __name__ == "__main__":
    unittest.main()
