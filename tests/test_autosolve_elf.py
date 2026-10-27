"""Static ELF intelligence from independently built challenge fixtures."""

import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import sys
from pathlib import Path

from scripts.autosolve_lib.profiles import elf
from scripts.autosolve_lib import setup as autosolve_setup


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


@unittest.skipUnless(shutil.which("gcc") and shutil.which("as") and shutil.which("ld"),
                     "ELF build tools are unavailable")
class ElfTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "sample.c"
        self.source.write_text(
            '#include <stdio.h>\n'
            '__attribute__((noinline)) void win(void) { puts("oracle"); }\n'
            'int main(void) { char buf[32]; fgets(buf, sizeof(buf), stdin); return buf[0]; }\n')
        self.plain = self.root / "plain"
        self.pie = self.root / "pie"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-pie", "-no-pie",
                        "-Wl,-z,relro", "-Wl,-z,lazy", "-o", str(self.plain), str(self.source)],
                       check=True, capture_output=True)
        subprocess.run(["gcc", "-O1", "-fstack-protector-all", "-fPIE", "-pie",
                        "-Wl,-z,relro,-z,now", "-o", str(self.pie), str(self.source)],
                       check=True, capture_output=True)

    def test_non_pie_symbols_and_gadgets_have_static_file_evidence(self):
        before = hashlib.sha256(self.plain.read_bytes()).hexdigest()
        report, warnings = elf.inspect_elf(self.plain)
        self.assertEqual(warnings, [])
        self.assertEqual((report["architecture"], report["bits"]), ("x86-64", 64))
        self.assertEqual(report["mitigations"],
                         {"pie": False, "nx": True, "relro": "partial",
                          "canary": "not detected"})
        self.assertTrue(any(row["name"] == "win" and row["vaddr"] > 0
                            and 0 <= row["file_offset"] < len(self.plain.read_bytes())
                            for row in report["symbols"]))
        self.assertTrue(any(row["instructions"] == "ret" for row in report["gadgets"]))
        payload = self.plain.read_bytes()
        for row in report["gadgets"]:
            encoded = bytes.fromhex(row["bytes"])
            self.assertEqual(payload[row["file_offset"]:row["file_offset"] + len(encoded)],
                             encoded)
            self.assertGreater(row["vaddr"], 0)
        self.assertIn("static", report["address_note"].lower())
        self.assertEqual(hashlib.sha256(self.plain.read_bytes()).hexdigest(), before)

    def test_pie_full_relro_canary_and_stripped_variant(self):
        report, warnings = elf.inspect_elf(self.pie)
        self.assertEqual(warnings, [])
        self.assertEqual(report["mitigations"],
                         {"pie": True, "nx": True, "relro": "full",
                          "canary": "detected"})
        self.assertTrue(any(row["name"] == "win" for row in report["symbols"]))
        self.assertIn("runtime base", report["address_note"].lower())
        self.assertTrue(all(row["file_offset"] >= 0 for row in report["gadgets"]))

        stripped = self.root / "stripped"
        shutil.copyfile(self.pie, stripped)
        subprocess.run(["strip", "--strip-all", str(stripped)], check=True)
        reduced, warnings = elf.inspect_elf(stripped)
        self.assertEqual(warnings, [])
        self.assertEqual(reduced["mitigations"], report["mitigations"])
        self.assertFalse(any(row["name"] == "win" for row in reduced["symbols"]))
        self.assertTrue(reduced["gadgets"])

    def test_x86_32_and_unsupported_or_malformed_elf(self):
        source = self.root / "small.s"
        source.write_text('.global _start\n.text\n_start:\n pop %eax\n ret\n'
                          '.section .note.GNU-stack,"",@progbits\n')
        obj = self.root / "small.o"
        binary = self.root / "small32"
        subprocess.run(["as", "--32", "-o", str(obj), str(source)], check=True)
        object_report, object_warnings = elf.inspect_elf(obj)
        self.assertIsNone(object_report)
        self.assertIn("unsupported ELF type", " ".join(object_warnings))
        subprocess.run(["ld", "-m", "elf_i386", "-o", str(binary), str(obj)], check=True)
        report, warnings = elf.inspect_elf(binary)
        self.assertEqual(warnings, [])
        self.assertEqual((report["architecture"], report["bits"]), ("x86-32", 32))
        self.assertTrue(any(row["instructions"] == "pop eax; ret"
                            for row in report["gadgets"]))

        unsupported = self.root / "arm-label"
        modified = bytearray(self.plain.read_bytes())
        struct.pack_into("<H", modified, 18, 40)  # EM_ARM
        unsupported.write_bytes(modified)
        self.assertIsNone(elf.inspect_elf(unsupported)[0])
        self.assertIn("unsupported", " ".join(elf.inspect_elf(unsupported)[1]).lower())
        malformed = self.root / "broken"
        malformed.write_bytes(b"\x7fELF" + b"\x00" * 12)
        self.assertIsNone(elf.inspect_elf(malformed)[0])
        self.assertTrue(elf.inspect_elf(malformed)[1])

    def test_different_compiler_and_executable_stack_no_relro(self):
        compiler = shutil.which("clang-16")
        if compiler is None:
            self.skipTest("Clang 16 is unavailable")
        heldout = self.root / "clang-heldout"
        subprocess.run([compiler, "-O2", "-fno-stack-protector", "-no-pie",
                        "-Wl,-z,execstack,-z,norelro", "-o", str(heldout), str(self.source)],
                       check=True, capture_output=True)
        report, warnings = elf.inspect_elf(heldout)
        self.assertEqual(warnings, [])
        self.assertEqual(report["mitigations"],
                         {"pie": False, "nx": False, "relro": "none",
                          "canary": "not detected"})
        self.assertTrue(any(row["name"] == "win" for row in report["symbols"]))

    def test_output_and_source_limits(self):
        report, warnings = elf.inspect_elf(self.plain, max_symbols=2, max_gadgets=2)
        self.assertLessEqual(len(report["symbols"]), 2)
        self.assertLessEqual(len(report["gadgets"]), 2)
        self.assertTrue(any("limit" in warning for warning in warnings))
        self.assertIsNone(elf.inspect_elf(self.plain, max_bytes=1)[0])
        with self.assertRaises(ValueError):
            elf.inspect_elf(self.plain, max_symbols=0)

    def test_existing_ret2win_e2e_fixture(self):
        challenge = Path("/tmp/autosolve-pwn-e2e-KlkbeB/ret2win")
        if not challenge.exists():
            self.skipTest("local pwn e2e fixture is absent")
        report, warnings = elf.inspect_elf(challenge)
        self.assertEqual(warnings, [])
        self.assertEqual(report["architecture"], "x86-64")
        self.assertTrue(any(row["name"] == "win" for row in report["symbols"]))
        self.assertTrue(report["gadgets"])
        self.assertFalse(report["mitigations"]["pie"])

    def test_public_cli_static_pwn_intelligence_and_resume(self):
        fixture = Path("/tmp/autosolve-pwn-e2e-KlkbeB/ret2win")
        source = self.root / "ret2win"
        shutil.copyfile(fixture if fixture.exists() else self.plain, source)
        original = source.read_bytes()
        digest = hashlib.sha256(original).hexdigest()

        def cli(*args):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        first = cli("analyze", source, "--category", "pwn", "--budget", "20",
                    "--runs-root", self.root / "runs")
        run = Path(first["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["coverage"]["PWN02"]["status"], "ran")
        self.assertEqual(manifest["coverage"]["PWN01"]["status"], "not scheduled")
        self.assertFalse(manifest["execute_local"])
        jobs = [job for job in manifest["jobs"] if job["adapter_id"] == "elf"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "complete")
        intel = [row for row in manifest["intelligence"] if row["job_id"] == jobs[0]["id"]]
        self.assertTrue(any(row["tag"] == "ELF mitigation" and "partial" in row["value"]
                            for row in intel))
        self.assertTrue(any(row["tag"] == "ELF symbol" and "win" in row["value"]
                            and row["source_locator"].get("static_vaddr")
                            and row["source_locator"].get("file_offset") is not None
                            for row in intel))
        self.assertTrue(any(row["tag"] == "ELF gadget" and "ret" in row["value"]
                            and row["source_locator"].get("file_offset") is not None
                            for row in intel))
        self.assertTrue(all(row["current"] for row in intel))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)

        cli("resume", run, "--budget", "10")
        resumed = json.loads((run / "manifest.json").read_text())
        self.assertEqual(len([job for job in resumed["jobs"] if job["adapter_id"] == "elf"]), 1)
        self.assertTrue(all(row["current"] for row in resumed["intelligence"]
                            if row["job_id"] == jobs[0]["id"]))

        automatic = cli("analyze", source, "--budget", "20",
                        "--runs-root", self.root / "auto-runs")
        auto_manifest = json.loads((Path(automatic["run"]) / "manifest.json").read_text())
        self.assertEqual(auto_manifest["coverage"]["PWN02"]["status"], "ran")

        source.write_bytes(b"changed source, no ELF signature\n")
        cli("resume", run, "--budget", "10")
        changed = json.loads((run / "manifest.json").read_text())
        self.assertTrue(all(not row["current"] for row in changed["intelligence"]
                            if row["job_id"] == jobs[0]["id"]))

        source.write_bytes(original)
        cli("resume", run, "--budget", "10")
        restored = json.loads((run / "manifest.json").read_text())
        self.assertTrue(any(row["current"] and row["tag"] == "ELF symbol"
                            and "win" in row["value"] for row in restored["intelligence"]))

    def test_doctor_reports_static_elf_operation_without_binary_execution(self):
        result = autosolve_setup.doctor(["pwn"], self_test=True)
        self.assertEqual(result["operations"]["pwn_services.elf_static"]["functional_probe"],
                         "passed")
        self.assertEqual(result["engines"]["pyelftools"]["status"], "ready")
        self.assertEqual(result["engines"]["pwntools"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
