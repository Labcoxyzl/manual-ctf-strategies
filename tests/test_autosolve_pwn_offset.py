"""Independent local ELF oracle for explicit PWN03 offset discovery."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from scripts.autosolve_lib import pwn_offset


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gdb"), "GCC/GDB unavailable")
class OffsetTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        source = self.root / "practice.c"
        source.write_text(
            '#include <string.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void vuln(const char *arg) { char buf[32]; '
            'if (arg) memcpy(buf, arg, strlen(arg)); else read(0, buf, 512); }\n'
            'int main(int argc, char **argv) { vuln(argc > 1 ? argv[1] : 0); return 0; }\n')
        self.binary = self.root / "practice"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(self.binary), str(source)],
                       check=True, capture_output=True)
        source.write_text('int main(void) { return 0; }\n')
        self.safe = self.root / "safe"
        subprocess.run(["gcc", "-o", str(self.safe), str(source)],
                       check=True, capture_output=True)

    def cli(self, *arguments, code=3, env=None):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                 *map(str, arguments)], capture_output=True,
                                text=True, timeout=20, env=env)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def args(self, binary=None, channel="stdin", alphabet="abcde12345"):
        return ("pwn-offset", "--binary", binary or self.binary,
                "--channel", channel, "--alphabet", alphabet,
                "--length", 256, "--budget", 8, "--runs-root", self.root / "runs")

    def record(self, result):
        return json.loads((Path(result["run"]) / "manifest.json").read_text())

    def test_stdin_crash_offset_is_verified_by_changed_payload_and_short_control(self):
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.cli(*self.args())
        run = Path(result["run"])
        row = self.record(result)
        self.assertEqual(row["offset"], 40)
        self.assertEqual(row["verification"], "controlled local replay")
        self.assertEqual(row["coverage"]["PWN03"]["status"], "ran")
        self.assertEqual(row["source_sha256"], digest)
        self.assertFalse(row["challenge_accepted"])
        self.assertEqual([item["status"] for item in row["controls"]],
                         ["matched", "no crash"])
        for name in ("pattern.bin", "replay.bin", "probe-gdb.txt", "replay-gdb.txt",
                     "probe-inferior.txt", "replay-inferior.txt"):
            self.assertEqual((run / name).stat().st_mode & 0o777, 0o600)
        self.assertNotIn((run / "pattern.bin").read_text(), (run / "report.md").read_text())
        before = (run / "probe-gdb.txt").read_bytes()
        self.cli("resume", run)
        self.cli("report", run, code=0)
        self.assertEqual((run / "probe-gdb.txt").read_bytes(), before)

    def test_argv_and_changed_alphabet_holdouts(self):
        for channel, alphabet in (("argv", "XYZpq789"), ("stdin", "QWERTY123")):
            with self.subTest(channel=channel, alphabet=alphabet):
                row = self.record(self.cli(*self.args(channel=channel, alphabet=alphabet)))
                self.assertEqual(row["offset"], 40)
                self.assertEqual(row["verification"], "controlled local replay")
                self.assertEqual(row["channel"], channel)

    def test_stdin_reader_waiting_for_eof_reaches_its_return(self):
        source = self.root / "eof.c"
        source.write_text(
            '#include <stdio.h>\nstatic volatile unsigned index;\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; int value; '
            'while ((value = getchar()) != EOF) buf[index++] = (char)value; }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "eof"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        row = self.record(self.cli(*self.args(binary=binary)))
        self.assertEqual(row["verification"], "controlled local replay")
        self.assertGreater(row["offset"], 0)
        self.assertFalse(row["challenge_accepted"])

    def test_relative_target_writes_stay_in_the_private_run(self):
        source = self.root / "relative.c"
        source.write_text(
            '#include <stdio.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'FILE *file = fopen("relative-marker", "w"); '
            'if (file) { fputs("local", file); fclose(file); } '
            'read(0, buf, 512); }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "relative"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        result = self.cli(*self.args(binary=binary))
        run = Path(result["run"])
        self.assertEqual(self.record(result)["verification"], "controlled local replay")
        self.assertEqual((run / "relative-marker").read_text(), "local")
        self.assertFalse((self.root / "relative-marker").exists())

    def test_no_crash_is_partial_and_never_guesses_offset(self):
        row = self.record(self.cli(*self.args(binary=self.safe)))
        self.assertIsNone(row["offset"])
        self.assertEqual(row["verification"], "unverified")
        self.assertEqual(row["stop_reason"], "no_crash")
        self.assertEqual(row["coverage"]["PWN03"]["status"], "partial")

    def test_unavailable_debugger_is_partial(self):
        with mock.patch.object(pwn_offset.shutil, "which", return_value=None):
            run, _ = pwn_offset.start(self.binary, "stdin", "abcde12345", 256, 8,
                                      self.root / "runs")
        row = json.loads((run / "manifest.json").read_text())
        self.assertIsNone(row["offset"])
        self.assertEqual(row["stop_reason"], "debugger_unavailable")

    def test_selected_elf_cannot_inherit_parent_secrets_or_loader_controls(self):
        source = self.root / "environment.c"
        source.write_text(
            '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
            'static const char *readvar(const char *name) { const char *value = getenv(name); '
            'return value ? value : "unset"; }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'printf("TOKEN=%s\\nPRELOAD=%s\\nLIBRARY=%s\\n", '
            'readvar("AUTOSOLVE_SECRET_SENTINEL"), readvar("LD_PRELOAD"), '
            'readvar("LD_LIBRARY_PATH")); fflush(stdout); read(0, buf, 512); }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "environment"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        fake_debugger = self.root / "gdb"
        fake_debugger.write_text('#!/bin/sh\nprintf selected > "' +
                                 str(self.root / "fake-gdb-ran") + '"\n')
        fake_debugger.chmod(0o755)
        original_which = shutil.which
        original_popen = subprocess.Popen
        with mock.patch.dict(os.environ, {"AUTOSOLVE_SECRET_SENTINEL": "LEAK_ONLY_IF_BROKEN",
                                              "LD_PRELOAD": "/tmp/unsafe-loader-sentinel.so",
                                              "LD_LIBRARY_PATH": "/tmp/unsafe-library-sentinel",
                                              "PATH": str(self.root)}), \
             mock.patch.object(pwn_offset.shutil, "which", wraps=original_which) as resolver, \
             mock.patch.object(pwn_offset.subprocess, "Popen", wraps=original_popen) as launcher:
            run, _ = pwn_offset.start(binary, "stdin", "abcde12345", 256, 8,
                                      self.root / "runs")
        self.assertTrue(launcher.call_args_list)
        self.assertTrue(all(call.kwargs['env'] == {'LC_ALL': 'C',
                                                 'PYTHONDONTWRITEBYTECODE': '1'}
                            for call in launcher.call_args_list))
        row = json.loads((run / "manifest.json").read_text())
        text = (run / "probe-inferior.txt").read_text()
        self.assertIn("TOKEN=unset\nPRELOAD=unset\nLIBRARY=unset", text)
        self.assertNotIn("LEAK_ONLY_IF_BROKEN", text)
        self.assertNotIn("unsafe-loader-sentinel", (run / "probe-gdb.txt").read_text())
        resolver.assert_called_with("gdb", path="/usr/bin:/bin")
        self.assertFalse((self.root / "fake-gdb-ran").exists())
        self.assertEqual(row["verification"], "controlled local replay")

    def test_explicit_local_library_path_and_loader_failure(self):
        library = self.root / "lib"
        library.mkdir()
        helper = self.root / "helper.c"
        helper.write_text('int helper(void) { return 1; }\n')
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library / "helper"),
                        str(helper)], check=True, capture_output=True)
        source = self.root / "linked.c"
        source.write_text(
            '#include <unistd.h>\nextern int helper(void);\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'if (helper()) read(0, buf, 512); }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "linked"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source), "-L", str(library),
                        "-l:helper"], check=True, capture_output=True)
        missing = self.record(self.cli(*self.args(binary=binary)))
        self.assertIsNone(missing["offset"])
        self.assertEqual(missing["stop_reason"], "loader_failure")
        supplied = self.record(self.cli(*self.args(binary=binary), "--library-path", library))
        self.assertEqual(supplied["verification"], "controlled local replay")
        self.assertEqual(supplied["offset"], 40)
        self.assertEqual(supplied["library_path"], str(library))
        for character in (":", ";", "$ORIGIN"):
            unsafe = self.root / f"unsafe{character}directory"
            unsafe.mkdir()
            self.assertEqual(self.cli(*self.args(binary=binary), "--library-path", unsafe,
                                      code=2)["status"], "invalid_input")
        with mock.patch.object(pwn_offset.shutil, "which",
                               side_effect=lambda name, path=None:
                               "/usr/bin/gdb" if name == "gdb" else None):
            run, _ = pwn_offset.start(binary, "stdin", "abcde12345", 256, 8,
                                      self.root / "runs", library)
        self.assertEqual(json.loads((run / "manifest.json").read_text())["offset"], 40)
        (library / "glibc-hwcaps").mkdir()
        self.assertEqual(self.cli(*self.args(binary=binary), "--library-path", library,
                                  code=2)["status"], "invalid_input")

    def test_rejects_invalid_input_and_stale_source(self):
        self.assertEqual(self.cli(*self.args(alphabet="AA1"), code=2)["status"],
                         "invalid_input")
        self.assertEqual(self.cli(*self.args(), "--length", 9999, code=2)["status"],
                         "invalid_input")
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.cli(*self.args())
        self.binary.write_bytes(self.binary.read_bytes() + b"x")
        row = self.record(self.cli("resume", result["run"]))
        self.assertEqual(row["source_sha256"], digest)
        self.assertIn("Source identity current: no",
                      (Path(result["run"]) / "report.md").read_text())

    def test_capability_and_distribution_include_the_offset_adapter(self):
        listing = self.cli("capabilities", "--category", "pwn_services", code=0)
        self.assertEqual(next(row["status"] for row in listing["families"]
                              if row["id"] == "PWN03"), "partial")
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import package_toolkit
            paths = package_toolkit.collect(SCRIPT.parent.parent)
        finally:
            sys.path.pop(0)
        self.assertIn("scripts/autosolve_lib/pwn_offset.py", paths)
        self.assertIn("tests/test_autosolve_pwn_offset.py", paths)

    def test_timeout_does_not_mislabel_an_unchanged_source(self):
        with mock.patch.object(pwn_offset, "_debugger", return_value=("timeout", None)), \
             mock.patch.object(pwn_offset, "_source_current", side_effect=(True, None, None)):
            run, status = pwn_offset.start(self.binary, "stdin", "abcde12345", 256, 8,
                                           self.root / "runs")
        row = json.loads((run / "manifest.json").read_text())
        self.assertEqual(status, "partial")
        self.assertEqual(row["stop_reason"], "timeout")
        self.assertIsNone(row["offset"])
        self.assertTrue(self.binary.exists())

    def test_gdb_disables_auto_load_before_reading_the_elf(self):
        run = self.root / "private"
        run.mkdir(mode=0o700)
        with mock.patch.object(pwn_offset.subprocess, "Popen", side_effect=OSError("stub")) as call:
            status, _ = pwn_offset._debugger(self.binary, "argv", b"ABC", run, "probe",
                                             time.monotonic() + 3, "/usr/bin/gdb")
        self.assertEqual(status, "debugger_unavailable")
        command = call.call_args.args[0]
        self.assertEqual(command[command.index("set auto-load off") - 1], "-iex")
        self.assertLess(command.index("set auto-load off"), command.index("--args"))


if __name__ == "__main__":
    unittest.main()
