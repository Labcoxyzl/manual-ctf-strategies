"""Public CLI checks for bounded local PWN04 ret2win synthesis."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.autosolve_lib import pwn_ret2win


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


@unittest.skipUnless(shutil.which("gcc"), "GCC unavailable")
class Ret2winTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        source = self.root / "practice.c"
        source.write_text(
            '#include <stdio.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void win(void) { puts("LOCAL-RET2WIN-SUCCESS"); fflush(stdout); }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); read(0, buf, 128); }\n'
            'int main(void) { vuln(); return 0; }\n')
        self.binary = self.root / "practice"
        self.pie = self.root / "practice-pie"
        self.canary = self.root / "practice-canary"
        for output, flags in ((self.binary, ["-fno-stack-protector", "-no-pie"]),
                              (self.pie, ["-fno-stack-protector", "-fPIE", "-pie"]),
                              (self.canary, ["-fstack-protector-all", "-no-pie"])):
            subprocess.run(["gcc", "-O0", "-fno-omit-frame-pointer", *flags,
                            "-o", str(output), str(source)], check=True, capture_output=True)

    def cli(self, *arguments, code=3):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                 *map(str, arguments)], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def args(self, binary=None, offset=40, marker="LOCAL-RET2WIN-SUCCESS"):
        return ("pwn-ret2win", "--binary", binary or self.binary,
                "--offset", offset, "--symbol", "win",
                "--prompt-hex", b"READY>\n".hex(),
                "--success-hex", marker.encode().hex(),
                "--budget", 3, "--runs-root", self.root / "runs")

    def test_generates_private_candidate_and_replays_success_once(self):
        before = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.cli(*self.args(), "--replay-local")
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        self.assertEqual([row["status"] for row in manifest["controls"]],
                         ["marker absent", "marker absent"])
        self.assertFalse(manifest["challenge_accepted"])
        self.assertEqual(manifest["coverage"]["PWN04"]["status"], "ran")
        self.assertEqual((run / "payload.bin").stat().st_mode & 0o777, 0o600)
        self.assertEqual((run / "transcript.jsonl").stat().st_mode & 0o777, 0o600)
        for name in ("short", "wrong-target"):
            self.assertEqual((run / f"control-{name}-transcript.jsonl").stat().st_mode &
                             0o777, 0o600)
        payload = (run / "payload.bin").read_bytes()
        self.assertEqual(len(payload), 56)
        self.assertEqual(payload[:40], b"A" * 40)
        self.assertEqual(payload[40:48], manifest["ret_address"].to_bytes(8, "little"))
        self.assertEqual(payload[48:56], manifest["target_address"].to_bytes(8, "little"))
        self.assertNotIn(payload.hex(), (run / "report.md").read_text())
        original_transcript = (run / "transcript.jsonl").read_bytes()
        self.cli("resume", run)
        self.cli("report", run, code=0)
        self.assertEqual((run / "transcript.jsonl").read_bytes(), original_transcript)
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), before)

    def test_wrong_offset_and_missing_marker_do_not_claim_success(self):
        wrong = self.cli(*self.args(offset=48), "--replay-local")
        manifest = json.loads((Path(wrong["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertFalse(manifest["challenge_accepted"])
        candidate = self.cli(*self.args(marker="never-printed"))
        candidate_run = Path(candidate["run"])
        record = json.loads((candidate_run / "manifest.json").read_text())
        self.assertEqual(record["validation"], "candidate")
        self.assertFalse((candidate_run / "transcript.jsonl").exists())

    def test_pie_canary_ambiguous_and_bad_arguments_refused(self):
        for binary, extras in ((self.pie, ()),
                               (self.pie, ("--runtime-base", "0x55555000")),
                               (self.canary, ())):
            with self.subTest(binary=binary.name, extras=extras):
                result = self.cli(*self.args(binary), *extras, code=2)
                self.assertEqual(result["status"], "invalid_input")
        supplied = self.cli(*self.args(self.pie), "--runtime-base", "0x55555000",
                            "--base-evidence", "sampled process leak")
        self.assertEqual(json.loads((Path(supplied["run"]) / "manifest.json").read_text())
                         ["validation"], "candidate")
        self.assertEqual(self.cli(*self.args(self.pie), "--runtime-base", "0x55555000",
                                  "--base-evidence", "sampled process leak",
                                  "--replay-local", code=2)["status"], "invalid_input")
        self.assertEqual(self.cli(*self.args(marker="READY>"), code=2)["status"],
                         "invalid_input")
        self.assertEqual(self.cli(*self.args(offset=0), code=2)["status"],
                         "invalid_input")

    def test_explicit_local_library_directory_and_missing_directory(self):
        result = self.cli(*self.args(), "--replay-local", "--library-path", self.root)
        manifest = json.loads((Path(result["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        missing = self.cli(*self.args(), "--replay-local", "--library-path",
                           self.root / "absent", code=2)
        self.assertEqual(missing["status"], "invalid_input")
        self.assertEqual(self.cli(*self.args(), "--library-path", self.root,
                                  code=2)["status"], "invalid_input")

    def test_resume_marks_changed_source_stale_without_replay(self):
        first = self.cli(*self.args(), "--replay-local")
        run = Path(first["run"])
        payload_digest = hashlib.sha256((run / "payload.bin").read_bytes()).hexdigest()
        transcript_digest = hashlib.sha256((run / "transcript.jsonl").read_bytes()).hexdigest()
        self.binary.write_bytes(self.binary.read_bytes() + b"changed")
        self.cli("resume", run)
        self.assertIn("Source identity current: no", (run / "report.md").read_text())
        self.assertEqual(hashlib.sha256((run / "payload.bin").read_bytes()).hexdigest(),
                         payload_digest)
        self.assertEqual(hashlib.sha256((run / "transcript.jsonl").read_bytes()).hexdigest(),
                         transcript_digest)

    def test_echo_of_payload_cannot_be_success_marker(self):
        result = self.cli(*self.args(marker="AAAA"), "--replay-local", code=2)
        self.assertEqual(result["status"], "invalid_input")
        self.assertIn("payload", result["reason"])

    def test_function_typed_symbol_in_nonexecutable_data_is_not_a_target(self):
        source = self.root / "fake.S"
        source.write_text('.data\n.globl fake_win\n.type fake_win, @function\n'
                          'fake_win: .byte 0xc3\n.section .note.GNU-stack,"",@progbits\n')
        fake = self.root / "fake-target"
        subprocess.run(["gcc", "-no-pie", "-o", str(fake),
                        str(self.root / "practice.c"), str(source)],
                       check=True, capture_output=True)
        args = list(self.args(fake))
        args[args.index("--symbol") + 1] = "fake_win"
        result = self.cli(*args, code=2)
        self.assertIn("executable", result["reason"])

    def test_identity_deadline_is_not_reported_as_source_change(self):
        original = pwn_ret2win.core._hash
        calls = 0

        def expire_third(*arguments):
            nonlocal calls
            calls += 1
            return None if calls == 3 else original(*arguments)

        with mock.patch.object(pwn_ret2win.core, "_hash", side_effect=expire_third):
            with self.assertRaisesRegex(ValueError, "identity incomplete"):
                pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                  b"LOCAL-RET2WIN-SUCCESS".hex(), 3,
                                  runs_root=self.root / "runs")

    def test_post_replay_identity_deadline_withholds_success_with_warning(self):
        original = pwn_ret2win.core._identity_matches
        calls = 0

        def expire_fifth(*arguments):
            nonlocal calls
            calls += 1
            return None if calls == 5 else original(*arguments)

        with mock.patch.object(pwn_ret2win.core, "_identity_matches",
                               side_effect=expire_fifth):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 3,
                                        runs_root=self.root / "runs", replay_local=True)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertIn("identity incomplete", " ".join(manifest["warnings"]))

    def test_marker_after_any_input_is_not_exploit_success(self):
        source = self.root / "always.c"
        source.write_text(
            '#include <stdio.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void win(void) { puts("REAL-WIN"); }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); read(0, buf, 128); '
            'puts("UNRELATED-MARKER"); fflush(stdout); }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "always"
        subprocess.run(["gcc", "-O0", "-fno-omit-frame-pointer", "-fno-stack-protector",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        result = self.cli(*self.args(binary, marker="UNRELATED-MARKER"), "--replay-local")
        manifest = json.loads((Path(result["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertFalse(manifest["challenge_accepted"])
        self.assertEqual(manifest["controls"][0]["status"], "marker observed")

    def test_marker_after_any_long_input_is_caught_by_wrong_target_control(self):
        source = self.root / "long.c"
        source.write_text(
            '#include <stdio.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void win(void) { puts("REAL-WIN"); }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); ssize_t n = read(0, buf, 128); '
            'if (n > 40) { puts("LONG-MARKER"); fflush(stdout); } }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "long"
        subprocess.run(["gcc", "-O0", "-fno-omit-frame-pointer", "-fno-stack-protector",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        result = self.cli(*self.args(binary, marker="LONG-MARKER"), "--replay-local")
        manifest = json.loads((Path(result["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertEqual([row["status"] for row in manifest["controls"]],
                         ["marker absent", "marker observed"])

    def test_changed_local_library_withholds_marker_claim(self):
        directory = self.root / "libs"
        directory.mkdir()
        library = directory / "libdemo.so"
        library.write_bytes(b"old-version")
        original = pwn_ret2win.run_service
        calls = 0

        def change_before_candidate(*arguments, **keywords):
            nonlocal calls
            calls += 1
            if calls == 3:
                library.write_bytes(b"new-version")
            return original(*arguments, **keywords)

        with mock.patch.object(pwn_ret2win, "run_service",
                               side_effect=change_before_candidate):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 5,
                                        runs_root=self.root / "runs", replay_local=True,
                                        library_path=directory)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(calls, 3)
        self.assertEqual(manifest["validation"], "unverified")
        self.assertIn("library identity changed", " ".join(manifest["warnings"]))

    def test_identity_deadline_after_run_creation_keeps_partial_record(self):
        original = pwn_ret2win.core._identity_matches
        calls = 0

        def expire_first_control(*arguments):
            nonlocal calls
            calls += 1
            return None if calls == 2 else original(*arguments)

        with mock.patch.object(pwn_ret2win.core, "_identity_matches",
                               side_effect=expire_first_control):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 3,
                                        runs_root=self.root / "runs", replay_local=True)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertEqual(manifest["controls"][0]["status"], "inconclusive")
        self.assertIn("source identity incomplete", " ".join(manifest["warnings"]))

    def test_added_library_entry_withholds_marker_claim(self):
        directory = self.root / "libs"
        directory.mkdir()
        original = pwn_ret2win.run_service
        calls = 0

        def add_before_candidate(*arguments, **keywords):
            nonlocal calls
            calls += 1
            if calls == 3:
                (directory / "libnew.so").write_bytes(b"new-entry")
            return original(*arguments, **keywords)

        with mock.patch.object(pwn_ret2win, "run_service", side_effect=add_before_candidate):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 5,
                                        runs_root=self.root / "runs", replay_local=True,
                                        library_path=directory)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertIn("library identity changed", " ".join(manifest["warnings"]))

    def test_removed_library_directory_keeps_partial_record(self):
        directory = self.root / "libs"
        directory.mkdir()
        original = pwn_ret2win.run_service
        calls = 0

        def remove_after_first_control(*arguments, **keywords):
            nonlocal calls
            calls += 1
            result = original(*arguments, **keywords)
            if calls == 1:
                directory.rmdir()
            return result

        with mock.patch.object(pwn_ret2win, "run_service",
                               side_effect=remove_after_first_control):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 5,
                                        runs_root=self.root / "runs", replay_local=True,
                                        library_path=directory)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertIn("library identity changed", " ".join(manifest["warnings"]))

    def test_removed_binary_after_control_keeps_partial_record(self):
        original = pwn_ret2win.run_service
        calls = 0

        def remove_after_first_control(*arguments, **keywords):
            nonlocal calls
            calls += 1
            result = original(*arguments, **keywords)
            if calls == 1:
                self.binary.unlink()
            return result

        with mock.patch.object(pwn_ret2win, "run_service",
                               side_effect=remove_after_first_control):
            run, _ = pwn_ret2win.start(self.binary, 40, "win", b"READY>\n".hex(),
                                        b"LOCAL-RET2WIN-SUCCESS".hex(), 5,
                                        runs_root=self.root / "runs", replay_local=True)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertIn("source identity changed", " ".join(manifest["warnings"]))


if __name__ == "__main__":
    unittest.main()
