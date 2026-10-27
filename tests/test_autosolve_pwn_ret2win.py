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

    def offset_args(self, run):
        return ("pwn-ret2win", "--binary", self.binary, "--offset-run", run,
                "--symbol", "win", "--prompt-hex", b"READY>\n".hex(),
                "--success-hex", b"LOCAL-RET2WIN-SUCCESS".hex(),
                "--budget", 5, "--runs-root", self.root / "runs")

    def verified_offset(self, channel="stdin", library=None):
        arguments = ("pwn-offset", "--binary", self.binary, "--channel", channel,
                     "--length", 128, "--budget", 8, "--runs-root", self.root / "runs")
        if library is not None:
            arguments += ("--library-path", library)
        result = self.cli(*arguments)
        run = Path(result["run"])
        self.assertEqual(json.loads((run / "manifest.json").read_text())["stop_reason"],
                         "verified")
        return run

    @unittest.skipUnless(shutil.which("gdb"), "GDB unavailable")
    def test_verified_offset_run_replays_with_explicit_marker(self):
        offset_run = self.verified_offset()
        candidate = self.cli(*self.offset_args(offset_run))
        candidate_run = Path(candidate["run"])
        self.assertEqual(json.loads((candidate_run / "manifest.json").read_text())
                         ["validation"], "candidate")
        self.assertFalse((candidate_run / "transcript.jsonl").exists())
        result = self.cli(*self.offset_args(offset_run), "--replay-local")
        manifest = json.loads((Path(result["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["offset"], 40)
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        self.assertEqual(manifest["offset_run"], str(offset_run))
        self.assertFalse(manifest["challenge_accepted"])
        conflict = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                   *map(str, self.offset_args(offset_run)), "--offset", "40"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(conflict.returncode, 2)
        self.assertIn("not allowed", conflict.stderr)

    @unittest.skipUnless(shutil.which("gdb"), "GDB unavailable")
    def test_offset_handoff_rejects_tampered_and_unverified_evidence(self):
        offset_run = self.verified_offset()
        manifest_path = offset_run / "manifest.json"
        original = json.loads(manifest_path.read_text())
        cases = (("verification", "unverified"), ("stop_reason", "timeout"),
                 ("offset", 41), ("channel", "argv"), ("schema_version", 999),
                 ("source", str(self.root / "other")),
                 ("source_sha256", "0" * 64),
                 ("controls", [{"name": "changed return bytes", "status": "matched"}]))
        for key, value in cases:
            with self.subTest(key=key):
                changed = dict(original)
                changed[key] = value
                manifest_path.write_text(json.dumps(changed))
                before = set((self.root / "runs").iterdir())
                result = self.cli(*self.offset_args(offset_run), "--replay-local", code=2)
                self.assertEqual(result["status"], "invalid_input")
                self.assertEqual(set((self.root / "runs").iterdir()), before)
        manifest_path.write_text(json.dumps(original))
        manifest_path.write_text("[" * 10000 + "0" + "]" * 10000)
        self.assertEqual(self.cli(*self.offset_args(offset_run), code=2)["status"],
                         "invalid_input")
        manifest_path.write_text(json.dumps(original))
        replay = offset_run / "replay.bin"
        replay.write_bytes(b"A" * 40 + b"C" * 8)
        self.assertEqual(self.cli(*self.offset_args(offset_run), code=2)["status"],
                         "invalid_input")
        replay.write_bytes(b"A" * 39 + b"B" * 8)
        paired = dict(original, offset=39, candidate_offset=39)
        manifest_path.write_text(json.dumps(paired))
        self.assertEqual(self.cli(*self.offset_args(offset_run), code=2)["status"],
                         "invalid_input")
        manifest_path.write_text(json.dumps(original))
        replay.write_bytes(b"A" * 40 + b"B" * 8)
        trace = offset_run / "replay-gdb.txt"
        recorded_trace = trace.read_bytes()
        trace.write_bytes(recorded_trace.replace(b"0x42", b"0x43"))
        self.assertEqual(self.cli(*self.offset_args(offset_run), code=2)["status"],
                         "invalid_input")
        trace.write_bytes(recorded_trace)
        self.binary.write_bytes(self.binary.read_bytes() + b"stale")
        self.assertEqual(self.cli(*self.offset_args(offset_run), code=2)["status"],
                         "invalid_input")

    @unittest.skipUnless(shutil.which("gdb"), "GDB unavailable")
    def test_offset_handoff_rejects_argv_and_changed_library_entry(self):
        library = self.root / "lib"
        library.mkdir()
        extra = library / "notes.txt"
        extra.write_text("recorded")
        offset_run = self.verified_offset(library=library)
        result = self.cli(*self.offset_args(offset_run), "--replay-local")
        manifest = json.loads((Path(result["run"]) / "manifest.json").read_text())
        self.assertEqual(manifest["library_path"], str(library))
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        extra.write_text("changed")
        self.assertEqual(self.cli(*self.offset_args(offset_run), "--replay-local",
                                  code=2)["status"], "invalid_input")
        extra.unlink()
        self.assertEqual(self.cli(*self.offset_args(offset_run), "--replay-local",
                                  code=2)["status"], "invalid_input")
        self.assertEqual(self.cli(*self.offset_args(offset_run), "--replay-local",
                                  "--library-path", self.root, code=2)["status"],
                         "invalid_input")

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

    def test_local_replay_uses_private_cwd_and_minimal_environment(self):
        source = self.root / "relative.c"
        source.write_text(
            '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void win(void) { puts("LOCAL-PRIVATE-WIN"); '
            'fflush(stdout); }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); read(0,buf,128); }\n'
            'int main(void) { FILE *f=fopen("relative-write.txt","w"); '
            'if(f) { fputs("probe",f); fclose(f); } '
            'if(getenv("AUTOSOLVE_SYNTHETIC_CANARY")) puts("ENV-LEAK"); '
            'vuln(); return 0; }\n')
        binary = self.root / "relative"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        with mock.patch.dict(os.environ, {"AUTOSOLVE_SYNTHETIC_CANARY": "canary-123"}):
            result = self.cli(*self.args(binary, marker="LOCAL-PRIVATE-WIN"),
                              "--replay-local")
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        self.assertFalse((self.root / "relative-write.txt").exists())
        self.assertTrue((run / "candidate" / "relative-write.txt").exists())
        for name in ("short", "wrong-target", "candidate"):
            self.assertTrue((run / name / "relative-write.txt").exists())
        self.assertNotIn("ENV-LEAK", (run / "transcript.jsonl").read_text())

    def test_adjacent_companion_requires_explicit_private_resource_copy(self):
        source = self.root / "resource.c"
        source.write_text(
            '#include <stdio.h>\n#include <unistd.h>\n'
            '__attribute__((noinline)) void win(void) { char text[32]; '
            'FILE *f=fopen("flag.txt","r"); if(!f) return; '
            'if(fgets(text,sizeof(text),f)) { puts("LOCAL-RESOURCE-WIN"); fflush(stdout); } '
            'fclose(f); }\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); read(0,buf,128); }\n'
            'int main(void) { vuln(); return 0; }\n')
        binary = self.root / "resource"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-o", str(binary), str(source)],
                       check=True, capture_output=True)
        companion = self.root / "flag.txt"
        companion.write_text("practice-key\n")
        args = self.args(binary, marker="LOCAL-RESOURCE-WIN")
        absent = self.cli(*args, "--replay-local")
        self.assertEqual(json.loads((Path(absent["run"]) / "manifest.json").read_text())
                         ["validation"], "unverified")
        present = self.cli(*args, "--replay-local", "--resource-file", companion)
        run = Path(present["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        self.assertEqual((run / "candidate" / "flag.txt").read_text(), "practice-key\n")
        self.assertEqual(companion.read_text(), "practice-key\n")

    def test_staging_budget_stop_keeps_partial_run(self):
        with mock.patch.object(pwn_ret2win, "_staged_cwd",
                               side_effect=ValueError("resource time budget")):
            run, _ = pwn_ret2win.start(
                self.binary, 40, "win", b"READY>\n".hex(),
                b"LOCAL-RET2WIN-SUCCESS".hex(), 5,
                runs_root=self.root / "runs", replay_local=True)
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "unverified")
        self.assertFalse(manifest["replay_attempted"])
        self.assertTrue((run / "report.md").is_file())

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


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gdb"), "GCC/GDB unavailable")
class CallChainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        (self.fixture / "calls.c").write_text(
            '#include <stdio.h>\n'
            'static int step;\n'
            'void one_body(unsigned long a,unsigned long b,unsigned long c) { '
            'if(a==0x123 && b==0x456 && c==0x789 && step==0) step=1; }\n'
            '__attribute__((naked)) void one(unsigned long a,unsigned long b,unsigned long c) '
            '{ __asm__("mov %rsp,%rax; and $15,%rax; cmp $8,%rax; jne 1f; '
            'jmp one_body; 1: ret"); }\n'
            'void two(unsigned long a,unsigned long b,unsigned long c) { '
            'if(a==0x123 && b==0x456 && c==0x789 && step==1) step=2; }\n'
            'void three_body(unsigned long a,unsigned long b,unsigned long c) { '
            'if(a==0x123 && b==0x456 && c==0x789 && step==2) '
            '{ puts("LOCAL-CALL-SUCCESS"); fflush(stdout); } }\n'
            '__attribute__((naked)) void three(unsigned long a,unsigned long b,unsigned long c) '
            '{ __asm__("mov %rsp,%rax; and $15,%rax; cmp $8,%rax; jne 1f; '
            'jmp three_body; 1: ret"); }\n')
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(self.fixture / "libcalls.so"),
                        str(self.fixture / "calls.c")], check=True, capture_output=True)
        (self.fixture / "main.c").write_text(
            '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
            'void one(unsigned long,unsigned long,unsigned long);\n'
            'void two(unsigned long,unsigned long,unsigned long);\n'
            'void three(unsigned long,unsigned long,unsigned long);\n'
            '__asm__(".global arg_gadget\\narg_gadget: pop %rdi; pop %rsi; pop %rdx; ret");\n'
            '__attribute__((noinline)) void vuln(void) { char buf[32]; '
            'puts("READY>"); fflush(stdout); read(0, buf, 256); }\n'
            'int main(int argc,char **argv) { '
            'FILE *f=fopen("relative-write.txt","w"); '
            'if(f) { fputs("probe",f); fclose(f); } '
            'if(getenv("AUTOSOLVE_SYNTHETIC_CANARY")) puts("ENV-LEAK"); '
            'if(argc==10) { one(0,0,0); two(0,0,0); '
            'three(0,0,0); } vuln(); return 0; }\n')
        self.binary = self.fixture / "main"
        subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                        "-no-pie", "-Wl,-z,now", "-L", str(self.fixture), "-o", str(self.binary),
                        str(self.fixture / "main.c"), "-lcalls"], check=True, capture_output=True)
        self.spec = self.root / "calls.json"
        self.spec.write_text(json.dumps({"schema_version": 1, "calls": [
            {"symbol": name, "args": ["0x123", "0x456", "0x789"]}
            for name in ("one", "two", "three")]}))
        self.spec.chmod(0o600)
        self.resource = self.root / "key.dat"
        self.resource.write_bytes(b"practice-key")

    def cli(self, *args, code=3):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                 *map(str, args)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_verified_three_call_cli_and_tamper_controls(self):
        offset = self.cli("pwn-offset", "--binary", self.binary, "--channel", "stdin",
                          "--length", 160, "--budget", 15,
                          "--library-path", self.fixture, "--runs-root", self.root / "offset-runs")
        offset_manifest = json.loads((Path(offset["run"]) / "manifest.json").read_text())
        self.assertEqual(offset_manifest["coverage"]["PWN03"]["status"], "ran",
                         offset_manifest)
        args = ("pwn-call-chain", "--binary", self.binary, "--offset-run", offset["run"],
                "--calls-json", self.spec, "--prompt-hex", b"READY>\n".hex(),
                "--success-hex", b"LOCAL-CALL-SUCCESS".hex(), "--budget", 10,
                "--runs-root", self.root / "call-runs", "--resource-file", self.resource)
        with mock.patch.dict(os.environ, {"AUTOSOLVE_SYNTHETIC_CANARY": "canary-123"}):
            result = self.cli(*args, "--replay-local")
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["validation"], "local marker observed with controls")
        self.assertEqual(len((run / "payload.bin").read_bytes()), 184)
        self.assertEqual([row["status"] for row in manifest["controls"]],
                         ["marker absent"] * 4)
        self.assertFalse(manifest["challenge_accepted"])
        self.assertFalse((self.fixture / "relative-write.txt").exists())
        self.assertTrue((run / "candidate" / "relative-write.txt").exists())
        self.assertNotIn("ENV-LEAK", (run / "transcript.jsonl").read_text())
        self.cli("resume", run)
        self.assertIn("Source and replay inputs verified current: yes",
                      (run / "report.md").read_text())
        copy = run / "candidate" / "key.dat"
        copy.write_bytes(b"tampered")
        self.cli("resume", run)
        self.assertIn("Source and replay inputs verified current: no",
                      (run / "report.md").read_text())
        copy.write_bytes(b"practice-key")
        from scripts.autosolve_lib import pwn_call_chain
        with mock.patch.object(pwn_call_chain.pwn, "_staged_cwd",
                               side_effect=ValueError("resource time budget")):
            stopped_run, _ = pwn_call_chain.start(
                self.binary, offset["run"], self.spec, b"READY>\n".hex(),
                b"LOCAL-CALL-SUCCESS".hex(), 10, self.root / "call-runs", True,
                [str(self.resource)])
        stopped_manifest = json.loads((stopped_run / "manifest.json").read_text())
        self.assertEqual(stopped_manifest["validation"], "unverified")
        self.assertFalse(stopped_manifest["replay_attempted"])
        self.assertTrue((stopped_run / "report.md").is_file())
        with mock.patch.object(pwn_call_chain.pwn, "_loader_current", return_value=False):
            pwn_call_chain.resume(run)
        self.assertIn("Source and replay inputs verified current: no",
                      (run / "report.md").read_text())
        original = pwn_call_chain.run_service
        calls = 0

        def change_non_library_entry(*arguments, **options):
            nonlocal calls
            result = original(*arguments, **options)
            calls += 1
            if calls == 1:
                source = self.fixture / "main.c"
                source.write_bytes(source.read_bytes() + b"changed")
            return result

        with mock.patch.object(pwn_call_chain, "run_service",
                               side_effect=change_non_library_entry):
            stale_run, _ = pwn_call_chain.start(self.binary, offset["run"], self.spec,
                                                 b"READY>\n".hex(),
                                                 b"LOCAL-CALL-SUCCESS".hex(), 10,
                                                 self.root / "call-runs", True)
        stale_manifest = json.loads((stale_run / "manifest.json").read_text())
        self.assertEqual(calls, 1)
        self.assertEqual(stale_manifest["validation"], "unverified")
        self.assertFalse(stale_manifest["replay_attempted"])
        self.assertIn("Source and replay inputs verified current: no",
                      (stale_run / "report.md").read_text())
        (self.fixture / "libcalls.so").write_bytes((self.fixture / "libcalls.so").read_bytes() + b"x")
        stale = self.cli(*args, code=2)
        self.assertEqual(stale["status"], "invalid_input")

    def test_private_spec_and_plt_stub_controls(self):
        from scripts.autosolve_lib import pwn_call_chain
        from elftools.elf.elffile import ELFFile

        deadline = 10 ** 10
        path, digest, calls = pwn_call_chain._spec(self.spec, deadline)
        self.assertEqual(path, self.spec)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(digest), 64)
        _, _, entries, _, _, _ = pwn_call_chain._candidate(self.binary, 40, calls, deadline)
        with self.binary.open("rb") as source:
            plt = ELFFile(source).get_section_by_name(".plt")
            target_offset = plt["sh_offset"] + entries["one"]["plt_address"] - plt["sh_addr"]
        changed = self.fixture / "changed-plt"
        raw = bytearray(self.binary.read_bytes())
        raw[target_offset] ^= 1
        changed.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "PLT stub"):
            pwn_call_chain._candidate(changed, 40, calls, deadline)
        alias = self.root / "alias.json"
        alias.symlink_to(self.spec)
        with self.assertRaises(ValueError):
            pwn_call_chain._spec(alias, deadline)
        self.spec.write_text('{"schema_version":1,"schema_version":1,"calls":[]}')
        with self.assertRaisesRegex(ValueError, "duplicate keys"):
            pwn_call_chain._spec(self.spec, deadline)

    def test_explicit_resources_are_bounded_private_copies(self):
        from scripts.autosolve_lib import pwn_ret2win

        deadline = 10 ** 10
        resource = self.root / "key.dat"
        resource.write_bytes(b"practice-key")
        records = pwn_ret2win._resources([str(resource)], self.binary, deadline)
        run = self.root / "resource-run"
        run.mkdir(mode=0o700)
        cwd = pwn_ret2win._staged_cwd(run, "short", records, deadline)
        self.assertEqual((cwd / "key.dat").read_bytes(), b"practice-key")
        self.assertEqual((cwd / "key.dat").stat().st_mode & 0o777, 0o600)
        self.assertTrue(pwn_ret2win._copied_resources_current(cwd, records, deadline))
        attempted = [{"name": "short", "status": "inconclusive", "attempted": True}]
        self.assertTrue(pwn_ret2win._run_copies_current(run, records, attempted, False, deadline))
        shutil.rmtree(cwd)
        self.assertFalse(pwn_ret2win._run_copies_current(run, records, attempted, False, deadline))
        resource.write_bytes(b"changed")
        self.assertFalse(pwn_ret2win._resources_current(records, deadline))
        alias = self.root / "alias.dat"
        alias.symlink_to(resource)
        with self.assertRaisesRegex(ValueError, "symlink"):
            pwn_ret2win._resources([str(alias)], self.binary, deadline)
        with self.assertRaisesRegex(ValueError, "collides"):
            pwn_ret2win._resources([str(resource), str(resource)], self.binary, deadline)


if __name__ == "__main__":
    unittest.main()
