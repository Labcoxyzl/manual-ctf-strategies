"""MISC01 arithmetic protocol checks against disposable loopback services."""

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.autosolve_lib import setup as capabilities
from scripts.autosolve_lib.profiles.arithmetic_protocol import run_arithmetic


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class ArithmeticProtocolTests(unittest.TestCase):
    @staticmethod
    def read_exact(conn, size):
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def serve(self, conversation):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        errors = []

        def worker():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(2)
                        conversation(conn)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        def finish():
            thread.join(2)
            self.assertFalse(thread.is_alive(), "loopback service did not stop")
            self.assertEqual(errors, [])

        self.addCleanup(finish)
        return {"host": "127.0.0.1", "port": listener.getsockname()[1]}

    @staticmethod
    def protocol(transport, **changes):
        spec = {
            "transport": transport,
            "framing": {"delimiter_hex": "0d0a"},
            "question": {"prefix_ascii": "ASK#", "separator_ascii": "| ",
                         "suffix_ascii": "?", "first_id": 5, "id_step": 2},
            "completion": {"prefix_ascii": "WIN:", "min_suffix_bytes": 1},
            "response": {"encoding": "ascii_decimal", "prefix_hex": b"ans=".hex(),
                         "suffix_hex": b";\r\n".hex()},
        }
        spec.update(changes)
        return spec

    def test_fragmented_non_template_protocol_and_exact_transcript(self):
        def conversation(conn):
            conn.sendall(b"ASK#5| (7 + 5)")
            time.sleep(.01)
            conn.sendall(b" * 3?\r\n")
            self.assertEqual(self.read_exact(conn, 9), b"ans=36;\r\n")
            conn.sendall(b"ASK#7| 18 / 3?\r\n")
            self.assertEqual(self.read_exact(conn, 8), b"ans=6;\r\n")
            conn.sendall(b"WIN:practice-token\r\n")

        report, warnings = run_arithmetic(self.protocol(self.serve(conversation)))
        self.assertEqual((report["status"], warnings), ("complete", []))
        self.assertEqual([row["answer"] for row in report["rounds"]], [36, 6])
        self.assertEqual(bytes.fromhex(report["completion_hex"]), b"WIN:practice-token\r\n")
        self.assertEqual(b"".join(bytes.fromhex(row["hex"]) for row in report["transcript"]
                                  if row["direction"] == "send"), b"ans=36;\r\nans=6;\r\n")
        self.assertEqual([bytes.fromhex(row["wire_hex"]) for row in report["frames"]],
                         [b"ASK#5| (7 + 5) * 3?\r\n", b"ASK#7| 18 / 3?\r\n",
                          b"WIN:practice-token\r\n"])

    def test_heldout_ids_grammar_and_numeric_bound(self):
        def conversation(conn):
            conn.sendall(b"R11 => -2 * (3 + 4)\n")
            self.assertEqual(self.read_exact(conn, 4), b"-14\n")
            conn.sendall(b"R14 => 23 // 5\n")
            self.assertEqual(self.read_exact(conn, 2), b"4\n")
            conn.sendall(b"OK\n")

        spec = self.protocol(self.serve(conversation),
                             framing={"delimiter_hex": "0a"},
                             question={"prefix_ascii": "R", "separator_ascii": " => ",
                                       "suffix_ascii": "", "first_id": 11, "id_step": 3},
                             completion={"prefix_ascii": "OK", "min_suffix_bytes": 0},
                             response={"encoding": "ascii_decimal", "prefix_hex": "",
                                       "suffix_hex": "0a"})
        report, warnings = run_arithmetic(spec, max_integer=100)
        self.assertEqual((report["status"], warnings), ("complete", []))
        self.assertEqual([row["id"] for row in report["rounds"]], [11, 14])

    def test_rejects_unsupported_expression_stale_id_and_premature_completion(self):
        for wire, expected in ((b"ASK#5| 2 ** 3?\r\n", "expression"),
                               (b"ASK#7| 2 + 3?\r\n", "stale_round"),
                               (b"WIN:too-early\r\n", "premature_completion")):
            with self.subTest(wire=wire):
                def conversation(conn):
                    conn.sendall(wire)
                    self.assertEqual(conn.recv(64), b"")

                report, warnings = run_arithmetic(self.protocol(self.serve(conversation)))
                self.assertEqual(report["status"], "partial")
                self.assertEqual(report["error"], expected)
                self.assertEqual(report["bytes_sent"], 0)
                self.assertTrue(warnings)

    def test_round_limit_requires_terminal_condition(self):
        def conversation(conn):
            conn.sendall(b"ASK#5| 2 + 3?\r\n")
            self.assertEqual(self.read_exact(conn, 8), b"ans=5;\r\n")
            conn.sendall(b"ASK#7| 3 + 4?\r\n")
            self.assertEqual(conn.recv(64), b"")

        report, warnings = run_arithmetic(self.protocol(self.serve(conversation)), max_rounds=1)
        self.assertEqual((report["status"], report["error"]), ("partial", "round_limit"))
        self.assertEqual(len(report["rounds"]), 1)
        self.assertTrue(warnings)

    def test_completion_before_declared_minimum_rounds_is_partial(self):
        def conversation(conn):
            conn.sendall(b"ASK#5| 2 + 3?\r\n")
            self.assertEqual(self.read_exact(conn, 8), b"ans=5;\r\n")
            conn.sendall(b"WIN:early\r\n")

        spec = self.protocol(self.serve(conversation), completion={
            "prefix_ascii": "WIN:", "min_suffix_bytes": 1, "min_rounds": 2})
        report, warnings = run_arithmetic(spec)
        self.assertEqual((report["status"], report["error"]),
                         ("partial", "premature_completion"))
        self.assertEqual(len(report["rounds"]), 1)
        self.assertTrue(warnings)

    def test_timeout_and_frame_limit_preserve_partial_wire(self):
        for wire, expected in ((b"ASK#5| 2 +", "timeout"),
                               (b"x" * 65, "frame_limit")):
            with self.subTest(expected=expected):
                def conversation(conn):
                    conn.sendall(wire)
                    time.sleep(.15)

                report, warnings = run_arithmetic(self.protocol(self.serve(conversation)),
                                                   timeout=.05, max_frame_bytes=64)
                self.assertEqual(report["error"], expected)
                self.assertEqual(bytes.fromhex(report["pending_hex"]), wire)
                self.assertTrue(warnings)

    def test_declared_integer_bound_rejects_large_answer_without_sending(self):
        def conversation(conn):
            conn.sendall(b"ASK#5| 101 + 0?\r\n")
            self.assertEqual(conn.recv(64), b"")

        report, warnings = run_arithmetic(self.protocol(self.serve(conversation)),
                                          max_integer=100)
        self.assertEqual((report["status"], report["error"]), ("partial", "expression"))
        self.assertEqual(report["bytes_sent"], 0)
        self.assertTrue(warnings)

    def test_invalid_configuration_fails_before_connection(self):
        spec = self.protocol({"host": "127.0.0.1", "port": 1})
        spec["response"]["encoding"] = "python_eval"
        with self.assertRaisesRegex(ValueError, "encoding"):
            run_arithmetic(spec)

    def test_public_cli_private_completion_and_resume_never_replays_answers(self):
        replies = []

        def conversation(conn):
            conn.sendall(b"ASK#5| 9 * 7?\r\n")
            replies.append(self.read_exact(conn, 9))
            conn.sendall(b"WIN:private-proof\r\n")

        endpoint = self.serve(conversation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.protocol(endpoint)
            del config["transport"]
            source = root / "arithmetic.json"
            source.write_text(json.dumps(config))

            def cli(*args, code):
                completed = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                            *map(str, args)], capture_output=True, text=True,
                                           timeout=10)
                self.assertEqual(completed.returncode, code,
                                 completed.stderr + completed.stdout)
                return json.loads(completed.stdout)

            result = cli("service", "--host", endpoint["host"], "--port", endpoint["port"],
                         "--arithmetic-protocol", source, "--max-rounds", 2,
                         "--budget", 3, "--runs-root", root / "runs", code=3)
            self.assertEqual(result["status"], "partial")
            run = Path(result["run"])
            manifest = json.loads((run / "manifest.json").read_text())
            self.assertEqual((manifest["category"], manifest["run_type"]),
                             ("can_misc", "service_arithmetic"))
            self.assertEqual(manifest["coverage"]["MISC01"]["status"], "ran")
            self.assertTrue(manifest["completion_observed"])
            self.assertFalse(manifest["challenge_accepted"])
            self.assertEqual(replies, [b"ans=63;\r\n"])
            self.assertEqual(json.loads((run / "rounds.json").read_text())[0]["answer"], 63)
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual((run / "transcript.jsonl").stat().st_mode & 0o777, 0o600)
            self.assertNotIn("private-proof", (run / "report.md").read_text())
            before = (run / "transcript.jsonl").read_bytes()
            self.assertEqual(cli("resume", run, code=3)["run"], str(run))
            self.assertEqual(cli("report", run, code=0)["status"], "complete")
            self.assertEqual((run / "transcript.jsonl").read_bytes(), before)
            self.assertEqual(replies, [b"ans=63;\r\n"])

    def test_public_cli_rejects_endpoint_redirection_and_mode_mixing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.protocol({"host": "127.0.0.1", "port": 1})
            source = root / "arithmetic.json"
            source.write_text(json.dumps(config))

            def cli(*args):
                completed = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                            "service", "--host", "127.0.0.1", "--port", "1",
                                            *map(str, args)], capture_output=True, text=True,
                                           timeout=5)
                self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
                return json.loads(completed.stdout)

            self.assertEqual(cli("--arithmetic-protocol", source)["status"], "invalid_input")
            del config["transport"]
            source.write_text(json.dumps(config))
            self.assertEqual(cli("--arithmetic-protocol", source, "--protocol", source)["status"],
                             "invalid_input")

    def test_doctor_probes_arithmetic_without_external_service(self):
        result = capabilities.doctor(["can_misc"], self_test=True)
        self.assertEqual(result["operations"]["can_misc.arithmetic_protocol"],
                         {"implemented": True, "functional_probe": "passed", "status": "ready"})


if __name__ == "__main__":
    unittest.main()
