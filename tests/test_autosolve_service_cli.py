"""Public PWN01 CLI evidence and replay safety on a loopback service."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class ServiceCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args, code):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def serve(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(3)
        observed = []

        def worker():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        conn.sendall(b"menu> ")
                        observed.append(conn.recv(16))
                        conn.sendall(b"ACK\x00\x05PROOF")
            except TimeoutError:
                pass

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        return listener.getsockname()[1], observed, thread

    def test_explicit_service_steps_private_transcript_and_no_replay(self):
        port, observed, thread = self.serve()
        protocol = self.root / "protocol.json"
        protocol.write_text(json.dumps({"steps": [
            {"read": {"delimiter_hex": b"> ".hex()}},
            {"write_hex": b"1\n".hex()},
            {"read": {"exact_bytes": 3}},
            {"read": {"length_bytes": 2}}]}))
        result = self.cli("service", "--host", "127.0.0.1", "--port", port,
                          "--protocol", protocol, "--budget", "3",
                          "--runs-root", self.root / "runs", code=3)
        self.assertEqual(result["status"], "partial")
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        transcript = [json.loads(line) for line in (run / "transcript.jsonl").read_text().splitlines()]
        frames = json.loads((run / "frames.json").read_text())
        self.assertEqual(manifest["transport_status"], "complete")
        self.assertEqual(manifest["coverage"]["PWN01"]["status"], "ran")
        self.assertFalse(manifest["challenge_accepted"])
        self.assertEqual(observed, [b"1\n"])
        self.assertEqual([bytes.fromhex(row["wire_hex"]) for row in frames],
                         [b"menu> ", b"ACK", b"\x00\x05PROOF"])
        self.assertEqual([row["direction"] for row in transcript],
                         ["recv", "send", "recv"])
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / "transcript.jsonl").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("PROOF", (run / "report.md").read_text())

        before = (run / "transcript.jsonl").read_bytes()
        self.assertEqual(self.cli("resume", run, "--budget", "3", code=3)["run"], str(run))
        self.assertEqual((run / "transcript.jsonl").read_bytes(), before)
        self.assertEqual(self.cli("report", run, code=0)["status"], "complete")
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(observed, [b"1\n"])

    def test_protocol_cannot_redirect_cli_endpoint_or_send_without_steps(self):
        for config in ({"transport": {"host": "127.0.0.1", "port": 1}, "steps": [
                            {"write_hex": "3130"}]}, {"steps": []}):
            protocol = self.root / "invalid.json"
            protocol.write_text(json.dumps(config))
            result = self.cli("service", "--host", "127.0.0.1", "--port", 1,
                              "--protocol", protocol, code=2)
            self.assertEqual(result["status"], "invalid_input")
        self.assertEqual(self.cli("service", "--host", "127.0.0.1", "--port", 1,
                                  code=2)["status"], "invalid_input")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(protocol)
        self.assertEqual(self.cli("service", "--host", "127.0.0.1", "--port", 1,
                                  "--protocol", symlink, code=2)["status"], "invalid_input")
        fifo = self.root / "fifo.json"
        os.mkfifo(fifo)
        started = time.monotonic()
        self.assertEqual(self.cli("service", "--host", "127.0.0.1", "--port", 1,
                                  "--protocol", fifo, "--budget", ".1", code=2)["status"],
                         "invalid_input")
        self.assertLess(time.monotonic() - started, 1)

    def test_doctor_probes_service_transport_without_network(self):
        result = capabilities.doctor(["pwn_services"], self_test=True)
        self.assertEqual(result["operations"]["pwn_services.service_transport"],
                         {"implemented": True, "functional_probe": "passed", "status": "ready"})


if __name__ == "__main__":
    unittest.main()
