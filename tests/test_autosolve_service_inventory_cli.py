"""Public PWN07 inventory CLI and private evidence contract."""

import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class InventoryCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args, code):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json", *map(str, args)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_enumeration_records_raw_banner_privately_and_resume_does_not_reconnect(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        open_port = listener.getsockname()[1]
        visits = []

        def server():
            with listener:
                conn, _ = listener.accept()
                with conn:
                    visits.append(1)
                    conn.sendall(b"FAKE/9.9 secret-looking-banner\n")

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        reserved = socket.socket()
        reserved.bind(("127.0.0.1", 0))
        closed_port = reserved.getsockname()[1]
        reserved.close()

        result = self.cli("service", "--host", "127.0.0.1", "--ports",
                          f"{open_port},{closed_port}", "--enumerate", "--budget", "2",
                          "--runs-root", self.root / "runs", code=3)
        self.assertEqual(result["status"], "partial")
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        inventory = json.loads((run / "inventory.json").read_text())
        self.assertEqual(manifest["run_type"], "service_inventory")
        self.assertEqual(manifest["coverage"]["PWN07"]["status"], "ran")
        self.assertEqual([row["state"] for row in inventory["ports"]], ["open", "closed"])
        self.assertEqual(inventory["ports"][0]["response_hex"],
                         b"FAKE/9.9 secret-looking-banner\n".hex())
        self.assertIsNone(inventory["ports"][0]["service_hypothesis"])
        self.assertNotIn("secret-looking-banner", (run / "report.md").read_text())
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / "inventory.json").stat().st_mode & 0o777, 0o600)
        before = (run / "inventory.json").read_bytes()
        self.assertEqual(self.cli("resume", run, code=3)["run"], str(run))
        self.assertEqual((run / "inventory.json").read_bytes(), before)
        self.assertEqual(self.cli("report", run, code=0)["status"], "complete")
        thread.join(1)
        self.assertEqual(visits, [1])

    def test_enumeration_requires_explicit_finite_ports_and_valid_protocol(self):
        for options in (("--ports", "1-100", "--enumerate"),
                        ("--ports", "", "--enumerate"),
                        ("--ports", "1", "--enumerate", "--protocol", "x"),
                        ("--ports", "1"),
                        ("--port", "1", "--enumerate")):
            with self.subTest(options=options):
                result = self.cli("service", "--host", "127.0.0.1", *options, code=2)
                self.assertEqual(result["status"], "invalid_input")

    def test_explicit_http_probe_collects_response_without_guessing_version(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        probe = b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"

        def server():
            with listener:
                conn, _ = listener.accept()
                with conn:
                    self.assertEqual(conn.recv(128), probe)
                    conn.sendall(b"HTTP/1.0 200 OK\r\nServer: Maybe/7\r\n\r\n")

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        protocol = self.root / "probes.json"
        protocol.write_text(json.dumps({"probes": {str(port): probe.hex()}}))
        result = self.cli("service", "--host", "127.0.0.1", "--ports", port,
                          "--enumerate", "--protocol", protocol,
                          "--budget", "2", "--runs-root", self.root / "runs", code=3)
        inventory = json.loads((Path(result["run"]) / "inventory.json").read_text())
        self.assertEqual(inventory["ports"][0]["request_hex"], probe.hex())
        self.assertEqual(inventory["ports"][0]["response_hex"],
                         b"HTTP/1.0 200 OK\r\nServer: Maybe/7\r\n\r\n".hex())
        self.assertEqual(inventory["ports"][0]["version_hint"],
                         {"value": "Maybe/7", "basis": "untrusted_server_header",
                          "verified": False})

    def test_doctor_probes_inventory_without_external_network(self):
        result = capabilities.doctor(["pwn_services"], self_test=True)
        self.assertEqual(result["operations"]["pwn_services.service_inventory"],
                         {"implemented": True, "functional_probe": "passed", "status": "ready"})


if __name__ == "__main__":
    unittest.main()
