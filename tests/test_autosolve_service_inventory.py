"""PWN07 inventory against disposable assigned loopback services."""

import socket
import threading
import time
import unittest
from unittest import mock

from scripts.autosolve_lib.profiles.service_inventory import run_inventory


class ServiceInventoryTests(unittest.TestCase):
    def serve(self, conversation):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        port = listener.getsockname()[1]

        def worker():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(2)
                        conversation(conn)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        return port

    def test_custom_and_http_services_preserve_raw_evidence(self):
        custom = self.serve(lambda conn: conn.sendall(b"SSH-2.0-fake-version\r\n"))

        def http(conn):
            self.assertEqual(conn.recv(128), b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            conn.sendall(b"HTTP/1.0 200 OK\r\nServer: Demo/9.9\r\n\r\n")

        web = self.serve(http)
        probe = b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [
            custom, {"port": web, "probe_hex": probe.hex()}]}, timeout=2)
        self.assertEqual(warnings, [])
        self.assertEqual(report["status"], "complete")
        self.assertEqual([row["port"] for row in report["ports"]], [custom, web])
        self.assertEqual([row["state"] for row in report["ports"]], ["open", "open"])
        self.assertEqual(report["ports"][0]["response_hex"], b"SSH-2.0-fake-version\r\n".hex())
        self.assertIsNone(report["ports"][0]["service_hypothesis"])
        self.assertEqual(report["ports"][0]["peer"], ["127.0.0.1", custom])
        self.assertEqual(report["ports"][1]["request_hex"], probe.hex())
        self.assertEqual(report["ports"][1]["response_hex"],
                         b"HTTP/1.0 200 OK\r\nServer: Demo/9.9\r\n\r\n".hex())
        self.assertEqual(report["ports"][1]["service_hypothesis"],
                         {"name": "http", "basis": "response_status_line", "verified": False})
        self.assertEqual(report["ports"][1]["version_hint"],
                         {"value": "Demo/9.9", "basis": "untrusted_server_header", "verified": False})

    def test_closed_and_delayed_banner_are_distinguished(self):
        delayed = self.serve(lambda conn: (time.sleep(.06), conn.sendall(b"ready>")))
        reserved = socket.socket()
        reserved.bind(("127.0.0.1", 0))
        closed = reserved.getsockname()[1]
        reserved.close()
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [closed, delayed]},
                                         timeout=1)
        self.assertEqual(warnings, [])
        self.assertEqual(report["ports"][0]["state"], "closed")
        self.assertEqual(report["ports"][0]["response_hex"], "")
        self.assertEqual(report["ports"][1]["state"], "open")
        self.assertEqual(report["ports"][1]["response_hex"], b"ready>".hex())

    def test_open_service_timeout_is_partial_and_keeps_observed_state(self):
        slow = self.serve(lambda conn: time.sleep(.3))
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [slow]}, timeout=.1)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["ports"][0]["state"], "open")
        self.assertEqual(report["ports"][0]["response_status"], "timeout")
        self.assertEqual(report["ports"][0]["response_hex"], "")
        self.assertTrue(warnings)

    def test_partial_banner_survives_timeout_and_does_not_starve_next_port(self):
        def stalled(conn):
            conn.sendall(b"partial")
            time.sleep(.4)

        first = self.serve(stalled)
        second = self.serve(lambda conn: conn.sendall(b"next>"))
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [first, second]},
                                         timeout=.3)
        self.assertTrue(warnings)
        self.assertEqual(report["ports"][0]["state"], "open")
        self.assertEqual(report["ports"][0]["response_hex"], b"partial".hex())
        self.assertEqual(report["ports"][0]["response_status"], "timeout_after_data")
        self.assertEqual(report["ports"][1]["state"], "open")
        self.assertEqual(report["ports"][1]["response_hex"], b"next>".hex())

    def test_response_limit_keeps_only_bounded_raw_evidence(self):
        port = self.serve(lambda conn: conn.sendall(b"A" * 2048))
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [port]})
        self.assertEqual(report["status"], "partial")
        self.assertTrue(warnings)
        self.assertEqual(report["ports"][0]["response_status"], "limit")
        self.assertEqual(report["ports"][0]["response_hex"], (b"A" * 1024).hex())

    def test_passive_inventory_sends_no_inferred_probe(self):
        received = []
        finished = threading.Event()

        def passive(conn):
            conn.sendall(b"choose 1> ")
            received.append(conn.recv(64))
            finished.set()

        port = self.serve(passive)
        report, _ = run_inventory({"host": "127.0.0.1", "ports": [port]}, timeout=.15)
        self.assertTrue(finished.wait(1))
        self.assertEqual(received, [b""])
        self.assertEqual(report["ports"][0]["request_hex"], "")
        self.assertEqual(report["ports"][0]["response_hex"], b"choose 1> ".hex())

    def test_hostname_resolution_obeys_requested_deadline(self):
        def slow_resolver(*args, **kwargs):
            time.sleep(.3)
            return []

        start = time.monotonic()
        with mock.patch("socket.getaddrinfo", side_effect=slow_resolver):
            report, warnings = run_inventory({"host": "assigned.example", "ports": [31337]},
                                             timeout=.05)
        self.assertLess(time.monotonic() - start, .2)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["ports"][0]["state"], "unknown")
        self.assertEqual(report["ports"][0]["response_status"], "timeout")
        self.assertTrue(warnings)

    def test_http_body_cannot_forge_server_header(self):
        response = b"HTTP/1.0 200 OK\r\nContent-Length: 18\r\n\r\nServer: Forged/9\r\n"
        port = self.serve(lambda conn: conn.sendall(response))
        report, warnings = run_inventory({"host": "127.0.0.1", "ports": [port]})
        self.assertEqual(warnings, [])
        row = report["ports"][0]
        self.assertEqual(row["response_hex"], response.hex())
        self.assertEqual(row["service_hypothesis"],
                         {"name": "http", "basis": "response_status_line", "verified": False})
        self.assertIsNone(row["version_hint"])

    def test_scope_and_probe_validation_precedes_network(self):
        invalid = [
            {"ports": [80]}, {"host": "127.0.0.1", "ports": []},
            {"host": "127.0.0.1/24", "ports": [80]},
            {"host": "127.0.0.1", "ports": ["1-65535"]},
            {"host": "127.0.0.1", "ports": [True]},
            {"host": "127.0.0.1", "ports": [80] * 17},
            {"host": "127.0.0.1", "ports": [80, 80]},
            {"host": "127.0.0.1", "ports": [{"port": 80, "probe_hex": "zz"}]},
            {"host": "127.0.0.1", "ports": [{"port": 80, "probe_hex": "aa" * 257}]},
        ]
        for scope in invalid:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                run_inventory(scope)


if __name__ == "__main__":
    unittest.main()
