"""PWN01 service framing against disposable loopback and local processes."""

import os
import signal
import socket
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles.service_transport import run_service


class ServiceTransportTests(unittest.TestCase):
    def serve(self, conversation):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)

        def worker():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(3)
                        conversation(conn)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        return {"host": "127.0.0.1", "port": listener.getsockname()[1]}

    def test_newline_prompt_never_triggers_guessed_choice(self):
        def conversation(conn):
            conn.sendall(b"Choose 1 to continue\n")
            conn.settimeout(.2)
            try:
                received = conn.recv(64)
            except socket.timeout:
                received = b""
            self.assertEqual(received, b"")

        endpoint = self.serve(conversation)
        report, warnings = run_service({"transport": endpoint,
                                        "steps": [{"read": {"delimiter_hex": "0a"}}]})
        self.assertEqual(warnings, [])
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["frames"][0]["wire_hex"], b"Choose 1 to continue\n".hex())
        self.assertEqual([row["direction"] for row in report["transcript"]], ["recv"])

    def test_heldout_fragmented_delimiter_and_explicit_write(self):
        def conversation(conn):
            conn.sendall(b"banner without newline;ready>")
            self.assertEqual(conn.recv(4), b"GO\n")
            conn.sendall(b"par")
            time.sleep(.02)
            conn.sendall(b"tial||tail")

        endpoint = self.serve(conversation)
        report, warnings = run_service({"transport": endpoint, "steps": [
            {"read": {"delimiter_hex": b"ready>".hex()}},
            {"write_hex": b"GO\n".hex()},
            {"read": {"delimiter_hex": b"||".hex()}}]})
        self.assertEqual(warnings, [])
        self.assertEqual([bytes.fromhex(row["wire_hex"]) for row in report["frames"]],
                         [b"banner without newline;ready>", b"partial||"])
        self.assertEqual(bytes.fromhex(report["pending_hex"]), b"tail")
        self.assertEqual([row["direction"] for row in report["transcript"]],
                         ["recv", "send", "recv", "recv"])
        self.assertTrue(all(row["elapsed_ms"] >= 0 for row in report["transcript"]))
        self.assertEqual([row["offset"] for row in report["transcript"] if row["direction"] == "recv"],
                         [0, len(b"banner without newline;ready>"),
                          len(b"banner without newline;ready>par")])

    def test_length_prefix_and_exact_framing(self):
        def conversation(conn):
            conn.sendall(b"\x00")
            time.sleep(.01)
            conn.sendall(b"\x03abcXY")

        endpoint = self.serve(conversation)
        report, warnings = run_service({"transport": endpoint, "steps": [
            {"read": {"length_bytes": 2, "byteorder": "big"}},
            {"read": {"exact_bytes": 2}}]})
        self.assertEqual(warnings, [])
        self.assertEqual([row["wire_hex"] for row in report["frames"]],
                         [b"\x00\x03abc".hex(), b"XY".hex()])
        self.assertEqual(report["frames"][0]["payload_hex"], b"abc".hex())
        self.assertEqual(report["frames"][1]["start_offset"], 5)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI is unavailable")
    def test_tls_wrapper_with_explicit_trust_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                           check=True, capture_output=True, timeout=10)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)

            def conversation(conn):
                with context.wrap_socket(conn, server_side=True) as wrapped:
                    wrapped.sendall(b"secure> ")

            endpoint = self.serve(conversation)
            endpoint.update({"tls": True, "ca_file": str(cert)})
            report, warnings = run_service({"transport": endpoint,
                                            "steps": [{"read": {"delimiter_hex": b"> ".hex()}}]})
            self.assertEqual(warnings, [])
            self.assertTrue(report["transport"]["tls"])
            self.assertEqual(bytes.fromhex(report["frames"][0]["wire_hex"]), b"secure> ")

    def test_ca_file_must_be_bounded_regular_file_before_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / "ca.fifo"
            os.mkfifo(fifo)
            symlink = root / "ca.link"
            symlink.symlink_to(fifo)
            oversized = root / "ca.pem"
            oversized.write_bytes(b"x" * (1024 * 1024 + 1))
            for source in (fifo, symlink, oversized):
                with self.subTest(source=source.name), mock.patch(
                        "scripts.autosolve_lib.profiles.service_transport._connect",
                        side_effect=AssertionError("connection attempted")) as connect:
                    with self.assertRaisesRegex(ValueError, "CA"):
                        run_service({"transport": {"host": "127.0.0.1", "port": 1,
                                                   "tls": True, "ca_file": str(source)},
                                     "steps": [{"read": {"exact_bytes": 1}}]}, timeout=.1)
                    connect.assert_not_called()

    def test_eof_timeout_and_oversized_length_are_partial(self):
        for mode in ("eof", "timeout", "length"):
            def conversation(conn, mode=mode):
                if mode == "eof":
                    conn.sendall(b"unterminated")
                elif mode == "timeout":
                    time.sleep(.3)
                else:
                    conn.sendall(b"\xff\xff")

            endpoint = self.serve(conversation)
            read = {"length_bytes": 2} if mode == "length" else {"delimiter_hex": "0a"}
            report, warnings = run_service({"transport": endpoint, "steps": [{"read": read}]},
                                           timeout=.1, max_bytes=64)
            self.assertEqual(report["status"], "partial", mode)
            self.assertTrue(warnings, mode)
            self.assertEqual(report["error"], {"eof": "early_eof", "timeout": "timeout",
                                                "length": "frame_limit"}[mode])

    def test_dns_lookup_obeys_budget(self):
        def slow_lookup(*args, **kwargs):
            time.sleep(.4)
            return []

        with mock.patch("socket.getaddrinfo", side_effect=slow_lookup):
            started = time.monotonic()
            report, warnings = run_service({"transport": {"host": "slow.example", "port": 1234},
                                            "steps": [{"read": {"exact_bytes": 1}}]}, timeout=.05)
        self.assertEqual(report["error"], "timeout")
        self.assertTrue(warnings)
        self.assertLess(time.monotonic() - started, .25)

    def test_interruption_is_reported_without_replay(self):
        with mock.patch("scripts.autosolve_lib.profiles.service_transport._connect",
                        side_effect=KeyboardInterrupt):
            report, warnings = run_service({"transport": {"host": "127.0.0.1", "port": 1},
                                            "steps": [{"read": {"exact_bytes": 1}}]})
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["error"], "interrupted")
        self.assertEqual(report["transcript"], [])
        self.assertTrue(warnings)

    def test_local_process_requires_explicit_permission_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "service.py"
            script.write_text("import sys\n"
                              "sys.stdout.buffer.write(b'ready>')\n"
                              "sys.stdout.buffer.flush()\n"
                              "line = sys.stdin.buffer.readline()\n"
                              "sys.stdout.buffer.write(b'ACK:' + line)\n"
                              "sys.stdout.buffer.flush()\n")
            spec = {"transport": {"argv": [sys.executable, str(script)]}, "steps": [
                {"read": {"delimiter_hex": b">".hex()}},
                {"write_hex": b"hello\n".hex()},
                {"read": {"delimiter_hex": "0a"}}]}
            with self.assertRaisesRegex(ValueError, "local execution"):
                run_service(spec)
            report, warnings = run_service(spec, allow_local=True)
            self.assertEqual(warnings, [])
            self.assertEqual(report["status"], "complete")
            self.assertEqual(bytes.fromhex(report["frames"][1]["wire_hex"]), b"ACK:hello\n")

    def test_local_process_timeout_preserves_partial_transcript(self):
        script = ("import sys,time; sys.stdout.buffer.write(b'partial'); "
                  "sys.stdout.buffer.flush(); time.sleep(30)")
        started = time.monotonic()
        report, warnings = run_service({"transport": {"argv": [sys.executable, "-c", script]},
                                        "steps": [{"read": {"delimiter_hex": "0a"}}]},
                                       timeout=.1, allow_local=True)
        self.assertEqual(report["error"], "timeout")
        self.assertEqual(bytes.fromhex(report["pending_hex"]), b"partial")
        self.assertTrue(warnings)
        self.assertLess(time.monotonic() - started, 1)

    def test_cleanup_kills_term_ignoring_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            armed = root / "child.pid"
            child = ("import os,signal,time,pathlib; "
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     f"pathlib.Path({str(armed)!r}).write_text(str(os.getpid())); "
                     "time.sleep(30)")
            leader = "\n".join((
                "import pathlib,subprocess,sys,time",
                f"subprocess.Popen([sys.executable,'-c',{child!r}])",
                f"p=pathlib.Path({str(armed)!r})",
                "while not p.exists(): time.sleep(.005)",
                "sys.stdout.buffer.write(b'ready>'); sys.stdout.buffer.flush(); time.sleep(30)",
            ))
            report, warnings = run_service({"transport": {"argv": [sys.executable, "-c", leader]},
                                            "steps": [{"read": {"delimiter_hex": "3e"}}]},
                                           timeout=2, allow_local=True)
            self.assertEqual((report["status"], warnings), ("complete", []))
            pid = int(armed.read_text())
            try:
                for _ in range(20):
                    stat_path = Path(f"/proc/{pid}/stat")
                    if not stat_path.exists() or stat_path.read_text().split()[2] == "Z":
                        break
                    time.sleep(.02)
                else:
                    self.fail("SIGTERM-ignoring child survived process-group cleanup")
            finally:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_invalid_protocol_fails_before_connection(self):
        endpoint = {"host": "127.0.0.1", "port": 1}
        for steps in ([{"write_hex": "gg"}], [{"write_hex": "aa bb "}],
                      [{"read": {"delimiter_hex": ""}}],
                      [{"read": {"length_bytes": 3}}], [{"choose_menu": 1}]):
            with self.assertRaises(ValueError):
                run_service({"transport": endpoint, "steps": steps})


if __name__ == "__main__":
    unittest.main()
