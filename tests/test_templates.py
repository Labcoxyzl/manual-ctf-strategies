"""Exercise the starter with harmless local and loopback prompt/echo services."""
import base64
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import struct
import time
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

STARTER = Path(__file__).resolve().parents[1] / "scripts/templates/pwntools_starter.py"
try:
    import pwnlib
except ImportError:
    pwnlib = None


@unittest.skipUnless(pwnlib, "requires pwntools; use /opt/ctf-tools/py312/bin/python")
class TemplateTests(unittest.TestCase):
    def run_starter(self, *args, code=0):
        result = subprocess.run([sys.executable, str(STARTER), *args],
                                capture_output=True, timeout=10,
                                env={**os.environ, "TERM": "xterm", "PWNLIB_NOTERM": "1"})
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def local(self, body, code=0, timeout="1"):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "echo fixture"
            fixture.write_text(f"#!{sys.executable}\nimport sys, time\n{body}\n")
            fixture.chmod(0o700)
            return self.run_starter("--local", str(fixture), "--timeout", timeout, code=code)

    def test_local_echo(self):
        result = self.local("print('> ', end='', flush=True)\nprint('echo:' + input(), flush=True)")
        self.assertEqual(result.stdout, b"Reply: b'echo:hello\\n'\n")

    def test_loopback_echo(self):
        received = []
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                try:
                    with listener.accept()[0] as peer:
                        peer.settimeout(5)
                        peer.sendall(b"> ")
                        data = bytearray()
                        while not data.endswith(b"\n"):
                            chunk = peer.recv(32)
                            if not chunk:
                                raise EOFError("starter closed before sending payload")
                            data.extend(chunk)
                        received.append(bytes(data))
                        peer.sendall(b"echo:" + data)
                        received.append(peer.recv(1))
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            result = self.run_starter("--remote", "127.0.0.1", str(listener.getsockname()[1]))
            worker.join(6)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [b"hello\n", b""])
        self.assertEqual(result.stdout, b"Reply: b'echo:hello\\n'\n")

    def test_prompt_timeout(self):
        result = self.local("time.sleep(5)", code=1, timeout="0.1")
        self.assertIn(b"TimeoutError", result.stderr)
        self.assertNotIn(b"Reply:", result.stdout)

    def test_reply_timeout(self):
        result = self.local("print('> ', end='', flush=True)\ninput()\ntime.sleep(5)", code=1, timeout="0.1")
        self.assertIn(b"TimeoutError", result.stderr)
        self.assertNotIn(b"Reply:", result.stdout)

    def test_early_eof(self):
        result = self.local("print('partial', end='', flush=True)", code=1)
        self.assertIn(b"EOFError", result.stderr)
        self.assertNotIn(b"Reply:", result.stdout)

    def test_response_limit(self):
        result = self.local("print('> ', end='', flush=True)\ninput()\nprint('X' * 4097, flush=True)", code=1)
        self.assertIn(b"4096 bytes", result.stderr)
        self.assertNotIn(b"Reply:", result.stdout)

    def test_invalid_parameters(self):
        for timeout in ("0", "-1", "nan", "inf"):
            self.run_starter("--local", "/nonexistent", "--timeout", timeout, code=2)
        for port in ("0", "65536", "not-a-port"):
            self.run_starter("--remote", "127.0.0.1", port, code=2)
        self.run_starter("--local", "/nonexistent", "--remote", "127.0.0.1", "1234", code=2)


class GeneralTemplateTests(unittest.TestCase):
    def test_optional_dependency_help_without_site_packages(self):
        for name in ("pwntools_starter.py", "math_client.py"):
            script = str(STARTER.with_name(name))
            help_result = subprocess.run([sys.executable, "-I", "-S", script, "--help"], capture_output=True, timeout=5)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            result = subprocess.run([sys.executable, "-I", "-S", script, "--remote", "127.0.0.1", "1"], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(b"pwntools is unavailable", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def run_template(self, name, *args, code=0):
        result = subprocess.run([sys.executable, str(STARTER.with_name(name)), *args],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_file_intel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            for data, snippets in (
                (b"", (b"Size: 0 bytes; examined: 0 bytes", b"Strings shown: 0")),
                (b"\x00hello\n\xffworld", (b"00000001: 'hello'", b"00000008: 'world'")),
                (bytes(range(32)), (b"00000010: 10 11 12", b"Strings shown: 0")),
                (b"A" * (1024 * 1024 + 3), (b"examined: 1048576 bytes", b"sample truncated: True", b"display truncated", b"continuation unknown")),
                (b"word\x00" * 21, (b"Strings shown: 20", b"Additional strings in sample omitted: True")),
            ):
                path.write_bytes(data)
                result = self.run_template("file_intel.py", str(path))
                for snippet in snippets:
                    self.assertIn(snippet, result.stdout)
                self.assertEqual(path.read_bytes(), data)
            self.run_template("file_intel.py", str(path.with_name("missing")), code=1)
            self.run_template("file_intel.py", directory, code=1)
            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "pipe"
                os.mkfifo(fifo)
                self.run_template("file_intel.py", str(fifo), code=1)

    def test_binary_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.bin"
            original = b"prefix" + struct.pack("<4sI", b"CTF!", 0x12345678)
            path.write_bytes(original)
            result = self.run_template("binary_parser.py", str(path), "--offset", "0x6")
            self.assertIn(b"value=305419896", result.stdout)
            for offset in ("7", "100", "999999999999999999999999999999"):
                self.run_template("binary_parser.py", str(path), "--offset", offset, code=1)
            self.run_template("binary_parser.py", str(path), "--offset", "-1", code=2)
            self.run_template("binary_parser.py", str(path), code=1)
            self.assertEqual(path.read_bytes(), original)
            path.write_bytes(b"CTF!")
            self.run_template("binary_parser.py", str(path), code=1)
            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "input.pipe"
                os.mkfifo(fifo)
                self.assertIn(b"regular file", self.run_template("binary_parser.py", str(fifo), code=1).stderr)

    def test_jwt_inspection_is_local_and_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token.txt"
            token = b"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.c2ln\n"
            path.write_bytes(token)
            result = self.run_template("jwt_inspect.py", str(path))
            self.assertIn(b'"role": "user"', result.stdout)
            self.assertIn(b"signature and claims are unverified", result.stdout)
            self.assertEqual(path.read_bytes(), token)
            duplicate = b"e30." + base64.urlsafe_b64encode(b'{"role":"user","role":"admin"}').rstrip(b"=") + b".c2ln"
            non_json = b"e30." + base64.urlsafe_b64encode(b'{"role":NaN}').rstrip(b"=") + b".c2ln"
            overflow = b"e30." + base64.urlsafe_b64encode(b'{"role":1e1000}').rstrip(b"=") + b".c2ln"
            surrogate = b"e30." + base64.urlsafe_b64encode(b'{"role":"\\ud800"}').rstrip(b"=") + b".c2ln"
            for malformed in (b"one.two", b"e30.W10.c2ln", b"e30.?.c2ln", b"e30.e30.a", duplicate, non_json, overflow, surrogate, b"x" * 16385):
                path.write_bytes(malformed)
                result = self.run_template("jwt_inspect.py", str(path), code=1)
                self.assertEqual(result.stdout, b"")
            self.run_template("jwt_inspect.py", directory, code=1)
            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "token.pipe"
                os.mkfifo(fifo)
                self.assertIn(b"regular file", self.run_template("jwt_inspect.py", str(fifo), code=1).stderr)

    def test_http_exchange_and_failure_controls(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            server_version = "Apache/2.4.49"

            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append(self.path)
                if self.path == "/slow":
                    time.sleep(0.3)
                status = 404 if self.path == "/missing" else 302 if self.path == "/redirect" else 200
                self.send_response(status)
                if self.path == "/short":
                    self.send_header("Content-Length", "100")
                self.send_header("X-Training-Marker", "header-visible")
                self.send_header("X-Long", "A" * 513)
                if status == 302:
                    self.send_header("Location", "/must-not-follow")
                self.end_headers()
                try:
                    self.wfile.write(b"X" * 65537 if self.path == "/large" else b"hello")
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_POST(self):
                requests.append(self.path)
                data = self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                observed = self.run_template("http_probe.py", base + "/ok").stdout
                self.assertIn(b"Body: b'hello'", observed)
                self.assertIn(b"Header 'Server': 'Apache/2.4.49", observed)
                self.assertIn(b"Header 'X-Training-Marker': 'header-visible'", observed)
                self.assertIn(b"[value truncated]", observed)
                self.assertNotIn(b"A" * 513, observed)
                self.assertIn(b"Body: b'test body'", self.run_template("http_probe.py", base + "/post", "--data", "test body").stdout)
                self.assertIn(b"HTTP 404", self.run_template("http_probe.py", base + "/missing", code=1).stdout)
                self.assertIn(b"not followed", self.run_template("http_probe.py", base + "/redirect", code=1).stdout)
                self.assertNotIn("/must-not-follow", requests)
                self.assertIn(b"truncated", self.run_template("http_probe.py", base + "/large", code=1).stderr)
                self.assertIn(b"incomplete body", self.run_template("http_probe.py", base + "/short", code=1).stderr)
                self.assertIn(b"Failed:", self.run_template("http_probe.py", base + "/slow", "--timeout", "0.05", code=1).stderr)
                self.run_template("http_probe.py", base, "--timeout", "nan", code=2)
                self.run_template("http_probe.py", "file:///etc/hosts", code=2)
            finally:
                server.shutdown()
                worker.join(2)


if __name__ == "__main__":
    unittest.main()
