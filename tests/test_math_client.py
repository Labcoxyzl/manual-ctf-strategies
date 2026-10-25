"""Harmless local fixtures and a 100-question loopback arithmetic service."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

CLIENT = Path(__file__).resolve().parents[1] / "scripts/templates/math_client.py"
try:
    import pwnlib
except ImportError:
    pwnlib = None


class ArithmeticTests(unittest.TestCase):
    def test_arithmetic_whitelist_and_limits(self):
        spec = importlib.util.spec_from_file_location("math_client", CLIENT)
        client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(client)
        for expression, answer in (("(2 + 3) * 4", 20), ("12 / 3", 4),
                                   ("-7 // 3", -3), ("-7 % 3", 2), ("+9 - 2", 7)):
            self.assertEqual(client.solve(expression), answer)
        for expression in ("__import__('os')", "2 ** 1000000", "True + 1", "1.5", "1 / 2",
                           "9" * 32, "10**30", "1" * 513, "+" * 129 + "1",
                           "999999999999999999999999999999 * 2", "[1]", "1 +"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                client.solve(expression)
        with self.assertRaises(ZeroDivisionError):
            client.solve("1 // 0")


@unittest.skipUnless(pwnlib, "requires pwntools; use /opt/ctf-tools/py312/bin/python")
class MathClientTests(unittest.TestCase):
    def run_client(self, *args, code=0):
        result = subprocess.run([sys.executable, str(CLIENT), *args],
                                capture_output=True, timeout=10,
                                env={**os.environ, "TERM": "xterm", "PWNLIB_NOTERM": "1"})
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def local(self, body, code=0, *args):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "math fixture"
            fixture.write_text(f"#!{sys.executable}\nimport time\n{body}\n")
            fixture.chmod(0o700)
            return self.run_client("--local", sys.executable, str(fixture), *args, code=code)

    def test_100_questions_one_connection(self):
        errors, answers = [], []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                try:
                    with listener.accept()[0] as peer:
                        peer.settimeout(5)
                        with peer.makefile("rb") as stream:
                            for number in range(1, 101):
                                peer.sendall(f"Q {number}: ({number} + 2) * 3\n".encode())
                                reply = stream.readline(128)
                                if reply != f"{(number + 2) * 3}\n".encode():
                                    raise AssertionError(reply)
                                answers.append(reply)
                            peer.sendall(b"DONE practice-complete\n")
                            if stream.read(1) != b"":
                                raise AssertionError("unexpected extra reply")
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            started = time.monotonic()
            result = self.run_client("--remote", "127.0.0.1", str(listener.getsockname()[1]))
            elapsed = time.monotonic() - started
            worker.join(6)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(answers), 100)
        self.assertLess(elapsed, 60)
        self.assertEqual(result.stdout, b"Answered 100; completion: b'DONE practice-complete'\n")
        print(f"100 loopback questions completed in {elapsed:.3f}s", file=sys.stderr)

    def test_demo_service(self):
        result = self.run_client("--local", sys.executable, str(CLIENT.with_name("math_demo.py")))
        self.assertIn(b"Answered 100", result.stdout)
        rejected = subprocess.run([sys.executable, str(CLIENT.with_name("math_demo.py"))],
                                  input=b"wrong\n", capture_output=True, timeout=5)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn(b"ERROR incorrect answer", rejected.stdout)
        self.assertNotIn(b"DONE", rejected.stdout)

    def test_local_completion(self):
        result = self.local("print('Q 1: 10 / 2', flush=True)\nassert input() == '5'\nprint('DONE ok', flush=True)")
        self.assertIn(b"Answered 1", result.stdout)

    def test_failure_controls(self):
        cases = (
            ("print('Q 1: 2 ** 99999', flush=True)", "unsupported", ()),
            ("print('Q 1: 3 / 2', flush=True)", "exact integer", ()),
            ("print('Q 1: 1 / 0', flush=True)", "ZeroDivisionError", ()),
            ("print('Q 2: 1 + 1', flush=True)", "IDs", ()),
            ("print('ERROR wrong answer', flush=True)", "unexpected", ()),
            ("print('Q 1: 2 +', end='', flush=True)", "EOFError", ()),
            ("print('x' * 1025, flush=True)", "1024", ()),
            ("time.sleep(2)", "TimeoutError", ("--budget", "0.1")),
            ("print('Q 1: 1', flush=True)\nassert input() == '1'\nprint('Q 2: 2', flush=True)\nassert input() == ''", "limit", ("--max-questions", "1")),
            ("print('Q 1: 1', flush=True)\nassert input() == '1'", "EOFError", ("--max-questions", "1")),
        )
        for body, message, args in cases:
            with self.subTest(message=message, body=body):
                result = self.local(body, 1, *args)
                self.assertIn(message.encode(), result.stderr)
                self.assertNotIn(b"completion:", result.stdout)

    def test_invalid_arguments(self):
        for budget in ("0", "-1", "nan", "inf"):
            self.run_client("--local", "/nonexistent", "--budget", budget, code=2)
        self.run_client("--remote", "localhost", "65536", code=2)
        self.run_client("--local", "/nonexistent", "--max-questions", "0", code=2)


if __name__ == "__main__":
    unittest.main()
