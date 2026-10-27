"""WEB02 checks against a disposable local HTTP server."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from scripts.autosolve_lib.profiles.web_discovery import discover_web
from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class WebDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Host")))
                parsed = urlsplit(self.path)
                params = parse_qs(parsed.query)
                host = self.headers.get("Host", "")
                if parsed.path == "/hidden":
                    status, body, location = 200, b"the known hidden route", None
                elif parsed.path == "/search" and "secret" in params:
                    status, body, location = 200, b"parameter accepted", None
                elif host.startswith("admin.example.test"):
                    status, body, location = 200, b"vhost accepted", None
                elif parsed.path == "/redirect":
                    status, body, location = 302, b"moved", "http://elsewhere.test/escape"
                elif parsed.path == "/local-redirect":
                    status, body, location = 302, b"moved", "/hidden"
                elif parsed.path.startswith("/catch/"):
                    status, body, location = 200, b"the same catch-all page", None
                elif parsed.path.startswith("/echo/"):
                    status, body, location = 200, parsed.path.encode(), None
                elif parsed.path == "/throttle":
                    status, body, location = 429, b"slow down", None
                elif parsed.path == "/slow":
                    time.sleep(.3)
                    status, body, location = 200, b"late response", None
                else:
                    status, body, location = 404, b"no route", None
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args, code):
        completed = subprocess.run([sys.executable, "-B", str(SCRIPT), "--json",
                                    *map(str, args)], capture_output=True, text=True,
                                   timeout=15)
        self.assertEqual(completed.returncode, code, completed.stderr + completed.stdout)
        return json.loads(completed.stdout)

    def scope(self, kind, words, path="/"):
        return {"origin": self.origin, "request": {"method": "GET", "path": path},
                "dictionary": words, "kind": kind}

    def test_path_controls_preserve_exact_evidence_and_do_not_follow_redirects(self):
        report, warnings = discover_web(
            self.scope("path", ["hidden", "redirect", "local-redirect", "absent"]),
            timeout=3, max_requests=6, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report["calibration"], "stable")
        self.assertEqual(report["requests_used"], 6)
        self.assertEqual(len(self.seen), 6)
        hidden, remote, local, absent = report["results"]
        self.assertEqual(hidden["classification"], "candidate")
        self.assertEqual(hidden["request"]["target"], "/hidden")
        self.assertEqual(hidden["response"]["status"], 200)
        self.assertEqual(hidden["response"]["bytes_read"], len(b"the known hidden route"))
        self.assertEqual(remote["redirect_scope"], "cross_origin")
        self.assertEqual(local["redirect_scope"], "same_origin")
        self.assertEqual(remote["response"]["headers"]["location"],
                         "http://elsewhere.test/escape")
        self.assertEqual(absent["classification"], "soft_404")
        self.assertFalse(any(path == "/escape" for path, _ in self.seen))

    def test_parameter_and_vhost_stay_on_explicit_connection(self):
        parameter, warnings = discover_web(
            self.scope("parameter", ["secret", "unused"], "/search"),
            timeout=2, max_requests=4, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(parameter["results"][0]["classification"], "candidate")
        self.assertEqual(parameter["results"][1]["classification"], "soft_404")
        self.assertIn("secret=1", parameter["results"][0]["request"]["target"])

        hosts, warnings = discover_web(
            self.scope("vhost", ["admin.example.test", "no.example.test"]),
            timeout=2, max_requests=4, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(hosts["results"][0]["classification"], "candidate")
        self.assertEqual(hosts["results"][0]["request"]["host"], "admin.example.test")
        self.assertEqual(hosts["results"][1]["classification"], "soft_404")
        self.assertEqual({host for _, host in self.seen if host.endswith("example.test")},
                         {"admin.example.test", "no.example.test"})

    def test_supplied_accept_encoding_is_not_duplicated(self):
        scope = self.scope("path", ["hidden"])
        scope["request"]["headers"] = {"accept-encoding": "gzip"}
        report, warnings = discover_web(scope, timeout=2, max_requests=3, rate=20)
        self.assertEqual(warnings, [])
        names = [key.lower() for key in report["results"][0]["request"]["headers"]]
        self.assertEqual(names.count("accept-encoding"), 1)

    def test_catch_all_throttle_and_budget_are_not_false_positive(self):
        catch, warnings = discover_web(
            self.scope("path", ["same", "other"], "/catch/"),
            timeout=2, max_requests=4, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual([row["classification"] for row in catch["results"]],
                         ["soft_404", "soft_404"])
        dynamic, warnings = discover_web(
            self.scope("path", ["hidden"], "/echo/"), timeout=2, max_requests=3,
            rate=20)
        self.assertEqual(dynamic["calibration"], "unstable")
        self.assertEqual(dynamic["results"][0]["classification"], "ambiguous")
        self.assertTrue(warnings)
        throttle, _ = discover_web(self.scope("path", ["throttle"]),
                                   timeout=2, max_requests=3, rate=20)
        self.assertEqual(throttle["results"][0]["classification"], "ambiguous")
        self.assertEqual(throttle["status"], "partial")
        limited, warnings = discover_web(self.scope("path", ["hidden", "absent"]),
                                         timeout=2, max_requests=3, rate=20)
        self.assertEqual(limited["status"], "partial")
        self.assertEqual([row["candidate"] for row in limited["results"]], ["hidden"])
        self.assertTrue(warnings)

    def test_timeout_and_unsafe_input_are_bounded(self):
        report, warnings = discover_web(self.scope("path", ["slow"]), timeout=.12,
                                        max_requests=3, rate=20)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(warnings)
        for bad in (
            {**self.scope("path", ["hidden"]), "origin": "http://127.0.0.1/other"},
            self.scope("path", ["../escape"]),
            self.scope("parameter", ["bad&name"]),
            self.scope("vhost", ["evil.test\r\nX: yes"]),
            {**self.scope("path", ["hidden"]), "request": {"method": "GET",
                "path": "/", "headers": {"X-Test": "value\r\nX-Evil: yes"}}},
            {**self.scope("path", ["hidden"]), "dictionary": ["x"] * 33},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                discover_web(bad)

    def test_public_raw_request_private_run_and_no_replay(self):
        request = self.root / "request.http"
        raw = (f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n"
               "Cookie: session=private\r\n\r\n").encode()
        request.write_bytes(raw)
        words = self.root / "words.txt"
        words.write_text("hidden\nabsent\n")
        result = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                          "--wordlist", words, "--budget", "3", "--rate", "20",
                          "--runs-root", self.root / "runs", code=3)
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        transcript = json.loads((run / "transcript.json").read_text())
        self.assertEqual(manifest["run_type"], "web_discovery")
        self.assertEqual(manifest["coverage"]["WEB02"]["status"], "ran")
        self.assertEqual(transcript["results"][0]["classification"], "candidate")
        self.assertEqual(transcript["requests_used"], 4)
        self.assertEqual((run / "request.http").read_bytes(), raw)
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / "transcript.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("session=private", (run / "report.md").read_text())
        self.assertNotIn("hidden", (run / "report.md").read_text())
        before = len(self.seen)
        self.cli("resume", run, code=3)
        self.cli("report", run, code=0)
        self.assertEqual(len(self.seen), before)

    def test_public_web_requires_explicit_dictionary_and_matching_host(self):
        request = self.root / "request.http"
        request.write_text(f"GET / HTTP/1.1\nHost: 127.0.0.1:{self.server.server_port}\n\n")
        no_words = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                            "--budget", "2", "--runs-root", self.root / "runs", code=3)
        self.assertEqual(json.loads((Path(no_words["run"]) / "manifest.json").read_text())
                         ["coverage"]["WEB02"]["status"], "partial")
        self.assertEqual(self.seen, [])
        words = self.root / "words.txt"
        words.write_text("hidden\n")
        request.write_text("GET / HTTP/1.1\nHost: elsewhere.test\n\n")
        self.assertEqual(self.cli("web", "--request-file", request,
                                  "--scope-origin", self.origin, "--wordlist", words,
                                  code=2)["status"], "invalid_input")
        self.assertEqual(self.seen, [])
        request.write_bytes((f"POST / HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n"
                             "Content-Length: 4\r\n\r\n").encode() + b"X\r\nY")
        unsupported = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                               "--wordlist", words, "--runs-root", self.root / "runs", code=3)
        self.assertEqual(json.loads((Path(unsupported["run"]) / "manifest.json").read_text())
                         ["coverage"]["WEB02"]["status"], "partial")
        self.assertEqual(self.seen, [])
        link = self.root / "link.http"
        link.symlink_to(request)
        self.assertEqual(self.cli("web", "--request-file", link,
                                  "--scope-origin", self.origin, code=2)["status"],
                         "invalid_input")

    def test_doctor_probes_discovery_against_loopback_only(self):
        result = capabilities.doctor(["web"], self_test=True)
        self.assertEqual(result["operations"]["web.discovery"],
                         {"implemented": True, "functional_probe": "passed", "status": "ready"})


if __name__ == "__main__":
    unittest.main()
