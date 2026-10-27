"""WEB05 differential checks against disposable loopback handlers only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from scripts.autosolve_lib import setup as capabilities
from scripts.autosolve_lib.profiles.web_leads import probe_web_leads


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autosolve.py"


class WebLeadTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                parsed = urlsplit(self.path)
                value = parse_qs(parsed.query).get("input", [""])[0]
                status = 200
                headers = {}
                if parsed.path == "/traversal":
                    body = (b"marker: selected-file-contents" if value == "../selected.txt"
                            else b"missing file")
                elif parsed.path == "/template":
                    body = ({"{{17*19}}": b"result: 323", "{{17*20}}": b"result: 340",
                             "${17*19}": b"result: 323", "${17*20}": b"result: 340"}
                            .get(value, b"result: unchanged"))
                elif parsed.path == "/echo":
                    body = ("escaped: " + value.replace("<", "&lt;")).encode()
                elif parsed.path == "/soft":
                    body = b"same soft-404 page"
                elif parsed.path == "/large":
                    body = b"A" * (64 * 1024 + 10)
                elif parsed.path == "/redirect":
                    status, body = 302, b"redirect"
                    headers["Location"] = "http://outside.invalid/escape"
                else:
                    status, body = 404, b"not found"
                self.send_response(status)
                for key, header_value in headers.items():
                    self.send_header(key, header_value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
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

    def request_file(self, path):
        request = self.root / "request.http"
        request.write_text(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n"
                           "Cookie: private-session\r\n\r\n")
        return request

    def scope(self, kind, path, **extra):
        return {"origin": self.origin, "request": {"method": "GET", "path": path,
                "query": {"input": "ordinary"}}, "parameter": "input", "kind": kind,
                **extra}

    def test_selected_traversal_has_exact_evidence_and_controls(self):
        report, warnings = probe_web_leads(
            self.scope("traversal", "/traversal", probe_value="../selected.txt",
                       expected="selected-file-contents"), timeout=2, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report["requests_used"], 4)
        self.assertEqual(report["classification"], "candidate")
        self.assertEqual(report["calibration"], "stable")
        self.assertEqual(report["requests"][-1]["request"]["target"],
                         "/traversal?input=..%2Fselected.txt")
        self.assertIn("selected-file-contents", report["requests"][-1]["response"]["body_text"])
        self.assertEqual(len(self.seen), 4)

    def test_arithmetic_template_requires_both_outputs(self):
        report, warnings = probe_web_leads(
            self.scope("template", "/template", expected="323"), timeout=2,
            rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report["classification"], "candidate")
        self.assertEqual(report["requests"][2]["value"], "{{17*20}}")
        self.assertEqual(report["requests"][3]["value"], "{{17*19}}")
        self.assertIn("340", report["requests"][2]["response"]["body_text"])
        self.assertIn("323", report["requests"][3]["response"]["body_text"])
        held_out, warnings = probe_web_leads(
            self.scope("template", "/template", expected="323", syntax="dollar"),
            timeout=2, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(held_out["classification"], "candidate")
        self.assertEqual(held_out["requests"][3]["value"], "${17*19}")

    def test_reflection_soft_404_and_redirect_are_not_candidates(self):
        for kind, path, extra in (
            ("template", "/echo", {"expected": "323"}),
            ("traversal", "/soft", {"probe_value": "../selected.txt",
                                       "expected": "selected-file-contents"}),
            ("traversal", "/redirect", {"probe_value": "../selected.txt",
                                           "expected": "selected-file-contents"}),
        ):
            with self.subTest(path=path):
                report, _ = probe_web_leads(self.scope(kind, path, **extra),
                                            timeout=2, rate=20)
                self.assertNotEqual(report["classification"], "candidate")
        self.assertEqual(len(self.seen), 12)
        self.assertFalse(any("/escape" in target for target in self.seen))

    def test_invalid_scope_and_budget_send_no_requests(self):
        cases = [
            self.scope("traversal", "/traversal", probe_value="../selected.txt"),
            self.scope("traversal", "/traversal", probe_value="http://other/",
                       expected="selected-file-contents"),
            self.scope("template", "/template", expected="999"),
            self.scope("template", "/template", expected="323", syntax="unknown"),
            {**self.scope("template", "/template", expected="323"),
             "origin": "http://127.0.0.1/other"},
            {**self.scope("template", "/template", expected="323"),
             "request": {"method": "POST", "path": "/template", "query": {"input": "x"}}},
            {**self.scope("template", "/template", expected="323"),
             "request": {"method": "GET", "path": "/template",
                         "query": {"input": "ordinary"},
                         "raw_query": "input=ordinary&%69nput=second"}},
            {**self.scope("template", "/template", expected="323"),
             "request": {"method": "GET", "path": "/template",
                         "query": {"input": "ordinary"},
                         "raw_query": "input=other"}},
            {**self.scope("template", "/template", expected="323"),
             "request": {"method": "GET", "path": "/template",
                         "query": {"input": "ordinary", "bad name": "x"},
                         "raw_query": "bad name=x&input=ordinary"}},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                probe_web_leads(case)
        with self.assertRaises(ValueError):
            probe_web_leads(self.scope("template", "/template", expected="323"), rate=21)
        self.assertEqual(self.seen, [])

    def test_request_and_response_caps_leave_ambiguous_evidence(self):
        scope = self.scope("traversal", "/large", probe_value="../selected.txt",
                           expected="selected-file-contents")
        limited, warnings = probe_web_leads(scope, timeout=2, max_requests=2, rate=20)
        self.assertEqual(limited["requests_used"], 2)
        self.assertEqual(limited["status"], "partial")
        self.assertEqual(limited["classification"], "ambiguous")
        self.assertTrue(warnings)
        complete, warnings = probe_web_leads(scope, timeout=2, rate=20)
        self.assertEqual(complete["requests_used"], 4)
        self.assertEqual(complete["classification"], "ambiguous")
        self.assertTrue(complete["requests"][0]["response"]["truncated"])
        self.assertTrue(warnings)

    def test_public_cli_private_candidate_and_no_replay(self):
        request = self.request_file("/traversal?input=ordinary")
        result = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                          "--lead-kind", "traversal", "--parameter", "input",
                          "--probe-value", "../selected.txt", "--expected",
                          "selected-file-contents", "--budget", "3", "--rate", "20",
                          "--runs-root", self.root / "runs", code=3)
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        transcript = json.loads((run / "transcript.json").read_text())
        self.assertEqual(manifest["run_type"], "web_leads")
        self.assertEqual(manifest["coverage"]["WEB05"]["status"], "ran")
        self.assertEqual(manifest["candidate_count"], 1)
        self.assertFalse(manifest["challenge_accepted"])
        self.assertEqual(transcript["classification"], "candidate")
        self.assertEqual(transcript["requests_used"], 4)
        self.assertEqual((run / "request.http").read_bytes(), request.read_bytes())
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / "transcript.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("private-session", (run / "report.md").read_text())
        self.assertNotIn("selected-file-contents", (run / "report.md").read_text())
        before = len(self.seen)
        self.cli("resume", run, code=3)
        self.cli("report", run, code=0)
        self.assertEqual(len(self.seen), before)

    def test_public_cli_preserves_unselected_query_bytes(self):
        original = "/traversal?keep=a%20b&%69nput=%6frdinary&sig=Ab%2fC+%25"
        request = self.request_file(original)
        result = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                          "--lead-kind", "traversal", "--parameter", "input",
                          "--probe-value", "../selected.txt", "--expected",
                          "selected-file-contents", "--budget", "3", "--rate", "20",
                          "--runs-root", self.root / "runs", code=3)
        transcript = json.loads((Path(result["run"]) / "transcript.json").read_text())
        targets = [row["request"]["target"] for row in transcript["requests"]]
        self.assertEqual(targets[0], original)
        self.assertEqual(targets, self.seen)
        self.assertTrue(all(target.startswith("/traversal?keep=a%20b&%69nput=") and
                            target.endswith("&sig=Ab%2fC+%25") for target in targets))
        self.assertEqual(transcript["classification"], "candidate")

    def test_public_cli_rejects_duplicate_selected_parameter(self):
        request = self.request_file("/traversal?input=ordinary&%69nput=second")
        result = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                          "--lead-kind", "traversal", "--parameter", "input",
                          "--probe-value", "../selected.txt", "--expected",
                          "selected-file-contents", "--budget", "3", "--rate", "20",
                          "--runs-root", self.root / "runs", code=2)
        self.assertEqual(result["status"], "invalid_input")
        self.assertEqual(self.seen, [])

    def test_public_cli_missing_selection_and_wordlist_conflict_send_nothing(self):
        request = self.request_file("/template?input=ordinary")
        base = ("web", "--request-file", request, "--scope-origin", self.origin,
                "--runs-root", self.root / "runs")
        self.assertEqual(self.cli(*base, "--parameter", "input", code=2)["status"],
                         "invalid_input")
        self.assertEqual(self.cli(*base, "--lead-kind", "template", "--parameter", "input",
                                  code=2)["status"], "invalid_input")
        words = self.root / "words.txt"
        words.write_text("admin\n")
        self.assertEqual(self.cli(*base, "--wordlist", words, "--lead-kind", "template",
                                  "--parameter", "input", "--expected", "323",
                                  code=2)["status"], "invalid_input")
        self.assertEqual(self.cli(*base, "--lead-kind", "template", "--parameter", "input",
                                  "--expected", "323", "--kind", "vhost",
                                  code=2)["status"], "invalid_input")
        self.assertEqual(self.seen, [])

    def test_public_cli_template_syntax_has_only_candidate_status(self):
        request = self.request_file("/template?input=ordinary")
        result = self.cli("web", "--request-file", request, "--scope-origin", self.origin,
                          "--lead-kind", "template", "--parameter", "input",
                          "--expected", "323", "--syntax", "dollar",
                          "--budget", "3", "--rate", "20",
                          "--runs-root", self.root / "runs", code=3)
        run = Path(result["run"])
        manifest = json.loads((run / "manifest.json").read_text())
        transcript = json.loads((run / "transcript.json").read_text())
        self.assertEqual(manifest["candidate_count"], 1)
        self.assertEqual(manifest["status"], "partial")
        self.assertFalse(manifest["challenge_accepted"])
        self.assertEqual(transcript["requests"][3]["value"], "${17*19}")

    def test_doctor_web_lead_probe_uses_loopback_only(self):
        result = capabilities.doctor(["web"], self_test=True)
        self.assertEqual(result["operations"]["web.selected_leads"]["functional_probe"],
                         "passed")


if __name__ == "__main__":
    unittest.main()
