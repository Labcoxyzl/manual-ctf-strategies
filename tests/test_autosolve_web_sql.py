"""WEB03 bounded checks against a disposable SQLite web app."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from scripts.autosolve_lib.profiles.web_sql import assess_sql
from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class WebSqlTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request()

            def do_POST(self):
                self.handle_request()

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                seen.append((self.command, self.path, body, self.headers.get('Cookie')))
                path = urlsplit(self.path)
                values = parse_qs(path.query if self.command == 'GET' else body.decode(),
                                  keep_blank_values=True)
                value = values.get('id', values.get('code', ['']))[0]
                if path.path == '/throttle':
                    status, payload = 429, b'slow down'
                elif path.path == '/unstable':
                    status, payload = 200, str(len(seen)).encode()
                elif path.path == '/transient' and len(seen) == 1:
                    status, payload = 500, b'temporary failure'
                elif path.path in ('/safe', '/vulnerable', '/form', '/numeric', '/transient'):
                    database = sqlite3.connect(':memory:')
                    database.execute('CREATE TABLE users (id TEXT, name TEXT)')
                    database.execute("INSERT INTO users VALUES ('1', 'alice')")
                    database.execute('CREATE TABLE secrets (value TEXT)')
                    database.execute("INSERT INTO secrets VALUES ('key_42')")
                    try:
                        if path.path == '/safe':
                            rows = database.execute('SELECT name FROM users WHERE id = ?',
                                                    (value,)).fetchall()
                        elif path.path == '/numeric':
                            rows = database.execute(
                                'SELECT name FROM users WHERE id = ' + value).fetchall()
                        else:
                            rows = database.execute(
                                "SELECT name FROM users WHERE id = '" + value + "'").fetchall()
                        status, payload = 200, b'alice' if rows else b'no match'
                    except sqlite3.Error:
                        status, payload = 500, b'query error'
                    finally:
                        database.close()
                else:
                    status, payload = 404, b'no route'
                self.send_response(status)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Site)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args, code):
        completed = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                    *map(str, args)], capture_output=True, text=True,
                                   timeout=15)
        self.assertEqual(completed.returncode, code, completed.stderr + completed.stdout)
        return json.loads(completed.stdout)

    def raw_get(self, path):
        return f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\nCookie: session=local\r\n\r\n'.encode()

    def test_vulnerable_get_and_selected_candidate_have_repeated_evidence(self):
        raw = self.raw_get('/vulnerable?id=1&keep=a%2Bb')
        report, warnings = assess_sql(raw, self.origin, 'id', authorized=True,
                                      test_mode=True, table='secrets', column='value',
                                      candidates=['wrong', 'key_42'], timeout=3,
                                      max_requests=10, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report['classification'], 'differential_candidate')
        self.assertEqual(report['selected_value'], 'key_42')
        self.assertEqual(report['requests_used'], 10)
        self.assertEqual(len(self.seen), 10)
        self.assertTrue(all('keep=a%2Bb' in path for _, path, _, _ in self.seen))
        self.assertTrue(all(cookie == 'session=local' for _, _, _, cookie in self.seen))
        self.assertEqual(report['probes'][0]['request']['target'], '/vulnerable?id=1&keep=a%2Bb')
        self.assertEqual(report['probes'][0]['response']['body_b64'], 'YWxpY2U=')
        self.assertEqual([row['role'] for row in report['probes'][:6]],
                         ['baseline', 'true', 'false', 'baseline', 'true', 'false'])

    def test_safe_query_and_dynamic_or_throttled_responses_are_not_positive(self):
        safe, _ = assess_sql(self.raw_get('/safe?id=1'), self.origin, 'id',
                             authorized=True, test_mode=True, timeout=3, rate=20)
        self.assertEqual(safe['classification'], 'not_detected')
        unstable, _ = assess_sql(self.raw_get('/unstable?id=1'), self.origin, 'id',
                                 authorized=True, test_mode=True, timeout=3, rate=20)
        self.assertEqual(unstable['classification'], 'inconclusive')
        throttle, _ = assess_sql(self.raw_get('/throttle?id=1'), self.origin, 'id',
                                 authorized=True, test_mode=True, timeout=3, rate=20)
        self.assertEqual(throttle['classification'], 'inconclusive')
        self.seen.clear()
        transient, _ = assess_sql(self.raw_get('/transient?id=1'), self.origin, 'id',
                                  authorized=True, test_mode=True, timeout=3, rate=20)
        self.assertEqual(transient['classification'], 'inconclusive')

    def test_numeric_context_and_different_parameter(self):
        report, warnings = assess_sql(self.raw_get('/numeric?code=%31'), self.origin,
                                      'code', authorized=True, test_mode=True,
                                      context='number', timeout=3, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report['classification'], 'differential_candidate')
        self.assertEqual(report['requests_used'], 6)
        self.assertEqual(report['probes'][0]['request']['target'], '/numeric?code=%31')

    def test_form_post_preserves_method_body_and_session(self):
        body = b'id=1&keep=a%2Bb'
        raw = (f'POST /form HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n'
               f'Content-Type: application/x-www-form-urlencoded\r\n'
               f'Cookie: session=local\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body
        report, warnings = assess_sql(raw, self.origin, 'id', location='form',
                                      authorized=True, test_mode=True, timeout=3, rate=20)
        self.assertEqual(warnings, [])
        self.assertEqual(report['classification'], 'differential_candidate')
        self.assertTrue(all(method == 'POST' and path == '/form' and b'keep=a%2Bb' in sent
                            for method, path, sent, _ in self.seen))
        self.assertEqual(report['probes'][0]['request']['body_b64'], 'aWQ9MSZrZWVwPWElMkJi')

    def test_opt_in_scope_and_budget_fail_before_network(self):
        raw = self.raw_get('/vulnerable?id=1')
        for kwargs in ({}, {'authorized': True}, {'test_mode': True},
                       {'authorized': True, 'test_mode': True, 'max_requests': 5},
                       {'authorized': True, 'test_mode': True, 'rate': 100},
                       {'authorized': True, 'test_mode': True, 'table': 'secrets;DROP',
                        'column': 'value', 'candidates': ['x']}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                assess_sql(raw, self.origin, 'id', **kwargs)
        with self.assertRaises(ValueError):
            assess_sql(raw.replace(str(self.server.server_port).encode(), b'1'),
                       self.origin, 'id', authorized=True, test_mode=True)
        self.assertEqual(self.seen, [])

    def test_budget_stops_without_classifying_a_partial_probe(self):
        report, warnings = assess_sql(self.raw_get('/vulnerable?id=1'), self.origin,
                                      'id', authorized=True, test_mode=True,
                                      max_requests=6, timeout=.01, rate=20)
        self.assertEqual(report['classification'], 'inconclusive')
        self.assertLessEqual(report['requests_used'], 6)
        self.assertTrue(warnings)

    def test_public_cli_private_run_selected_recovery_and_no_replay(self):
        request = self.root / 'request.http'
        raw = self.raw_get('/vulnerable?id=1&keep=a%2Bb')
        request.write_bytes(raw)
        result = self.cli('web', '--request-file', request, '--scope-origin', self.origin,
                          '--sql-parameter', 'id', '--sql-test', '--sql-table', 'secrets',
                          '--sql-column', 'value', '--sql-candidate', 'wrong',
                          '--sql-candidate', 'key_42', '--budget', '3', '--rate', '20',
                          '--runs-root', self.root / 'runs', code=3)
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        transcript = json.loads((run / 'transcript.json').read_text())
        self.assertEqual(manifest['run_type'], 'web_sql')
        self.assertEqual(manifest['coverage']['WEB03']['status'], 'ran')
        self.assertFalse(manifest['challenge_accepted'])
        self.assertEqual(transcript['classification'], 'differential_candidate')
        self.assertEqual(transcript['selected_value'], 'key_42')
        self.assertEqual((run / 'request.http').read_bytes(), raw)
        self.assertEqual(len(self.seen), 10)
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / 'transcript.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('key_42', (run / 'report.md').read_text())
        self.assertNotIn('session=local', (run / 'report.md').read_text())
        self.cli('resume', run, code=3)
        self.cli('report', run, code=0)
        self.assertEqual(len(self.seen), 10)

    def test_public_cli_requires_opt_in_and_selected_scope(self):
        request = self.root / 'request.http'
        request.write_bytes(self.raw_get('/vulnerable?id=1'))
        base = ('web', '--request-file', request, '--scope-origin', self.origin,
                '--sql-parameter', 'id', '--runs-root', self.root / 'runs')
        self.assertEqual(self.cli(*base, code=2)['status'], 'invalid_input')
        self.assertEqual(self.cli(*base, '--sql-test', '--wordlist', request,
                                  code=2)['status'], 'invalid_input')
        request.write_bytes(self.raw_get('/vulnerable?id=1').replace(
            str(self.server.server_port).encode(), b'1'))
        self.assertEqual(self.cli(*base, '--sql-test', code=2)['status'], 'invalid_input')
        self.assertEqual(self.seen, [])

    def test_public_cli_form_post(self):
        body = b'id=1&keep=original'
        request = self.root / 'form.http'
        request.write_bytes((
            f'POST /form HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
        result = self.cli('web', '--request-file', request, '--scope-origin', self.origin,
                          '--sql-parameter', 'id', '--sql-test', '--sql-location', 'form',
                          '--budget', '3', '--rate', '20', '--runs-root', self.root / 'runs',
                          code=3)
        transcript = json.loads((Path(result['run']) / 'transcript.json').read_text())
        self.assertEqual(transcript['classification'], 'differential_candidate')
        self.assertEqual(transcript['requests_used'], 6)
        self.assertTrue(all(method == 'POST' and path == '/form' and
                            b'keep=original' in sent for method, path, sent, _ in self.seen))

    def test_doctor_checks_web03_locally(self):
        result = capabilities.doctor(['web'], self_test=True)
        self.assertEqual(result['operations']['web.sql_assessment'],
                         {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'})


if __name__ == '__main__':
    unittest.main()
