"""Loopback-only checks for explicitly supplied WEB08 workflows."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from scripts.autosolve_lib import setup as capabilities
from scripts.autosolve_lib.profiles.web_workflows import replay_workflows


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class Handler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.__class__.requests.append((self.path, self.headers.get('Cookie', '')))
        role = self.headers.get('X-Role', '')
        if self.path in ('/header-order', '/header-duplicate'):
            self.send_response_only(200)
            if role == 'owner':
                fields = [('X-A', 'one'), ('X-B', 'two'),
                          ('X-Dup', 'first'), ('X-Dup', 'second')]
            else:
                fields = [('x-b', 'two'), ('x-a', 'one'),
                          ('x-dup', 'first'), ('X-DUP', 'second')]
                if self.path == '/header-duplicate':
                    fields.pop()
            for name, value in fields:
                self.send_header(name, value)
            self.send_header('Content-Length', '4')
            self.end_headers()
            self.wfile.write(b'same')
            return
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:1/elsewhere')
            self.end_headers()
            return
        if self.path == '/big-header':
            self.send_response(200)
            self.send_header('X-State', 'a' * 17000)
            self.end_headers()
            self.wfile.write(b'x')
            return
        if self.path == '/unstable':
            body = str(len(self.__class__.requests)).encode()
            status = 200
        elif self.path.startswith('/object/'):
            object_id = self.path.removeprefix('/object/')
            status = 200 if role == 'owner' or self.headers.get('X-Unsafe') == 'yes' else 403
            body = (role + ':' + object_id).encode() if status == 200 else b'denied'
        else:
            status, body = 404, b'missing'
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.__class__.requests.append((self.path, self.headers.get('Cookie', '')))
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/issue':
            status, body = 200, b'issued'
            self.send_response(status)
            self.send_header('Set-Cookie', 'token=one; Path=/')
        elif self.path == '/use':
            status = 200 if 'token=one' in self.headers.get('Cookie', '') else 403
            body = b'used' if status == 200 else b'denied'
            self.send_response(status)
            if status == 200:
                self.send_header('Set-Cookie', 'token=gone; Path=/')
        else:
            status, body = 404, b'missing'
            self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def step(step_id, path, role, **fields):
    return {'id': step_id, 'method': 'GET', 'path': path,
            'headers': {'X-Role': role}, 'safe_to_replay': True, **fields}


def fixture(left, right, relation='different_status', baselines=None):
    invariant = {'left': {'role': left['role'], 'step': left['steps'][-1]['id']},
                 'right': {'role': right['role'], 'step': right['steps'][-1]['id']},
                 'relation': relation}
    if baselines is not None:
        invariant['baselines'] = baselines
    return {'expected_invariant': invariant, 'workflows': [left, right]}


class WebWorkflowTests(unittest.TestCase):
    def setUp(self):
        Handler.requests = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_fixture(self, data):
        return replay_workflows(data, origin=self.origin, timeout=3)

    def cli(self, *args, code):
        completed = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                    *map(str, args)], capture_output=True, text=True,
                                   timeout=15)
        self.assertEqual(completed.returncode, code, completed.stderr + completed.stdout)
        return json.loads(completed.stdout)

    def test_access_difference_and_exact_responses(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/object/42', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/object/42', 'guest')]})
        result, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertEqual(result['assessment'], 'invariant held')
        self.assertEqual([row['status'] for row in result['responses']], [200, 403])
        self.assertEqual(base64.b64decode(result['responses'][0]['body_b64']), b'owner:42')
        self.assertEqual(base64.b64decode(result['responses'][1]['body_b64']), b'denied')
        self.assertEqual(Handler.requests, [('/object/42', ''), ('/object/42', '')])

    def test_changed_id_and_role_expose_only_observed_deviation(self):
        data = fixture({'role': 'holder', 'steps': [step('read', '/object/97', 'owner')]},
                       {'role': 'stranger', 'steps': [step('read', '/object/97', 'guest',
                                                          headers={'X-Role': 'guest', 'X-Unsafe': 'yes'})]})
        result, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertEqual(result['assessment'], 'observed deviation')
        self.assertFalse(result['invariant_holds'])
        self.assertEqual([row['status'] for row in result['responses']], [200, 200])
        self.assertNotIn('bypass', str(result).lower())

    def test_one_use_token_keeps_cookie_state_and_declared_order(self):
        data = fixture({'role': 'holder', 'steps': [
                           {'id': 'issue', 'method': 'POST', 'path': '/issue', 'safe_to_replay': True},
                           {'id': 'consume', 'method': 'POST', 'path': '/use', 'safe_to_replay': True},
                           {'id': 'again', 'method': 'POST', 'path': '/use', 'safe_to_replay': True}]},
                       {'role': 'observer', 'steps': [step('read', '/object/other', 'guest')]},
                       relation='different_status')
        data['expected_invariant']['left']['step'] = 'consume'
        data['expected_invariant']['right'] = {'role': 'holder', 'step': 'again'}
        result, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertEqual([row['status'] for row in result['responses'][:3]], [200, 200, 403])
        self.assertEqual(result['assessment'], 'invariant held')
        self.assertNotEqual(result['responses'][0]['cookie_state_after_sha256'],
                            result['responses'][1]['cookie_state_after_sha256'])
        self.assertEqual([path for path, _ in Handler.requests],
                         ['/issue', '/use', '/use', '/object/other'])

    def test_unstable_baseline_is_inconclusive(self):
        data = fixture({'role': 'owner', 'steps': [step('first', '/unstable', 'owner'),
                                                 step('second', '/unstable', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/object/42', 'guest')]},
                       baselines=[{'left': {'role': 'owner', 'step': 'first'},
                                   'right': {'role': 'owner', 'step': 'second'},
                                   'relation': 'same_body'}])
        result, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertEqual(result['assessment'], 'inconclusive: unstable baseline')
        self.assertFalse(result['baselines'][0]['holds'])

    def test_rejects_undeclared_mutation_or_bad_scope_before_any_request(self):
        good = {'role': 'owner', 'steps': [step('read', '/object/1', 'owner')]}
        for bad_step in [
            {'id': 'write', 'method': 'POST', 'path': '/issue'},
            {'id': 'read', 'method': 'GET', 'path': '/object/1'},
            step('cross', '//other.test/object/1', 'owner'),
            step('absolute', 'http://127.0.0.1:1/elsewhere', 'owner'),
            step('host', '/object/1', 'owner', headers={'Host': 'other.test'}),
        ]:
            with self.subTest(bad_step=bad_step), self.assertRaises(ValueError):
                self.run_fixture(fixture(good, {'role': 'guest', 'steps': [bad_step]}))
        self.assertEqual(Handler.requests, [])

    def test_redirect_is_recorded_without_following(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/redirect', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/object/1', 'guest')]})
        result, warnings = self.run_fixture(data)
        self.assertEqual(result['responses'][0]['status'], 302)
        self.assertEqual(dict(result['responses'][0]['headers'])['Location'],
                         'http://127.0.0.1:1/elsewhere')
        self.assertEqual([path for path, _ in Handler.requests], ['/redirect', '/object/1'])
        self.assertEqual(warnings, [])

    def test_request_and_response_caps(self):
        good = {'role': 'owner', 'steps': [step('read', '/object/1', 'owner')]}
        with self.assertRaises(ValueError):
            replay_workflows(fixture(good, {'role': 'guest', 'steps': [step('read', '/object/1', 'guest')]}),
                             origin=self.origin, max_requests=1)
        with self.assertRaises(ValueError):
            replay_workflows(fixture(good, {'role': 'guest', 'steps': [step('read', '/object/1', 'guest')]}),
                             origin=self.origin, rate=6)
        self.assertEqual(Handler.requests, [])
        data = fixture(good, {'role': 'guest', 'steps': [step('read', '/object/1', 'guest')]},
                       relation='different_body')
        result, warnings = replay_workflows(data, origin=self.origin, max_response_bytes=3, timeout=3)
        self.assertEqual(result['assessment'], 'inconclusive: truncated response')
        self.assertTrue(any('response byte limit' in item for item in warnings))

    def test_oversize_headers_make_full_response_comparison_inconclusive(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/big-header', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/big-header', 'guest')]},
                       relation='same_response')
        result, warnings = self.run_fixture(data)
        self.assertEqual(result['assessment'], 'inconclusive: truncated response')
        self.assertTrue(any('header byte limit' in item for item in warnings))

    def test_response_header_order_and_case_do_not_change_full_comparison(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/header-order', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/header-order', 'guest')]},
                       relation='same_response')
        result, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertNotEqual(result['responses'][0]['headers'], result['responses'][1]['headers'])
        self.assertEqual(result['assessment'], 'invariant held')

        data['workflows'][0]['steps'][0]['path'] = '/header-duplicate'
        data['workflows'][1]['steps'][0]['path'] = '/header-duplicate'
        different, warnings = self.run_fixture(data)
        self.assertEqual(warnings, [])
        self.assertEqual(different['assessment'], 'observed deviation')

    def test_public_cli_header_order_regression_preserves_private_rows(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/header-order', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/header-order', 'guest')]},
                       relation='same_response')
        source = self.root / 'header-workflow.json'
        source.write_text(json.dumps(data))
        result = self.cli('web', '--scope-origin', self.origin, '--workflow-file', source,
                          '--workflow-test', '--budget', '3', '--runs-root', self.root / 'runs',
                          code=3)
        run = Path(result['run'])
        transcript = json.loads((run / 'transcript.json').read_text())
        self.assertEqual(transcript['assessment'], 'invariant held')
        self.assertNotEqual(transcript['responses'][0]['headers'],
                            transcript['responses'][1]['headers'])
        self.assertEqual(json.loads((run / 'manifest.json').read_text())['assessment'],
                         'invariant held')

    def test_public_cli_private_evidence_and_no_replay(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/object/72', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '/object/72', 'guest')]})
        data['workflows'][0]['steps'][0]['headers']['Cookie'] = 'session=private-owner'
        source = self.root / 'fixture.json'
        source.write_text(json.dumps(data))
        result = self.cli('web', '--scope-origin', self.origin, '--workflow-file', source,
                          '--workflow-test', '--budget', '3', '--runs-root', self.root / 'runs',
                          code=3)
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        transcript = json.loads((run / 'transcript.json').read_text())
        self.assertEqual(manifest['run_type'], 'web_workflow')
        self.assertEqual(manifest['coverage']['WEB08']['status'], 'ran')
        self.assertEqual(manifest['assessment'], 'invariant held')
        self.assertFalse(manifest['challenge_accepted'])
        self.assertEqual(transcript['assessment'], 'invariant held')
        self.assertEqual([row['status'] for row in transcript['responses']], [200, 403])
        self.assertEqual((run / 'fixture.json').read_text(), source.read_text())
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((run / 'fixture.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual((run / 'transcript.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('session=private-owner', (run / 'report.md').read_text())
        self.assertNotIn('owner:72', (run / 'report.md').read_text())
        self.assertNotIn('private-owner', (run / 'manifest.json').read_text())
        self.assertNotIn('private-owner', json.dumps(result))
        self.assertEqual(len(Handler.requests), 2)
        self.cli('resume', run, code=3)
        self.cli('report', run, code=0)
        self.assertEqual(len(Handler.requests), 2)

    def test_public_cli_requires_explicit_opt_in_and_preflights_all_steps(self):
        data = fixture({'role': 'owner', 'steps': [step('read', '/object/72', 'owner')]},
                       {'role': 'guest', 'steps': [step('read', '//outside.test/x', 'guest')]})
        source = self.root / 'fixture.json'
        source.write_text(json.dumps(data))
        base = ('web', '--scope-origin', self.origin, '--workflow-file', source,
                '--runs-root', self.root / 'runs')
        self.assertEqual(self.cli(*base, code=2)['status'], 'invalid_input')
        self.assertEqual(self.cli(*base, '--workflow-test', code=2)['status'], 'invalid_input')
        raw_request = self.root / 'request.http'
        raw_request.write_text('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        self.assertEqual(self.cli(*base, '--workflow-test', '--request-file', raw_request,
                                  code=2)['status'], 'invalid_input')
        self.assertEqual(Handler.requests, [])

    def test_doctor_checks_web08_with_loopback_fixture(self):
        result = capabilities.doctor(['web'], self_test=True)
        self.assertEqual(result['operations']['web.workflow_comparison'],
                         {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'})


if __name__ == '__main__':
    unittest.main()
