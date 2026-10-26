"""The callback receiver remains private, scoped, and finite."""

import json
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/chatbot_callback.py'


class CallbackTests(unittest.TestCase):
    def test_one_request_then_exit_with_private_exact_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--runs-root', root,
                                        '--port', '0', '--max-requests', '1', '--duration', '5'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready = json.loads(process.stdout.readline())
                self.assertEqual(ready['status'], 'listening')
                request = urllib.request.Request(ready['origin'] + '/probe', headers={'X-Probe-Key': 'private-test'})
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 204)
                out, err = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, err + out)
                self.assertNotIn('private-test', out)
                trace = Path(json.loads(out)['transcript'])
                self.assertEqual(trace.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(trace.read_text())['headers']['X-Probe-Key'], 'private-test')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_public_bind_needs_explicit_flag(self):
        process = subprocess.run([sys.executable, '-B', str(SCRIPT), '--bind', '0.0.0.0'],
                                 capture_output=True, text=True, timeout=3)
        self.assertEqual(process.returncode, 2)
        self.assertIn('allow-public-bind', process.stderr)


if __name__ == '__main__':
    unittest.main()
