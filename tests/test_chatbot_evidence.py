"""Decoding and audit differentials remain candidates until app state confirms them."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/chatbot_evidence.py'


class EvidenceTests(unittest.TestCase):
    def command(self, root, *args, code=0):
        process = subprocess.run([sys.executable, '-B', str(SCRIPT), '--runs-root', str(Path(root) / 'runs'),
                                  *map(str, args)], capture_output=True, text=True, timeout=5)
        self.assertEqual(process.returncode, code, process.stderr + process.stdout)
        return json.loads(process.stdout)

    def test_decodes_codepoints_characters_and_nato_without_validation_claim(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'answer.txt'
            for value, mode, expected in [('[65, 66]', 'codepoints', 'AB'),
                                          ('["A", "B"]', 'characters', 'AB'),
                                          ('Alfa Bravo', 'nato', 'AB')]:
                source.write_text(value)
                result = self.command(root, 'decode', '--input', source, '--mode', mode)
                report = json.loads(Path(result['report']).read_text())
                self.assertEqual(report['state'], 'candidate')
                self.assertEqual(Path(result['candidate_file']).read_text(), expected)
                self.assertNotIn(expected, json.dumps(result))
            source.write_text('[55296]')
            self.assertEqual(self.command(root, 'decode', '--input', source, '--mode', 'codepoints', code=2)['status'], 'invalid_input')
            source.write_text(json.dumps([65 / 255, 66 / 255, 67 / 255, 0]))
            result = self.command(root, 'decode', '--input', source, '--mode', 'embedding-bytes')
            self.assertEqual(Path(result['candidate_file']).read_text(), 'ABC')
            source.write_text('[1.2]')
            self.assertEqual(self.command(root, 'decode', '--input', source, '--mode', 'embedding-bytes', code=2)['status'], 'invalid_input')

    def test_rejects_nonobject_transcript_line_without_traceback(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'bad.txt'
            source.write_text('[]\n')
            result = self.command(root, 'audit', '--input', source, '--line', '1', code=2)
            self.assertEqual(result['status'], 'invalid_input')

    def test_audit_reports_changed_fields_without_values(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            source.write_text(json.dumps({'response': {'tool_calls': [{'args_raw': {'mode': ['safe', 'override']},
                                                                       'args_validated': {'mode': 'safe'},
                                                                       'args_normalized': {'mode': 'override'},
                                                                       'args_applied': {'mode': 'override'}}]}}) + '\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in report['comparisons']], [False, False, True])
            self.assertEqual(report['comparisons'][0]['changed_paths'], ['mode'])
            self.assertNotIn('override', Path(result['report']).read_text())


if __name__ == '__main__':
    unittest.main()
