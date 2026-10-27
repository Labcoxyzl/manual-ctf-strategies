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

    def test_score_controls_rank_observations_without_membership_claim(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'manifest.json'
            rows = [{'id': f'score_{index}', 'status': 200, 'redirect_hops': 0, 'score': value}
                    for index, value in enumerate((.9, .8, .1, .2, .7, .3), 1)]
            source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                          'api_checks': rows}))
            args = ('score-controls', '--input', source, '--positive', '1,2', '--negative', '3,4',
                    '--candidates', '5,6', '--direction', 'higher')
            result = self.command(root, *args)
            report = json.loads(Path(result['report']).read_text())
            self.assertTrue(report['observed_strict_separation'])
            self.assertFalse(report['membership_validated'])
            self.assertEqual(report['control_probe_ids']['positive'], ['score_1', 'score_2'])
            self.assertEqual([row['probe_id'] for row in report['ranked_candidates']], ['score_5', 'score_6'])
            self.assertNotIn('candidate input', Path(result['report']).read_text())
            lower = self.command(root, *args[:-1], 'lower')
            lower_report = json.loads(Path(lower['report']).read_text())
            self.assertEqual([row['probe_id'] for row in lower_report['ranked_candidates']], ['score_6', 'score_5'])
            self.assertFalse(lower_report['observed_strict_separation'])
            self.assertEqual(self.command(root, 'score-controls', '--input', source, '--positive', '1,2',
                                          '--negative', '2,3', '--candidates', '5', '--direction', 'higher',
                                          code=2)['status'], 'invalid_input')
            rows[4]['redirect_hops'] = 1
            source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                          'api_checks': rows}))
            self.assertIn('score_5', self.command(root, *args, code=2)['reason'])
            rows[4].pop('redirect_hops')
            source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                          'api_checks': rows}))
            self.assertIn('score_5', self.command(root, *args, code=2)['reason'])
            large = 10 ** 100
            for row, value in zip(rows, (large + 2, large + 4, large - 4, large - 2, large + 1, large - 1)):
                row['score'] = value
                row['redirect_hops'] = 0
            source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                          'api_checks': rows}))
            exact = self.command(root, *args)
            exact_report = json.loads(Path(exact['report']).read_text())
            self.assertTrue(exact_report['observed_strict_separation'])
            self.assertEqual(exact_report['median_gap'], '6')


if __name__ == '__main__':
    unittest.main()
