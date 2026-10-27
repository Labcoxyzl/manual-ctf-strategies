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

    def test_overdeep_local_reply_is_invalid_input_without_traceback(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'deep.txt'
            source.write_text('[' * 10_000 + '65' + ']' * 10_000)
            result = self.command(root, 'decode', '--input', source, '--mode', 'codepoints', code=2)
            self.assertEqual(result['status'], 'invalid_input')
            self.assertNotIn('candidate_file', result)

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

    def test_audit_detects_boolean_to_integer_tool_argument_coercion(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            source.write_text(json.dumps({'response': {'tool_calls': [{
                'args_raw': {'enabled': True, 'mode': 'safe'},
                'args_validated': {'enabled': 1, 'mode': 'safe'},
                'args_normalized': {'enabled': 1, 'mode': 'safe'},
                'args_applied': {'enabled': 1, 'mode': 'safe'}}]}}) + '\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in report['comparisons']], [False, True, True])
            self.assertEqual(report['comparisons'][0]['changed_paths'], ['enabled'])
            self.assertNotIn('enabled', json.dumps(report['stages']))

    def test_audit_marks_changed_path_cap_without_claiming_complete_diff(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            raw = {f'field_{index:03}': 0 for index in range(101)}
            changed = {key: 1 for key in raw}
            source.write_text(json.dumps({'response': {'tool_calls': [{
                'args_raw': raw, 'args_validated': changed,
                'args_normalized': changed, 'args_applied': changed}]}}) + '\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args)
            report = json.loads(Path(result['report']).read_text())
            first = report['comparisons'][0]
            self.assertFalse(first['equal'])
            self.assertEqual(len(first['changed_paths']), 100)
            self.assertTrue(first['changed_paths_truncated'])
            self.assertEqual(first['changed_paths'][0], 'field_000')
            self.assertEqual(first['changed_paths'][-1], 'field_099')

    def test_audit_keeps_high_precision_numeric_argument_difference(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            source.write_text('{"response":{"tool_calls":[{'
                              '"args_raw":{"threshold":1.0000000000000001},'
                              '"args_validated":{"threshold":1.0},'
                              '"args_normalized":{"threshold":1.0},'
                              '"args_applied":{"threshold":1.0}}]}}\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in report['comparisons']], [False, True, True])
            self.assertEqual(report['comparisons'][0]['changed_paths'], ['threshold'])
            self.assertNotEqual(report['stages']['raw']['sha256'], report['stages']['validated']['sha256'])

    def test_audit_rejects_duplicate_json_keys_before_comparing_stages(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            source.write_text('{"response":{"tool_calls":[{'
                              '"args_raw":{"role":"user","role":"admin"},'
                              '"args_validated":{"role":"admin"},'
                              '"args_normalized":{"role":"admin"},'
                              '"args_applied":{"role":"admin"}}]}}\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args, code=2)
            self.assertIn('duplicate audit JSON key', result['reason'])
            self.assertNotIn('report', result)

    def test_audit_rejects_extreme_numeric_exponent_without_traceback(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'trace.jsonl'
            source.write_text('{"response":{"tool_calls":[{'
                              '"args_raw":{"threshold":1e99999999999999999999},'
                              '"args_validated":{"threshold":1.0},'
                              '"args_normalized":{"threshold":1.0},'
                              '"args_applied":{"threshold":1.0}}]}}\n')
            args = ['audit', '--input', source, '--line', '1']
            for name in ('raw', 'validated', 'normalized', 'applied'):
                args += [f'--{name}-field', f'tool_calls.0.args_{name}']
            result = self.command(root, *args, code=2)
            self.assertIn('numeric literal is invalid', result['reason'])

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
            self.assertFalse(exact_report['medians_rounded'])
            for bad_score in ('NaN', '1e9999999', '1e99999999999999999999', '9' * 513):
                rows[4]['score'] = bad_score
                source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                              'api_checks': rows}))
                self.assertIn('score_5', self.command(root, *args, code=2)['reason'])
            for row, value in zip(rows, ('1e150', '1e-400', '0', '0', '1e-400', '0')):
                row['score'] = value
            source.write_text(json.dumps({'category': 'ai_chatbot', 'strategy': 'scorer_batch',
                                          'api_checks': rows}))
            rounded = self.command(root, *args)
            rounded_report = json.loads(Path(rounded['report']).read_text())
            self.assertTrue(rounded_report['medians_rounded'])
            self.assertEqual(rounded_report['median_precision_digits'], 512)
            self.assertTrue(rounded_report['observed_strict_separation'])


if __name__ == '__main__':
    unittest.main()
