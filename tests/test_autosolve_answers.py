"""Sourced, schema-controlled answers for no-flag forensic cases."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.autosolve_lib.profiles.answers import collect_answers, validate_schema


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class AnswerSchemaTests(unittest.TestCase):
    SCHEMA = {'fields': [{'name': 'operator', 'question': 'Who calibrated it?'},
                         {'name': 'badge_number', 'question': 'What badge was used?'}],
              'compose': '{operator}|{badge_number}'}

    def artifact(self, path):
        return {'id': path.name, 'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'size': path.stat().st_size, 'depth': 0, 'complete': True, 'current': True}

    def test_schema_rejects_format_expressions_and_unknown_fields(self):
        for template in ('{operator.__class__}', '{operator!r}', '{operator:>10}',
                         '{missing}', '{operator}{', '{operator[0]}'):
            with self.subTest(template=template), self.assertRaises(ValueError):
                validate_schema({**self.SCHEMA, 'compose': template})
        with self.assertRaises(ValueError):
            validate_schema({'fields': [{'name': 'operator', 'question': 'One'},
                                                {'name': 'operator', 'question': 'Two'}]})

    def test_missing_answer_stays_unresolved_with_source_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'events.jsonl'
            source.write_text('{"event":"calibration","operator":"Mara Chen"}\n')
            result, warnings = collect_answers([self.artifact(source)], self.SCHEMA,
                                               time.monotonic() + 5)
            self.assertEqual(warnings, [])
            self.assertEqual(result['fields'][0]['status'], 'answered')
            self.assertEqual(result['fields'][0]['value'], 'Mara Chen')
            self.assertEqual(result['fields'][0]['sources'][0]['source_locator'],
                             {'line': 1, 'byte_offset': 0, 'json_key': 'operator'})
            self.assertEqual(result['fields'][1]['status'], 'unresolved')
            self.assertEqual(result['composition']['status'], 'unresolved')
            self.assertNotIn('value', result['composition'])

    def test_all_fields_compose_without_interpreting_template(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'events.jsonl'
            source.write_text('{"operator":"Mara Chen","badge_number":69}\n')
            result, warnings = collect_answers([self.artifact(source)], self.SCHEMA,
                                               time.monotonic() + 5)
            self.assertEqual(warnings, [])
            self.assertEqual(result['composition'],
                             {'status': 'ready', 'value': 'Mara Chen|69',
                              'source_fields': ['operator', 'badge_number']})

    def test_conflicting_values_and_changed_bytes_withhold_composition(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'events.jsonl'
            source.write_text('{"operator":"Mara","badge_number":69}\n'
                              '{"operator":"Kai","badge_number":69}\n')
            artifact = self.artifact(source)
            result, _ = collect_answers([artifact], self.SCHEMA, time.monotonic() + 5)
            self.assertEqual(result['fields'][0]['status'], 'conflict')
            self.assertEqual(result['composition']['status'], 'unresolved')
            source.write_text('{"operator":"Mara","badge_number":69}\n')
            result, warnings = collect_answers([artifact], self.SCHEMA, time.monotonic() + 5)
            self.assertTrue(any('changed' in warning for warning in warnings))
            self.assertEqual(result['composition']['status'], 'unresolved')

    def test_invalid_jsonl_and_large_source_are_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'events.jsonl'
            source.write_text('{"operator":"Mara","badge_number":69}\nnot json\n')
            result, warnings = collect_answers([self.artifact(source)], self.SCHEMA,
                                               time.monotonic() + 5)
            self.assertTrue(any('invalid JSONL' in warning for warning in warnings))
            self.assertEqual(result['composition']['status'], 'unresolved')
            source.write_bytes(b'x' * (8 * 1024 * 1024 + 1))
            result, warnings = collect_answers([self.artifact(source)], self.SCHEMA,
                                               time.monotonic() + 5)
            self.assertTrue(any('limit' in warning for warning in warnings))
            self.assertEqual(result['composition']['status'], 'unresolved')

    def test_public_cli_resume_replaces_stale_answer_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input' / 'events.jsonl'
            source.parent.mkdir()
            source.write_text('{"operator":"Mara Chen"}\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'answer_schema': self.SCHEMA}))

            def cli(*args):
                result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                         *map(str, args)], capture_output=True, timeout=60)
                self.assertIn(result.returncode, (0, 3), result.stderr + result.stdout)
                return json.loads(result.stdout)

            first = cli('analyze', source.parent, '--category', 'encoding', '--budget', 15,
                        '--hints', hints,
                        '--runs-root', root / 'runs')
            run = Path(first['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            old_id = manifest['answers']['fields'][0]['sources'][0]['artifact_id']
            self.assertEqual(manifest['answers']['composition']['status'], 'unresolved')
            self.assertIn('badge_number', (run / 'report.md').read_text())
            self.assertFalse(any(finding['state'] == 'challenge_accepted'
                                 for finding in manifest['findings']))

            source.write_text('{"operator":"Mara Chen","badge_number":69}\n')
            cli('resume', run, '--budget', 15, '--hints', hints)
            refreshed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(refreshed['answers']['composition']['value'], 'Mara Chen|69')
            self.assertNotEqual(refreshed['answers']['fields'][0]['sources'][0]['artifact_id'], old_id)
            self.assertFalse(any(finding['state'] == 'challenge_accepted'
                                 for finding in refreshed['findings']))


if __name__ == '__main__':
    unittest.main()
