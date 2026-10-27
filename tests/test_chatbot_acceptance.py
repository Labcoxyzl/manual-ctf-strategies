"""Focused AI/chatbot records stay narrower than bespoke MISC coverage."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ChatbotAcceptanceTests(unittest.TestCase):
    def test_partial_ai_families_and_local_acceptance_records(self):
        catalog = json.loads((ROOT / 'scripts/autosolve_lib/family_catalog.json').read_text())
        acceptance = json.loads((ROOT / 'scripts/chatbot_acceptance.json').read_text())
        families = {row['id']: row for row in catalog['families']}
        self.assertEqual({row['family_id'] for row in acceptance['cases']}, {'AIC01', 'AIC02'})
        self.assertEqual(families['MISC03']['planned_coverage'], 'unsupported')
        self.assertEqual(acceptance['legacy_misc03']['coverage'], 'unsupported')
        for row in acceptance['cases']:
            self.assertEqual(families[row['family_id']]['planned_coverage'], 'partial')
            self.assertIn('publisher transfer untested', row['status'])
            self.assertTrue(all((ROOT / path).is_file() for path in row['check_paths']))


if __name__ == '__main__':
    unittest.main()
