import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts.autosolve_lib import core
from scripts.autosolve_lib.profiles.passwords import inspect_password_hashes


class PasswordProfileTests(unittest.TestCase):
    def test_unsalted_and_salted_passwords_verify_original_digest(self):
        words = [b'wrong', b'coral\xff', b'second']
        records = [
            {'algorithm': 'md5', 'digest': hashlib.md5(words[2]).hexdigest()},
            {'algorithm': 'sha256', 'digest': hashlib.sha256(b'\x00\x01' + words[1]).hexdigest(),
             'salt_hex': '0001', 'salt_position': 'prefix'},
            {'algorithm': 'sha512', 'digest': hashlib.sha512(words[0] + b'\xfe').hexdigest(),
             'salt_hex': 'fe', 'salt_position': 'suffix'},
        ]
        rows = inspect_password_hashes(records, words)
        self.assertEqual([row['status'] for row in rows], ['validated_transform'] * 3)
        self.assertEqual([row['password'] for row in rows], [words[2], words[1], words[0]])
        self.assertEqual([row['evidence']['candidate_index'] for row in rows], [2, 1, 0])
        self.assertTrue(all(row['evidence']['digest_verified'] for row in rows))

    def test_held_out_order_encoding_and_algorithm(self):
        password = 'café'
        records = [
            {'algorithm': 'sha1', 'encoding': 'latin-1',
             'digest': hashlib.sha1(password.encode('latin-1')).hexdigest()},
            {'algorithm': 'sha256', 'encoding': 'utf-8', 'salt_hex': 'f00d',
             'salt_position': 'suffix',
             'digest': hashlib.sha256(password.encode() + bytes.fromhex('f00d')).hexdigest()},
        ]
        rows = inspect_password_hashes(records, ['wrong', password, 'other'])
        self.assertEqual([row['password'] for row in rows],
                         [password.encode('latin-1'), password.encode()])
        self.assertEqual([row['evidence']['candidate_index'] for row in rows], [1, 1])

    def test_no_match_is_distinct_from_ambiguous_or_invalid_format(self):
        digest = hashlib.sha256(b'outside').hexdigest()
        rows = inspect_password_hashes([
            {'algorithm': 'sha256', 'digest': digest},
            {'digest': digest},
            {'algorithm': 'sha256', 'digest': 'bad'},
            {'algorithm': 'argon2', 'digest': digest},
        ], [b'candidate'])
        self.assertEqual([row['status'] for row in rows],
                         ['no_match', 'ambiguous', 'invalid_input', 'unsupported'])
        self.assertEqual(rows[0]['evidence']['checked'], 1)
        self.assertNotIn('password', rows[0])
        self.assertEqual(rows[1]['evidence']['plausible_algorithms'], ['sha256'])
        self.assertNotIn('password', rows[1])

    def test_input_and_work_caps_reject_oversized_jobs(self):
        record = {'algorithm': 'sha256', 'digest': hashlib.sha256(b'x').hexdigest()}
        for records, words in (([record] * 33, ['x']), ([record], ['x'] * 4097),
                               ([record], ['x' * 129])):
            with self.assertRaises(ValueError):
                inspect_password_hashes(records, words)
        for budget in (0, math.nan):
            with self.assertRaises(ValueError):
                inspect_password_hashes([record], ['x'], budget_seconds=budget)

    def test_unencodable_candidate_does_not_claim_full_no_match(self):
        record = {'algorithm': 'sha256', 'encoding': 'latin-1',
                  'digest': hashlib.sha256(b'outside').hexdigest()}
        row = inspect_password_hashes([record], ['emoji\U0001f642', 'wrong'])[0]
        self.assertEqual(row['status'], 'incomplete')
        self.assertEqual((row['evidence']['checked'], row['evidence']['skipped']), (1, 1))

    def test_hash_backend_error_is_not_reported_as_no_match(self):
        record = {'algorithm': 'sha256', 'digest': hashlib.sha256(b'x').hexdigest()}
        with patch('scripts.autosolve_lib.profiles.passwords.hashlib.new',
                   side_effect=ValueError('backend unavailable')):
            row = inspect_password_hashes([record], [b'x'])[0]
        self.assertEqual(row['status'], 'tool_error')
        self.assertEqual(row['evidence']['checked'], 0)

    def test_public_cli_hash_wordlist_and_resume_identity(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.bin'
            source.write_bytes(b'ordinary input')
            words = root / 'private-words.txt'
            words.write_bytes(b'wrong\n secret space \n')
            secret = b' secret space '
            hints = root / 'hints.json'
            record = {'algorithm': 'sha256', 'salt_hex': '00ff',
                      'salt_position': 'prefix',
                      'digest': hashlib.sha256(b'\x00\xff' + secret).hexdigest()}
            hints.write_text(json.dumps({'hash_parameters': [record],
                                         'hash_wordlist_file': str(words)}))

            def cli(*args):
                result = subprocess.run([sys.executable, '-B', str(script), '--json', *map(str, args)],
                                        capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
                self.assertNotIn(secret, result.stdout)
                return json.loads(result.stdout)

            run = Path(cli('analyze', source, '--category', 'encoding', '--hints', hints,
                           '--runs-root', root / 'runs')['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            found = [item for item in manifest['findings'] if item.get('operation') == 'password_hash']
            self.assertEqual(len(found), 1)
            self.assertTrue(found[0]['current'])
            self.assertEqual(found[0]['state'], 'validated_transform')
            self.assertEqual(found[0]['recovered_password_hex'], secret.hex())
            self.assertNotIn(secret.decode(), (run / 'report.md').read_text())
            self.assertNotIn(secret, (run / 'events.jsonl').read_bytes())
            original_jobs = len([job for job in manifest['jobs'] if job['adapter_id'] == 'password-hashes'])
            cli('resume', run, '--hints', hints)
            repeated = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([job for job in repeated['jobs'] if job['adapter_id'] == 'password-hashes']),
                             original_jobs)

            words.write_bytes(b'wrong\n')
            cli('resume', run, '--hints', hints)
            changed = json.loads((run / 'manifest.json').read_text())
            old = next(item for item in changed['findings'] if item.get('operation') == 'password_hash')
            self.assertFalse(old['current'])
            self.assertEqual(changed['coverage']['ENC10']['status'], 'no finding')
            self.assertNotIn('- no_match: declared', (run / 'report.md').read_text())

            words.write_bytes(b'wrong\n secret space \n')
            record['digest'] = hashlib.sha256(b'outside').hexdigest()
            hints.write_text(json.dumps({'hash_parameters': [record],
                                         'hash_wordlist_file': str(words)}))
            cli('resume', run, '--hints', hints)
            new_hash = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(next(item for item in new_hash['findings']
                                  if item.get('recovered_password_hex'))['current'])
            self.assertEqual(new_hash['coverage']['ENC10']['status'], 'no finding')

            new_hash['current_adapter_fingerprints']['password-hashes'] = []
            core._refresh_current(new_hash, {item['id'] for item in new_hash['artifacts']
                                             if item['depth'] == 0 and item['current']})
            self.assertTrue(all(not item['current'] for item in new_hash['findings']
                                if item.get('operation') == 'password_hash'))

    def test_hash_wordlist_is_private_and_exact_and_invalid_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            words = root / 'words'
            words.write_bytes(b' a \n\nlast\r\n')
            loaded, digest = core._hash_wordlist({'hash_wordlist_file': str(words)}, root / 'hints')
            self.assertEqual(loaded, [b' a ', b'', b'last\r'])
            self.assertEqual(digest, hashlib.sha256(words.read_bytes()).hexdigest())
            self.assertIn(words.absolute(), core._private_paths(root / 'hints',
                                                                 {'hash_wordlist_file': str(words)}))
            words.write_bytes((b'x' * 129) + b'\n')
            with self.assertRaises(core.InvalidInput):
                core._hash_wordlist({'hash_wordlist_file': str(words)}, root / 'hints')

    def test_runner_coverage_distinguishes_incomplete_and_backend_error(self):
        with tempfile.TemporaryDirectory() as directory:
            for status, expected in (('incomplete', 'truncated'), ('tool_error', 'failed')):
                with self.subTest(status=status):
                    manifest = {'coverage': {'ENC10': {'status': 'not scheduled', 'note': ''}},
                                'jobs': [], 'findings': [], 'warnings': []}
                    row = {'family': 'ENC10', 'source_index': 0, 'status': status,
                           'evidence': {'algorithm': 'sha256', 'checked': 0}}
                    with patch('scripts.autosolve_lib.core._run_hash', return_value=[row]):
                        core._hash_job(Path(directory), manifest,
                                       [{'algorithm': 'sha256', 'digest': '00' * 32}],
                                       'params', [b'word'], 'words', time.monotonic() + 5)
                    self.assertEqual(manifest['coverage']['ENC10']['status'], expected)


if __name__ == '__main__':
    unittest.main()
