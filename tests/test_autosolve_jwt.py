import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.autosolve_lib import core
from scripts.autosolve_lib.profiles.jwt import inspect_jwt


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


def compact(header, claims, sign):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')

    signing_input = part(header) + b'.' + part(claims)
    return signing_input + b'.' + base64.urlsafe_b64encode(sign(signing_input)).rstrip(b'=')


class JwtProfileTests(unittest.TestCase):
    def _cli(self, *arguments):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', *map(str, arguments)],
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_hs_token_found_at_exact_byte_offset_and_word_index_without_secret_disclosure(self):
        secret = b'held-out-secret-47'
        token = compact({'alg': 'HS256', 'typ': 'JWT', 'kid': 'v2'},
                        {'sub': 'user-17', 'exp': 100},
                        lambda data: hmac.digest(secret, data, hashlib.sha256))
        records, warnings = inspect_jwt(b'\xffAuthorization: Bearer ' + token + b'\n',
                                        words=[b'wrong', secret], now=200)
        self.assertEqual(warnings, [])
        self.assertEqual(len(records), 1)
        row = records[0]
        self.assertEqual(row['offset'], 23)
        self.assertEqual(row['header']['kid'], 'v2')
        self.assertEqual(row['claims']['sub'], 'user-17')
        self.assertEqual(row['claims_trust'], 'untrusted')
        self.assertTrue(row['expired'])
        self.assertEqual(row['status'], 'validated_transform')
        self.assertTrue(row['signature_verified'])
        self.assertIsNone(row['server_accepted'])
        self.assertEqual(row['key_source'], 'wordlist')
        self.assertEqual(row['key_index'], 1)
        self.assertNotIn(secret.decode(), json.dumps(records))
        self.assertNotIn(token.decode(), json.dumps(records))

    def test_declared_rsa_key_verifies_only_matching_algorithm_and_kid(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        token = compact({'alg': 'RS384', 'kid': 'current'}, {'scope': 'read'},
                        lambda data: private.sign(data, padding.PKCS1v15(), hashes.SHA384()))
        keys = [{'alg': 'RS384', 'kid': 'retired', 'key': public},
                {'alg': 'RS256', 'kid': 'current', 'key': public},
                {'alg': 'RS384', 'kid': 'current', 'key': public}]
        records, warnings = inspect_jwt(token, keys=keys)
        self.assertEqual(warnings, [])
        self.assertEqual(records[0]['key_source'], 'supplied_key')
        self.assertEqual(records[0]['key_index'], 2)
        self.assertTrue(records[0]['signature_verified'])
        self.assertIsNone(records[0]['expired'])
        self.assertIsNone(records[0]['server_accepted'])

    def test_untrusted_kid_mismatch_does_not_hide_local_signature_relation(self):
        token = compact({'alg': 'HS256', 'kid': 'claimed'}, {'sub': 'x'},
                        lambda data: hmac.digest(b'secret', data, hashlib.sha256))
        records, _ = inspect_jwt(token, keys=[{'alg': 'HS256', 'kid': 'actual', 'key': b'secret'}])
        self.assertTrue(records[0]['signature_verified'])
        self.assertFalse(records[0]['kid_matches'])
        self.assertIsNone(records[0]['server_accepted'])

    def test_unrelated_or_modified_signatures_do_not_validate(self):
        token = compact({'alg': 'HS512'}, {'role': 'user'},
                        lambda data: hmac.digest(b'correct', data, hashlib.sha512))
        segments = token.split(b'.')
        changed_signature = base64.urlsafe_b64encode(
            bytes([base64.urlsafe_b64decode(segments[2] + b'==')[0] ^ 1])
            + base64.urlsafe_b64decode(segments[2] + b'==')[1:]).rstrip(b'=')
        for variant in (token, b'.'.join([*segments[:2], changed_signature])):
            with self.subTest(variant=variant[-8:]):
                records, _ = inspect_jwt(variant, keys=[{'alg': 'HS512', 'key': b'wrong'}])
                self.assertEqual(len(records), 1)
                self.assertFalse(records[0]['signature_verified'])
                self.assertNotEqual(records[0]['status'], 'validated_transform')
        records, _ = inspect_jwt(token, keys=[{'alg': 'HS256', 'key': b'correct'}])
        self.assertFalse(records[0]['signature_verified'])

    def test_none_jwe_duplicate_json_and_critical_extensions_are_not_verified(self):
        valid = compact({'alg': 'HS256'}, {'ok': 1},
                        lambda data: hmac.digest(b'secret', data, hashlib.sha256))
        raw_header = base64.urlsafe_b64encode(b'{"alg":"HS256","alg":"HS256"}').rstrip(b'=')
        duplicate = raw_header + b'.' + valid.split(b'.')[1] + b'.' + valid.split(b'.')[2]
        none = compact({'alg': 'none'}, {'admin': True}, lambda _: b'')
        critical = compact({'alg': 'HS256', 'crit': ['b64'], 'b64': False}, {'ok': 1},
                           lambda data: hmac.digest(b'secret', data, hashlib.sha256))
        jwe = b'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..a.b.c'
        for token in (duplicate, none, critical, jwe):
            with self.subTest(token=token[:20]):
                records, _ = inspect_jwt(token, keys=[{'alg': 'HS256', 'key': b'secret'}])
                self.assertFalse(any(row['signature_verified'] for row in records))

    def test_public_key_bytes_cannot_be_treated_as_hmac_secret(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        token = compact({'alg': 'HS256'}, {'admin': True},
                        lambda data: hmac.digest(public, data, hashlib.sha256))
        records, _ = inspect_jwt(token, keys=[{'alg': 'HS256', 'key': public}])
        self.assertFalse(records[0]['signature_verified'])
        self.assertNotEqual(records[0]['status'], 'validated_transform')
        der_public = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        der_token = compact({'alg': 'HS256'}, {'admin': True},
                            lambda data: hmac.digest(der_public, data, hashlib.sha256))
        records, _ = inspect_jwt(der_token, words=[der_public])
        self.assertFalse(records[0]['signature_verified'])

    def test_malformed_algorithm_values_do_not_crash_or_verify(self):
        for algorithm in (['HS256'], {'name': 'HS256'}, None):
            token = compact({'alg': algorithm}, {'user': 'x'},
                            lambda data: hmac.digest(b'secret', data, hashlib.sha256))
            records, _ = inspect_jwt(token, words=[b'secret'])
            self.assertEqual(len(records), 1)
            self.assertFalse(records[0]['signature_verified'])
            with self.assertRaises(ValueError):
                inspect_jwt(token, keys=[{'alg': algorithm, 'key': b'secret'}])

    def test_bounded_inputs_reject_oversized_or_invalid_key_lists(self):
        token = compact({'alg': 'HS256'}, {'ok': True},
                        lambda data: hmac.digest(b'secret', data, hashlib.sha256))
        for kwargs in ({'words': [b'x'] * 1025},
                       {'keys': [{'alg': 'HS256', 'key': b'x'}] * 33},
                       {'words': [b'x' * 257]},
                       {'keys': [{'alg': 'HS256', 'key': b'x' * 4097}]},
                       {'max_token_bytes': -1},
                       {'now': True}):
            with self.subTest(kwargs=list(kwargs)):
                with self.assertRaises(ValueError):
                    inspect_jwt(token, **kwargs)

    def test_malformed_token_flood_respects_scan_limit(self):
        records, warnings = inspect_jwt(b'a.b.c ' * 200, max_tokens=2)
        self.assertEqual(records, [])
        self.assertLessEqual(len(warnings), 3)
        self.assertIn('JWT token count limit reached', warnings)

    def test_public_cli_web_key_file_resume_and_private_exclusion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / 'bundle'
            bundle.mkdir()
            secret = b'private-key-for-jwt-47'
            token = compact({'alg': 'HS256', 'kid': 'k1'}, {'sub': 'cli-user'},
                            lambda data: hmac.digest(secret, data, hashlib.sha256))
            (bundle / 'auth.txt').write_bytes(b'Authorization: Bearer ' + token + b'\n')
            private_key = bundle / 'key.bin'
            private_key.write_bytes(secret)
            os.link(private_key, bundle / 'key-hardlink.bin')
            hints = bundle / 'hints.json'
            hints.write_text(json.dumps({'key_files': ['key.bin'],
                                         'jwt_keys': [{'alg': 'HS256', 'kid': 'k1',
                                                       'key_file_index': 0}]}))
            run = Path(self._cli('analyze', bundle, '--category', 'web', '--hints', hints,
                                 '--runs-root', root / 'runs', '--budget', '20')['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([a for a in manifest['artifacts'] if a['depth'] == 0]), 1)
            jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'jwt']
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]['status'], 'complete')
            self.assertEqual(manifest['coverage']['WEB04']['status'], 'ran')
            records = json.loads(Path(jobs[0]['records_path']).read_text())
            self.assertTrue(records[0]['signature_verified'])
            self.assertEqual(records[0]['key_index'], 0)
            self.assertEqual(records[0]['offset'], 22)
            self.assertIsNone(records[0]['server_accepted'])
            self.assertIn('WEB04 JWT', (run / 'report.md').read_text())
            self.assertNotIn(secret.decode(), (run / 'report.md').read_text())
            self.assertNotIn(token.decode(), json.dumps([item for item in manifest['intelligence']
                                                          if item['tag'] == 'WEB04 JWT']))
            self.assertNotIn(secret.decode(), json.dumps(manifest))
            self._cli('resume', run, '--hints', hints, '--budget', '20')
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([job for job in manifest['jobs'] if job['adapter_id'] == 'jwt']), 1)
            private_key.write_bytes(b'unrelated-private-key')
            self._cli('resume', run, '--hints', hints, '--budget', '20')
            manifest = json.loads((run / 'manifest.json').read_text())
            jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'jwt']
            self.assertEqual(len(jobs), 2)
            self.assertFalse(any(row['current'] for row in manifest['intelligence']
                                 if row['job_id'] == jobs[0]['id']))
            self.assertFalse(json.loads(Path(jobs[1]['records_path']).read_text())[0]['signature_verified'])

    def test_public_cli_auto_derived_text_wordlist_and_doctor(self):
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = b'wordlist-match-19'
            token = compact({'alg': 'HS384'}, {'exp': 1},
                            lambda data: hmac.digest(secret, data, hashlib.sha384))
            archive = root / 'bundle.zip'
            with zipfile.ZipFile(archive, 'w') as target:
                target.writestr('nested/session.txt', b'cookie=' + token)
            words = root / 'jwt-words.txt'
            words.write_bytes(b'wrong\n' + secret + b'\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'jwt_wordlist_file': str(words)}))
            run = Path(self._cli('analyze', archive, '--category', 'auto', '--hints', hints,
                                 '--runs-root', root / 'runs', '--budget', '20')['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['WEB04']['status'], 'ran',
                             [(job.get('warnings'), job.get('coverage_status')) for job in manifest['jobs']
                              if job['adapter_id'] == 'jwt'])
            records = [json.loads(Path(job['records_path']).read_text()) for job in manifest['jobs']
                       if job['adapter_id'] == 'jwt']
            self.assertTrue(any(row['signature_verified'] and row['key_source'] == 'wordlist'
                                and row['key_index'] == 1 for group in records for row in group))
            doctor = self._cli('doctor', '--profiles', 'web', '--self-test')
            self.assertEqual(doctor['operations']['web.jwt_local'],
                             {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'})

    def test_public_cli_asymmetric_public_key_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            token = compact({'alg': 'RS256', 'kid': 'public-v3'}, {'sub': 'asymmetric'},
                            lambda data: private.sign(data, padding.PKCS1v15(), hashes.SHA256()))
            source = root / 'session.jwt'
            source.write_bytes(token)
            public = root / 'public.pem'
            public.write_bytes(private.public_key().public_bytes(Encoding.PEM,
                                                                  PublicFormat.SubjectPublicKeyInfo))
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'key_files': ['public.pem'],
                                         'jwt_keys': [{'alg': 'RS256', 'kid': 'public-v3',
                                                       'key_file_index': 0}]}))
            run = Path(self._cli('analyze', source, '--category', 'web', '--hints', hints,
                                 '--runs-root', root / 'runs', '--budget', '20')['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'jwt')
            record = json.loads(Path(job['records_path']).read_text())[0]
            self.assertTrue(record['signature_verified'])
            self.assertEqual(record['algorithm'], 'RS256')
            self.assertEqual(record['key_index'], 0)
            self.assertIsNone(record['server_accepted'])
            self.assertEqual(manifest['coverage']['WEB04']['status'], 'ran')

    def test_public_cli_large_text_inspects_bounded_prefix_and_marks_truncated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = compact({'alg': 'HS256'}, {'sub': 'large-file'},
                            lambda data: hmac.digest(b'secret', data, hashlib.sha256))
            source = root / 'large.txt'
            source.write_bytes(token + b'\n' + b'x' * (1024 * 1024))
            run = Path(self._cli('analyze', source, '--category', 'web',
                                 '--runs-root', root / 'runs', '--budget', '20')['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'jwt')
            records = json.loads(Path(job['records_path']).read_text())
            self.assertEqual(records[0]['claims']['sub'], 'large-file')
            self.assertEqual(manifest['coverage']['WEB04']['status'], 'truncated')

    def test_private_jwt_hints_require_bounded_regular_files_and_explicit_key_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'secret.bin'
            source.write_bytes(b'secret')
            alias = root / 'alias.bin'
            alias.symlink_to(source)
            words = root / 'words.txt'
            words.write_bytes(b'x\n' * 1025)
            hints = root / 'hints.json'
            for value in (
                    {'jwt_keys': [{'alg': 'HS256', 'key': 'inline-secret'}]},
                    {'key_files': ['alias.bin'],
                     'jwt_keys': [{'alg': 'HS256', 'key_file_index': 0}]},
                    {'jwt_wordlist_file': 'words.txt'},
                    {'key_files': ['secret.bin'],
                     'jwt_keys': [{'alg': 'HS256', 'key_file_index': True}]}):
                hints.write_text(json.dumps(value))
                with self.subTest(value=list(value)), self.assertRaises(core.InvalidInput):
                    core.load_hints(hints)


if __name__ == '__main__':
    unittest.main()
