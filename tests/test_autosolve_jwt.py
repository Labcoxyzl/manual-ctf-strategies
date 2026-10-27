import base64
import hashlib
import hmac
import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.autosolve_lib.profiles.jwt import inspect_jwt


def compact(header, claims, sign):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')

    signing_input = part(header) + b'.' + part(claims)
    return signing_input + b'.' + base64.urlsafe_b64encode(sign(signing_input)).rstrip(b'=')


class JwtProfileTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
