import unittest

from cryptography.hazmat.primitives.asymmetric import rsa as cryptography_rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.autosolve_lib.profiles.rsa import inspect_rsa, parse_public_key


class RsaProfileTests(unittest.TestCase):
    def test_public_key_pem_and_der_parse_exact_public_numbers(self):
        key = cryptography_rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
        numbers = key.public_numbers()
        expected = {'n': numbers.n, 'e': numbers.e}
        for encoding, form in ((Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
                               (Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
                               (Encoding.PEM, PublicFormat.PKCS1),
                               (Encoding.DER, PublicFormat.PKCS1)):
            with self.subTest(encoding=encoding, form=form):
                serialized = key.public_bytes(encoding, form)
                self.assertEqual(parse_public_key(serialized), expected)
                if encoding is Encoding.PEM:
                    self.assertEqual(parse_public_key(serialized.decode('ascii')), expected)

    def test_public_key_rejects_malformed_private_or_non_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

        private = cryptography_rsa.generate_private_key(public_exponent=65537, key_size=1024)
        secret = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        non_rsa = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        for item in (secret, non_rsa, b'not DER', b'-----BEGIN PUBLIC KEY-----\nBAD\n',
                     b'x' * 16385, 123, ''):
            with self.subTest(item=type(item).__name__):
                self.assertIsNone(parse_public_key(item))

    def test_serialized_weak_key_flows_into_exact_recovery(self):
        n, e, message = 1000003 * 1000033, 65537, 0x4243
        serialized = cryptography_rsa.RSAPublicNumbers(e, n).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        numbers = parse_public_key(serialized)
        self.assertIsNotNone(numbers)
        rows = inspect_rsa([{**numbers, 'c': pow(message, e, n)}])
        self.assertTrue(any(row['method'] == 'close_prime_factor'
                            and row['plaintext_hex'] == '4243' for row in rows))

    def test_declared_broadcast_recovers_only_exact_shared_message(self):
        moduli = [101 * 113, 127 * 131, 137 * 139]
        message = 257
        inputs = [{'n': n, 'e': 3, 'c': pow(message, 3, n), 'message_label': 'shared'}
                  for n in moduli]
        rows = [row for row in inspect_rsa(inputs) if row['method'] == 'declared_broadcast']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_int'], str(message))
        self.assertEqual(rows[0]['source_indices'], [0, 1, 2])
        self.assertTrue(rows[0]['evidence']['all_equations_verified'])
        self.assertEqual(rows[0]['family'], 'ENC07')

    def test_broadcast_held_out_shuffled_unrelated_and_changed_exponent(self):
        message = 777
        moduli = [101 * 113, 127 * 131, 137 * 139, 149 * 151, 157 * 163]
        inputs = [{'n': n, 'e': 5, 'c': pow(message, 5, n), 'message_label': 'case'}
                  for n in moduli]
        inputs.insert(2, {'n': 167 * 173, 'e': 5, 'c': pow(779, 5, 167 * 173),
                          'message_label': 'other'})
        inputs.insert(0, {'n': 179 * 181, 'e': 65537, 'c': 17})
        rows = [row for row in inspect_rsa(inputs) if row['method'] == 'declared_broadcast']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_int'], str(message))
        self.assertEqual(rows[0]['source_indices'], [1, 2, 4, 5, 6])

    def test_broadcast_rejects_missing_label_non_coprime_moduli_and_mixed_messages(self):
        moduli = [101 * 113, 127 * 131, 137 * 139]
        base = [{'n': n, 'e': 3, 'c': pow(257, 3, n), 'message_label': 'shared'}
                for n in moduli]
        variants = [
            [{**base[0], 'message_label': None}, *base[1:]],
            [base[0], base[1], {**base[2], 'n': 101 * 139,
                                  'c': pow(257, 3, 101 * 139)}],
            [base[0], base[1], {**base[2], 'c': pow(258, 3, moduli[2])}],
        ]
        for inputs in variants:
            with self.subTest(inputs=inputs):
                self.assertFalse(any(row['method'] == 'declared_broadcast'
                                     for row in inspect_rsa(inputs)))

    def test_close_prime_factorization_recovers_verified_preimage(self):
        p, q, message = 1000003, 1000033, 0x4243
        n, e = p * q, 65537
        rows = [row for row in inspect_rsa([{'n': n, 'e': e, 'c': pow(message, e, n)}])
                if row['method'] == 'close_prime_factor']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_hex'], '4243')
        self.assertEqual(int(rows[0]['evidence']['factor_a'])
                         * int(rows[0]['evidence']['factor_b']), n)
        self.assertTrue(rows[0]['evidence']['reencryption_verified'])

    def test_small_private_exponent_recovers_verified_preimage(self):
        # Generated from primes 223, 673 with d=5 and e=29837.
        n, e, message = 223 * 673, 29837, 0x42
        rows = [row for row in inspect_rsa([{'n': n, 'e': e, 'c': pow(message, e, n)}])
                if row['method'] == 'small_private_exponent']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_int'], str(message))
        self.assertEqual(rows[0]['evidence']['private_exponent'], '5')
        self.assertTrue(rows[0]['evidence']['reencryption_verified'])

    def test_strong_unrelated_key_has_no_weak_key_finding(self):
        key = cryptography_rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public = key.public_key().public_numbers()
        rows = inspect_rsa([{'n': public.n, 'e': public.e,
                             'c': pow(0x4243, public.e, public.n)}])
        self.assertEqual(rows, [])

    def test_shared_factor_recovers_each_labeled_ciphertext_and_keeps_both_sources(self):
        p, q1, q2 = 10007, 10009, 10037
        first = {'n': p * q1, 'e': 65537, 'c': pow(0x4142, 65537, p * q1)}
        second = {'n': p * q2, 'e': 65537, 'c': pow(0x4344, 65537, p * q2)}
        result = inspect_rsa([first, second])
        recovered = {(row['ciphertext_index'], row['plaintext_hex']) for row in result
                     if row['method'] == 'shared_factor'}
        self.assertEqual(recovered, {(0, '4142'), (1, '4344')})
        for row in (item for item in result if item['method'] == 'shared_factor'):
            self.assertEqual(row['source_indices'], [0, 1])
            self.assertEqual(row['status'], 'validated_transform')
            self.assertTrue(row['evidence']['reencryption_verified'])

    def test_shared_factor_held_out_shuffled_unrelated_key(self):
        shared = 101
        parameters = [
            {'n': 131 * 137, 'e': 17, 'c': pow(55, 17, 131 * 137)},
            {'n': shared * 127, 'e': 17, 'c': pow(89, 17, shared * 127)},
            {'n': shared * 113, 'e': 17, 'c': pow(73, 17, shared * 113)},
        ]
        result = [row for row in inspect_rsa(parameters) if row['method'] == 'shared_factor']
        self.assertEqual({(row['ciphertext_index'], tuple(row['source_indices']), row['plaintext_int']) for row in result},
                         {(1, (1, 2), '89'), (2, (1, 2), '73')})

    def test_shared_factor_held_out_larger_integers(self):
        p, q1, q2 = 2 ** 127 - 1, 2 ** 61 - 1, 2 ** 31 - 1
        inputs = [
            {'n': p * q1, 'e': 65537, 'c': pow(0x414243, 65537, p * q1)},
            {'n': p * q2, 'e': 65537, 'c': pow(0x444546, 65537, p * q2)},
        ]
        rows = [row for row in inspect_rsa(inputs) if row['method'] == 'shared_factor']
        self.assertEqual({row['plaintext_hex'] for row in rows}, {'414243', '444546'})
        self.assertTrue(all(row['source_indices'] == [0, 1] for row in rows))

    def test_declared_common_modulus_requires_same_label_and_checks_both_equations(self):
        n, message = 101 * 113, 321
        inputs = [
            {'n': n, 'e': 7, 'c': pow(message, 7, n), 'message_label': 'same'},
            {'n': n, 'e': 11, 'c': pow(message, 11, n), 'message_label': 'same'},
        ]
        rows = [row for row in inspect_rsa(inputs) if row['method'] == 'common_modulus']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_int'], '321')
        self.assertEqual(rows[0]['source_indices'], [0, 1])
        self.assertEqual(rows[0]['status'], 'validated_transform')
        for variant in ({**inputs[1], 'message_label': 'other'},
                        {**inputs[1], 'c': pow(322, 11, n)}):
            self.assertFalse(any(row['method'] == 'common_modulus'
                                 for row in inspect_rsa([inputs[0], variant])))

    def test_common_modulus_rejects_non_coprime_exponents_and_nonunits(self):
        n = 101 * 113
        self.assertFalse(any(row['method'] == 'common_modulus' for row in inspect_rsa([
            {'n': n, 'e': 6, 'c': pow(321, 6, n), 'message_label': 'x'},
            {'n': n, 'e': 10, 'c': pow(321, 10, n), 'message_label': 'x'},
        ])))
        self.assertFalse(any(row['method'] == 'common_modulus' for row in inspect_rsa([
            {'n': n, 'e': 3, 'c': pow(101, 3, n), 'message_label': 'x'},
            {'n': n, 'e': 5, 'c': pow(101, 5, n), 'message_label': 'x'},
        ])))

    def test_exact_low_exponent_root_requires_unwrapped_ciphertext_power(self):
        n = 1000003 * 1000033
        inputs = [{'n': n, 'e': 3, 'c': 1234 ** 3}]
        rows = [row for row in inspect_rsa(inputs) if row['method'] == 'exact_low_exponent_root']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['plaintext_int'], '1234')
        self.assertEqual(rows[0]['source_indices'], [0])
        self.assertEqual(rows[0]['status'], 'validated_transform')
        self.assertEqual(inspect_rsa([{'n': n, 'e': 3, 'c': 1234 ** 3 + 1}]), [])

    def test_no_recovery_from_unrelated_or_malformed_parameters(self):
        unrelated = [
            {'n': 1000003 * 1000033, 'e': 65537, 'c': 47},
            {'n': 1000037 * 1000039, 'e': 65537, 'c': 53},
        ]
        self.assertFalse(any(row['family'] == 'ENC07' for row in inspect_rsa(unrelated)))
        for item in (
            {'n': '11413', 'e': 3, 'c': 8},
            {'n': True, 'e': 3, 'c': 8},
            {'n': 101 * 113, 'e': 3, 'c': -1},
            {'n': 101 * 113, 'e': 3, 'c': 101 * 113},
            {'n': 2 ** 4097 + 1, 'e': 3, 'c': 8},
            {'n': 101 * 113, 'e': 2 ** 32, 'c': 8},
        ):
            with self.subTest(item=item):
                self.assertEqual(inspect_rsa([item]), [])


if __name__ == '__main__':
    unittest.main()
