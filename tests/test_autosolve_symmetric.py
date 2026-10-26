import unittest

from scripts.autosolve_lib.profiles.symmetric import decrypt_declared


# GCM/CBC/CTR values below include NIST SP 800-38A/D examples. The shorter-tag,
# binary, and padded CBC vectors were generated independently with PyCryptodome.
KEY = '00112233445566778899aabbccddeeff'
IV = '0f0e0d0c0b0a09080706050403020100'
BINARY = bytes.fromhex('00ff8042494e4152590001fe')


class SymmetricProfileTests(unittest.TestCase):
    def test_gcm_published_vectors_and_empty_plaintext(self):
        base = {'algorithm': 'AES', 'mode': 'GCM', 'key': '00' * 16,
                'nonce': '00' * 12}
        rows = decrypt_declared([
            {**base, 'ciphertext': '0388dace60b6a392f328c2b971b2fe78',
             'tag': 'ab6e47d42cec13bdf53a67b21257bddf'},
            {**base, 'ciphertext': '', 'tag': '58e2fccefa7e3061367f1d57a4e7455a'},
        ], max_output=16)
        self.assertEqual([(row['source_index'], row['plaintext']) for row in rows],
                         [(0, bytes(16)), (1, b'')])
        self.assertTrue(all(row['status'] == 'validated_transform' for row in rows))
        self.assertTrue(all(row['evidence']['tag_verified'] for row in rows))
        short_tag = decrypt_declared([{**base,
                                       'ciphertext': '0388dace60b6a392f328c2b971b2fe78',
                                       'tag': 'ab6e47d4'}], max_output=16)
        self.assertEqual(short_tag[0]['plaintext'], bytes(16))
        self.assertEqual(short_tag[0]['evidence']['tag_bytes'], 4)
        self.assertEqual(decrypt_declared([{**base, 'ciphertext': '',
                                            'tag': '58e2fccefa7e3061367f1d57a4e7455a'}],
                                          max_output=0)[0]['plaintext'], b'')

    def test_gcm_binary_aad_and_truncated_tag(self):
        record = {'algorithm': 'AES', 'mode': 'GCM', 'key': KEY,
                  'nonce': '0102030405060708090a0b0c', 'aad': 'deadbeef0080ff',
                  'ciphertext': 'e679aedc78312d5f1a26260c',
                  'tag': '646a93684548310646324ec8'}
        rows = decrypt_declared([record], max_output=len(BINARY))
        self.assertEqual(rows[0]['plaintext'], BINARY)
        self.assertEqual(rows[0]['evidence']['tag_bytes'], 12)
        for bad in ({**record, 'key': '01' * 16},
                    {**record, 'nonce': '01' * 12},
                    {**record, 'tag': '00' + record['tag'][2:]},
                    {**record, 'aad': 'deadbeef0080fe'},
                    {**record, 'tag': ''}):
            with self.subTest(bad=tuple(k for k in bad if bad[k] != record[k])):
                self.assertEqual(decrypt_declared([bad], max_output=64), [])

    def test_cbc_published_unpadded_and_independent_pkcs7_vectors(self):
        published = {'algorithm': 'AES', 'mode': 'CBC',
                     'key': '2b7e151628aed2a6abf7158809cf4f3c',
                     'iv': '000102030405060708090a0b0c0d0e0f',
                     'ciphertext': '7649abac8119b246cee98e9b12e9197d'}
        padded = {'algorithm': 'AES', 'mode': 'CBC', 'key': KEY, 'iv': IV,
                  'padding': 'pkcs7', 'ciphertext': 'a1d77db123de591fb6c9838f0d51bfe2'}
        empty = {**padded, 'ciphertext': 'd8f43fc6392d8dced3af48947afeeee4'}
        full_block = {**padded,
                      'ciphertext': '8f0151744bf465d6f055ecc39de0fada09f04d4909dff599a58f117a4d8dff78'}
        rows = decrypt_declared([published, padded, empty, full_block], max_output=16)
        self.assertEqual([row['plaintext'] for row in rows],
                         [bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
                          BINARY, b'', b'16-byte-block!!?'])
        self.assertTrue(all(row['status'] == 'candidate' for row in rows))
        self.assertTrue(all('authentication' in row['limitations'] for row in rows))
        self.assertTrue(rows[1]['evidence']['padding_verified'])
        self.assertEqual(decrypt_declared([empty], max_output=0)[0]['plaintext'], b'')
        self.assertEqual(decrypt_declared([{**padded, 'key': '01' * 16}], max_output=16), [])
        self.assertEqual(decrypt_declared([{**padded, 'ciphertext': '00' * 16}], max_output=16), [])
        changed_iv = decrypt_declared([{**padded, 'iv': '00' + IV[2:]}], max_output=16)
        self.assertEqual(changed_iv[0]['status'], 'candidate')
        self.assertNotEqual(changed_iv[0]['plaintext'], BINARY)

    def test_ctr_published_vector_is_candidate(self):
        row = decrypt_declared([{
            'algorithm': 'AES', 'mode': 'CTR',
            'key': '2b7e151628aed2a6abf7158809cf4f3c',
            'nonce': 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
            'ciphertext': '874d6191b620e3261bef6864990db6ce',
        }], max_output=16)[0]
        self.assertEqual(row['plaintext'], bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'))
        self.assertEqual(row['status'], 'candidate')
        self.assertIn('without authentication', row['limitations'])

    def test_strict_fields_and_bounds(self):
        record = {'algorithm': 'AES', 'mode': 'GCM', 'key': '00' * 16,
                  'nonce': '00' * 12, 'ciphertext': '',
                  'tag': '58e2fccefa7e3061367f1d57a4e7455a'}
        for bad in ({**record, 'key': '00 ' * 16},
                    {**record, 'key': '00' * 15},
                    {**record, 'ciphertext': '0'},
                    {**record, 'tag': 'ab' * 3},
                    {**record, 'extra': '00'},
                    {**record, 'algorithm': 'DES'},
                    {**record, 'iv': '00' * 16},
                    {**record, 'padding': 'pkcs7'},
                    {**record, 'ciphertext': '00' * ((1 << 20) + 1)}):
            with self.subTest(keys=tuple(bad)):
                self.assertEqual(decrypt_declared([bad], max_output=1 << 20), [])
        self.assertEqual(decrypt_declared([record] * 33, max_output=0), [])
        self.assertEqual(decrypt_declared([record], max_output=-1), [])
        self.assertEqual(decrypt_declared([record], max_output=True), [])
        self.assertEqual(decrypt_declared([{**record, 'ciphertext': '0388dace60b6a392f328c2b971b2fe78',
                                            'tag': 'ab6e47d42cec13bdf53a67b21257bddf'}],
                                          max_output=15), [])


if __name__ == '__main__':
    unittest.main()
