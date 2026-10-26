"""Bounded AES decryption for explicitly supplied keys, modes, and parameters."""

import re


MAX_RECORDS = 32
MAX_BYTES = 1 << 20
_HEX = re.compile(r'[0-9a-fA-F]*\Z')
_FIELDS = {'algorithm', 'mode', 'key', 'nonce', 'iv', 'ciphertext', 'tag', 'aad', 'padding'}


def _bytes(value: object, maximum: int) -> bytes | None:
    if (type(value) is not str or len(value) > 2 * maximum or len(value) % 2
            or not _HEX.fullmatch(value)):
        return None
    return bytes.fromhex(value)


def decrypt_declared(records: list[dict], *, max_output: int) -> list[dict]:
    """Decrypt at most 32 declared AES records; never infer parameters or trust text scores.

    Hex fields are literal bytes. GCM requires nonce and tag, CBC requires IV and
    optionally ``padding='pkcs7'``, and CTR requires its full 16-byte counter
    block as ``nonce``. Malformed or failed records produce no plaintext row.
    """
    if (type(records) is not list or len(records) > MAX_RECORDS
            or type(max_output) is not int or max_output < 0):
        return []
    limit = min(max_output, MAX_BYTES)
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    results = []
    for index, record in enumerate(records):
        if (type(record) is not dict or set(record) - _FIELDS
                or record.get('algorithm') != 'AES'
                or record.get('mode') not in ('GCM', 'CBC', 'CTR')):
            continue
        mode = record['mode']
        key = _bytes(record.get('key'), 32)
        ciphertext = _bytes(record.get('ciphertext'), MAX_BYTES)
        if key is None or len(key) not in (16, 24, 32) or ciphertext is None:
            continue
        if len(ciphertext) > limit + (16 if mode == 'CBC' else 0):
            continue
        if mode == 'GCM':
            if 'iv' in record or 'padding' in record:
                continue
            nonce = _bytes(record.get('nonce'), 128)
            tag = _bytes(record.get('tag'), 16)
            aad = _bytes(record.get('aad', ''), MAX_BYTES)
            if (nonce is None or not 8 <= len(nonce) <= 128 or tag is None
                    or not 4 <= len(tag) <= 16 or aad is None):
                continue
            try:
                decryptor = Cipher(algorithms.AES(key), modes.GCM(
                    nonce, tag, min_tag_length=len(tag))).decryptor()
                decryptor.authenticate_additional_data(aad)
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except (InvalidTag, ValueError):
                continue
            evidence = {'tag_verified': True, 'tag_bytes': len(tag)}
            status = 'validated_transform'
            limitation = 'Authenticated relation verified; challenge meaning remains unverified.'
        elif mode == 'CBC':
            if 'nonce' in record or 'tag' in record or 'aad' in record:
                continue
            iv = _bytes(record.get('iv'), 16)
            declared_padding = record.get('padding', 'none')
            if (iv is None or len(iv) != 16 or declared_padding not in ('none', 'pkcs7')
                    or len(ciphertext) % 16):
                continue
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            if declared_padding == 'pkcs7':
                try:
                    unpadder = padding.PKCS7(128).unpadder()
                    plaintext = unpadder.update(padded) + unpadder.finalize()
                except ValueError:
                    continue
                evidence = {'padding_verified': True, 'authenticated': False}
                status = 'candidate'
                limitation = ('PKCS#7 padding is not authentication; a wrong key can '
                              'occasionally pass the padding check.')
            else:
                plaintext = padded
                evidence = {'authenticated': False}
                status = 'candidate'
                limitation = 'CBC without authentication cannot confirm the supplied key or plaintext.'
        else:
            if any(field in record for field in ('iv', 'tag', 'aad', 'padding')):
                continue
            nonce = _bytes(record.get('nonce'), 16)
            if nonce is None or len(nonce) != 16:
                continue
            decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            evidence = {'authenticated': False}
            status = 'candidate'
            limitation = 'CTR without authentication cannot confirm the supplied key or plaintext.'
        if len(plaintext) <= limit:
            results.append({'family': 'ENC08', 'method': f'aes_{mode.lower()}',
                            'status': status, 'plaintext': plaintext,
                            'source_index': index, 'evidence': evidence,
                            'limitations': limitation})
    return results
