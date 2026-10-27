"""Bounded offline JWT/JWS inspection with explicitly supplied verification material."""

import base64
import binascii
import hashlib
import hmac
import json
import re
import time

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


_TOKEN = re.compile(rb'(?<![A-Za-z0-9_.-])([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){2,4})(?![A-Za-z0-9_.-])')
_HASHES = {'HS256': (hashlib.sha256, hashes.SHA256),
           'HS384': (hashlib.sha384, hashes.SHA384),
           'HS512': (hashlib.sha512, hashes.SHA512),
           'RS256': (hashlib.sha256, hashes.SHA256),
           'RS384': (hashlib.sha384, hashes.SHA384),
           'RS512': (hashlib.sha512, hashes.SHA512)}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result


def _decode(part):
    if not part or not re.fullmatch(rb'[A-Za-z0-9_-]+', part):
        raise ValueError('invalid base64url')
    raw = base64.b64decode(part + b'=' * (-len(part) % 4), altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b'=') != part or len(raw) > 8192:
        raise ValueError('noncanonical or oversized base64url')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if not isinstance(value, dict):
        raise ValueError('JWT JSON value must be object')
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    return value


def _material(value, limit):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes) or not 0 < len(value) <= limit:
        raise ValueError('verification material must be bounded bytes or text')
    return value


def _public_key(value):
    for loader in (serialization.load_pem_public_key, serialization.load_der_public_key):
        try:
            key = loader(value)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        return key
    return None


def inspect_jwt(data: bytes, *, keys=None, words=None, now=None,
                max_input_bytes=1024 * 1024, max_tokens=64,
                max_token_bytes=16384):
    """Return private-report records and warnings; local verification never implies server acceptance."""
    if not isinstance(data, bytes):
        raise ValueError('JWT input must be bytes')
    if (not isinstance(max_input_bytes, int) or isinstance(max_input_bytes, bool)
            or not 0 < max_input_bytes <= 4 * 1024 * 1024
            or not isinstance(max_tokens, int) or isinstance(max_tokens, bool)
            or not 0 < max_tokens <= 64
            or not isinstance(max_token_bytes, int) or isinstance(max_token_bytes, bool)
            or not 0 < max_token_bytes <= 16384
            or now is not None and (not isinstance(now, int) or isinstance(now, bool))):
        raise ValueError('JWT limits and time must be bounded integers')
    if len(data) > max_input_bytes:
        return [], ['JWT input byte limit reached']
    keys = [] if keys is None else keys
    words = [] if words is None else words
    if not isinstance(keys, (list, tuple)) or len(keys) > 32:
        raise ValueError('at most 32 declared JWT keys allowed')
    if not isinstance(words, (list, tuple)) or len(words) > 1024:
        raise ValueError('at most 1024 JWT words allowed')
    declared = []
    for index, item in enumerate(keys):
        if (not isinstance(item, dict) or set(item) - {'alg', 'key', 'kid'}
                or not isinstance(item.get('alg'), str) or item['alg'] not in _HASHES
                or 'kid' in item and (not isinstance(item['kid'], str) or len(item['kid']) > 256)):
            raise ValueError('JWT key requires a supported explicit algorithm and optional bounded key ID')
        material = _material(item.get('key'), 4096)
        algorithm = item['alg']
        if algorithm.startswith('RS'):
            material = _public_key(material)
            if not isinstance(material, rsa.RSAPublicKey):
                raise ValueError('RS key must be an RSA public key')
        elif material.startswith((b'-----BEGIN ', b'ssh-rsa ')) or _public_key(material) is not None:
            material = None
        declared.append((index, algorithm, item.get('kid'), material))
    dictionary = []
    for word in words:
        material = _material(word, 256)
        dictionary.append(None if material.startswith((b'-----BEGIN ', b'ssh-rsa '))
                          or _public_key(material) is not None else material)
    observed_at = int(time.time()) if now is None else now
    records, warnings = [], []
    for candidate_index, match in enumerate(_TOKEN.finditer(data)):
        if candidate_index >= max_tokens:
            warnings.append('JWT token count limit reached')
            break
        token = match.group(1)
        if len(token) > max_token_bytes:
            warnings.append('JWT token byte limit reached')
            continue
        parts = token.split(b'.')
        if len(parts) != 3:
            warnings.append('unsupported compact token; encrypted JWE is not inspected')
            continue
        try:
            header, claims = _decode(parts[0]), _decode(parts[1])
            signature = (base64.b64decode(parts[2] + b'=' * (-len(parts[2]) % 4),
                                          altchars=b'-_', validate=True) if parts[2] else b'')
            if (parts[2] and (not re.fullmatch(rb'[A-Za-z0-9_-]+', parts[2])
                              or base64.urlsafe_b64encode(signature).rstrip(b'=') != parts[2])):
                raise ValueError('invalid signature encoding')
        except (ValueError, UnicodeError, binascii.Error, RecursionError):
            warnings.append('malformed compact JWT at byte offset ' + str(match.start(1)))
            continue
        algorithm = header.get('alg')
        expired = claims.get('exp')
        expired = (expired <= observed_at if isinstance(expired, (int, float))
                   and not isinstance(expired, bool) else None)
        row = {'family': 'WEB04', 'offset': match.start(1),
               'token_sha256': hashlib.sha256(token).hexdigest(),
               'header': header, 'claims': claims, 'claims_trust': 'untrusted',
               'algorithm': algorithm, 'expired': expired,
               'signature_verified': False, 'server_accepted': None,
               'status': 'candidate',
               'limitations': 'Local signature verification cannot establish server acceptance.'}
        records.append(row)
        if (not isinstance(algorithm, str) or algorithm not in _HASHES or not signature or 'crit' in header
                or 'b64' in header or not isinstance(header.get('kid'), (str, type(None)))):
            row['signature_relation'] = 'unsupported_or_unverified'
            continue
        signing_input = parts[0] + b'.' + parts[1]
        for index, key_alg, kid, material in sorted(
                declared, key=lambda item: item[2] != header.get('kid')):
            if key_alg != algorithm or material is None:
                continue
            try:
                if algorithm.startswith('HS'):
                    verified = hmac.compare_digest(
                        hmac.digest(material, signing_input, _HASHES[algorithm][0]), signature)
                else:
                    material.verify(signature, signing_input, padding.PKCS1v15(),
                                    _HASHES[algorithm][1]())
                    verified = True
            except InvalidSignature:
                verified = False
            if verified:
                row.update(status='validated_transform', signature_verified=True,
                           signature_relation='supplied_key_verified',
                           key_source='supplied_key', key_index=index,
                           kid_matches=(kid == header.get('kid') if kid is not None else None))
                break
        if not row['signature_verified'] and algorithm.startswith('HS'):
            for index, word in enumerate(dictionary):
                if word is not None and hmac.compare_digest(hmac.digest(word, signing_input, _HASHES[algorithm][0]),
                                       signature):
                    row.update(status='validated_transform', signature_verified=True,
                               signature_relation='wordlist_verified',
                               key_source='wordlist', key_index=index)
                    break
        if not row['signature_verified']:
            row['signature_relation'] = 'no_local_key_match'
    return records, warnings
