"""Exact, bounded textbook RSA relationships over supplied public parameters.

Results prove a modular preimage, not padding, text encoding, original byte
width, or a challenge flag. Unsupported sizes produce no recovery.
"""

from itertools import combinations
import math
import time


MAX_PARAMETERS = 32
MAX_MODULUS_BITS = 4096
MAX_EXPONENT = 65537
LIMITATIONS = ('Textbook RSA integer only; original leading zero bytes and padding are unknown. '
               'At most 32 records, 4096-bit n, e <= 65537, root e <= 17, and 5 seconds. '
               'Broadcast requires an explicit shared label, pairwise coprime moduli, and at most 12 records per label/exponent. '
               'Close-prime search is limited to 512 Fermat steps. '
               'No general factor search, primality proof, or strong-key recovery.')


def parse_public_key(data: str | bytes) -> dict[str, int] | None:
    """Read one canonical PEM/DER RSA public key, never private key material."""
    if isinstance(data, str):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            return None
    if not isinstance(data, bytes) or not 0 < len(data) <= 16384:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, load_der_public_key, load_pem_public_key)

        if data.lstrip().startswith(b'-----BEGIN '):
            stripped = data.strip()
            if stripped.startswith(b'-----BEGIN PUBLIC KEY-----'):
                ending = b'-----END PUBLIC KEY-----'
            elif stripped.startswith(b'-----BEGIN RSA PUBLIC KEY-----'):
                ending = b'-----END RSA PUBLIC KEY-----'
            else:
                return None
            if stripped.count(b'-----BEGIN ') != 1 or not stripped.endswith(ending):
                return None
            key = load_pem_public_key(data)
        else:
            key = load_der_public_key(data)
            if data not in (key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
                            key.public_bytes(Encoding.DER, PublicFormat.PKCS1)):
                return None
        if not isinstance(key, RSAPublicKey):
            return None
        public = key.public_numbers()
        if (public.n <= 3 or public.n % 2 == 0 or public.n.bit_length() > MAX_MODULUS_BITS
                or not 2 <= public.e <= MAX_EXPONENT):
            return None
        return {'n': public.n, 'e': public.e}
    except (ImportError, TypeError, ValueError):
        return None


def _integer_root(value: int, exponent: int, deadline: float) -> int | None:
    low, high = 0, 1 << ((value.bit_length() + exponent - 1) // exponent)
    while low < high:
        if time.monotonic() >= deadline:
            return None
        middle = (low + high + 1) // 2
        if pow(middle, exponent) <= value:
            low = middle
        else:
            high = middle - 1
    return low if pow(low, exponent) == value else None


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r, old_s, s, old_t, t = a, b, 1, 0, 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def _factored_preimage(n: int, e: int, c: int, p: int, q: int) -> int | None:
    if p <= 1 or q <= 1 or p == q or p * q != n:
        return None
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return None
    message = pow(c, pow(e, -1, phi), n)
    return message if pow(message, e, n) == c else None


def _wiener_factors(n: int, e: int, deadline: float) -> tuple[int, int, int] | None:
    numerator, denominator = e, n
    previous_num, current_num = 0, 1
    previous_den, current_den = 1, 0
    while denominator and time.monotonic() < deadline:
        quotient, remainder = divmod(numerator, denominator)
        numerator, denominator = denominator, remainder
        next_num = quotient * current_num + previous_num
        next_den = quotient * current_den + previous_den
        previous_num, current_num = current_num, next_num
        previous_den, current_den = current_den, next_den
        if not next_num or (e * next_den - 1) % next_num:
            continue
        phi = (e * next_den - 1) // next_num
        total = n - phi + 1
        discriminant = total * total - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root == discriminant and (total + root) % 2 == 0:
            p, q = (total + root) // 2, (total - root) // 2
            if p > 1 and q > 1 and p * q == n:
                return p, q, next_den
    return None


def _verified(method: str, family: str, plaintext: int, sources: list[int],
              ciphertext_index: int | None, evidence: dict) -> dict:
    hex_value = f'{plaintext:x}'
    return {'family': family, 'method': method, 'status': 'validated_transform',
            'plaintext_int': str(plaintext), 'plaintext_hex': hex_value.zfill(len(hex_value) + len(hex_value) % 2),
            'source_indices': sources, 'ciphertext_index': ciphertext_index,
            'evidence': {'reencryption_verified': True, **evidence}, 'limitations': LIMITATIONS}


def inspect_rsa(parameters: list[dict], *, budget_seconds: float = 5.0) -> list[dict]:
    """Recover only exact raw RSA integer preimages from at most 32 supplied records.

    A shared nontrivial factor may decrypt either member. Common-modulus recovery
    requires the same explicit message_label and coprime exponents. Exact root
    recovery requires c == m**e < n for e <= 17. Broadcast recovery requires
    one explicit label across e pairwise-coprime moduli. All results are re-encrypted;
    unrelated keys, inconsistent labels/messages, and timeouts return no claim.
    """
    if (not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS
            or not isinstance(budget_seconds, (int, float)) or not math.isfinite(budget_seconds)
            or budget_seconds <= 0):
        return []
    deadline = time.monotonic() + min(float(budget_seconds), 5.0)
    valid = []
    for index, record in enumerate(parameters):
        if not isinstance(record, dict):
            continue
        n, e, c = (record.get(key) for key in ('n', 'e', 'c'))
        if (any(type(value) is not int for value in (n, e, c)) or n <= 3 or n % 2 == 0
                or n.bit_length() > MAX_MODULUS_BITS or not 2 <= e <= MAX_EXPONENT
                or not 0 <= c < n):
            continue
        label = record.get('message_label')
        valid.append((index, n, e, c, label if isinstance(label, str) and 0 < len(label) <= 128 else None))

    results = []
    for index, n, e, c, _ in valid:
        if time.monotonic() >= deadline:
            return results
        if e <= 17:
            message = _integer_root(c, e, deadline)
            if message is not None and pow(message, e, n) == c:
                results.append(_verified('exact_low_exponent_root', 'ENC06', message,
                                         [index], index, {'exact_power': True}))
        if factors := _wiener_factors(n, e, deadline):
            p, q, private = factors
            message = _factored_preimage(n, e, c, p, q)
            if message is not None:
                results.append(_verified('small_private_exponent', 'ENC06', message,
                                         [index], index, {'private_exponent': str(private),
                                                         'factor_a': str(p), 'factor_b': str(q),
                                                         'factors_multiply_to_modulus': True}))
        candidate = math.isqrt(n)
        candidate += candidate * candidate < n
        for step in range(512):
            if time.monotonic() >= deadline:
                return results
            square = candidate * candidate - n
            root = math.isqrt(square)
            if root * root == square:
                p, q = candidate - root, candidate + root
                message = _factored_preimage(n, e, c, p, q)
                if message is not None:
                    results.append(_verified('close_prime_factor', 'ENC06', message,
                                             [index], index, {'factor_a': str(p),
                                                             'factor_b': str(q),
                                                             'fermat_steps': step,
                                                             'factors_multiply_to_modulus': True}))
                break
            candidate += 1

    for offset, (i, n1, e1, c1, label1) in enumerate(valid):
        for j, n2, e2, c2, label2 in valid[offset + 1:]:
            if time.monotonic() >= deadline:
                return results
            if n1 == n2:
                if not label1 or label1 != label2 or math.gcd(e1, e2) != 1:
                    continue
                if math.gcd(c1, n1) != 1 or math.gcd(c2, n1) != 1:
                    continue
                _, a, b = _extended_gcd(e1, e2)
                try:
                    message = pow(c1, a, n1) * pow(c2, b, n1) % n1
                except ValueError:
                    continue
                if pow(message, e1, n1) == c1 and pow(message, e2, n1) == c2:
                    results.append(_verified('common_modulus', 'ENC07', message,
                                             [i, j], None, {'message_label': label1,
                                                            'both_equations_verified': True}))
                continue
            factor = math.gcd(n1, n2)
            if factor <= 1 or factor >= min(n1, n2):
                continue
            for target, n, e, c in ((i, n1, e1, c1), (j, n2, e2, c2)):
                other = n // factor
                message = _factored_preimage(n, e, c, factor, other)
                if message is not None:
                    results.append(_verified('shared_factor', 'ENC07', message,
                                             [i, j], target, {'factor': str(factor),
                                                              'factors_multiply_to_modulus': True}))

    groups = {}
    for record in valid:
        if record[4] and 2 <= record[2] <= 17:
            groups.setdefault((record[4], record[2]), []).append(record)
    for (label, exponent), group in groups.items():
        if len(group) < exponent or len(group) > 12:
            continue
        for subset in combinations(group, exponent):
            if time.monotonic() >= deadline:
                return results
            moduli = [row[1] for row in subset]
            if any(math.gcd(left, right) != 1
                   for offset, left in enumerate(moduli) for right in moduli[offset + 1:]):
                continue
            product = math.prod(moduli)
            combined = sum(row[3] * (product // row[1])
                           * pow(product // row[1], -1, row[1]) for row in subset) % product
            message = _integer_root(combined, exponent, deadline)
            if message is not None and all(pow(message, exponent, row[1]) == row[3]
                                           for row in subset):
                results.append(_verified('declared_broadcast', 'ENC07', message,
                                         [row[0] for row in subset], None,
                                         {'message_label': label, 'all_equations_verified': True,
                                          'pairwise_coprime_moduli': True, 'exact_crt_root': True}))
                break
    return results
