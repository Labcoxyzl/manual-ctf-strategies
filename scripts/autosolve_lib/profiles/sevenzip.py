"""Bounded 7z member streaming with private password input."""

import hashlib
import os
import resource
import subprocess
import tempfile
import uuid
import zlib
from pathlib import Path


def _invoke(executable, args, password, output_dir, limit):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (max(1, limit), max(1, limit)))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    fd, name = tempfile.mkstemp(prefix='.7z-stage-', dir=output_dir)
    try:
        with os.fdopen(fd, 'wb') as output:
            result = subprocess.run([executable, *args], input=(password + b'\n' if password is not None else b''),
                                    stdout=output, stderr=subprocess.DEVNULL, timeout=10,
                                    cwd=output_dir, preexec_fn=limits)
        return result.returncode, Path(name)
    except Exception:
        os.unlink(name)
        raise


def _listing(raw):
    prompt = b'\nEnter password (will not be echoed):\n'
    if raw.startswith(prompt):
        raw = raw[len(prompt):]
    if not raw:
        return []
    blocks = raw.decode('utf-8').strip().split('\n\n')
    rows = []
    names = set()
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition(' = ')
            if not separator or key in fields:
                raise ValueError('ambiguous 7z member listing')
            fields[key] = value
        name = fields['Path']
        parts = name.split('/')
        attributes = fields['Attributes'].split()
        if (not name or name[0] in '/-@' or '\\' in name or '\x00' in name or '\r' in name
                or ':' in parts[0] or any(part in ('', '.', '..') for part in parts)
                or name in names or len(name) > 1024):
            raise ValueError('unsafe or ambiguous 7z member path')
        names.add(name)
        size = int(fields['Size'])
        if size < 0 or fields['Encrypted'] not in ('+', '-'):
            raise ValueError('invalid 7z member metadata')
        kind = attributes[-1][0] if attributes else ''
        rows.append({'member': name, 'size': size, 'encrypted': fields['Encrypted'] == '+',
                     'regular': kind == '-' and not any(key in fields for key in ('Symbolic Link', 'Hard Link')),
                     'crc': fields.get('CRC', '')})
    return rows


def extract_7z(path: Path, output_dir: Path, *, max_members: int, max_total_bytes: int,
               max_member_bytes: int, passwords: list[bytes], executable: str) -> tuple[list[dict], list[str]]:
    """Extract regular members by exact name without passing passwords in argv."""
    if min(max_members, max_total_bytes, max_member_bytes) < 0:
        raise ValueError('7z limits must be nonnegative')
    path = path.absolute()
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('7z output directory must be private and not a symlink')
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    warnings = []
    results = []
    with path.open('rb') as source:
        header = source.read(32)
    if (len(header) != 32 or not header.startswith(b'7z\xbc\xaf\x27\x1c')
            or zlib.crc32(header[12:32]) != int.from_bytes(header[8:12], 'little')):
        return [], ['invalid 7z archive header']

    listing = None
    header_password = None
    for candidate in [None, *passwords]:
        code, listing_path = _invoke(executable, ['l', '-slt', '-ba', '-spd', '-sccUTF-8', str(path)],
                                     candidate, output_dir, 1024 * 1024)
        try:
            if code == 0:
                listing = _listing(listing_path.read_bytes())
                header_password = candidate
                break
        except (UnicodeError, ValueError, KeyError):
            return [], ['unsafe or ambiguous 7z member listing']
        finally:
            listing_path.unlink()
    if listing is None:
        return [], [('supplied passwords did not validate or archive is corrupt' if passwords
                     else 'password required or archive is corrupt')]

    total = 0
    for index, row in enumerate(listing):
        if index >= max_members:
            warnings.append(f'member {index}: member limit reached')
            break
        name = row['member']
        if not row['regular']:
            warnings.append(f'member {index} ({name!r}): unsafe path or file type')
            continue
        remaining = min(max_member_bytes, max_total_bytes - total)
        if row['size'] > remaining:
            warnings.append(f'member {index} ({name!r}): expanded byte limit reached')
            continue
        candidates = ([header_password] if header_password is not None else passwords)
        if not row['encrypted']:
            candidates = [None]
        if row['encrypted'] and not candidates:
            warnings.append(f'member {index} ({name!r}): password required')
            continue
        verified = False
        for candidate in candidates:
            code, staged = _invoke(executable, ['e', '-so', '-spd', str(path), name],
                                   candidate, output_dir, remaining + 1)
            try:
                if code or staged.stat().st_size != row['size']:
                    continue
                digest = hashlib.sha256()
                crc = 0
                with staged.open('rb') as source:
                    while chunk := source.read(65536):
                        digest.update(chunk)
                        crc = zlib.crc32(chunk, crc)
                if row['crc'] and f'{crc:08X}' != row['crc'].upper():
                    continue
                published = output_dir / f'{index:06d}-{uuid.uuid4().hex}'
                os.link(staged, published)
                results.append({'path': published, 'member': name, 'index': index,
                                'sha256': digest.hexdigest(), 'size': row['size'],
                                'encrypted': row['encrypted']})
                total += row['size']
                verified = True
                break
            finally:
                staged.unlink()
        if not verified:
            warnings.append(f'member {index} ({name!r}): ' +
                            ('supplied passwords did not validate or archive is corrupt' if row['encrypted']
                             else 'member extraction failed or archive is corrupt'))
    return results, warnings
