"""Stream bounded, verified 7z members into private staging."""

import hashlib
import os
import re
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
            result = subprocess.run([executable, *args], input=password + b'\n' if password is not None else b'',
                                    stdout=output, stderr=subprocess.DEVNULL, timeout=10,
                                    cwd=output_dir, preexec_fn=limits)
        return result.returncode, Path(name)
    except BaseException:
        os.unlink(name)
        raise


def _listing(raw):
    prompt = b'\nEnter password (will not be echoed):\n'
    if raw.startswith(prompt):
        raw = raw[len(prompt):]
    if not raw:
        return []
    rows = []
    names = set()
    for block in raw.decode('utf-8').strip().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(' = ')
            if not sep or key in fields:
                raise ValueError('ambiguous 7z member listing')
            fields[key] = value
        name = fields['Path']
        parts = name.split('/')
        if (not name or name[0] in '/-@' or '\\' in name or '\x00' in name or '\r' in name
                or ':' in parts[0] or any(part in ('', '.', '..') for part in parts)
                or name in names or len(name) > 1024):
            raise ValueError('unsafe or ambiguous 7z member path')
        names.add(name)
        size = int(fields['Size'])
        if size < 0 or fields['Encrypted'] not in ('+', '-'):
            raise ValueError('invalid 7z member metadata')
        attributes = fields['Attributes'].split()
        flags = attributes[0] if attributes else ''
        mode = attributes[1] if len(attributes) == 2 else None
        # Windows entries need not carry a POSIX mode; D/L/d/8 are directory, reparse, device or volume.
        regular = (len(attributes) <= 2 and len(flags) == len(set(flags)) and
                   set(flags) <= set('RHSANTsCOIEVvXPUMB') and
                   (mode is None or re.fullmatch(r'-[rwxSsTt-]{9}', mode) is not None) and
                   fields.get('Folder', '-') == '-' and
                   not any('Link' in key or 'Reparse' in key for key in fields))
        rows.append({'member': name, 'size': size, 'encrypted': fields['Encrypted'] == '+',
                     'regular': regular,
                     'crc': fields.get('CRC', '')})
    return rows


def extract_7z(path: Path, output_dir: Path, *, max_members: int, max_total_bytes: int,
               max_member_bytes: int, passwords: list[bytes], executable: str) -> tuple[list[dict], list[str]]:
    """Extract exact regular names; passwords are stdin bytes, never process arguments."""
    if min(max_members, max_total_bytes, max_member_bytes) < 0:
        raise ValueError('7z limits must be nonnegative')
    path = path.absolute()
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('7z staging must be a separate private directory')
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.stat().st_mode & 0o077:
        raise ValueError('7z staging must not be readable by other users')
    with path.open('rb') as source:
        header = source.read(32)
    if (len(header) != 32 or not header.startswith(b'7z\xbc\xaf\x27\x1c')
            or zlib.crc32(header[12:32]) != int.from_bytes(header[8:12], 'little')):
        return [], ['invalid 7z archive header']

    listing = None
    header_password = None
    for candidate in [None, *passwords]:
        code, result = _invoke(executable, ['l', '-slt', '-ba', '-spd', '-sccUTF-8', str(path)],
                               candidate, output_dir, 1024 * 1024)
        try:
            if code and result.stat().st_size >= 1024 * 1024:
                return [], ['7z member listing byte limit reached']
            if code == 0:
                listing = _listing(result.read_bytes())
                header_password = candidate
                break
        except (UnicodeError, ValueError, KeyError):
            return [], ['unsafe or ambiguous 7z member listing']
        finally:
            result.unlink()
    if listing is None:
        return [], ['supplied passwords did not validate or archive is corrupt' if passwords
                    else 'password required or archive is corrupt']

    records = []
    warnings = []
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
        candidates = ([None] if not row['encrypted'] else
                      [header_password] if header_password is not None else passwords)
        if not candidates:
            warnings.append(f'member {index} ({name!r}): password required')
            continue
        for candidate in candidates:
            code, staged = _invoke(executable, ['e', '-so', '-spd', str(path), name],
                                   candidate, output_dir, remaining + 1)
            try:
                if code or staged.stat().st_size != row['size']:
                    continue
                digest = hashlib.sha256()
                crc = 0
                with staged.open('rb') as source:
                    while block := source.read(65536):
                        digest.update(block)
                        crc = zlib.crc32(block, crc)
                if row['crc'] and f'{crc:08X}' != row['crc'].upper():
                    continue
                published = output_dir / f'{index:06d}-{uuid.uuid4().hex}'
                os.link(staged, published)
                records.append({'path': published, 'member': name, 'index': index,
                                'sha256': digest.hexdigest(), 'size': row['size'],
                                'encrypted': row['encrypted']})
                total += row['size']
                break
            finally:
                staged.unlink()
        else:
            warnings.append(f'member {index} ({name!r}): ' +
                            ('supplied passwords did not validate or archive is corrupt'
                             if row['encrypted'] else 'member extraction failed or archive is corrupt'))
    return records, warnings
