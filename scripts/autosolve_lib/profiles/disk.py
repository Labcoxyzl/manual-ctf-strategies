"""Read-only, bounded partition inventory and targeted allocated-file extraction."""

import hashlib
import os
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


MMLS = shutil.which('mmls') or '/usr/bin/mmls'
FLS = shutil.which('fls') or '/usr/bin/fls'
ICAT = shutil.which('icat') or '/usr/bin/icat'
_PARTITION = re.compile(r'^\s*\d{3}:\s+(\d{3}(?::\d{3})?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$')
_ENTRY = re.compile(r'^r/r\s+(\d+(?:-\d+)*):\t(.+)$')


def is_raw_ext_image(head: bytes, size: int) -> bool:
    """Recognize a whole-file ext filesystem from bounded superblock geometry."""
    if len(head) < 2048 or size < 2048:
        return False
    if head[1080:1082] != b'\x53\xef':
        return False
    sb = head[1024:2048]
    u16 = lambda offset: int.from_bytes(sb[offset:offset + 2], 'little')
    u32 = lambda offset: int.from_bytes(sb[offset:offset + 4], 'little')
    log_block = u32(24)
    if log_block > 2:
        return False
    block_size = 1024 << log_block
    blocks = u32(4)
    inode_size = u16(88) if u32(76) else 128
    return (u32(0) > 0 and blocks > 0 and
            u32(20) == (1 if block_size == 1024 else 0) and
            0 < u32(32) <= block_size * 8 and
            0 < u32(40) <= block_size * 8 and
            inode_size >= 128 and inode_size <= block_size and
            inode_size & (inode_size - 1) == 0 and
            blocks * block_size <= size)


def _run(argv: list[str], deadline: float, limit: int, target=None):
    """Stream one native tool with a byte and wall-time cap; never keep partial extraction."""
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        return b'', f'{Path(argv[0]).name} unavailable: {error}'
    output = bytearray()
    errors = bytearray()
    size = 0
    problem = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, False)
        selector.register(process.stderr, selectors.EVENT_READ, True)
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                problem = f'{Path(argv[0]).name} timed out; inventory incomplete'
                break
            for key, _ in selector.select(left):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data:
                    errors.extend(chunk[:max(0, 4096 - len(errors))])
                elif size + len(chunk) > limit:
                    problem = f'{Path(argv[0]).name} byte limit reached; inventory incomplete'
                    break
                else:
                    size += len(chunk)
                    if target is None:
                        output.extend(chunk)
                    else:
                        target.write(chunk)
            if problem:
                break
    finally:
        selector.close()
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if problem is None and process.returncode:
        detail = errors.decode('utf-8', 'replace').strip().splitlines()
        problem = f'{Path(argv[0]).name} exited {process.returncode}: {(detail[0] if detail else "unknown error")[:300]}'
    return bytes(output), problem


def _safe_target(value: str) -> bool:
    return (isinstance(value, str) and value and not value.startswith('/') and
            not any(ord(char) < 32 for char in value) and
            all(part not in ('', '.', '..') for part in value.split('/')))


def inspect_disk(path: Path, output_dir: Path, *, target_paths: list[str], timeout: float,
                 max_output: int, max_files: int, max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Inventory partitions or a raw ext volume and stage exact selected regular files.

    The caller supplies exact filesystem-relative paths. Offsets come from a validated
    mmls listing or a raw ext superblock and are passed to Sleuth Kit in sectors.
    """
    if timeout <= 0 or max_output <= 0 or max_files < 0 or max_total_bytes < 0:
        raise ValueError('disk limits must be positive or nonnegative as applicable')
    if any(not _safe_target(value) for value in target_paths):
        raise ValueError('target paths must be relative regular-file paths')
    path, output_dir = Path(path), Path(output_dir)
    if output_dir.is_symlink():
        raise ValueError('disk output directory must not be a symlink')
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError('disk output directory must differ from source directory')
    try:
        source = path.lstat()
    except OSError as error:
        return [], [f'disk image unavailable: {error}']
    if not stat.S_ISREG(source.st_mode):
        return [], ['disk image must be an explicit regular file']
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    deadline = time.monotonic() + timeout
    image = str(path.resolve())
    records: list[dict] = []
    warnings: list[str] = []
    with path.open('rb') as source_file:
        raw = is_raw_ext_image(source_file.read(2048), source.st_size)
    if raw:
        sector_size = 512
        partitions = [('raw', 0, 'raw ext filesystem (no partition table)')]
        records.append({'kind': 'partition', 'slot': 'raw', 'offset_sectors': 0,
                        'offset_bytes': 0, 'length_sectors': source.st_size // 512,
                        'sector_size': sector_size, 'description': partitions[0][2],
                        'locator': 'raw ext filesystem sector 0'})
    else:
        listing, error = _run([MMLS, image], deadline, max_output)
        if error:
            return records, [f'partition listing: {error}']
        text = listing.decode('utf-8', 'replace')
        match = re.search(r'Units are in (\d+)-byte sectors', text)
        if not match:
            return records, ['partition listing has no sector size']
        sector_size = int(match.group(1))
        if sector_size < 512 or sector_size > 4096 or sector_size & (sector_size - 1):
            return records, ['unsupported partition sector size']
        partitions = []
        for line in text.splitlines():
            match = _PARTITION.match(line)
            if not match:
                continue
            slot, start, end, length, description = match.groups()
            start, end, length = int(start), int(end), int(length)
            if not length or end != start + length - 1 or (start + length) * sector_size > source.st_size:
                warnings.append(f'partition {slot}: invalid or out-of-range offset')
                continue
            if len(partitions) >= 16:
                warnings.append('partition count limit reached; inventory incomplete')
                break
            partitions.append((slot, start, description))
            records.append({'kind': 'partition', 'slot': slot, 'offset_sectors': start,
                            'offset_bytes': start * sector_size, 'length_sectors': length,
                            'sector_size': sector_size, 'description': description,
                            'locator': f'partition {slot} sector {start}'})
    if not partitions:
        warnings.append('no valid allocated partitions found in volume table')
        return records, warnings

    targets = set(target_paths)
    total = 0
    staged = 0
    for slot, offset, _ in partitions:
        volume = 'raw ext filesystem' if raw else f'partition {slot}'
        listing, error = _run([FLS, '-u', '-r', '-p', '-b', str(sector_size),
                               '-o', str(offset), image],
                              deadline, max_output)
        if error:
            warnings.append(f'{volume} filesystem listing: {error}')
            continue
        for line in listing.decode('utf-8', 'replace').splitlines():
            match = _ENTRY.match(line)
            if not match:
                continue
            inode, name = match.groups()
            if not _safe_target(name):
                warnings.append(f'{volume} inode {inode}: unsafe or unsupported path')
                continue
            locator = f'{volume} sector {offset} inode {inode} path {name}'
            records.append({'kind': 'entry', 'slot': slot, 'offset_sectors': offset,
                            'inode': inode, 'file_path': name, 'locator': locator})
            if name not in targets:
                continue
            if staged >= max_files:
                warnings.append(f'{locator}: file count limit reached')
                continue
            remaining = max_total_bytes - total
            if remaining <= 0:
                warnings.append(f'{locator}: extracted byte limit reached')
                continue
            fd, temporary = tempfile.mkstemp(prefix='.disk-stage-', dir=output_dir)
            try:
                with os.fdopen(fd, 'wb') as target:
                    _, error = _run([ICAT, '-b', str(sector_size), '-o', str(offset), image, inode],
                                    deadline, remaining, target)
                if error:
                    warnings.append(f'{locator}: {error}')
                    continue
                staged_path = Path(temporary)
                size = staged_path.stat().st_size
                if size > remaining:
                    warnings.append(f'{locator}: extracted byte limit reached')
                    continue
                with staged_path.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                published = output_dir / f'{staged:06d}-{uuid.uuid4().hex}'
                os.link(temporary, published)
                total += size
                staged += 1
                records.append({'kind': 'file', 'slot': slot, 'offset_sectors': offset,
                                'inode': inode, 'file_path': name, 'locator': locator,
                                'path': published, 'sha256': digest, 'size': size})
            finally:
                os.unlink(temporary)
    return records, warnings
