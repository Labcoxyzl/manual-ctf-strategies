"""Bounded, read-only deleted-file recovery and verified PNG/ZIP carving."""

import hashlib
import io
import os
import re
import shutil
import stat
import struct
import tempfile
import time
import uuid
import zipfile
import zlib
from pathlib import Path

from .disk import FLS, ICAT, MMLS, _PARTITION, _run, _safe_target, is_raw_ext_image


BINWALK = shutil.which('binwalk') or '/usr/bin/binwalk'
_DELETED = re.compile(r'^r/r \* (\d+(?:-\d+)*)(\(realloc\))?:\t(.+)$')
_SIGNATURE = re.compile(rb'^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(PNG image|Zip archive data)\b', re.M)
_PNG = b'\x89PNG\r\n\x1a\n'


def _png_size(data: bytes) -> int | None:
    if not data.startswith(_PNG):
        return None
    cursor = 8
    shape = None
    compressed = []
    palette_entries = 0
    saw_end = False
    while cursor + 12 <= len(data):
        length = struct.unpack_from('>I', data, cursor)[0]
        if length > len(data) - cursor - 12:
            return None
        kind = data[cursor + 4:cursor + 8]
        chunk = data[cursor + 8:cursor + 8 + length]
        checksum = struct.unpack_from('>I', data, cursor + 8 + length)[0]
        if zlib.crc32(kind + chunk) != checksum:
            return None
        if cursor == 8:
            if kind != b'IHDR' or length != 13:
                return None
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', chunk)
            channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
            depths = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8),
                      4: (8, 16), 6: (8, 16)}
            if not channels or depth not in depths[color] or not 0 < width <= 32768 or not 0 < height <= 32768 or (compression, filtering, interlace) != (0, 0, 0):
                return None
            stride = 1 + (width * channels * depth + 7) // 8
            expected = height * stride
            if expected > 16 * 1024 * 1024:
                return None
            shape = (height, stride, expected)
        elif kind == b'PLTE':
            if compressed or palette_entries or color in (0, 4) or not 0 < length <= 768 or length % 3 or (color == 3 and length // 3 > 1 << depth):
                return None
            palette_entries = length // 3
        elif kind == b'IDAT':
            if color == 3 and not palette_entries:
                return None
            compressed.append(chunk)
        elif kind == b'IEND':
            if length:
                return None
            cursor += 12
            saw_end = True
            break
        cursor += 12 + length
    if not saw_end or not compressed or shape is None:
        return None
    height, stride, expected = shape
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(b''.join(compressed), expected + 1)
        pixels += decoder.flush(max(1, expected + 1 - len(pixels)))
    except zlib.error:
        return None
    if not decoder.eof or decoder.unused_data or len(pixels) != expected:
        return None
    if any(pixels[row * stride] > 4 for row in range(height)):
        return None
    return cursor


def _zip_size(data: bytes, deadline: float) -> int | None:
    if not data.startswith(b'PK\x03\x04'):
        return None
    cursor = 0
    while True:
        end = data.find(b'PK\x05\x06', cursor)
        if end < 0 or end + 22 > len(data):
            return None
        size = end + 22 + struct.unpack_from('<H', data, end + 20)[0]
        cursor = end + 4
        if size > len(data):
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(data[:size])) as archive:
                members = archive.infolist()
                if not members or len(members) > 64 or sum(item.file_size for item in members) > 16 * 1024 * 1024:
                    continue
                decoded = 0
                for item in members:
                    with archive.open(item) as stream:
                        while chunk := stream.read(65536):
                            decoded += len(chunk)
                            if decoded > 16 * 1024 * 1024 or time.monotonic() >= deadline:
                                return None
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, EOFError,
                NotImplementedError, zlib.error):
            continue
        return size


def _publish(output_dir: Path, temporary: str, ordinal: int) -> Path:
    path = output_dir / f'{ordinal:06d}-{uuid.uuid4().hex}'
    os.link(temporary, path)
    return path


def recover_disk(path: Path, output_dir: Path, *, timeout: float,
                 max_output: int = 2 * 1024 * 1024, max_files: int = 8,
                 max_total_bytes: int = 16 * 1024 * 1024,
                 max_source_bytes: int = 256 * 1024 * 1024) -> tuple[list[dict], list[str]]:
    """Return deleted-entry evidence and exact staged bytes; format-verify carved objects."""
    if min(timeout, max_output, max_files, max_total_bytes, max_source_bytes) <= 0:
        raise ValueError('disk recovery limits must be positive')
    path, output_dir = Path(path), Path(output_dir)
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        return [], ['disk image must be an explicit regular file']
    size = path.stat().st_size
    if size > max_source_bytes:
        return [], ['disk image exceeds recovery source byte limit']
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('disk output directory must be separate and not a symlink')
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError('disk output directory must be empty')
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    deadline = time.monotonic() + timeout
    image = str(path.resolve())
    rows, warnings = [], []
    total = 0
    with path.open('rb') as source_file:
        raw = is_raw_ext_image(source_file.read(2048), size)
    if raw:
        sector, partitions = 512, [('raw', 0)]
    else:
        partitions = []
        listing, error = _run([MMLS, image], deadline, max_output)
        if error:
            warnings.append(f'partition listing: {error}')
        else:
            match = re.search(rb'Units are in (\d+)-byte sectors', listing)
            sector = int(match.group(1)) if match else 0
            if sector not in (512, 1024, 2048, 4096):
                warnings.append('unsupported or missing partition sector size')
            else:
                for line in listing.decode('utf-8', 'replace').splitlines():
                    match = _PARTITION.match(line)
                    if not match:
                        continue
                    slot, start, end, length, _ = match.groups()
                    start, end, length = int(start), int(end), int(length)
                    if length and end == start + length - 1 and (start + length) * sector <= size:
                        partitions.append((slot, start))
                    else:
                        warnings.append(f'partition {slot}: invalid or out-of-range offset')
                    if len(partitions) >= 16:
                        warnings.append('partition count limit reached; deleted inventory incomplete')
                        break
                if not partitions:
                    warnings.append('no valid allocated partitions found')
    if partitions:
        count = 0
        for slot, offset in partitions:
            volume = 'raw ext filesystem' if raw else f'partition {slot}'
            listing, error = _run([FLS, '-d', '-F', '-r', '-p', '-b', str(sector),
                                   '-o', str(offset), image], deadline, max_output)
            if error:
                warnings.append(f'{volume} deleted listing: {error}')
                continue
            for line in listing.decode('utf-8', 'replace').splitlines():
                match = _DELETED.match(line)
                if not match:
                    continue
                if count >= 256:
                    warnings.append('deleted entry count limit reached; inventory incomplete')
                    break
                count += 1
                inode, realloc, name = match.groups()
                if not _safe_target(name):
                    warnings.append(f'{volume} inode {inode}: unsafe or unsupported path')
                    continue
                locator = f'{volume} sector {offset} deleted inode {inode} path {name}'
                row = {'kind': 'deleted_entry', 'slot': slot, 'offset_sectors': offset,
                       'inode': inode, 'file_path': name, 'locator': locator,
                       'uncertainty': 'deleted metadata may survive after content blocks are reused'}
                rows.append(row)
                if realloc:
                    warnings.append(f'{locator}: inode reallocated; content attribution unsafe')
                    continue
                if len([item for item in rows if item['kind'] in ('deleted_file', 'carved_file')]) >= max_files:
                    warnings.append('recovered file count limit reached; recovery incomplete')
                    break
                remaining = max_total_bytes - total
                if remaining <= 0:
                    warnings.append('recovered byte limit reached; recovery incomplete')
                    break
                fd, temporary = tempfile.mkstemp(prefix='.disk-recover-', dir=output_dir)
                try:
                    with os.fdopen(fd, 'wb') as target:
                        _, error = _run([ICAT, '-r', '-b', str(sector), '-o', str(offset),
                                         image, inode], deadline, remaining, target)
                    if error:
                        warnings.append(f'{locator}: {error}')
                        continue
                    with open(temporary, 'rb') as stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    extracted = Path(temporary).stat().st_size
                    published = _publish(output_dir, temporary, len(rows))
                    total += extracted
                    rows.append({**row, 'kind': 'deleted_file', 'path': published,
                                 'sha256': digest, 'size': extracted,
                                 'uncertainty': 'content may be stale, overwritten or fragmented; no original checksum'})
                finally:
                    os.unlink(temporary)
    if time.monotonic() >= deadline or total >= max_total_bytes:
        warnings.append('carving skipped after recovery budget')
        return rows, warnings
    signatures, error = _run([BINWALK, '-B', image], deadline, max_output)
    if error:
        warnings.append(f'signature scan: {error}')
        return rows, warnings
    seen = set()
    with path.open('rb') as source:
        for match in _SIGNATURE.finditer(signatures):
            if time.monotonic() >= deadline:
                warnings.append('recovery timed out; carving incomplete')
                break
            offset = int(match.group(1))
            kind = 'png' if match.group(2) == b'PNG image' else 'zip'
            if (offset, kind) in seen or offset >= size:
                continue
            seen.add((offset, kind))
            if len(seen) > 256:
                warnings.append('signature count limit reached; carving incomplete')
                break
            if len([item for item in rows if item['kind'] in ('deleted_file', 'carved_file')]) >= max_files:
                warnings.append('recovered file count limit reached; carving incomplete')
                break
            remaining = min(size - offset, max_total_bytes - total, 16 * 1024 * 1024)
            if remaining <= 0:
                warnings.append('recovered byte limit reached; carving incomplete')
                break
            source.seek(offset)
            candidate = source.read(remaining)
            carved = _png_size(candidate) if kind == 'png' else _zip_size(candidate, deadline)
            if carved is None:
                continue
            content = candidate[:carved]
            fd, temporary = tempfile.mkstemp(prefix='.disk-carve-', dir=output_dir)
            try:
                with os.fdopen(fd, 'wb') as target:
                    target.write(content)
                published = _publish(output_dir, temporary, len(rows))
            finally:
                os.unlink(temporary)
            total += carved
            rows.append({'kind': 'carved_file', 'format': kind, 'offset_bytes': offset,
                         'locator': f'byte offset {offset} verified {kind}',
                         'path': published, 'size': carved,
                         'sha256': hashlib.sha256(content).hexdigest(),
                         'verification': 'PNG chunk CRC and pixel stream' if kind == 'png'
                                         else 'ZIP directory and member CRC',
                         'uncertainty': 'signature location does not establish original filename or filesystem allocation'})
    if time.monotonic() >= deadline and not any('timed out' in warning for warning in warnings):
        warnings.append('recovery timed out; carving incomplete')
    return rows, warnings
