"""Bounded static Java archive, class and Android DEX triage."""

import hashlib
import io
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
import zipfile
import zlib
from pathlib import Path

from .documents import _safe_file


MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_PARTS = 64
MAX_ENTRIES = 2048
MAX_CLASSES = 16
MAX_DEX = 4
MAX_RESOURCE_PARTS = 32
MAX_TOOL_OUTPUT = 1024 * 1024
MAX_DEX_STRINGS = 32


def _read_source(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                return None, 'Java/Android source must be a regular file'
            if before.st_size > limit:
                return None, 'Java/Android source byte limit reached'
            raw = source.read(limit + 1)
            after = os.fstat(source.fileno())
        if len(raw) > limit:
            return None, 'Java/Android source byte limit reached'
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            return None, 'Java/Android source changed during reading'
        return raw, None
    except OSError as error:
        return None, f'Java/Android source unavailable: {type(error).__name__}: {error}'


def _tool_limits() -> None:
    # javap reserves a substantial virtual address range even with a small heap.
    for kind, requested in ((resource.RLIMIT_AS, 4 * 1024 * 1024 * 1024),
                            (resource.RLIMIT_FSIZE, MAX_TOOL_OUTPUT)):
        soft, hard = resource.getrlimit(kind)
        cap = min([requested] + [value for value in (soft, hard)
                                  if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (cap, hard))


def _run(argv: list[str], deadline: float, supervised: bool) -> tuple[bytes | None, str | None]:
    env = os.environ.copy()
    for key in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'):
        env.pop(key, None)
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=not supervised, preexec_fn=_tool_limits, env=env)
    except (OSError, subprocess.SubprocessError) as error:
        return None, f'backend unavailable: {type(error).__name__}: {error}'
    output = bytearray()
    selector = selectors.DefaultSelector()
    warning = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = 'backend timed out'
                break
            for key, _ in selector.select(min(.1, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > MAX_TOOL_OUTPUT:
                    warning = 'backend output limit reached'
                    break
                output.extend(chunk)
            if warning:
                break
    finally:
        selector.close()
        if process.poll() is None:
            try:
                if supervised:
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if warning:
        return None, warning
    if process.returncode:
        detail = output.decode('utf-8', 'replace').splitlines()
        return None, f'backend exited {process.returncode}: {(detail[0] if detail else "unknown error")[:160]}'
    return bytes(output), None


def _dex_strings(data: bytes, limit: int) -> tuple[list[tuple[int, bytes]], str | None]:
    if (len(data) < 0x70 or not re.fullmatch(rb'dex\n0(?:3[5-9]|4[01])\x00', data[:8])
            or int.from_bytes(data[0x20:0x24], 'little') != len(data)
            or int.from_bytes(data[0x24:0x28], 'little') != 0x70
            or int.from_bytes(data[0x28:0x2c], 'little') != 0x12345678):
        return [], 'invalid DEX header, version or size'
    count = int.from_bytes(data[0x38:0x3c], 'little')
    table = int.from_bytes(data[0x3c:0x40], 'little')
    if count > 65536 or table < 0x70 or table + count * 4 > len(data):
        return [], 'invalid DEX string table'
    found = []
    for index in range(count):
        offset = int.from_bytes(data[table + index * 4:table + index * 4 + 4], 'little')
        if not 0x70 <= offset < len(data):
            return found, f'invalid DEX string offset at index {index}'
        cursor = offset
        for _ in range(5):
            if cursor >= len(data):
                return found, f'invalid DEX string length at index {index}'
            byte = data[cursor]
            cursor += 1
            if not byte & 0x80:
                break
        else:
            return found, f'invalid DEX string length at index {index}'
        end = data.find(b'\0', cursor, min(cursor + 513, len(data)))
        if end < 0:
            continue
        value = data[cursor:end]
        if 4 <= len(value) <= 512 and all(32 <= byte < 127 for byte in value):
            found.append((cursor, value))
            if len(found) >= limit:
                return found, 'DEX string output limit reached'
    return found, None


def _zip_index_budget(raw: bytes) -> str | None:
    marker = raw.rfind(b'PK\x05\x06', max(0, len(raw) - 65557))
    if marker < 0 or marker + 22 > len(raw):
        return 'invalid Java/Android archive index'
    count = int.from_bytes(raw[marker + 10:marker + 12], 'little')
    size = int.from_bytes(raw[marker + 12:marker + 16], 'little')
    if count == 0xffff or size == 0xffffffff:
        return 'ZIP64 Java/Android archive index unsupported'
    if count > MAX_ENTRIES or size > 4 * 1024 * 1024:
        return 'Java/Android archive index limit reached'
    return None


def inspect_java_android(path: Path, output_dir: Path, *, timeout: float = 20,
                         max_source_bytes: int = MAX_SOURCE_BYTES,
                         max_total_bytes: int = MAX_TOTAL_BYTES,
                         max_parts: int = MAX_PARTS,
                         javap_path: str | None = None,
                         java_path: str | None = None,
                         supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Stage exact archive members and located static bytecode leads; never execute challenge code."""
    if not (0 < timeout <= 60 and 0 < max_source_bytes <= MAX_SOURCE_BYTES and
            0 < max_total_bytes <= MAX_TOTAL_BYTES and 0 < max_parts <= MAX_PARTS):
        raise ValueError('REV06 limits must be positive and bounded')
    path, output_dir = Path(path), Path(output_dir)
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('REV06 output directory must be separate and not a symlink')
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ValueError('REV06 output directory must be empty')
    raw, error = _read_source(path, max_source_bytes)
    if raw is None:
        return [], [error]
    if raw.startswith(b'dex\n'):
        strings, warning = _dex_strings(raw, MAX_DEX_STRINGS)
        digest = hashlib.sha256(raw).hexdigest()
        records = [{'kind': 'dex_string', 'state': 'lead', 'data': value,
                    'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                    'source_sha256': digest, 'member': None, 'index': None,
                    'source_locator': {'dex_offset': offset}}
                   for offset, value in strings]
        notices = [warning] if warning else []
        if not warning:
            notices.append('JADX unavailable; DEX source decompilation not attempted'
                           if shutil.which('jadx') is None else
                           'JADX source decompilation is not configured; DEX strings are leads')
        return records, notices
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        return [], []
    index_error = _zip_index_budget(raw)
    if index_error:
        return [], [index_error]
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    source_sha256 = hashlib.sha256(raw).hexdigest()
    deadline = time.monotonic() + timeout
    records, warnings = [], []
    total = 0

    def stage(data: bytes, kind: str, info: zipfile.ZipInfo, index: int,
              **details) -> dict | None:
        nonlocal total
        locator = {'member': info.orig_filename, 'index': index,
                   'zip_header_offset': info.header_offset, **details.pop('source_locator', {})}
        if len(records) >= max_parts:
            warnings.append(f'member {index}: part limit reached')
            return None
        if len(data) > max_total_bytes - total:
            warnings.append(f'member {index}: expanded byte limit reached')
            return None
        suffix = '.class' if kind == 'class' else '.txt' if kind == 'bytecode_listing' else ''
        target = output_dir / f'{index:06d}-{uuid.uuid4().hex}{suffix}'
        with target.open('xb') as output:
            output.write(data)
        target.chmod(0o600)
        total += len(data)
        record = {'kind': kind, 'path': target, 'size': len(data),
                  'sha256': hashlib.sha256(data).hexdigest(),
                  'source_sha256': source_sha256, 'member': info.orig_filename,
                  'index': index, 'source_locator': locator, **details}
        records.append(record)
        return record

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                warnings.append('Java/Android archive entry limit reached')
                entries = entries[:MAX_ENTRIES]
            if not any(info.orig_filename.endswith(('.class', '.dex')) or
                       info.orig_filename in ('AndroidManifest.xml', 'META-INF/MANIFEST.MF')
                       for info in entries):
                return [], []
            indexed = list(enumerate(entries))
            # Preserve manifests and resources when class-heavy archives meet the part cap.
            indexed.sort(key=lambda pair: (2 if pair[1].orig_filename.endswith('.class') else
                                           3 if pair[1].orig_filename.endswith('.dex') else
                                           0 if pair[1].orig_filename in
                                           ('AndroidManifest.xml', 'META-INF/MANIFEST.MF') else 1,
                                           pair[0]))
            classes = dex_count = resources = 0
            javap = javap_path or shutil.which('javap')
            java = java_path or shutil.which('java')
            javap_major = None
            runtime_version = None
            has_class = any(info.orig_filename.endswith('.class') for info in entries)
            if has_class and javap and java:
                version, failure = _run([java, '-version'], deadline, supervised)
                if failure:
                    warnings.append(f'Java runtime {failure}')
                elif version:
                    runtime_version = version.decode('utf-8', 'replace').splitlines()[0][:100]
                version, failure = _run([javap, '-J-Xmx128m', '-version'], deadline, supervised)
                if failure:
                    warnings.append(f'javap {failure}')
                elif version:
                    match = re.search(rb'\b(\d+)(?:\.\d+)*\b', version)
                    javap_major = int(match[1]) if match else None
            elif has_class:
                warnings.append('Java runtime or javap unavailable; class disassembly not attempted')
            for index, info in indexed:
                if time.monotonic() >= deadline:
                    warnings.append('Java/Android inspection timed out')
                    break
                locator = f'member {index} ({info.orig_filename!r})'
                if info.is_dir():
                    continue
                if not _safe_file(info):
                    warnings.append(f'{locator}: unsafe path or file type')
                    continue
                if info.flag_bits & 1:
                    warnings.append(f'{locator}: encrypted member requires a password')
                    continue
                name = info.orig_filename
                kind = ('manifest' if name in ('AndroidManifest.xml', 'META-INF/MANIFEST.MF')
                        else 'class' if name.endswith('.class') else 'dex' if name.endswith('.dex')
                        else 'resource')
                if kind == 'class':
                    classes += 1
                    if classes > MAX_CLASSES:
                        warnings.append('Java class count limit reached')
                        continue
                elif kind == 'dex':
                    dex_count += 1
                    if dex_count > MAX_DEX:
                        warnings.append('DEX file count limit reached')
                        continue
                else:
                    resources += 1
                    if resources > MAX_RESOURCE_PARTS:
                        warnings.append('Java/Android resource count limit reached')
                        continue
                if info.file_size > max_total_bytes - total:
                    warnings.append(f'{locator}: expanded byte limit reached')
                    continue
                try:
                    with archive.open(info) as member:
                        chunks = []
                        size = 0
                        while chunk := member.read(min(65536, max_total_bytes - total - size + 1)):
                            if time.monotonic() >= deadline:
                                raise TimeoutError('member extraction timed out')
                            size += len(chunk)
                            if size > max_total_bytes - total:
                                raise ValueError('expanded byte limit reached')
                            chunks.append(chunk)
                    data = b''.join(chunks)
                    if size != info.file_size:
                        raise ValueError('member size mismatch')
                except (zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, EOFError,
                        OSError, TimeoutError, ValueError) as error:
                    warnings.append(f'{locator}: extraction failed: {type(error).__name__}: {error}')
                    continue
                record = stage(data, kind, info, index)
                if record is None:
                    continue
                if name.startswith('lib/') and name.endswith('.so'):
                    warnings.append(f'{locator}: native library requires native-code analysis')
                if kind == 'dex':
                    strings, failure = _dex_strings(data, MAX_DEX_STRINGS)
                    if failure:
                        warnings.append(f'{locator}: {failure}')
                    for dex_offset, value in strings:
                        if len(records) >= max_parts:
                            warnings.append('DEX string part limit reached')
                            break
                        records.append({'kind': 'dex_string', 'state': 'lead', 'data': value,
                                        'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                                        'source_sha256': source_sha256, 'member': name, 'index': index,
                                        'source_locator': {'member': name, 'index': index,
                                                           'zip_header_offset': info.header_offset,
                                                           'dex_offset': dex_offset}})
                elif kind == 'class':
                    if len(data) < 8 or data[:4] != b'\xca\xfe\xba\xbe':
                        warnings.append(f'{locator}: invalid Java class header')
                        continue
                    major = int.from_bytes(data[6:8], 'big')
                    if major < 45 or major > (javap_major + 44 if javap_major else 65):
                        warnings.append(f'{locator}: unsupported class version {major}')
                        continue
                    if javap_major is None:
                        continue
                    listing, failure = _run([javap, '-J-Xmx128m', '-J-XX:ActiveProcessorCount=1',
                                             '-c', '-p', '-constants', str(record['path'])],
                                            deadline, supervised)
                    if failure:
                        warnings.append(f'{locator}: javap {failure}')
                    elif listing is not None:
                        class_name = name[:-6].replace('/', '.')
                        stage(listing, 'bytecode_listing', info, index,
                              source_locator={'class_name': class_name,
                                              'class_version': major,
                                              'java_runtime': runtime_version,
                                              'javap_major': javap_major,
                                              'listing_backend': 'javap'},
                              backend='javap', state='lead')
            if dex_count:
                warnings.append('JADX unavailable; DEX source decompilation not attempted'
                                if shutil.which('jadx') is None else
                                'JADX source decompilation is not configured; DEX strings are leads')
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as error:
        warnings.append(f'Java/Android archive parse failed: {type(error).__name__}: {error}')
    current, _ = _read_source(path, max_source_bytes)
    if current is None or hashlib.sha256(current).hexdigest() != source_sha256:
        for record in records:
            if 'path' in record:
                record['path'].unlink(missing_ok=True)
        return [], ['Java/Android source changed during inspection']
    return records, warnings
