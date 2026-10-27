"""Bounded UPX unpacking and unvalidated binwalk signature leads."""

import hashlib
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
from pathlib import Path


MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DERIVED_BYTES = 64 * 1024 * 1024
MAX_TOOL_OUTPUT = 128 * 1024
MAX_LEADS = 32
_SIGNATURE = re.compile(rb'^\s*(\d+)\s+(0x[0-9a-fA-F]+)\s+(.{1,300})$')


def _digest(path: Path, limit: int) -> tuple[str, int] | None:
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as source:
        while chunk := source.read(65536):
            size += len(chunk)
            if size > limit:
                return None
            digest.update(chunk)
    return digest.hexdigest(), size


def _limits(max_bytes: int) -> None:
    for kind, requested in ((resource.RLIMIT_FSIZE, max_bytes),
                            (resource.RLIMIT_AS, 768 * 1024 * 1024)):
        soft, hard = resource.getrlimit(kind)
        cap = min([requested] + [value for value in (soft, hard)
                                  if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (cap, hard))


def _run(argv: list[str], deadline: float, max_bytes: int,
         supervised: bool) -> tuple[bytes, str | None]:
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=not supervised,
                                   preexec_fn=lambda: _limits(max_bytes))
    except (OSError, subprocess.SubprocessError) as error:
        return b'', f'tool unavailable: {type(error).__name__}: {error}'
    selector = selectors.DefaultSelector()
    output = bytearray()
    error = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                error = 'tool timed out; packer inspection incomplete'
                break
            for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > MAX_TOOL_OUTPUT:
                    error = 'tool output limit reached; packer inspection incomplete'
                    break
                output.extend(chunk)
            if error:
                break
    finally:
        selector.close()
        if error is not None or process.poll() is None:
            if supervised:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if error:
        return b'', error
    if process.returncode:
        return bytes(output), f'tool exited {process.returncode}'
    return bytes(output), None


def _binwalk_leads(path: Path, source_sha256: str, source_size: int,
                   executable: str, deadline: float, max_leads: int,
                   supervised: bool) -> tuple[list[dict], list[str]]:
    output, error = _run([executable, '--signature', str(path)], deadline,
                         MAX_DERIVED_BYTES, supervised)
    if error:
        return [], [f'binwalk {error}']
    leads = []
    for line in output.splitlines():
        match = _SIGNATURE.match(line)
        if not match:
            continue
        offset = int(match[1])
        if offset != int(match[2], 16) or offset >= source_size:
            continue
        description = match[3].decode('utf-8', 'replace').strip()
        if not description:
            continue
        leads.append({'kind': 'signature-lead', 'state': 'lead', 'backend': 'binwalk',
                      'description': description, 'source_sha256': source_sha256,
                      'source_locator': {'file_offset': offset}, 'validated': False})
        if len(leads) >= max_leads:
            return leads, ['binwalk signature lead limit reached']
    return leads, []


def inspect_packers(path: Path, output_dir: Path, *, timeout: float = 20,
                    max_source_bytes: int = MAX_SOURCE_BYTES,
                    max_derived_bytes: int = MAX_DERIVED_BYTES,
                    max_leads: int = MAX_LEADS,
                    upx_path: str | None = None, binwalk_path: str | None = None,
                    supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Unpack only UPX-validated private copies; binwalk hits remain leads."""
    if not (0 < timeout <= 120 and 0 < max_source_bytes <= MAX_SOURCE_BYTES and
            0 < max_derived_bytes <= MAX_DERIVED_BYTES and 0 < max_leads <= MAX_LEADS):
        raise ValueError('REV04 limits must be positive and bounded')
    path, output_dir = Path(path), Path(output_dir)
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        return [], ['packer source unavailable or symlinked']
    if path.stat().st_size > max_source_bytes:
        return [], ['packer source byte limit reached']
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('packer output directory must be separate from source and not a symlink')
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ValueError('packer output directory must be an empty directory')
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    source = _digest(path, max_source_bytes)
    if source is None:
        return [], ['packer source byte limit reached']
    source_sha256, source_size = source
    with path.open('rb') as reader:
        magic = reader.read(4)
    deadline = time.monotonic() + timeout
    records, warnings = [], []
    scans = [(path, source_sha256, source_size)]
    upx = upx_path or shutil.which('upx')
    if upx is None:
        warnings.append('UPX unavailable; unpacking not attempted')
    elif magic == b'\x7fELF' or magic[:2] == b'MZ':
        with tempfile.TemporaryDirectory(prefix='.upx-', dir=output_dir) as scratch:
            copied = Path(scratch) / 'source'
            with path.open('rb') as reader, copied.open('xb') as writer:
                remaining = max_source_bytes + 1
                while remaining:
                    chunk = reader.read(min(65536, remaining))
                    if not chunk:
                        break
                    writer.write(chunk)
                    remaining -= len(chunk)
            if _digest(copied, max_source_bytes) != source or _digest(path, max_source_bytes) != source:
                return [], ['packer source changed during private staging']
            checked, error = _run([upx, '-t', str(copied)], deadline,
                                  max_derived_bytes, supervised)
            if error:
                warnings.append(f'UPX test {error}; unpacking not attempted')
            elif _digest(copied, max_source_bytes) != source:
                warnings.append('UPX test changed the private source copy; unpacking not attempted')
            else:
                unpacked = Path(scratch) / 'unpacked'
                _, error = _run([upx, '-d', '-o', str(unpacked), str(copied)], deadline,
                                max_derived_bytes, supervised)
                if error:
                    warnings.append(f'UPX unpack {error}')
                elif _digest(copied, max_source_bytes) != source:
                    warnings.append('UPX unpack changed the private source copy; output rejected')
                elif unpacked.is_symlink() or not unpacked.is_file() or not stat.S_ISREG(unpacked.stat().st_mode):
                    warnings.append('UPX did not produce a regular unpacked file')
                else:
                    derived = _digest(unpacked, max_derived_bytes)
                    with unpacked.open('rb') as stream:
                        magic = stream.read(4)
                    if (derived is None or not derived[1] or derived[0] == source_sha256 or
                            magic != b'\x7fELF' and magic[:2] != b'MZ'):
                        warnings.append('UPX output was empty, oversized, unchanged or not an executable')
                    elif _digest(path, max_source_bytes) != source:
                        return [], ['packer source changed during UPX inspection']
                    else:
                        target = output_dir / 'upx-unpacked'
                        os.replace(unpacked, target)
                        records.append({'kind': 'upx-unpacked', 'state': 'derived',
                                        'path': target, 'size': derived[1], 'sha256': derived[0],
                                        'source_sha256': source_sha256, 'backend': 'upx',
                                        'source_locator': {'packer': 'UPX',
                                                           'validation': 'upx -t on private copy',
                                                           'test_output': checked.decode('utf-8', 'replace')[:200]},
                                        'validated': True})
                        scans.insert(0, (target, derived[0], derived[1]))
    else:
        warnings.append('UPX supports only recognized ELF or PE executables')
    binwalk = binwalk_path or shutil.which('binwalk')
    if binwalk is None:
        warnings.append('binwalk unavailable; embedded signature scan not attempted')
    else:
        for scan_path, scan_sha256, scan_size in scans:
            if time.monotonic() >= deadline:
                warnings.append('packer inspection timed out before binwalk scan')
                break
            remaining = max_leads - sum(row['kind'] == 'signature-lead' for row in records)
            if remaining <= 0:
                warnings.append('binwalk signature lead limit reached')
                break
            leads, notices = _binwalk_leads(scan_path, scan_sha256, scan_size, binwalk,
                                            deadline, remaining, supervised)
            records.extend(leads)
            warnings.extend(notices)
    if _digest(path, max_source_bytes) != source:
        for row in records:
            if row['kind'] == 'upx-unpacked':
                row['path'].unlink(missing_ok=True)
        return [], ['packer source changed during inspection']
    return records, warnings
