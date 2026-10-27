"""Bounded static capa/YARA rule evidence for executable samples."""

import hashlib
import json
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


MAX_SAMPLE_BYTES = 32 * 1024 * 1024
MAX_RULE_BYTES = 64 * 1024 * 1024
MAX_RULE_FILES = 4096
MAX_OUTPUT = 4 * 1024 * 1024
MAX_MATCHES = 64
MAX_EVIDENCE = 64


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('file is not regular or exceeds byte limit')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(data) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('file changed or exceeds byte limit')
    return data


def _identity(path: Path, suffixes: tuple[str, ...] = ()) -> dict:
    """Hash every selected rule/signature byte, including relative filenames."""
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError('symlink rule data is not accepted')
    if path.is_file():
        entries = [(path.name, path)]
    elif path.is_dir():
        entries = []
        for base, dirs, files in os.walk(path, followlinks=False):
            if any((Path(base) / name).is_symlink() for name in dirs + files):
                raise ValueError('symlink rule data is not accepted')
            for name in files:
                file = Path(base) / name
                entries.append((file.relative_to(path).as_posix(), file))
                if len(entries) > MAX_RULE_FILES:
                    raise ValueError('rule file count limit reached')
    else:
        raise ValueError('rule path is absent')
    if not entries:
        raise ValueError('rule path contains no files')
    if suffixes and not any(name.lower().endswith(suffixes) for name, _ in entries):
        raise ValueError('no compatible rule or signature file in path')
    digest = hashlib.sha256()
    remaining = MAX_RULE_BYTES
    for name, file in sorted(entries):
        data = _read_regular(file, remaining)
        remaining -= len(data)
        digest.update(name.encode('utf-8', 'surrogateescape') + b'\0')
        digest.update(len(data).to_bytes(8, 'big') + data)
    return {'path': str(path), 'sha256': digest.hexdigest(), 'files': len(entries)}


def _limits(timeout: float) -> None:
    cpu = max(1, min(31, int(timeout) + 1))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def _run(command: list[str], timeout: float, limit: int = MAX_OUTPUT) -> tuple[bytes | None, str | None]:
    """Bound time, output, child processes and writes to a disposable work directory."""
    with tempfile.TemporaryDirectory(prefix='autosolve-rules-') as work:
        env = os.environ.copy()
        env.update({'HOME': work, 'XDG_CACHE_HOME': work, 'TMPDIR': work})
        try:
            process = subprocess.Popen(command, cwd=work, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True,
                                       preexec_fn=lambda: _limits(timeout))
        except (OSError, subprocess.SubprocessError) as error:
            return None, f'tool unavailable: {type(error).__name__}: {error}'
        output, errors = bytearray(), bytearray()
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout
        problem = None
        try:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    problem = 'tool timed out; analysis incomplete'
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(errors) + len(chunk) > limit:
                        problem = 'tool output limit reached; analysis incomplete'
                        break
                    else:
                        key.data.extend(chunk)
                if problem:
                    break
        finally:
            selector.close()
            if not problem:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    problem = 'tool timed out; analysis incomplete'
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
        if problem:
            return None, problem
        if process.returncode:
            detail = errors.decode('utf-8', 'replace').strip().splitlines()
            return None, f'tool exited {process.returncode}: {(detail[0] if detail else "unknown error")[:200]}'
        return bytes(output), None


def _capa_evidence(match: dict) -> list[dict]:
    evidence, pending = [], [match]
    while pending and len(evidence) < MAX_EVIDENCE:
        item = pending.pop()
        if not isinstance(item, dict):
            continue
        if item.get('success') and isinstance(item.get('node'), dict):
            feature = item['node'].get('feature')
            locations = item.get('locations')
            if isinstance(feature, dict) and isinstance(locations, list) and locations:
                evidence.append({'feature': feature, 'locations': locations[:MAX_EVIDENCE],
                                 'captures': item.get('captures', {})})
        children = item.get('children')
        if isinstance(children, list):
            pending.extend(reversed(children[:MAX_EVIDENCE]))
    return evidence


def _parse_capa(output: bytes, sample_hash: str) -> list[dict]:
    document = json.loads(output)
    if not isinstance(document, dict) or not isinstance(document.get('rules'), dict) or not (
            isinstance(document.get('meta'), dict) and
            isinstance(document['meta'].get('sample'), dict) and
            document['meta']['sample'].get('sha256') == sample_hash):
        raise ValueError('capa JSON schema or sample hash mismatch')
    analysis = document['meta'].get('analysis')
    if not isinstance(analysis, dict) or not isinstance(analysis.get('rules'), list) or not (
            analysis['rules']):
        raise ValueError('capa output has no loaded rules')
    rows = []
    for name, rule in document['rules'].items():
        if not isinstance(name, str) or not isinstance(rule, dict) or not isinstance(rule.get('matches'), list):
            raise ValueError('invalid capa rule match schema')
        for pair in rule['matches']:
            if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[1], dict):
                raise ValueError('invalid capa address or evidence')
            rows.append({'rule': name, 'address': pair[0], 'evidence': _capa_evidence(pair[1])})
            if len(rows) > MAX_MATCHES:
                raise ValueError('capa match count limit reached')
    return rows


_YARA_STRING = re.compile(r'^0x([0-9a-fA-F]+):(\d+):(\$[A-Za-z0-9_]+):(?:.*)$')
_YARA_RULE = re.compile(r'^([A-Za-z0-9_]+):([A-Za-z0-9_]+)$')


def _parse_yara(output: bytes, path: Path, sample: bytes) -> list[dict]:
    rows = []
    current = None
    suffix = ' ' + str(path)
    for line in output.decode('utf-8', 'replace').splitlines():
        if line.endswith(suffix):
            header = _YARA_RULE.fullmatch(line[:-len(suffix)])
            if header is None:
                raise ValueError('invalid YARA rule header')
            current = {'namespace': header.group(1), 'rule': header.group(2), 'strings': []}
            rows.append(current)
            if len(rows) > MAX_MATCHES:
                raise ValueError('YARA match count limit reached')
            continue
        if current is None:
            raise ValueError('YARA string without rule header')
        match = _YARA_STRING.fullmatch(line)
        if match is None:
            raise ValueError('invalid YARA string location')
        offset, length = int(match.group(1), 16), int(match.group(2))
        if length <= 0 or length > 4096 or offset + length > len(sample):
            raise ValueError('YARA string location exceeds sample or evidence limit')
        if len(current['strings']) >= MAX_EVIDENCE:
            raise ValueError('YARA evidence count limit reached')
        current['strings'].append({'identifier': match.group(3), 'file_offset': offset,
                                   'length': length, 'matched_hex': sample[offset:offset + length].hex()})
    return rows


def inspect_rules(path: Path, *, capa_rules: Path | None = None,
                  capa_signatures: Path | None = None, yara_rules: Path | None = None,
                  capa_path: str | None = None, yara_path: str | None = None,
                  timeout: float = 10, max_bytes: int = MAX_SAMPLE_BYTES) -> tuple[dict, list[str]]:
    """Return rule matches as static clues; never infer execution or malicious behavior."""
    if not 0 < timeout <= 30 or not 0 < max_bytes <= MAX_SAMPLE_BYTES:
        raise ValueError('rule scan limits must be positive and bounded')
    path = Path(path).absolute()
    try:
        sample = _read_regular(path, max_bytes)
    except (OSError, ValueError) as error:
        return {'sample_sha256': None, 'engines': {}}, [f'sample unavailable: {error}']
    sample_hash = hashlib.sha256(sample).hexdigest()
    report = {'sample_sha256': sample_hash, 'engines': {}}
    warnings = []
    for engine, required, executable, version_arg in (
            ('capa', (capa_rules, capa_signatures), capa_path, '--version'),
            ('yara', (yara_rules,), yara_path, '-v')):
        row = {'status': 'skipped_prerequisite', 'matches': []}
        report['engines'][engine] = row
        if any(item is None for item in required):
            row['reason'] = 'rule/signature path not supplied'
            if any(item is not None for item in required):
                warnings.append(f'{engine} needs both rule and signature paths')
            continue
        try:
            suffixes = ((('.yml', '.yaml'), ('.pat', '.pat.gz', '.sig')) if engine == 'capa'
                        else ((),))
            identities = [_identity(Path(item), kinds) for item, kinds in zip(required, suffixes)]
        except (OSError, ValueError) as error:
            warnings.append(f'{engine} rule/signature data unavailable: {error}')
            continue
        row['rules'] = identities[0]
        if engine == 'capa':
            row['signatures'] = identities[1]
            if not sample.startswith((b'\x7fELF', b'MZ')):
                warnings.append('capa requires a supported executable format')
                continue
        binary = executable or shutil.which(engine)
        if binary and os.sep in str(binary):
            binary = str(Path(binary).absolute())
        if not binary:
            row['status'] = 'unavailable'
            warnings.append(f'{engine} tool unavailable')
            continue
        if executable and os.sep in executable:
            binary = str(Path(executable).absolute())
        version, error = _run([str(binary), version_arg], min(2, timeout), 4096)
        if error:
            row['status'] = 'unavailable'
            warnings.append(f'{engine} version probe: {error}')
            continue
        lines = version.decode('utf-8', 'replace').strip().splitlines()
        if not lines:
            row['status'] = 'unavailable'
            warnings.append(f'{engine} version probe returned no version')
            continue
        row['version'] = lines[0][:128]
        with tempfile.TemporaryDirectory(prefix='autosolve-rule-sample-') as work:
            scan_path = Path(work) / 'sample.bin'
            scan_path.write_bytes(sample)
            scan_path.chmod(0o400)
            if engine == 'capa':
                command = [str(binary), '-j', '-r', str(Path(capa_rules).absolute()), '-s',
                           str(Path(capa_signatures).absolute()), str(scan_path)]
            else:
                command = [str(binary), '-s', '-L', '-e', str(Path(yara_rules).absolute()),
                           str(scan_path)]
            output, error = _run(command, timeout)
            try:
                changed = hashlib.sha256(_read_regular(scan_path, max_bytes)).hexdigest() != sample_hash
                changed |= any(_identity(Path(item), kinds) != initial
                               for item, kinds, initial in zip(required, suffixes, identities))
            except (OSError, ValueError):
                changed = True
            if changed:
                row['status'] = 'incomplete'
                warnings.append(f'{engine}: sample or rule/signature data changed during scan')
                continue
            if not error and engine == 'yara':
                try:
                    row['matches'] = _parse_yara(output, scan_path, sample)
                except (ValueError, UnicodeDecodeError) as problem:
                    error = f'invalid result: {problem}'
        if error:
            row['status'] = 'incomplete'
            warnings.append(f'{engine}: {error}')
            continue
        try:
            if engine == 'capa':
                row['matches'] = _parse_capa(output, sample_hash)
        except (ValueError, UnicodeDecodeError) as error:
            row['status'] = 'incomplete'
            warnings.append(f'{engine}: invalid result: {error}')
            continue
        row['status'] = 'matched' if row['matches'] else 'no_match'
    return report, warnings
