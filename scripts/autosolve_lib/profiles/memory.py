"""Offline Volatility 3 Windows triage with explicit symbol and dump gates."""

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
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


VOL = shutil.which(os.environ.get('AUTOSOLVE_VOL', 'vol')) or os.environ.get('AUTOSOLVE_VOL') or '/opt/ctf-tools/py312/bin/vol'
PLUGINS = ('windows.info', 'windows.pslist', 'windows.cmdline', 'windows.filescan')


def _run(argv, deadline, max_output, dump_dir=None, max_dump_bytes=0,
         scratch_dir=None):
    def limit_dump():
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (min(max_dump_bytes, soft) if soft >= 0 else max_dump_bytes, hard))

    try:
        if scratch_dir is not None and (scratch_dir.is_symlink() or not scratch_dir.is_dir()):
            raise ValueError('Volatility scratch directory must be a real directory')
        environment = ({**os.environ, 'HOME': str(scratch_dir),
                        'XDG_CACHE_HOME': str(scratch_dir),
                        'TMPDIR': str(scratch_dir), 'TMP': str(scratch_dir),
                        'TEMP': str(scratch_dir)} if scratch_dir is not None else None)
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True,
                                   preexec_fn=limit_dump if dump_dir is not None else None,
                                   env=environment)
    except OSError as error:
        return b'', b'', f'Volatility unavailable: {error}'
    streams = (bytearray(), bytearray())
    selector = selectors.DefaultSelector()
    problem = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ, streams[0])
        selector.register(process.stderr, selectors.EVENT_READ, streams[1])
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                problem = 'Volatility timed out; analysis incomplete'
                break
            for key, _ in selector.select(min(remaining, .1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max_output - sum(map(len, streams))
                key.data.extend(chunk[:max(0, room)])
                if len(chunk) > room:
                    problem = 'Volatility output byte limit reached; analysis incomplete'
                    break
            if problem:
                break
            if dump_dir is not None:
                files = list(dump_dir.iterdir())
                if any(item.is_symlink() or not item.is_file() for item in files):
                    problem = 'Volatility created unsupported dump output; dump discarded'
                    break
                if sum(item.stat().st_size for item in files) > max_dump_bytes:
                    problem = 'Volatility dump byte limit reached; dump discarded'
                    break
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if not problem and process.returncode:
        if dump_dir is not None and (b'File too large' in streams[1] or
                                     b'Errno 27' in streams[1] or
                                     process.returncode == -signal.SIGXFSZ):
            problem = 'Volatility dump byte limit reached; dump discarded'
        else:
            problem = f'Volatility exited {process.returncode}; analysis incomplete'
    return bytes(streams[0]), bytes(streams[1]), problem


def _rows(raw):
    tree = json.loads(raw)
    if not isinstance(tree, list):
        raise ValueError('Volatility JSON root is not a list')
    rows = []

    def visit(items):
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get('__children'), list):
                raise ValueError('Volatility JSON row is malformed')
            rows.append({key: value for key, value in item.items() if key != '__children'})
            visit(item['__children'])

    visit(tree)
    return rows


def _symbol_gate(rows):
    facts = {row.get('Variable'): row.get('Value') for row in rows}
    symbol = facts.get('Symbols')
    try:
        kernel = int(str(facts['Kernel Base']), 0)
        dtb = int(str(facts['DTB']), 0)
    except (KeyError, TypeError, ValueError):
        return None
    if not symbol or not isinstance(symbol, str) or kernel <= 0 or dtb <= 0:
        return None
    return {'symbols': symbol, 'kernel_base': kernel, 'dtb': dtb,
            'build': facts.get('NTBuildLab'), 'version': facts.get('Major/Minor')}


def _address(value):
    if type(value) is int:
        return value if value >= 0 else None
    if type(value) is str and len(value) <= 34 and re.fullmatch(
            r'(?:0[xX][0-9a-fA-F]+|[0-9]+)', value):
        return int(value, 16 if value.lower().startswith('0x') else 10)
    return None


def _dump_name_matches(value, target):
    if type(value) is not str or not value:
        return False
    actual, expected = value.replace('/', '\\').casefold(), target.replace('/', '\\').casefold()
    return actual == (expected if '\\' in actual else expected.rsplit('\\', 1)[-1])


def inspect_memory(path: Path, output_dir: Path, *, symbols_dir: Path | None = None,
                   targets: list[dict] | None = None, timeout: float, max_output: int,
                   max_files: int, max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Return raw plugin output and row-linked facts; dump only filescan-matched targets.

    Targets are {'address': integer, 'space': 'physical'|'virtual', 'name': exact
    filescan name}. The caller must know the address space; filescan varies by OS.
    """
    if timeout <= 0 or max_output <= 0 or max_files < 0 or max_total_bytes < 0:
        raise ValueError('memory limits must be positive or nonnegative as applicable')
    targets = targets or []
    if any(not isinstance(item, dict) or set(item) != {'address', 'space', 'name'} or
           not isinstance(item['address'], int) or isinstance(item['address'], bool) or
           item['address'] < 0 or item['space'] not in ('physical', 'virtual') or
           not isinstance(item['name'], str) or not item['name'] for item in targets):
        raise ValueError('memory targets need exact address, address space and file name')
    path, output_dir = Path(path), Path(output_dir)
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError('memory output directory must differ from source directory')
    if symbols_dir is not None and (not Path(symbols_dir).is_dir() or Path(symbols_dir).is_symlink()):
        raise ValueError('symbol directory must be an existing real directory')
    try:
        source = path.lstat()
    except OSError as error:
        return [], [f'memory image unavailable: {error}']
    if not stat.S_ISREG(source.st_mode):
        return [], ['memory image must be an explicit regular file']
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache = output_dir / 'cache'
    if cache.is_symlink():
        raise ValueError('Volatility cache directory must not be a symlink')
    cache.mkdir(mode=0o700, exist_ok=True)
    deadline = time.monotonic() + timeout
    executable = Path(VOL)
    try:
        with executable.open('rb') as stream:
            tool_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    except OSError:
        tool_sha256 = None
    try:
        package_version = version('volatility3')
    except PackageNotFoundError:
        package_version = None
    identity = {'tool': str(executable), 'tool_sha256': tool_sha256,
                'volatility_package_version': package_version}
    base = [str(executable), '--offline', '--cache-path', str(output_dir / 'cache'),
            '-q', '-r', 'json', '-f', str(path.resolve())]
    if symbols_dir is not None:
        base[1:1] = ['-s', str(Path(symbols_dir).resolve())]
    records, warnings = [], []
    file_rows = []
    completed_plugins = []
    plugins = list(PLUGINS)
    symbol_identity = None
    for plugin in plugins:
        raw, err, problem = _run(base + [plugin], deadline, max_output,
                                 scratch_dir=cache)
        record = {'kind': 'plugin_output', 'plugin': plugin, 'status': 'complete',
                  'raw_stdout': raw.decode('utf-8', 'replace'),
                  'raw_stderr': err.decode('utf-8', 'replace'), **identity}
        if problem:
            record['status'] = 'skipped' if plugin == 'windows.info' else 'failed'
            if plugin == 'windows.info' and (b'symbol_table_name' in err or
                                             b'Unsatisfied requirement' in err):
                problem = 'matching Windows image layer and symbols unavailable; analysis skipped'
            record['reason'] = problem
            records.append(record)
            warnings.append(f'{plugin}: {problem}')
            break
        try:
            rows = _rows(raw)
        except (ValueError, TypeError, RecursionError) as error:
            record['status'] = 'failed'
            record['reason'] = f'invalid Volatility JSON: {error}'
            records.append(record)
            warnings.append(f'{plugin}: invalid Volatility JSON; analysis incomplete')
            break
        record['row_count'] = len(rows)
        records.append(record)
        if plugin == 'windows.pslist' and not rows:
            # shortcut: scan only when the linked list is empty; expand for hidden-process hunting.
            plugins.insert(plugins.index(plugin) + 1, 'windows.psscan')
        if plugin == 'windows.info':
            symbol_identity = _symbol_gate(rows)
            if symbol_identity is None:
                record['status'] = 'skipped'
                record['reason'] = 'matching Windows image layer and symbols not established'
                warnings.append('Windows memory analysis skipped: matching image layer or symbols unavailable')
                break
        completed_plugins.append(plugin)
        record['symbol_identity'] = symbol_identity
        for index, row in enumerate(rows):
            offset = row.get('Offset(V)', row.get('Offset(P)', row.get('Offset')))
            locator = {'plugin': plugin, 'row': index}
            if offset is not None:
                locator['offset'] = offset
            if row.get('PID') is not None:
                locator['pid'] = row['PID']
            records.append({'kind': 'row', 'plugin': plugin, 'row': row,
                            'locator': locator, 'symbol_identity': symbol_identity,
                            **identity})
        if plugin == 'windows.filescan':
            file_rows = rows
    if symbol_identity is None or completed_plugins != plugins:
        if targets:
            warnings.append('targeted memory dumps skipped: memory triage prerequisite incomplete')
        return records, warnings

    triage_plugins = {record['plugin'] for record in records if record['kind'] == 'row'}
    if not triage_plugins.intersection(('windows.pslist', 'windows.psscan')):
        warnings.append('memory process triage returned no rows')
    if 'windows.cmdline' not in triage_plugins:
        warnings.append('memory command-line triage returned no rows')
    if 'windows.filescan' not in triage_plugins:
        warnings.append('memory file triage returned no rows')

    available = set()
    for row in file_rows:
        if not isinstance(row.get('Name'), str):
            continue
        offset = _address(row.get('Offset'))
        if offset is None:
            warnings.append('filescan row with invalid offset omitted from dump selection')
            continue
        available.add((offset, row['Name']))
    total, dumped = 0, 0
    for target_index, target in enumerate(targets):
        locator = {'plugin': 'windows.filescan', 'offset': hex(target['address']),
                   'name': target['name'], 'space': target['space']}
        if (target['address'], target['name']) not in available:
            warnings.append(f"{locator}: dump skipped; no exact filescan target")
            continue
        if dumped >= max_files or total >= max_total_bytes:
            warnings.append(f'{locator}: dump skipped; file or byte limit reached')
            continue
        dump_dir = output_dir / f'dump-{target_index:03d}'
        dump_dir.mkdir(mode=0o700)
        address_option = '--physaddr' if target['space'] == 'physical' else '--virtaddr'
        dump_base = base[:]
        dump_base[1:1] = ['-o', str(dump_dir)]
        raw, err, problem = _run(dump_base + ['windows.dumpfiles', address_option,
                                            str(target['address'])], deadline, max_output,
                                 dump_dir, max_total_bytes - total, cache)
        records.append({'kind': 'plugin_output', 'plugin': 'windows.dumpfiles',
                        'status': 'failed' if problem else 'complete',
                        'raw_stdout': raw.decode('utf-8', 'replace'),
                        'raw_stderr': err.decode('utf-8', 'replace'),
                        'target': locator, 'symbol_identity': symbol_identity, **identity})
        if problem:
            warnings.append(f'{locator}: {problem}')
            shutil.rmtree(dump_dir, ignore_errors=True)
            continue
        try:
            dump_rows = _rows(raw)
        except (ValueError, TypeError, RecursionError):
            warnings.append(f'{locator}: invalid dumpfiles JSON; dump discarded')
            shutil.rmtree(dump_dir, ignore_errors=True)
            continue
        files = sorted(dump_dir.iterdir())
        results = {}
        for row in dump_rows:
            result = row.get('Result')
            if isinstance(result, str):
                results[result] = (row if result not in results and
                                   _address(row.get('FileObject')) == target['address'] and
                                   _dump_name_matches(row.get('FileName'), target['name']) else None)
        if (not files or dumped + len(files) > max_files or
                any(not item.is_file() or item.is_symlink() or not results.get(item.name)
                    for item in files)):
            warnings.append(f'{locator}: unverified dump output or file limit reached; dump discarded')
            shutil.rmtree(dump_dir, ignore_errors=True)
            continue
        sizes = [item.stat().st_size for item in files]
        if sum(sizes) > max_total_bytes - total:
            warnings.append(f'{locator}: dump byte limit reached; dump discarded')
            shutil.rmtree(dump_dir, ignore_errors=True)
            continue
        for staged, size in zip(files, sizes):
            with staged.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            records.append({'kind': 'file', 'path': staged, 'sha256': digest, 'size': size,
                            'file_name': target['name'], 'locator': locator,
                            'dump_row': results[staged.name],
                            'symbol_identity': symbol_identity, **identity})
            dumped += 1
            total += size
    return records, warnings
