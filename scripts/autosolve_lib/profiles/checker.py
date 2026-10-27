"""Constrained angr checker search with optional, explicit local replay."""

import hashlib
import multiprocessing
import os
import resource
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 64
MAX_STEPS = 5000
MAX_STATES = 128
MAX_OUTPUT_BYTES = 65536


def _condition(value):
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError('checker condition must contain one address or stdout field')
    if 'address' in value and type(value['address']) is int and 0 < value['address'] < 2**64:
        return {'address': value['address']}
    if 'stdout' in value and isinstance(value['stdout'], str):
        encoded = value['stdout'].encode('utf-8')
        if 0 < len(encoded) <= 128:
            return {'stdout': value['stdout']}
    raise ValueError('checker condition must be a positive integer address or short stdout text')


def _hints(checker):
    if not isinstance(checker, dict) or set(checker) - {
            'channel', 'length', 'find', 'avoid', 'ascii_printable'}:
        raise ValueError('unsupported checker hint field')
    channel = checker.get('channel')
    length = checker.get('length')
    if channel not in ('stdin', 'argv') or type(length) is not int or not 1 <= length <= MAX_INPUT_BYTES:
        raise ValueError('checker channel and bounded input length are required')
    printable = checker.get('ascii_printable', True)
    if type(printable) is not bool:
        raise ValueError('ascii_printable must be boolean')
    if channel == 'argv' and not printable:
        raise ValueError('argv input must be printable ASCII')
    find = _condition(checker.get('find'))
    avoid = _condition(checker['avoid']) if 'avoid' in checker else None
    if avoid == find:
        raise ValueError('find and avoid cannot be identical')
    return {'channel': channel, 'length': length, 'find': find, 'avoid': avoid,
            'ascii_printable': printable}


def _limit(kind, cap):
    soft, hard = resource.getrlimit(kind)
    limit = min(cap, hard) if hard != resource.RLIM_INFINITY else cap
    resource.setrlimit(kind, (limit, hard))


def _solve(path, hints, max_steps, deadline, pipe, scratch_dir):
    try:
        _limit(resource.RLIMIT_AS, 2 * 1024**3)
        _limit(resource.RLIMIT_CPU, max(2, min(60, int(deadline - time.monotonic()) + 2)))
        if scratch_dir is not None:
            # This dedicated spawned worker may scope third-party parser scratch safely.
            os.environ.update(HOME=str(scratch_dir), XDG_CACHE_HOME=str(scratch_dir),
                              TMPDIR=str(scratch_dir), TMP=str(scratch_dir),
                              TEMP=str(scratch_dir))
        import angr
        import claripy
        from cle.backends.elf import ELF

        project = angr.Project(str(path), auto_load_libs=False)
        if project.arch.name not in ('AMD64', 'X86') or not isinstance(
                project.loader.main_object, ELF):
            pipe.send({'status': 'skipped_prerequisite', 'reason': 'only Linux x86 ELF checkers are modeled'})
            return
        symbolic = claripy.BVS('checker_input', 8 * hints['length'])
        if hints['channel'] == 'argv':
            state = project.factory.entry_state(args=[str(path), symbolic])
        else:
            content = claripy.Concat(symbolic, claripy.BVV(b'\n'))
            state = project.factory.entry_state(
                args=[str(path)], stdin=angr.SimFileStream(name='stdin', content=content, has_end=True))
        for index in range(hints['length']):
            byte = symbolic.get_byte(index)
            if hints['ascii_printable']:
                state.solver.add(byte >= 0x20, byte <= 0x7e)
        state.inspect.b('syscall', when=angr.BP_BEFORE,
                        action=lambda current: current.globals.__setitem__('native_syscall_seen', True))
        manager = project.factory.simgr(state, save_unconstrained=True)

        def matches(current, condition):
            if condition is None:
                return False
            if 'address' in condition:
                return current.addr == condition['address']
            return condition['stdout'].encode('utf-8') in current.posix.dumps(1)

        for step in range(max_steps + 1):
            if time.monotonic() >= deadline:
                pipe.send({'status': 'timeout', 'steps': step})
                return
            manager.stashes['active'] = [current for current in manager.active
                                         if not matches(current, hints['avoid'])]
            for current in manager.active + manager.deadended:
                if current.globals.get('native_syscall_seen'):
                    pipe.send({'status': 'incomplete', 'reason': 'native syscall requires review',
                               'steps': step})
                    return
                if matches(current, hints['avoid']):
                    continue
                if matches(current, hints['find']):
                    candidate = current.solver.eval(symbolic, cast_to=bytes)
                    pipe.send({'status': 'candidate', 'candidate_hex': candidate.hex(),
                               'steps': step, 'found_address': current.addr,
                               'modeled_stdout_hex': current.posix.dumps(1)[:MAX_OUTPUT_BYTES].hex()})
                    return
            if manager.errored or manager.unconstrained:
                pipe.send({'status': 'incomplete', 'reason': 'errored or unconstrained state',
                           'steps': step})
                return
            manager.stashes['deadended'].clear()
            if not manager.active:
                pipe.send({'status': 'unsat_under_model', 'steps': step})
                return
            if step == max_steps or len(manager.active) > MAX_STATES:
                pipe.send({'status': 'incomplete', 'reason': 'symbolic step or state limit reached',
                           'steps': step})
                return
            manager.step()
    except (Exception, MemoryError) as error:
        pipe.send({'status': 'incomplete', 'reason': f'{type(error).__name__}: {error}'[:240]})
    finally:
        pipe.close()


def _replay(path, hints, candidate, timeout, scratch_dir: Path | None = None):
    argv = [str(path)] + ([candidate.decode('ascii')] if hints['channel'] == 'argv' else [])
    stdin = candidate + b'\n' if hints['channel'] == 'stdin' else b''
    if scratch_dir is not None and (scratch_dir.is_symlink() or not scratch_dir.is_dir()):
        raise ValueError('checker scratch directory must be a real directory')
    with tempfile.TemporaryDirectory(prefix='autosolve-checker-', dir=scratch_dir) as work:
        env = {'PATH': '/usr/bin:/bin', 'HOME': work, 'TMPDIR': work, 'LANG': 'C'}
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=work, env=env,
                                   start_new_session=True,
                                   preexec_fn=lambda: (_limit(resource.RLIMIT_CPU, 5),
                                                       _limit(resource.RLIMIT_AS, 512 * 1024**2),
                                                       _limit(resource.RLIMIT_FSIZE, MAX_OUTPUT_BYTES)))
        selector = selectors.DefaultSelector()
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + min(timeout, 5)
        problem = None
        try:
            try:
                process.stdin.write(stdin)
                process.stdin.close()
            except BrokenPipeError:
                process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    problem = 'replay timeout'
                    break
                for key, _ in selector.select(min(remaining, .1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(errors) + len(chunk) > MAX_OUTPUT_BYTES:
                        problem = 'replay output limit reached'
                        break
                    else:
                        key.data.extend(chunk)
                if problem:
                    break
        finally:
            selector.close()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
        return {'attempted': True, 'returncode': process.returncode,
                'stdout_hex': bytes(output).hex(), 'stderr_hex': bytes(errors).hex(),
                'problem': problem}


def inspect_checker(path: Path, checker: dict, *, execute_local: bool = False,
                    replay: bool = False, timeout: float = 20,
                    max_steps: int = MAX_STEPS,
                    scratch_dir: Path | None = None) -> tuple[dict, list[str]]:
    """Search a local checker only after explicit execution authorization.

    `replay=True` authorizes a separate concrete run. A symbolic candidate is not a
    validated input, and replay success is not challenge acceptance.
    """
    hints = _hints(checker)
    if type(execute_local) is not bool or type(replay) is not bool or (replay and not execute_local):
        raise ValueError('checker execution and replay require explicit boolean authorization')
    if not 0 < timeout <= 60 or type(max_steps) is not int or not 1 <= max_steps <= MAX_STEPS:
        raise ValueError('checker time and step limits are invalid')
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError('checker path cannot be a symlink')
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SOURCE_BYTES:
        raise ValueError('checker must be a bounded regular file')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    report = {'status': 'skipped_execution', 'source': str(path), 'source_sha256': digest,
              'checker': hints, 'replay': {'attempted': False}}
    if not execute_local:
        return report, []
    if not os.access(path, os.X_OK):
        return {**report, 'status': 'skipped_prerequisite',
                'reason': 'checker is not executable'}, []
    if scratch_dir is not None:
        scratch_dir = Path(scratch_dir).absolute()
        if scratch_dir.is_symlink() or not scratch_dir.is_dir():
            raise ValueError('checker scratch directory must be a real directory')
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe(duplex=False)
    deadline = time.monotonic() + timeout
    worker = context.Process(target=_solve,
                             args=(path, hints, max_steps, deadline, child, scratch_dir))
    try:
        worker.start()
    except Exception:
        parent.close()
        child.close()
        raise
    child.close()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if parent.poll(max(0, min(.1, remaining))):
                outcome = parent.recv()
                break
            if not worker.is_alive():
                outcome = {'status': 'incomplete', 'reason': 'symbolic worker stopped without a result'}
                break
            if remaining <= 0:
                outcome = {'status': 'timeout', 'reason': 'symbolic worker timed out'}
                break
    except EOFError:
        outcome = {'status': 'incomplete', 'reason': 'symbolic worker stopped without a result'}
    finally:
        worker.terminate()
        worker.join(.5)
        if worker.is_alive():
            worker.kill()
            worker.join()
        parent.close()
    report.update(outcome)
    if report['status'] == 'candidate' and replay:
        try:
            report['replay'] = _replay(path, hints, bytes.fromhex(report['candidate_hex']),
                                       max(.01, deadline - time.monotonic()), scratch_dir)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report['replay'] = {'attempted': True, 'problem': f'{type(error).__name__}: {error}'[:200]}
        if report['replay']['problem'] is None:
            if 'stdout' in hints['find']:
                stdout = bytes.fromhex(report['replay']['stdout_hex'])
                reached = (report['replay']['returncode'] == 0 and
                           hints['find']['stdout'].encode('utf-8') in stdout and
                           not (hints['avoid'] and 'stdout' in hints['avoid'] and
                                hints['avoid']['stdout'].encode('utf-8') in stdout))
            else:
                reached = False
            if reached:
                report['status'] = 'validated_input'
            elif 'stdout' in hints['find']:
                report['status'] = 'replay_failed'
        else:
            report['status'] = 'incomplete'
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        report['status'] = 'incomplete'
        report['reason'] = 'checker source changed during analysis'
    return report, []
