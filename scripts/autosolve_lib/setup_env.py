"""Install the reviewed autosolve Python core into a task-owned uv environment."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def _writable_paths_safe(root: Path, env: Path) -> bool:
    autosolve = root / '.autosolve'
    cache = autosolve / 'cache/uv'
    managed_python = autosolve / 'python'
    if any(path.is_symlink() for path in (autosolve, autosolve / 'envs',
                                          autosolve / 'cache', cache,
                                          managed_python, env)):
        return False
    for tree in (cache, managed_python, env):
        if not tree.exists():
            continue
        scan_errors = []
        for directory, dirs, files in os.walk(tree, followlinks=False,
                                              onerror=scan_errors.append):
            for name in dirs + files:
                path = Path(directory) / name
                if not path.is_symlink():
                    continue
                # uv venv links these executable names to the base interpreter.
                if tree == env and path.parent == env / 'bin' and name in (
                        'python', 'python3', 'python3.12'):
                    continue
                target = path.readlink()
                destination = Path(os.path.normpath(str(
                    target if target.is_absolute() else path.parent / target)))
                if not destination.is_relative_to(tree):
                    return False
        if scan_errors:
            return False
    return True


def prepare(root: Path | None = None) -> dict:
    root = root or Path(__file__).resolve().parents[2]
    lock = root / 'scripts/autosolve_requirements/core.lock.txt'
    env = root / '.autosolve/envs/core'
    python = env / 'bin/python'
    result = {'status': 'partial', 'environment': str(env), 'python': str(python),
              'installed': [], 'interpreter_request': 'cpython3.12'}
    uv = shutil.which('uv')
    if not uv:
        return {**result, 'reason': 'uv_missing'}
    if not lock.is_file():
        return {**result, 'reason': 'core_lock_missing'}
    if not _writable_paths_safe(root, env):
        return {**result, 'reason': 'setup_path_is_symlink'}
    if env.is_symlink() or (env.exists() and not (env / 'pyvenv.cfg').is_file()):
        return {**result, 'reason': 'core_environment_path_not_a_venv'}
    result['lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
    environment = os.environ.copy()
    environment['UV_CACHE_DIR'] = str(root / '.autosolve/cache/uv')
    environment['UV_PYTHON_INSTALL_DIR'] = str(root / '.autosolve/python')
    commands = []
    if not env.exists():
        commands.append(('venv', [uv, 'venv', '--no-project', '--no-config',
                                  '--python', 'cpython3.12', str(env)]))
    commands.extend([
        ('python', [str(python), '-c',
                    'import json,platform,sys; print(json.dumps({'
                    '"implementation":platform.python_implementation(),'
                    '"version":list(sys.version_info[:2]),"prefix":sys.prefix,'
                    '"base_executable":sys._base_executable}))']),
        ('sync', [uv, 'pip', 'sync', '--no-config', '--python', str(python),
                  '--require-hashes', '--only-binary', ':all:', str(lock)]),
    ])
    for stage, command in commands:
        if not _writable_paths_safe(root, env):
            return {**result, 'reason': 'setup_path_is_symlink'}
        try:
            run = subprocess.run(command, capture_output=True, timeout=240,
                                 check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            return {**result, 'reason': f'{stage}_could_not_run'}
        if run.returncode:
            return {**result, 'reason': f'{stage}_failed', 'exit_code': run.returncode}
        if stage == 'python':
            try:
                details = json.loads(run.stdout)
                valid = (details['implementation'] == 'CPython' and
                         details['version'] == [3, 12] and
                         Path(details['prefix']).resolve() == env.resolve())
            except (ValueError, KeyError, TypeError):
                valid = False
            if not valid:
                return {**result, 'reason': 'python_not_cpython_3_12'}
            result['interpreter'] = details
    return {**result, 'status': 'ready', 'installed': ['core']}
