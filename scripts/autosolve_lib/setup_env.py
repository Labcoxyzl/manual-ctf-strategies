"""Install the reviewed autosolve Python core into a task-owned uv environment."""

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def _task_temporary(root: Path) -> Path:
    """Create private probe scratch below the exported toolkit without following links."""
    directory = root / '.autosolve/tmp'
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in ('.autosolve', 'tmp'):
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            try:
                state = os.fstat(child)
                if state.st_uid != os.geteuid():
                    raise OSError('autosolve scratch directory is not owned by this user')
                if stat.S_IMODE(state.st_mode) != 0o700:
                    os.fchmod(child, 0o700)
                    if stat.S_IMODE(os.fstat(child).st_mode) != 0o700:
                        raise OSError('autosolve scratch directory is not private')
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    return directory


def _writable_paths_safe(root: Path, env: Path) -> bool:
    autosolve = root / '.autosolve'
    cache = autosolve / 'cache/uv'
    managed_python = autosolve / 'python'
    temporary = autosolve / 'tmp'
    if any(path.is_symlink() for path in (autosolve, autosolve / 'envs',
                                          autosolve / 'cache', cache,
                                          managed_python, temporary, env)):
        return False
    for tree in (cache, managed_python, temporary, env):
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


def prepare(root: Path | None = None, environment_name: str = 'core') -> dict:
    root = root or Path(__file__).resolve().parents[2]
    if environment_name not in ('core', 'ai-cpu', 'checker'):
        raise ValueError('unknown autosolve environment')
    lock = root / f'scripts/autosolve_requirements/{environment_name}.lock.txt'
    env = root / '.autosolve/envs' / environment_name
    python = env / 'bin/python'
    result = {'status': 'partial', 'environment': str(env), 'python': str(python),
              'installed': [], 'interpreter_request': 'cpython3.12'}
    if environment_name in ('ai-cpu', 'checker') and (
            sys.platform != 'linux' or platform.machine() != 'x86_64'):
        return {**result, 'reason': f'{environment_name.replace("-", "_")}_requires_linux_x86_64'}
    uv = shutil.which('uv')
    if not uv:
        return {**result, 'reason': 'uv_missing'}
    if not lock.is_file():
        return {**result, 'reason': f'{environment_name}_lock_missing'}
    wheels = root / 'scripts/autosolve_requirements/wheels'
    if environment_name == 'checker' and (wheels.is_symlink() or not wheels.is_dir() or
            any(not (wheels / name).is_file() or (wheels / name).is_symlink() for name in (
                'arpy-1.1.1-py3-none-any.whl', 'mulpyplexer-0.9-py3-none-any.whl'))):
        return {**result, 'reason': 'checker_wheels_missing_or_symlink'}
    if not _writable_paths_safe(root, env):
        return {**result, 'reason': 'setup_path_is_symlink'}
    if env.is_symlink() or (env.exists() and not (env / 'pyvenv.cfg').is_file()):
        return {**result, 'reason': f'{environment_name}_environment_path_not_a_venv'}
    try:
        temporary = _task_temporary(root)
    except OSError:
        return {**result, 'reason': f'{environment_name}_temporary_directory_unavailable'}
    result['lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
    environment = os.environ.copy()
    environment['UV_CACHE_DIR'] = str(root / '.autosolve/cache/uv')
    environment['UV_PYTHON_INSTALL_DIR'] = str(root / '.autosolve/python')
    environment.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary))
    if environment_name in ('ai-cpu', 'checker'):
        for name in ('UV_INDEX', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_DEFAULT_INDEX',
                     'UV_FIND_LINKS', 'UV_NO_INDEX', 'UV_INDEX_STRATEGY', 'UV_TORCH_BACKEND',
                     'UV_NO_VERIFY_HASHES', 'UV_NO_BINARY', 'UV_ONLY_BINARY',
                     'UV_NO_BUILD_ISOLATION', 'UV_BUILD_CONSTRAINT',
                     'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_FIND_LINKS', 'PIP_NO_INDEX'):
            environment.pop(name, None)
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
                  *(['--default-index', 'https://pypi.org/simple']
                    if environment_name in ('ai-cpu', 'checker') else []),
                  *(['--find-links', str(wheels)] if environment_name == 'checker' else []),
                  '--require-hashes', '--only-binary', ':all:',
                  str(lock)]),
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
    return {**result, 'status': 'ready', 'installed': [environment_name]}


def prepare_ai_cpu(root: Path | None = None) -> dict:
    """Install and exercise the opt-in CPU-only AIC02 environment."""
    root = root or Path(__file__).resolve().parents[2]
    prepared = prepare(root, environment_name='ai-cpu')
    if prepared['status'] != 'ready':
        return {**prepared, 'functional_probe': 'not_run'}
    env = root / '.autosolve/envs/ai-cpu'
    if not _writable_paths_safe(root, env):
        return {**prepared, 'status': 'partial', 'reason': 'setup_path_is_symlink',
                'functional_probe': 'not_run'}
    try:
        with tempfile.TemporaryDirectory(prefix='ai-cpu-probe-', dir=root / '.autosolve') as directory:
            probe = Path(directory)
            (probe / 'model.bin').write_bytes(b'generated-model-marker')
            (probe / 'input.bin').write_bytes(b'generated-input-marker')
            (probe / 'adapter.py').write_text(
                'import torch\n'
                'def load_model(path): return torch.nn.Identity()\n'
                'def load_input(path): return torch.tensor([0.2, 0.3], dtype=torch.float32)\n'
                'def loss(model, x, target): return model(x).sum()\n')
            command = [prepared['python'], '-I', str(root / 'scripts/ai_model_attack.py'),
                       '--runs-root', str(probe / 'runs'), '--adapter', str(probe / 'adapter.py'),
                       '--execute-local', '--budget', '30', 'gradient',
                       '--model', str(probe / 'model.bin'), '--input', str(probe / 'input.bin'),
                       '--target', 'up', '--epsilon', '.2', '--step-size', '.1', '--steps', '2']
            run = subprocess.run(command, capture_output=True, timeout=45, check=False)
            if run.returncode != 0:
                raise ValueError('gradient command failed')
            output = json.loads(run.stdout)
            report_path = Path(output['report'])
            candidate = Path(output['candidate_file'])
            if not (report_path.resolve().is_relative_to(probe.resolve())
                    and candidate.resolve().is_relative_to(probe.resolve())
                    and candidate.is_file() and 0 < candidate.stat().st_size <= 4096):
                raise ValueError('gradient output path or size failed validation')
            report = json.loads(report_path.read_text())
            check = subprocess.run([prepared['python'], '-I', '-c',
                                    'import json,numpy as np,sys; x=np.load(sys.argv[1],allow_pickle=False); '
                                    'print(json.dumps({"shape":x.shape,"dtype":str(x.dtype),"values":x.tolist()}))',
                                    str(candidate)], capture_output=True, timeout=20, check=False)
            if check.returncode != 0:
                raise ValueError('gradient tensor could not be loaded')
            tensor = json.loads(check.stdout)
            if not (output['status'] == 'complete' and report['state'] == 'candidate'
                    and abs(report['clean_objective'] - .5) < 1e-5
                    and abs(report['candidate_objective'] - .9) < 1e-5
                    and abs(report['max_abs_change'] - .2) < 1e-5
                    and tensor['shape'] == [2] and tensor['dtype'] == 'float32'
                    and len(tensor['values']) == 2
                    and all(abs(value - expected) < 1e-5 for value, expected in
                            zip(tensor['values'], (.4, .5)))):
                raise ValueError('gradient result failed validation')
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return {**prepared, 'status': 'partial', 'reason': 'ai_cpu_probe_failed',
                'functional_probe': 'failed'}
    return {**prepared, 'functional_probe': 'passed', 'operation': 'aic02.gradient'}


def prepare_checker(root: Path | None = None) -> dict:
    """Install and exercise the opt-in REV07 symbolic checker environment."""
    root = root or Path(__file__).resolve().parents[2]
    prepared = prepare(root, environment_name='checker')
    if prepared['status'] != 'ready':
        return {**prepared, 'functional_probe': 'not_run'}
    env = root / '.autosolve/envs/checker'
    if not _writable_paths_safe(root, env):
        return {**prepared, 'status': 'partial', 'reason': 'setup_path_is_symlink',
                'functional_probe': 'not_run'}
    temporary = root / '.autosolve/tmp'
    try:
        temporary.mkdir(parents=True, exist_ok=True)
    except OSError:
        return {**prepared, 'status': 'partial', 'reason': 'checker_temporary_directory_unavailable',
                'functional_probe': 'not_run'}
    if not _writable_paths_safe(root, env):
        return {**prepared, 'status': 'partial', 'reason': 'setup_path_is_symlink',
                'functional_probe': 'not_run'}
    command = [prepared['python'], '-I', str(root / 'scripts/autosolve.py'),
               '--json', 'doctor', '--profiles', 'malware_reversing', '--self-test']
    try:
        environment = {**os.environ, 'TMPDIR': str(temporary), 'TMP': str(temporary),
                       'TEMP': str(temporary)}
        run = subprocess.run(command, capture_output=True, timeout=180,
                             check=False, env=environment)
        doctor = json.loads(run.stdout)
        operation = doctor['operations']['malware_reversing.checker']
        engine = doctor['engines']['angr']
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return {**prepared, 'status': 'partial', 'reason': 'checker_probe_failed',
                'functional_probe': 'failed'}
    if run.returncode not in (0, 3) or operation.get('functional_probe') != 'passed' or (
            engine.get('status') != 'ready'):
        return {**prepared, 'status': 'partial',
                'reason': operation.get('reason', 'checker_probe_failed'),
                'functional_probe': operation.get('functional_probe', 'failed'),
                'probe_detail': operation.get('probe_detail')}
    return {**prepared, 'functional_probe': 'passed', 'operation': 'rev07.checker',
            'engine_version': engine.get('version')}
