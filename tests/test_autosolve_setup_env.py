import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from autosolve_lib import setup, setup_env


class SetupEnvironmentTests(unittest.TestCase):
    def test_prepare_uses_explicit_python_and_hash_checked_wheel_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'scripts/autosolve_requirements/core.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('pypdf==6.11.0 --hash=sha256:' + '0' * 64 + '\n')
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                self.assertEqual(kwargs['env']['UV_CACHE_DIR'], str(root / '.autosolve/cache/uv'))
                self.assertEqual(kwargs['env']['UV_PYTHON_INSTALL_DIR'], str(root / '.autosolve/python'))
                if command[0].endswith('/bin/python'):
                    data = {'implementation': 'CPython', 'version': [3, 12],
                            'prefix': str(root / '.autosolve/envs/core')}
                    return subprocess.CompletedProcess(command, 0, json.dumps(data).encode(), b'')
                return subprocess.CompletedProcess(command, 0, b'', b'')

            with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                result = setup_env.prepare(root)
            self.assertEqual(result['status'], 'ready')
            self.assertEqual(result['installed'], ['core'])
            self.assertEqual(commands[0][1:5], ['venv', '--no-project', '--no-config', '--python'])
            self.assertIn('cpython3.12', commands[0])
            self.assertEqual(commands[-1][1:4], ['pip', 'sync', '--no-config'])
            self.assertIn('--require-hashes', commands[-1])
            self.assertEqual(commands[-1][-3:-1], ['--only-binary', ':all:'])
            self.assertEqual(commands[-1][-1], str(lock))

    def test_prepare_preserves_an_existing_non_venv_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'scripts/autosolve_requirements/core.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('pypdf==6.11.0 --hash=sha256:' + '0' * 64 + '\n')
            env = root / '.autosolve/envs/core'
            env.mkdir(parents=True)
            (env / 'keep.txt').write_text('user data')
            with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run') as run:
                result = setup_env.prepare(root)
            self.assertEqual(result['reason'], 'core_environment_path_not_a_venv')
            self.assertEqual((env / 'keep.txt').read_text(), 'user data')
            run.assert_not_called()

    def test_prepare_rejects_cache_symlink_outside_task_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            outside = Path(directory) / 'protected'
            outside.mkdir()
            (outside / 'keep.txt').write_text('untouched')
            lock = root / 'scripts/autosolve_requirements/core.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('pypdf==6.11.0 --hash=sha256:' + '0' * 64 + '\n')
            cache = root / '.autosolve/cache/uv'
            cache.parent.mkdir(parents=True)
            cache.symlink_to(outside, target_is_directory=True)
            with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run') as run:
                result = setup_env.prepare(root)
            self.assertEqual(result['reason'], 'setup_path_is_symlink')
            self.assertEqual((outside / 'keep.txt').read_text(), 'untouched')
            run.assert_not_called()

    def test_prepare_rejects_venv_writable_descendant_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            outside = Path(directory) / 'protected'
            outside.mkdir()
            (outside / 'keep.txt').write_text('untouched')
            lock = root / 'scripts/autosolve_requirements/core.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('pypdf==6.11.0 --hash=sha256:' + '0' * 64 + '\n')
            env = root / '.autosolve/envs/core'
            env.mkdir(parents=True)
            (env / 'pyvenv.cfg').write_text('home = /usr/bin\n')
            for relative in ('lib', 'bin/pip', 'lib/python3.12/site-packages'):
                with self.subTest(relative=relative):
                    target = env / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(outside, target_is_directory=True)
                    with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                         mock.patch.object(setup_env.subprocess, 'run') as run:
                        result = setup_env.prepare(root)
                    self.assertEqual(result['reason'], 'setup_path_is_symlink')
                    self.assertEqual((outside / 'keep.txt').read_text(), 'untouched')
                    run.assert_not_called()
                    target.unlink()

    def test_wrong_interpreter_fails_before_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'scripts/autosolve_requirements/core.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('pypdf==6.11.0 --hash=sha256:' + '0' * 64 + '\n')
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[0].endswith('/bin/python'):
                    data = {'implementation': 'CPython', 'version': [3, 11],
                            'prefix': str(root / '.autosolve/envs/core')}
                    return subprocess.CompletedProcess(command, 0, json.dumps(data).encode(), b'')
                return subprocess.CompletedProcess(command, 0, b'')

            with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                result = setup_env.prepare(root)
            self.assertEqual(result['reason'], 'python_not_cpython_3_12')
            self.assertEqual(len(commands), 2)

    def test_setup_runs_doctor_in_installed_interpreter(self):
        prepared = {'status': 'ready', 'installed': ['core'], 'python': '/tmp/core/bin/python'}
        checked = {'status': 'partial', 'profiles': ['encoding'], 'operations': {}}
        with mock.patch.object(setup_env, 'prepare', return_value=prepared), \
             mock.patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess(
                 [], 3, json.dumps(checked).encode(), b'')) as run:
            result = setup.setup(['encoding'])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['installed'], ['core'])
        self.assertEqual(run.call_args.args[0][0], '/tmp/core/bin/python')
        self.assertIn('--self-test', run.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
