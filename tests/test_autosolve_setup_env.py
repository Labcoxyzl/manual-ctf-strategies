import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from autosolve_lib import setup, setup_env


class SetupEnvironmentTests(unittest.TestCase):
    def test_ai_cpu_prepares_a_separate_hash_checked_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'scripts/autosolve_requirements/ai-cpu.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('torch==2.9.1+cpu --hash=sha256:' + '0' * 64 + '\n')
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                self.assertEqual(kwargs['env']['UV_CACHE_DIR'], str(root / '.autosolve/cache/uv'))
                self.assertNotIn('UV_EXTRA_INDEX_URL', kwargs['env'])
                self.assertNotIn('PIP_INDEX_URL', kwargs['env'])
                if command[0].endswith('/bin/python'):
                    data = {'implementation': 'CPython', 'version': [3, 12],
                            'prefix': str(root / '.autosolve/envs/ai-cpu')}
                    return subprocess.CompletedProcess(command, 0, json.dumps(data).encode(), b'')
                return subprocess.CompletedProcess(command, 0, b'', b'')

            with mock.patch.dict(os.environ, {'UV_EXTRA_INDEX_URL': 'https://untrusted.invalid/simple',
                                              'PIP_INDEX_URL': 'https://untrusted.invalid/simple'}), \
                 mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                result = setup_env.prepare(root, environment_name='ai-cpu')
            self.assertEqual(result['status'], 'ready')
            self.assertEqual(result['installed'], ['ai-cpu'])
            self.assertEqual(result['environment'], str(root / '.autosolve/envs/ai-cpu'))
            self.assertIn('--require-hashes', commands[-1])
            self.assertIn('https://pypi.org/simple', commands[-1])
            self.assertEqual(commands[-1][-1], str(lock))
            self.assertFalse((root / '.autosolve/envs/core').exists())

    def test_ai_cpu_wrong_arch_and_missing_uv_leave_core_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(setup_env.platform, 'machine', return_value='aarch64'), \
                 mock.patch.object(setup_env.shutil, 'which') as which:
                wrong_arch = setup_env.prepare_ai_cpu(root)
            self.assertEqual(wrong_arch['reason'], 'ai_cpu_requires_linux_x86_64')
            self.assertEqual(wrong_arch['functional_probe'], 'not_run')
            which.assert_not_called()
            with mock.patch.object(setup_env.shutil, 'which', return_value=None):
                missing_uv = setup_env.prepare_ai_cpu(root)
            self.assertEqual(missing_uv['reason'], 'uv_missing')
            self.assertFalse((root / '.autosolve').exists())

    def test_ai_cpu_sync_failure_is_partial_without_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'scripts/autosolve_requirements/ai-cpu.lock.txt'
            lock.parent.mkdir(parents=True)
            lock.write_text('torch==2.9.1+cpu --hash=sha256:' + '0' * 64 + '\n')

            def run(command, **kwargs):
                if command[0].endswith('/bin/python'):
                    data = {'implementation': 'CPython', 'version': [3, 12],
                            'prefix': str(root / '.autosolve/envs/ai-cpu')}
                    return subprocess.CompletedProcess(command, 0, json.dumps(data).encode(), b'')
                return subprocess.CompletedProcess(command, 1 if command[1:3] == ['pip', 'sync'] else 0,
                                                   b'', b'offline or unavailable wheel')

            with mock.patch.object(setup_env.shutil, 'which', return_value='/usr/bin/uv'), \
                 mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                result = setup_env.prepare_ai_cpu(root)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['reason'], 'sync_failed')
            self.assertEqual(result['functional_probe'], 'not_run')

    def test_ai_cpu_probe_checks_public_gradient_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.autosolve').mkdir()
            prepared = {'status': 'ready', 'python': '/tmp/ai-cpu/bin/python',
                        'environment': str(root / '.autosolve/envs/ai-cpu'), 'installed': ['ai-cpu']}

            def run(command, **kwargs):
                if command[1:3] == ['-I', '-c']:
                    self.assertIn('allow_pickle=False', command[3])
                    return subprocess.CompletedProcess(command, 0, json.dumps({
                        'shape': [2], 'dtype': 'float32', 'values': [.4, .5]}).encode(), b'')
                self.assertEqual(command[1], '-I')
                self.assertTrue(command[2].endswith('/scripts/ai_model_attack.py'))
                self.assertIn('--execute-local', command)
                self.assertIn('gradient', command)
                probe = Path(command[command.index('--runs-root') + 1])
                probe.mkdir()
                report = probe / 'result.json'
                candidate = probe / 'candidate.npy'
                candidate.write_bytes(b'generated')
                report.write_text(json.dumps({'state': 'candidate', 'clean_objective': .5,
                                              'candidate_objective': .9, 'max_abs_change': .2}))
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    'status': 'complete', 'report': str(report),
                    'candidate_file': str(candidate)}).encode(), b'')

            with mock.patch.object(setup_env, 'prepare', return_value=prepared), \
                 mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                result = setup_env.prepare_ai_cpu(root)
            self.assertEqual(result['functional_probe'], 'passed')
            self.assertEqual(result['operation'], 'aic02.gradient')
            self.assertEqual(result['status'], 'ready')

    def test_ai_cpu_probe_rejects_corrupt_or_wrong_candidate_tensor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.autosolve').mkdir()
            prepared = {'status': 'ready', 'python': '/tmp/ai-cpu/bin/python',
                        'environment': str(root / '.autosolve/envs/ai-cpu'), 'installed': ['ai-cpu']}
            for check_code, values in ((1, None), (0, [.2, .3])):
                with self.subTest(check_code=check_code, values=values):
                    def run(command, **kwargs):
                        if command[1:3] == ['-I', '-c']:
                            body = json.dumps({'shape': [2], 'dtype': 'float32',
                                               'values': values}).encode()
                            return subprocess.CompletedProcess(command, check_code, body, b'')
                        runs = Path(command[command.index('--runs-root') + 1])
                        runs.mkdir()
                        candidate = runs / 'candidate.npy'
                        candidate.write_bytes(b'candidate')
                        report = runs / 'result.json'
                        report.write_text(json.dumps({'state': 'candidate', 'clean_objective': .5,
                                                      'candidate_objective': .9,
                                                      'max_abs_change': .2}))
                        body = json.dumps({'status': 'complete', 'report': str(report),
                                           'candidate_file': str(candidate)}).encode()
                        return subprocess.CompletedProcess(command, 0, body, b'')

                    with mock.patch.object(setup_env, 'prepare', return_value=prepared), \
                         mock.patch.object(setup_env.subprocess, 'run', side_effect=run):
                        result = setup_env.prepare_ai_cpu(root)
                    self.assertEqual(result['status'], 'partial')
                    self.assertEqual(result['reason'], 'ai_cpu_probe_failed')
                    self.assertEqual(result['functional_probe'], 'failed')

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
