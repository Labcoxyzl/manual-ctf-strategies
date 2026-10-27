"""Product jobs keep optional tool scratch files inside their run."""

import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from scripts.autosolve_lib import core
from scripts.autosolve_lib.profiles import checker, zsteg


class ProductScratchScopeTests(unittest.TestCase):
    def test_zsteg_worker_supplies_private_job_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            source = run / 'source.png'
            source.write_bytes(b'PNG fixture')
            staging = run / 'staging' / 'job'
            seen = {}

            def inspect(path, output, **kwargs):
                seen.update(kwargs)
                self.assertEqual(path, source)
                self.assertEqual(output, staging)
                self.assertTrue(staging.is_dir())
                self.assertEqual(staging.stat().st_mode & 0o077, 0)
                return [], []

            pipe = mock.Mock()
            with mock.patch.object(core.resource, 'setrlimit'), mock.patch.object(
                    zsteg, 'inspect_lsb', side_effect=inspect):
                core._zsteg_worker(source, staging, 100, 1024, 2, pipe)
            self.assertEqual(seen['scratch_dir'], staging)
            pipe.send.assert_called_once_with(('ok', [], []))

    def test_checker_job_supplies_private_scratch_and_removes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / 'run'
            (run / 'jobs').mkdir(parents=True)
            source = Path(directory) / 'checker'
            source.write_bytes(b'checker fixture')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            artifact = {'id': 'source', 'path': str(source), 'sha256': digest}
            manifest = {
                'execute_local': True, 'coverage': {'REV07': {'status': 'not scheduled'}},
                'current_adapter_fingerprints': {'checker': ['test-fingerprint']},
                'checker_hints_sha256': 'test-hints', 'jobs': [], 'findings': [], 'warnings': [],
            }
            seen = {}

            def inspect(path, hints, **kwargs):
                seen.update(kwargs)
                scratch = kwargs['scratch_dir']
                self.assertEqual(path, source)
                self.assertEqual(hints, {'channel': 'argv'})
                self.assertEqual(scratch.parent, run / 'staging')
                self.assertTrue(scratch.is_dir())
                self.assertEqual(scratch.stat().st_mode & 0o077, 0)
                return {'status': 'unsat_under_model', 'source_sha256': digest,
                        'reason': 'fixture has no solution'}, []

            with mock.patch.object(checker, 'inspect_checker', side_effect=inspect):
                core._checker_job(run, manifest, artifact, {'channel': 'argv'},
                                  False, time.monotonic() + 10)
            self.assertEqual(manifest['jobs'][0]['status'], 'complete', manifest['jobs'])
            self.assertEqual(manifest['coverage']['REV07']['status'], 'no finding')
            self.assertFalse(seen['scratch_dir'].exists())
            report = json.loads(Path(manifest['jobs'][0]['report_path']).read_text())
            self.assertEqual(report['status'], 'unsat_under_model')

    def test_symlinked_staging_parent_cannot_redirect_tool_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'run'
            (run / 'jobs').mkdir(parents=True)
            outside = root / 'outside'
            (outside / 'known').mkdir(parents=True)
            sentinel = outside / 'known' / 'keep'
            sentinel.write_text('untouched')
            (run / 'staging').symlink_to(outside, target_is_directory=True)
            source = root / 'checker'
            source.write_bytes(b'checker fixture')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = {
                'execute_local': True, 'coverage': {'REV07': {'status': 'not scheduled'}},
                'current_adapter_fingerprints': {'checker': ['test-fingerprint']},
                'checker_hints_sha256': 'test-hints', 'jobs': [], 'findings': [], 'warnings': [],
            }
            with (mock.patch.object(core.uuid, 'uuid4', return_value=mock.Mock(hex='known')),
                  mock.patch.object(checker, 'inspect_checker') as inspect):
                core._checker_job(run, manifest,
                                  {'id': 'source', 'path': str(source), 'sha256': digest},
                                  {'channel': 'argv'}, False, time.monotonic() + 10)
            inspect.assert_not_called()
            self.assertEqual(manifest['jobs'][0]['status'], 'failed')
            self.assertEqual(sentinel.read_text(), 'untouched')

            pipe = mock.Mock()
            with mock.patch.object(core.resource, 'setrlimit'), mock.patch.object(
                    zsteg, 'inspect_lsb') as inspect:
                core._zsteg_worker(source, run / 'staging' / 'known', 100, 1024, 2, pipe)
            inspect.assert_not_called()
            self.assertEqual(pipe.send.call_args.args[0][0], 'error')
            self.assertEqual(sentinel.read_text(), 'untouched')


if __name__ == '__main__':
    unittest.main()
