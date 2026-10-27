"""Bounded 7z extraction through the helper and public CLI."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import sevenzip
from scripts.autosolve_lib.profiles.sevenzip import extract_7z, _listing
from scripts.autosolve_lib import setup as capabilities


class ListingSafetyTests(unittest.TestCase):
    def test_windows_attributes_without_posix_mode(self):
        def listing(attributes, extra=''):
            return (f'Path = payload.txt\nSize = 1\nAttributes = {attributes}\n'
                    f'Encrypted = -\n{extra}').encode()

        for attributes in ('A', 'RA ----------', ''):
            with self.subTest(attributes=attributes):
                self.assertTrue(_listing(listing(attributes))[0]['regular'])
        for attributes in ('D', 'L', 'd', '8', 'AL', 'A lrwxrwxrwx', 'A 00000400', 'AA'):
            with self.subTest(attributes=attributes):
                self.assertFalse(_listing(listing(attributes))[0]['regular'])
        self.assertFalse(_listing(listing('A', 'Symbolic Link = target\n'))[0]['regular'])
        self.assertFalse(_listing(listing('A', 'Folder = +\n'))[0]['regular'])

    def test_rejects_ambiguous_and_traversal_members(self):
        for name in ('../outside', '/absolute', 'C:/drive', 'a\\b', '-option', 'a/./b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _listing(f'Path = {name}\nSize = 1\nAttributes = A -rw-r--r--\nEncrypted = -\n'.encode())
        with self.assertRaises(ValueError):
            _listing(b'Path = good\nPath = bad\nSize = 1\nAttributes = A -rw-r--r--\nEncrypted = -\n')

    def test_missing_binary_is_an_explicit_prerequisite(self):
        with mock.patch.object(capabilities.shutil, 'which', return_value=None):
            operation, engine = capabilities._sevenzip_probe(True)
        self.assertEqual(operation['status'], 'unavailable')
        self.assertFalse(engine['found'])


@unittest.skipUnless(shutil.which('7z') or shutil.which('7zz'), '7-Zip unavailable')
class SevenZipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tool = shutil.which('7z') or shutil.which('7zz')

    def archive(self, *, hidden=True, data=b'DOC{sevenzip_oracle}\n'):
        member = self.root / 'nested' / 'payload.txt'
        member.parent.mkdir(exist_ok=True)
        member.write_bytes(data)
        target = self.root / ('hidden.7z' if hidden else 'visible.7z')
        subprocess.run([self.tool, 'a', '-t7z', '-mx=1', '-psecret',
                        '-mhe=on' if hidden else '-mhe=off', str(target), 'nested/payload.txt'],
                       cwd=self.root, check=True, capture_output=True)
        return target

    def extract(self, path, label, passwords, *, limit=1024):
        return extract_7z(path, self.root / label, max_members=10,
                          max_total_bytes=limit, max_member_bytes=limit,
                          passwords=passwords, executable=self.tool)

    def test_encrypted_header_wrong_password_and_expansion_limit(self):
        source = self.archive()
        records, warnings = self.extract(source, 'right', [b'wrong', b'secret'])
        self.assertEqual(warnings, [])
        self.assertEqual([(row['member'], row['path'].read_bytes(), row['encrypted'])
                          for row in records], [('nested/payload.txt', b'DOC{sevenzip_oracle}\n', True)])
        records, warnings = self.extract(source, 'wrong', [b'wrong'])
        self.assertEqual(records, [])
        self.assertTrue(any('passwords did not validate' in warning for warning in warnings))
        records, warnings = self.extract(source, 'missing', [])
        self.assertEqual(records, [])
        self.assertTrue(any('password required' in warning for warning in warnings))

        visible = self.archive(hidden=False)
        records, warnings = self.extract(visible, 'visible', [b'wrong', b'secret'])
        self.assertEqual(warnings, [])
        self.assertEqual(records[0]['path'].read_bytes(), b'DOC{sevenzip_oracle}\n')

        source = self.archive(hidden=False, data=b'A' * 4096)
        records, warnings = self.extract(source, 'large', [b'secret'], limit=128)
        self.assertEqual(records, [])
        self.assertTrue(any('expanded byte limit' in warning for warning in warnings))

        shared = self.root / 'shared'
        shared.mkdir(mode=0o755)
        os.chmod(shared, 0o755)
        with self.assertRaisesRegex(ValueError, 'readable by other users'):
            extract_7z(source, shared, max_members=10, max_total_bytes=128,
                       max_member_bytes=128, passwords=[b'secret'], executable=self.tool)

    def test_link_and_absolute_member_are_rejected(self):
        target = self.archive(hidden=False)
        link = self.root / 'link'
        link.symlink_to('nested/payload.txt')
        linked = self.root / 'linked.7z'
        subprocess.run([self.tool, 'a', '-t7z', '-snl', str(linked), 'link'],
                       cwd=self.root, check=True, capture_output=True)
        records, warnings = self.extract(linked, 'link-out', [])
        self.assertEqual(records, [])
        self.assertTrue(any('unsafe' in warning for warning in warnings))

        absolute = self.root / 'absolute.7z'
        subprocess.run([self.tool, 'a', '-t7z', '-spf', str(absolute),
                        str(self.root / 'nested' / 'payload.txt')],
                       cwd=self.root, check=True, capture_output=True)
        records, warnings = self.extract(absolute, 'absolute-out', [])
        self.assertEqual(records, [])
        self.assertTrue(any('unsafe' in warning for warning in warnings))
        self.assertTrue(target.exists())

    def test_encrypted_empty_password_is_supplied(self):
        member = self.root / 'empty.txt'
        member.write_bytes(b'known empty-password payload')
        source = self.root / 'empty.7z'
        subprocess.run([self.tool, 'a', '-t7z', '-mx=1', '-p', '-mhe=on',
                        str(source), member.name], input=b'\n', cwd=self.root,
                       check=True, capture_output=True)
        with mock.patch.object(sevenzip, '_invoke', wraps=sevenzip._invoke) as invoke:
            records, warnings = self.extract(source, 'empty-right', [b'wrong', b''])
        self.assertEqual(warnings, [])
        self.assertEqual([row['path'].read_bytes() for row in records], [member.read_bytes()])
        self.assertTrue(records[0]['encrypted'])
        self.assertEqual([call.args[2] for call in invoke.call_args_list if call.args[1][0] == 'e'], [b''])
        records, warnings = self.extract(source, 'empty-wrong', [b'wrong'])
        self.assertEqual(records, [])
        self.assertTrue(any('passwords did not validate' in warning for warning in warnings))

        words = self.root / 'empty-passwords.txt'
        words.write_bytes(b'\n')
        hints = self.root / 'empty-hints.json'
        hints.write_text(json.dumps({'password_file': str(words)}))
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.autosolve', 'analyze', str(source),
             '--category', 'documents', '--hints', str(hints),
             '--runs-root', str(self.root / 'empty-runs')],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DOC02']['status'], 'ran')
        self.assertTrue(any(row['depth'] > 0 and Path(row['path']).read_bytes() == member.read_bytes()
                            for row in manifest['artifacts']))

    def test_public_cli_resume_and_private_password(self):
        source = self.archive()
        original = source.read_bytes()
        words = self.root / 'passwords.txt'
        words.write_bytes(b'wrong\nsecret\n')
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'password_file': str(words)}))
        run_root = self.root / 'runs'
        command = [sys.executable, '-m', 'scripts.autosolve', 'analyze', str(source),
                   '--category', 'documents', '--hints', str(hints), '--runs-root', str(run_root)]
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DOC02']['status'], 'ran')
        child = next(row for row in manifest['artifacts'] if row['depth'] > 0 and
                     Path(row['path']).read_bytes() == b'DOC{sevenzip_oracle}\n')
        self.assertEqual(child['source_locator']['archive_member'], 'nested/payload.txt')
        self.assertEqual(child['parents'][0]['operation'], '7z member 0')
        self.assertNotIn('secret', (run / 'manifest.json').read_text())
        self.assertNotIn('secret', (run / 'report.md').read_text())
        self.assertTrue(all('secret' not in path.read_text()
                            for path in (run / 'jobs').glob('*.json')))

        resume = [sys.executable, '-m', 'scripts.autosolve', 'resume', str(run), '--hints', str(hints)]
        result = subprocess.run(resume, cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        current = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(next(row for row in current['artifacts'] if row['id'] == child['id'])['current'])
        self.assertEqual(len([job for job in current['jobs'] if job['adapter_id'] == '7z']), 1)

        words.write_bytes(b'wrong\n')
        result = subprocess.run(resume, cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(changed['coverage']['DOC02']['status'], 'skipped prerequisite')
        self.assertFalse(next(row for row in changed['artifacts'] if row['id'] == child['id'])['current'])
        self.assertNotIn('DOC{sevenzip_oracle}', (run / 'report.md').read_text())
        self.assertEqual(source.read_bytes(), original)

    def test_backend_change_retries_a_completed_no_finding_job(self):
        source = self.archive()
        tools = self.root / 'tools'
        tools.mkdir()
        backend = tools / 'backend'
        wrapper = tools / '7z'
        backend.write_text(f'#!/bin/sh\n# backend v1\nexec "{self.tool}" "$@"\n')
        wrapper.write_text(f'#!/bin/sh\nexec "{backend}" "$@"\n')
        backend.chmod(0o755)
        wrapper.chmod(0o755)
        env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')}
        command = [sys.executable, '-m', 'scripts.autosolve', 'analyze', str(source),
                   '--category', 'documents', '--runs-root', str(self.root / 'backend-runs')]
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                env=env, capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        run = Path(json.loads(result.stdout)['run'])
        before = json.loads((run / 'manifest.json').read_text())
        original_jobs = [job for job in before['jobs'] if job['adapter_id'] == '7z']
        self.assertEqual(len(original_jobs), 1)
        self.assertEqual(original_jobs[0]['status'], 'complete')
        self.assertEqual(original_jobs[0]['child_ids'], [])

        backend.write_text(f'#!/bin/sh\n# backend v2\nexec "{self.tool}" "$@"\n')
        result = subprocess.run([sys.executable, '-m', 'scripts.autosolve', 'resume', str(run)],
                                cwd=Path(__file__).resolve().parents[1], env=env,
                                capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 3), result.stderr)
        after = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in after['jobs'] if job['adapter_id'] == '7z']
        self.assertEqual(len(jobs), 2)
        self.assertNotEqual(jobs[0]['tool_fingerprint'], jobs[1]['tool_fingerprint'])
        self.assertEqual(jobs[1]['status'], 'complete')
