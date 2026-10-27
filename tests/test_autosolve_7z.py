"""DOC02 encrypted 7z extraction through the profile and public CLI."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.autosolve_lib.profiles.sevenzip import extract_7z


@unittest.skipUnless(shutil.which('7z') or shutil.which('7zz'), '7-Zip unavailable')
class SevenZipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tool = shutil.which('7z') or shutil.which('7zz')

    def archive(self, *, hidden=False, name='nested/payload.txt', data=b'DOC{sevenzip_oracle}\n'):
        member = self.root / name
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_bytes(data)
        source = self.root / ('hidden.7z' if hidden else 'plain.7z')
        args = [self.tool, 'a', '-t7z', '-mx=1', '-psecret', '-mhe=on' if hidden else '-mhe=off',
                str(source), name]
        subprocess.run(args, cwd=self.root, check=True, capture_output=True)
        return source

    def test_encrypted_header_exact_bytes_and_wrong_password(self):
        source = self.archive(hidden=True)
        records, warnings = extract_7z(source, self.root / 'out', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[b'wrong', b'secret'], executable=self.tool)
        self.assertEqual(warnings, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['member'], 'nested/payload.txt')
        self.assertEqual(records[0]['path'].read_bytes(), b'DOC{sevenzip_oracle}\n')
        self.assertTrue(records[0]['encrypted'])

        records, warnings = extract_7z(source, self.root / 'wrong', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[b'plausible'], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(any('passwords did not validate' in row for row in warnings))
        records, warnings = extract_7z(source, self.root / 'missing', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(any('password required' in row for row in warnings))

        visible = self.archive(hidden=False, name='alternate.txt', data=b'visible header secret')
        records, warnings = extract_7z(visible, self.root / 'visible', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[b'wrong', b'secret'], executable=self.tool)
        self.assertEqual(warnings, [])
        self.assertEqual([record['path'].read_bytes() for record in records],
                         [b'visible header secret'])

    def test_corrupt_traversal_link_and_expansion_limits(self):
        source = self.archive(hidden=False)
        truncated = self.root / 'truncated.7z'
        truncated.write_bytes(source.read_bytes()[:-12])
        records, warnings = extract_7z(truncated, self.root / 'corrupt', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[b'secret'], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(warnings)

        encrypted = self.archive(hidden=True, name='header-secret.txt')
        broken = bytearray(encrypted.read_bytes())
        broken[12] ^= 1
        damaged = self.root / 'damaged-header.7z'
        damaged.write_bytes(broken)
        records, warnings = extract_7z(damaged, self.root / 'damaged', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[b'secret'], executable=self.tool)
        self.assertEqual(records, [])
        self.assertEqual(warnings, ['invalid 7z archive header'])

        link = self.root / 'link'
        link.symlink_to('nested/payload.txt')
        linked = self.root / 'linked.7z'
        subprocess.run([self.tool, 'a', '-t7z', '-mx=1', '-snl', str(linked), 'link'],
                       cwd=self.root, check=True, capture_output=True)
        records, warnings = extract_7z(linked, self.root / 'link-out', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(any('unsafe' in row for row in warnings))

        absolute = self.root / 'absolute.7z'
        subprocess.run([self.tool, 'a', '-t7z', '-spf', str(absolute),
                        str(self.root / 'nested' / 'payload.txt')],
                       cwd=self.root, check=True, capture_output=True)
        records, warnings = extract_7z(absolute, self.root / 'absolute-out', max_members=10,
                                        max_total_bytes=1024, max_member_bytes=1024,
                                        passwords=[], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(any('unsafe' in row for row in warnings))

        large = self.archive(data=b'A' * 4096)
        records, warnings = extract_7z(large, self.root / 'large', max_members=10,
                                        max_total_bytes=128, max_member_bytes=128,
                                        passwords=[b'secret'], executable=self.tool)
        self.assertEqual(records, [])
        self.assertTrue(any('expanded byte limit' in row for row in warnings))

    def test_public_cli_resume_retires_password_derived_artifact(self):
        source = self.archive(hidden=True)
        original = source.read_bytes()
        password_file = self.root / 'passwords.txt'
        password_file.write_bytes(b'wrong\nsecret\n')
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'password_file': str(password_file)}))
        args = [sys.executable, '-m', 'scripts.autosolve', 'analyze', str(source), '--category', 'documents',
                '--hints', str(hints), '--runs-root', str(self.root / 'runs')]
        proc = subprocess.run(args, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 3), proc.stderr)
        run = Path(json.loads(proc.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DOC02']['status'], 'ran')
        children = [row for row in manifest['artifacts'] if row['depth'] > 0]
        self.assertTrue(any(Path(row['path']).read_bytes() == b'DOC{sevenzip_oracle}\n' for row in children))
        child = next(row for row in children if Path(row['path']).read_bytes() == b'DOC{sevenzip_oracle}\n')
        self.assertEqual(child['parents'][0]['operation'], '7z member 0')
        self.assertEqual(child['parents'][0]['source_locator']['archive_member'], 'nested/payload.txt')
        self.assertEqual(child['parents'][0]['source_locator']['member_index'], 0)
        self.assertNotIn('secret', (run / 'report.md').read_text())
        self.assertNotIn('secret', (run / 'manifest.json').read_text())

        proc = subprocess.run([sys.executable, '-m', 'scripts.autosolve', 'resume', str(run),
                               '--hints', str(hints)], cwd=Path(__file__).resolve().parents[1],
                              capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 3), proc.stderr)
        repeated = json.loads((run / 'manifest.json').read_text())
        current = next(row for row in repeated['artifacts'] if row['id'] == child['id'])
        self.assertTrue(current['current'])
        self.assertTrue(any(edge['operation'] == '7z member 0' and
                            edge['source_locator']['archive_member'] == 'nested/payload.txt' and
                            edge['source_locator']['member_index'] == 0
                            for edge in current['parents']))

        password_file.write_bytes(b'plausible\n')
        proc = subprocess.run([sys.executable, '-m', 'scripts.autosolve', 'resume', str(run),
                               '--hints', str(hints)], cwd=Path(__file__).resolve().parents[1],
                              capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 3), proc.stderr)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(changed['coverage']['DOC02']['status'], 'skipped prerequisite')
        self.assertTrue(all(not row['current'] for row in changed['artifacts']
                            if row['source_locator'].get('encrypted')))
        self.assertNotIn('DOC{sevenzip_oracle}', (run / 'report.md').read_text())
        self.assertEqual(source.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
