import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.autosolve_lib.profiles.disk import inspect_disk


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'autosolve.py'


@unittest.skipUnless(all(shutil.which(name) for name in ('mke2fs', 'debugfs', 'mmls', 'fls', 'icat')),
                     'Sleuth Kit and ext fixture tools required')
class DiskInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = self.root / 'disk.img'
        self.output = self.root / 'staged'

    def make_image(self, offset, name='answer.txt', content=b'answer\x00\xff'):
        filesystem = self.root / 'filesystem.img'
        filesystem.write_bytes(b'\0' * (4 * 1024 * 1024))
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', str(filesystem)], check=True,
                       capture_output=True)
        payload = self.root / 'payload'
        payload.write_bytes(content)
        subprocess.run(['debugfs', '-w', '-R', f'write {payload} {name}', str(filesystem)],
                       check=True, capture_output=True)
        sectors = filesystem.stat().st_size // 512
        header = bytearray(offset * 512)
        struct.pack_into('<B3sB3sII', header, 446, 0, b'\0' * 3, 0x83,
                         b'\0' * 3, offset, sectors)
        header[510:512] = b'\x55\xaa'
        self.image.write_bytes(header + filesystem.read_bytes())
        return content

    def make_fat_image(self, offset, content=b'FAT held-out'):
        filesystem = bytearray(2880 * 512)
        filesystem[:3] = b'\xeb\x3c\x90'
        filesystem[3:11] = b'MSDOS5.0'
        struct.pack_into('<HBHBHHBHHHII', filesystem, 11, 512, 1, 1, 2, 224,
                         2880, 0xf0, 9, 18, 2, 0, 0)
        filesystem[510:512] = b'\x55\xaa'
        for sector in (1, 10):
            filesystem[sector * 512:sector * 512 + 5] = b'\xf0\xff\xff\xff\x0f'
        root = 19 * 512
        filesystem[root:root + 11] = b'ANSWER  TXT'
        filesystem[root + 11] = 0x20
        struct.pack_into('<HI', filesystem, root + 26, 2, len(content))
        filesystem[33 * 512:33 * 512 + len(content)] = content
        header = bytearray(offset * 512)
        struct.pack_into('<B3sB3sII', header, 446, 0, b'\0' * 3, 0x01,
                         b'\0' * 3, offset, 2880)
        header[510:512] = b'\x55\xaa'
        self.image.write_bytes(header + filesystem)
        return content

    def inspect(self, **kwargs):
        return inspect_disk(self.image, self.output, target_paths=['answer.txt'], timeout=10,
                            max_output=100_000, max_files=4, max_total_bytes=1024, **kwargs)

    def test_partition_listing_and_targeted_extraction_preserve_bytes(self):
        content = self.make_image(2048)
        source_hash = hashlib.sha256(self.image.read_bytes()).hexdigest()
        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        partition = next(row for row in records if row['kind'] == 'partition')
        entry = next(row for row in records if row['kind'] == 'entry' and row['file_path'] == 'answer.txt')
        extracted = next(row for row in records if row['kind'] == 'file')
        self.assertEqual(partition['offset_sectors'], 2048)
        self.assertEqual(partition['offset_bytes'], 2048 * 512)
        self.assertEqual(extracted['inode'], entry['inode'])
        self.assertEqual(extracted['file_path'], 'answer.txt')
        self.assertEqual(extracted['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(extracted['path'].read_bytes(), content)
        self.assertIn('partition', extracted['locator'])
        self.assertIn('inode', extracted['locator'])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), source_hash)

    def test_held_out_partition_offset_and_unrequested_file(self):
        self.make_image(4096, content=b'held-out-different')
        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual(next(row for row in records if row['kind'] == 'file')['path'].read_bytes(),
                         b'held-out-different')
        self.assertEqual(next(row for row in records if row['kind'] == 'partition')['offset_sectors'],
                         4096)
        other, _ = inspect_disk(self.image, self.root / 'other', target_paths=['missing.txt'],
                                timeout=10, max_output=100_000, max_files=4,
                                max_total_bytes=1024)
        self.assertFalse(any(row['kind'] == 'file' for row in other))

    def test_leading_space_filename_keeps_exact_selector_and_locator(self):
        self.make_image(2048, name='" lead.txt"', content=b'leading-name')
        records, warnings = inspect_disk(self.image, self.output, target_paths=[' lead.txt'],
                                         timeout=10, max_output=100_000, max_files=4,
                                         max_total_bytes=1024)
        self.assertEqual(warnings, [])
        extracted = next(row for row in records if row['kind'] == 'file')
        self.assertEqual(extracted['file_path'], ' lead.txt')
        self.assertEqual(extracted['path'].read_bytes(), b'leading-name')

    def test_hand_authored_fat12_image_is_extracted_at_different_offset(self):
        content = self.make_fat_image(3072)
        records, warnings = inspect_disk(self.image, self.output, target_paths=['ANSWER.TXT'],
                                         timeout=10, max_output=100_000, max_files=4,
                                         max_total_bytes=1024)
        self.assertEqual(warnings, [])
        self.assertEqual(next(row for row in records if row['kind'] == 'partition')['offset_sectors'],
                         3072)
        extracted = next(row for row in records if row['kind'] == 'file')
        self.assertEqual(extracted['path'].read_bytes(), content)
        self.assertEqual(extracted['sha256'], hashlib.sha256(content).hexdigest())

    def test_invalid_table_and_output_limits_do_not_publish_partial_data(self):
        self.image.write_bytes(b'not an image' * 100)
        records, warnings = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('partition' in warning or 'volume' in warning for warning in warnings))
        self.make_image(2048, content=b'A' * 4096)
        records, warnings = inspect_disk(self.image, self.output, target_paths=['answer.txt'],
                                         timeout=10, max_output=100_000, max_files=4,
                                         max_total_bytes=64)
        self.assertFalse(any(row['kind'] == 'file' for row in records))
        self.assertTrue(any('byte limit' in warning for warning in warnings))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_out_of_range_partition_and_unsupported_filesystem_are_reported(self):
        self.make_image(2048)
        image = bytearray(self.image.read_bytes())
        struct.pack_into('<I', image, 446 + 12, 100_000)
        self.image.write_bytes(image)
        records, warnings = self.inspect()
        self.assertFalse(any(row['kind'] == 'file' for row in records))
        self.assertTrue(any('out-of-range offset' in warning for warning in warnings))

        image = bytearray(self.image.read_bytes())
        struct.pack_into('<I', image, 446 + 12, 8192)
        image[2048 * 512:] = b'\0' * (8192 * 512)
        self.image.write_bytes(image)
        records, warnings = self.inspect()
        self.assertFalse(any(row['kind'] == 'file' for row in records))
        self.assertTrue(any('filesystem listing' in warning for warning in warnings))

    def test_no_target_and_unsafe_output_directory(self):
        self.make_image(2048)
        records, warnings = inspect_disk(self.image, self.output, target_paths=[], timeout=10,
                                         max_output=100_000, max_files=4, max_total_bytes=1024)
        self.assertEqual(warnings, [])
        self.assertFalse(any(row['kind'] == 'file' for row in records))
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.inspect()

    def test_public_cli_inventory_extraction_and_hint_change_resume(self):
        content = self.make_image(2048)
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'disk_target_paths': ['answer.txt']}))
        before = self.image.read_bytes()
        command = [str(SCRIPT), '--json', 'analyze', str(self.image), '--category', 'disk',
                   '--hints', str(hints), '--runs-root', str(self.root / 'runs')]
        result = subprocess.run(['/opt/ctf-tools/py312/bin/python', '-B', *command],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF01']['status'], 'ran')
        children = [a for a in manifest['artifacts'] if a['source_locator'].get('disk_inode')]
        self.assertEqual(len(children), 1)
        self.assertEqual(Path(children[0]['path']).read_bytes(), content)
        self.assertEqual(children[0]['source_locator']['disk_offset_sectors'], 2048)
        self.assertEqual(children[0]['source_locator']['disk_path'], 'answer.txt')
        self.assertEqual(self.image.read_bytes(), before)
        self.assertFalse(any(a['path'] == str(hints) for a in manifest['artifacts']))
        hints.write_text(json.dumps({'disk_target_paths': []}))
        result = subprocess.run(['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json',
                                 'resume', str(run), '--hints', str(hints)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(a for a in changed['artifacts'] if a['id'] == children[0]['id'])['current'])
        self.assertEqual(changed['coverage']['DF01']['status'], 'ran')

    def test_public_cli_inventory_only_and_invalid_target_hint(self):
        self.make_fat_image(3072)
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'disk_target_paths': []}))
        result = subprocess.run(['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json',
                                 'analyze', str(self.image), '--category', 'disk',
                                 '--hints', str(hints), '--runs-root', str(self.root / 'runs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertFalse(any(a['depth'] > 0 for a in manifest['artifacts']))
        self.assertTrue(any(i['tag'] == 'disk partition' and i['current']
                            for i in manifest['intelligence']))
        hints.write_text(json.dumps({'disk_target_paths': ['../outside']}))
        bad = subprocess.run(['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json',
                              'analyze', str(self.image), '--category', 'disk',
                              '--hints', str(hints), '--runs-root', str(self.root / 'other-runs')],
                             capture_output=True, timeout=30)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(json.loads(bad.stdout)['status'], 'invalid_input')

    def test_resume_supersedes_disk_child_after_tool_change(self):
        self.make_image(2048)
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'disk_target_paths': ['answer.txt']}))
        command = ['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json']
        initial = subprocess.run([*command, 'analyze', str(self.image), '--category', 'disk',
                                  '--hints', str(hints), '--runs-root', str(self.root / 'runs')],
                                 capture_output=True, timeout=30)
        self.assertEqual(initial.returncode, 3, initial.stderr + initial.stdout)
        run = Path(json.loads(initial.stdout)['run'])
        before = json.loads((run / 'manifest.json').read_text())
        child = next(a for a in before['artifacts'] if a['source_locator'].get('disk_inode'))
        fakebin = self.root / 'fake-bin'
        fakebin.mkdir()
        fake = fakebin / 'mmls'
        fake.write_text('#!/bin/sh\nexit 1\n')
        fake.chmod(0o700)
        resumed = subprocess.run([*command, 'resume', str(run), '--hints', str(hints)],
                                 capture_output=True, timeout=30,
                                 env={**os.environ, 'PATH': str(fakebin) + os.pathsep + os.environ['PATH']})
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(a for a in after['artifacts'] if a['id'] == child['id'])['current'])
        self.assertTrue(any('partition listing' in warning for warning in after['warnings']))

    def test_public_cli_rejects_non_image_as_disk_prerequisite(self):
        self.image.write_bytes(b'not a partition image')
        result = subprocess.run(['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json',
                                 'analyze', str(self.image), '--category', 'disk',
                                 '--runs-root', str(self.root / 'runs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF01']['status'], 'skipped prerequisite')


if __name__ == '__main__':
    unittest.main()
