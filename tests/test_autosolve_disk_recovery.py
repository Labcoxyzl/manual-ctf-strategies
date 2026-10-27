import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from scripts.autosolve_lib.profiles.disk_recovery import _png_size, recover_disk


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'autosolve.py'


class PngCarveValidationTests(unittest.TestCase):
    def test_indexed_and_one_bit_pngs_and_invalid_formats(self):
        def chunk(kind, content):
            return (struct.pack('>I', len(content)) + kind + content +
                    struct.pack('>I', zlib.crc32(kind + content)))

        def png(width, depth, color, pixels, palette=b''):
            header = struct.pack('>IIBBBBB', width, 2, depth, color, 0, 0, 0)
            return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) +
                    (chunk(b'PLTE', palette) if palette else b'') +
                    chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))

        palette = b'\0\0\0\xff\xff\xff'
        valid = (
            png(2, 1, 0, b'\x00\x40\x00\x80'),
            png(2, 1, 3, b'\x00\x40\x00\x80', palette),
            png(9, 1, 3, b'\x00\x80\x00' * 2, palette),
            png(2, 8, 3, b'\x00\x00\x01' * 2, palette),
        )
        for image in valid:
            with self.subTest(depth=image[24], color=image[25], width=int.from_bytes(image[16:20])):
                self.assertEqual(_png_size(image + b'AFTER'), len(image))
        self.assertIsNone(_png_size(png(2, 1, 2, b'\x00\x40\x00\x80')))
        self.assertIsNone(_png_size(png(2, 1, 3, b'\x00\x40\x00\x80')))
        damaged = bytearray(valid[1])
        damaged[-5] ^= 1
        self.assertIsNone(_png_size(damaged))


@unittest.skipUnless(all(shutil.which(tool) for tool in
                         ('mke2fs', 'debugfs', 'mmls', 'fls', 'icat', 'binwalk')),
                     'Sleuth Kit, Binwalk and ext fixture tools required')
class DiskRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fs = self.root / 'filesystem.img'
        self.image = self.root / 'disk.img'
        self.output = self.root / 'private' / 'staged'
        self.fs.write_bytes(bytes(8 * 1024 * 1024))
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', str(self.fs)],
                       check=True, capture_output=True)

    def command(self, line):
        subprocess.run(['debugfs', '-w', '-R', line, str(self.fs)],
                       check=True, capture_output=True)

    def write_deleted(self, name, content):
        payload = self.root / f'{name}.source'
        payload.write_bytes(content)
        self.command(f'write {payload} {name}')
        self.command(f'rm {name}')

    def build(self, offset=2048):
        prefix = bytearray(offset * 512)
        struct.pack_into('<B3sB3sII', prefix, 446, 0, b'\0' * 3, 0x83,
                         b'\0' * 3, offset, self.fs.stat().st_size // 512)
        prefix[510:512] = b'\x55\xaa'
        self.image.write_bytes(prefix + self.fs.read_bytes())

    def recover(self, **limits):
        return recover_disk(self.image, self.output, timeout=10,
                            max_output=100_000, max_files=8,
                            max_total_bytes=1024 * 1024, **limits)

    def test_deleted_inode_surviving_bytes_have_locator_and_uncertainty(self):
        original = b'INDEPENDENT-DELETED\x00\xff'
        self.write_deleted('lost.txt', original)
        self.build()
        source_hash = hashlib.sha256(self.image.read_bytes()).hexdigest()
        rows, warnings = self.recover()
        self.assertFalse(warnings, warnings)
        entry = next(row for row in rows if row['kind'] == 'deleted_entry')
        recovered = next(row for row in rows if row['kind'] == 'deleted_file')
        self.assertEqual(recovered['inode'], entry['inode'])
        self.assertEqual(recovered['offset_sectors'], 2048)
        self.assertEqual(recovered['file_path'], 'lost.txt')
        self.assertEqual(recovered['path'].read_bytes(), original)
        self.assertEqual(recovered['sha256'], hashlib.sha256(original).hexdigest())
        self.assertIn('deleted inode', recovered['locator'])
        self.assertIn('overwritten', recovered['uncertainty'])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), source_hash)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_held_out_partition_offset_and_partial_overwritten_content(self):
        original = b'A' * 800 + b'ORIGINAL-TAIL'
        payload = self.root / 'gone.source'
        payload.write_bytes(original)
        self.command(f'write {payload} gone.bin')
        stat = subprocess.run(['debugfs', '-R', 'stat gone.bin', str(self.fs)],
                              check=True, capture_output=True, text=True).stdout
        block = int(re.search(r'\(0\):(\d+)', stat).group(1))
        geometry = subprocess.run(['dumpe2fs', '-h', str(self.fs)], check=True,
                                  capture_output=True, text=True).stdout
        block_size = int(re.search(r'Block size:\s+(\d+)', geometry).group(1))
        self.command('rm gone.bin')
        with self.fs.open('r+b') as image:
            image.seek(block * block_size)
            image.write(b'B' * 100)
        self.build(offset=4096)
        rows, warnings = self.recover()
        self.assertFalse(warnings, warnings)
        entry = next(row for row in rows if row['kind'] == 'deleted_entry')
        self.assertEqual(entry['offset_sectors'], 4096)
        self.assertEqual(entry['file_path'], 'gone.bin')
        recovered = next(row for row in rows if row['kind'] == 'deleted_file')
        self.assertNotEqual(recovered['path'].read_bytes(), original)
        self.assertEqual(recovered['path'].read_bytes()[:100], b'B' * 100)
        self.assertIn('overwritten', recovered['uncertainty'])
        self.assertEqual(recovered['sha256'], hashlib.sha256(recovered['path'].read_bytes()).hexdigest())
        self.assertFalse(any(row.get('verification') == 'original content verified' for row in rows))

    def test_held_out_valid_png_and_zip_carves_exact_bytes_at_distinct_offsets(self):
        def chunk(kind, data):
            return (struct.pack('>I', len(data)) + kind + data +
                    struct.pack('>I', zlib.crc32(kind + data)))

        png = (b'\x89PNG\r\n\x1a\n' +
               chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) +
               chunk(b'IDAT', zlib.compress(b'\x00\x12\x34\x56')) +
               chunk(b'IEND', b''))
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as writer:
            writer.writestr('proof.txt', b'ZIP-PROOF\x00\xff')
        zip_bytes = archive.getvalue()
        self.build(offset=2048)
        original = self.image.read_bytes()
        blob = (b'JUNK' + png + b'FALSE\x89PNG\r\n\x1a\nMAGIC' +
                zip_bytes + b'PADDING' + png)
        self.image.write_bytes(original + blob)
        rows, warnings = self.recover()
        self.assertFalse(warnings, warnings)
        carved = [row for row in rows if row['kind'] == 'carved_file']
        self.assertEqual([row['format'] for row in carved].count('png'), 2)
        self.assertEqual([row['format'] for row in carved].count('zip'), 1)
        for content in (png, zip_bytes):
            row = next(item for item in carved if item['path'].read_bytes() == content)
            self.assertEqual(row['offset_bytes'], len(original) + blob.index(content))
            self.assertEqual(row['sha256'], hashlib.sha256(content).hexdigest())
            self.assertIn('verified', row['locator'])
        self.assertEqual({row['offset_bytes'] for row in carved if row['format'] == 'png'},
                         {len(original) + blob.index(png), len(original) + blob.rindex(png)})

    def test_negative_no_deleted_entry_and_random_slack_claims_nothing(self):
        live = self.root / 'live.source'
        live.write_bytes(b'LIVE-DATA-ONLY')
        self.command(f'write {live} live.txt')
        self.build()
        rows, warnings = self.recover()
        self.assertEqual(rows, [])
        self.assertEqual(warnings, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_limits_and_unsafe_output_preserve_existing_data(self):
        self.write_deleted('large.bin', b'A' * 4096)
        self.build()
        rows, warnings = recover_disk(self.image, self.output, timeout=10,
                                      max_total_bytes=32)
        self.assertTrue(any(row['kind'] == 'deleted_entry' for row in rows))
        self.assertFalse(any(row['kind'] == 'deleted_file' for row in rows))
        self.assertTrue(any('byte limit' in warning for warning in warnings))
        self.assertEqual(list(self.output.iterdir()), [])
        sentinel = self.output / 'existing'
        sentinel.write_bytes(b'KEEP')
        with self.assertRaisesRegex(ValueError, 'empty'):
            self.recover()
        self.assertEqual(sentinel.read_bytes(), b'KEEP')
        sentinel.unlink()
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.recover()
        self.output.unlink()
        rows, warnings = self.recover(max_source_bytes=10)
        self.assertEqual(rows, [])
        self.assertTrue(any('source byte limit' in warning for warning in warnings))

    def test_public_cli_recovery_resume_and_setup_probe(self):
        original = b'PUBLIC-CLI-DELETED\x00\xff'
        self.write_deleted('lost.txt', original)
        self.build()
        command = ['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json']
        started = subprocess.run([*command, 'analyze', str(self.image), '--category', 'disk',
                                  '--runs-root', str(self.root / 'runs')],
                                 capture_output=True, timeout=60)
        self.assertEqual(started.returncode, 3, started.stderr + started.stdout)
        run = Path(json.loads(started.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF02']['status'], 'ran')
        child = next(row for row in manifest['artifacts'] if
                     row['source_locator'].get('recovery_state') == 'uncertain_deleted_content')
        self.assertEqual(Path(child['path']).read_bytes(), original)
        self.assertEqual(child['source_locator']['disk_path'], 'lost.txt')
        self.assertEqual(child['source_locator']['disk_offset_sectors'], 2048)
        self.assertTrue(any(edge['job_key'] for edge in child['parents']))
        job = next(row for row in manifest['jobs'] if row['adapter_id'] == 'disk-recovery')
        self.assertIn(child['id'], job['child_ids'])
        self.assertEqual(job['status'], 'complete')
        resumed = subprocess.run([*command, 'resume', str(run)], capture_output=True, timeout=60)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in after['jobs'] if row['adapter_id'] == 'disk-recovery']), 1)
        self.assertEqual(len([row for row in after['jobs'] if row['adapter_id'] == 'disk']), 1)
        self.assertTrue(next(row for row in after['artifacts'] if row['id'] == child['id'])['current'])
        self.fs.write_bytes(bytes(8 * 1024 * 1024))
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', str(self.fs)],
                       check=True, capture_output=True)
        self.build()
        changed = subprocess.run([*command, 'resume', str(run)], capture_output=True, timeout=60)
        self.assertEqual(changed.returncode, 3, changed.stderr + changed.stdout)
        updated = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(row for row in updated['artifacts'] if row['id'] == child['id'])['current'])
        self.assertEqual(updated['coverage']['DF02']['status'], 'no finding')
        checked = subprocess.run([*command, 'doctor', '--profiles', 'disk_memory', '--self-test'],
                                 capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 3, checked.stderr + checked.stdout)
        capabilities = json.loads(checked.stdout)
        self.assertEqual(capabilities['operations']['disk_memory.recovery']['functional_probe'], 'passed')

    def test_raw_ext4_auto_recovers_deleted_inode_and_allocated_target(self):
        self.fs.write_bytes(bytes(8 * 1024 * 1024))
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', str(self.fs)],
                       check=True, capture_output=True)
        live = b'RAW-EXT4-LIVE\x00\xff'
        gone = b'RAW-EXT4-DELETED\x00\xfe'
        for name, content in (('live.txt', live), ('gone.txt', gone)):
            payload = self.root / f'{name}.source'
            payload.write_bytes(content)
            self.command(f'write {payload} {name}')
        self.command('rm gone.txt')
        # Independent TSK oracle: the image starts at filesystem sector zero.
        listing = subprocess.run(['fls', '-d', '-F', '-r', '-p', str(self.fs)],
                                 check=True, capture_output=True, text=True).stdout
        inode = re.search(r'r/r \* (\d+):\s+gone\.txt', listing)
        self.assertIsNotNone(inode, listing)
        oracle = subprocess.run(['icat', '-r', str(self.fs), inode.group(1)],
                                check=True, capture_output=True).stdout
        self.assertEqual(oracle, gone)
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'disk_target_paths': ['live.txt']}))
        before = hashlib.sha256(self.fs.read_bytes()).hexdigest()
        command = ['/opt/ctf-tools/py312/bin/python', '-B', str(SCRIPT), '--json']
        started = subprocess.run([*command, 'analyze', str(self.fs), '--category', 'auto',
                                  '--hints', str(hints), '--runs-root', str(self.root / 'runs')],
                                 capture_output=True, timeout=90)
        self.assertEqual(started.returncode, 3, started.stderr + started.stdout)
        run = Path(json.loads(started.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        source = next(row for row in manifest['artifacts'] if row['depth'] == 0)
        self.assertEqual(source['kind_evidence'], 'disk_image')
        self.assertEqual(manifest['coverage']['DF01']['status'], 'ran')
        self.assertEqual(manifest['coverage']['DF02']['status'], 'ran')
        children = [row for row in manifest['artifacts'] if row['depth'] == 1 and row['current']]
        self.assertEqual({Path(row['path']).read_bytes() for row in children}, {live, gone})
        self.assertTrue(all(row['source_locator']['disk_offset_sectors'] == 0 for row in children))
        self.assertEqual({row['source_locator']['disk_path'] for row in children},
                         {'live.txt', 'gone.txt'})
        self.assertEqual(hashlib.sha256(self.fs.read_bytes()).hexdigest(), before)
        resumed = subprocess.run([*command, 'resume', str(run), '--hints', str(hints)],
                                 capture_output=True, timeout=90)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in after['jobs'] if row['adapter_id'] == 'disk']), 1)
        self.assertEqual(len([row for row in after['jobs'] if row['adapter_id'] == 'disk-recovery']), 1)

    def test_raw_ext4_four_kib_blocks_use_sector_zero(self):
        self.fs.write_bytes(bytes(16 * 1024 * 1024))
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', str(self.fs)],
                       check=True, capture_output=True)
        original = b'FOUR-KIB-BLOCK-RECOVERY\x00\xff'
        self.write_deleted('large-block.txt', original)
        rows, warnings = recover_disk(self.fs, self.output, timeout=10,
                                      max_output=100_000, max_files=8,
                                      max_total_bytes=1024 * 1024)
        self.assertEqual(warnings, [])
        recovered = next(row for row in rows if row['kind'] == 'deleted_file')
        self.assertEqual(recovered['path'].read_bytes(), original)
        self.assertEqual(recovered['offset_sectors'], 0)
        self.assertIn('raw ext filesystem', recovered['locator'])
