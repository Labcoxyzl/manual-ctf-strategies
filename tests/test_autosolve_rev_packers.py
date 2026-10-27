"""REV04 bounds, source preservation, and honest signature leads."""

import gzip
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles import rev_packers


class PackerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _tool(self, name, body):
        tool = self.root / name
        tool.write_text('#!/usr/bin/env python3\n' + body)
        tool.chmod(0o700)
        return str(tool)

    def test_private_upx_copy_exact_hash_and_binwalk_lead(self):
        source = self.root / 'packed'
        source.write_bytes(b'\x7fELFUPX!PARENT')
        original = source.read_bytes()
        upx = self._tool('fake-upx',
                         'import pathlib,sys\n'
                         'args=sys.argv[1:]\n'
                         'src=pathlib.Path(args[-1])\n'
                         'assert src.name == "source"\n'
                         'assert src.read_bytes() == b"\\x7fELFUPX!PARENT"\n'
                         'if args[0] == "-t": print("UPX test passed")\n'
                         'elif args[0] == "-d": pathlib.Path(args[args.index("-o")+1]).write_bytes(b"\\x7fELFNESTED")\n'
                         'else: sys.exit(1)\n')
        binwalk = self._tool('fake-binwalk',
                             'print("DECIMAL       HEXADECIMAL     DESCRIPTION")\n'
                             'print("4             0x4             embedded ELF executable signature")\n')
        records, warnings = rev_packers.inspect_packers(
            source, self.root / 'stage', upx_path=upx, binwalk_path=binwalk, timeout=5)
        self.assertEqual(warnings, [])
        unpacked = [row for row in records if row['kind'] == 'upx-unpacked']
        leads = [row for row in records if row['kind'] == 'signature-lead']
        self.assertEqual(len(unpacked), 1)
        self.assertEqual(unpacked[0]['path'].read_bytes(), b'\x7fELFNESTED')
        self.assertEqual(unpacked[0]['sha256'], hashlib.sha256(b'\x7fELFNESTED').hexdigest())
        self.assertEqual(unpacked[0]['source_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(len(leads), 2)
        self.assertEqual({row['source_sha256'] for row in leads},
                         {unpacked[0]['sha256'], unpacked[0]['source_sha256']})
        self.assertTrue(all(row['source_locator']['file_offset'] == 4 and
                            not row['validated'] and 'path' not in row for row in leads))

    def test_failed_test_never_unpacks_and_magic_lead_is_unvalidated(self):
        source = self.root / 'modified'
        source.write_bytes(b'\x7fELFbroken')
        marker = self.root / 'unpack-called'
        upx = self._tool('reject-upx',
                         'import pathlib,sys\n'
                         'if sys.argv[1] == "-d": pathlib.Path(' + repr(str(marker)) + ').touch()\n'
                         'sys.exit(1)\n')
        binwalk = self._tool('lead-binwalk',
                             'print("0  0x0  ELF executable")\n')
        records, warnings = rev_packers.inspect_packers(
            source, self.root / 'stage', upx_path=upx, binwalk_path=binwalk, timeout=5)
        self.assertFalse(marker.exists())
        self.assertEqual([row['kind'] for row in records], ['signature-lead'])
        self.assertFalse(records[0]['validated'])
        self.assertIn('UPX test', ' '.join(warnings))

    def test_tool_cannot_change_private_copy_before_unpack(self):
        source = self.root / 'packed'
        source.write_bytes(b'\x7fELFUPX!')
        marker = self.root / 'unpack-called'
        upx = self._tool('mutating-upx',
                         'import pathlib,sys\n'
                         'if sys.argv[1] == "-t": pathlib.Path(sys.argv[-1]).write_bytes(b"changed")\n'
                         'else: pathlib.Path(' + repr(str(marker)) + ').touch()\n')
        with patch.object(rev_packers.shutil, 'which', return_value=None):
            records, warnings = rev_packers.inspect_packers(
                source, self.root / 'stage', upx_path=upx, timeout=5)
        self.assertEqual(records, [])
        self.assertFalse(marker.exists())
        self.assertEqual(source.read_bytes(), b'\x7fELFUPX!')
        self.assertIn('changed the private source copy', ' '.join(warnings))

    def test_missing_upx_and_limits_are_explicit(self):
        source = self.root / 'plain'
        source.write_bytes(b'\x7fELFordinary')
        with patch.object(rev_packers.shutil, 'which', return_value=None):
            records, warnings = rev_packers.inspect_packers(source, self.root / 'stage')
        self.assertEqual(records, [])
        self.assertIn('UPX unavailable', ' '.join(warnings))
        self.assertIn('binwalk unavailable', ' '.join(warnings))
        with self.assertRaises(ValueError):
            rev_packers.inspect_packers(source, self.root / 'bad', timeout=0)
        oversized = self.root / 'oversized'
        oversized.write_bytes(b'\x7fELF' + b'x' * 20)
        self.assertIn('source byte limit', ' '.join(rev_packers.inspect_packers(
            oversized, self.root / 'too-large', max_source_bytes=8)[1]))
        link = self.root / 'link'
        link.symlink_to(source)
        self.assertIn('symlinked', ' '.join(rev_packers.inspect_packers(
            link, self.root / 'link-output')[1]))

    def test_timeout_stops_unpacking(self):
        source = self.root / 'slow'
        source.write_bytes(b'\x7fELFUPX!')
        upx = self._tool('slow-upx', 'import time\ntime.sleep(2)\n')
        records, warnings = rev_packers.inspect_packers(
            source, self.root / 'stage', timeout=.05, upx_path=upx)
        self.assertFalse(any(row['kind'] == 'upx-unpacked' for row in records))
        self.assertIn('timed out', ' '.join(warnings))

    def test_expanded_byte_cap_rejects_upx_output(self):
        source = self.root / 'packed'
        source.write_bytes(b'\x7fELFUPX!')
        upx = self._tool('huge-upx',
                         'import pathlib,sys\n'
                         'if sys.argv[1] == "-d":\n'
                         '    pathlib.Path(sys.argv[sys.argv.index("-o")+1]).write_bytes(b"\\x7fELF" + b"x"*128)\n')
        with patch.object(rev_packers.shutil, 'which', return_value=None):
            records, warnings = rev_packers.inspect_packers(
                source, self.root / 'stage', upx_path=upx,
                max_derived_bytes=64, timeout=5)
        self.assertEqual(records, [])
        self.assertIn('UPX unpack', ' '.join(warnings))
        self.assertFalse((self.root / 'stage' / 'upx-unpacked').exists())

    @unittest.skipUnless(shutil.which('binwalk'), 'real binwalk is unavailable')
    def test_real_binwalk_embedded_signature_is_only_a_lead(self):
        source = self.root / 'nested.bin'
        source.write_bytes(b'HEADER' + gzip.compress(b'HELLO_REVERSE_TEST', mtime=0))
        actual_binwalk = shutil.which('binwalk')
        with patch.object(rev_packers.shutil, 'which',
                          side_effect=lambda name: None if name == 'upx' else actual_binwalk):
            records, warnings = rev_packers.inspect_packers(source, self.root / 'stage',
                                                             timeout=5)
        self.assertTrue(any(row['kind'] == 'signature-lead' and
                            row['source_locator']['file_offset'] == 6 and
                            not row['validated'] and 'path' not in row
                            for row in records), (records, warnings))

    @unittest.skipUnless(shutil.which('upx') and shutil.which('gcc'),
                         'real UPX and GCC are both required')
    def test_real_upx_roundtrip_with_nested_marker(self):
        code = self.root / 'payload.c'
        code.write_text('const unsigned char nested[] = "NESTED_PAYLOAD_TEST";'
                        'int main(void){return nested[0];}')
        original = self.root / 'original'
        packed = self.root / 'packed'
        subprocess.run(['gcc', '-no-pie', '-o', str(original), str(code)],
                       check=True, capture_output=True)
        subprocess.run(['upx', '-q', '-o', str(packed), str(original)],
                       check=True, capture_output=True)
        before = hashlib.sha256(packed.read_bytes()).hexdigest()
        records, warnings = rev_packers.inspect_packers(packed, self.root / 'stage',
                                                         timeout=10)
        unpacked = [row for row in records if row['kind'] == 'upx-unpacked']
        self.assertEqual(len(unpacked), 1, warnings)
        self.assertIn(b'NESTED_PAYLOAD_TEST', unpacked[0]['path'].read_bytes())
        self.assertEqual(hashlib.sha256(packed.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
