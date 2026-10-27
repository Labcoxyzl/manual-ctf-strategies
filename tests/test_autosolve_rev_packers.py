"""REV04 bounds, source preservation, and honest signature leads."""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles import rev_packers
from scripts.autosolve_lib import setup as autosolve_setup


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


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

    def _cli(self, env, *args):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 *map(str, args)], capture_output=True, text=True,
                                timeout=45, env=env)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return json.loads(result.stdout)

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

    def test_public_cli_unpacked_child_lineage_resume_and_changed_source(self):
        source = self.root / 'packed'
        source.write_bytes(b'\x7fELFUPX!PARENT')
        original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        tools = self.root / 'tools'
        tools.mkdir()
        upx = tools / 'upx'
        upx.write_text('#!/usr/bin/env python3\n'
                       'import pathlib,sys\n'
                       'args=sys.argv[1:]; blob=pathlib.Path(args[-1]).read_bytes()\n'
                       'if args[0]=="-t": sys.exit(0 if b"UPX!" in blob else 1)\n'
                       'if args[0]=="-d" and b"UPX!" in blob:\n'
                       ' pathlib.Path(args[args.index("-o")+1]).write_bytes(b"\\x7fELFNESTED_MARKER")\n'
                       ' sys.exit(0)\n'
                       'sys.exit(1)\n')
        upx.chmod(0o700)
        binwalk = tools / 'binwalk'
        binwalk.write_text('#!/usr/bin/env python3\nprint("4 0x4 embedded ELF signature")\n')
        binwalk.chmod(0o700)
        env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH']}
        result = self._cli(env, 'analyze', source, '--category', 'reversing',
                           '--budget', 25, '--runs-root', self.root / 'runs')
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV04']['status'], 'ran')
        root = next(row for row in manifest['artifacts'] if row['depth'] == 0)
        job = next(row for row in manifest['jobs'] if row['adapter_id'] == 'rev-packers'
                   and row['input_ids'] == [root['id']])
        self.assertEqual(job['status'], 'complete')
        self.assertEqual(len(job['child_ids']), 1)
        child = next(row for row in manifest['artifacts'] if row['id'] == job['child_ids'][0])
        self.assertEqual(Path(child['path']).read_bytes(), b'\x7fELFNESTED_MARKER')
        self.assertEqual(child['parents'][0]['job_key'], job['key'])
        self.assertEqual(child['source_locator']['source_sha256'], original_hash)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original_hash)
        leads = [row for row in manifest['intelligence'] if row['tag'] == 'REV04 signature lead']
        self.assertTrue(any(row['artifact_id'] == child['id'] and row['current'] for row in leads))
        self.assertTrue(all(not row['source_locator']['validated'] for row in leads))
        self.assertTrue(all('path' not in row for row in leads))

        before = len([row for row in manifest['jobs'] if row['adapter_id'] == 'rev-packers'])
        self._cli(env, 'resume', run, '--budget', 15)
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in resumed['jobs'] if row['adapter_id'] == 'rev-packers']),
                         before)
        source.write_bytes(b'\x7fELFCHANGED')
        self._cli(env, 'resume', run, '--budget', 15)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(row for row in changed['artifacts'] if row['id'] == child['id'])['current'])
        self.assertTrue(all(not row['current'] for row in changed['intelligence']
                            if row['job_id'] == job['id']))

    @unittest.skipUnless(shutil.which('upx') is None, 'UPX is installed')
    def test_public_cli_auto_binary_missing_upx_is_skipped_prerequisite(self):
        source = self.root / 'blob'
        source.write_bytes(b'\0HEADER' + gzip.compress(b'EMBEDDED', mtime=0))
        tools = self.root / 'tools'
        tools.mkdir()
        binwalk = tools / 'binwalk'
        binwalk.write_text('#!/usr/bin/env python3\nprint("7 0x7 gzip signature")\n')
        binwalk.chmod(0o700)
        env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH']}
        result = self._cli(env, 'analyze', source, '--budget', 15,
                           '--runs-root', self.root / 'runs')
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV04']['status'], 'skipped prerequisite')
        jobs = [row for row in manifest['jobs'] if row['adapter_id'] == 'rev-packers']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        self.assertEqual(jobs[0]['child_ids'], [])
        self.assertTrue(any(row['tag'] == 'REV04 signature lead' and row['current'] and
                            row['source_locator']['file_offset'] == 7
                            for row in manifest['intelligence']))

    def test_doctor_reports_packers_without_claiming_upx_roundtrip(self):
        report = autosolve_setup.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.packers']
        self.assertTrue(operation['implemented'])
        self.assertEqual(operation['status'], 'partial' if shutil.which('upx') or
                         shutil.which('binwalk') else 'unavailable')
        self.assertEqual(report['engines']['upx']['found'], bool(shutil.which('upx')))
        if shutil.which('binwalk'):
            self.assertTrue(report['engines']['binwalk']['found'])
            self.assertEqual(operation['functional_probe'], 'passed')
        else:
            self.assertEqual(operation['functional_probe'], 'not_run')
        self.assertNotEqual(report['engines']['upx']['functional_probe'], 'passed')


if __name__ == '__main__':
    unittest.main()
