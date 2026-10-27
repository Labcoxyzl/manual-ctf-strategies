"""REV06 static Java/Android resource and bytecode triage."""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles import java_android
from scripts.autosolve_lib.profiles.java_android import inspect_java_android
from scripts.autosolve_lib import setup as autosolve_setup


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


def _dex_with_string(value: bytes) -> bytes:
    # Standalone DEX structure produced independently of the inspector.
    assert value.isascii() and len(value) < 128
    data = bytearray(0x76 + len(value))
    data[:8] = b'dex\n035\0'
    struct.pack_into('<I', data, 0x20, len(data))
    struct.pack_into('<I', data, 0x24, 0x70)
    struct.pack_into('<I', data, 0x28, 0x12345678)
    struct.pack_into('<I', data, 0x38, 1)
    struct.pack_into('<I', data, 0x3c, 0x70)
    struct.pack_into('<I', data, 0x70, 0x74)
    data[0x74:] = bytes([len(value)]) + value + b'\0'
    return bytes(data)


class JavaAndroidTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _cli(self, *args):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 *map(str, args)], capture_output=True, text=True,
                                timeout=60, env=os.environ.copy())
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return json.loads(result.stdout)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('javap') and shutil.which('java'),
                         'Java tools unavailable')
    def test_real_jar_disassembly_and_exact_resource(self):
        source = self.root / 'Checker.java'
        source.write_text('public class Checker {\n'
                          '  public static boolean check(String s) {\n'
                          '    return "FLAG{java_resource_test}".equals(s);\n'
                          '  }\n}\n')
        obfuscated = self.root / 'a.java'
        obfuscated.write_text('public class a { static String x() { return "OBF_LEAD"; } }')
        subprocess.run(['javac', '-J-XX:-UsePerfData', '--release', '17',
                        str(source), str(obfuscated)], check=True,
                       capture_output=True, timeout=10)
        jar = self.root / 'renamed.bin'
        resource = b'FLAG{resource_exact}\x00\xff'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.write(self.root / 'Checker.class', 'Checker.class')
            archive.write(self.root / 'a.class', 'a.class')
            archive.writestr('assets/clue.dat', resource)
            archive.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')
        original = jar.read_bytes()
        launched = []
        real_run = java_android._run
        def observe(argv, *args):
            launched.append(argv)
            return real_run(argv, *args)
        with patch.object(java_android, '_run', side_effect=observe):
            records, warnings = inspect_java_android(jar, self.root / 'stage', timeout=10)
        self.assertTrue(any(Path(argv[0]).name == 'javap' for argv in launched))
        self.assertTrue(all(('-XX:-UsePerfData' if Path(argv[0]).name == 'java'
                             else '-J-XX:-UsePerfData') in argv for argv in launched))
        by_kind = {kind: [row for row in records if row['kind'] == kind]
                   for kind in ('resource', 'manifest', 'class', 'bytecode_listing')}
        self.assertEqual(len(by_kind['bytecode_listing']), 2, warnings)
        self.assertIn(b'FLAG{java_resource_test}',
                      b''.join(row['path'].read_bytes() for row in by_kind['bytecode_listing']))
        self.assertIn(b'OBF_LEAD',
                      b''.join(row['path'].read_bytes() for row in by_kind['bytecode_listing']))
        self.assertNotIn('decompiled_source', {row['kind'] for row in records})
        self.assertEqual(by_kind['bytecode_listing'][0]['source_locator']['class_name'],
                         'Checker')
        self.assertEqual(by_kind['resource'][0]['path'].read_bytes(), resource)
        self.assertEqual(by_kind['resource'][0]['sha256'], hashlib.sha256(resource).hexdigest())
        self.assertEqual(by_kind['resource'][0]['source_locator']['member'], 'assets/clue.dat')
        self.assertEqual(len(by_kind['manifest']), 1)
        self.assertEqual(jar.read_bytes(), original)

    def test_apk_multidex_resources_and_native_gap(self):
        apk = self.root / 'app.apk'
        dex_a = _dex_with_string(b'FLAG{dex_a}')
        dex_b = _dex_with_string(b'FLAG{dex_b}')
        manifest = b'<?xml version="1.0"?><manifest package="edu.test"/>'
        with zipfile.ZipFile(apk, 'w') as archive:
            archive.writestr('AndroidManifest.xml', manifest)
            archive.writestr('classes.dex', dex_a)
            archive.writestr('classes2.dex', dex_b)
            archive.writestr('res/raw/clue.bin', b'FLAG{apk_resource}')
            archive.writestr('lib/arm64-v8a/libcheck.so', b'\x7fELFplaceholder')
        records, warnings = inspect_java_android(apk, self.root / 'stage')
        self.assertEqual({row['member'] for row in records if row['kind'] == 'dex'},
                         {'classes.dex', 'classes2.dex'})
        self.assertEqual({row['data'] for row in records if row['kind'] == 'dex_string'},
                         {b'FLAG{dex_a}', b'FLAG{dex_b}'})
        for row in (row for row in records if row['kind'] == 'dex_string'):
            self.assertEqual(row['source_locator']['dex_offset'], 0x75)
            self.assertTrue(row['source_locator']['member'].endswith('.dex'))
        self.assertEqual(next(row for row in records if row['kind'] == 'manifest')
                         ['path'].read_bytes(), manifest)
        self.assertEqual(next(row for row in records if row['kind'] == 'resource' and
                              row['member'] == 'res/raw/clue.bin')['path'].read_bytes(),
                         b'FLAG{apk_resource}')
        self.assertIn('native library', ' '.join(warnings))
        self.assertIn('JADX unavailable', ' '.join(warnings))

    def test_corrupt_dex_unsupported_class_and_unsafe_member_are_explicit(self):
        bad = bytearray(_dex_with_string(b'FLAG{invalid}'))
        struct.pack_into('<I', bad, 0x20, len(bad) + 10)
        jar = self.root / 'negative.jar'
        unsupported_class = b'\xca\xfe\xba\xbe\x00\x00\xff\xff' + b'\x00\x01'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.writestr('classes.dex', bad)
            archive.writestr('Obf.class', unsupported_class)
            archive.writestr('Broken.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x01')
            archive.writestr('../escape.txt', b'NEVER_STAGE')
        records, warnings = inspect_java_android(jar, self.root / 'stage')
        self.assertFalse(any(row['kind'] == 'dex_string' for row in records))
        self.assertFalse(any(row['kind'] == 'bytecode_listing' for row in records))
        self.assertFalse(any(row.get('member') == '../escape.txt' for row in records))
        self.assertIn('invalid DEX', ' '.join(warnings))
        self.assertIn('unsupported class version', ' '.join(warnings))
        if shutil.which('javap') and shutil.which('java'):
            self.assertIn('javap backend exited', ' '.join(warnings))
        self.assertIn('unsafe', ' '.join(warnings))

    def test_source_and_expanded_limits(self):
        jar = self.root / 'small.jar'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')
            archive.writestr('assets/large.bin', b'A' * 4096)
        records, warnings = inspect_java_android(jar, self.root / 'stage',
                                                  max_total_bytes=1024)
        self.assertFalse(any(row.get('member') == 'assets/large.bin' for row in records))
        self.assertIn('expanded byte limit', ' '.join(warnings))
        records, warnings = inspect_java_android(jar, self.root / 'stage2',
                                                  max_source_bytes=32)
        self.assertEqual(records, [])
        self.assertIn('source byte limit', ' '.join(warnings))
        bad_index = bytearray(jar.read_bytes())
        marker = bad_index.rfind(b'PK\x05\x06')
        struct.pack_into('<H', bad_index, marker + 10, 2049)
        modified = self.root / 'oversized-index.jar'
        modified.write_bytes(bad_index)
        records, warnings = inspect_java_android(modified, self.root / 'stage3')
        self.assertEqual(records, [])
        self.assertIn('archive index limit', ' '.join(warnings))

    @unittest.skipUnless(shutil.which('java'), 'Java runtime unavailable')
    def test_javap_timeout_is_reported_without_a_listing(self):
        jar = self.root / 'slow.jar'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.writestr('a.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x01')
        fake = self.root / 'javap'
        fake.write_text('#!/usr/bin/env python3\n'
                        'import sys,time\n'
                        'if "-version" in sys.argv: print("21.0.1")\n'
                        'else: time.sleep(3)\n')
        fake.chmod(0o700)
        started = time.monotonic()
        records, warnings = inspect_java_android(jar, self.root / 'stage4',
                                                  javap_path=str(fake), timeout=.7)
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(any(row['kind'] == 'bytecode_listing' for row in records))
        self.assertIn('timed out', ' '.join(warnings))

    @unittest.skipUnless(shutil.which('javac') and shutil.which('javap') and shutil.which('java'),
                         'Java tools unavailable')
    def test_public_cli_renamed_jar_resource_listing_and_resume(self):
        source = self.root / 'R.java'
        source.write_text('public class R { public static String clue() { return "FLAG{jar_cli}"; } }')
        subprocess.run(['javac', '-J-XX:-UsePerfData', '--release', '17', str(source)], check=True,
                       capture_output=True, timeout=10)
        jar = self.root / 'renamed.bin'
        resource = b'FLAG{resource_cli}\x00\xff'
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.write(self.root / 'R.class', 'R.class')
            archive.writestr('assets/clue.bin', resource)
        result = self._cli('analyze', jar, '--category', 'auto',
                           '--budget', 25, '--runs-root', self.root / 'runs')
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [row for row in manifest['jobs'] if row['adapter_id'] == 'java-android']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        self.assertEqual(manifest['coverage']['REV06']['status'], 'ran')
        children = [row for row in manifest['artifacts'] if row['id'] in jobs[0]['child_ids']]
        self.assertTrue(any(row['source_locator'].get('java_kind') == 'resource' and
                            Path(row['path']).read_bytes() == resource for row in children))
        self.assertTrue(any(row['source_locator'].get('java_kind') == 'bytecode_listing' and
                            b'FLAG{jar_cli}' in Path(row['path']).read_bytes() for row in children))
        self._cli('resume', run, '--budget', 15)
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in resumed['jobs']
                              if row['adapter_id'] == 'java-android']), 1)
        prior_resource = next(row for row in children
                              if row['source_locator'].get('java_kind') == 'resource')
        with zipfile.ZipFile(jar, 'w') as archive:
            archive.write(self.root / 'R.class', 'R.class')
            archive.writestr('assets/clue.bin', b'FLAG{resource_changed}')
        self._cli('resume', run, '--budget', 15)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(row for row in changed['artifacts']
                              if row['id'] == prior_resource['id'])['current'])
        self.assertTrue(any(row['source_locator'].get('java_kind') == 'resource' and
                            Path(row['path']).read_bytes() == b'FLAG{resource_changed}' and
                            row['current'] for row in changed['artifacts']))

    def test_public_cli_apk_multidex_and_standalone_dex(self):
        apk = self.root / 'app.apk'
        with zipfile.ZipFile(apk, 'w') as archive:
            archive.writestr('AndroidManifest.xml', b'<manifest package="ctf.test"/>')
            archive.writestr('classes.dex', _dex_with_string(b'FLAG{apk_dex1}'))
            archive.writestr('classes2.dex', _dex_with_string(b'FLAG{apk_dex2}'))
            archive.writestr('lib/arm64-v8a/libnative.so', b'\x7fELFplaceholder')
        result = self._cli('analyze', apk, '--category', 'reversing',
                           '--budget', 25, '--runs-root', self.root / 'runs')
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        leads = [row for row in manifest['intelligence'] if row['tag'] == 'REV06 DEX string lead']
        self.assertEqual({row['value'] for row in leads}, {'FLAG{apk_dex1}', 'FLAG{apk_dex2}'})
        self.assertTrue(all(row['source_locator']['dex_offset'] == 0x75 for row in leads))
        self.assertIn('native library', ' '.join(manifest['warnings']))
        self.assertEqual(manifest['coverage']['REV06']['status'], 'truncated')

        dex = self.root / 'renamed.dat'
        dex.write_bytes(_dex_with_string(b'FLAG{direct_dex}'))
        result = self._cli('analyze', dex, '--category', 'reversing',
                           '--budget', 20, '--runs-root', self.root / 'runs')
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        self.assertEqual(next(row for row in manifest['artifacts'] if row['depth'] == 0)
                         ['kind_evidence'], 'dex')
        self.assertTrue(any(row['tag'] == 'REV06 DEX string lead' and
                            row['value'] == 'FLAG{direct_dex}' for row in manifest['intelligence']))

    def test_doctor_java_probe_is_honest(self):
        launched = []
        real_command = autosolve_setup._command
        def observe(argv, *args, **kwargs):
            if Path(argv[0]).name in ('java', 'javap', 'javac'):
                launched.append(argv)
            return real_command(argv, *args, **kwargs)
        with patch.object(autosolve_setup, '_command', side_effect=observe):
            report = autosolve_setup.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.java_android']
        self.assertTrue(operation['implemented'])
        self.assertIn(operation['functional_probe'], ('passed', 'failed'))
        self.assertIn(operation['status'], ('partial', 'unavailable'))
        self.assertIn('javap', report['engines'])
        if shutil.which('javac') and shutil.which('javap') and shutil.which('java'):
            self.assertEqual(operation['functional_probe'], 'passed')
            self.assertEqual(report['engines']['javap']['functional_probe'], 'passed')
            self.assertEqual({Path(argv[0]).name for argv in launched},
                             {'java', 'javap', 'javac'})
            self.assertTrue(all(('-XX:-UsePerfData' if Path(argv[0]).name == 'java'
                                 else '-J-XX:-UsePerfData') in argv for argv in launched))


if __name__ == '__main__':
    unittest.main()
