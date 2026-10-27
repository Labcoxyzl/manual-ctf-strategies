import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import memory
from scripts.autosolve_lib import setup as capabilities


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'autosolve.py'


FAKE_VOL = '''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
if '--help' in args:
    print('--offline --cache-path windows.info.Info windows.dumpfiles.DumpFiles')
    sys.exit(0)
plugin = next((part for part in args if part.startswith('windows.')), '')
with open(os.environ['MEM_FAKE_LOG'], 'a') as log:
    log.write(plugin + '\\n')
mode = os.environ.get('MEM_FAKE_MODE', 'good')
if mode == 'slow':
    time.sleep(5)
if mode == 'truncated' and plugin == 'windows.info':
    print('Unable to construct kernel layer', file=sys.stderr)
    sys.exit(1)
if mode == 'bad_filescan' and plugin == 'windows.filescan':
    print('filescan failed', file=sys.stderr)
    sys.exit(1)
if plugin == 'windows.info':
    rows = [('Kernel Base', '0x1000'), ('DTB', '0x2000')]
    if mode != 'no_symbols':
        rows.append(('Symbols', 'file:///symbols/ntkrnlmp.pdb/ABC-1.json.xz'))
    rows += [('NTBuildLab', '26000.test'), ('Major/Minor', '10.0')]
    result = [{'Variable': key, 'Value': value, '__children': []} for key, value in rows]
elif plugin == 'windows.pslist':
    result = [{'PID': 4, 'PPID': 0, 'ImageFileName': 'System',
               'Offset(V)': '0x3000', '__children': []}]
elif plugin == 'windows.cmdline':
    result = [{'PID': 4, 'Process': 'System', 'Args': 'System', '__children': []}]
elif plugin == 'windows.filescan':
    result = [{'Offset': '0x4000', 'Name': r'\\Windows\\System32\\file.txt',
               '__children': []}]
elif plugin == 'windows.dumpfiles':
    out = pathlib.Path(args[args.index('-o') + 1])
    (out / 'file.dat').write_bytes(b'X' * 1000 if mode == 'oversize'
                                   else b'fixture memory content')
    result = [{'Cache': 'DataSectionObject', 'FileObject': '0x4000',
               'FileName': r'\\Windows\\System32\\file.txt',
               'Result': 'file.dat', '__children': []}]
    if mode == 'multiple':
        (out / 'file.img').write_bytes(b'other cached view')
        result.append({'Cache': 'ImageSectionObject', 'FileObject': '0x4000',
                       'FileName': r'\\Windows\\System32\\file.txt',
                       'Result': 'file.img', '__children': []})
else:
    sys.exit(2)
print(json.dumps(result))
'''


class MemoryProfileTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / 'capture.raw'
        self.image.write_bytes(b'example image')
        self.output = self.root / 'staging'
        self.vol = self.root / 'vol'
        self.vol.write_text(FAKE_VOL)
        self.vol.chmod(0o700)
        self.log = self.root / 'calls.log'
        self.environment = mock.patch.dict(os.environ, {'MEM_FAKE_LOG': str(self.log)}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.tool = mock.patch.object(memory, 'VOL', str(self.vol))
        self.tool.start()
        self.addCleanup(self.tool.stop)

    def inspect(self, *, targets=None, timeout=2, output=100000):
        return memory.inspect_memory(self.image, self.output, targets=targets,
                                     timeout=timeout, max_output=output,
                                     max_files=2, max_total_bytes=100)

    def test_info_gate_process_rows_and_exact_target_dump(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        records, warnings = self.inspect(targets=[target])
        self.assertEqual(warnings, [])
        self.assertTrue((self.output / 'cache').is_dir())
        self.assertEqual(self.log.read_text().splitlines(),
                         list(memory.PLUGINS) + ['windows.dumpfiles'])
        process = next(row for row in records if row['kind'] == 'row' and
                       row['plugin'] == 'windows.pslist')
        self.assertEqual(process['locator']['offset'], '0x3000')
        self.assertEqual(process['symbol_identity']['kernel_base'], 0x1000)
        self.assertIn('26000.test', process['symbol_identity']['build'])
        raw = next(row for row in records if row['kind'] == 'plugin_output' and
                   row['plugin'] == 'windows.cmdline')
        self.assertEqual(json.loads(raw['raw_stdout'])[0]['Args'], 'System')
        dump = next(row for row in records if row['kind'] == 'file')
        self.assertEqual(dump['path'].read_bytes(), b'fixture memory content')
        self.assertEqual(dump['locator']['space'], 'physical')
        self.assertEqual(dump['dump_row']['FileObject'], '0x4000')

    def test_multiple_cache_views_remain_separate_files(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'multiple'}):
            records, warnings = self.inspect(targets=[target])
        self.assertEqual(warnings, [])
        files = [row for row in records if row['kind'] == 'file']
        self.assertEqual(len(files), 2)
        self.assertEqual({row['dump_row']['Cache'] for row in files},
                         {'DataSectionObject', 'ImageSectionObject'})

    def test_missing_symbols_skip_all_dependent_plugins(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'no_symbols'}):
            records, warnings = self.inspect(targets=[{'address': 0x4000,
                'space': 'physical', 'name': r'\Windows\System32\file.txt'}])
        self.assertEqual(self.log.read_text().splitlines(), ['windows.info'])
        self.assertEqual(records[0]['status'], 'skipped')
        self.assertTrue(any('symbols unavailable' in warning for warning in warnings))
        self.assertTrue(any('dumps skipped' in warning for warning in warnings))

    def test_truncated_image_is_explicit_and_no_dumps(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'truncated'}):
            records, warnings = self.inspect()
        self.assertEqual(self.log.read_text().splitlines(), ['windows.info'])
        self.assertEqual(records[0]['status'], 'skipped')
        self.assertIn('Unable to construct kernel layer', records[0]['raw_stderr'])
        self.assertTrue(any('analysis incomplete' in warning for warning in warnings))

    def test_unmatched_target_never_invokes_dump(self):
        records, warnings = self.inspect(targets=[{'address': 0x4001,
            'space': 'physical', 'name': r'\Windows\System32\file.txt'}])
        self.assertEqual(self.log.read_text().splitlines(), list(memory.PLUGINS))
        self.assertFalse(any(record['kind'] == 'file' for record in records))
        self.assertTrue(any('no exact filescan target' in warning for warning in warnings))

    def test_failed_filescan_cannot_authorize_dump(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'bad_filescan'}):
            records, warnings = self.inspect(targets=[target])
        self.assertEqual(self.log.read_text().splitlines(), list(memory.PLUGINS))
        self.assertFalse(any(record['kind'] == 'file' for record in records))
        self.assertTrue(any('dumps skipped' in warning for warning in warnings))

    def test_oversized_dump_is_discarded(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'oversize'}):
            records, warnings = self.inspect(targets=[target])
        self.assertFalse(any(record['kind'] == 'file' for record in records))
        self.assertFalse((self.output / 'dump-000').exists())
        self.assertTrue(any('byte limit reached' in warning for warning in warnings))

    def test_timeout_and_invalid_target(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'slow'}):
            records, warnings = self.inspect(timeout=0.05)
        self.assertEqual(records[0]['status'], 'skipped')
        self.assertTrue(any('timed out' in warning for warning in warnings))
        with self.assertRaises(ValueError):
            self.inspect(targets=[{'address': 0x4000, 'space': 'guess', 'name': 'x'}])

    def test_cache_symlink_cannot_redirect_symbol_writes(self):
        self.output.mkdir()
        (self.output / 'cache').symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, 'cache directory'):
            self.inspect()
        self.assertFalse(self.log.exists())

    def test_setup_reports_negative_probe_without_claiming_positive_readiness(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'truncated'}):
            operation, engine = capabilities._memory_probe(True)
        self.assertEqual(engine['status'], 'partial')
        self.assertEqual(engine['functional_probe'], 'passed_negative')
        self.assertEqual(operation['reason'], 'positive_memory_fixture_not_supplied')


class MemoryCLITest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / 'capture.raw'
        self.image.write_bytes(b'raw memory fixture placeholder')
        self.vol = self.root / 'vol'
        self.vol.write_text(FAKE_VOL)
        self.vol.chmod(0o700)
        self.log = self.root / 'calls.log'
        self.symbols = self.root / 'symbols'
        self.symbols.mkdir()
        (self.symbols / 'ntkrnlmp.json.xz').write_bytes(b'first symbol version')
        self.hints = self.root / 'hints.json'
        self.environment = {**os.environ, 'AUTOSOLVE_VOL': str(self.vol),
                            'MEM_FAKE_LOG': str(self.log)}

    def call(self, *args):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 *map(str, args)], env=self.environment,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_public_cli_dump_and_symbol_change_invalidate_old_job(self):
        self.hints.write_text(json.dumps({
            'memory_image': True, 'memory_symbol_dir': str(self.symbols),
            'memory_dump_targets': [{'address': 0x4000, 'space': 'physical',
                                     'name': r'\Windows\System32\file.txt'}]}))
        source_bytes = self.image.read_bytes()
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [row for row in manifest['jobs'] if row['adapter_id'] == 'memory']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(manifest['coverage']['DF05']['status'], 'ran')
        self.assertEqual(self.image.read_bytes(), source_bytes)
        self.assertEqual(self.log.read_text().splitlines(),
                         list(memory.PLUGINS) + ['windows.dumpfiles'])
        self.assertTrue(any(row['depth'] == 1 and Path(row['path']).read_bytes() ==
                            b'fixture memory content' for row in manifest['artifacts']))
        inventory = json.loads(Path(jobs[0]['inventory_path']).read_text())
        self.assertTrue(any(row['kind'] == 'plugin_output' and row['raw_stdout']
                            for row in inventory))
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        self.assertEqual(len([row for row in json.loads((run / 'manifest.json').read_text())['jobs']
                              if row['adapter_id'] == 'memory']), 1)
        (self.symbols / 'ntkrnlmp.json.xz').write_bytes(b'second symbol version')
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        updated = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in updated['jobs'] if row['adapter_id'] == 'memory']), 2)
        self.assertNotEqual(jobs[0]['data_fingerprints']['memory_symbols'],
                            updated['memory_symbols_sha256'])
        self.assertFalse(any(row.get('current') for row in updated['intelligence']
                             if row['job_id'] == jobs[0]['id']))

    def test_missing_symbols_and_unmatched_target_skip_safely(self):
        self.hints.write_text(json.dumps({'memory_image': True}))
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'skipped prerequisite')
        self.assertFalse(self.log.exists())
        self.hints.write_text(json.dumps({'memory_image': True,
            'memory_symbol_dir': str(self.symbols),
            'memory_dump_targets': [{'address': 0x4001, 'space': 'physical',
                                     'name': r'\Windows\System32\file.txt'}]}))
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        updated = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(updated['coverage']['DF05']['status'], 'truncated')
        self.assertNotIn('windows.dumpfiles', self.log.read_text())
        self.assertFalse(any(row['depth'] > 0 for row in updated['artifacts']))

    def test_symbol_hardlink_inside_bundle_is_not_analyzed(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        (bundle / 'capture.vmem').write_bytes(b'\0' * 128)
        linked = bundle / 'linked-symbol.bin'
        os.link(self.symbols / 'ntkrnlmp.json.xz', linked)
        self.hints.write_text(json.dumps({'memory_symbol_dir': str(self.symbols)}))
        run = Path(self.call('analyze', bundle, '--category', 'auto',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(any(row['path'] == str(linked) for row in manifest['artifacts']))
        self.assertEqual(manifest['coverage']['DF05']['status'], 'ran')

    def test_removing_explicit_raw_image_hint_retires_memory_evidence(self):
        original = {'memory_image': True, 'memory_symbol_dir': str(self.symbols)}
        self.hints.write_text(json.dumps(original))
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        before = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(any(row['tag'] == 'memory row' and row['current']
                            for row in before['intelligence']))
        self.hints.write_text(json.dumps({**original, 'memory_image': False}))
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        after = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(any(row['tag'] == 'memory row' and row['current']
                             for row in after['intelligence']))

    def test_missing_volatility_is_a_skipped_prerequisite(self):
        self.environment['AUTOSOLVE_VOL'] = str(self.root / 'missing-vol')
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'skipped prerequisite')
        self.assertTrue(any('Volatility unavailable' in warning for warning in manifest['warnings']))


if __name__ == '__main__':
    unittest.main()
