import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import memory
from scripts.autosolve_lib import core
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
    result = [] if mode in ('pslist_empty', 'metadata_only', 'process_empty') else [
        {'PID': 4, 'PPID': 0, 'ImageFileName': 'System',
         'Offset(V)': '0x3000', '__children': []}]
    if mode == 'many_rows':
        result = [{'PID': index, 'PPID': 0, 'ImageFileName': f'process-{index}',
                   'Offset(V)': 0x3000 + index, '__children': []}
                  for index in range(120)]
elif plugin == 'windows.psscan':
    result = [] if mode in ('metadata_only', 'process_empty') else [
        {'PID': 1640, 'PPID': 1484, 'ImageFileName': 'reader_sl.exe',
         'Offset(V)': 34061728, '__children': []}]
elif plugin == 'windows.cmdline':
    result = [] if mode in ('pslist_empty', 'metadata_only', 'cmdline_empty', 'process_empty') else [
        {'PID': 4, 'Process': 'System', 'Args': 'System', '__children': []}]
    if mode == 'many_rows':
        result = [{'PID': index, 'Process': f'process-{index}',
                   'Args': f'command-{index}', '__children': []}
                  for index in range(120)]
elif plugin == 'windows.filescan':
    result = [] if mode in ('pslist_empty', 'metadata_only', 'filescan_empty') else [
        {'Offset': '0x4000', 'Name': r'\\Windows\\System32\\file.txt',
         '__children': []}]
    if mode == 'many_rows':
        result = [{'Offset': 0x5000 + index, 'Name': f'file-{index}',
                   '__children': []} for index in range(120)]
elif plugin == 'windows.dumpfiles':
    out = pathlib.Path(args[args.index('-o') + 1])
    (out / 'file.dat').write_bytes(b'X' * 1000 if mode == 'oversize'
                                   else b'fixture memory content')
    file_object = (0x4000 if mode == 'integer_file_object' else
                   '16384' if mode == 'decimal_file_object' else
                   0x4001 if mode == 'mismatched_file_object' else
                   '0x4000garbage' if mode == 'unsafe_file_object' else '0x4000')
    file_name = ('file.txt' if mode == 'basename_dump_name' else
                 r'\\Other\\file.txt' if mode == 'mismatched_dump_path' else
                 r'\\Windows\\System32\\wrong.txt' if mode == 'mismatched_dump_name'
                 else r'\\Windows\\System32\\file.txt')
    result = [{'Cache': 'DataSectionObject', 'FileObject': file_object,
               'FileName': file_name,
               'Result': '../file.dat' if mode == 'unsafe_result' else 'file.dat',
               '__children': []}]
    if mode == 'duplicate_result':
        result.append({**result[0], 'FileName': r'\\Windows\\System32\\wrong.txt'})
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

    def test_dumpfile_address_forms_and_wrong_object(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        for mode in ('integer_file_object', 'decimal_file_object',
                     'mismatched_file_object', 'unsafe_file_object', 'unsafe_result'):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                if self.output.exists():
                    import shutil
                    shutil.rmtree(self.output)
                with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': mode}):
                    records, warnings = self.inspect(targets=[target])
                files = [row for row in records if row['kind'] == 'file']
                if mode in ('mismatched_file_object', 'unsafe_file_object', 'unsafe_result'):
                    self.assertEqual(files, [])
                    self.assertFalse((self.output / 'dump-000').exists())
                    self.assertTrue(any('unverified dump output' in x for x in warnings))
                else:
                    self.assertEqual(len(files), 1)
                    self.assertEqual(files[0]['dump_row']['FileObject'],
                                     0x4000 if mode == 'integer_file_object' else '16384')

    def test_dumpfile_name_must_match_target_or_its_basename(self):
        target = {'address': 0x4000, 'space': 'physical',
                  'name': r'\Windows\System32\file.txt'}
        for mode in ('basename_dump_name', 'mismatched_dump_name',
                     'mismatched_dump_path', 'duplicate_result'):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                if self.output.exists():
                    import shutil
                    shutil.rmtree(self.output)
                with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': mode}):
                    records, warnings = self.inspect(targets=[target])
                files = [row for row in records if row['kind'] == 'file']
                if mode == 'basename_dump_name':
                    self.assertEqual(len(files), 1)
                else:
                    self.assertEqual(files, [])
                    self.assertFalse((self.output / 'dump-000').exists())
                    self.assertTrue(any('unverified dump output' in x for x in warnings))

    def test_psscan_recovers_process_when_pslist_is_empty(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'pslist_empty'}):
            records, warnings = self.inspect()
        self.assertTrue(any('command-line triage returned no rows'
                            in warning for warning in warnings))
        self.assertEqual(self.log.read_text().splitlines(),
                         ['windows.info', 'windows.pslist', 'windows.psscan',
                          'windows.cmdline', 'windows.filescan'])
        process = next(row for row in records if row['kind'] == 'row' and
                       row['plugin'] == 'windows.psscan')
        self.assertEqual(process['row']['ImageFileName'], 'reader_sl.exe')
        self.assertEqual((process['locator']['pid'], process['locator']['offset']),
                         (1640, 34061728))
        self.assertEqual(next(row['row_count'] for row in records if
                             row['kind'] == 'plugin_output' and
                             row['plugin'] == 'windows.pslist'), 0)

    def test_metadata_only_is_incomplete_triage(self):
        with mock.patch.dict(os.environ, {'MEM_FAKE_MODE': 'metadata_only'}):
            records, warnings = self.inspect()
        for group in ('process', 'command-line', 'file'):
            self.assertTrue(any(f'{group} triage returned no rows' in warning
                                for warning in warnings))
        self.assertFalse(any(row['kind'] == 'row' and
                             row['plugin'] != 'windows.info' for row in records))

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

    def test_symbol_path_roundtrip_reactivates_cached_memory_rows(self):
        original = {'memory_image': True, 'memory_symbol_dir': str(self.symbols)}
        relocated = self.root / 'relocated-symbols'
        relocated.mkdir()
        (relocated / 'ntkrnlmp.json.xz').write_bytes(
            (self.symbols / 'ntkrnlmp.json.xz').read_bytes())
        self.hints.write_text(json.dumps(original))
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        first = json.loads((run / 'manifest.json').read_text())
        first_job = next(row['id'] for row in first['jobs'] if row['adapter_id'] == 'memory')
        first_inventory = next(row['inventory_path'] for row in first['jobs']
                               if row['id'] == first_job)
        first_rows = [row for row in first['intelligence']
                      if row['tag'] == 'memory row' and row['current']]
        self.assertTrue(first_rows)

        self.hints.write_text(json.dumps({**original, 'memory_symbol_dir': str(relocated)}))
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        middle = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([row for row in middle['jobs']
                              if row['adapter_id'] == 'memory']), 2)
        self.assertFalse(any(row['current'] for row in middle['intelligence']
                             if row['job_id'] == first_job))
        self.assertNotIn(first_inventory, (run / 'report.md').read_text())
        relocated_inventory = next(row['inventory_path'] for row in middle['jobs']
                                   if row['adapter_id'] == 'memory' and row['id'] != first_job)

        self.hints.write_text(json.dumps(original))
        self.call('resume', run, '--hints', self.hints, '--budget', '10')
        last = json.loads((run / 'manifest.json').read_text())
        current_rows = [row for row in last['intelligence']
                        if row['tag'] == 'memory row' and row['current']]
        self.assertEqual(len([row for row in last['jobs']
                              if row['adapter_id'] == 'memory']), 2)
        self.assertEqual({row['job_id'] for row in current_rows}, {first_job})
        self.assertEqual(len(current_rows), len(first_rows))
        self.assertEqual((run / 'report.md').read_text().count('"memory row" ('),
                         len(first_rows))
        self.assertIn(first_inventory, (run / 'report.md').read_text())
        self.assertNotIn(relocated_inventory, (run / 'report.md').read_text())
        self.assertEqual(last['coverage']['DF05']['status'], 'ran')

    def test_zero_row_memory_job_still_links_raw_inventory(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'no_symbols'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        job = next(row for row in manifest['jobs'] if row['adapter_id'] == 'memory')
        self.assertEqual(job['status'], 'complete')
        self.assertEqual(job['row_count'], 0)
        self.assertTrue(Path(job['inventory_path']).is_file())
        report = (run / 'report.md').read_text()
        self.assertIn(job['inventory_path'], report)
        self.assertIn(job['inventory_sha256'], report)

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

    def test_metadata_only_does_not_mark_df05_ran(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'metadata_only'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        for group in ('process', 'command-line', 'file'):
            self.assertTrue(any(f'{group} triage returned no rows' in warning
                                for warning in manifest['warnings']))

    def test_psscan_process_only_keeps_evidence_with_partial_coverage(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'pslist_empty'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        self.assertIn('network triage not attempted', manifest['coverage']['DF05']['note'])
        self.assertTrue(any('command-line triage returned no rows' in warning
                            for warning in manifest['warnings']))
        self.assertTrue(any('file triage returned no rows' in warning
                            for warning in manifest['warnings']))
        self.assertTrue(any(row['current'] and row['group'] == 'windows.psscan' and
                            'reader_sl.exe' in row['value'] for row in manifest['intelligence']))

    def test_empty_cmdline_keeps_process_and_file_evidence_but_not_full_coverage(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'cmdline_empty'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        self.assertTrue(any('command-line triage returned no rows' in warning
                            for warning in manifest['warnings']))
        groups = {row['group'] for row in manifest['intelligence'] if
                  row['tag'] == 'memory row' and row['current']}
        self.assertIn('windows.pslist', groups)
        self.assertIn('windows.filescan', groups)
        self.assertNotIn('windows.cmdline', groups)

    def test_empty_filescan_keeps_process_and_command_evidence_but_not_full_coverage(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'filescan_empty'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        self.assertTrue(any('file triage returned no rows' in warning
                            for warning in manifest['warnings']))
        groups = {row['group'] for row in manifest['intelligence'] if
                  row['tag'] == 'memory row' and row['current']}
        self.assertIn('windows.pslist', groups)
        self.assertIn('windows.cmdline', groups)
        self.assertNotIn('windows.filescan', groups)

    def test_empty_process_and_cmdline_report_both_missing_groups(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'process_empty'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        self.assertTrue(any('process triage returned no rows' in warning
                            for warning in manifest['warnings']))
        self.assertTrue(any('command-line triage returned no rows' in warning
                            for warning in manifest['warnings']))
        self.assertTrue(any(row['current'] and row['group'] == 'windows.filescan'
                            for row in manifest['intelligence']))

    def test_mismatched_dump_name_never_publishes_child(self):
        self.hints.write_text(json.dumps({
            'memory_image': True, 'memory_symbol_dir': str(self.symbols),
            'memory_dump_targets': [{'address': 0x4000, 'space': 'physical',
                                     'name': r'\Windows\System32\file.txt'}]}))
        self.environment['MEM_FAKE_MODE'] = 'mismatched_dump_name'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['DF05']['status'], 'truncated')
        self.assertFalse(any(row['depth'] == 1 for row in manifest['artifacts']))
        self.assertTrue(any('unverified dump output' in warning
                            for warning in manifest['warnings']))

    def test_memory_report_cap_retains_each_plugin_type(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        self.environment['MEM_FAKE_MODE'] = 'many_rows'
        run = Path(self.call('analyze', self.image, '--category', 'memory',
                             '--hints', self.hints, '--budget', '10',
                             '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        rows = [row for row in manifest['intelligence'] if row['tag'] == 'memory row'
                and row['current']]
        self.assertLessEqual(len(rows), 100)
        self.assertEqual({row['group'] for row in rows},
                         {'windows.info', 'windows.pslist', 'windows.cmdline',
                          'windows.filescan'})
        inventory = json.loads(Path(next(row['inventory_path'] for row in manifest['jobs']
                                         if row['adapter_id'] == 'memory')).read_text())
        self.assertEqual(len([row for row in inventory if row['kind'] == 'row']), 365)
        self.assertTrue(any(row['group'] == 'windows.pslist' and
                            row['source_locator']['memory_locator']['row'] == 119
                            for row in rows))
        self.assertTrue(any(row['group'] == 'windows.cmdline' and
                            row['source_locator']['memory_locator']['row'] == 119
                            for row in rows))
        self.assertIn('process-119', (run / 'report.md').read_text())
        self.assertIn('command-119', (run / 'report.md').read_text())
        sampled_line = next(line for line in (run / 'report.md').read_text().splitlines()
                            if '"memory row" ("windows.pslist")' in line and
                            'process-119' in line)
        self.assertIn('"memory_locator"', sampled_line)
        self.assertIn('"row": 119', sampled_line)

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

    def test_postworker_volatility_identity_distinguishes_missing_expired_and_changed(self):
        self.hints.write_text(json.dumps({'memory_image': True,
                                          'memory_symbol_dir': str(self.symbols)}))
        real_hash = core._hash
        for identity, expected_job, expected_coverage in (
                ('missing', 'complete', 'skipped prerequisite'),
                ('matching', 'complete', 'skipped prerequisite'),
                ('expired', 'truncated', 'truncated'),
                ('changed', 'failed', 'failed')):
            with self.subTest(identity=identity):
                self.vol.write_text(FAKE_VOL)
                tool = self.root / 'missing-vol' if identity == 'missing' else self.vol
                after_worker = False

                def run_memory(*args):
                    nonlocal after_worker
                    after_worker = True
                    if identity == 'changed':
                        self.vol.write_text(FAKE_VOL + '\n# changed')
                    return ([{'kind': 'plugin_output', 'plugin': 'windows.info',
                              'status': 'skipped', 'reason': 'Volatility unavailable'}],
                            ['Volatility unavailable'])

                def source_hash(path, deadline):
                    if identity == 'expired' and after_worker and Path(path) == tool:
                        return None
                    return real_hash(path, deadline)

                with mock.patch.object(memory, 'VOL', str(tool)), \
                     mock.patch.object(core, '_run_memory', side_effect=run_memory), \
                     mock.patch.object(core, '_hash', side_effect=source_hash):
                    run, _ = core.analyze(self.image, category='memory', hints_path=self.hints,
                                          budget=5, runs_root=self.root / f'runs-{identity}')
                manifest = json.loads((run / 'manifest.json').read_text())
                job = next(item for item in manifest['jobs'] if item['adapter_id'] == 'memory')
                self.assertTrue(after_worker)
                self.assertEqual(job['status'], expected_job)
                self.assertEqual(manifest['coverage']['DF05']['status'], expected_coverage)


if __name__ == '__main__':
    unittest.main()
