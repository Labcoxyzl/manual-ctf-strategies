"""Public CLI regressions for source identity changes during resume."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'autosolve.py'


class MissingSourceResumeTests(unittest.TestCase):
    def cli(self, *args, code):
        completed = subprocess.run(
            [sys.executable, '-B', str(SCRIPT), '--json', *map(str, args)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, code, completed.stderr + completed.stdout)
        return json.loads(completed.stdout)

    def start(self, root, source_parent=None):
        source = (source_parent or root) / 'challenge.txt'
        source.write_bytes(b'SEVMTE8gV09STEQ=')
        hints = root / 'hints.json'
        hints.write_text(json.dumps({'flag_patterns': ['HELLO']}))
        result = self.cli('analyze', source, '--category', 'encoding', '--hints', hints,
                          '--runs-root', root / 'runs', code=3)
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(any(f['current'] and 'HELLO' in f['evidence']
                            for f in manifest['findings']))
        return source, hints, run

    def test_missing_direct_input_retires_current_evidence_and_can_be_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            source, hints, run = self.start(Path(directory))
            source.unlink()
            manifest_path = run / 'manifest.json'
            interrupted = json.loads(manifest_path.read_text())
            self.assertTrue(interrupted['jobs'])
            interrupted['jobs'][0]['status'] = 'running'
            manifest_path.write_text(json.dumps(interrupted))
            rejected = self.cli('resume', run, '--hints', hints, code=2)
            self.assertEqual(rejected['status'], 'invalid_input')
            self.assertIn('source must be a regular file or directory', rejected['reason'])

            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'partial')
            self.assertFalse(any(job['status'] == 'running' for job in manifest['jobs']))
            self.assertFalse(any(a['current'] for a in manifest['artifacts']))
            self.assertFalse(any(f['current'] for f in manifest['findings']))
            self.assertFalse(any(item['current'] for item in manifest['intelligence']))
            self.assertEqual(json.loads((run / 'findings.json').read_text()), manifest['findings'])
            self.cli('report', run, code=0)
            report = (run / 'report.md').read_text()
            self.assertNotIn('HELLO WORLD', report)
            self.assertIn('Status: partial', report)

            source.write_bytes(b'SEVMTE8gV09STEQ=')
            self.cli('resume', run, '--hints', hints, code=3)
            recovered = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(f['current'] and 'HELLO' in f['evidence']
                                for f in recovered['findings']))

    def test_changed_direct_input_retires_old_report_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source, hints, run = self.start(Path(directory))
            source.write_bytes(b'Rk9P')
            self.cli('resume', run, '--hints', hints, code=3)
            self.cli('report', run, code=0)
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any(f['current'] and 'HELLO' in f['evidence']
                                 for f in manifest['findings']))
            self.assertNotIn('HELLO WORLD', (run / 'report.md').read_text())

    def test_missing_source_clears_cached_memory_inventory_from_report(self):
        with tempfile.TemporaryDirectory() as directory:
            source, hints, run = self.start(Path(directory))
            path = run / 'manifest.json'
            manifest = json.loads(path.read_text())
            source_id = next(a['id'] for a in manifest['artifacts'] if a['depth'] == 0)
            fingerprint = 'memory-fixture-fingerprint'
            manifest['memory_routed_input_ids'] = [source_id]
            manifest['current_adapter_fingerprints']['memory'] = [fingerprint]
            manifest['jobs'].append({
                'id': 'memory-fixture', 'adapter_id': 'memory', 'status': 'complete',
                'input_ids': [source_id], 'tool_fingerprint': fingerprint,
                'data_fingerprints': {
                    'memory_symbols': manifest.get('memory_symbols_sha256'),
                    'memory_targets': manifest.get('memory_targets_sha256')},
                'inventory_path': str(run / 'inventory.json'), 'inventory_sha256': 'fixture'})
            path.write_text(json.dumps(manifest))
            self.cli('report', run, code=0)
            self.assertIn('Full memory inventory:', (run / 'report.md').read_text())

            source.unlink()
            self.cli('resume', run, '--hints', hints, code=2)
            self.cli('report', run, code=0)
            self.assertNotIn('Full memory inventory:', (run / 'report.md').read_text())

    def test_removed_source_parent_retires_evidence_and_can_be_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_parent = root / 'inputs'
            source_parent.mkdir()
            source, hints, run = self.start(root, source_parent)
            source.unlink()
            source_parent.rmdir()
            source_parent.write_text('replacement file')

            rejected = self.cli('resume', run, '--hints', hints, code=2)
            self.assertEqual(rejected['status'], 'invalid_input')
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'partial')
            self.assertFalse(any(f['current'] for f in manifest['findings']))

            source_parent.unlink()
            source_parent.mkdir()
            source.write_bytes(b'SEVMTE8gV09STEQ=')
            self.cli('resume', run, '--hints', hints, code=3)
            restored = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(f['current'] and 'HELLO' in f['evidence']
                                for f in restored['findings']))

    def test_unsafe_replacement_rejection_does_not_mutate_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, hints, run = self.start(root)
            source.unlink()
            outside = root / 'outside.txt'
            outside.write_text('outside')
            for unsafe in ('symlink', 'fifo'):
                with self.subTest(unsafe=unsafe):
                    if unsafe == 'symlink':
                        source.symlink_to(outside)
                    else:
                        os.mkfifo(source)
                    try:
                        before = {name: (run / name).read_bytes() for name in
                                  ('manifest.json', 'findings.json', 'report.md', 'events.jsonl')}
                        rejected = self.cli('resume', run, '--hints', hints, code=2)
                        self.assertEqual(rejected['status'], 'invalid_input')
                        self.assertEqual(before, {name: (run / name).read_bytes()
                                                  for name in before})
                    finally:
                        source.unlink()
            replacement_hints = root / 'replacement-hints.json'
            replacement_hints.write_text(hints.read_text())
            os.link(replacement_hints, source)
            before = {name: (run / name).read_bytes() for name in
                      ('manifest.json', 'findings.json', 'report.md', 'events.jsonl')}
            rejected = self.cli('resume', run, '--hints', replacement_hints, code=2)
            self.assertEqual(rejected['status'], 'invalid_input')
            self.assertEqual(before, {name: (run / name).read_bytes() for name in before})
            source.unlink()
            symbol_dir = root / 'private-symbols'
            symbol_dir.mkdir()
            symbol_file = symbol_dir / 'symbols.json'
            symbol_file.write_text('private data')
            symbol_hints = root / 'symbol-hints.json'
            symbol_hints.write_text(json.dumps({'flag_patterns': ['HELLO'],
                                                'memory_symbol_dir': str(symbol_dir)}))
            os.link(symbol_file, source)
            before = {name: (run / name).read_bytes() for name in before}
            rejected = self.cli('resume', run, '--hints', symbol_hints, code=2)
            self.assertEqual(rejected['status'], 'invalid_input')
            self.assertEqual(before, {name: (run / name).read_bytes() for name in before})


if __name__ == '__main__':
    unittest.main()
