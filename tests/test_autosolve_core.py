"""Public CLI checks for run identity, provenance, and honest partial results."""

import base64
import fcntl
import gzip
import hashlib
import io
import json
import lzma
import multiprocessing
import os
import sqlite3
import shutil
from email.message import EmailMessage
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

from test_autosolve_documents import ENCRYPTED_ZIP
from test_autosolve_checker import ANGR_IMPORT_READY
from test_autosolve_images import sample_png
from test_autosolve_packet_objects import pcap as object_pcap, transaction as http_transaction
from scripts.autosolve_lib import core

MIXED_PASSWORD_ZIP = base64.b64decode(
    'UEsDBBQAAQAAAPUEW10/4namGAAAAAwAAAABAAAAYefZxcULHaildVlk5VAUjUP3ySS4U2j53FBLAwQUAAEAAAD1BFtduWa8sxkAAAANAAAAAQAAAGL04rAjADnRhfpNazlwQZq1SJKpTGV6CcG5UEsBAj8DFAABAAAA9QRbXT/idqYYAAAADAAAAAEAJAAAAAAAAAAggKSBAAAAAGEKACAAAAAAAAEAGACSVPj6cGXdAQAAAAAAAAAAAAAAAAAAAABQSwECPwMUAAEAAAD1BFtduWa8sxkAAAANAAAAAQAkAAAAAAAAACCApIE3AAAAYgoAIAAAAAAAAQAYAJJU+PpwZd0BAAAAAAAAAAAAAAAAAAAAAFBLBQYAAAAAAgACAKYAAABvAAAAAAA='
)
WHITESPACE_PASSWORD_ZIP = base64.b64decode(
    'UEsDBBQAAQAAALU4W13c7i/pIQAAABUAAAALAAAAcGF5bG9hZC50eHRU2Q/v8fFaHauyBegPXZQMJmOLAZVk2pPNkYXdgomCA8pQSwECPwMUAAEAAAC1OFtd3O4v6SEAAAAVAAAACwAkAAAAAAAAACCApIEAAAAAcGF5bG9hZC50eHQKACAAAAAAAAEAGACo4nTnpmXdAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAEAAQBdAAAASgAAAAAA'
)


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


def _spawn_descendant(marker):
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    Path(marker).write_text(str(child.pid))
    time.sleep(30)


class AutosolveCoreTests(unittest.TestCase):
    def run_cli(self, *args, code=0):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', *map(str, args)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def checker_fixture(self, root):
        source = root / 'checker.c'
        binary = root / 'checker'
        source.write_text('''#include <stdio.h>
int main(int argc, char **argv) {
  if (argc == 2 && argv[1][0] == 'R' && argv[1][1] == '7') {
    puts("REV07_WIN"); return 0;
  }
  puts("REV07_LOSE"); return 1;
}''')
        subprocess.run(['gcc', '-O0', '-fno-pie', '-no-pie', '-o', str(binary), str(source)],
                       check=True, capture_output=True)
        hints = root / 'hints.json'
        hints.write_text(json.dumps({'checker': {'channel': 'argv', 'length': 2,
                                  'find': {'stdout': 'REV07_WIN'},
                                  'avoid': {'stdout': 'REV07_LOSE'}}}))
        return source, binary, hints

    def test_help_without_optional_packages(self):
        result = subprocess.run([sys.executable, '-I', '-S', str(SCRIPT), '--help'],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'analyze', result.stdout)
        self.assertIn(b'doctor', result.stdout)

    def test_capabilities_reflect_integrated_baselines(self):
        for category, family in (('images', 'IMG02'), ('documents', 'DOC05'),
                                 ('encoding', 'ENC10'), ('audio_video', 'AV04'),
                                 ('can_misc', 'CAN02'), ('packets', 'NET02'),
                                 ('packets', 'NET05'), ('disk_memory', 'DF01'),
                                 ('disk_memory', 'DF02'), ('disk_memory', 'DF03'),
                                 ('disk_memory', 'DF05'), ('pwn_services', 'PWN01'),
                                 ('pwn_services', 'PWN02'), ('pwn_services', 'PWN07'),
                                 ('malware_reversing', 'REV03'),
                                 ('malware_reversing', 'REV07'),
                                 ('web', 'WEB01'), ('web', 'WEB02'), ('web', 'WEB03'),
                                 ('web', 'WEB05')):
            with self.subTest(category=category):
                rows = self.run_cli('capabilities', '--category', category)['families']
                self.assertEqual(next(row['status'] for row in rows if row['id'] == family), 'partial')

    def test_worker_timeout_stops_only_its_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'child.pid'
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                         start_new_session=True)
            worker = multiprocessing.Process(target=core._worker_entry,
                                             args=(_spawn_descendant, str(marker)))
            worker.start()
            try:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists())
                child_pid = int(marker.read_text())
                self.assertEqual(os.getpgid(child_pid), worker.pid)
                core._stop_worker(worker)
                self.assertFalse(worker.is_alive())
                self.assertIsNone(unrelated.poll())
                try:
                    state = Path(f'/proc/{child_pid}/stat').read_text().split()[2]
                except (FileNotFoundError, ProcessLookupError):
                    state = 'gone'
                self.assertIn(state, ('gone', 'Z'))
            finally:
                if worker.is_alive():
                    core._stop_worker(worker)
                unrelated.terminate()
                unrelated.wait(timeout=3)

    def test_source_resume_new_hints_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'challenge.txt'
            source.write_bytes(b'SEVMTE8gV09STEQ=')  # HELLO WORLD, independently known oracle.
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'flag_patterns': ['HELLO']}))
            first = self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                 '--runs-root', root / 'runs', code=3)
            run = Path(first['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'partial')
            self.assertTrue(any(Path(a['path']).read_bytes() == b'HELLO WORLD'
                                for a in manifest['artifacts'] if a['depth'] > 0))
            self.assertTrue(any(f['state'] == 'candidate' and 'HELLO' in f['evidence']
                                for f in manifest['findings']))
            self.assertFalse(any(f['state'] == 'challenge_accepted' for f in manifest['findings']))
            self.assertEqual(source.read_bytes(), b'SEVMTE8gV09STEQ=')
            jobs = len(manifest['jobs'])

            hints.write_text(json.dumps({'flag_patterns': ['WORLD']}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len(resumed['jobs']), jobs)
            self.assertTrue(any('WORLD' in f['evidence'] for f in resumed['findings']))
            self.assertFalse(any('HELLO' in f['evidence'] for f in resumed['findings']))

            source.write_bytes(b'Rk9P')  # FOO
            self.run_cli('resume', run, '--hints', hints, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertNotEqual(changed['artifacts'][0]['sha256'], changed['artifacts'][-1]['sha256'])
            self.assertFalse(changed['artifacts'][0]['current'])
            old_children = [a for a in changed['artifacts'] if a['depth'] > 0 and a['sha256'] ==
                            next(a['sha256'] for a in manifest['artifacts'] if a['depth'] > 0)]
            self.assertTrue(old_children)
            self.assertTrue(all(not a['current'] for a in old_children))

    def test_changed_pattern_retires_old_match_before_tiny_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input'
            source.write_bytes(b'PROOF{OLD}')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'flag_patterns': [r'PROOF\{OLD\}']}))
            run = Path(self.run_cli('analyze', source, '--category', 'images', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(f['current'] and 'OLD' in f['evidence'] for f in before['findings']))
            hints.write_text(json.dumps({'flag_patterns': [r'NEW\{[^}]+\}']}))
            self.run_cli('resume', run, '--hints', hints, '--budget', '0.001', code=3)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(all(not f['current'] for f in after['findings'] if 'OLD' in f['evidence']))

    def test_invalid_hints_and_single_writer_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input'
            source.write_text('SGVsbG8=')
            hints = root / 'hints.json'
            hints.write_text('{"unknown": true}')
            self.assertEqual(self.run_cli('analyze', source, '--hints', hints,
                                          '--runs-root', root / 'runs', code=2)['status'], 'invalid_input')
            hints.write_text('{"flag_patterns": ["\\ud800"]}')
            self.assertEqual(self.run_cli('analyze', source, '--hints', hints,
                                          '--runs-root', root / 'runs', code=2)['status'], 'invalid_input')
            self.assertFalse((root / 'runs').exists())
            run = Path(self.run_cli('analyze', source, '--runs-root', root / 'runs', code=3)['run'])
            with (run / '.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(self.run_cli('resume', run, code=2)['status'], 'invalid_input')

    def test_layered_chain_through_public_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = b'Independent binary oracle\x00\xff'
            encoded = base64.b64encode(gzip.compress(oracle))
            source = root / 'input.txt'
            source.write_bytes(encoded)
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            recovered = [a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == oracle]
            self.assertEqual(len(recovered), 1)
            self.assertTrue(recovered[0]['parents'])
            self.assertEqual(manifest['coverage']['ENC01']['status'], 'ran')
            self.assertEqual(manifest['coverage']['ENC02']['status'], 'ran')
            self.assertEqual(source.read_bytes(), encoded)

    def test_encoded_concatenated_compression_reports_trailing_and_member_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = gzip.compress(b'ENC{member_one}', mtime=0)
            second = gzip.compress(b'\x00\xff-member-two', mtime=0)
            source = root / 'input.txt'
            source.write_bytes(base64.b64encode(first + second + b'TAIL'))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            final = next(item for item in manifest['artifacts']
                         if item['depth'] == 2 and
                         Path(item['path']).read_bytes() == b'ENC{member_one}\x00\xff-member-two')
            locator = final['source_locator']
            self.assertEqual(locator['transform'], 'gzip')
            self.assertEqual(locator['trailing_bytes'], 4)
            self.assertEqual(locator['members'], [
                {'input_start': 0, 'input_end': len(first), 'output_start': 0, 'output_end': 15},
                {'input_start': len(first), 'input_end': len(first) + len(second),
                 'output_start': 15, 'output_end': 28},
            ])
            self.assertEqual(manifest['coverage']['ENC02']['status'], 'truncated')
            self.assertTrue(any('4 trailing bytes' in warning for warning in manifest['warnings']))
            resumed = self.run_cli('resume', run, code=3)
            self.assertEqual(resumed['status'], 'partial')
            continued = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(continued['coverage']['ENC02']['status'], 'truncated')
            self.assertEqual(sum('4 trailing bytes' in warning
                                 for warning in continued['warnings']), 1)

    def test_encoded_truncated_stream_and_expansion_limit_have_explicit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, compressed in (
                ('truncated', gzip.compress(b'ENC{complete}', mtime=0)[:-2]),
                ('limit', gzip.compress(b'A' * (core.MAX_CHILD + 1), mtime=0)),
            ):
                with self.subTest(name=name):
                    source = root / f'{name}.txt'
                    source.write_bytes(base64.b64encode(compressed))
                    run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                            '--runs-root', root / f'{name}-runs', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(manifest['coverage']['ENC02']['status'], 'truncated')
                    self.assertTrue(any(f'gzip {name}' in warning
                                        for warning in manifest['warnings']))
                    self.assertFalse(any(edge['operation'].startswith('gzip')
                                         for item in manifest['artifacts']
                                         for edge in item['parents']))

    def test_encoded_xz_padding_joins_valid_streams_but_rejects_misaligned_padding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = lzma.compress(b'ENC{xz-first}'), lzma.compress(b'\x00xz-second')
            for pad, valid in ((b'\x00' * 4, True), (b'\x00' * 3, False)):
                with self.subTest(valid=valid):
                    source = root / f'{len(pad)}.txt'
                    source.write_bytes(base64.b64encode(first + pad + second + b'TAIL'))
                    run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                            '--runs-root', root / f'runs-{len(pad)}', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    recovered = [item for item in manifest['artifacts'] if item['depth'] == 2
                                 and Path(item['path']).read_bytes() == b'ENC{xz-first}\x00xz-second']
                    if valid:
                        self.assertEqual(len(recovered), 1)
                        locator = recovered[0]['source_locator']
                        self.assertEqual(locator['padding_bytes'], 4)
                        self.assertEqual(locator['trailing_bytes'], 4)
                        self.assertEqual(locator['members'][1]['input_start'], len(first) + 4)
                    else:
                        self.assertEqual(recovered, [])
                        self.assertTrue(any('xz invalid' in warning
                                            for warning in manifest['warnings']))
                    self.assertEqual(manifest['coverage']['ENC02']['status'], 'truncated')

    def test_binary_rows_keep_line_locator_and_declared_count_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'bits.txt'
            source.write_bytes(b'Bits Found: 24\nDecoded bitstream:\n01001000\n01101001\n')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'Hi')
            self.assertEqual(child['source_locator'], {'transform': 'bit-text', 'line_start': 3,
                                                        'line_end': 4, 'bit_count': 16})
            self.assertTrue(any('declared bit count 24 differs from decoded 16' in warning
                                for warning in manifest['warnings']))

    def test_classical_atbash_candidate_is_covered_through_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'cipher.txt'
            source.write_bytes(b'Svool, Dliow!')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == b'Hello, World!'
                                and a['source_locator']['transform'].startswith('atbash ')
                                for a in manifest['artifacts']))
            self.assertEqual(manifest['coverage']['ENC03']['status'], 'ran')

    def test_unranked_classical_candidates_do_not_expand_recursively(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'cipher.txt'
            source.write_bytes('¡Nurg, ykñux! Bgsuy gr iglé.'.encode())
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            children = [a for a in manifest['artifacts'] if a['depth'] > 0]
            self.assertEqual(len(children), 25)
            self.assertTrue(any(Path(a['path']).read_bytes() == '¡Hola, señor! Vamos al café.'.encode()
                                and a['parents'][0]['operation'].startswith('caesar-shift:-6')
                                for a in children))
            self.assertTrue(all(a['depth'] == 1 for a in children))
            self.assertFalse(any(f['state'] == 'accepted' for f in manifest['findings']))
            self.run_cli('resume', run, '--budget', 30, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len(resumed['artifacts']), len(manifest['artifacts']))
            self.assertEqual(len(resumed['jobs']), len(manifest['jobs']))
            self.assertFalse(any(f['state'] == 'accepted' for f in resumed['findings']))

    def test_plain_prose_rot13_child_does_not_spawn_unranked_caesar_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'ordinary.txt'
            source.write_bytes(b'The ordinary report describes a meeting at noon; no cipher was applied.')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertLessEqual(len(manifest['artifacts']), 5)
            self.assertFalse(any(edge['operation'].endswith('(hypothesis; unranked)')
                                 for item in manifest['artifacts'] for edge in item['parents']))
            self.assertFalse(any(f['state'] == 'accepted' for f in manifest['findings']))

    def test_directory_privacy_and_shared_lineage_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'bundle'
            source.mkdir()
            (source / 'a').write_bytes(b'SEVMTE8=')
            (source / 'b').write_bytes(b'hex: 48 45 4c 4c 4f')
            hints = source / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': 'PRIVATE_SENTINEL'}))
            first = self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                 '--runs-root', source / 'runs', code=3)
            run = Path(first['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            roots = {a['path'] for a in manifest['artifacts'] if a['depth'] == 0}
            self.assertEqual(roots, {str(source / 'a'), str(source / 'b')})
            self.assertNotIn('PRIVATE_SENTINEL', (run / 'report.md').read_text())
            hello = next(a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'HELLO')
            self.assertEqual(len(hello['parents']), 2)

            (source / 'a').write_bytes(b'Rk9P')
            self.run_cli('resume', run, '--hints', hints, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            hello = next(a for a in changed['artifacts'] if a['id'] == hello['id'])
            self.assertTrue(hello['current'])
            (source / 'b').unlink()
            self.run_cli('resume', run, '--hints', hints, code=3)
            deleted = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(next(a for a in deleted['artifacts'] if a['id'] == hello['id'])['current'])
            self.assertNotIn('PRIVATE_SENTINEL', (run / 'report.md').read_text())

    def test_shared_child_requires_a_valid_job_for_its_current_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            with zipfile.ZipFile(bundle / 'archive.zip', 'w') as archive:
                archive.writestr('message.txt', b'HELLO_TEST')
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            (bundle / 'encoded.txt').write_bytes(base64.b64encode(b'HELLO_TEST'))
            self.run_cli('resume', run, code=3)
            (bundle / 'encoded2.txt').write_bytes(base64.b64encode(b'HELLO_TEST'))
            self.run_cli('resume', run, code=3)
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'HELLO_TEST')
            roots = {Path(a['path']).name: a['id'] for a in manifest['artifacts'] if a['depth'] == 0}
            self.assertEqual({edge['id'] for edge in child['parents']}, set(roots.values()))
            self.assertTrue(all(edge.get('job_key') for edge in child['parents']))
            self.assertEqual([edge['operation'] for edge in child['parents']
                              if edge['id'] == roots['encoded2.txt']], ['base64'])

            core._refresh_current(manifest, [roots['encoded.txt']])
            self.assertTrue(child['current'])
            zip_job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'zip')
            manifest['findings'].append({'state': 'candidate', 'artifact_id': child['id'],
                                         'job_id': zip_job['id'], 'operation': 'ZIP-specific lead',
                                         'current': True})
            manifest['current_adapter_fingerprints']['zip'] = []
            core._refresh_current(manifest, [roots['encoded.txt']])
            self.assertTrue(child['current'])
            self.assertFalse(manifest['findings'][-1]['current'])
            manifest['current_adapter_fingerprints']['encoding'] = []
            core._refresh_current(manifest, [roots['encoded.txt']])
            self.assertFalse(child['current'])

    def test_shared_child_report_uses_only_current_parent_locator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            with zipfile.ZipFile(bundle / 'archive.zip', 'w') as archive:
                archive.writestr('message.txt', b'HELLO_TEST')
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            (bundle / 'encoded.txt').write_bytes(base64.b64encode(b'HELLO_TEST'))
            self.run_cli('resume', run, code=3)
            (bundle / 'archive.zip').unlink()
            self.run_cli('resume', run, code=3)
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'HELLO_TEST')
            self.assertTrue(child['current'])
            self.assertEqual([row['locator'] for row in child['current_source_locators']],
                             [{'transform': 'base64'}])
            row = next(line for line in (run / 'report.md').read_text().splitlines()
                       if child['sha256'] in line and line.startswith('- text:'))
            self.assertIn('base64', row)
            self.assertNotIn('archive_member', row)

    def test_private_hints_hardlink_inside_bundle_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'challenge').write_bytes(b'ordinary bytes')
            hints = root / 'private-hints.json'
            hints.write_text(json.dumps({'known_plaintext': 'TOKEN{private-example}',
                                         'flag_patterns': [r'TOKEN\{[^}]+\}']}))
            os.link(hints, bundle / 'linked-hints.json')
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual({Path(a['path']).name for a in manifest['artifacts'] if a['depth'] == 0},
                             {'challenge'})
            self.assertNotIn('private-example', (run / 'report.md').read_text())

    def test_replaced_hints_do_not_ingest_old_private_file_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'challenge').write_bytes(b'ordinary challenge bytes')
            old_hints = bundle / 'old_hints.json'
            old_hints.write_text(json.dumps({'known_plaintext': 'SECRET{old_private}'}))
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--hints', old_hints,
                                    '--runs-root', bundle / 'runs', code=3)['run'])
            new_hints = root / 'fresh_hints.json'
            new_hints.write_text(json.dumps({'flag_patterns': [r'SECRET\{[^}]+\}']}))
            self.run_cli('resume', run, '--hints', new_hints, code=3)
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual({Path(a['path']).name for a in manifest['artifacts']
                              if a['depth'] == 0 and a['current']}, {'challenge'})
            self.assertNotIn('old_private', (run / 'report.md').read_text())
            manifest.pop('private_hint_paths')
            manifest.pop('private_hint_identities')
            (run / 'manifest.json').write_text(json.dumps(manifest))
            refused = self.run_cli('resume', run, '--hints', new_hints, code=2)
            self.assertIn('lacks private hint exclusions', refused['reason'])

    def test_private_hint_exclusion_is_checkpointed_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hints = root / 'hints.json'
            hints.write_text('{}')
            run = root / 'run'
            manifest = {'jobs': [], 'private_hint_paths': [], 'private_hint_identities': []}
            with patch.object(core, '_execute', side_effect=RuntimeError('simulated crash')):
                with self.assertRaisesRegex(RuntimeError, 'simulated crash'):
                    core._locked_execute(run, manifest, 1, {}, 'digest', hints)
            saved = json.loads((run / 'manifest.json').read_text())
            self.assertIn(str(hints.absolute()), saved['private_hint_paths'])
            self.assertTrue(saved['private_hint_identities'])

    def test_transform_cycle_does_not_reparent_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'word'
            source.write_bytes(b'HELLO')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            original = next(a for a in manifest['artifacts'] if a['depth'] == 0)
            self.assertEqual(original['parents'], [])
            self.assertTrue(all(original['id'] not in job['child_ids'] for job in manifest['jobs']))

    def test_decoded_content_matching_another_root_survives_root_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'bundle'
            source.mkdir()
            (source / 'encoded').write_bytes(b'SEVMTE8=')
            (source / 'plain').write_bytes(b'HELLO')
            hints = root / 'hints.json'
            hints.write_text('{"flag_patterns": ["HELLO"]}')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            (source / 'plain').unlink()
            self.run_cli('resume', run, '--hints', hints, code=3)
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'HELLO'
                                for a in manifest['artifacts']))
            self.assertTrue(any(f['current'] and 'HELLO' in f['evidence']
                                for f in manifest['findings']))

    def test_identical_roots_share_child_with_both_parent_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            for name in ('a', 'b'):
                (bundle / name).write_bytes(b'SEVMTE8=')
            run = Path(self.run_cli('analyze', bundle, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            roots = {a['id'] for a in manifest['artifacts'] if a['depth'] == 0}
            hello = next(a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'HELLO')
            self.assertEqual({edge['id'] for edge in hello['parents']}, roots)

    def test_runs_root_cannot_equal_input_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input').write_bytes(b'SEVMTE8=')
            response = self.run_cli('analyze', root, '--runs-root', root, code=2)
            self.assertEqual(response['status'], 'invalid_input')
            self.assertEqual({p.name for p in root.iterdir()}, {'input'})

    def test_resume_recomputes_current_warnings_and_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'bundle'
            source.mkdir()
            item = source / 'item'
            item.write_bytes(b'A' * (1024 * 1024 + 1))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            initial = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any('candidate block match limit' in x for x in initial['warnings']))
            self.assertEqual(initial['coverage']['ENC03']['status'], 'ran')
            item.write_bytes(b'\x00\xff')
            self.run_cli('resume', run, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any('candidate block match limit' in x for x in changed['warnings']))
            self.assertTrue(any('candidate block match limit' in x for x in changed['history_warnings']))
            self.assertEqual(changed['coverage']['ENC03']['status'], 'no finding')
            item.unlink()
            self.run_cli('resume', run, code=3)
            deleted = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(deleted['coverage']['ENC03']['status'], 'not scheduled')
            self.assertIn('no regular source files remain', (run / 'report.md').read_text())

    def test_zip_to_encoded_payload_chain_and_member_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = b'ZIP to encoded to compressed payload\x00\xff'
            source = root / 'input.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('nested/payload.dat', base64.b64encode(gzip.compress(oracle)))
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue(any(a['source_locator'].get('archive_member') == 'nested/payload.dat'
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == oracle
                                for a in manifest['artifacts']))
            for family in ('DOC01', 'ENC01', 'ENC02'):
                self.assertEqual(manifest['coverage'][family]['status'], 'ran')

    def test_mime_attachment_to_encoded_payload_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = b'Independent MIME oracle\x00\xff'
            message = EmailMessage()
            message.set_content('See attached bytes.')
            message.add_attachment(base64.b64encode(gzip.compress(oracle)),
                                   maintype='application', subtype='octet-stream',
                                   filename='../do-not-use-as-path.dat')
            source = root / 'mail.dat'
            source.write_bytes(message.as_bytes())
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue(any(a['source_locator'].get('mime_part') == '0.1'
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == oracle
                                for a in manifest['artifacts']))
            self.assertFalse((root / 'do-not-use-as-path.dat').exists())
            for family in ('DOC06', 'ENC01', 'ENC02'):
                self.assertEqual(manifest['coverage'][family]['status'], 'ran')

    def test_pdf_public_cli_stages_attachment_with_object_locator(self):
        source = Path(__file__).resolve().parents[1] / 'examples/core/attachment.pdf'
        with tempfile.TemporaryDirectory() as directory:
            run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                    '--runs-root', Path(directory) / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            attachment = next(a for a in manifest['artifacts']
                              if a['source_locator'].get('pdf_kind') == 'attachment')
            self.assertEqual(Path(attachment['path']).read_bytes(), b'TRAINING-BYTES\x00\xff\n')
            self.assertIn('object 6 0', attachment['source_locator']['pdf_locator'])
            self.assertEqual(next(j for j in manifest['jobs'] if j['adapter_id'] == 'pdf')['status'],
                             'complete')
            self.assertEqual(manifest['coverage']['DOC04']['status'], 'truncated')

    def test_can_log_public_cli_preserves_frame_lines_and_malformed_rows(self):
        examples = Path(__file__).resolve().parents[1] / 'examples/core'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = examples / 'can-capture.txt'
            before = good.read_bytes()
            run = Path(self.run_cli('analyze', good, '--category', 'can',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'can-log')
            self.assertEqual(job['frame_count'], 5)
            frames = json.loads(Path(job['frames_path']).read_text())
            self.assertEqual((frames[0]['can_id'], frames[0]['source_line'],
                              frames[0]['payload_hex']), ('123', 1, '0102030405060708'))
            self.assertEqual(manifest['coverage']['CAN01']['status'], 'ran')
            self.assertEqual(good.read_bytes(), before)

            malformed = examples / 'can-malformed.asc'
            run = Path(self.run_cli('analyze', malformed, '--category', 'can',
                                    '--runs-root', root / 'runs', code=3)['run'])
            result = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(result['coverage']['CAN01']['status'], 'truncated')
            self.assertTrue(any('line 5' in warning for warning in result['warnings']))

            unstamped = root / 'unstamped.txt'
            unstamped.write_text('vcan0 123#0102\nvcan1 1ABCDEFF [2] AA BB\n')
            run = Path(self.run_cli('analyze', unstamped, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            parsed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(parsed['coverage']['CAN01']['status'], 'ran')
            job = next(j for j in parsed['jobs'] if j['adapter_id'] == 'can-log')
            rows = json.loads(Path(job['frames_path']).read_text())
            self.assertTrue(all(row['timestamp'] is None for row in rows))

    def test_packet_cli_preserves_http_frame_and_incomplete_capture(self):
        examples = Path(__file__).resolve().parents[1] / 'examples/core'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = examples / 'http.pcap'
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'packets',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'packets')
            records = json.loads(Path(job['records_path']).read_text())
            request = next(row for row in records if row.get('http', {}).get('method') == 'GET')
            self.assertEqual((request['packet'], request['http']['uri'], request['tcp_stream']),
                             (4, '/report.txt', 0))
            self.assertEqual(manifest['coverage']['NET01']['status'], 'ran')
            self.assertEqual(source.read_bytes(), original)

            run = Path(self.run_cli('analyze', examples / 'http-incomplete.pcap',
                                    '--category', 'packets', '--runs-root', root / 'runs', code=3)['run'])
            incomplete = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(incomplete['coverage']['NET01']['status'], 'truncated')
            self.assertEqual(incomplete['coverage']['NET02']['status'], 'truncated')
            self.assertFalse(any(item['adapter_id'] == 'packet-objects' and item['child_ids']
                                 for item in incomplete['jobs']))
            self.assertTrue(any('conversation incomplete' in warning for warning in incomplete['warnings']))

    def test_packet_cli_exports_archive_with_exact_locator_and_recurses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('inside.txt', b'NETWORK-ARCHIVE-CONTENT')
            source = root / 'capture.pcap'
            source.write_bytes(object_pcap(http_transaction(41000, archive.getvalue())))
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'packets',
                                    '--budget', '10', '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['NET02']['status'], 'ran')
            job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'packet-objects')
            self.assertEqual(len(job['child_ids']), 1)
            child = next(item for item in manifest['artifacts'] if item['id'] == job['child_ids'][0])
            self.assertEqual(Path(child['path']).read_bytes(), archive.getvalue())
            self.assertEqual((child['source_locator']['packet'],
                              child['source_locator']['tcp_stream']), (6, 0))
            self.assertEqual(child['source_locator']['source_locators'][0]['request_packet'], 4)
            self.assertTrue(child['source_locator']['wire_length_verified'])
            self.assertTrue(any(item['depth'] == 2 and
                                Path(item['path']).read_bytes() == b'NETWORK-ARCHIVE-CONTENT'
                                for item in manifest['artifacts']))
            self.assertEqual(source.read_bytes(), original)
            self.run_cli('resume', run, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([item for item in resumed['jobs']
                                  if item['adapter_id'] == 'packet-objects']), 1)

    def test_source_reversion_rebuilds_current_can_and_packet_intelligence(self):
        examples = Path(__file__).resolve().parents[1] / 'examples/core'
        for filename, category, tag, adapter in (
            ('can-capture.txt', 'can', 'CAN frame', 'can-log'),
            ('http.pcap', 'packets', 'PCAP frame', 'packets'),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / filename
                original = (examples / filename).read_bytes()
                source.write_bytes(original)
                run = Path(self.run_cli('analyze', source, '--category', category,
                                        '--runs-root', root / 'runs', code=3)['run'])
                first = json.loads((run / 'manifest.json').read_text())
                first_root = next(a['id'] for a in first['artifacts'] if a['depth'] == 0)
                source.write_bytes(b'unrelated text')
                self.run_cli('resume', run, code=3)
                source.write_bytes(original)
                self.run_cli('resume', run, code=3)
                restored = json.loads((run / 'manifest.json').read_text())
                new_root = next(a['id'] for a in restored['artifacts']
                                if a['depth'] == 0 and a['current'])
                self.assertNotEqual(new_root, first_root)
                self.assertTrue(any(item['current'] and item['artifact_id'] == new_root
                                    and item['tag'] == tag for item in restored['intelligence']))
                self.assertFalse(any(item['current'] and item['artifact_id'] == first_root
                                     and item['tag'] == tag for item in restored['intelligence']))
                self.assertEqual(len([j for j in restored['jobs'] if j['adapter_id'] == adapter]), 2)

    def test_packet_tool_change_retires_old_intelligence_even_on_failed_resume(self):
        source = Path(__file__).resolve().parents[1] / 'examples/core/http.pcap'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = Path(self.run_cli('analyze', source, '--category', 'packets',
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(item['current'] and item['tag'] == 'PCAP frame'
                                for item in before['intelligence']))
            command = [sys.executable, '-B', str(SCRIPT), '--json', 'resume', str(run),
                       '--budget', '0.005']
            result = subprocess.run(command, capture_output=True, timeout=15,
                                    env={**os.environ, 'AUTOSOLVE_TSHARK': '/bin/false'})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any(item['current'] and item['tag'] == 'PCAP frame'
                                 for item in after['intelligence']))

    def test_sqlite_wal_rows_and_resume_companion_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'evidence.db'
            connection = sqlite3.connect(source)
            try:
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA wal_autocheckpoint=0')
                connection.execute('CREATE TABLE notes (value TEXT)')
                connection.commit()
                connection.execute('INSERT INTO notes VALUES (?)', ('first clue',))
                connection.commit()
                before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
                run = Path(self.run_cli('analyze', source, '--category', 'memory',
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                self.assertEqual(manifest['coverage']['DF04']['status'], 'ran')
                rows = [a for a in manifest['artifacts']
                        if a['source_locator'].get('sqlite_kind') == 'row']
                self.assertEqual(len(rows), 1)
                self.assertEqual(json.loads(Path(rows[0]['path']).read_text())['values']['value'],
                                 'first clue')
                self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()})

                connection.execute('INSERT INTO notes VALUES (?)', ('second clue',))
                connection.commit()
                self.run_cli('resume', run, code=3)
                changed = json.loads((run / 'manifest.json').read_text())
                current_rows = [a for a in changed['artifacts']
                                if a['current'] and a['source_locator'].get('sqlite_kind') == 'row']
                self.assertEqual({json.loads(Path(a['path']).read_text())['values']['value']
                                  for a in current_rows}, {'first clue', 'second clue'})
                self.assertFalse(rows[0]['id'] in {a['id'] for a in current_rows})
            finally:
                connection.close()

    def test_auto_initial_pass_schedules_sqlite_before_packet_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'examples/core/http.pcap',
                            bundle / 'a.pcap')
            with sqlite3.connect(bundle / 'b.db') as connection:
                connection.execute('CREATE TABLE evidence (value TEXT)')
                connection.execute('INSERT INTO evidence VALUES (?)', ('clue',))
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--budget', '.3',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            adapters = [job['adapter_id'] for job in manifest['jobs']]
            self.assertIn('sqlite', adapters)
            self.assertIn('packets', adapters)
            self.assertLess(adapters.index('sqlite'), adapters.index('packets'))
            self.assertNotEqual(manifest['coverage']['DF04']['status'], 'not scheduled')
            self.assertNotEqual(manifest['coverage']['NET01']['status'], 'not scheduled')

    def test_heavy_rsa_hints_do_not_starve_other_initial_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'encoded.txt').write_bytes(b'SEVMTE8=')
            with zipfile.ZipFile(bundle / 'archive.zip', 'w') as archive:
                archive.writestr('payload', b'ZIP_ONLY')
            n = (1 << 4096) - 1
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'rsa_parameters': {'records': [
                {'n': n, 'e': 17, 'c': (1 << 4095) - 1} for _ in range(32)]}}))
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--hints', hints,
                                    '--budget', '2', '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['ENC01']['status'], 'ran')
            self.assertEqual(manifest['coverage']['DOC01']['status'], 'ran')

    def test_changed_tool_retires_packet_evidence_before_unscheduled_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            with sqlite3.connect(bundle / 'a.db') as connection:
                connection.execute('CREATE TABLE evidence (value TEXT)')
                connection.execute('INSERT INTO evidence VALUES (?)', ('clue',))
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'examples/core/http.pcap',
                            bundle / 'b.pcap')
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--budget', '2',
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(item['current'] and item['tag'] == 'PCAP frame'
                                for item in before['intelligence']))
            command = [sys.executable, '-B', str(SCRIPT), '--json', 'resume', str(run),
                       '--budget', '.001']
            result = subprocess.run(command, capture_output=True, timeout=15,
                                    env={**os.environ, 'AUTOSOLVE_TSHARK': '/bin/false'})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any(item['current'] and item['tag'] == 'PCAP frame'
                                 for item in after['intelligence']))

    def test_original_mime_headers_are_scanned_for_custom_pattern(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'mail.eml'
            source.write_bytes(b'MIME-Version: 1.0\nX-Challenge: PROOF{header_only}\n'
                               b'Content-Type: text/plain\n\nOrdinary body.\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'flag_patterns': [r'PROOF\{[^}]+\}']}))
            run = Path(self.run_cli('analyze', source, '--category', 'auto', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            original = next(a for a in manifest['artifacts'] if a['depth'] == 0)
            self.assertTrue(any(f['artifact_id'] == original['id'] and 'PROOF' in f['evidence']
                                for f in manifest['findings']))

    def test_encrypted_zip_resume_with_private_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encrypted.zip'
            source.write_bytes(ENCRYPTED_ZIP)
            run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(before['coverage']['DOC02']['status'], 'skipped prerequisite')
            password = root / 'private-password.txt'
            password.write_text('wrong\ncorrect horse\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(password)}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == b'verified zip payload'
                                for a in after['artifacts']))
            self.assertEqual(after['coverage']['DOC02']['status'], 'ran')
            self.assertNotIn('correct horse', (run / 'report.md').read_text())

    def test_shared_encoded_child_survives_zip_password_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'encrypted.zip').write_bytes(ENCRYPTED_ZIP)
            password = root / 'passwords.txt'
            password.write_text('correct horse\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(password)}))
            run = Path(self.run_cli('analyze', bundle, '--category', 'auto', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            (bundle / 'encoded.txt').write_bytes(base64.b64encode(b'verified zip payload'))
            self.run_cli('resume', run, '--hints', hints, code=3)
            before = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in before['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == b'verified zip payload')
            self.assertEqual(len(child['parents']), 2)

            hints.write_text('{}')
            self.run_cli('resume', run, '--hints', hints, code=3)
            after = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in after['artifacts'] if a['id'] == child['id'])
            self.assertTrue(child['current'])
            self.assertEqual(after['coverage']['DOC02']['status'], 'skipped prerequisite')
            self.assertTrue(any(edge['operation'] == 'base64' for edge in child['parents']))

    def test_zip_password_file_preserves_surrounding_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encrypted.zip'
            source.write_bytes(WHITESPACE_PASSWORD_ZIP)
            password = root / 'passwords.txt'
            password.write_bytes(b'wrong\n space \n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(password)}))
            self.assertEqual(core._passwords({'password_file': str(password)}, hints)[0],
                             [b'wrong', b' space '])
            run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() ==
                                b'whitespace-key oracle' for a in manifest['artifacts']))
            self.assertEqual(manifest['coverage']['DOC02']['status'], 'ran')

    def test_user_pattern_cannot_block_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input'
            source.write_bytes(b'a' * 30000 + b'!')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'flag_patterns': ['(a+)+$']}))
            run = Path(self.run_cli('analyze', source, '--category', 'images', '--hints', hints,
                                    '--runs-root', root / 'runs', '--budget', '5', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['findings'], [])
            self.assertTrue(any('pattern scan timed out' in warning for warning in manifest['warnings']))
            self.assertEqual(source.read_bytes(), b'a' * 30000 + b'!')

    def test_single_byte_xor_candidate_from_public_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = b'The message is in the file and the key is in the text.\n'
            source = root / 'encoded'
            source.write_bytes(bytes(byte ^ 0xA7 for byte in plaintext))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            recovered = [a for a in manifest['artifacts'] if a['source_locator'].get('xor_key_hex') == 'a7']
            self.assertEqual(len(recovered), 1)
            self.assertEqual(Path(recovered[0]['path']).read_bytes(), plaintext)
            self.assertEqual(manifest['coverage']['ENC05']['status'], 'ran')
            self.assertTrue(any(f['artifact_id'] == recovered[0]['id'] and f['state'] == 'candidate'
                                for f in manifest['findings']))
            self.assertFalse(any(f['state'] == 'challenge_accepted' for f in manifest['findings']))

    def test_repeating_xor_candidate_from_public_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = (b'The message is in the file and the key is in the data. '
                         b'Read the last line of the report to find the answer. ') * 5
            key = b'ICE'
            source = root / 'cipher.bin'
            source.write_bytes(bytes(byte ^ key[index % len(key)]
                                     for index, byte in enumerate(plaintext)))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts']
                         if a['source_locator'].get('xor_key_hex') == key.hex())
            self.assertEqual(Path(child['path']).read_bytes(), plaintext)
            self.assertEqual(child['source_locator']['xor_key_length'], len(key))
            self.assertEqual(manifest['coverage']['ENC05']['status'], 'ran')

    def test_explicit_encoding_searches_xor_when_ciphertext_looks_like_bmp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = b'BLUE-CABLE!'
            phase = 7
            plaintext = (bytes(range(32)) +
                         b'The message is in the file and the key is in the data. ' * 12 +
                         bytes(range(255, 223, -1)))
            source = root / 'cipher.bin'
            source.write_bytes(bytes(byte ^ key[(index + phase) % len(key)]
                                     for index, byte in enumerate(plaintext)))
            self.assertEqual(source.read_bytes()[:2], b'BM')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            rotated = (key[phase:] + key[:phase]).hex()
            child = next(a for a in manifest['artifacts']
                         if a['source_locator'].get('xor_key_hex') == rotated)
            self.assertEqual(Path(child['path']).read_bytes(), plaintext)
            self.assertEqual(manifest['coverage']['ENC05']['status'], 'ran')

    def test_xor_missing_frequency_evidence_is_reported(self):
        for name, data, expected in (
            ('short', b'\x00\x01\x02', 'skipped prerequisite'),
            ('binary', bytes(range(256)), 'no finding'),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / name
                source.write_bytes(data)
                run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                coverage = manifest['coverage']['ENC05']
                self.assertEqual(coverage['status'], expected)
                self.assertIn('frequency', coverage['note'])

    def test_literal_xor_crib_candidate_and_changed_hint_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = b'BLUE-CABLE!'
            phase = 7
            crib = b'KNOWN-CONTAINER!'
            plaintext = bytearray(bytes(range(256)) * 4)
            plaintext[37:37 + len(crib)] = crib
            source = root / 'cipher.bin'
            source.write_bytes(bytes(byte ^ key[(index + phase) % len(key)]
                                     for index, byte in enumerate(plaintext)))
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': crib.decode()}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts']
                         if a['source_locator'].get('xor_crib_offset') == 37 and
                         Path(a['path']).read_bytes() == bytes(plaintext))
            self.assertEqual(child['source_locator']['xor_key_hex'],
                             (key[phase:] + key[:phase]).hex())
            self.assertEqual(child['source_locator']['xor_crib_key_phase'], 37 % len(key))
            self.assertNotIn(crib.decode(), (run / 'report.md').read_text())
            self.assertTrue(any(f['artifact_id'] == child['id'] and f['state'] == 'candidate'
                                for f in manifest['findings']))
            self.assertFalse(any(f['artifact_id'] == child['id'] and
                                 f['state'] in ('validated_transform', 'challenge_accepted')
                                 for f in manifest['findings']))
            self.assertEqual(manifest['coverage']['ENC05']['status'], 'ran')

            hints.write_text(json.dumps({'known_plaintext': 'WRONG-CONTAINER!'}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            updated = json.loads((run / 'manifest.json').read_text())
            retired = next(a for a in updated['artifacts'] if a['id'] == child['id'])
            self.assertFalse(retired['current'])
            self.assertFalse(any(f['artifact_id'] == child['id'] and f['current']
                                 for f in updated['findings']))
            self.assertEqual(updated['coverage']['ENC05']['status'], 'no finding')
            self.assertIn('supplied literal crib', updated['coverage']['ENC05']['note'])

            hints.write_text(json.dumps({'known_plaintext': 'A' * 257}))
            self.assertEqual(self.run_cli('resume', run, '--hints', hints, code=2)['status'],
                             'invalid_input')

    def test_crib_inside_user_pattern_keeps_exact_match_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = b'BLUE-CABLE!'
            phase = 7
            value = b'flag{KNOWN_PREFIX_MORE}'
            crib = b'KNOWN_PREFIX_MORE'
            plaintext = bytearray(bytes(range(256)) * 4)
            plaintext[37:37 + len(value)] = value
            source = root / 'cipher.bin'
            source.write_bytes(bytes(byte ^ key[(index + phase) % len(key)]
                                     for index, byte in enumerate(plaintext)))
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': crib.decode(),
                                         'flag_patterns': [r'flag\{KNOWN_PREFIX_MORE\}']}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts']
                         if a['source_locator'].get('xor_crib_offset') == 42 and
                         Path(a['path']).read_bytes() == bytes(plaintext))
            matches = [f for f in manifest['findings']
                       if f['artifact_id'] == child['id'] and f['operation'] == 'user pattern']
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['source_locator'], {'offset': 37})
            self.assertEqual(matches[0]['match_bytes'], len(value))
            self.assertEqual(matches[0]['match_sha256'], hashlib.sha256(value).hexdigest())
            self.assertEqual(matches[0]['state'], 'candidate')
            self.assertNotIn(crib.decode(), (run / 'report.md').read_text())
            self.assertNotIn(crib.decode(), (run / 'findings.json').read_text())

    def test_large_file_pattern_keeps_exact_match_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = b'flag{KNOWN_PREFIX_MORE}'
            crib = b'KNOWN_PREFIX_MORE'
            offset = core.MAX_READ + 8
            source = root / 'large.bin'
            source.write_bytes(b'\x00' * offset + value)
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': crib.decode(),
                                         'flag_patterns': [r'flag\{KNOWN_PREFIX_MORE\}']}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            matches = [f for f in manifest['findings'] if f['operation'] == 'user pattern']
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['source_locator'], {'offset': offset})
            self.assertEqual(matches[0]['match_bytes'], len(value))
            self.assertEqual(matches[0]['match_sha256'], hashlib.sha256(value).hexdigest())
            self.assertNotIn(crib.decode(), (run / 'report.md').read_text())
            self.assertNotIn(crib.decode(), (run / 'findings.json').read_text())

    def test_large_file_partial_crib_match_keeps_preview_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crib = b'PRIVATE-CRIB-TOKEN!'
            offset = core.MAX_READ + 8
            source = root / 'large.bin'
            source.write_bytes(b'\x00' * offset + crib)
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': crib.decode(),
                                         'flag_patterns': ['PRIVATE-CRIB']}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            matches = [f for f in manifest['findings'] if f['operation'] == 'user pattern']
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['source_locator'], {'offset': offset})
            self.assertEqual(matches[0]['match_bytes'], len(b'PRIVATE-CRIB'))
            self.assertEqual(matches[0]['match_sha256'], hashlib.sha256(b'PRIVATE-CRIB').hexdigest())
            self.assertEqual(matches[0]['evidence'], '[preview withheld for private known plaintext]')
            self.assertNotIn('PRIVATE-CRIB', (run / 'report.md').read_text())
            self.assertNotIn('PRIVATE-CRIB', (run / 'findings.json').read_text())

    def test_default_printable_preview_keeps_long_crib_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crib = 'A' * 256
            source = root / 'plain.bin'
            source.write_bytes(crib.encode())
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'known_plaintext': crib}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            previews = [f for f in manifest['findings'] if f['operation'] == 'printable text']
            self.assertTrue(previews)
            self.assertTrue(all(f['evidence'] == '[preview withheld for private known plaintext]'
                                for f in previews))
            self.assertNotIn('A' * 64, (run / 'report.md').read_text())
            self.assertNotIn('A' * 64, (run / 'findings.json').read_text())

    def test_rsa_hint_relations_are_verified_and_resume_is_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'case.txt'
            source.write_text('RSA parameters are in the private hints file.')
            p, q1, q2 = 10007, 10009, 10037
            records = [{'n': p * q1, 'e': 65537, 'c': pow(0x4142, 65537, p * q1)},
                       {'n': p * q2, 'e': 65537, 'c': pow(0x4344, 65537, p * q2)}]
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'rsa_parameters': {'records': records}}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            verified = [f for f in manifest['findings'] if f['operation'] == 'shared_factor']
            self.assertEqual({f['raw_preimage_hex'] for f in verified}, {'4142', '4344'})
            self.assertTrue(all(f['state'] == 'validated_transform' and f['artifact_id'] is None
                                for f in verified))
            self.assertEqual(manifest['coverage']['ENC07']['status'], 'ran')
            self.assertEqual(manifest['current_adapter_fingerprints']['rsa-literals'],
                             [next(j['tool_fingerprint'] for j in manifest['jobs']
                                   if j['adapter_id'] == 'rsa-literals')])
            manifest['current_adapter_fingerprints']['rsa-literals'] = []
            core._refresh_current(manifest, {a['id'] for a in manifest['artifacts'] if a['depth'] == 0})
            self.assertTrue(all(not f['current'] for f in manifest['findings']
                                if f['operation'] == 'shared_factor'))
            jobs = len([j for j in manifest['jobs'] if j['adapter_id'] == 'rsa-literals'])
            hints.write_text(json.dumps({'rsa_parameters': {'records': records},
                                         'flag_patterns': ['NEVER_MATCH_THIS']}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([j for j in resumed['jobs'] if j['adapter_id'] == 'rsa-literals']), jobs)
            self.assertTrue(all(f['current'] for f in resumed['findings'] if f['operation'] == 'shared_factor'))
            unrelated = [{'n': 101 * 113, 'e': 65537, 'c': 47},
                         {'n': 127 * 131, 'e': 65537, 'c': 53}]
            hints.write_text(json.dumps({'rsa_parameters': {'records': unrelated}}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(changed['coverage']['ENC07']['status'], 'no finding')
            self.assertTrue(all(not f['current'] for f in changed['findings']
                                if f['operation'] == 'shared_factor'))

    def test_rsa_public_key_pem_der_and_private_file_hints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'case.txt'
            source.write_text('Public RSA key is in private structured hints.')
            body = 'MB0wDQYJKoZIhvcNAQEBBQADDAAwCQIEBfhSPwIBAw=='
            pem = f'-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n'
            der = base64.b64decode(body)
            key_file = root / 'key.der'
            key_file.write_bytes(der)
            for record in ({'public_key_pem': pem, 'c': 123 ** 3},
                           {'public_key_der_hex': der.hex(), 'c': 123 ** 3},
                           {'key_file_index': 0, 'c': 123 ** 3}):
                with self.subTest(source=next(iter(record))):
                    hints = root / 'hints.json'
                    hints.write_text(json.dumps({'key_files': [str(key_file)],
                                                 'rsa_parameters': {'records': [record]}}))
                    run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                            '--hints', hints, '--runs-root', root / 'runs', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    self.assertTrue(any(f['current'] and f['operation'] == 'exact_low_exponent_root'
                                        and f['raw_preimage_hex'] == '7b' for f in manifest['findings']))
                    self.assertNotIn(body, (run / 'report.md').read_text())

    def test_declared_aes_respects_authentication_and_hint_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'case.txt'
            source.write_text('AES parameters are in private hints.')
            gcm = {'algorithm': 'AES', 'mode': 'GCM', 'key': '00' * 16,
                   'nonce': '00' * 12, 'ciphertext': '0388dace60b6a392f328c2b971b2fe78',
                   'tag': 'ab6e47d42cec13bdf53a67b21257bddf'}
            cbc = {'algorithm': 'AES', 'mode': 'CBC',
                   'key': '2b7e151628aed2a6abf7158809cf4f3c',
                   'iv': '000102030405060708090a0b0c0d0e0f',
                   'ciphertext': '7649abac8119b246cee98e9b12e9197d'}
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'symmetric_parameters': [gcm, cbc]}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            aes = [f for f in manifest['findings'] if f['operation'].startswith('aes_')]
            self.assertEqual({(f['operation'], f['state']) for f in aes},
                             {('aes_gcm', 'validated_transform'), ('aes_cbc', 'candidate')})
            self.assertEqual(next(f for f in aes if f['operation'] == 'aes_gcm')['raw_plaintext_hex'],
                             '00' * 16)
            self.assertEqual(manifest['coverage']['ENC08']['status'], 'ran')
            self.assertEqual(manifest['current_adapter_fingerprints']['aes-declared'],
                             [next(j['tool_fingerprint'] for j in manifest['jobs']
                                   if j['adapter_id'] == 'aes-declared')])
            manifest['current_adapter_fingerprints']['aes-declared'] = []
            core._refresh_current(manifest, {a['id'] for a in manifest['artifacts'] if a['depth'] == 0})
            self.assertTrue(all(not f['current'] for f in manifest['findings']
                                if f['operation'].startswith('aes_')))
            self.assertNotIn(gcm['key'], (run / 'report.md').read_text())
            count = len([j for j in manifest['jobs'] if j['adapter_id'] == 'aes-declared'])
            hints.write_text(json.dumps({'symmetric_parameters': [gcm, cbc],
                                         'flag_patterns': ['MISSING']}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len([j for j in resumed['jobs'] if j['adapter_id'] == 'aes-declared']), count)
            bad = {**gcm, 'tag': '00' * 16}
            hints.write_text(json.dumps({'symmetric_parameters': [bad, cbc]}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any(f['current'] and f['operation'] == 'aes_gcm'
                                 for f in changed['findings']))
            self.assertTrue(any(f['current'] and f['operation'] == 'aes_cbc'
                                for f in changed['findings']))

    def test_authenticated_aes_plaintext_enters_candidate_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'case.txt'
            source.write_text('Ciphertext and key are in private hints.')
            record = {'algorithm': 'AES', 'mode': 'GCM', 'key': '00' * 16,
                      'nonce': '00' * 12, 'ciphertext': '4fc998b507d5cecd8341b2dc1ddb901d8a9f',
                      'tag': '1cfb96c6dc782c5257233f5ad3ec37d8'}
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'symmetric_parameters': [record],
                                         'flag_patterns': [r'LAB\{[^}]+\}']}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in manifest['artifacts'] if a['source_locator'].get('authentication'))
            self.assertEqual(Path(child['path']).read_bytes(), b'LAB{gcm_pipeline}\n')
            self.assertEqual(child['source_locator']['symmetric_hint_index'], 0)
            self.assertTrue(any(f['current'] and f['artifact_id'] == child['id']
                                and f['operation'] == 'user pattern' for f in manifest['findings']))
            self.assertTrue(any(f['current'] and f['artifact_id'] == child['id']
                                and f['operation'] == 'aes_gcm' for f in manifest['findings']))

            hints.write_text(json.dumps({'symmetric_parameters': [{**record, 'tag': '00' * 16}],
                                         'flag_patterns': [r'LAB\{[^}]+\}']}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(next(a for a in changed['artifacts'] if a['id'] == child['id'])['current'])
            self.assertFalse(any(f['current'] and f['artifact_id'] == child['id']
                                 for f in changed['findings']))

    def test_zip_multiple_passwords_and_wrong_password_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'mixed.zip'
            source.write_bytes(MIXED_PASSWORD_ZIP)
            passwords = root / 'passwords.txt'
            passwords.write_text('one\ntwo\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(passwords)}))
            run = Path(self.run_cli('analyze', source, '--category', 'documents', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            members = {(a['source_locator'].get('member_index'), Path(a['path']).read_bytes())
                       for a in manifest['artifacts'] if a['depth'] > 0}
            self.assertEqual(members, {(0, b'first secret'), (1, b'second secret')})
            self.assertEqual(manifest['coverage']['DOC02']['status'], 'ran')

            passwords.write_text('wrong\n')
            self.run_cli('resume', run, '--hints', hints, code=3)
            wrong = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(wrong['coverage']['DOC02']['status'], 'skipped prerequisite')
            self.assertTrue(any('passwords did not validate' in warning for warning in wrong['warnings']))
            self.assertTrue(all(not a['current'] for a in wrong['artifacts']
                                if a['source_locator'].get('encrypted') is True))
            self.assertNotIn('first secret', (run / 'report.md').read_text())
            self.run_cli('resume', run, '--hints', hints, code=3)
            repeated = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(repeated['coverage']['DOC02']['status'], 'skipped prerequisite')
            self.assertTrue(any('passwords did not validate' in warning for warning in repeated['warnings']))

    def test_equal_zip_members_keep_both_occurrences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'equal.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('first', b'same bytes')
                archive.writestr('second', b'same bytes')
            run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            members = [a for a in manifest['artifacts'] if 'member_index' in a['source_locator']]
            self.assertEqual({a['source_locator']['member_index'] for a in members}, {0, 1})
            self.assertEqual(len({a['id'] for a in members}), 2)
            self.assertEqual(len({a['path'] for a in members}), 1)

    def test_resume_repairs_tampered_derived_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encoded'
            source.write_bytes(b'SEVMTE8=')
            run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                    '--runs-root', root / 'runs', code=3)['run'])
            initial = json.loads((run / 'manifest.json').read_text())
            child = next(a for a in initial['artifacts'] if a['depth'] > 0 and
                         Path(a['path']).read_bytes() == b'HELLO')
            Path(child['path']).write_bytes(b'EVIL!')
            self.run_cli('resume', run, code=3)
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(Path(child['path']).read_bytes(), b'HELLO')
            self.assertFalse(next(a for a in manifest['artifacts'] if a['id'] == child['id'])['complete'])
            self.assertTrue(any(a['complete'] and a['depth'] > 0 and a['sha256'] == child['sha256']
                                for a in manifest['artifacts']))
            self.assertTrue(any(job['status'] == 'invalidated' for job in manifest['jobs']))

    def test_png_to_zip_to_encoded_payload_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = b'Independent image chain oracle\x00\xff'
            archive_path = root / 'tail.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('payload', base64.b64encode(gzip.compress(oracle)))
            png = sample_png()
            source = root / 'challenge.dat'
            source.write_bytes(png + archive_path.read_bytes())
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['source_locator'].get('image_offset') == len(png)
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['source_locator'].get('archive_member') == 'payload'
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == oracle
                                for a in manifest['artifacts']))
            self.assertEqual(source.read_bytes(), original)
            for family in ('IMG01', 'DOC01', 'ENC01', 'ENC02'):
                self.assertEqual(manifest['coverage'][family]['status'], 'ran')

    def test_png_binary_gap_zip_child_is_current_after_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('oracle.bin', b'PNG_GAP_ORACLE\x00')
            png = sample_png()
            gap = b'CFG\xff\x00\x11'
            source = root / 'image.dat'
            original = png + gap + archive.getvalue()
            source.write_bytes(original)
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['current'] and a['source_locator'].get('image_offset') == len(png) + len(gap)
                                and a['source_locator'].get('iend_offset') == len(png) - 12
                                and a['source_locator'].get('gap_bytes') == len(gap)
                                and a['source_locator'].get('padding_bytes') == 0
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'PNG_GAP_ORACLE\x00'
                                for a in manifest['artifacts']))
            before = [j['id'] for j in manifest['jobs'] if j['adapter_id'] == 'image-tail']
            self.run_cli('resume', run, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual([j['id'] for j in resumed['jobs'] if j['adapter_id'] == 'image-tail'], before)
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'PNG_GAP_ORACLE\x00'
                                for a in resumed['artifacts']))
            self.assertEqual(source.read_bytes(), original)

    def test_png_gap_truncated_and_oversized_decoy_have_no_zip_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('oracle.bin', b'PNG_GAP_ORACLE')
            source = root / 'image.png'
            for index, tail in enumerate((b'CFG\xff' + archive.getvalue()[:-5],
                                          b'\x01PK\x03\x04' + b'J' * (core.MAX_CHILD + 1))):
                with self.subTest(index=index):
                    original = sample_png() + tail
                    source.write_bytes(original)
                    run = Path(self.run_cli('analyze', source, '--category', 'images',
                                            '--runs-root', root / f'runs-{index}', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    jobs = [j for j in manifest['jobs'] if j['adapter_id'] == 'image-tail']
                    self.assertEqual(len(jobs), 1)
                    self.assertEqual(jobs[0]['status'], 'complete')
                    self.assertEqual(jobs[0]['child_ids'], [])
                    self.assertFalse(any('trailing ZIP exceeds' in note for note in manifest['warnings']))
                    self.assertEqual(source.read_bytes(), original)

    def test_jpeg_padded_zip_tail_reaches_archive_member_without_changing_source(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer = io.BytesIO()
            Image.new('RGB', (2, 2), (20, 80, 140)).save(buffer, format='JPEG')
            jpeg = buffer.getvalue()
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('oracle.bin', b'JPEG_TAIL_ORACLE\x00\xff')
            padding = b'\x00\x00\n'
            source = root / 'image.dat'
            original = jpeg + padding + archive.getvalue()
            source.write_bytes(original)
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['depth'] > 0 and a['current']
                                and Path(a['path']).read_bytes() == b'JPEG_TAIL_ORACLE\x00\xff'
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['current'] and a['source_locator'].get('image_offset') == len(jpeg) + len(padding)
                                and a['source_locator'].get('eoi_offset') == len(jpeg) - 2
                                for a in manifest['artifacts']))
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'ran')
            self.assertEqual(manifest['coverage']['DOC01']['status'], 'ran')
            self.assertEqual(source.read_bytes(), original)
            before = [job['id'] for job in manifest['jobs'] if job['adapter_id'] == 'image-tail']
            self.run_cli('resume', run, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual([job['id'] for job in resumed['jobs'] if job['adapter_id'] == 'image-tail'], before)
            self.assertTrue(any(a['depth'] > 0 and a['current']
                                and Path(a['path']).read_bytes() == b'JPEG_TAIL_ORACLE\x00\xff'
                                for a in resumed['artifacts']))
            self.assertEqual(source.read_bytes(), original)

    def test_jpeg_truncated_or_corrupt_appended_zip_produces_no_archive_child(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer = io.BytesIO()
            Image.new('RGB', (2, 2), (20, 80, 140)).save(buffer, format='JPEG')
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as writer:
                writer.writestr('oracle.bin', b'JPEG_TAIL_ORACLE')
            source = root / 'image.dat'
            corrupt = bytearray(archive.getvalue())
            corrupt[corrupt.index(b'JPEG_TAIL_ORACLE')] ^= 1
            fake_jpeg = bytes.fromhex('ffd8 ffc0 0008 080001000101 ffda 0006 01010000 ffd9')
            for index, data in enumerate((buffer.getvalue() + b'\x00' + archive.getvalue()[:-5],
                                          buffer.getvalue() + b'\x01PK\x03\x04decoy' + archive.getvalue()[:-5],
                                          buffer.getvalue() + b'\x01PK\x03\x04random',
                                          buffer.getvalue() + b'\x00' + bytes(corrupt),
                                          fake_jpeg + archive.getvalue())):
                with self.subTest(index=index):
                    source.write_bytes(data)
                    run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                            '--runs-root', root / f'runs-{index}', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    self.assertFalse(any(a['source_locator'].get('image_offset') is not None
                                         for a in manifest['artifacts']))

    def test_jpeg_binary_gap_zip_child_is_current_after_resume(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jpeg = io.BytesIO()
            Image.new('RGB', (2, 2), (20, 80, 140)).save(jpeg, format='JPEG')
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('oracle.bin', b'BINARY_GAP_ORACLE\x00')
            gap = b'CFG\xff\x00\x11'
            source = root / 'image.dat'
            original = jpeg.getvalue() + gap + archive.getvalue()
            source.write_bytes(original)
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['current'] and a['source_locator'].get('image_offset') == len(jpeg.getvalue()) + len(gap)
                                and a['source_locator'].get('eoi_offset') == len(jpeg.getvalue()) - 2
                                and a['source_locator'].get('gap_bytes') == len(gap)
                                and a['source_locator'].get('padding_bytes') == 0
                                for a in manifest['artifacts']))
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'BINARY_GAP_ORACLE\x00'
                                for a in manifest['artifacts']))
            before = [j['id'] for j in manifest['jobs'] if j['adapter_id'] == 'image-tail']
            self.run_cli('resume', run, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual([j['id'] for j in resumed['jobs'] if j['adapter_id'] == 'image-tail'], before)
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'BINARY_GAP_ORACLE\x00'
                                for a in resumed['artifacts']))
            self.assertEqual(source.read_bytes(), original)

    def test_jpeg_oversized_decoy_is_no_finding_and_real_zip_is_truncated(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jpeg = io.BytesIO()
            Image.new('RGB', (2, 2), (20, 80, 140)).save(jpeg, format='JPEG')
            source = root / 'image.jpg'
            original = jpeg.getvalue() + b'\x01PK\x03\x04' + b'J' * (core.MAX_CHILD + 1)
            source.write_bytes(original)
            run = Path(self.run_cli('analyze', source, '--category', 'images',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            jobs = [j for j in manifest['jobs'] if j['adapter_id'] == 'image-tail']
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]['status'], 'complete')
            self.assertEqual(jobs[0]['child_ids'], [])
            self.assertFalse(any('trailing ZIP exceeds' in note for note in manifest['warnings']))
            self.assertEqual(source.read_bytes(), original)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as writer:
                writer.writestr('large.bin', b'A' * (core.MAX_CHILD + 1))
            real = jpeg.getvalue() + b'\x01' + archive.getvalue()
            source.write_bytes(real)
            run = Path(self.run_cli('analyze', source, '--category', 'images',
                                    '--runs-root', root / 'real-runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'truncated')
            self.assertTrue(any('JPEG trailing ZIP exceeds' in note for note in manifest['warnings']))
            self.assertEqual(source.read_bytes(), real)

    def test_jpeg_expanded_zip_limit_is_truncated(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the JPEG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jpeg = io.BytesIO()
            Image.new('RGB', (2, 2), (20, 80, 140)).save(jpeg, format='JPEG')
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as writer:
                writer.writestr('large.bin', b'A' * (core.MAX_CHILD + 1))
            source = root / 'image.jpg'
            source.write_bytes(jpeg.getvalue() + archive.getvalue())
            run = Path(self.run_cli('analyze', source, '--category', 'images',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'truncated')
            self.assertTrue(any('ZIP member bytes exceed' in note for note in manifest['warnings']))
            self.assertFalse(any(a['source_locator'].get('image_offset') is not None
                                 for a in manifest['artifacts']))

    def test_image_zip_mime_compressed_encoding_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = b'Cross-category oracle\x00\xff\n'
            message = EmailMessage()
            message.set_content('Artifact attached.')
            message.add_attachment(base64.b64encode(gzip.compress(oracle)),
                                   maintype='application', subtype='octet-stream',
                                   filename='blob.dat')
            archive_path = root / 'tail.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('letter.eml', message.as_bytes())
            source = root / 'image.dat'
            source.write_bytes(sample_png() + b'\x01CFG' + archive_path.read_bytes())
            run = Path(self.run_cli('analyze', source, '--category', 'auto',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            recovered = [a for a in manifest['artifacts'] if a['depth'] > 0
                         and Path(a['path']).read_bytes() == oracle]
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0]['depth'], 5)
            for family in ('IMG01', 'DOC01', 'DOC06', 'ENC01', 'ENC02'):
                self.assertEqual(manifest['coverage'][family]['status'], 'ran')

    def test_image_metadata_views_and_osint_tags_through_cli(self):
        source = Path(__file__).resolve().parents[1] / 'examples/core/carrier.png'
        original = source.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image_run = Path(self.run_cli('analyze', source, '--category', 'images',
                                          '--runs-root', root / 'runs', code=3)['run'])
            image = json.loads((image_run / 'manifest.json').read_text())
            previews = [a for a in image['artifacts'] if a['source_locator'].get('preview')]
            self.assertTrue(previews)
            self.assertTrue(all(a['source_locator']['channel'] for a in previews))
            self.assertTrue(image['intelligence'])
            self.assertEqual(image['coverage']['IMG04']['status'], 'ran')
            osint_run = Path(self.run_cli('analyze', source, '--category', 'osint',
                                          '--runs-root', root / 'runs', code=3)['run'])
            osint = json.loads((osint_run / 'manifest.json').read_text())
            self.assertTrue(osint['intelligence'])
            self.assertEqual(osint['coverage']['OS01']['status'], 'ran')
            self.assertFalse(any(a['source_locator'].get('preview') for a in osint['artifacts']))
        self.assertEqual(source.read_bytes(), original)

    def test_osint_metadata_interpretation_keeps_source_and_resume_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'metadata.jpg'
            from PIL import Image
            Image.new('RGB', (2, 2), 'red').save(source)
            subprocess.run(['/usr/bin/exiftool', '-overwrite_original',
                            '-GPSLatitude=12.345678', '-GPSLatitudeRef=S',
                            '-GPSLongitude=103.456789', '-GPSLongitudeRef=E',
                            '-DateTimeOriginal=2022:01:02 03:04:05',
                            '-OffsetTimeOriginal=+07:00',
                            '-XMP:DateCreated=2033:06:07 08:09:10+09:00', str(source)],
                           check=True, capture_output=True)
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'osint',
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            rows = [row for row in before['intelligence'] if row['artifact_id'] ==
                    before['artifacts'][0]['id'] and row['current']]
            raw = next(row for row in rows if row['source_locator'].get('exif_tag') ==
                       'GPS:Copy1:GPSLatitude')
            signed = next(row for row in rows if row['source_locator'].get('exif_tag') ==
                          'Composite:GPSLatitude')
            self.assertEqual((raw['value'], signed['value']), ('12.345678', '-12.345678'))
            self.assertIn('unsigned magnitude', raw['interpretation'])
            self.assertIn('hemisphere-signed', signed['interpretation'])
            report = (run / 'report.md').read_text()
            for term in ('unsigned magnitude', 'hemisphere-signed',
                         'capture-time fields conflict', '+07:00'):
                self.assertIn(term, report)
            self.assertNotIn('location:', report.lower())
            self.run_cli('resume', run, code=3)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len(after['intelligence']), len(before['intelligence']))
            self.assertEqual(source.read_bytes(), original)

            subprocess.run(['/usr/bin/exiftool', '-overwrite_original',
                            '-DateTimeOriginal=2033:06:07 08:09:10',
                            '-OffsetTimeOriginal=+09:00', str(source)],
                           check=True, capture_output=True)
            self.run_cli('resume', run, code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(all(not row['current'] for row in changed['intelligence']
                                if row['artifact_id'] == before['artifacts'][0]['id']))
            self.assertNotIn('capture-time fields conflict', (run / 'report.md').read_text())

    def test_osint_metadata_does_not_trust_partial_gps_or_invalid_timezone(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, arguments, source_tag, expected in (
                ('one-ref', ('-GPSLatitude=12.345678', '-GPSLatitudeRef=S',
                             '-GPSLongitude=103.456789'), 'Composite:GPSPosition',
                 'incomplete hemisphere references'),
                ('bad-offset', ('-DateTimeOriginal=2022:01:02 03:04:05',
                                '-OffsetTimeOriginal=+25:00'),
                 'ExifIFD:DateTimeOriginal', 'invalid OffsetTimeOriginal'),
            ):
                source = root / f'{name}.jpg'
                Image.new('RGB', (2, 2), 'red').save(source)
                subprocess.run(['/usr/bin/exiftool', '-overwrite_original',
                                *arguments, str(source)], check=True, capture_output=True)
                run = Path(self.run_cli('analyze', source, '--category', 'osint',
                                        '--runs-root', root / name, code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                row = next(item for item in manifest['intelligence'] if
                           item['current'] and item['source_locator'].get('exif_tag') == source_tag)
                self.assertIn(expected, row['interpretation'])
                self.assertIn(expected, (run / 'report.md').read_text())
                self.assertEqual(manifest['coverage']['OS01']['status'], 'ran')

    @unittest.skipUnless(shutil.which('gcc'), 'gcc is unavailable')
    def test_checker_cli_requires_explicit_execution_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, binary, hints = self.checker_fixture(root)
            no_gate = self.run_cli('analyze', binary, '--category', 'reversing',
                                   '--hints', hints, '--runs-root', root / 'runs',
                                   '--budget', '45', code=3)
            manifest = json.loads((Path(no_gate['run']) / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['REV07']['status'], 'skipped prerequisite')
            self.assertFalse(any(job['adapter_id'] == 'checker' for job in manifest['jobs']))
            self.assertFalse(any(f['state'] == 'validated_input' for f in manifest['findings']))
            self.assertEqual(self.run_cli('analyze', binary, '--category', 'reversing',
                                          '--hints', hints, '--replay-checker',
                                          '--runs-root', root / 'other', code=2)['status'], 'invalid_input')

    @unittest.skipUnless(shutil.which('gcc') and ANGR_IMPORT_READY,
                         'gcc and an importable angr are needed for REV07 solving')
    def test_checker_cli_execution_gate_replay_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary, hints = self.checker_fixture(root)

            result = self.run_cli('analyze', binary, '--category', 'reversing',
                                  '--hints', hints, '--execute-local', '--runs-root',
                                  root / 'runs', '--budget', '45', code=3)
            run = Path(result['run'])
            candidate = json.loads((run / 'manifest.json').read_text())
            jobs = [job for job in candidate['jobs'] if job['adapter_id'] == 'checker']
            self.assertEqual(len(jobs), 1)
            report = json.loads(Path(jobs[0]['report_path']).read_text())
            self.assertEqual(report['status'], 'candidate', report)
            self.assertEqual(bytes.fromhex(report['candidate_hex']), b'R7')
            self.assertFalse(report['replay']['attempted'])
            self.assertTrue(any(f['state'] == 'candidate' and f['job_id'] == jobs[0]['id']
                                for f in candidate['findings']))
            self.assertFalse(any(f['state'] == 'validated_input' for f in candidate['findings']))

            self.run_cli('resume', run, '--hints', hints, '--replay-checker',
                         '--budget', '45', code=3)
            replayed = json.loads((run / 'manifest.json').read_text())
            replay_jobs = [job for job in replayed['jobs'] if job['adapter_id'] == 'checker'
                           and job.get('replay_requested')]
            self.assertEqual(len(replay_jobs), 1)
            replay_report = json.loads(Path(replay_jobs[0]['report_path']).read_text())
            self.assertEqual(replay_report['status'], 'validated_input', replay_report)
            self.assertEqual(replay_report['replay']['returncode'], 0)
            self.assertTrue(any(f['state'] == 'validated_input' and f['current']
                                for f in replayed['findings']))
            self.assertFalse(any(f['state'] == 'challenge_accepted'
                                 for f in replayed['findings']))
            before = len(replayed['jobs'])
            self.run_cli('resume', run, '--hints', hints, '--budget', '45', code=3)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(len(after['jobs']), before)
            self.assertTrue(any(f['state'] == 'validated_input' and f['current']
                                for f in after['findings']))

            source.write_text(source.read_text().replace("== 'R'", "== 'X'"))
            subprocess.run(['gcc', '-O0', '-fno-pie', '-no-pie', '-o', str(binary), str(source)],
                           check=True, capture_output=True)
            self.run_cli('resume', run, '--hints', hints, '--budget', '45', code=3)
            changed = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(any(f['state'] == 'validated_input' and f['current']
                                 for f in changed['findings']))
            self.assertTrue(any(f['state'] == 'candidate' and f['current'] and
                                f['evidence'].endswith(b'X7'.hex())
                                for f in changed['findings']))

    def test_missing_exiftool_does_not_truncate_completed_channel_views(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'image.png'
            source.write_bytes(sample_png())
            command = [sys.executable, '-B', str(SCRIPT), '--json', 'analyze', str(source),
                       '--category', 'images', '--runs-root', str(root / 'runs')]
            result = subprocess.run(command, capture_output=True, timeout=15,
                                    env={**os.environ, 'AUTOSOLVE_EXIFTOOL': '/nonexistent'})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            run = Path(json.loads(result.stdout)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['IMG04']['status'], 'ran')
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'truncated')
            self.assertTrue(any(a['source_locator'].get('preview') for a in manifest['artifacts']))

    def test_oversized_png_zip_is_truncated_not_no_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / 'large.zip'
            with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_STORED) as archive:
                archive.writestr('large', b'A' * (16 * 1024 * 1024))
            source = root / 'input.png'
            source.write_bytes(sample_png() + archive_path.read_bytes())
            run = Path(self.run_cli('analyze', source, '--category', 'images',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'truncated')
            self.assertEqual(manifest['coverage']['IMG02']['status'], 'truncated')
            self.assertTrue(any('trailing ZIP exceeds' in warning for warning in manifest['warnings']))
            self.assertFalse(any('image_offset' in a['source_locator']
                                 for a in manifest['artifacts']))

    def test_animated_png_preview_limit_preserves_appended_zip_chain(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is needed to author the APNG fixture')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frames = [Image.new('RGBA', (2, 2), (index * 30, 10, 20, 255))
                      for index in range(8)]
            source = root / 'animated.png'
            frames[0].save(source, save_all=True, append_images=frames[1:],
                           duration=[100] * 8, format='PNG')
            archive = root / 'tail.zip'
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('payload.txt', b'X01_ORACLE')
            source.write_bytes(source.read_bytes() + archive.read_bytes())
            original = source.read_bytes()
            run = Path(self.run_cli('analyze', source, '--category', 'auto', '--budget', '50',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(a['depth'] > 0 and Path(a['path']).read_bytes() == b'X01_ORACLE'
                                for a in manifest['artifacts']))
            self.assertLessEqual(sum(a['source_locator'].get('preview', False)
                                     for a in manifest['artifacts']), 32)
            self.assertEqual(manifest['coverage']['DOC01']['status'], 'ran')
            self.assertEqual(manifest['coverage']['IMG04']['status'], 'truncated')
            self.assertTrue(any('artifact capacity reserved' in note for note in manifest['warnings']))
            self.assertEqual(source.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
