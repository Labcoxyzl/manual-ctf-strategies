"""Public CLI checks for run identity, provenance, and honest partial results."""

import base64
import fcntl
import gzip
import hashlib
import io
import json
import lzma
import mmap
import multiprocessing
import os
import struct
import sqlite3
import shutil
from email.message import EmailMessage
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

from test_autosolve_documents import ENCRYPTED_ZIP
from test_autosolve_pdf import handwritten_pdf
from test_autosolve_checker import ANGR_IMPORT_READY
from test_autosolve_images import sample_png
from test_autosolve_packet_objects import (pcap as object_pcap, transaction as http_transaction,
                                           complete_transfer, frame as tcp_frame)
from test_autosolve_packets import ipv4, udp
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


def _delayed_worker_entry(*args):
    time.sleep(5)


class AutosolveCoreTests(unittest.TestCase):
    def test_declared_classical_cli_recovers_exact_candidates(self):
        cases = (
            (b'Avfb th kim hzu czbrxf iyhvs anbjfb.',
             {'family': 'vigenere', 'key': 'ORBIT'}, b'Meet at the old bridge after sunset.'),
            (b'Bgel p mi.rn h ivrcmasa ingtitseostdh',
             {'family': 'rail_fence', 'rails': 3}, b'Bring the silver compass at midnight.'),
        )
        for wire, parameter, expected in cases:
            with self.subTest(family=parameter['family']), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'cipher.txt'
                source.write_bytes(wire)
                hints = root / 'hints.json'
                hints.write_text(json.dumps({'classical_parameters': [parameter]}))
                run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                exact = [a for a in manifest['artifacts'] if a['depth'] > 0 and
                         Path(a['path']).read_bytes() == expected and
                         any(edge['operation'].startswith(parameter['family'] + ':')
                             for edge in a['parents'])]
                self.assertEqual(len(exact), 1)
                self.assertEqual(manifest['coverage']['ENC04']['status'], 'ran')
                self.assertFalse(any(f['state'] == 'challenge_accepted' for f in manifest['findings']))

    def test_classical_missing_and_bad_parameters_keep_honest_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'cipher.txt'
            source.write_bytes(b'IEMYMVXSZOKATAMKMWGJMRKFFHXTMP')
            hints = root / 'hints.json'
            for parameter in ({'family': 'vigenere'}, {'family': 'rail_fence'}):
                hints.write_text(json.dumps({'classical_parameters': [parameter]}))
                run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                self.assertEqual(manifest['coverage']['ENC04']['status'], 'skipped prerequisite')
                self.assertFalse(any(f['state'] == 'challenge_accepted' for f in manifest['findings']))
            for parameter in ({'family': 'vigenere', 'key': ''},
                              {'family': 'vigenere', 'key': 'é'},
                              {'family': 'rail_fence', 'rails': True},
                              {'family': 'rail_fence', 'rails': 1},
                              {'family': 'beaufort', 'key': 'CEDAR'}):
                hints.write_text(json.dumps({'classical_parameters': [parameter]}))
                self.assertEqual(self.run_cli('analyze', source, '--category', 'encoding',
                                              '--hints', hints, '--runs-root', root / 'runs',
                                              code=2)['status'], 'invalid_input')

    def test_classical_changed_key_retires_old_plaintext_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'cipher.txt'
            source.write_bytes(b'Avfb th kim hzu czbrxf iyhvs anbjfb.')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'classical_parameters': [
                {'family': 'vigenere', 'key': 'ORBIT'}]}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            before = json.loads((run / 'manifest.json').read_text())
            old = next(a for a in before['artifacts'] if a['depth'] > 0 and
                       Path(a['path']).read_bytes() == b'Meet at the old bridge after sunset.')
            hints.write_text(json.dumps({'classical_parameters': [
                {'family': 'vigenere', 'key': 'COBRA'}]}))
            self.run_cli('resume', run, '--hints', hints, code=3)
            after = json.loads((run / 'manifest.json').read_text())
            self.assertFalse(next(a for a in after['artifacts'] if a['id'] == old['id'])['current'])
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                any(edge['operation'].startswith('vigenere:') for edge in a['parents'])
                                for a in after['artifacts']))

    def test_declared_key_without_transformable_letters_is_no_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'digits.txt'
            source.write_bytes(b'12345')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'classical_parameters': [
                {'family': 'vigenere', 'key': 'ORBIT'}]}))
            run = Path(self.run_cli('analyze', source, '--category', 'encoding', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['ENC04']['status'], 'no finding')

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

    def test_report_counts_current_findings_omitted_after_fifty(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            findings = [{'state': 'candidate', 'current': True, 'artifact_id': f'a{index}',
                         'source_locator': {},
                         'evidence': f'safe finding {index}' if index < 50
                         else f'PRIVATE_OMITTED_{index}'} for index in range(52)]
            findings.append({'state': 'candidate', 'current': False,
                             'artifact_id': 'old', 'source_locator': {},
                             'evidence': 'PRIVATE_HISTORICAL'})
            manifest = {'schema_version': core.SCHEMA, 'status': 'partial',
                        'findings': findings, 'artifacts': [], 'intelligence': [],
                        'warnings': [], 'coverage': {}}
            (run / 'manifest.json').write_text(json.dumps(manifest))
            core.report(run)
            report = (run / 'report.md').read_text()
            self.assertIn('safe finding 0', report)
            self.assertIn('safe finding 49', report)
            self.assertIn('2 more current finding(s) omitted', report)
            self.assertIn(f'`{run / "manifest.json"}` (`findings` array)', report)
            self.assertFalse((run / 'findings.json').exists())
            self.assertNotIn('PRIVATE_OMITTED', report)
            self.assertNotIn('PRIVATE_HISTORICAL', report)

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

    def test_mime_timeout_during_spawn_startup_stops_worker_promptly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'message.eml'
            source.write_bytes(b'MIME-Version: 1.0\nContent-Type: text/plain\n\nhello')
            before = {child.pid for child in multiprocessing.active_children()}
            started = time.monotonic()
            with patch.object(core, '_worker_entry', _delayed_worker_entry):
                with self.assertRaises(TimeoutError):
                    core._run_mime(source, root / 'staging', 8, 1024, .001)
            self.assertLess(time.monotonic() - started, 3)
            self.assertFalse({child.pid for child in multiprocessing.active_children()} - before)

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

    def test_encoding_worker_error_updates_family_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.txt'
            source.write_bytes(b'SEVMTE8=')
            for error, expected in ((core.WorkLimit('stored artifact identity incomplete'),
                                     'truncated'),
                                    (TimeoutError('encoding operation exceeded its time limit'),
                                     'truncated'),
                                    (RuntimeError('decoder broke'), 'failed')):
                with self.subTest(expected=expected), patch.object(core, '_run_decode', side_effect=error):
                    run, _ = core.analyze(source, category='encoding', budget=5,
                                          runs_root=root / expected)
                manifest = json.loads((run / 'manifest.json').read_text())
                job = next(item for item in manifest['jobs'] if item['adapter_id'] == 'encoding')
                self.assertEqual(job['status'], expected)
                for family in ('ENC01', 'ENC02', 'ENC03'):
                    self.assertEqual(manifest['coverage'][family]['status'], expected)
                    self.assertIn(str(error), manifest['coverage'][family]['note'])

    def test_zip_worker_error_updates_both_document_families(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('evidence.txt', b'ZIP_CONTROL')
            for error, expected in ((TimeoutError('ZIP extraction exceeded its time limit'),
                                     'truncated'),
                                    (RuntimeError('extractor broke'), 'failed')):
                with self.subTest(expected=expected), patch.object(core, '_run_zip', side_effect=error):
                    run, _ = core.analyze(source, category='documents', budget=5,
                                          runs_root=root / expected)
                manifest = json.loads((run / 'manifest.json').read_text())
                job = next(item for item in manifest['jobs'] if item['adapter_id'] == 'zip')
                self.assertEqual(job['status'], expected)
                for family in ('DOC01', 'DOC02'):
                    self.assertEqual(manifest['coverage'][family]['status'], expected)

    def test_compressed_tar_decode_error_updates_encoding_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.tar.gz'
            with tarfile.open(source, 'w:gz') as archive:
                data = b'TAR_CONTROL'
                member = tarfile.TarInfo('evidence.txt')
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            with patch.object(core, '_run_decode', side_effect=TimeoutError('decode time limit')), \
                 patch.object(core, '_run_tar', return_value=([], [])):
                run, _ = core.analyze(source, category='auto', budget=5,
                                      runs_root=root / 'runs')
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(item for item in manifest['jobs']
                       if item['adapter_id'] == 'encoding' and 'TAR' in item['operation'])
            self.assertEqual(job['status'], 'truncated')
            self.assertEqual(manifest['coverage']['DOC01']['status'], 'truncated')
            self.assertEqual(manifest['coverage']['ENC02']['status'], 'truncated')
            self.assertIn('decode time limit', manifest['coverage']['ENC02']['note'])

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
            source = root / 'challenge'
            source.write_bytes(b'challenge')
            run = root / 'run'
            manifest = {'input_path': str(source), 'jobs': [],
                        'private_hint_paths': [], 'private_hint_identities': []}
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

    def test_zip_publication_distinguishes_expired_identity_from_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('payload', b'ZIP_IDENTITY_CONTROL')
            original = source.read_bytes()
            real_hash, real_run_zip = core._hash, core._run_zip
            for identity, expected in (('expired', 'truncated'), ('changed', 'failed'),
                                       ('matching', 'complete')):
                with self.subTest(identity=identity):
                    source.write_bytes(original)
                    extracted = False

                    def run_zip(*args):
                        nonlocal extracted
                        result = real_run_zip(*args)
                        extracted = True
                        if identity == 'changed':
                            source.write_bytes(original + b'changed after extraction')
                        return result

                    def source_hash(path, deadline):
                        if extracted and Path(path) == source and identity == 'expired':
                            return None
                        return real_hash(path, deadline)

                    with patch.object(core, '_run_zip', side_effect=run_zip), \
                         patch.object(core, '_hash', side_effect=source_hash):
                        run, _ = core.analyze(source, category='documents', budget=3,
                                              runs_root=root / 'runs')
                    manifest = json.loads((run / 'manifest.json').read_text())
                    job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'zip')
                    self.assertEqual(job['status'], expected)
                    self.assertEqual(manifest['coverage']['DOC01']['status'],
                                     'ran' if identity == 'matching'
                                     else expected)
                    self.assertEqual(bool(job['child_ids']), expected == 'complete')
                    self.assertEqual(source.read_bytes() == original, identity != 'changed')
                    if identity == 'expired':
                        self.assertIn('identity incomplete', job['warning'])
                        self.assertNotIn('changed', job['warning'])
                        self.assertEqual(manifest['coverage']['DOC02']['status'], 'truncated')
                    elif expected == 'failed':
                        self.assertIn('archive changed', job['warning'])

    def test_encrypted_zip_identity_expiry_marks_both_document_families_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encrypted.zip'
            source.write_bytes(ENCRYPTED_ZIP)
            password = root / 'passwords.txt'
            password.write_text('correct horse\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': password.name}))
            real_hash, real_run_zip = core._hash, core._run_zip
            extracted = False

            def run_zip(*args):
                nonlocal extracted
                result = real_run_zip(*args)
                extracted = True
                return result

            def source_hash(path, deadline):
                if extracted and Path(path) == source:
                    return None
                return real_hash(path, deadline)

            with patch.object(core, '_run_zip', side_effect=run_zip), \
                 patch.object(core, '_hash', side_effect=source_hash):
                run, _ = core.analyze(source, category='documents', hints_path=hints,
                                      budget=3, runs_root=root / 'runs')
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'zip')
            self.assertTrue(extracted)
            self.assertEqual(job['status'], 'truncated')
            self.assertFalse(job['child_ids'])
            self.assertEqual(manifest['coverage']['DOC01']['status'], 'truncated')
            self.assertEqual(manifest['coverage']['DOC02']['status'], 'truncated')
            self.assertIn('identity incomplete', job['warning'])

    def test_image_tail_identity_expiry_has_neutral_coverage_note(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('payload.txt', b'IMAGE_TAIL_ORACLE')
            source = root / 'image.png'
            source.write_bytes(sample_png() + archive.getvalue())
            real_hash, real_run_image = core._hash, core._run_image
            inspected = False

            def run_image(*args):
                nonlocal inspected
                result = real_run_image(*args)
                inspected = True
                return result

            def source_hash(path, deadline):
                if inspected and Path(path) == source:
                    return None
                return real_hash(path, deadline)

            with patch.object(core, '_run_image', side_effect=run_image), \
                 patch.object(core, '_hash', side_effect=source_hash):
                run, _ = core.analyze(source, category='images', budget=3,
                                      runs_root=root / 'runs')
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'image-tail')
            self.assertTrue(inspected)
            self.assertEqual(job['status'], 'truncated')
            self.assertFalse(job['child_ids'])
            self.assertEqual(manifest['coverage']['IMG01']['status'], 'truncated')
            self.assertIn('identity incomplete', manifest['coverage']['IMG01']['note'])
            self.assertNotIn('exceeds output bound', manifest['coverage']['IMG01']['note'])

    def test_nullable_identity_never_reuses_child_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'child'
            path.write_bytes(b'cached bytes')
            child = {'id': 'child', 'sha256': None, 'path': str(path),
                     'complete': True, 'current': True, 'parents': []}
            manifest = {'artifacts': [child], 'warnings': []}
            job = {'id': 'cache-job', 'child_ids': ['child'], 'input_ids': [], 'key': 'cache'}
            with patch.object(core, '_hash', return_value=None):
                self.assertIsNone(core._reusable_children(manifest, job, time.monotonic() + 1))
            self.assertFalse(child['complete'])
            child['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            child['complete'] = child['current'] = True
            manifest['warnings'].clear()
            with patch.object(core, '_hash', return_value=None):
                self.assertIsNone(core._reusable_children(manifest, job, time.monotonic() + 1))
            self.assertTrue(child['complete'])
            self.assertTrue(child['current'])
            self.assertIn('identity incomplete', manifest['warnings'][0])

            source = Path(directory) / 'clue.txt'
            source.write_text('See https://example.org/evidence')
            run, _ = core.analyze(source, category='osint', budget=3,
                                  runs_root=Path(directory) / 'runs')
            stored = json.loads((run / 'manifest.json').read_text())
            old = next(item for item in stored['jobs'] if item['adapter_id'] == 'osint-ids')
            old['records_sha256'] = None
            (run / 'manifest.json').write_text(json.dumps(stored))

            def output_hash(path, deadline):
                if str(path).endswith('.osint-ids.json'):
                    return None
                return real_hash(path, deadline)

            real_hash = core._hash
            with patch.object(core, '_hash', side_effect=output_hash):
                core.resume(run, budget=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            jobs = [item for item in resumed['jobs'] if item['adapter_id'] == 'osint-ids']
            self.assertEqual(len(jobs), 2)
            self.assertEqual(jobs[0]['status'], 'invalidated')
            self.assertEqual(jobs[1]['status'], 'truncated')
            self.assertFalse(any(row['job_id'] == jobs[0]['id'] and row['current']
                                 for row in resumed['intelligence']))

    def test_expired_child_cache_invalidates_only_affected_job_and_runs_mime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / 'inputs'
            inputs.mkdir()
            source = inputs / 'bundle.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('flag.txt', b'FLAG{CACHE_RESUME_ORACLE}')
            run, _ = core.analyze(inputs, category='documents', budget=3,
                                  runs_root=root / 'runs')
            first = json.loads((run / 'manifest.json').read_text())
            old = next(item for item in first['jobs'] if item['adapter_id'] == 'zip')
            child = next(item for item in first['artifacts'] if item['id'] in old['child_ids'])
            message = EmailMessage()
            message.set_content('A separate ready job.')
            message.add_attachment(b'MIME_READY', maintype='application',
                                   subtype='octet-stream', filename='ready.bin')
            (inputs / 'note.eml').write_bytes(message.as_bytes())
            real_hash = core._hash
            expired = False

            def child_hash(path, deadline):
                nonlocal expired
                if Path(path) == Path(child['path']):
                    expired = True
                    return None
                return real_hash(path, deadline)

            with patch.object(core, '_hash', side_effect=child_hash):
                core.resume(run, budget=3)
            self.assertTrue(expired)
            partial = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(next(j for j in partial['jobs'] if j['id'] == old['id'])['status'],
                             'invalidated')
            self.assertTrue(next(a for a in partial['artifacts'] if a['id'] == child['id'])['complete'])
            self.assertFalse(next(a for a in partial['artifacts'] if a['id'] == child['id'])['current'])
            self.assertFalse(any(f['artifact_id'] == child['id'] and f['current']
                                 for f in partial['findings']))
            self.assertNotIn(child['path'], (run / 'report.md').read_text())
            self.assertTrue(any('identity incomplete' in warning and 'changed' not in warning
                                for warning in partial['warnings']))
            mime = next(j for j in partial['jobs'] if j['adapter_id'] == 'mime')
            self.assertEqual(mime['status'], 'complete')
            self.assertTrue(any(a['current'] and a['id'] in mime['child_ids'] and
                                Path(a['path']).read_bytes() == b'MIME_READY'
                                for a in partial['artifacts']))

            core.resume(run, budget=3)
            fresh = json.loads((run / 'manifest.json').read_text())
            self.assertTrue(any(j['adapter_id'] == 'zip' and j['id'] != old['id'] and
                                j['status'] == 'complete' for j in fresh['jobs']))
            self.assertTrue(any(a['current'] and a['depth'] > 0 and
                                Path(a['path']).read_bytes() == b'FLAG{CACHE_RESUME_ORACLE}'
                                for a in fresh['artifacts']))

    def test_mime_worker_handles_large_parent_address_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'message.eml'
            payload = b'MIME_MAP_ORACLE' + b'X' * (4 * 1024 * 1024)
            message = EmailMessage()
            message.set_content('See attached evidence.')
            message.add_attachment(payload, maintype='application',
                                   subtype='octet-stream', filename='evidence.bin')
            source.write_bytes(message.as_bytes())
            original = source.read_bytes()
            with mmap.mmap(-1, 1024**3):
                records, warnings = core._run_mime(source, root / 'staging', 8, 6 * 1024 * 1024, 10)
            self.assertEqual(warnings, [])
            self.assertTrue(any(Path(record['path']).read_bytes() == payload
                                for record in records))
            self.assertEqual(source.read_bytes(), original)

    def test_candidate_scan_with_expired_source_identity_publishes_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'large.bin'
            with source.open('wb') as stream:
                stream.truncate(core.MAX_READ + 1)
            artifact = {'id': 'sample', 'path': str(source),
                        'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'current': True}
            manifest = {'findings': [], 'warnings': [], 'candidate_pattern_sha256': 'pattern'}
            finding = {'state': 'candidate', 'artifact_id': 'sample', 'operation': 'user pattern'}
            with patch.object(core, 'scan_candidates', return_value=([finding], [])), \
                 patch.object(core, '_hash', return_value=None):
                core._scan_artifact(manifest, artifact, time.monotonic() + 1, [])
            self.assertFalse(manifest['findings'])
            self.assertIn('identity incomplete', manifest['warnings'][0])

    def test_sqlite_invalidated_cache_new_failure_keeps_failed_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'evidence.db'
            with sqlite3.connect(source) as connection:
                connection.execute('CREATE TABLE notes (value TEXT)')
                connection.execute('INSERT INTO notes VALUES (?)', ('source row',))
            run, _ = core.analyze(source, category='disk_memory', budget=5,
                                  runs_root=root / 'runs')
            first = json.loads((run / 'manifest.json').read_text())
            old = next(item for item in first['jobs'] if item['adapter_id'] == 'sqlite')
            self.assertEqual(old['status'], 'complete')
            child = next(item for item in first['artifacts'] if item['id'] in old['child_ids'])
            Path(child['path']).write_bytes(b'tampered stored output')
            with patch.object(core, '_run_sqlite', side_effect=RuntimeError('controlled failure')):
                core.resume(run, budget=5)
            resumed = json.loads((run / 'manifest.json').read_text())
            jobs = [item for item in resumed['jobs'] if item['adapter_id'] == 'sqlite']
            self.assertEqual([item['status'] for item in jobs], ['invalidated', 'failed'])
            self.assertEqual(resumed['coverage']['DF04']['status'], 'failed')
            self.assertFalse(next(item for item in resumed['artifacts'] if item['id'] == child['id'])['current'])

    def test_osint_ids_publication_distinguishes_expired_identity_from_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'clue.txt'
            source.write_text('A local clue: https://example.org/evidence')
            original = source.read_bytes()
            real_hash, real_runner = core._hash, core._run_osint_ids
            for identity, expected in (('expired', 'truncated'), ('changed', 'failed'),
                                       ('matching', 'complete')):
                with self.subTest(identity=identity):
                    source.write_bytes(original)
                    inspected = False

                    def run_ids(*args):
                        nonlocal inspected
                        result = real_runner(*args)
                        inspected = True
                        if identity == 'changed':
                            source.write_bytes(original + b' changed')
                        return result

                    def source_hash(path, deadline):
                        if inspected and Path(path) == source and identity == 'expired':
                            return None
                        return real_hash(path, deadline)

                    with patch.object(core, '_run_osint_ids', side_effect=run_ids), \
                         patch.object(core, '_hash', side_effect=source_hash):
                        run, _ = core.analyze(source, category='osint', budget=3,
                                              runs_root=root / f'runs-{identity}')
                    manifest = json.loads((run / 'manifest.json').read_text())
                    job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'osint-ids')
                    self.assertEqual(job['status'], expected)
                    self.assertEqual(manifest['coverage']['OS02']['status'],
                                     'ran' if identity == 'matching' else expected)
                    self.assertEqual(any(row['job_id'] == job['id'] and row['current']
                                         for row in manifest['intelligence']), identity == 'matching')

    def test_tls_publication_distinguishes_expired_identity_from_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'wire.pcap'
            source.write_bytes(object_pcap([]))
            original = source.read_bytes()
            keylog = root / 'secrets.log'
            keylog.write_text('CLIENT_RANDOM ' + '1' * 64 + ' ' + '2' * 96 + '\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'tls_keylog': keylog.name}))
            real_hash = core._hash
            for identity, expected in (('expired', 'truncated'), ('changed', 'failed'),
                                       ('matching', 'complete')):
                with self.subTest(identity=identity):
                    source.write_bytes(original)
                    inspected = False

                    def run_tls(*args):
                        nonlocal inspected
                        inspected = True
                        if identity == 'changed':
                            source.write_bytes(original + b' changed')
                        stage = Path(args[2])
                        stage.mkdir(parents=True, exist_ok=True)
                        payload = stage / 'body.bin'
                        payload.write_bytes(b'TLS_DEADLINE_ORACLE')
                        return [{'path': str(payload), 'size': payload.stat().st_size,
                                 'sha256': hashlib.sha256(payload.read_bytes()).hexdigest(),
                                 'length_verified': True, 'index': 0, 'name': 'body.bin',
                                 'packet': 1, 'tcp_stream': 0, 'source_locators': [],
                                 'decrypted_fields': {}}], []

                    def source_hash(path, deadline):
                        if inspected and Path(path) == source and identity == 'expired':
                            return None
                        return real_hash(path, deadline)

                    with patch.object(core, '_run_packet_tls', side_effect=run_tls), \
                         patch.object(core, '_hash', side_effect=source_hash):
                        run, _ = core.analyze(source, category='packets', hints_path=hints,
                                              budget=3, runs_root=root / f'runs-{identity}')
                    self.assertTrue(inspected)
                    manifest = json.loads((run / 'manifest.json').read_text())
                    job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'packet-tls')
                    self.assertEqual(job['status'], expected)
                    self.assertEqual(manifest['coverage']['NET05']['status'],
                                     'ran' if identity == 'matching' else expected)
                    self.assertEqual(bool(job['child_ids']), identity == 'matching')

    def test_osint_snapshot_publication_distinguishes_expired_identity_from_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'snapshot.html'
            source.write_text('<link rel="canonical" href="https://example.org/archive">'
                              '<article data-captured="2026-04-09T07:18:22Z">Note</article>')
            original = source.read_bytes()
            real_hash, real_runner = core._hash, core._run_snapshot
            for identity, expected in (('expired', 'truncated'), ('changed', 'failed'),
                                       ('matching', 'complete')):
                with self.subTest(identity=identity):
                    source.write_bytes(original)
                    inspected = False

                    def run_snapshot(*args):
                        nonlocal inspected
                        result = real_runner(*args)
                        inspected = True
                        if identity == 'changed':
                            source.write_bytes(original + b' changed')
                        return result

                    def source_hash(path, deadline):
                        if inspected and Path(path) == source and identity == 'expired':
                            return None
                        return real_hash(path, deadline)

                    with patch.object(core, '_run_snapshot', side_effect=run_snapshot), \
                         patch.object(core, '_hash', side_effect=source_hash):
                        run, _ = core.analyze(source, category='osint', budget=3,
                                              runs_root=root / f'runs-{identity}')
                    self.assertTrue(inspected)
                    manifest = json.loads((run / 'manifest.json').read_text())
                    job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'osint-snapshots')
                    self.assertEqual(job['status'], expected)
                    self.assertEqual(manifest['coverage']['OS03']['status'],
                                     'ran' if identity == 'matching' else expected)
                    self.assertEqual(any(row['job_id'] == job['id'] and row['current']
                                         for row in manifest['intelligence']), identity == 'matching')

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

    def test_encrypted_pdf_private_password_resume_and_retirement(self):
        from pypdf import PdfWriter

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encrypted.pdf'
            writer = PdfWriter(clone_from=io.BytesIO(handwritten_pdf(b'DOC04 PRIVATE ORACLE')))
            writer.add_attachment(filename='../proof.bin', data=b'attachment proof\x00')
            writer.encrypt('pdf-private-pass')
            with source.open('wb') as target:
                writer.write(target)
            original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                    '--runs-root', root / 'runs', code=3)['run'])
            initial = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(initial['coverage']['DOC04']['status'], 'skipped prerequisite')
            self.assertFalse(any(a['depth'] > 0 for a in initial['artifacts']))

            password = root / 'private.txt'
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(password)}))
            password.write_text('wrong\n')
            self.run_cli('resume', run, '--hints', hints, code=3)
            wrong = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(wrong['coverage']['DOC04']['status'], 'skipped prerequisite')
            self.assertTrue(any('passwords did not validate' in note for note in wrong['warnings']))
            self.assertFalse(any(a['depth'] > 0 and a['current'] for a in wrong['artifacts']))

            password.write_text('wrong\npdf-private-pass\n')
            self.run_cli('resume', run, '--hints', hints, code=3)
            solved = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(solved['coverage']['DOC04']['status'], 'ran')
            children = [a for a in solved['artifacts'] if a['depth'] > 0 and a['current']]
            self.assertTrue(any(Path(a['path']).read_bytes() == b'attachment proof\x00'
                                for a in children))
            self.assertTrue(any(Path(a['path']).read_bytes() == b'DOC04 PRIVATE ORACLE'
                                for a in children))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original_hash)
            for name in ('manifest.json', 'report.md', 'events.jsonl'):
                self.assertNotIn('pdf-private-pass', (run / name).read_text())
            self.assertFalse((root / 'proof.bin').exists())

            password.write_text('wrong\n')
            self.run_cli('resume', run, '--hints', hints, code=3)
            retired = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(retired['coverage']['DOC04']['status'], 'skipped prerequisite')
            self.assertTrue(all(not a['current'] for a in retired['artifacts']
                                if a['source_locator'].get('pdf_kind')))
            self.assertNotIn('DOC04 PRIVATE ORACLE', (run / 'report.md').read_text())

            password.write_text('wrong\npdf-private-pass\n')
            self.run_cli('resume', run, '--hints', hints, code=3)
            restored = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(restored['coverage']['DOC04']['status'], 'ran')
            self.assertTrue(any(a['current'] and a['id'] in {child['id'] for child in children}
                                for a in restored['artifacts']))

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

    def test_unframed_text_does_not_erase_can01_directory_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for valid_first in (True, False):
                with self.subTest(valid_first=valid_first):
                    bundle = root / ('valid_first' if valid_first else 'note_first')
                    bundle.mkdir()
                    valid = bundle / ('a_valid.log' if valid_first else 'z_valid.log')
                    note = bundle / ('z_notes.txt' if valid_first else 'a_notes.txt')
                    valid.write_text('(1700000000.000000) can0 123#0102\n')
                    note.write_text('unrelated note with no CAN framing\n')
                    run = Path(self.run_cli('analyze', bundle, '--category', 'can',
                                            '--runs-root', root / 'runs', code=3)['run'])
                    first = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(first['coverage']['CAN01']['status'], 'ran')
                    self.assertEqual(len([job for job in first['jobs']
                                          if job['adapter_id'] == 'can-log']), 1)
                    self.run_cli('resume', run, code=3)
                    resumed = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(resumed['coverage']['CAN01']['status'], 'ran')

    def test_can_report_display_limit_is_notice_but_bad_row_truncates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'frames.log'
            source.write_text(''.join(
                f'(1700000000.{index:06d}) can0 123#0102\n' for index in range(101)))
            run = Path(self.run_cli('analyze', source, '--category', 'can',
                                    '--runs-root', root / 'runs', code=3)['run'])
            first = json.loads((run / 'manifest.json').read_text())
            job = next(job for job in first['jobs'] if job['adapter_id'] == 'can-log')
            self.assertEqual(job['frame_count'], 101)
            self.assertEqual(len(json.loads(Path(job['frames_path']).read_text())), 101)
            self.assertEqual(first['coverage']['CAN01']['status'], 'ran')
            self.assertIn('Notice: CAN report displays first 100 frames',
                          (run / 'report.md').read_text())

            source.write_text(source.read_text() + 'unparseable CAN row\n')
            self.run_cli('resume', run, code=3)
            truncated = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(truncated['coverage']['CAN01']['status'], 'truncated')
            self.assertTrue(any('line 102:' in warning for warning in truncated['warnings']))

            with source.open('wb') as oversized:
                oversized.write(b'(1700000000.000000) can0 123#0102\n')
                oversized.truncate(8 * 1024 * 1024 + 1)
            self.run_cli('resume', run, code=3)
            limited = json.loads((run / 'manifest.json').read_text())
            latest_job = [job for job in limited['jobs'] if job['adapter_id'] == 'can-log'][-1]
            self.assertEqual(limited['coverage']['CAN01']['status'], 'truncated')
            self.assertTrue(any('CAN source byte limit reached' in warning
                                for warning in latest_job['warnings']))

    def test_can_signal_report_display_limit_is_notice(self):
        try:
            import cantools
        except ImportError:
            self.skipTest('cantools is optional outside core setup')
        from test_autosolve_can_dbc import DBC

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'frames.log'
            source.write_text(''.join(
                f'({index + 1}.0) can0 123#01ECFF0007000000\n'
                for index in range(101)))
            database = root / 'signals.dbc'
            database.write_text(DBC)
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'dbc': str(database)}))
            run = Path(self.run_cli('analyze', source, '--category', 'can', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'can-dbc')
            self.assertEqual(job['record_count'], 101)
            self.assertEqual(manifest['coverage']['CAN01']['status'], 'ran')
            self.assertEqual(manifest['coverage']['CAN02']['status'], 'ran')
            report = (run / 'report.md').read_text()
            self.assertIn('Notice: CAN report displays first 100 frames', report)
            self.assertIn('Notice: CAN report displays first 100 signals', report)

    def test_can_signal_output_limit_remains_truncated(self):
        from test_autosolve_can_dbc import DBC

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'frames.log'
            source.write_text('(1.0) can0 123#01ECFF0007000000\n')
            database = root / 'signals.dbc'
            database.write_text(DBC)
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'dbc': str(database)}))
            with patch.object(core, '_run_can_dbc', return_value=(
                    [], ['CAN signal output byte limit reached (1)'])):
                run, _ = core.analyze(source, category='can', hints_path=hints,
                                      runs_root=root / 'runs')
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['CAN02']['status'], 'truncated')
            self.assertIn('Limit or prerequisite: CAN signal output byte limit reached (1)',
                          (run / 'report.md').read_text())

    def test_can_worker_survives_pillow_import_with_memory_cap(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow is optional outside core setup')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n')
            with patch.dict(os.environ, {'PYTHONSAFEPATH': '1'}):
                run, _ = core.analyze(source, category='can', runs_root=root / 'runs')
            manifest = json.loads((run / 'manifest.json').read_text())
            job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'can-log')
            self.assertEqual(job.get('frame_count'), 1, job)
            self.assertEqual(manifest['coverage']['CAN01']['status'], 'ran')

    def test_can_worker_preserves_frame_and_byte_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n(2.0) can0 456#0304\n')
            original = subprocess.Popen
            commands = []

            def launch(argv, **kwargs):
                commands.append(argv)
                return original(argv, **kwargs)

            with patch.object(core.subprocess, 'Popen', side_effect=launch):
                frames, warnings = core._run_can(source, 1, 4096, 5)
            self.assertEqual(len(frames), 1)
            self.assertTrue(any('frame limit reached' in warning for warning in warnings))
            self.assertEqual(len(commands), 1)
            self.assertNotIn(str(source), ' '.join(commands[0]))
            frames, warnings = core._run_can(source, 100, 2, 5)
            self.assertEqual(frames, [])
            self.assertTrue(any('byte limit reached' in warning for warning in warnings))

    def test_can_worker_accepts_valid_long_unicode_path(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for _ in range(12):
                folder /= '😀' * 60
                folder.mkdir()
            source = folder / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n')
            self.assertGreater(len(json.dumps(str(source)).encode()), 8192)
            frames, warnings = core._run_can(source, 100, 4096, 5)
            self.assertEqual(len(frames), 1)
            self.assertEqual(warnings, [])

    def test_can_worker_timeout_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n')
            original = subprocess.Popen
            launched = []

            def launch(*args, **kwargs):
                worker = original(*args, **kwargs)
                launched.append(worker)
                return worker

            with patch.object(core.subprocess, 'Popen', side_effect=launch):
                with self.assertRaises(TimeoutError):
                    core._run_can(source, 10000, 8 * 1024 * 1024, 0)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())

    def test_can_worker_body_stall_obeys_deadline_and_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n')
            original = subprocess.Popen
            launched = []

            def stalled_launch(*args, **kwargs):
                script = ('import os,struct,sys,time; '
                          'os.write(int(sys.argv[1]), struct.pack("!i", 1024)); '
                          'time.sleep(2)')
                worker = original([sys.executable, '-I', '-B', '-c', script,
                                   str(kwargs['pass_fds'][0])], **kwargs)
                launched.append(worker)
                return worker

            started = time.monotonic()
            with patch.object(core.subprocess, 'Popen', side_effect=stalled_launch):
                with self.assertRaises(TimeoutError):
                    core._run_can(source, 10000, 8 * 1024 * 1024, .1)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())

    def test_can_worker_rejects_invalid_and_oversized_ipc(self):
        from multiprocessing.connection import Connection

        class Done:
            def __init__(self):
                self._read, write = os.pipe()
                self.stdin = os.fdopen(write, 'wb', buffering=0)

            def poll(self):
                return 0

            def wait(self):
                os.close(self._read)
                return 0

        def fake_launch(*args, pass_fds, **kwargs):
            descriptor = os.dup(pass_fds[0])
            with Connection(descriptor, readable=False, writable=True) as pipe:
                if oversized:
                    os.write(descriptor, struct.pack('!i', 32 * 1024 * 1024 + 1))
                else:
                    pipe.send_bytes(b'not JSON')
            return Done()

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'frames.log'
            source.write_text('(1.0) can0 123#0102\n')
            for oversized in (False, True):
                with self.subTest(oversized=oversized), \
                     patch.object(core.subprocess, 'Popen', side_effect=fake_launch):
                    with self.assertRaisesRegex(
                            core.WorkLimit if oversized else RuntimeError,
                            'output limit' if oversized else 'invalid result'):
                        core._run_can(source, 10000, 8 * 1024 * 1024, 1)

    def test_blf_non_can_notice_does_not_truncate_can01_or_hide_real_skip(self):
        try:
            import can
        except ImportError:
            self.skipTest('python-can is optional outside core setup')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for malformed in (False, True):
                source = root / ('a_mixed.blf' if malformed else 'z_marker.blf')
                with can.BLFWriter(source, compression_level=0) as writer:
                    writer.on_message_received(can.Message(
                        timestamp=1700000000.0, channel=0, arbitration_id=0x123,
                        is_extended_id=False, data=b'\x01', dlc=1))
                    writer.log_event('xx', timestamp=1700000000.01)
                    if malformed:
                        writer.on_message_received(can.Message(
                            timestamp=1700000000.015, channel=0, arbitration_id=0x321,
                            is_extended_id=False, data=b'\x02', dlc=9))
                    writer.on_message_received(can.Message(
                        timestamp=1700000000.02, channel=0, arbitration_id=0x456,
                        is_extended_id=False, data=b'\x03', dlc=1))
                before = source.read_bytes()
                run = Path(self.run_cli('analyze', source, '--category', 'can',
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'can-log')
                rows = json.loads(Path(job['frames_path']).read_text())
                self.assertEqual([row['can_id'] for row in rows], ['123', '456'])
                self.assertEqual([row['source_object'] for row in rows],
                                 [1, 4] if malformed else [1, 3])
                self.assertEqual(manifest['coverage']['CAN01']['status'],
                                 'truncated' if malformed else 'ran')
                self.assertTrue(any('skipped 1 non-CAN objects' in note
                                    for note in job['warnings']))
                self.assertEqual(any('invalid CAN frame skipped' in note
                                     for note in job['warnings']), malformed)
                self.assertIn('Notice: BLF skipped 1 non-CAN objects',
                              (run / 'report.md').read_text())
                self.assertEqual(source.read_bytes(), before)
                if not malformed:
                    old_key = job['key']
                    old_hash = job['frames_sha256']
                    self.run_cli('resume', run, code=3)
                    resumed = json.loads((run / 'manifest.json').read_text())
                    can_jobs = [j for j in resumed['jobs'] if j['adapter_id'] == 'can-log']
                    self.assertEqual(len(can_jobs), 1)
                    self.assertEqual((can_jobs[0]['key'], can_jobs[0]['frames_sha256']),
                                     (old_key, old_hash))
                    self.assertEqual(resumed['coverage']['CAN01']['status'], 'ran')
                    self.assertTrue(any('skipped 1 non-CAN objects' in note
                                        for note in resumed['warnings']))
                    self.assertEqual(source.read_bytes(), before)
            combined_run = Path(self.run_cli('analyze', root, '--category', 'can',
                                             '--runs-root', root / 'runs', code=3)['run'])
            combined = json.loads((combined_run / 'manifest.json').read_text())
            self.assertEqual(combined['coverage']['CAN01']['status'], 'truncated')
            self.assertEqual(len([j for j in combined['jobs']
                                  if j['adapter_id'] == 'can-log']), 2)
            self.assertTrue(any('invalid CAN frame skipped' in note
                                for note in combined['warnings']))
            self.assertTrue(any('skipped 1 non-CAN objects' in note
                                for note in combined['warnings']))
            self.run_cli('resume', combined_run, code=3)
            after_resume = json.loads((combined_run / 'manifest.json').read_text())
            self.assertEqual(after_resume['coverage']['CAN01']['status'], 'truncated')

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

    def test_net01_reordered_gap_flag_requires_complete_stream_proof(self):
        request = b'GET /object.bin HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, options, expected in (
                    ('reordered', {}, 'ran'),
                    ('missing', {'missing': True}, 'truncated'),
                    ('conflict', {'conflicting': True}, 'truncated')):
                with self.subTest(name=name):
                    source = root / f'{name}.pcap'
                    frames = complete_transfer(bytes(range(100)), reordered=True, **options)
                    frames.append(tcp_frame('198.51.100.10', '198.51.100.20',
                                            41000, 19091, 1001 + len(request), 0, 17))
                    source.write_bytes(object_pcap(frames))
                    original = source.read_bytes()
                    run = Path(self.run_cli('analyze', source, '--category', 'packets',
                                            '--runs-root', root / 'runs', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    packet_job = next(job for job in manifest['jobs']
                                      if job['adapter_id'] == 'packets')
                    records = json.loads(Path(packet_job['records_path']).read_text())
                    self.assertTrue(any('lost_segment' in row.get('tcp_analysis', [])
                                        for row in records))
                    self.assertTrue(any('conversation incomplete' in warning
                                        for warning in packet_job['warnings']))
                    self.assertEqual(manifest['coverage']['NET01']['status'], expected)
                    self.assertEqual(manifest['coverage']['NET03']['status'], expected)
                    self.assertEqual(any('conversation incomplete' in warning
                                         for warning in manifest['warnings']), expected == 'truncated')
                    self.assertEqual(source.read_bytes(), original)
                    if name == 'reordered':
                        stream_job = next(job for job in manifest['jobs']
                                          if job['adapter_id'] == 'packet-streams')
                        streams = json.loads(Path(stream_job['records_path']).read_text())
                        self.assertEqual({stream['direction'] for stream in streams}, {0, 1})
                        self.assertTrue(all(stream['complete'] and not stream['gaps']
                                            and not stream['conflicts'] for stream in streams))
                        self.run_cli('resume', run, code=3)
                        resumed = json.loads((run / 'manifest.json').read_text())
                        self.assertEqual(resumed['coverage']['NET01']['status'], 'ran')
                        self.assertEqual(len(resumed['jobs']), len(manifest['jobs']))
                        Path(packet_job['records_path']).write_text('invalidated packet cache')
                        with patch.object(core, '_run_packets', side_effect=RuntimeError('fixture failure')):
                            core.resume(run, budget=20)
                        failed = json.loads((run / 'manifest.json').read_text())
                        self.assertEqual(failed['coverage']['NET01']['status'], 'failed')
                        self.assertEqual(next(job for job in reversed(failed['jobs'])
                                              if job['adapter_id'] == 'packets')['status'], 'failed')

            clipped = ipv4('198.51.100.10', '198.51.100.20', 17,
                           udp(53000, 53001, b'test'))
            source_dir = root / 'mixed'
            source_dir.mkdir()
            capture = bytearray(object_pcap([clipped]))
            capture[24 + 12:24 + 16] = (len(clipped) + 10).to_bytes(4, 'little')
            (source_dir / 'a-clipped.pcap').write_bytes(capture)
            (source_dir / 'b-reordered.pcap').write_bytes((root / 'reordered.pcap').read_bytes())
            run = Path(self.run_cli('analyze', source_dir, '--category', 'packets',
                                    '--runs-root', root / 'mixed-runs', code=3)['run'])
            mixed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(mixed['coverage']['NET01']['status'], 'truncated')
            self.assertTrue(any('packet data truncated by capture' in warning
                                for warning in mixed['warnings']))
            (source_dir / 'a-clipped.pcap').unlink()
            core.resume(run, budget=20)
            current = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(current['coverage']['NET01']['status'], 'ran')
            self.assertFalse(any('packet data truncated by capture' in warning
                                 for warning in current['warnings']))

            ack_source = root / 'ack-gap.pcap'
            ack_frames = complete_transfer(bytes(range(100)))
            ack_frames.extend((
                tcp_frame('198.51.100.10', '198.51.100.20', 41000, 19091,
                          1001 + len(request), 999999, 16),
                tcp_frame('198.51.100.10', '198.51.100.20', 41000, 19091,
                          1001 + len(request), 999999, 17)))
            ack_source.write_bytes(object_pcap(ack_frames))
            run = Path(self.run_cli('analyze', ack_source, '--category', 'packets',
                                    '--runs-root', root / 'ack-runs', code=3)['run'])
            ack = json.loads((run / 'manifest.json').read_text())
            ack_job = next(job for job in ack['jobs'] if job['adapter_id'] == 'packets')
            ack_rows = json.loads(Path(ack_job['records_path']).read_text())
            self.assertIn('ack_lost_segment', ack_rows[8]['tcp_analysis'])
            self.assertEqual(ack['coverage']['NET03']['status'], 'ran')
            self.assertEqual(ack['coverage']['NET01']['status'], 'truncated')
            self.assertTrue(any('ACK acknowledges uncaptured TCP segment' in warning
                                for warning in ack['warnings']))

            clean_dir = root / 'clean-mixed'
            clean_dir.mkdir()
            (clean_dir / 'a-clipped.pcap').write_bytes(capture)
            clean_frames = complete_transfer(bytes(range(100)))
            clean_frames.append(tcp_frame('198.51.100.10', '198.51.100.20',
                                          41000, 19091, 1001 + len(request), 0, 17))
            (clean_dir / 'b-clean.pcap').write_bytes(object_pcap(clean_frames))
            run = Path(self.run_cli('analyze', clean_dir, '--category', 'packets',
                                    '--runs-root', root / 'clean-mixed-runs', code=3)['run'])
            clean_mixed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(clean_mixed['coverage']['NET01']['status'], 'truncated')
            self.assertTrue(any('packet data truncated by capture' in warning
                                for warning in clean_mixed['warnings']))
            (clean_dir / 'a-clipped.pcap').unlink()
            core.resume(run, budget=20)
            clean_only = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(clean_only['coverage']['NET01']['status'], 'ran')
            self.assertFalse(any('packet data truncated by capture' in warning
                                 for warning in clean_only['warnings']))

    def test_net01_unsupported_sibling_does_not_replace_packet_coverage(self):
        examples = Path(__file__).resolve().parents[1] / 'examples/core'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / 'sources'
            sources.mkdir()
            packet = sources / 'a-incomplete.pcap'
            packet.write_bytes((examples / 'http-incomplete.pcap').read_bytes())
            (sources / 'z-note.txt').write_text('unrelated note')
            run = Path(self.run_cli('analyze', sources, '--category', 'packets',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['NET01']['status'], 'truncated')
            self.assertTrue(any('conversation incomplete' in warning
                                for warning in manifest['warnings']))
            packet.unlink()
            core.resume(run, budget=20)
            only_note = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(only_note['coverage']['NET01']['status'], 'skipped prerequisite')

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
                self.assertTrue(any(item['current'] and item['artifact_id'] == first_root
                                    and item['tag'] == tag for item in first['intelligence']))
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

    def test_sqlite_wal_without_shm_is_complete_but_missing_wal_is_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / 'live.db'
            connection = sqlite3.connect(live)
            try:
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA wal_autocheckpoint=0')
                connection.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY, body TEXT)')
                connection.commit()
                connection.execute('INSERT INTO evidence VALUES (?, ?)', (1, 'wal_alpha'))
                connection.commit()
                connection.execute('INSERT INTO evidence VALUES (?, ?)', (2, 'wal_emoji_🐙'))
                connection.commit()
                original_wal = Path(str(live) + '-wal').read_bytes()
                page_size = int.from_bytes(original_wal[8:12], 'big')
                for case in ('complete', 'missing', 'wrong_db_mode', 'short_frame', 'bad_magic',
                             'bad_header', 'bad_salt', 'bad_frame', 'bad_page'):
                    with self.subTest(case=case):
                        source = root / f'{case}.db'
                        wal = Path(str(source) + '-wal')
                        shutil.copyfile(live, source)
                        if case == 'wrong_db_mode':
                            data = bytearray(source.read_bytes())
                            data[18:20] = b'\x01\x01'
                            source.write_bytes(data)
                        if case != 'missing':
                            data = bytearray(original_wal)
                            if case == 'short_frame':
                                data.pop()
                            elif case == 'bad_magic':
                                data[0] ^= 1
                            elif case == 'bad_header':
                                data[24] ^= 1
                            elif case == 'bad_salt':
                                data[40] ^= 1
                            elif case == 'bad_frame':
                                data[-page_size - 24 + 16] ^= 1
                            elif case == 'bad_page':
                                data[-1] ^= 1
                            wal.write_bytes(data)
                        self.assertFalse(Path(str(source) + '-shm').exists())
                        db_hash = hashlib.sha256(source.read_bytes()).hexdigest()
                        wal_hash = hashlib.sha256(wal.read_bytes()).hexdigest() if wal.exists() else None
                        run = Path(self.run_cli('analyze', source, '--category', 'disk_memory',
                                                '--runs-root', root / 'runs', code=3)['run'])
                        for action in ('analyze', 'resume'):
                            if action == 'resume':
                                self.run_cli('resume', run, code=3)
                            manifest = json.loads((run / 'manifest.json').read_text())
                            expected_status = 'ran' if case == 'complete' else 'truncated'
                            self.assertEqual(manifest['coverage']['DF04']['status'], expected_status)
                            source_artifact = next(item for item in manifest['artifacts']
                                                   if item['depth'] == 0 and item['current'])
                            self.assertEqual(source_artifact['sha256'], db_hash)
                            job = [item for item in manifest['jobs'] if item['adapter_id'] == 'sqlite'][-1]
                            self.assertEqual(job['status'], 'complete')
                            self.assertEqual(job['data_fingerprints']['-wal'], wal_hash)
                            rows = [item for item in manifest['artifacts'] if item['current'] and
                                    item['source_locator'].get('sqlite_kind') == 'row']
                            if case == 'complete':
                                self.assertEqual([Path(item['path']).read_bytes() for item in rows], [
                                    b'{"primary_key":null,"rowid":1,"table":"evidence","values":{"body":"wal_alpha","id":1}}\n',
                                    '{"primary_key":null,"rowid":2,"table":"evidence","values":{"body":"wal_emoji_🐙","id":2}}\n'.encode(),
                                ])
                                self.assertEqual([item['source_locator']['sqlite_locator'] for item in rows],
                                                 ['table evidence rowid 1', 'table evidence rowid 2'])
                                self.assertTrue(all(item['source_locator']['sqlite_companion_sha256'] ==
                                                    manifest['sqlite_companions'][source_artifact['id']]
                                                    for item in rows))
                                self.assertIn('-shm companion missing', ' '.join(job['warnings']))
                                self.assertIn('-shm companion missing', ' '.join(manifest['warnings']))
                            elif case == 'missing':
                                self.assertEqual(rows, [])
                                self.assertIn('no -wal companion', ' '.join(job['warnings']))
                            else:
                                self.assertIn('WAL integrity incomplete', ' '.join(job['warnings']))
                                if case != 'wrong_db_mode':
                                    self.assertFalse(any(b'wal_emoji_' in Path(item['path']).read_bytes()
                                                         for item in rows))
                        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), db_hash)
                        if wal.exists():
                            self.assertEqual(hashlib.sha256(wal.read_bytes()).hexdigest(), wal_hash)
            finally:
                connection.close()

    def test_sqlite_restart_wal_keeps_supplied_shm_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / 'live.db'
            connection = sqlite3.connect(live)
            try:
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA wal_autocheckpoint=0')
                connection.execute('CREATE TABLE evidence (body TEXT)')
                connection.commit()
                for index in range(10):
                    connection.execute('INSERT INTO evidence VALUES (?)', (f'base-{index}',))
                    connection.commit()
                old_size = Path(str(live) + '-wal').stat().st_size
                self.assertEqual(connection.execute('PRAGMA wal_checkpoint(RESTART)').fetchone()[0], 0)
                connection.execute('INSERT INTO evidence VALUES (?)', ('current-wal',))
                connection.commit()
                self.assertEqual(Path(str(live) + '-wal').stat().st_size, old_size)
                for copy_shm, expected_status in ((True, 'ran'), (False, 'truncated')):
                    with self.subTest(copy_shm=copy_shm):
                        source = root / ('with-shm.db' if copy_shm else 'without-shm.db')
                        shutil.copyfile(live, source)
                        shutil.copyfile(Path(str(live) + '-wal'), Path(str(source) + '-wal'))
                        if copy_shm:
                            shutil.copyfile(Path(str(live) + '-shm'), Path(str(source) + '-shm'))
                        run = Path(self.run_cli('analyze', source, '--category', 'disk_memory',
                                                '--runs-root', root / 'runs', code=3)['run'])
                        manifest = json.loads((run / 'manifest.json').read_text())
                        job = next(item for item in manifest['jobs'] if item['adapter_id'] == 'sqlite')
                        self.assertEqual(manifest['coverage']['DF04']['status'], expected_status)
                        self.assertEqual(job['status'], 'complete')
                        if copy_shm:
                            self.assertEqual(job['warnings'], [])
                        else:
                            self.assertIn('WAL integrity incomplete', ' '.join(job['warnings']))
                        rows = [item for item in manifest['artifacts'] if item['current'] and
                                item['source_locator'].get('sqlite_kind') == 'row']
                        self.assertEqual([json.loads(Path(item['path']).read_bytes())['values']['body']
                                          for item in rows],
                                         [*(f'base-{index}' for index in range(10)), 'current-wal'])
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

    def test_minimum_flag_shape_xor_from_public_cli(self):
        for name, plaintext, key in (
            ('ctf', b'ctf{123456}', 0x91),
            ('flag', b'flag{123456}', 0x5c),
            ('crypto', b'crypto{abcdef}', 0xd3),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'cipher.bin'
                source.write_bytes(bytes(byte ^ key for byte in plaintext))
                run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                original = next(a for a in manifest['artifacts'] if a['depth'] == 0)
                exact = [a for a in manifest['artifacts']
                         if a['source_locator'].get('xor_key_hex') == f'{key:02x}' and
                         Path(a['path']).read_bytes() == plaintext]
                self.assertEqual(len(exact), 1)
                self.assertEqual(exact[0]['parents'][0]['id'], original['id'])
                self.assertTrue(any(f['artifact_id'] == exact[0]['id'] and f['state'] == 'candidate'
                                    for f in manifest['findings']))
                self.assertFalse(any(f['state'] == 'challenge_accepted'
                                     for f in manifest['findings']))

        for source_bytes in (bytes(byte ^ 0x5c for byte in b'not-a-flag!'),
                             bytes(range(12))):
            with self.subTest(control=source_bytes.hex()), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'cipher.bin'
                source.write_bytes(source_bytes)
                run = Path(self.run_cli('analyze', source, '--category', 'encoding',
                                        '--runs-root', root / 'runs', code=3)['run'])
                manifest = json.loads((run / 'manifest.json').read_text())
                self.assertFalse(any(a['source_locator'].get('xor_key_hex')
                                     for a in manifest['artifacts']))
                self.assertFalse(any(f['state'] == 'challenge_accepted'
                                     for f in manifest['findings']))

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

    def test_encrypted_zip_local_header_corruption_is_not_wrong_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'encrypted.zip'
            passwords = root / 'passwords.txt'
            hints = root / 'hints.json'
            passwords.write_bytes(b'correct horse\n')
            hints.write_text(json.dumps({'password_file': str(passwords)}))

            source.write_bytes(ENCRYPTED_ZIP)
            intact = Path(self.run_cli('analyze', source, '--category', 'documents', '--hints', hints,
                                       '--runs-root', root / 'intact-runs', code=3)['run'])
            good = json.loads((intact / 'manifest.json').read_text())
            self.assertEqual(good['coverage']['DOC02']['status'], 'ran')
            self.assertIn(b'verified zip payload',
                          [Path(a['path']).read_bytes() for a in good['artifacts'] if a['depth'] > 0])

            passwords.write_bytes(b'wrong\n')
            wrong = Path(self.run_cli('analyze', source, '--category', 'documents', '--hints', hints,
                                      '--runs-root', root / 'wrong-runs', code=3)['run'])
            wrong_manifest = json.loads((wrong / 'manifest.json').read_text())
            self.assertEqual(wrong_manifest['coverage']['DOC02']['status'], 'skipped prerequisite')

            raw = bytearray(ENCRYPTED_ZIP)
            local = raw.index(b'PK\x03\x04')
            central = raw.index(b'PK\x01\x02')
            local_name_size = int.from_bytes(raw[local + 26:local + 28], 'little')
            central_name_size = int.from_bytes(raw[central + 28:central + 30], 'little')
            self.assertEqual(raw[local + 30:local + 30 + local_name_size],
                             raw[central + 46:central + 46 + central_name_size])
            raw[local + 30] ^= 1
            self.assertNotEqual(raw[local + 30:local + 30 + local_name_size],
                                raw[central + 46:central + 46 + central_name_size])
            self.assertEqual(raw[central:], ENCRYPTED_ZIP[central:])
            source.write_bytes(raw)
            passwords.write_bytes(b'correct horse\n')
            corrupt = Path(self.run_cli('analyze', source, '--category', 'documents', '--hints', hints,
                                        '--runs-root', root / 'corrupt-runs', code=3)['run'])
            broken = json.loads((corrupt / 'manifest.json').read_text())
            self.assertEqual(broken['coverage']['DOC02']['status'], 'failed')
            self.assertIn('corrupt ZIP local header', broken['coverage']['DOC02']['note'])
            self.assertTrue(any('corrupt ZIP local header' in warning for warning in broken['warnings']))
            self.assertFalse(any('passwords did not validate' in warning for warning in broken['warnings']))
            self.assertFalse(any(a['depth'] > 0 for a in broken['artifacts']))
            self.assertNotIn('correct horse', (corrupt / 'report.md').read_text())

            self.run_cli('resume', corrupt, '--hints', hints, code=3)
            resumed = json.loads((corrupt / 'manifest.json').read_text())
            self.assertEqual(resumed['coverage']['DOC02']['status'], 'failed')
            self.assertIn('corrupt ZIP local header', resumed['coverage']['DOC02']['note'])
            self.assertFalse(any(a['depth'] > 0 and a['current'] for a in resumed['artifacts']))

            self.run_cli('resume', intact, '--hints', hints, code=3)
            changed = json.loads((intact / 'manifest.json').read_text())
            self.assertEqual(changed['coverage']['DOC02']['status'], 'failed')
            self.assertFalse(any(a['depth'] > 0 and a['current'] for a in changed['artifacts']))

    def test_encrypted_zip_corrupt_member_withholds_other_decrypted_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            passwords = root / 'passwords.txt'
            passwords.write_bytes(b'one\ntwo\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(passwords)}))
            for corruption in ('member-name', 'leading-signature'):
                with self.subTest(corruption=corruption):
                    source = root / f'mixed-{corruption}.zip'
                    raw = bytearray(MIXED_PASSWORD_ZIP)
                    raw[30 if corruption == 'member-name' else 0] ^= 1
                    source.write_bytes(raw)
                    with zipfile.ZipFile(source) as archive:
                        self.assertEqual(archive.read(archive.infolist()[1], pwd=b'two'),
                                         b'second secret')
                    run = Path(self.run_cli('analyze', source, '--category', 'documents',
                                            '--hints', hints,
                                            '--runs-root', root / f'runs-{corruption}', code=3)['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(manifest['coverage']['DOC02']['status'], 'failed')
                    self.assertIn('corrupt ZIP local header', manifest['coverage']['DOC02']['note'])
                    self.assertFalse(any(a['depth'] > 0 and a['source_locator'].get('encrypted')
                                         for a in manifest['artifacts']))
                    self.assertNotIn('second secret', (run / 'report.md').read_text())

    def test_damaged_zip_leading_signature_needs_valid_central_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for offset in range(4):
                variant = bytearray(ENCRYPTED_ZIP)
                variant[offset] ^= 1
                candidate = root / f'damaged-{offset}.dat'
                candidate.write_bytes(variant)
                self.assertEqual(core._kind(candidate), 'zip')
            damaged = bytearray(ENCRYPTED_ZIP)
            damaged[0] ^= 1
            source = root / 'renamed.dat'
            source.write_bytes(damaged)
            with zipfile.ZipFile(source) as archive:
                with self.assertRaises(zipfile.BadZipFile):
                    archive.read(archive.infolist()[0], pwd=b'correct horse')
            self.assertEqual(core._kind(source), 'zip')

            passwords = root / 'passwords.txt'
            passwords.write_bytes(b'correct horse\n')
            hints = root / 'hints.json'
            hints.write_text(json.dumps({'password_file': str(passwords)}))
            run = Path(self.run_cli('analyze', source, '--category', 'documents', '--hints', hints,
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(manifest['coverage']['DOC02']['status'], 'failed')
            self.assertIn('corrupt ZIP local header', manifest['coverage']['DOC02']['note'])
            self.assertFalse(any(a['depth'] > 0 for a in manifest['artifacts']))
            self.assertNotIn('correct horse', (run / 'report.md').read_text())
            self.run_cli('resume', run, '--hints', hints, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            self.assertEqual(resumed['coverage']['DOC02']['status'], 'failed')
            self.assertFalse(any(a['depth'] > 0 and a['current'] for a in resumed['artifacts']))

            non_zip = root / 'not-an-archive.zip'
            non_zip.write_bytes(b'XK\x03\x04' + b'plain unrelated data')
            self.assertNotEqual(core._kind(non_zip), 'zip')
            non_zip.write_bytes(b'XK\x03\x04junk' + b'PK\x05\x06' + b'\0' * 18)
            self.assertNotEqual(core._kind(non_zip), 'zip')
            damaged[damaged.index(b'PK\x01\x02')] ^= 1
            source.write_bytes(damaged)
            self.assertNotEqual(core._kind(source), 'zip')

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

    def test_images_category_extracts_member_from_validated_png_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b'IMAGE_TAIL_MEMBER\x00\xff'
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as writer:
                writer.writestr('oracle.bin', payload)
            source = root / 'image.blob'
            source.write_bytes(sample_png() + archive.getvalue())
            run = Path(self.run_cli('analyze', source, '--category', 'images',
                                    '--runs-root', root / 'runs', code=3)['run'])
            manifest = json.loads((run / 'manifest.json').read_text())
            members = [item for item in manifest['artifacts']
                       if item['current'] and item['depth'] == 2
                       and item['source_locator'].get('archive_member') == 'oracle.bin']
            self.assertEqual(len(members), 1)
            self.assertEqual(Path(members[0]['path']).read_bytes(), payload)
            self.assertEqual(source.read_bytes(), sample_png() + archive.getvalue())
            self.run_cli('resume', run, code=3)
            resumed = json.loads((run / 'manifest.json').read_text())
            member = next(item for item in resumed['artifacts'] if item['id'] == members[0]['id'])
            self.assertTrue(member['current'])
            self.assertEqual(member['parents'], members[0]['parents'])

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
