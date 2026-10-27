"""REV02 fixtures use independent compiled executables and bounded fake FLOSS JSON."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import rev_strings
from scripts.autosolve_lib import setup as setup_module
from scripts.autosolve_lib import core


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


@unittest.skipUnless(shutil.which('gcc'), 'GCC is unavailable')
class ReverseStringsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def build(self, name, body, *, compiler='gcc', optimization='-O0', strip=False):
        source = self.root / f'{name}.c'
        target = self.root / name
        source.write_text(body)
        command = [compiler, optimization, '-o', str(target), str(source)]
        if strip:
            command.insert(2, '-s')
        subprocess.run(command, check=True, capture_output=True)
        return target

    def test_stack_string_exact_bytes_and_instruction_offsets(self):
        phrase = b'STACK_HELLO'
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(phrase + b'\0'))
        binary = self.build('stack', 'int probe(void){volatile char s[32];'
                            + assignments + 'return s[1];} int main(void){return probe();}')
        before = hashlib.sha256(binary.read_bytes()).digest()
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        matches = [row for row in rows if row['kind'] == 'stack' and row['data'] == phrase]
        self.assertEqual(len(matches), 1, (rows, warnings))
        row = matches[0]
        self.assertEqual(row['state'], 'candidate')
        self.assertTrue(row['source_locator']['instruction_file_offsets'])
        payload = binary.read_bytes()
        for offset in row['source_locator']['instruction_file_offsets']:
            self.assertEqual(payload[offset], 0xc6)  # x86 mov byte ptr [bp+disp], imm8
        self.assertEqual(hashlib.sha256(binary.read_bytes()).digest(), before)

    def test_xor_string_from_object_symbol_and_heldout_layout(self):
        phrase = b'hello secret message in the data'
        key = 0x37
        encoded = bytes(byte ^ key for byte in phrase)
        initializer = ','.join(str(byte) for byte in encoded + b'\0')
        source = ('volatile unsigned char encoded[] = {' + initializer + '};'
                  'int main(void){for(int i=0;i<' + str(len(phrase))
                  + ';i++)encoded[i]^=0x37;return encoded[0];}')
        for name, optimization, strip in (('xor_gcc', '-O0', False),
                                          ('xor_heldout', '-O2', True)):
            binary = self.build(name, source, optimization=optimization, strip=strip)
            rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
            matches = [row for row in rows if row['kind'] == 'xor' and row['data'] == phrase]
            self.assertEqual(len(matches), 1, (name, rows, warnings))
            row = matches[0]
            self.assertEqual(row['state'], 'candidate')
            self.assertEqual(row['key_hex'], f'{key:02x}')
            offset = row['source_locator']['file_offset']
            self.assertEqual(binary.read_bytes()[offset:offset + len(phrase)], encoded)

    def test_heldout_compiler_stack_placement(self):
        compiler = shutil.which('clang-16')
        if not compiler:
            self.skipTest('Clang 16 unavailable')
        phrase = b'CLANG_STACK_TEST'
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(phrase + b'\0'))
        binary = self.build('clang_stack', 'int probe(void){volatile char s[32];'
                            + assignments + 'return s[1];} int main(void){return probe();}',
                            compiler=compiler, optimization='-O2')
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertTrue(any(row['kind'] == 'stack' and row['data'] == phrase for row in rows),
                        (rows, warnings))

    def test_negative_arithmetic_and_random_constants_do_not_invent_plaintext(self):
        binary = self.build('negative', 'volatile unsigned long constants[] = '
                            '{0x138e8c037bba5105ULL,0x56201d854e249044ULL};'
                            'int main(void){unsigned long x=1;for(int i=0;i<8;i++)'
                            'x=(x*13+7)^constants[i%2];return (int)x;}')
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertEqual(rows, [])
        self.assertTrue(any('no plaintext inferred' in item for item in warnings))

    def test_floss_json_preserves_decoder_location_and_exact_encoding(self):
        doc = {'strings': {'stack_strings': [
            {'string': 'stack string', 'encoding': 'ASCII', 'function': 0x401000,
             'program_counter': 0x401020, 'frame_offset': 12, 'offset': 4}],
            'decoded_strings': [
                {'string': 'secret', 'encoding': 'UTF-16LE', 'address': 0x402000,
                 'address_type': 'GLOBAL', 'decoded_at': 0x401040,
                 'decoding_routine': 0x401080}]}}
        script = self.root / 'fake-floss'
        script.write_text('#!/usr/bin/env python3\nimport json\nprint(json.dumps(' + repr(doc) + '))\n')
        script.chmod(0o700)
        binary = self.build('floss_input', 'int main(void){return 0;}')
        rows, warnings = rev_strings.inspect_strings(binary, floss_path=str(script), timeout=5)
        self.assertFalse(any('FLOSS' in item for item in warnings), warnings)
        self.assertTrue(any(row['data'] == b'stack string' and
                            row['source_locator']['program_counter'] == 0x401020 for row in rows))
        self.assertTrue(any(row['data'] == 'secret'.encode('utf-16le') and
                            row['source_locator']['decoding_routine'] == 0x401080 for row in rows))

    def test_limits_bad_schema_and_unsupported_source(self):
        source = self.root / 'random'
        source.write_bytes(b'hello world')
        self.assertEqual(rev_strings.inspect_strings(source)[0], [])
        self.assertIn('unsupported', ' '.join(rev_strings.inspect_strings(source)[1]))
        with self.assertRaises(ValueError):
            rev_strings.inspect_strings(source, max_records=0)
        binary = self.build('limits', 'int main(void){return 0;}')
        self.assertEqual(rev_strings.inspect_strings(binary, max_source_bytes=1)[0], [])
        script = self.root / 'bad-floss'
        script.write_text('#!/usr/bin/env python3\nprint("{}")\n')
        script.chmod(0o700)
        self.assertIn('invalid FLOSS JSON', ' '.join(rev_strings.inspect_strings(
            binary, floss_path=str(script), timeout=5)[1]))
        script.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n')
        self.assertIn('FLOSS timed out', ' '.join(rev_strings.inspect_strings(
            binary, floss_path=str(script), timeout=0.05)[1]))
        rows, warnings = rev_strings._floss_records({'strings': {
            'stack_strings': [{'string': 'invented', 'encoding': 'ASCII'}]}}, 4)
        self.assertEqual(rows, [])
        self.assertIn('source address or offset', ' '.join(warnings))
        link = self.root / 'link'
        link.symlink_to(binary)
        self.assertEqual(rev_strings.inspect_strings(link)[0], [])
        malformed = self.root / 'malformed'
        malformed.write_bytes(b'\x7fELF' + b'\0' * 96)
        self.assertEqual(rev_strings.inspect_strings(malformed)[0], [])
        self.assertIn('malformed ELF', ' '.join(rev_strings.inspect_strings(malformed)[1]))

    def test_public_cli_reversing_and_auto_resume_preserve_candidate_lineage(self):
        stack = b'STACK_HELLO'
        plaintext = b'hello secret message in the data'
        encoded = bytes(byte ^ 0x37 for byte in plaintext)
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(stack + b'\0'))
        source = ('volatile unsigned char encoded[] = {' +
                  ','.join(str(byte) for byte in encoded + b'\0') + '};'
                  'int probe(void){volatile char s[32];' + assignments + 'return s[1];}'
                  'int main(void){return probe()+encoded[0];}')
        binary = self.build('reversing', source)
        original = binary.read_bytes()

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                     *map(str, args)], capture_output=True, timeout=50,
                                    env={**os.environ, 'PATH': str(self.root)})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        first = cli('analyze', binary, '--category', 'reversing', '--budget', '30',
                    '--runs-root', self.root / 'runs')
        run = Path(first['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV01']['status'], 'ran')
        self.assertEqual(manifest['coverage']['REV02']['status'], 'truncated')
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'rev-strings']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        self.assertTrue(any('FLOSS backend unavailable' in item for item in jobs[0]['warnings']))
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertTrue(any(row['kind'] == 'stack' and bytes.fromhex(row['data_hex']) == stack
                            for row in records))
        xor = next(row for row in records if row['kind'] == 'xor' and
                   bytes.fromhex(row['data_hex']) == plaintext)
        offset = xor['source_locator']['file_offset']
        self.assertEqual(original[offset:offset + len(encoded)], encoded)
        children = [item for item in manifest['artifacts'] if item['id'] in jobs[0]['child_ids']]
        self.assertTrue(any(Path(item['path']).read_bytes() == stack for item in children))
        self.assertTrue(any(Path(item['path']).read_bytes() == plaintext for item in children))
        self.assertTrue(all(any(edge['job_key'] == jobs[0]['key'] for edge in item['parents'])
                            for item in children))
        intel = [item for item in manifest['intelligence'] if item['job_id'] == jobs[0]['id']]
        self.assertTrue(any(item['source_locator'].get('file_offset') == offset and
                            item['source_locator']['candidate_state'] == 'candidate' for item in intel))
        self.assertEqual(binary.read_bytes(), original)

        cli('resume', run, '--budget', '10')
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in resumed['jobs'] if job['adapter_id'] == 'rev-strings']), 1)
        self.assertTrue(all(item['current'] for item in resumed['intelligence']
                            if item['job_id'] == jobs[0]['id']))
        binary.write_bytes(b'changed source\n')
        cli('resume', run, '--budget', '10')
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(all(not item['current'] for item in changed['intelligence']
                            if item['job_id'] == jobs[0]['id']))
        self.assertTrue(all(not item['current'] for item in changed['artifacts']
                            if item['id'] in jobs[0]['child_ids']))

        binary.write_bytes(original)
        automatic = cli('analyze', binary, '--budget', '30',
                        '--runs-root', self.root / 'auto-runs')
        auto = json.loads((Path(automatic['run']) / 'manifest.json').read_text())
        self.assertEqual(len([job for job in auto['jobs'] if job['adapter_id'] == 'rev-strings']), 1)
        self.assertEqual(auto['coverage']['REV02']['status'], 'truncated')

    def test_doctor_reports_missing_floss_and_static_fallback(self):
        original = setup_module.shutil.which
        with mock.patch.object(setup_module.shutil, 'which',
                               side_effect=lambda name: None if name == 'floss' else original(name)):
            report = setup_module.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.obfuscated_strings']
        self.assertEqual(operation['functional_probe'], 'passed')
        self.assertEqual(operation['status'], 'partial')
        self.assertEqual(report['engines']['floss']['found'], False)
        self.assertIn('floss_missing', operation['reason'])

    def test_source_change_during_worker_rejects_publication(self):
        binary = self.build('changing', 'int main(void){return 0;}')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        run = self.root / 'changing-run'
        (run / 'jobs').mkdir(parents=True)
        artifact = {'id': 'root', 'sha256': digest, 'path': str(binary),
                    'kind_evidence': 'elf', 'depth': 0}
        manifest = {'coverage': {'REV02': {'status': 'not scheduled', 'note': ''}},
                    'current_adapter_fingerprints': {'rev-strings': ['test-fingerprint']},
                    'jobs': [], 'intelligence': [], 'artifacts': [artifact],
                    'warnings': [], 'derived_bytes': 0}

        def change_source(*_):
            binary.write_bytes(b'changed during inspection')
            return [], []

        with mock.patch.object(core, '_run_rev_strings', side_effect=change_source):
            core._rev_strings_job(run, manifest, artifact, time.monotonic() + 5, deque(), 0)
        self.assertEqual(manifest['jobs'][0]['status'], 'failed')
        self.assertIn('source changed', manifest['jobs'][0]['warning'])
        self.assertEqual(manifest['jobs'][0]['child_ids'], [])
        self.assertEqual(manifest['intelligence'], [])


if __name__ == '__main__':
    unittest.main()
