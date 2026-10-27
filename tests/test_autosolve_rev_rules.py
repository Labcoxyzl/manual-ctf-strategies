"""REV03 checks rule evidence, missing prerequisites, and bounded static execution."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import rev_rules
from scripts.autosolve_lib import setup as setup_module
from scripts.autosolve_lib import core


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class ReverseRuleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sample = self.root / 'benign.elf'
        self.sample.write_bytes(b'\x7fELF' + b'\0' * 32 + b'KNOWN_CAPABILITY' + b'\0' * 8)

    def tool(self, name, source):
        path = self.root / name
        path.write_text('#!/usr/bin/env python3\n' + source)
        path.chmod(0o700)
        return str(path)

    def test_missing_rules_is_skipped_prerequisite_not_no_match(self):
        report, warnings = rev_rules.inspect_rules(self.sample)
        self.assertEqual(report['engines']['capa']['status'], 'skipped_prerequisite')
        self.assertEqual(report['engines']['yara']['status'], 'skipped_prerequisite')
        self.assertEqual(report['sample_sha256'], hashlib.sha256(self.sample.read_bytes()).hexdigest())
        self.assertIn('rule', report['engines']['capa']['reason'])
        self.assertEqual(warnings, [])

    def test_yara_match_keeps_file_offset_and_rule_identity_across_relocation(self):
        rules = self.root / 'capability.yar'
        rules.write_text('rule BenignCapability { strings: $a = "KNOWN_CAPABILITY" condition: $a }\n')
        yara = self.tool('fake-yara', '''import pathlib, sys
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
assert '-s' in sys.argv and '-L' in sys.argv and '-e' in sys.argv
sample = pathlib.Path(sys.argv[-1]); data = sample.read_bytes()
needle = b'KNOWN_CAPABILITY'; offset = data.find(needle)
if offset >= 0:
 print('default:BenignCapability ' + str(sample))
 print('0x%x:%d:$a: KNOWN_CAPABILITY' % (offset, len(needle)))
''')
        for offset in (36, 69):
            self.sample.write_bytes(b'\x7fELF' + b'\0' * (offset - 4) + b'KNOWN_CAPABILITY')
            before = hashlib.sha256(self.sample.read_bytes()).hexdigest()
            report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
            self.assertEqual(warnings, [])
            row = report['engines']['yara']
            self.assertEqual(row['status'], 'matched')
            self.assertEqual(row['version'], 'YARA 4.5.2')
            self.assertEqual(row['matches'][0]['rule'], 'BenignCapability')
            self.assertEqual(row['matches'][0]['strings'][0]['file_offset'], offset)
            self.assertEqual(row['matches'][0]['strings'][0]['matched_hex'], b'KNOWN_CAPABILITY'.hex())
            self.assertEqual(report['sample_sha256'], before)
            self.assertEqual(hashlib.sha256(self.sample.read_bytes()).hexdigest(), before)
        first_identity = row['rules']['sha256']
        rules.write_text(rules.read_text() + '// held-out rule revision\n')
        revised, _ = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
        self.assertNotEqual(revised['engines']['yara']['rules']['sha256'], first_identity)

    def test_yara_near_match_is_completed_no_match(self):
        rules = self.root / 'capability.yar'
        rules.write_text('rule BenignCapability { strings: $a = "KNOWN_CAPABILITY" condition: $a }\n')
        self.sample.write_bytes(b'\x7fELF' + b'\0' * 20 + b'KNOWN_CAPABILITX')
        yara = self.tool('fake-yara', '''import sys
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
''')
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
        self.assertEqual(report['engines']['yara']['status'], 'no_match')
        self.assertEqual(report['engines']['yara']['matches'], [])
        self.assertEqual(warnings, [])

    def test_yara_source_name_with_newline_does_not_corrupt_rule_headers(self):
        unusual = self.root / 'odd\nname.elf'
        unusual.write_bytes(self.sample.read_bytes())
        rules = self.root / 'capability.yar'
        rules.write_text('rule BenignCapability { strings: $a = "KNOWN_CAPABILITY" condition: $a }\n')
        yara = self.tool('fake-yara', '''import pathlib, sys
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
sample = pathlib.Path(sys.argv[-1]); offset = sample.read_bytes().find(b'KNOWN_CAPABILITY')
print('default:BenignCapability ' + str(sample))
print('0x%x:16:$a: KNOWN_CAPABILITY' % offset)
''')
        report, warnings = rev_rules.inspect_rules(unusual, yara_rules=rules, yara_path=yara)
        self.assertEqual(report['engines']['yara']['status'], 'matched', warnings)

    def test_capa_json_preserves_rule_address_feature_and_pack_identity(self):
        rules = self.root / 'capa-rules'
        rules.mkdir()
        rule = rules / 'example.yml'
        rule.write_text('rule:\n  meta:\n    name: test capability\n')
        sigs = self.root / 'capa-sigs'
        sigs.mkdir()
        (sigs / 'example.pat').write_text('signature data')
        capa = self.tool('fake-capa', '''import hashlib, json, pathlib, sys
if '--version' in sys.argv: print('capa 10.0.0'); sys.exit(0)
assert '-j' in sys.argv and '-r' in sys.argv and '-s' in sys.argv
sample = pathlib.Path(sys.argv[-1]); data = sample.read_bytes()
offset = data.find(b'KNOWN_CAPABILITY')
match = {'success': True, 'node': {'type': 'feature', 'feature': {'type': 'string',
         'string': 'KNOWN_CAPABILITY'}}, 'children': [],
         'locations': [{'type': 'absolute', 'value': 4194304 + offset}], 'captures': {}}
print(json.dumps({'meta': {'version': '10.0.0', 'sample': {'sha256':
    hashlib.sha256(data).hexdigest()}, 'analysis': {'rules': [sys.argv[sys.argv.index('-r') + 1]]}},
    'rules': {'test capability': {'meta': {'name': 'test capability'}, 'source': 'rule:',
    'matches': [[{'type': 'absolute', 'value': 4194304 + offset}, match]]}}}))
''')
        report, warnings = rev_rules.inspect_rules(self.sample, capa_rules=rules,
                                                   capa_signatures=sigs, capa_path=capa)
        self.assertEqual(warnings, [])
        row = report['engines']['capa']
        self.assertEqual(row['status'], 'matched')
        self.assertEqual(row['version'], 'capa 10.0.0')
        self.assertEqual(row['matches'][0]['rule'], 'test capability')
        self.assertEqual(row['matches'][0]['address']['value'], 4194340)
        self.assertEqual(row['matches'][0]['evidence'][0]['feature']['string'], 'KNOWN_CAPABILITY')
        self.assertEqual(row['matches'][0]['evidence'][0]['locations'][0]['value'], 4194340)
        old_hash = row['rules']['sha256']
        rule.write_text(rule.read_text() + '# revised\n')
        revised, _ = rev_rules.inspect_rules(self.sample, capa_rules=rules,
                                             capa_signatures=sigs, capa_path=capa)
        self.assertNotEqual(revised['engines']['capa']['rules']['sha256'], old_hash)

    def test_capa_output_with_no_loaded_rules_is_not_no_match(self):
        rules = self.root / 'capa-rules'
        signatures = self.root / 'capa-sigs'
        rules.mkdir()
        signatures.mkdir()
        (rules / 'example.yml').write_text('rule:\n  meta:\n    name: test capability\n')
        (signatures / 'example.pat').write_text('signature data')
        capa = self.tool('empty-capa', '''import hashlib, json, pathlib, sys
if '--version' in sys.argv: print('capa 10.0.0'); sys.exit(0)
data = pathlib.Path(sys.argv[-1]).read_bytes()
print(json.dumps({'meta': {'version': '10.0.0', 'sample': {'sha256': hashlib.sha256(data).hexdigest()},
    'analysis': {'rules': []}}, 'rules': {}}))
''')
        report, warnings = rev_rules.inspect_rules(self.sample, capa_rules=rules,
                                                   capa_signatures=signatures, capa_path=capa)
        self.assertEqual(report['engines']['capa']['status'], 'incomplete')
        self.assertIn('loaded', ' '.join(warnings))

    def test_invalid_rule_path_and_tool_timeout_are_not_no_match(self):
        absent, _ = rev_rules.inspect_rules(self.sample, yara_rules=self.root / 'missing.yar')
        self.assertEqual(absent['engines']['yara']['status'], 'skipped_prerequisite')
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        link = self.root / 'link.yar'
        link.symlink_to(rules)
        linked, _ = rev_rules.inspect_rules(self.sample, yara_rules=link)
        self.assertEqual(linked['engines']['yara']['status'], 'skipped_prerequisite')
        yara = self.tool('slow-yara', '''import sys, time
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
time.sleep(5)
''')
        timed, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules,
                                                  yara_path=yara, timeout=.3)
        self.assertEqual(timed['engines']['yara']['status'], 'incomplete')
        self.assertIn('timed out', ' '.join(warnings))

    def test_capa_needs_actual_rule_and_signature_files(self):
        rules = self.root / 'capa-rules'
        signatures = self.root / 'capa-sigs'
        rules.mkdir()
        signatures.mkdir()
        (rules / 'README.md').write_text('not a capa rule')
        (signatures / 'README.md').write_text('not a signature')
        report, warnings = rev_rules.inspect_rules(self.sample, capa_rules=rules,
                                                   capa_signatures=signatures)
        self.assertEqual(report['engines']['capa']['status'], 'skipped_prerequisite')
        self.assertIn('compatible', ' '.join(warnings))

    def test_empty_tool_version_is_unavailable(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        yara = self.tool('silent-yara', 'import sys\n')
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
        self.assertEqual(report['engines']['yara']['status'], 'unavailable')
        self.assertIn('version', ' '.join(warnings))

    def test_relative_explicit_tool_path_resolves_before_private_workdir(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        yara = self.tool('fake-yara', '''import sys
if '-v' in sys.argv: print('YARA 4.5.2')
''')
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules,
                                                       yara_path='./fake-yara')
        finally:
            os.chdir(previous)
        self.assertEqual(report['engines']['yara']['status'], 'no_match', warnings)

    def test_changed_rule_data_invalidates_a_scan(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        yara = self.tool('editing-yara', '''import pathlib, sys
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
pathlib.Path(sys.argv[-2]).write_text('rule x { condition: false }')
''')
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
        self.assertEqual(report['engines']['yara']['status'], 'incomplete')
        self.assertIn('changed', ' '.join(warnings))

    def test_external_tool_cannot_mutate_original_sample(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        yara = self.tool('editing-input-yara', '''import os, pathlib, sys
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
path = pathlib.Path(sys.argv[-1]); os.chmod(path, 0o600); path.write_bytes(b'changed')
''')
        before = self.sample.read_bytes()
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules, yara_path=yara)
        self.assertEqual(self.sample.read_bytes(), before)
        self.assertEqual(report['engines']['yara']['status'], 'incomplete')
        self.assertIn('changed', ' '.join(warnings))

    def test_timeout_stops_descendants_after_launcher_exits(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        marker = self.root / 'late-write'
        child = "import sys,time; time.sleep(.4); open(sys.argv[1],'w').write('escaped')"
        source = ("import subprocess,sys\n"
                  "if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)\n"
                  "subprocess.Popen([sys.executable, '-c', " + repr(child) + ', '
                  + repr(str(marker)) + '])\n')
        yara = self.tool('child-yara', source)
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules,
                                                  yara_path=yara, timeout=.1)
        self.assertEqual(report['engines']['yara']['status'], 'incomplete')
        self.assertIn('timed out', ' '.join(warnings))
        time.sleep(.5)
        self.assertFalse(marker.exists())

    def test_tool_can_close_output_before_clean_exit(self):
        rules = self.root / 'rules.yar'
        rules.write_text('rule x { condition: true }')
        yara = self.tool('early-close-yara', '''import os,sys,time
if '-v' in sys.argv: print('YARA 4.5.2'); sys.exit(0)
os.close(1); os.close(2); time.sleep(.5)
''')
        report, warnings = rev_rules.inspect_rules(self.sample, yara_rules=rules,
                                                  yara_path=yara, timeout=1)
        self.assertEqual(report['engines']['yara']['status'], 'no_match', warnings)

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable')
    def test_public_cli_rule_match_private_hints_and_resume_identity(self):
        inputs = self.root / 'inputs'
        inputs.mkdir()
        source = inputs / 'benign.c'
        source.write_text('#include <stdio.h>\nint main(void){puts("KNOWN_CAPABILITY");return 0;}\n')
        binary = inputs / 'benign.elf'
        subprocess.run(['gcc', '-o', str(binary), str(source)], check=True, capture_output=True)
        source.unlink()
        rules = inputs / 'rules.yar'
        rules.write_text('rule BenignCapability { strings: $a = "KNOWN_CAPABILITY" condition: $a }\n')
        hints = inputs / 'hints.json'
        hints.write_text('{"yara_rules":"rules.yar"}')
        tools = self.root / 'tools'
        tools.mkdir()
        version_file = tools / 'yara-version.txt'
        version_file.write_text('YARA 4.5.2')
        yara = tools / 'yara'
        yara.write_text('''#!/usr/bin/env python3
import pathlib, sys
if '-v' in sys.argv: print((pathlib.Path(__file__).parent / 'yara-version.txt').read_text()); sys.exit(0)
assert '-s' in sys.argv and '-L' in sys.argv and '-e' in sys.argv
sample = pathlib.Path(sys.argv[-1]); data = sample.read_bytes()
offset = data.find(b'KNOWN_CAPABILITY')
if offset >= 0:
 print('default:BenignCapability ' + str(sample))
 print('0x%x:16:$a: KNOWN_CAPABILITY' % offset)
''')
        yara.chmod(0o700)

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', *map(str, args)],
                                    capture_output=True, text=True, timeout=70,
                                    env={**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH']})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        first = cli('analyze', inputs, '--category', 'reversing', '--hints', hints,
                    '--budget', '30', '--runs-root', self.root / 'runs')
        run = Path(first['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual([Path(item['path']).name for item in manifest['artifacts']
                          if item['depth'] == 0], ['benign.elf'])
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'rev-rules']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['coverage_status'], 'ran')
        report = json.loads(Path(jobs[0]['report_path']).read_text())
        self.assertEqual(report['engines']['capa']['status'], 'skipped_prerequisite')
        self.assertEqual(report['engines']['yara']['status'], 'matched')
        offset = binary.read_bytes().find(b'KNOWN_CAPABILITY')
        evidence = next(item for item in manifest['intelligence'] if item['tag'] == 'REV03 rule match')
        self.assertEqual(evidence['source_locator']['strings'][0]['file_offset'], offset)
        self.assertIn('not proof', evidence['next_action'])
        cli('resume', run, '--hints', hints, '--budget', '10')
        unchanged = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in unchanged['jobs'] if job['adapter_id'] == 'rev-rules']), 1)
        rules.write_text(rules.read_text() + '// revised pack\n')
        cli('resume', run, '--hints', hints, '--budget', '10')
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in changed['jobs'] if job['adapter_id'] == 'rev-rules']), 2)
        self.assertFalse(any(item['current'] for item in changed['intelligence']
                             if item['job_id'] == jobs[0]['id']))
        version_file.write_text('YARA 4.5.3')
        cli('resume', run, '--hints', hints, '--budget', '10')
        upgraded = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in upgraded['jobs'] if job['adapter_id'] == 'rev-rules']), 3)

    def test_doctor_discloses_missing_rule_engines_and_required_data(self):
        original = setup_module.shutil.which
        with mock.patch.object(setup_module.shutil, 'which',
                               side_effect=lambda name: None if name in ('capa', 'yara')
                               else original(name)):
            report = setup_module.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.rule_matching']
        self.assertTrue(operation['implemented'])
        self.assertEqual(operation['status'], 'unavailable')
        self.assertEqual(report['engines']['capa']['status'], 'unavailable')
        self.assertEqual(report['engines']['yara']['status'], 'unavailable')
        self.assertIn('rule', report['engines']['capa']['required_data'])

    def test_doctor_finds_compatible_tools_but_waits_for_explicit_rule_data(self):
        capa = self.tool('capa', '''import sys
if '--help' in sys.argv: print('-j -r -s')
elif '--version' in sys.argv: print('capa 10.0.0')
''')
        yara = self.tool('yara', '''import sys
if '--help' in sys.argv: print('-s -L -e')
elif '-v' in sys.argv: print('YARA 4.5.2')
''')
        original = setup_module.shutil.which
        with mock.patch.object(setup_module.shutil, 'which',
                               side_effect=lambda name: {'capa': capa, 'yara': yara}.get(name)
                               or original(name)):
            report = setup_module.doctor(['reversing'], self_test=True)
        for engine in ('capa', 'yara'):
            self.assertEqual(report['engines'][engine]['status'], 'partial')
            self.assertTrue(report['engines'][engine]['options_compatible'])
            self.assertEqual(report['engines'][engine]['functional_probe'], 'not_run')
        self.assertEqual(report['operations']['malware_reversing.rule_matching']['status'], 'partial')

    def test_public_cli_without_rules_reports_skipped_prerequisite(self):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', 'analyze',
                                 str(self.sample), '--category', 'reversing', '--budget', '10',
                                 '--runs-root', str(self.root / 'runs')],
                                capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'rev-rules']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['coverage_status'], 'skipped prerequisite')
        self.assertEqual(manifest['coverage']['REV03']['status'], 'skipped prerequisite')
        report = json.loads(Path(jobs[0]['report_path']).read_text())
        self.assertEqual({row['status'] for row in report['engines'].values()},
                         {'skipped_prerequisite'})

    def test_source_change_during_worker_rejects_rule_publication(self):
        run = self.root / 'run'
        (run / 'jobs').mkdir(parents=True)
        digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        artifact = {'id': 'root', 'sha256': digest, 'path': str(self.sample)}
        manifest = {'coverage': {'REV03': {'status': 'not scheduled', 'note': ''}},
                    'current_adapter_fingerprints': {'rev-rules': ['test-adapter']},
                    'rev_rules_identity': 'test-rules', 'jobs': [], 'intelligence': [],
                    'warnings': []}

        def change_source(*_):
            self.sample.write_bytes(b'changed during matching')
            return {'sample_sha256': digest, 'engines': {}}, []

        with mock.patch.object(core, '_run_rev_rules', side_effect=change_source):
            core._rev_rules_job(run, manifest, artifact, time.monotonic() + 5, {})
        self.assertEqual(manifest['jobs'][0]['status'], 'failed')
        self.assertIn('source changed', manifest['jobs'][0]['warning'])
        self.assertEqual(manifest['intelligence'], [])


if __name__ == '__main__':
    unittest.main()
