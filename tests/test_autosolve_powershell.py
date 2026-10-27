"""REV11 independent static PowerShell fixtures."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.autosolve_lib.profiles import powershell
from scripts.autosolve_lib import setup as autosolve_setup


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class PowerShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def source(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def test_encoded_command_and_nested_literal_concat_have_source_chain(self):
        script = "Write-Output ('HEL' + 'LO')"
        encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        source = f'powershell -NoP -EncodedCommand {encoded}\n'.encode()
        path = self.source('command.txt', source)
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(warnings, [])
        command = next(row for row in rows if row['kind'] == 'encoded_command')
        self.assertEqual(command['data'], script.encode())
        self.assertEqual(command['transform_chain'], ['base64', 'utf-16le'])
        self.assertEqual(source[command['source_locator']['byte_start']:
                                command['source_locator']['byte_end']], encoded.encode())
        concat = next(row for row in rows if row['kind'] == 'concat')
        self.assertEqual(concat['data'], b'HELLO')
        self.assertEqual(concat['source_locator']['byte_start'],
                         command['source_locator']['byte_start'])
        self.assertTrue(concat['source_locator']['derived_spans'])
        self.assertEqual(path.read_bytes(), source)

    def test_heldout_quotes_case_utf16_source_and_explicit_base64(self):
        source = ("# [Convert]::FromBase64String('RkFLRQ==')\n"
                  "$a = 'A''B' + \"C`nD\"\n"
                  "$b = [CoNvErT]::FrOmBaSe64StRiNg('SEVMTE8=')\n")
        path = self.source('heldout.ps1', b'\xff\xfe' + source.encode('utf-16le'))
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(warnings, [])
        self.assertTrue(any(row['kind'] == 'concat' and row['data'] == b"A'BC\nD"
                            for row in rows))
        decoded = next(row for row in rows if row['kind'] == 'base64' and
                       row['data'] == b'HELLO')
        begin = decoded['source_locator']['byte_start']
        end = decoded['source_locator']['byte_end']
        self.assertEqual(path.read_bytes()[begin:end].decode('utf-16le'), 'SEVMTE8=')
        self.assertFalse(any(row['data'] == b'FAKE' for row in rows))

    def test_encoded_command_with_nested_base64_and_quoted_argument(self):
        script = "$x=[Convert]::FromBase64String('SEVMTE8=')"
        encoded = base64.b64encode(script.encode('utf-16le')).decode()
        path = self.source('layers.ps1',
                           f'powershell -e "{encoded}"\n'.encode())
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(warnings, [])
        nested = next(row for row in rows if row['kind'] == 'base64')
        self.assertEqual(nested['data'], b'HELLO')
        self.assertEqual(nested['transform_chain'], ['base64', 'utf-16le', 'base64'])
        self.assertEqual(len(nested['source_locator']['derived_spans']), 1)

    def test_dynamic_and_malformed_values_remain_unresolved(self):
        path = self.source('negative.ps1',
                           b'$x = Get-Date\n$y = [Convert]::FromBase64String($x)\n'
                           b'$z = "A$env:USER" + "B"\n'
                           b'powershell -EncodedCommand %%%\n'
                           b"$q = 'unclosed + 'HELLO\n")
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])
        self.assertTrue(any('unsupported or malformed' in item for item in warnings))

    def test_syntax_mentioned_inside_string_is_not_evaluated(self):
        path = self.source('quoted.ps1',
                           b'Write-Output "[Convert]::FromBase64String(\'SEVMTE8=\')"\n'
                           b"Write-Output \"'ABC' + 'DEF'\"\n"
                           b'Write-Output "powershell -EncodedCommand SABFAEwATABPAA=="\n'
                           b'powershell -EncodedCommand SABFAEwATABPAA==%\n')
        rows, _ = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])

    def test_unclosed_quote_reports_malformed_without_value(self):
        path = self.source('malformed.ps1', b"Write-Output 'unclosed\n")
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])
        self.assertTrue(any('malformed' in item for item in warnings))

    def test_block_comment_does_not_produce_candidate(self):
        path = self.source('comment.ps1',
                           b'<# explanation\n'
                           b"[Convert]::FromBase64String('SEVMTE8=')\n"
                           b"'HEL' + 'LO'\n#>\n")
        rows, _ = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])

    def test_here_string_is_data_not_code(self):
        path = self.source('here.ps1',
                           b"$description = @'\n"
                           b"'HEL' + 'LO'\n"
                           b"[Convert]::FromBase64String('SEVMTE8=')\n"
                           b"'@\n")
        rows, _ = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])

    def test_limits_and_symlink_do_not_produce_unbounded_results(self):
        path = self.source('bounded.ps1', b"'ABC' + 'DEF'\n")
        self.assertEqual(powershell.inspect_powershell(path, max_source_bytes=2)[0], [])
        self.assertEqual(powershell.inspect_powershell(path, max_output_bytes=3)[0], [])
        link = self.root / 'link.ps1'
        link.symlink_to(path)
        self.assertEqual(powershell.inspect_powershell(link)[0], [])
        with self.assertRaises(ValueError):
            powershell.inspect_powershell(path, max_records=0)

    def test_public_cli_reversing_auto_and_resume_keep_exact_candidate_lineage(self):
        script = "Write-Output ('AUTO' + 'SOLVE_REV11')"
        encoded = base64.b64encode(script.encode('utf-16le')).decode()
        source = f'powershell -EncodedCommand {encoded}\n'.encode()
        path = self.source('fixture.ps1', source)

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                     *map(str, args)], capture_output=True, timeout=60,
                                    env=os.environ.copy())
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        first = cli('analyze', path, '--category', 'reversing', '--budget', '15',
                    '--runs-root', self.root / 'runs')
        run = Path(first['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV11']['status'], 'ran')
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'rev-powershell']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        children = [row for row in manifest['artifacts'] if row['id'] in jobs[0]['child_ids']]
        self.assertTrue(any(Path(row['path']).read_bytes() == b'AUTOSOLVE_REV11' for row in children))
        self.assertTrue(all(any(edge['job_key'] == jobs[0]['key'] for edge in row['parents'])
                            for row in children))
        evidence = [row for row in manifest['intelligence'] if row['job_id'] == jobs[0]['id']]
        self.assertTrue(evidence)
        self.assertTrue(all(row['source_locator']['candidate_state'] == 'candidate'
                            for row in evidence))
        self.assertTrue(any(source[row['source_locator']['byte_start']:
                                   row['source_locator']['byte_end']] == encoded.encode()
                            for row in evidence))

        cli('resume', run, '--budget', '5')
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in resumed['jobs'] if
                              job['adapter_id'] == 'rev-powershell']), 1)
        self.assertTrue(all(row['current'] for row in resumed['intelligence']
                            if row['job_id'] == jobs[0]['id']))
        path.write_text("'NEW' + 'SOURCE'\n")
        cli('resume', run, '--budget', '5')
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(all(not row['current'] for row in changed['intelligence']
                            if row['job_id'] == jobs[0]['id']))
        self.assertTrue(all(not row['current'] for row in changed['artifacts']
                            if row['id'] in jobs[0]['child_ids']))

        automatic = cli('analyze', path, '--budget', '15',
                        '--runs-root', self.root / 'auto-runs')
        auto = json.loads((Path(automatic['run']) / 'manifest.json').read_text())
        self.assertEqual(len([job for job in auto['jobs'] if
                              job['adapter_id'] == 'rev-powershell']), 1)

    def test_doctor_reports_static_powershell_probe(self):
        report = autosolve_setup.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.powershell_constants']
        self.assertEqual(operation['functional_probe'], 'passed')
        self.assertEqual(operation['status'], 'partial')

    def test_multi_source_resume_keeps_truncated_coverage(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        (bundle / 'a.ps1').write_text("'HEL' + 'LO'\n")
        (bundle / 'b.ps1').write_text('$x = [Convert]::FromBase64String($runtime)\n')

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                     *map(str, args)], capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        run = Path(cli('analyze', bundle, '--category', 'reversing', '--budget', '10',
                       '--runs-root', self.root / 'runs')['run'])
        before = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(before['coverage']['REV11']['status'], 'truncated')
        self.assertEqual(len([job for job in before['jobs'] if
                              job['adapter_id'] == 'rev-powershell']), 2)
        cli('resume', run, '--budget', '10')
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(resumed['coverage']['REV11']['status'], 'truncated')
        self.assertEqual(len([job for job in resumed['jobs'] if
                              job['adapter_id'] == 'rev-powershell']), 2)


if __name__ == '__main__':
    unittest.main()
