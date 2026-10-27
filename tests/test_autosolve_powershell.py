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

    def test_punctuation_adjacent_comments_remain_data(self):
        for index, source in enumerate((
                b"if($true){# [Convert]::FromBase64String('SEVMTE8=')\n}\n",
                b"Write-Output (# [Convert]::FromBase64String('SEVMTE8=')\n 1)\n",
                b"Write-Output (<# [Convert]::FromBase64String('SEVMTE8=') #> 1)\n")):
            path = self.source(f'punctuation-{index}.ps1', source)
            rows, _ = powershell.inspect_powershell(path)
            self.assertEqual(rows, [])

    def test_here_string_is_data_not_code(self):
        for quote in ("'", '"'):
            source = (f'$description = @{quote}\n'
                      "header' with an inner quote\n"
                      "'HEL' + 'LO'\n"
                      "[Convert]::FromBase64String('SEVMTE8=')\n"
                      f'{quote}@\n'
                      "[Convert]::FromBase64String('T1VU')\n")
            path = self.source(f'here-{ord(quote)}.ps1', source.encode())
            rows, warnings = powershell.inspect_powershell(path)
            self.assertEqual(warnings, [])
            self.assertEqual([row['data'] for row in rows], [b'OUT'])

    def test_abbreviated_and_mixed_dynamic_expressions_are_unresolved(self):
        valid = base64.b64encode("Write-Output 'OK'".encode('utf-16le')).decode()
        source = (f"[Convert]::FromBase64String('SEVMTE8='); "
                  "[Convert]::FromBase64String($runtime)\n"
                  f"powershell -enc {valid}\n"
                  "powershell -enc $runtime\n"
                  "powershell -e $runtime\n"
                  "'LEFT' + 'RIGHT'; $runtime + 'suffix'\n")
        path = self.source('mixed.ps1', source.encode())
        rows, warnings = powershell.inspect_powershell(path)
        self.assertTrue(any(row['data'] == b'HELLO' for row in rows))
        self.assertTrue(any(row['data'] == b'LEFTRIGHT' for row in rows))
        self.assertTrue(any(row['kind'] == 'encoded_command' for row in rows))
        self.assertTrue(any('dynamic values unresolved' in warning for warning in warnings))
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 'analyze', str(path), '--category', 'reversing',
                                 '--budget', '15', '--runs-root', str(self.root / 'mixed-runs')],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV11']['status'], 'truncated')
        self.assertTrue(any(row['tag'] == 'REV11 PowerShell candidate'
                            for row in manifest['intelligence']))

        for abbreviation in ('-enc', '-e'):
            path = self.source(f'dynamic-{abbreviation[1:]}.ps1',
                               f'powershell {abbreviation} $runtime\n'.encode())
            rows, warnings = powershell.inspect_powershell(path)
            self.assertEqual(rows, [])
            self.assertTrue(any('dynamic values unresolved' in warning for warning in warnings))

    def test_unsupported_literal_escape_warns_without_decoding(self):
        path = self.source('escape.ps1', b'"A`a" + \'B\'\n')
        rows, warnings = powershell.inspect_powershell(path)
        self.assertEqual(rows, [])
        self.assertTrue(any('dynamic values unresolved' in warning for warning in warnings))

    def test_hash_inside_encoded_token_is_not_a_comment(self):
        encoded = base64.b64encode('HELLO'.encode('utf-16le')).decode()
        for index, suffix in enumerate(('#junk', '<#junk#>')):
            invalid = self.source(f'invalid-{index}.ps1',
                                  f'powershell -enc {encoded}{suffix}\n'.encode())
            rows, warnings = powershell.inspect_powershell(invalid)
            self.assertEqual(rows, [])
            self.assertTrue(any('dynamic values unresolved' in warning for warning in warnings))
        for index, comment in enumerate(('# note', '<# note #>')):
            valid = self.source(f'valid-{index}.ps1',
                                f'powershell -enc {encoded} {comment}\n'.encode())
            rows, warnings = powershell.inspect_powershell(valid)
            self.assertEqual(warnings, [])
            self.assertTrue(any(row['data'] == b'HELLO' for row in rows))

    def test_limits_and_symlink_do_not_produce_unbounded_results(self):
        path = self.source('bounded.ps1', b"'ABC' + 'DEF'\n")
        self.assertEqual(powershell.inspect_powershell(path, max_source_bytes=2)[0], [])
        rows, warnings = powershell.inspect_powershell(path, max_output_bytes=3)
        self.assertEqual(rows, [])
        self.assertTrue(any('output byte limit' in warning for warning in warnings))
        link = self.root / 'link.ps1'
        link.symlink_to(path)
        self.assertEqual(powershell.inspect_powershell(link)[0], [])
        fifo = self.root / 'pipe.ps1'
        os.mkfifo(fifo)
        self.assertEqual(powershell.inspect_powershell(fifo)[0], [])
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

    def test_auto_routes_extensionless_command_but_comment_is_not_a_candidate(self):
        decoded = "Write-Output ('HELD' + 'OUT')"
        encoded = base64.b64encode(decoded.encode('utf-16le')).decode()
        path = self.source('command.txt', f'powershell -enc {encoded}\n'.encode())
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 'analyze', str(path), '--budget', '15',
                                 '--runs-root', str(self.root / 'runs')],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV11']['status'], 'ran')
        self.assertTrue(any(row['tag'] == 'REV11 PowerShell candidate' and
                            row['value'] == decoded for row in manifest['intelligence']))

        comment = self.source('comment.ps1',
                              f'# powershell -EncodedCommand {encoded}\n'.encode())
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 'analyze', str(comment), '--category', 'reversing',
                                 '--budget', '15', '--runs-root', str(self.root / 'negative')],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV11']['status'], 'no finding')
        self.assertFalse(any(row['tag'] == 'REV11 PowerShell candidate'
                             for row in manifest['intelligence']))

    def test_generic_reversing_text_does_not_become_a_powershell_candidate(self):
        for index, source in enumerate((b"ordinary note: 'alpha' + 'beta'\n",
                                        b"Article mentions FromBase64String and 'alpha' + 'beta'\n",
                                        b'Write-Output "powershell -enc SABFAEwATABPAA=="\n')):
            path = self.source(f'ordinary-{index}.txt', source)
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                     'analyze', str(path), '--category', 'reversing',
                                     '--budget', '15', '--runs-root', str(self.root / f'runs-{index}')],
                                    capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
            self.assertFalse(any(job['adapter_id'] == 'rev-powershell'
                                 for job in manifest['jobs']))
            self.assertFalse(any(row['tag'] == 'REV11 PowerShell candidate'
                                 for row in manifest['intelligence']))

    def test_dynamic_short_command_cli_is_truncated_not_no_finding(self):
        path = self.source('dynamic-command.ps1', b'powershell -enc $runtime\n')
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 'analyze', str(path), '--category', 'reversing',
                                 '--budget', '15', '--runs-root', str(self.root / 'runs')],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV11']['status'], 'truncated')
        self.assertFalse(any(row['tag'] == 'REV11 PowerShell candidate'
                             for row in manifest['intelligence']))

    def test_comment_only_extensionless_source_stays_out_of_auto_reversing(self):
        path = self.source('article.txt',
                           b'# powershell -enc SABFAEwATABPAA==\n'
                           b'# [Convert]::FromBase64String("SEVMTE8=")\n')
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 'analyze', str(path), '--budget', '15',
                                 '--runs-root', str(self.root / 'runs')],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertFalse(any(job['adapter_id'] == 'rev-powershell'
                             for job in manifest['jobs']))

    def test_path_qualified_commands_route_extensionless_text(self):
        decoded = "Write-Output 'PATH'"
        encoded = base64.b64encode(decoded.encode('utf-16le')).decode()
        commands = (
            r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc ',
            r'"C:\Program Files\PowerShell\7\pwsh.exe" -enc ',
            r'& "C:\Program Files\PowerShell\7\pwsh.exe" -enc ',
        )
        for index, command in enumerate(commands):
            path = self.source(f'path-{index}.txt', f'{command}{encoded}\n'.encode())
            for category in ('auto', 'reversing'):
                args = [] if category == 'auto' else ['--category', 'reversing']
                result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                         'analyze', str(path), *args, '--budget', '15',
                                         '--runs-root', str(self.root / f'runs-{index}-{category}')],
                                        capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
                manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
                self.assertEqual(manifest['coverage']['REV11']['status'], 'ran')
                self.assertTrue(any(row['tag'] == 'REV11 PowerShell candidate' and
                                    row['value'] == decoded for row in manifest['intelligence']))


if __name__ == '__main__':
    unittest.main()
