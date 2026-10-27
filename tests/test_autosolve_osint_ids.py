import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib import core
from scripts.autosolve_lib.profiles.osint_ids import extract_identifiers


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class IdentifierExtractionTests(unittest.TestCase):
    def test_document_clues_have_exact_byte_spans_and_ambiguity(self):
        source = (b"Brief: https://maps.example.org/place?q=7, then email lead@example.org; "
                  b"handle @map_reader; GPS: -12.34567, 103.45678.\n")
        before = bytes(source)
        records, warnings = extract_identifiers(source)
        self.assertEqual(warnings, [])
        self.assertEqual([row['kind'] for row in records],
                         ['url', 'email', 'handle', 'coordinates'])
        self.assertEqual([row['value'] for row in records], [
            'https://maps.example.org/place?q=7', 'lead@example.org',
            '@map_reader', '-12.34567, 103.45678'])
        for row in records:
            self.assertEqual(source[row['byte_offset']:row['byte_offset'] + row['byte_length']],
                             row['value'].encode('ascii'))
            self.assertIn('unverified', row['ambiguity'])
            self.assertIn(str(row['byte_offset']), row['locator'])
        self.assertEqual(source, before)

    def test_utf8_delimiters_and_utf16_bom_keep_offsets(self):
        for source, encoding, prefix in (
            ('café: “https://example.net/über” and @river_7'.encode('utf-8'),
             'utf-8', b'https://example.net/'),
            ('Δ😀: @river_7 | contact@example.net'.encode('utf-16-le'),
             'utf-16-le', '@river_7'.encode('utf-16-le')),
        ):
            if encoding == 'utf-16-le':
                source = b'\xff\xfe' + source
            with self.subTest(encoding=encoding):
                records, warnings = extract_identifiers(source)
                self.assertEqual(warnings, [])
                self.assertTrue(records)
                self.assertTrue(all(row['encoding'] == encoding for row in records))
                self.assertEqual(records[0]['byte_offset'], source.index(prefix))
                for row in records:
                    raw = source[row['byte_offset']:row['byte_offset'] + row['byte_length']]
                    self.assertEqual(raw.decode('utf-16-le' if encoding == 'utf-16-le'
                                                else 'utf-8'), row['value'])

    def test_random_patterns_do_not_create_strong_clues(self):
        source = (b"http://not-a-domain @123456 9.999, 999.999 "
                  b"abc@example invalid@example.c 192.168.1.1 "
                  b"https://user:pass@example.org/private "
                  b"90.001, 100.000 45.000, 180.001 "
                  b"https://example.org\x00secret https://@example.org foo@-bad.org "
                  b"lead@" + b"a." * 200 + b"org")
        records, warnings = extract_identifiers(source)
        self.assertEqual(warnings, [])
        self.assertEqual(records, [])

    def test_repeated_occurrences_and_limits_are_explicit(self):
        source = b'@alpha_1 @alpha_1 @alpha_1 https://example.org'
        records, warnings = extract_identifiers(source, max_records=2)
        self.assertEqual([row['byte_offset'] for row in records], [0, 9])
        self.assertTrue(any('record limit' in warning for warning in warnings))
        records, warnings = extract_identifiers(source, max_bytes=11)
        self.assertEqual([row['value'] for row in records], ['@alpha_1'])
        self.assertTrue(any('first 11 bytes' in warning for warning in warnings))
        records, warnings = extract_identifiers(b'https://example.org/unfinished', max_bytes=19)
        self.assertEqual(records, [])
        self.assertTrue(warnings)
        prefix = b'https://example.org/@guide_9'
        records, _ = extract_identifiers(prefix + b'_more', max_bytes=len(prefix))
        self.assertEqual(records, [])
        with self.assertRaises(ValueError):
            extract_identifiers(source, max_records=0)
        with self.assertRaises(ValueError):
            extract_identifiers(source, max_bytes=0)

    def test_utf16_be_and_invalid_text_are_labeled(self):
        source = b'\xfe\xff' + '名😀: https://example.org/路 @guide_9'.encode('utf-16-be')
        records, warnings = extract_identifiers(source)
        self.assertEqual(warnings, [])
        self.assertEqual([row['kind'] for row in records], ['url', 'handle'])
        for row in records:
            self.assertEqual(source[row['byte_offset']:row['byte_offset'] + row['byte_length']]
                             .decode('utf-16-be'), row['value'])
            self.assertEqual(row['encoding'], 'utf-16-be')
        records, warnings = extract_identifiers(b'\xff\xfe\x00')
        self.assertEqual(records, [])
        self.assertTrue(any('invalid BOM-marked UTF-16' in item for item in warnings))
        records, warnings = extract_identifiers(b'\xff @guide_9')
        self.assertEqual(records[0]['encoding'], 'latin-1')
        self.assertEqual(records[0]['byte_offset'], 2)
        self.assertEqual(warnings, [])


class IdentifierRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args):
        result = subprocess.run([sys.executable, str(SCRIPT), '--json', *map(str, args)],
                                capture_output=True, text=True, timeout=45)
        self.assertIn(result.returncode, (0, 3), result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_expired_publication_budget_does_not_claim_source_changed(self):
        source = self.root / 'stable.txt'
        source.write_text('Visit https://example.org/stable', encoding='utf-8')
        (self.root / 'jobs').mkdir()
        artifact = {'id': 'stable', 'path': str(source),
                    'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        manifest = {'current_adapter_fingerprints': {'osint-ids': ['test']},
                    'jobs': [], 'intelligence': [], 'warnings': [],
                    'coverage': {'OS02': {'status': 'not scheduled'}}}
        record = {'kind': 'url', 'value': 'https://example.org/stable',
                  'ambiguity': 'URL pattern only; destination unverified',
                  'byte_offset': 6, 'byte_length': 26, 'encoding': 'utf-8'}

        with patch.object(core, '_run_osint_ids', return_value=([record], [])):
            core._osint_ids_job(self.root, manifest, artifact, time.monotonic() - 1)

        self.assertEqual(manifest['coverage']['OS02']['status'], 'truncated')
        self.assertEqual(manifest['intelligence'], [])
        self.assertTrue(any('identity incomplete' in warning for warning in manifest['warnings']))
        self.assertFalse(any('source changed' in warning for warning in manifest['warnings']))

    def test_changed_source_is_rejected_before_clue_publication(self):
        source = self.root / 'changed.txt'
        source.write_text('Visit https://example.org/old', encoding='utf-8')
        (self.root / 'jobs').mkdir()
        artifact = {'id': 'changed', 'path': str(source),
                    'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        manifest = {'current_adapter_fingerprints': {'osint-ids': ['test']},
                    'jobs': [], 'intelligence': [], 'warnings': [],
                    'coverage': {'OS02': {'status': 'not scheduled'}}}

        def change_source(*_args):
            source.write_text('Visit https://example.org/new', encoding='utf-8')
            return [], []

        with patch.object(core, '_run_osint_ids', side_effect=change_source):
            core._osint_ids_job(self.root, manifest, artifact, time.monotonic() + 5)

        self.assertEqual(manifest['coverage']['OS02']['status'], 'failed')
        self.assertEqual(manifest['intelligence'], [])
        self.assertTrue(any('source changed before publication' in warning
                            for warning in manifest['warnings']))

    def test_public_cli_source_and_derived_text_are_clues(self):
        source = self.root / 'clues.txt'
        source.write_bytes(b'Visit https://example.org/map and @guide_9; GPS 12.3456, 78.9012')
        compressed = self.root / 'attachments.zip'
        with zipfile.ZipFile(compressed, 'w') as archive:
            archive.writestr('inside.txt', b'Contact field@example.net')
        result = self.cli('analyze', self.root, '--category', 'osint',
                          '--budget', 30, '--runs-root', self.root / 'runs')
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        self.assertIn('unverified', (Path(result['run']) / 'report.md').read_text())
        clues = [row for row in manifest['intelligence'] if row['tag'] == 'OSINT clue' and row['current']]
        self.assertEqual(manifest['coverage']['OS02']['status'], 'ran')
        self.assertEqual({row['value'] for row in clues},
                         {'https://example.org/map', '@guide_9', '12.3456, 78.9012',
                          'field@example.net'})
        by_id = {row['id']: row for row in manifest['artifacts']}
        self.assertTrue(any(by_id[row['artifact_id']]['depth'] > 0 for row in clues))
        for row in clues:
            locator = row['source_locator']
            artifact = by_id[row['artifact_id']]
            data = Path(artifact['path']).read_bytes()
            self.assertEqual(data[locator['byte_offset']:locator['byte_offset'] +
                                  locator['byte_length']].decode(locator['encoding']), row['value'])
            self.assertIn('unverified', row['ambiguity'])

    def test_resume_supersedes_clues_from_changed_source(self):
        source = self.root / 'clues.txt'
        source.write_text('Look at https://example.org/old', encoding='utf-8')
        result = self.cli('analyze', source, '--category', 'osint', '--budget', 20,
                          '--runs-root', self.root / 'runs')
        source.write_text('Look at https://example.org/new', encoding='utf-8')
        self.cli('resume', result['run'], '--budget', 20)
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        clues = [row for row in manifest['intelligence'] if row['tag'] == 'OSINT clue']
        self.assertEqual([(row['value'], row['current']) for row in clues],
                         [('https://example.org/old', False),
                          ('https://example.org/new', True)])

    def test_unchanged_resume_reuses_clue_job_without_duplicates(self):
        source = self.root / 'clues.txt'
        source.write_text('Visit https://example.org/stable', encoding='utf-8')
        result = self.cli('analyze', source, '--category', 'osint', '--budget', 20,
                          '--runs-root', self.root / 'runs')
        self.cli('resume', result['run'], '--budget', 20)
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        clues = [row for row in manifest['intelligence'] if row['tag'] == 'OSINT clue']
        jobs = [row for row in manifest['jobs'] if row['adapter_id'] == 'osint-ids']
        self.assertEqual(len(clues), 1)
        self.assertTrue(clues[0]['current'])
        self.assertEqual(len(jobs), 1)

    def test_doctor_probes_local_extraction_without_claiming_external_lookup(self):
        result = self.cli('doctor', '--profiles', 'osint', '--self-test')
        self.assertEqual(result['operations']['osint.identifiers']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['osint.identifiers']['status'], 'ready')
        self.assertEqual(result['engines']['pywhat']['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
