import sqlite3
import hashlib
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.os_artifacts import inspect_os_artifact


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class OsArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'renamed-evidence'

    def history(self, *, title=True):
        with sqlite3.connect(self.path) as db:
            db.execute(f"CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT{', title TEXT' if title else ''})")
            db.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
            db.execute("INSERT INTO urls VALUES (?, ?%s)" % (", ?" if title else ""),
                       (7, 'https://example.test/path', 'Page') if title else
                       (7, 'https://example.test/path'))
            db.execute("INSERT INTO visits VALUES (11, 7, 13253760000000000)")
            db.execute("INSERT INTO visits VALUES (12, 404, 13253763600000000)")

    def firefox_history(self):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
            db.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)")
            db.execute("INSERT INTO moz_places VALUES (9, 'https://firefox.example/visit', 'Fox')")
            db.execute("INSERT INTO moz_historyvisits VALUES (17, 9, 1793102400123456)")
            db.execute("INSERT INTO moz_historyvisits VALUES (18, 404, 1793102401123456)")

    def test_firefox_visit_source_time_and_missing_place(self):
        self.firefox_history()
        original = self.path.read_bytes()
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(warnings, [])
        self.assertEqual([item['locator'] for item in records],
                         ['moz_historyvisits id 17', 'moz_historyvisits id 18'])
        self.assertEqual(records[0]['source'], str(self.path))
        self.assertEqual(records[0]['url'], 'https://firefox.example/visit')
        self.assertEqual(records[0]['title'], 'Fox')
        self.assertEqual(records[0]['timestamp'], '2026-10-27T12:00:00.123456Z')
        self.assertEqual(records[0]['timestamp_basis'], 'Firefox microseconds since 1970 UTC')
        self.assertEqual(records[0]['url_id'], 9)
        self.assertIsNone(records[1]['url'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_firefox_partial_schema_and_invalid_time_withhold_claim(self):
        self.firefox_history()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO moz_historyvisits VALUES (19, 9, 'not-a-time')")
        records, warnings = inspect_os_artifact(self.path)
        self.assertIsNone(records[2]['timestamp'])
        self.assertTrue(any('unsupported visit_date' in note for note in warnings))
        with sqlite3.connect(self.path) as db:
            db.execute('DROP TABLE moz_places')
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(records, [])
        self.assertTrue(any('Firefox' in note and 'absent' in note for note in warnings))

    def test_long_browser_urls_are_incomplete_for_both_schemas(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        prefix = 'https://history.example/'
        url = prefix + 'a' * (2048 - len(prefix)) + 'different-tail'
        for browser, table, key, captured in (
                ('Chromium', 'urls', 7, '2020-12-30T00:01:00Z'),
                ('Firefox', 'moz_places', 9, '2026-10-27T12:01:00Z')):
            with self.subTest(browser=browser):
                if self.path.exists():
                    self.path.unlink()
                self.history() if browser == 'Chromium' else self.firefox_history()
                with sqlite3.connect(self.path) as db:
                    db.execute(f'UPDATE {table} SET url=? WHERE id=?', (url, key))
                records, warnings = inspect_os_artifact(self.path)
                visit = records[0]
                self.assertEqual(visit['url'], url[:2048])
                self.assertTrue(visit['url_truncated'])
                self.assertTrue(any('URL truncated' in note for note in warnings))
                page = self.root / 'snapshot.html'
                data = (f'<meta name="source-url" content="{url[:2048]}">'
                        f'<article data-captured="{captured}">Note</article>').encode()
                page.write_bytes(data)
                source = {'artifact_id': 'snapshot', 'source_name': 'snapshot.html',
                          'path': page, 'sha256': hashlib.sha256(data).hexdigest()}
                rows, _ = build_snapshot_trail([source], browser_visits=[visit])
                self.assertFalse(any(row['kind'] == 'browser_snapshot_relation' for row in rows))

    def test_long_browser_titles_are_explicit_for_both_schemas(self):
        for browser, table, key in (('Chromium', 'urls', 7), ('Firefox', 'moz_places', 9)):
            with self.subTest(browser=browser):
                if self.path.exists():
                    self.path.unlink()
                self.history() if browser == 'Chromium' else self.firefox_history()
                with sqlite3.connect(self.path) as db:
                    db.execute(f'UPDATE {table} SET title=? WHERE id=?', ('T' * 520, key))
                original = self.path.read_bytes()
                records, warnings = inspect_os_artifact(self.path)
                self.assertEqual(records[0]['title'], 'T' * 512)
                self.assertTrue(records[0]['title_truncated'])
                self.assertFalse(records[0]['url_truncated'])
                self.assertEqual(sum('title truncated' in note for note in warnings), 1)
                self.assertEqual(self.path.read_bytes(), original)
                with sqlite3.connect(self.path) as db:
                    db.execute(f'UPDATE {table} SET title=? WHERE id=?', ('T' * 512, key))
                records, warnings = inspect_os_artifact(self.path)
                self.assertEqual(records[0]['title'], 'T' * 512)
                self.assertFalse(records[0]['title_truncated'])
                self.assertFalse(any('title truncated' in note for note in warnings))

    def test_browser_visit_source_time_and_missing_url(self):
        self.history()
        original = self.path.read_bytes()
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(warnings, [])
        self.assertEqual([item['locator'] for item in records], ['visits id 11', 'visits id 12'])
        self.assertEqual(records[0]['source'], str(self.path))
        self.assertEqual(records[0]['timestamp'], '2020-12-30T00:00:00Z')
        self.assertEqual(records[0]['timestamp_basis'], 'Chromium microseconds since 1601 UTC')
        self.assertEqual(records[0]['url'], 'https://example.test/path')
        self.assertIsNone(records[1]['url'])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_held_out_schema_and_invalid_time_are_explicit(self):
        self.history(title=False)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO visits VALUES (13, 7, 'not-a-time')")
        records, warnings = inspect_os_artifact(self.path, max_records=10)
        self.assertEqual(records[0]['title'], None)
        self.assertEqual(records[2]['timestamp'], None)
        self.assertTrue(any('unsupported visit_time' in item for item in warnings))
        limited, warnings = inspect_os_artifact(self.path, max_records=1)
        self.assertEqual(len(limited), 1)
        self.assertTrue(any('record limit' in item for item in warnings))

    def test_corrupt_schema_wal_and_limits(self):
        self.path.write_bytes(b'SQLite format 3\x00' + b'bad')
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(records, [])
        self.assertTrue(any('parse failed' in item for item in warnings))
        self.path.unlink()
        self.history()
        self.path.with_name(self.path.name + '-wal').write_bytes(b'unread WAL')
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(len(records), 2)
        self.assertTrue(any('WAL not read' in item for item in warnings))
        self.assertEqual(inspect_os_artifact(self.path, max_bytes=4)[0], [])
        with self.assertRaises(ValueError):
            inspect_os_artifact(self.path, max_records=0)

    def test_unsupported_evtx_and_registry_do_not_fabricate_records(self):
        self.path.write_bytes(b'ElfFile\x00' + b'\x00' * 32)
        with patch.dict('sys.modules', {'Evtx': None}):
            records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(records, [])
        self.assertTrue(any('unavailable' in item for item in warnings))
        self.path.write_bytes(b'regf' + b'\x00' * 32)
        records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(records, [])
        self.assertTrue(any('parse failed' in item for item in warnings))

    def test_evtx_partial_chunk_and_record_warn_without_events(self):
        from types import ModuleType

        class EmptyLog:
            def __init__(self, path):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def records(self):
                return iter(())

        package = ModuleType('Evtx')
        module = ModuleType('Evtx.Evtx')
        module.Evtx = EmptyLog
        with patch.dict(sys.modules, {'Evtx': package, 'Evtx.Evtx': module}):
            data = bytearray(5000)
            data[:8] = b'ElfFile\x00'
            data[0x28:0x2c] = b'\x00\x10\x01\x00'
            data[4096:4104] = b'ElfChnk\x00'
            data[4608:4616] = b'\x2a\x2a\x00\x00\x80\x08\x00\x00'
            self.path.write_bytes(data)
            records, warnings = inspect_os_artifact(self.path)
            self.assertEqual(records, [])
            self.assertTrue(any('EVTX truncated' in note and 'record' in note for note in warnings))
            second = bytearray(7500)
            second[:len(data)] = data
            second[6784:6792] = b'\x2a\x2a\x00\x00\x20\x05\x00\x00'
            self.path.write_bytes(second)
            records, warnings = inspect_os_artifact(self.path)
            self.assertEqual(records, [])
            self.assertTrue(any('EVTX truncated record at offset 6784' in note for note in warnings))
            self.path.write_bytes(b'ElfFile\x00' + b'\x00' * (4096 - 8))
            self.assertEqual(inspect_os_artifact(self.path), ([], []))

    def test_evtx_record_number_offset_and_time_from_parser(self):
        data = bytearray(4096 + 65536)
        data[:8] = b'ElfFile\x00'
        data[0x28:0x2c] = b'\x00\x10\x01\x00'
        data[4096:4104] = b'ElfChnk\x00'
        self.path.write_bytes(data)

        class Record:
            def xml(self):
                return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                        '<System><Provider Name="Example"/><EventID>42</EventID></System></Event>')

            def record_num(self):
                return 9

            def offset(self):
                return 8192

            def timestamp(self):
                return datetime(2024, 2, 3, 4, 5, tzinfo=timezone.utc)

        class Issue38Record(Record):
            def xml(self):
                return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                        '<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
                        '<EventID>4672</EventID><EventRecordID>17845</EventRecordID>'
                        '<TimeCreated SystemTime="2017-06-23T05:31:19.787263200Z"/>'
                        '</System></Event>')

            def record_num(self):
                return 1

            def offset(self):
                return 4608

            def timestamp(self):
                return datetime(2017, 6, 23, 5, 31, 44, 420743, tzinfo=timezone.utc)

        class InvalidTimeRecord(Record):
            def xml(self):
                return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                        '<System><EventID>42</EventID><TimeCreated SystemTime="invalid"/>'
                        '</System></Event>')

        class OverflowTimeRecord(Record):
            def xml(self):
                return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                        '<System><EventID>42</EventID>'
                        '<TimeCreated SystemTime="0001-01-01T00:00:00+01:00"/>'
                        '</System></Event>')

        class Log:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def records(self):
                yield Record()
                yield Issue38Record()
                yield InvalidTimeRecord()
                yield OverflowTimeRecord()

        import sys
        from types import ModuleType
        package = ModuleType('Evtx')
        module = ModuleType('Evtx.Evtx')
        module.Evtx = Log
        with patch.dict(sys.modules, {'Evtx': package, 'Evtx.Evtx': module}):
            records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(warnings, ['record 9: invalid System TimeCreated'] * 2)
        self.assertEqual(records[0]['locator'], 'record 9 offset 8192')
        self.assertEqual(records[0]['timestamp'], '2024-02-03T04:05:00Z')
        self.assertEqual(records[0]['event_id'], '42')
        self.assertIsNone(records[0]['event_record_id'])
        self.assertIsNone(records[0]['xml_timestamp'])
        issue38 = records[1]
        self.assertEqual(issue38['locator'], 'record 1 offset 4608')
        self.assertEqual(issue38['record_number_basis'], 'EVTX record header')
        self.assertEqual(issue38['event_record_id'], 17845)
        self.assertEqual(issue38['timestamp'], '2017-06-23T05:31:44.420743Z')
        self.assertEqual(issue38['timestamp_basis'], 'EVTX record FILETIME UTC')
        self.assertEqual(issue38['header_timestamp'], issue38['timestamp'])
        self.assertEqual(issue38['header_timestamp_basis'], issue38['timestamp_basis'])
        self.assertEqual(issue38['system_time_raw'], '2017-06-23T05:31:19.787263200Z')
        self.assertEqual(issue38['xml_timestamp'], '2017-06-23T05:31:19.787263Z')
        self.assertEqual(issue38['xml_timestamp_basis'], 'Event.System.TimeCreated.SystemTime UTC')
        self.assertNotEqual(issue38['timestamp'], issue38['xml_timestamp'])
        self.assertIsNone(records[2]['xml_timestamp'])
        self.assertIsNone(records[3]['xml_timestamp'])

    def test_registry_key_timestamp_and_binary_value_basis(self):
        self.path.write_bytes(b'regf' + b'\x00' * 4096)

        class Value:
            def name(self):
                return 'payload'

            def value_type_str(self):
                return 'RegBin'

            def value(self):
                return b'\x00\xff'

        class Key:
            def path(self):
                return r'ROOT\Software\Example'

            def timestamp(self):
                return datetime(2023, 6, 7, 8, 9)

            def values(self):
                return [Value()]

            def values_number(self):
                return 1

            def subkeys(self):
                return []

        class Hive:
            def __init__(self, stream):
                self.data = stream.read()

            def root(self):
                return Key()

        with patch('Registry.Registry.Registry', Hive):
            records, warnings = inspect_os_artifact(self.path)
        self.assertEqual(warnings, [])
        self.assertEqual(records[0]['locator'], r'ROOT\Software\Example')
        self.assertEqual(records[0]['timestamp'], '2023-06-07T08:09:00Z')
        self.assertEqual(records[0]['values'][0]['value'], {
            'bytes': 2, 'sha256': hashlib.sha256(b'\x00\xff').hexdigest(),
            'prefix_base64': base64.b64encode(b'\x00\xff').decode(), 'truncated': False})

    def test_evtx_issue38_intelligence_keeps_header_and_xml_provenance(self):
        from scripts.autosolve_lib import core
        import time

        self.path.write_bytes(b'ElfFile\x00' + b'\x00' * 32)
        run = self.root / 'run'
        (run / 'jobs').mkdir(parents=True)
        artifact = {'id': 'source', 'path': str(self.path), 'kind_evidence': 'evtx',
                    'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest(),
                    'size': self.path.stat().st_size, 'current': True, 'depth': 0,
                    'source_locator': {'path': str(self.path)}}
        manifest = {'status': 'partial', 'jobs': [], 'artifacts': [artifact],
                    'findings': [], 'intelligence': [], 'warnings': [],
                    'coverage': {'DF03': {'status': 'not scheduled'}}}
        record = {'kind': 'evtx_event', 'source': str(self.path),
                  'locator': 'record 1 offset 4608', 'record_number': 1,
                  'event_record_id': 17845, 'event_id': '4672',
                  'provider': 'Microsoft-Windows-Security-Auditing',
                  'timestamp': '2017-06-23T05:31:44.420744Z',
                  'timestamp_basis': 'EVTX record FILETIME UTC',
                  'system_time_raw': '2017-06-23 05:31:19.787264+00:00',
                  'xml_timestamp': '2017-06-23T05:31:19.787264Z',
                  'xml_timestamp_basis': 'Event.System.TimeCreated.SystemTime UTC'}
        with patch.object(core, '_run_os_artifact', return_value=([record], [])):
            core._os_artifact_job(run, manifest, artifact, time.monotonic() + 30)
        self.assertEqual(manifest['jobs'][0]['status'], 'complete')
        lead = manifest['intelligence'][0]
        locator = lead['source_locator']
        self.assertEqual(locator['record'], record['locator'])
        self.assertEqual(locator['time'], record['timestamp'])
        self.assertEqual(locator['time_basis'], record['timestamp_basis'])
        self.assertEqual(locator['event_record_id'], 17845)
        self.assertEqual(locator['xml_time'], record['xml_timestamp'])
        self.assertEqual(locator['xml_time_basis'], record['xml_timestamp_basis'])
        self.assertEqual(locator['system_time_raw'], record['system_time_raw'])
        core._render_report(run, manifest)
        report = (run / 'report.md').read_text()
        for value in ('XML record ID 17845', record['timestamp'], record['timestamp_basis'],
                      record['xml_timestamp'], record['xml_timestamp_basis'],
                      record['system_time_raw']):
            self.assertIn(value, report)

    def test_public_cli_source_linked_browser_job_and_resume(self):
        self.history()
        original = hashlib.sha256(self.path.read_bytes()).hexdigest()
        command = [sys.executable, '-B', str(SCRIPT), '--json', 'analyze', str(self.path),
                   '--category', 'disk_memory', '--runs-root', str(self.root / 'runs'),
                   '--budget', '30']
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [item for item in manifest['jobs'] if item['adapter_id'] == 'os-artifact']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertEqual([item['locator'] for item in records], ['visits id 11', 'visits id 12'])
        self.assertEqual(manifest['coverage']['DF03']['status'], 'ran')
        self.assertTrue(any(item['tag'] == 'OS artifact' and item['current'] and
                            item['source_locator']['record'] == 'visits id 11'
                            for item in manifest['intelligence']))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), original)
        resumed = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', 'resume',
                                  str(run), '--budget', '30'], capture_output=True,
                                 text=True, timeout=45)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([item for item in after['jobs']
                              if item['adapter_id'] == 'os-artifact']), 1)
        self.path.with_name(self.path.name + '-wal').write_bytes(b'unread companion')
        changed = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', 'resume',
                                  str(run), '--budget', '30'], capture_output=True,
                                 text=True, timeout=45)
        self.assertEqual(changed.returncode, 3, changed.stderr + changed.stdout)
        refreshed = json.loads((run / 'manifest.json').read_text())
        os_jobs = [item for item in refreshed['jobs'] if item['adapter_id'] == 'os-artifact']
        self.assertEqual(len(os_jobs), 2)
        self.assertEqual(refreshed['coverage']['DF03']['status'], 'truncated')
        self.assertTrue(any('browser WAL not read' in item for item in refreshed['warnings']))
        self.assertFalse(any(item['current'] for item in refreshed['intelligence']
                             if item['tag'] == 'OS artifact' and item['job_id'] == os_jobs[0]['id']))
        self.assertTrue(any(item['current'] for item in refreshed['intelligence']
                            if item['tag'] == 'OS artifact' and item['job_id'] == os_jobs[1]['id']))

    def test_public_cli_firefox_visit_and_source_change(self):
        self.firefox_history()
        runs_root = self.root / 'runs'
        command = [sys.executable, '-B', str(SCRIPT), '--json', 'analyze', str(self.path),
                   '--category', 'disk_memory', '--runs-root', str(runs_root), '--budget', '30']
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [item for item in manifest['jobs'] if item['adapter_id'] == 'os-artifact']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['coverage_status'], 'ran')
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertEqual(records[0]['locator'], 'moz_historyvisits id 17')
        self.assertEqual(records[0]['url'], 'https://firefox.example/visit')
        self.assertTrue(any(item['current'] and item['job_id'] == jobs[0]['id'] and
                            item['source_locator']['record'] == records[0]['locator']
                            for item in manifest['intelligence'] if item['tag'] == 'OS artifact'))
        resume = [sys.executable, '-B', str(SCRIPT), '--json', 'resume', str(run), '--budget', '30']
        unchanged = subprocess.run(resume, capture_output=True, text=True, timeout=45)
        self.assertEqual(unchanged.returncode, 3, unchanged.stderr + unchanged.stdout)
        same = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([item for item in same['jobs'] if item['adapter_id'] == 'os-artifact']), 1)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO moz_historyvisits VALUES (19, 9, 1793102402123456)")
        changed = subprocess.run(resume, capture_output=True, text=True, timeout=45)
        self.assertEqual(changed.returncode, 3, changed.stderr + changed.stdout)
        refreshed = json.loads((run / 'manifest.json').read_text())
        jobs = [item for item in refreshed['jobs'] if item['adapter_id'] == 'os-artifact']
        self.assertEqual(len(jobs), 2)
        self.assertTrue(any(item['current'] and item['job_id'] == jobs[1]['id']
                            for item in refreshed['intelligence'] if item['tag'] == 'OS artifact'))
        self.assertFalse(any(item['current'] and item['job_id'] == jobs[0]['id']
                             for item in refreshed['intelligence'] if item['tag'] == 'OS artifact'))

    def test_extracted_sqlite_has_companion_identity_before_browser_records(self):
        from scripts.autosolve_lib.core import _os_artifact_job
        import time

        self.history()
        run = self.root / 'run'
        (run / 'jobs').mkdir(parents=True)
        artifact = {'id': 'derived-history', 'path': str(self.path), 'kind_evidence': 'sqlite',
                    'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest()}
        manifest = {'jobs': [], 'intelligence': [], 'warnings': [],
                    'coverage': {'DF03': {'status': 'no finding', 'note': ''}},
                    'sqlite_companions': {}}
        _os_artifact_job(run, manifest, artifact, time.monotonic() + 30)
        self.assertEqual(manifest['coverage']['DF03']['status'], 'ran')
        self.assertEqual(manifest['jobs'][0]['status'], 'complete')
        self.assertTrue(manifest['sqlite_companions'].get(artifact['id']))


if __name__ == '__main__':
    unittest.main()
