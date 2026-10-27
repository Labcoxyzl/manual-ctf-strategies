import sqlite3
import hashlib
import base64
import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.os_artifacts import inspect_os_artifact
from scripts.autosolve_lib import core


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

    def test_evtx_record_number_offset_and_time_from_parser(self):
        self.path.write_bytes(b'ElfFile\x00' + b'\x00' * 32)

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

        class DivergentRecord(Record):
            def xml(self):
                return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                        '<System><Provider Name="Example"/><EventID>4625</EventID>'
                        '<EventRecordID>77</EventRecordID>'
                        '<TimeCreated SystemTime="2024-02-03T04:05:30.123Z"/>'
                        '</System></Event>')

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
                yield DivergentRecord()
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
        self.assertEqual(records[0]['event_record_id'], None)
        self.assertEqual(records[0]['timestamp_basis'], 'EVTX record FILETIME UTC')
        self.assertEqual(records[1]['record_number'], 9)
        self.assertEqual(records[1]['record_number_basis'], 'EVTX record header')
        self.assertEqual(records[1]['event_record_id'], 77)
        self.assertEqual(records[1]['timestamp'], '2024-02-03T04:05:30.123000Z')
        self.assertEqual(records[1]['timestamp_basis'], 'Event.System.TimeCreated.SystemTime UTC')
        self.assertEqual(records[1]['header_timestamp'], '2024-02-03T04:05:00Z')
        self.assertEqual(records[1]['system_time_raw'], '2024-02-03T04:05:30.123Z')
        self.assertEqual(records[2]['timestamp'], '2024-02-03T04:05:00Z')
        self.assertEqual(records[2]['timestamp_basis'], 'EVTX record FILETIME UTC')
        self.assertEqual(records[3]['timestamp'], '2024-02-03T04:05:00Z')
        self.assertEqual(records[3]['timestamp_basis'], 'EVTX record FILETIME UTC')

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

    def test_evtx_intelligence_keeps_xml_record_id(self):
        self.path.write_bytes(b'ElfFile\x00' + b'\x00' * 32)
        run = self.root / 'run'
        (run / 'jobs').mkdir(parents=True)
        artifact = {'id': 'source', 'path': str(self.path), 'kind_evidence': 'evtx',
                    'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest()}
        manifest = {'jobs': [], 'intelligence': [], 'warnings': [],
                    'coverage': {'DF03': {'status': 'not scheduled'}}}
        record = {'kind': 'evtx_event', 'source': str(self.path),
                  'locator': 'record 4 offset 8264', 'record_number': 4,
                  'event_record_id': 319457832, 'event_id': '4625', 'provider': 'Example',
                  'timestamp': '2016-06-29T15:24:36.685999Z',
                  'timestamp_basis': 'Event.System.TimeCreated.SystemTime UTC'}
        with patch.object(core, '_run_os_artifact', return_value=([record], [])):
            core._os_artifact_job(run, manifest, artifact, time.monotonic() + 30)
        self.assertEqual(manifest['jobs'][0]['status'], 'complete')
        lead = manifest['intelligence'][0]
        self.assertIn('XML record ID 319457832', lead['value'])
        self.assertEqual(lead['source_locator']['event_record_id'], 319457832)
        self.assertEqual(lead['source_locator']['record'], 'record 4 offset 8264')

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


if __name__ == '__main__':
    unittest.main()
