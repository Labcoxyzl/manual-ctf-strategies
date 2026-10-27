"""Independent offline OS03 snapshot and document-trail cases."""

import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.autosolve_lib.profiles.osint_ids import extract_identifiers
from scripts.autosolve_lib.profiles.web_static import inspect_web_static


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class SnapshotTrailTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def source(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        web_records = []
        if path.suffix.lower() in ('.html', '.htm', '.js', '.map'):
            web_records, web_warnings = inspect_web_static(path, source_name=name)
            self.assertEqual(web_warnings, [])
        identifier_records, identifier_warnings = extract_identifiers(content)
        self.assertEqual(identifier_warnings, [])
        return {'artifact_id': name, 'source_name': name, 'path': path,
                'sha256': hashlib.sha256(content).hexdigest(),
                'web_records': web_records, 'identifier_records': identifier_records}

    def test_browser_snapshot_relation_requires_explicit_matching_url_and_time(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        url = 'https://records.example.invalid/waterline/shift-c'
        page = self.source('capture/page.html',
                           (f'<meta name="source-url" content="{url}">'
                            '<article data-captured="2026-04-09T14:18:22+07:00">Note</article>').encode())
        visit = {'kind': 'browser_visit', 'source_artifact_id': 'history',
                 'source_name': 'profiles/default/History', 'locator': 'visits id 17',
                 'url': url, 'timestamp': '2026-04-09T07:11:22Z'}
        rows, warnings = build_snapshot_trail([page], browser_visits=[visit])
        self.assertEqual(warnings, [])
        relations = [row for row in rows if row['kind'] == 'browser_snapshot_relation']
        self.assertEqual(len(relations), 1)
        self.assertEqual(relations[0]['elapsed_seconds'], 420)
        self.assertEqual(relations[0]['browser_source_name'], 'profiles/default/History')
        self.assertEqual(relations[0]['browser_locator'], 'visits id 17')
        self.assertEqual(relations[0]['snapshot_timestamp'], '2026-04-09T07:18:22Z')
        self.assertEqual(page['path'].read_bytes()[relations[0]['source_offset']:
                                                     relations[0]['source_offset'] +
                                                     relations[0]['source_length']].decode(), url)
        for altered in ({**visit, 'url': url + '/other'},
                        {**visit, 'url_truncated': True},
                        {**visit, 'timestamp': '2026-04-09T07:10:21Z'},
                        {**visit, 'timestamp': None}):
            rows, _ = build_snapshot_trail([page], browser_visits=[altered])
            self.assertFalse(any(row['kind'] == 'browser_snapshot_relation' for row in rows))
        undated = self.source('capture/undated.html',
                              f'<meta name="source-url" content="{url}">'.encode())
        rows, _ = build_snapshot_trail([undated], browser_visits=[visit])
        self.assertFalse(any(row['kind'] == 'browser_snapshot_relation' for row in rows))

    def test_relation_currentness_requires_browser_artifact_and_job(self):
        from scripts.autosolve_lib.core import _refresh_current

        manifest = {
            'artifacts': [{'id': artifact_id, 'depth': 0, 'complete': True, 'parents': [],
                           'source_locator': {}, 'current': True}
                          for artifact_id in ('history', 'snapshot')],
            'jobs': [{'id': 'browser-job', 'adapter_id': 'os-artifact', 'status': 'complete',
                      'tool_fingerprint': 'browser-v1', 'input_ids': ['history'],
                      'data_fingerprints': {'sqlite_companions': None}},
                     {'id': 'snapshot-job', 'adapter_id': 'osint-snapshots',
                      'status': 'complete', 'tool_fingerprint': 'snapshot-v1',
                      'input_ids': ['snapshot'], 'data_fingerprints': {'scope_origin': None}}],
            'current_adapter_fingerprints': {'os-artifact': ['browser-v1'],
                                             'osint-snapshots': ['snapshot-v1']},
            'intelligence': [
                {'artifact_id': 'snapshot', 'job_id': 'snapshot-job', 'group': 'date',
                 'source_locator': {}, 'superseded': False},
                {'artifact_id': 'snapshot', 'job_id': 'snapshot-job',
                 'group': 'browser_snapshot_relation', 'superseded': False,
                 'source_locator': {'browser_artifact_id': 'history',
                                    'browser_job_id': 'browser-job'}}],
            'findings': []}
        _refresh_current(manifest, {'snapshot'})
        self.assertTrue(manifest['intelligence'][0]['current'])
        self.assertFalse(manifest['intelligence'][1]['current'])
        _refresh_current(manifest, {'history', 'snapshot'})
        self.assertTrue(manifest['intelligence'][1]['current'])
        manifest['current_adapter_fingerprints']['os-artifact'] = ['browser-v2']
        _refresh_current(manifest, {'history', 'snapshot'})
        self.assertFalse(manifest['intelligence'][1]['current'])
        self.assertTrue(manifest['intelligence'][0]['current'])

    def test_escaped_canonical_url_keeps_exact_source_span(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        url = 'https://records.example.invalid/page?x=1&y=2'
        raw_url = url.replace('&', '&amp;')
        page = self.source('capture/escaped.html',
                           (f'<link rel="canonical" href="{raw_url}">'
                            '<article data-captured="2026-04-09T07:18:22Z">Note</article>').encode())
        visit = {'kind': 'browser_visit', 'source_artifact_id': 'history',
                 'source_name': 'profiles/default/History', 'locator': 'visits id 17',
                 'url': url, 'timestamp': '2026-04-09T07:11:22Z'}
        rows, warnings = build_snapshot_trail([page], browser_visits=[visit])
        self.assertEqual(warnings, [])
        relation, = [row for row in rows if row['kind'] == 'browser_snapshot_relation']
        self.assertEqual(relation['value'], raw_url)
        self.assertEqual(relation['matched_url'], url)
        raw = page['path'].read_bytes()
        self.assertEqual(raw[relation['source_offset']:
                             relation['source_offset'] + relation['source_length']], raw_url.encode())
        wrong = {**visit, 'url': url.replace('y=2', 'y=3')}
        rows, _ = build_snapshot_trail([page], browser_visits=[wrong])
        self.assertFalse(any(row['kind'] == 'browser_snapshot_relation' for row in rows))

    def test_multi_page_links_comments_and_document_dates_keep_original_provenance(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        home = self.source('index.html',
                           b'<a href="docs/report.pdf">Report dated 2025-02-03</a>\n'
                           b'<!-- archive note: 2024-12-31 -->\n')
        second = self.source('pages/history.html',
                             b'<a href="../docs/report.pdf">Report 2025-02-03</a>\n')
        doc = self.source('docs/report.pdf', b'Published 2025-02-03. Contact https://example.org/map\n')
        sources = [second, doc, home]
        before = {row['source_name']: Path(row['path']).read_bytes() for row in sources}
        records, warnings = build_snapshot_trail(sources)

        self.assertEqual(warnings, [])
        links = [row for row in records if row['kind'] == 'local_link']
        self.assertEqual(len(links), 2)
        self.assertEqual({row['target_artifact_id'] for row in links}, {'docs/report.pdf'})
        self.assertTrue(all(row['relation'] == 'direct_link' for row in links))
        self.assertTrue(any(row['kind'] == 'comment' and 'archive note' in row['value']
                            for row in records))
        self.assertTrue(any(row['kind'] == 'url' and row['value'] == 'https://example.org/map'
                            for row in records))
        dates = [row for row in records if row['kind'] == 'date']
        self.assertEqual(len(dates), 4)
        self.assertTrue(any(row['value'] == '2025-02-03' and
                            row.get('inferred_target_artifact_id') == 'docs/report.pdf'
                            and row['relation'] == 'inferred_near_link' for row in dates))
        self.assertFalse(any(row['kind'] == 'date_conflict' for row in records))
        for row in records:
            source = next(item for item in sources if item['artifact_id'] == row['source_artifact_id'])
            raw = before[source['source_name']]
            self.assertEqual(raw[row['source_offset']:row['source_offset'] + row['source_length']],
                             row['value'].encode('utf-8'))
            self.assertEqual(row['source_name'], source['source_name'])
        self.assertEqual(before, {row['source_name']: Path(row['path']).read_bytes()
                                  for row in sources})

    def test_held_out_relative_paths_and_page_order(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        page = self.source('en/2025/news.html',
                           b'<a href="../../files/notice.txt#page=2">Notice 2025/07/09</a>\n')
        target = self.source('files/notice.txt', b'Notice issued 2025-07-09\n')
        for sources in ([page, target], [target, page]):
            with self.subTest(order=sources[0]['source_name']):
                records, warnings = build_snapshot_trail(sources)
                self.assertEqual(warnings, [])
                link = next(row for row in records if row['kind'] == 'local_link')
                self.assertEqual(link['target_artifact_id'], 'files/notice.txt')
                date = next(row for row in records if row['kind'] == 'date' and
                            row['source_artifact_id'] == page['artifact_id'])
                self.assertEqual(date['value'], '2025-07-09')
                self.assertEqual(date['inferred_target_artifact_id'], target['artifact_id'])

    def test_missing_link_and_conflicting_dates_are_clues_not_current_claims(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        a = self.source('a.html', b'<a href="report.pdf">Published 2025-01-02</a>\n'
                         b'<a href="missing.pdf">Missing evidence</a>\n')
        b = self.source('b.html', b'<a href="report.pdf">Published 2024-12-31</a>\n')
        report = self.source('report.pdf', b'Report title\n')
        records, warnings = build_snapshot_trail([a, b, report])

        self.assertEqual(warnings, [])
        missing = next(row for row in records if row['kind'] == 'missing_local_target')
        self.assertEqual(missing['value'], 'missing.pdf')
        conflict = next(row for row in records if row['kind'] == 'date_conflict')
        self.assertEqual(conflict['value'], 'report.pdf')
        self.assertEqual({claim['date'] for claim in conflict['claims']},
                         {'2025-01-02', '2024-12-31'})
        self.assertTrue(all(claim['relation'] == 'inferred_near_link' for claim in conflict['claims']))
        self.assertTrue(all('offline' in row['ambiguity'].lower() for row in records))
        self.assertFalse(any(row.get('current_live') for row in records))

    def test_link_date_disagrees_with_supplied_document_date(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        page = self.source('news.html', b'<a href="notice.txt">Notice 2025-03-01</a>\n')
        notice = self.source('notice.txt', b'Notice issued 2025-03-02\n')
        records, warnings = build_snapshot_trail([page, notice])

        self.assertEqual(warnings, [])
        conflict = next(row for row in records if row['kind'] == 'date_conflict')
        self.assertEqual(conflict['value'], 'notice.txt')
        self.assertEqual({claim['relation'] for claim in conflict['claims']},
                         {'inferred_near_link', 'inferred_document_date'})

    def test_changed_oversize_and_symlink_sources_do_not_publish_clues(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        changed = self.source('changed.html', b'<a href="safe.html">2025-01-01</a>')
        changed['path'].write_text('<a href="unsafe.html">2025-01-02</a>')
        oversized = self.source('large.txt', b'2025-01-03' + b'x' * 100)
        alias = self.source('alias.txt', b'2025-01-04')
        alias['path'].unlink()
        alias['path'].symlink_to(oversized['path'])
        records, warnings = build_snapshot_trail([changed, oversized, alias], max_file_bytes=32)

        self.assertEqual(records, [])
        self.assertTrue(any('changed' in warning for warning in warnings))
        self.assertTrue(any('byte limit' in warning for warning in warnings))
        self.assertTrue(any('regular file' in warning for warning in warnings))

    def test_link_does_not_resolve_to_changed_target(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        page = self.source('index.html', b'<a href="notice.txt">Notice 2025-03-01</a>')
        notice = self.source('notice.txt', b'Published 2025-03-01')
        notice['path'].write_text('changed')
        records, warnings = build_snapshot_trail([page, notice])

        self.assertTrue(any('changed' in warning for warning in warnings))
        self.assertFalse(any(row['kind'] == 'local_link' for row in records))
        self.assertTrue(any(row['kind'] == 'missing_local_target' for row in records))

    def test_duplicate_snapshot_names_remain_ambiguous(self):
        from scripts.autosolve_lib.profiles.osint_snapshots import build_snapshot_trail

        page = self.source('index.html', b'<a href="docs/report.txt">Report 2025-03-01</a>')
        first = self.source('a.txt', b'first')
        second = self.source('b.txt', b'second')
        first['source_name'] = second['source_name'] = 'docs/report.txt'
        records, warnings = build_snapshot_trail([page, first, second])

        self.assertEqual(warnings, [])
        self.assertTrue(any(row['kind'] == 'ambiguous_target' for row in records))
        self.assertFalse(any(row['kind'] in ('local_link', 'missing_local_target') for row in records))


class SnapshotRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def cli(self, *args):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 *map(str, args)], capture_output=True, text=True, timeout=60)
        self.assertIn(result.returncode, (0, 3), result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_public_cli_escaped_canonical_url_preserves_raw_locator(self):
        site = self.root / 'site'
        (site / 'capture').mkdir(parents=True)
        history = site / 'History'
        url = 'https://records.example.invalid/page?x=1&y=2'
        source_url = url.replace('&', '&amp;')
        with sqlite3.connect(history) as db:
            db.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)')
            db.execute('CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)')
            db.execute('INSERT INTO urls VALUES (?, ?)', (7, url))
            db.execute('INSERT INTO visits VALUES (?, ?, ?)', (17, 7, 13253760000000000))
        page = site / 'capture' / 'page.html'
        page.write_text(f'<link rel="canonical" href="{source_url}">'
                        '<article data-captured="2020-12-30T00:05:00Z">Note</article>')
        run = Path(self.cli('analyze', site, '--category', 'auto', '--budget', 30,
                            '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        relation, = [row for row in manifest['intelligence']
                     if row['group'] == 'browser_snapshot_relation' and row['current']]
        locator = relation['source_locator']
        self.assertEqual(locator['source_value'], source_url)
        self.assertEqual(locator['matched_url'], url)
        self.assertEqual(page.read_bytes()[locator['byte_offset']:
                                           locator['byte_offset'] + locator['byte_length']],
                         source_url.encode())
        self.assertIn('same HTML-decoded URL ' + url, relation['value'])
        self.assertIn('browser_snapshot_relation', (run / 'report.md').read_text())

    def test_public_cli_directory_resume_and_source_retirement(self):
        site = self.root / 'site'
        (site / 'docs').mkdir(parents=True)
        (site / 'index.html').write_text('<a href="docs/notice.txt">Notice 2025-03-01</a>'
                                         '<p>https://maps.example.org/area</p>')
        notice = site / 'docs/notice.txt'
        notice.write_text('Published 2025-03-02')
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'scope_origin': 'https://site.test'}))
        result = self.cli('analyze', site, '--category', 'osint', '--budget', 30,
                          '--hints', hints, '--runs-root', self.root / 'runs')
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'osint-snapshots']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(manifest['coverage']['OS03']['status'], 'ran')
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertEqual(next(row['target_name'] for row in records if row['kind'] == 'local_link'),
                         'docs/notice.txt')
        self.assertTrue(any(row['kind'] == 'date_conflict' for row in records))
        self.assertTrue(any(row['tag'] == 'OSINT clue' and
                            row['value'] == 'https://maps.example.org/area'
                            for row in manifest['intelligence']))
        report = (run / 'report.md').read_text()
        conflict_line = next(line for line in report.splitlines()
                             if 'OS03 trail' in line and 'date_conflict' in line)
        self.assertIn('2025-03-01', conflict_line)
        self.assertIn('2025-03-02', conflict_line)
        self.assertIn('byte_offset', conflict_line)
        self.assertNotIn('"claims"', conflict_line)
        self.assertLess(len(conflict_line), 384)

        self.cli('resume', run, '--hints', hints, '--budget', 30)
        same = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in same['jobs'] if job['adapter_id'] == 'osint-snapshots']), 1)
        hints.write_text(json.dumps({'scope_origin': 'https://other.test'}))
        self.cli('resume', run, '--hints', hints, '--budget', 0.001)
        rescoped = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(any(row['current'] for row in rescoped['intelligence']
                             if row['tag'] == 'OS03 trail' and row['job_id'] == jobs[0]['id']))
        notice.unlink()
        self.cli('resume', run, '--hints', hints, '--budget', 30)
        removed = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(any(row['current'] for row in removed['intelligence']
                             if row['tag'] == 'OS03 trail' and row['job_id'] == jobs[0]['id']))

    def test_public_cli_zip_bundle_and_doctor_probe(self):
        archive = self.root / 'site.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('pages/index.html',
                            '<a href="../docs/report.txt">Report 2025-06-01</a>')
            output.writestr('docs/report.txt', 'Issued 2025-06-01')
        result = self.cli('analyze', archive, '--category', 'osint', '--budget', 30,
                          '--runs-root', self.root / 'runs')
        manifest = json.loads((Path(result['run']) / 'manifest.json').read_text())
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'osint-snapshots']
        self.assertEqual(len(jobs), 1)
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertTrue(any(row['kind'] == 'local_link' and
                            row['target_name'] == 'docs/report.txt' for row in records))
        doctor = self.cli('doctor', '--profiles', 'osint', '--self-test')
        self.assertEqual(doctor['operations']['osint.snapshot_trail'],
                         {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'})


if __name__ == '__main__':
    unittest.main()
