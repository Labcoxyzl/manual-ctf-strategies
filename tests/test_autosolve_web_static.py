import json
import os
import hashlib
import subprocess
import sys
import zipfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.web_static import inspect_web_static


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class WebStaticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_html_forms_links_comments_and_inline_js_keep_source_offsets(self):
        path = self.root / 'page.html'
        content = ('<a href="/guide?lang=fr">guide</a>\n'
                   '<form method="post" action="submit"><input name="q"></form>\n'
                   '<!-- decoy /hidden -->\n'
                   '<script>fetch("/api/search?q=é");</script>\n'
                   '<a href="https://other.test/out">out</a>\n')
        path.write_text(content)
        with patch('urllib.request.urlopen', side_effect=AssertionError('network request')):
            records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(warnings, [])
        for kind, value, scope in (
            ('link', '/guide?lang=fr', 'same_origin'),
            ('form', 'submit', 'same_origin'),
            ('literal_endpoint', '/api/search?q=é', 'same_origin'),
            ('link', 'https://other.test/out', 'cross_origin'),
        ):
            row = next(item for item in records if item['kind'] == kind and item['value'] == value)
            self.assertEqual(row['scope'], scope)
            self.assertEqual(row['source'], str(path))
            self.assertEqual(content.encode().index(value.encode()), row['offset'])
            self.assertEqual(content[:content.index(value)].count('\n') + 1, row['line'])
        self.assertEqual(next(row['method'] for row in records if row['kind'] == 'form'), 'POST')
        self.assertTrue(any(row['kind'] == 'html_comment' and '/hidden' in row['value'] for row in records))
        self.assertFalse(any(row['kind'] == 'literal_endpoint' and row['value'] == '/hidden' for row in records))

    def test_minified_js_source_map_and_comment_decoy(self):
        js = self.root / 'bundle.js'
        js.write_text('const x="/é?q=1";fetch(x);// /comment-only\n//# sourceMappingURL=bundle.js.map\n')
        records, warnings = inspect_web_static(js)
        self.assertEqual(warnings, [])
        self.assertEqual(next(row['scope'] for row in records if row['value'] == '/é?q=1'), 'unknown_origin')
        self.assertTrue(any(row['kind'] == 'source_map_ref' and row['value'] == 'bundle.js.map'
                            for row in records))
        self.assertTrue(any(row['kind'] == 'js_comment' and '/comment-only' in row['value']
                            for row in records))
        self.assertFalse(any(row['value'] == '/comment-only' for row in records))

        source_map = self.root / 'bundle.js.map'
        source_map.write_text(json.dumps({'version': 3, 'sources': ['src/one.js'],
                                          'sourcesContent': ['fetch("/mapped?q=2")']}))
        records, warnings = inspect_web_static(source_map, origin='https://site.test')
        self.assertEqual(warnings, [])
        source = next(row for row in records if row['kind'] == 'source_map_source')
        self.assertEqual(source['value'], 'src/one.js')
        self.assertEqual(source_map.read_bytes()[source['offset']:source['offset'] + 1], b'"')
        mapped = next(row for row in records if row['value'] == '/mapped?q=2')
        self.assertEqual(mapped['kind'], 'literal_endpoint')
        self.assertEqual(mapped['scope'], 'same_origin')
        self.assertEqual(mapped['embedded_source'], 'src/one.js')
        self.assertEqual(mapped['embedded_offset'], len('fetch("'))
        self.assertIn('sourcesContent[0]', mapped['locator'])
        self.assertEqual(source_map.read_bytes()[mapped['offset']:mapped['offset'] + 1], b'/')

    def test_preserved_source_name_selects_js_parser_for_private_derived_file(self):
        path = self.root / 'sha256-content-name'
        path.write_text('fetch("/from-member")')
        records, warnings = inspect_web_static(path, source_name='bundle.js')
        self.assertEqual(warnings, [])
        self.assertEqual(next(row['value'] for row in records if row['kind'] == 'literal_endpoint'),
                         '/from-member')
        records, warnings = inspect_web_static(path)
        self.assertEqual(warnings, [])
        self.assertTrue(any(row['value'] == '/from-member' for row in records))

    def test_source_map_quoted_decoy_does_not_steal_provenance(self):
        path = self.root / 'odd.map'
        path.write_text(json.dumps({'noise': {'sources': ['fake.js']},
                                    'version': 3, 'sources': ['real.js'],
                                    'sourcesContent': ['fetch("/real")']}))
        records, warnings = inspect_web_static(path)
        self.assertEqual(warnings, [])
        source = next(row for row in records if row['kind'] == 'source_map_source')
        self.assertEqual(source['value'], 'real.js')
        self.assertEqual(path.read_bytes()[source['offset']:source['offset'] + 9], b'"real.js"')

    def test_external_html_base_reclassifies_relative_links(self):
        path = self.root / 'base.html'
        path.write_text('<a href="/before">first</a><base href="https://other.test/assets/">'
                        '<a href="after">second</a><form action="submit"></form>'
                        '<form action="\\\\site.test/submit"></form>'
                        '<form action="///site.test/submit"></form>')
        records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(warnings, [])
        self.assertEqual([row['scope'] for row in records if row['kind'] == 'link'],
                         ['cross_origin', 'cross_origin'])
        self.assertEqual([row['scope'] for row in records if row['kind'] == 'form'],
                         ['cross_origin', 'same_origin', 'same_origin'])

    def test_relative_form_urls_resolve_to_supplied_origin_only(self):
        path = self.root / 'forms.html'
        path.write_text(''.join(f'<form action="{action}"></form>' for action in (
            'submit', '../submit?q=é', '?next=1', '#section', '/submit',
            '//other.test/submit', 'javascript:alert(1)')))
        with patch('urllib.request.urlopen', side_effect=AssertionError('network request')):
            records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(warnings, [])
        self.assertEqual([(row['value'], row['scope']) for row in records], [
            ('submit', 'same_origin'), ('../submit?q=é', 'same_origin'),
            ('?next=1', 'same_origin'), ('#section', 'same_origin'),
            ('/submit', 'same_origin'), ('//other.test/submit', 'cross_origin'),
            ('javascript:alert(1)', 'non_http')])
        self.assertEqual([row['scope'] for row in inspect_web_static(path)[0][:5]],
                         ['relative', 'relative', 'relative', 'relative', 'unknown_origin'])
        for row in records:
            self.assertEqual(path.read_bytes()[row['offset']:row['offset'] + len(row['value'].encode())],
                             row['value'].encode())

    def test_browser_backslash_network_paths_are_not_same_origin(self):
        path = self.root / 'slashes.html'
        actions = (r'\\other.test/submit', r'/\other.test/submit',
                   r'\/other.test/submit', '///other.test/submit', r'\submit')
        path.write_text(''.join(f'<form action="{action}"></form>' for action in actions))
        records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(warnings, [])
        self.assertEqual([row['scope'] for row in records],
                         ['cross_origin', 'cross_origin', 'cross_origin', 'cross_origin',
                          'same_origin'])
        self.assertEqual([row['scope'] for row in inspect_web_static(path)[0]],
                         ['unknown_origin', 'unknown_origin', 'unknown_origin',
                          'unknown_origin', 'relative'])

    def test_absolute_port_zero_and_empty_network_paths_are_not_same_origin(self):
        path = self.root / 'ports.html'
        actions = ('https://site.test:0/submit', 'https://site.test:00/submit',
                   'https://site.test:443/submit', '//', '///?x')
        path.write_text(''.join(f'<form action="{action}"></form>' for action in actions))
        records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(warnings, [])
        self.assertEqual([row['scope'] for row in records],
                         ['cross_origin', 'cross_origin', 'same_origin', 'invalid', 'invalid'])

    def test_bad_scope_oversize_symlink_and_limits(self):
        path = self.root / 'a.html'
        path.write_text('<a href="javascript:alert(1)">x</a><a href="//else.test/y">y</a>')
        records, warnings = inspect_web_static(path, origin='https://site.test', max_records=1)
        self.assertEqual(len(records), 1)
        self.assertTrue(any('record limit' in warning for warning in warnings))
        self.assertEqual(records[0]['scope'], 'non_http')
        records, warnings = inspect_web_static(path, origin='https://site.test')
        self.assertEqual(next(row['scope'] for row in records if row['value'] == '//else.test/y'),
                         'cross_origin')
        with self.assertRaises(ValueError):
            inspect_web_static(path, origin='https://site.test/path')
        link = self.root / 'alias.html'
        link.symlink_to(path)
        self.assertEqual(inspect_web_static(link)[0], [])
        fifo = self.root / 'pipe.html'
        os.mkfifo(fifo)
        self.assertEqual(inspect_web_static(fifo)[0], [])
        self.assertEqual(inspect_web_static(path, max_bytes=4)[0], [])
        self.assertEqual(path.read_text(), '<a href="javascript:alert(1)">x</a><a href="//else.test/y">y</a>')

    def test_public_cli_web_inventory_resume_and_source_retirement(self):
        path = self.root / 'site.js'
        path.write_text('fetch("/api/first?q=1");fetch("https://site.test/private");'
                        ' //# sourceMappingURL=site.js.map\n')
        original_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'scope_origin': 'https://site.test'}))

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', *map(str, args)],
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        result = cli('analyze', path, '--category', 'web', '--hints', hints,
                     '--runs-root', self.root / 'runs', '--budget', '20')
        run = Path(result['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'web-static']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        self.assertEqual(manifest['coverage']['WEB01']['status'], 'ran')
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        endpoint = next(row for row in records if row['value'] == '/api/first?q=1')
        self.assertEqual(endpoint['offset'], path.read_bytes().index(b'/api/first'))
        self.assertEqual(endpoint['scope'], 'same_origin')
        self.assertTrue(any(item['tag'] == 'WEB01 static' and item['current'] and
                            item['source_locator']['offset'] == endpoint['offset']
                            for item in manifest['intelligence']))
        self.assertIn('line 1 byte', (run / 'report.md').read_text())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), original_hash)

        cli('resume', run, '--hints', hints, '--budget', '20')
        unchanged = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in unchanged['jobs'] if job['adapter_id'] == 'web-static']), 1)

        hints.write_text(json.dumps({'scope_origin': 'https://else.test'}))
        cli('resume', run, '--hints', hints, '--budget', '20')
        rescoped = json.loads((run / 'manifest.json').read_text())
        scope_jobs = [job for job in rescoped['jobs'] if job['adapter_id'] == 'web-static']
        self.assertEqual(len(scope_jobs), 2)
        self.assertFalse(any(row['current'] for row in rescoped['intelligence']
                             if row['job_id'] == scope_jobs[0]['id']))
        scope_records = json.loads(Path(scope_jobs[1]['records_path']).read_text())
        self.assertEqual(next(row['scope'] for row in scope_records
                              if row['value'] == 'https://site.test/private'), 'cross_origin')

        hints.write_text(json.dumps({'scope_origin': 'https://site.test'}))
        cli('resume', run, '--hints', hints, '--budget', '20')
        restored = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(any(row['current'] for row in restored['intelligence']
                            if row['job_id'] == scope_jobs[0]['id']))
        self.assertFalse(any(row['current'] for row in restored['intelligence']
                             if row['job_id'] == scope_jobs[1]['id']))

        path.write_text('fetch("/api/second");\n')
        cli('resume', run, '--hints', hints, '--budget', '20')
        changed = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in changed['jobs'] if job['adapter_id'] == 'web-static']
        self.assertEqual(len(jobs), 3)
        self.assertFalse(any(row['current'] for row in changed['intelligence']
                             if row['job_id'] == jobs[0]['id']))
        self.assertTrue(any(row['current'] and '/api/second' in row['value']
                            for row in changed['intelligence'] if row['job_id'] == jobs[2]['id']))

    def test_auto_routes_snapshot_and_doctor_probes_real_parser(self):
        snapshot = self.root / 'snapshot'
        snapshot.mkdir()
        (snapshot / 'index.html').write_text('<a href="/public">public</a>')
        (snapshot / 'app.js').write_text('fetch("/api/items")')
        (snapshot / 'app.js.map').write_text(json.dumps({
            'version': 3, 'sources': ['src/app.js'],
            'sourcesContent': ['fetch("/api/from-map")']}))
        with zipfile.ZipFile(snapshot / 'assets.zip', 'w') as archive:
            archive.writestr('site/from-archive.js', 'fetch("/api/from-archive")')
        analyze = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', 'analyze',
                                  str(snapshot), '--category', 'auto', '--budget', '20',
                                  '--runs-root', str(self.root / 'runs')], capture_output=True,
                                 text=True, timeout=45)
        self.assertEqual(analyze.returncode, 3, analyze.stderr + analyze.stdout)
        run = Path(json.loads(analyze.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in manifest['jobs'] if job['adapter_id'] == 'web-static']), 4)
        self.assertEqual(manifest['coverage']['WEB01']['status'], 'ran')
        self.assertTrue(any(row['tag'] == 'WEB01 static' and '/api/from-archive' in row['value']
                            for row in manifest['intelligence']))
        doctor = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json', 'doctor',
                                 '--profiles', 'web', '--self-test'], capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(json.loads(doctor.stdout)['operations']['web.static_inventory'],
                         {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'})
