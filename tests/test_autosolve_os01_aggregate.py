"""OS01 coverage reflects every current image source, independent of scan order."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from PIL import Image

from scripts.autosolve_lib import core


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


class OS01AggregateTests(unittest.TestCase):
    def _cli(self, env, *arguments):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                 *map(str, arguments)], capture_output=True, env=env, timeout=40)
        self.assertIn(result.returncode, (0, 3), result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_warning_source_survives_clean_source_and_drops_on_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / 'exiftool'
            tool.write_text('#!/usr/bin/env python3\n'
                            'import json, pathlib, sys\n'
                            'name = pathlib.Path(sys.argv[-1]).name\n'
                            'print(json.dumps([{"File:FileName": name}]))\n'
                            'if "warn" in name:\n'
                            '    print("metadata warning", file=sys.stderr)\n'
                            '    sys.exit(1)\n')
            tool.chmod(0o700)
            env = {**os.environ, 'AUTOSOLVE_EXIFTOOL': str(tool)}
            for warn_first in (True, False):
                with self.subTest(warn_first=warn_first):
                    sources = root / ('first' if warn_first else 'last')
                    sources.mkdir()
                    names = ('a_warn.jpg', 'b_clean.jpg') if warn_first else (
                        'a_clean.jpg', 'b_warn.jpg')
                    for name in names:
                        Image.new('RGB', (2, 2), 'red').save(sources / name)
                    run = Path(self._cli(env, 'analyze', sources, '--category', 'osint',
                                         '--runs-root', root / 'runs')['run'])
                    manifest = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(manifest['coverage']['OS01']['status'], 'truncated')
                    self.assertEqual(len([job for job in manifest['jobs'] if
                                          job['adapter_id'] == 'image-metadata' and
                                          job['status'] == 'complete']), 2)
                    self._cli(env, 'resume', run)
                    resumed = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(resumed['coverage']['OS01']['status'], 'truncated')
                    (sources / next(name for name in names if 'warn' in name)).unlink()
                    self._cli(env, 'resume', run)
                    removed = json.loads((run / 'manifest.json').read_text())
                    self.assertEqual(removed['coverage']['OS01']['status'], 'ran')
                    self.assertEqual(len([row for row in removed['intelligence'] if
                                          row['current'] and row['tag'] == 'FileName']), 1)

    def test_failed_source_survives_later_clean_source(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / 'jobs').mkdir()
            manifest = {'coverage': core._coverage('osint'), 'jobs': [], 'intelligence': [],
                        'warnings': [], 'artifacts': [], 'derived_bytes': 0}
            path = run / 'source.jpg'
            Image.new('RGB', (2, 2), 'red').save(path)
            artifact = {'id': 'source', 'sha256': 'a' * 64, 'path': str(path)}
            tag = {'tag': 'FileName', 'group': 'File', 'value': 'clean.jpg',
                   'source_tag': 'File:FileName'}
            with mock.patch.object(core, '_run_image_metadata', side_effect=[
                    RuntimeError('parser failed'), ([tag], [], [], [])]), \
                    mock.patch.object(core, '_require_identity', return_value=True):
                core._image_metadata_job(run, manifest, artifact, time.monotonic() + 30,
                                         make_views=False)
                self.assertEqual(manifest['coverage']['OS01']['status'], 'failed')
                core._image_metadata_job(run, manifest, artifact, time.monotonic() + 30,
                                         make_views=False)
            self.assertEqual(manifest['coverage']['OS01']['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
