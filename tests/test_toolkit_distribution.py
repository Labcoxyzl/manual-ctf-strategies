"""Exercise the explicit public export and its failure boundary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_toolkit', ROOT / 'scripts/package_toolkit.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class DistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = exporter.collect(ROOT)

    def test_exact_allowlist_and_public_graph(self):
        expected = set(exporter.PUBLIC_PAGES + exporter.CODE + exporter.COMPANIONS + exporter.FIXTURES) | {'README.md'}
        self.assertEqual(set(self.files), expected)
        self.assertEqual(self.files['index.html'], self.files['keyword-preview.html'])
        self.assertNotIn('EVENT_SOURCES.html', self.files)
        for name in exporter.PUBLIC_PAGES:
            page = exporter.Page(self.files[name].decode())
            for link in page.links:
                target, _ = exporter.local_target(name, link)
                self.assertNotIn(target, exporter.INTERNAL_EVIDENCE)
        self.assertIn(b'internal evidence; not distributed', self.files['RESOURCE_EVALUATION.html'])
        self.assertIn(b'RULES.html', self.files['index.html'])

    def test_unknown_and_private_links_fail_before_destination(self):
        read = exporter.read_source
        with tempfile.TemporaryDirectory(prefix='toolkit export rejection ') as temp:
            for target in ['organiser-private.pdf', 'unrecognised-local.txt', 'research/learning/review-secret.html']:
                def injected(root, name):
                    data = read(root, name)
                    if name in ('index.html', 'keyword-preview.html'):
                        data += f'<a href="{target}">Excluded test</a>'.encode()
                    return data
                destination = Path(temp) / 'rejected'
                with patch.object(exporter, 'read_source', side_effect=injected):
                    with self.assertRaisesRegex(ValueError, 'Excluded or unknown'):
                        exporter.package(destination)
                self.assertFalse(destination.exists())

    def test_rejects_symlinked_inputs_and_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'original').write_text('synthetic')
            (root / 'linked').symlink_to(root / 'original')
            with self.assertRaisesRegex(ValueError, 'Symlinked'):
                exporter.read_source(root, 'linked')
            (root / 'directory').mkdir()
            (root / 'parent').symlink_to(root / 'directory', target_is_directory=True)
            (root / 'directory' / 'child').write_text('synthetic')
            with self.assertRaisesRegex(ValueError, 'Symlinked'):
                exporter.read_source(root, 'parent/child')
            with self.assertRaises(ValueError):
                exporter.package(root / 'parent' / 'output')
            (root / 'dangling').symlink_to(root / 'absent')
            with self.assertRaises(ValueError):
                exporter.package(root / 'dangling')

    def test_file_urls_are_not_external_references(self):
        for link in ['file:///private/organiser.pdf', 'FILE:///private/organiser.pdf', 'javascript:alert(1)']:
            with self.assertRaisesRegex(ValueError, 'Excluded URL scheme'):
                exporter.local_target('index.html', link)

    def test_output_parent_swap_cannot_publish_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'source'
            root.mkdir()
            parent = Path(temp) / 'output-parent'
            parent.mkdir()
            def swap(source):
                parent.rmdir()
                parent.symlink_to(root, target_is_directory=True)
                return {'test.txt': b'synthetic'}
            with patch.object(exporter, 'collect', side_effect=swap):
                with self.assertRaises(OSError):
                    exporter.package(parent / 'export', root=root)
            self.assertFalse((root / 'export').exists())

    def test_input_parent_swap_never_reads_outside_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'source'
            safe = root / 'safe'
            safe.mkdir(parents=True)
            (safe / 'x').write_bytes(b'public')
            private = Path(temp) / 'private'
            private.mkdir()
            (private / 'x').write_bytes(b'private')
            original_open = os.open
            def swap(path, flags, *args, **kwargs):
                if path == 'x':
                    (safe / 'x').unlink()
                    safe.rmdir()
                    safe.symlink_to(private, target_is_directory=True)
                return original_open(path, flags, *args, **kwargs)
            with patch.object(exporter.os, 'open', side_effect=swap):
                with self.assertRaises(ValueError):
                    exporter.read_source(root, 'safe/x')

    def test_rejects_existing_and_overlapping_output(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp)
            marker = destination / 'keep'
            marker.write_text('preserve')
            with self.assertRaises(ValueError):
                exporter.package(destination)
            self.assertEqual(marker.read_text(), 'preserve')
        with self.assertRaisesRegex(ValueError, 'overlap'):
            exporter.package(ROOT / 'never-create-export-here')

    def test_export_from_unrelated_directory_and_clone(self):
        with tempfile.TemporaryDirectory(prefix='toolkit isolated with spaces ') as temp:
            destination = Path(temp) / 'offline kit'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/package_toolkit.py'),
                                     '--out', str(destination)], cwd=temp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            exported = {str(path.relative_to(destination)) for path in destination.rglob('*') if path.is_file()}
            self.assertEqual(exported, set(self.files))
            for name, data in self.files.items():
                self.assertEqual(hashlib.sha256((destination / name).read_bytes()).digest(),
                                 hashlib.sha256(data).digest(), name)
            self.run_smoke(destination, temp)
            if shutil.which('git'):
                git_env = os.environ.copy()
                for name in subprocess.check_output(['git', 'rev-parse', '--local-env-vars'], cwd=ROOT, text=True).splitlines():
                    git_env.pop(name, None)
                subprocess.run(['git', 'init', '-q', str(destination)], check=True, capture_output=True, env=git_env)
                subprocess.run(['git', '-C', str(destination), 'add', '.'], check=True, capture_output=True, env=git_env)
                subprocess.run(['git', '-C', str(destination), '-c', 'user.name=Toolkit test',
                                '-c', 'user.email=toolkit-test@example.invalid', '-c', 'commit.gpgsign=false',
                                'commit', '-qm', 'Synthetic local export verification'], check=True, capture_output=True, env=git_env)
                clone = Path(temp) / 'local clone'
                subprocess.run(['git', 'clone', '-q', '--no-hardlinks', str(destination), str(clone)],
                               check=True, capture_output=True, env=git_env)
                self.run_smoke(clone, temp)

    def run_smoke(self, destination, cwd):
        command = [sys.executable, '-I', str(destination / 'scripts/ctf.py'),
                   'bits', '--text', '01000001', '--json']
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'complete')
        with tempfile.TemporaryDirectory(dir=cwd) as temp:
            source = Path(temp) / 'encoded.txt'
            source.write_bytes(b'SEVMTE8=')
            command = [sys.executable, '-I', str(destination / 'scripts/autosolve.py'), '--json',
                       'analyze', str(source), '--category', 'encoding',
                       '--runs-root', str(Path(temp) / 'runs')]
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
            self.assertTrue(any(item['depth'] > 0 and Path(item['path']).read_bytes() == b'HELLO'
                                for item in manifest['artifacts']))
            self.assertEqual(source.read_bytes(), b'SEVMTE8=')
            prefs = Path(temp) / 'settings.preferences_pb'
            prefs.write_bytes(bytes.fromhex(
                '0a0d0a07656e61626c656412020801'
                '0a1a0a086578706563746564120e2a0c6b6e6f776e2d6d61726b6572'))
            reader = [sys.executable, '-I', '-S',
                      str(destination / 'scripts/templates/datastore_pref.py'), str(prefs)]
            selected = subprocess.run([*reader, 'expected'], cwd=cwd,
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(selected.stdout, 'type: string\nvalue: "known-marker"\n')
            absent = subprocess.run([*reader, 'missing'], cwd=cwd,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(absent.returncode, 1, absent.stderr)
            self.assertIn('app-state absence is not established', absent.stderr)
            adapter = Path(temp) / 'model_adapter.py'
            adapter.write_text('def load_model(path):\n import torch\n return torch.nn.Identity()\n'
                               'def load_input(path):\n import numpy as np\n import torch\n'
                               ' return torch.from_numpy(np.load(path)).float()\n'
                               'def loss(model, tensor, target): return model(tensor).sum()\n')
            model = Path(temp) / 'model.bin'
            model.write_bytes(b'toy')
            model_input = Path(temp) / 'input.npy'
            model_input.write_bytes(b'placeholder')
            attack = [str(destination / 'scripts/ai_model_attack.py'), '--runs-root',
                      str(Path(temp) / 'model-runs'), '--adapter', str(adapter),
                      '--execute-local', '--budget', '10', 'gradient', '--model', str(model),
                      '--input', str(model_input), '--target', 'up', '--epsilon', '.2',
                      '--step-size', '.1', '--steps', '2']
            missing = subprocess.run([sys.executable, '-I', '-S', *attack], cwd=cwd,
                                     capture_output=True, text=True, timeout=15)
            self.assertEqual(missing.returncode, 2, missing.stderr + missing.stdout)
            self.assertEqual(json.loads(missing.stdout)['reason'],
                             'gradient mode needs installed numpy and torch')
            probe = subprocess.run([sys.executable, '-I', '-c', 'import numpy, torch'],
                                   cwd=cwd, capture_output=True, text=True, timeout=20)
            if probe.returncode:
                self.assertRegex(probe.stderr, r"ModuleNotFoundError: No module named '(numpy|torch)'")
                return
            import numpy as np
            np.save(model_input, np.array([.2, .3], dtype='float32'))
            result = subprocess.run([sys.executable, '-I', *attack], cwd=cwd,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            exported = json.loads(result.stdout)
            report = json.loads(Path(exported['report']).read_text())
            self.assertEqual(report['state'], 'candidate')
            self.assertGreater(report['candidate_objective'], report['clean_objective'])
            self.assertLessEqual(report['max_abs_change'], .200001)
            self.assertTrue(np.allclose(np.load(exported['candidate_file']), [.4, .5]))

    @unittest.skipUnless(shutil.which('unshare'), 'Linux namespace isolation unavailable')
    def test_offline_with_development_workspace_hidden(self):
        probe = subprocess.run(['unshare', '-Urnm', 'true'], capture_output=True)
        if probe.returncode:
            self.skipTest('User/mount/network namespaces unavailable')
        with tempfile.TemporaryDirectory(prefix='toolkit namespace ') as temp:
            destination = Path(temp) / 'offline kit'
            exporter.package(destination)
            # Only this child mount namespace hides the source tree; host files stay untouched.
            script = ('mount --make-rprivate / && mount -t tmpfs tmpfs "$1" && '
                      'cd "$2" && test ! -e "$1/scripts/ctf.py" && '
                      '"$3" -I scripts/ctf.py doctor --workflow bytes --json && '
                      '"$3" -I scripts/ctf.py bits --text 01000001 --json && '
                      '"$3" -I -m unittest discover -s tests -p "test_toolkit*.py"')
            result = subprocess.run(['unshare', '-Urnm', 'sh', '-c', script, 'isolated-toolkit',
                                     str(ROOT), str(destination), sys.executable],
                                    cwd=temp, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
