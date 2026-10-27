import json
import mmap
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from autosolve_lib import setup as capabilities
from test_autosolve_checker import ANGR_IMPORT_READY


class SetupTests(unittest.TestCase):
    def test_missing_file_tool_is_partial_and_does_not_run_a_command(self):
        with mock.patch.object(capabilities.shutil, "which", return_value=None), \
             mock.patch.object(capabilities.subprocess, "run") as run:
            result = capabilities.doctor(["malware_reversing"], self_test=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["engines"]["file"]["found"], False)
        self.assertEqual(result["engines"]["file"]["functional_probe"], "not_run")
        self.assertEqual(result["engines"]["capa"]["reason"], "tool_missing_or_incompatible")
        self.assertEqual(result["operations"]["malware_reversing.rule_matching"]["status"],
                         "unavailable")
        run.assert_not_called()

    def test_file_probe_checks_options_and_magic_data_without_writing(self):
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            if argv[-1] == "--version":
                out = b"file-5.45\n"
            elif argv[-1] == "--help":
                out = b"--brief --mime-type"
            else:
                self.assertEqual(kwargs["input"][:8], b"\x89PNG\r\n\x1a\n")
                out = b"image/png\n"
            return subprocess.CompletedProcess(argv, 0, out, b"")

        with tempfile.TemporaryDirectory() as empty_dir:
            with mock.patch.dict(os.environ, {"AUTOSOLVE_FILE": "/fake/file"}), \
                 mock.patch.object(capabilities.shutil, "which",
                                   side_effect=lambda name: "/fake/file" if name == "/fake/file" else None) as which, \
                 mock.patch.object(capabilities.subprocess, "run", side_effect=run):
                original_cwd = os.getcwd()
                try:
                    os.chdir(empty_dir)
                    result = capabilities.doctor(["reversing"], self_test=True)
                finally:
                    os.chdir(original_cwd)
            self.assertEqual(os.listdir(empty_dir), [])
        self.assertEqual(result["engines"]["file"]["status"], "ready")
        self.assertEqual(result["engines"]["file"]["discovery_source"], "override")
        self.assertEqual(result["engines"]["file"]["required_data"], "present")
        self.assertIn(mock.call("/fake/file"), which.call_args_list)
        self.assertEqual(len(commands), 3)
        self.assertTrue(all(command[0] == "/fake/file" for command in commands))

    def test_encoding_probe_requires_callable_and_valid_result(self):
        decoder = types.SimpleNamespace(decode=lambda data, limit: [(b"probe", "base64")])
        with mock.patch.object(capabilities.importlib, "import_module", return_value=decoder):
            result = capabilities.doctor(["crypto"], self_test=True)
        self.assertEqual(result["operations"]["encoding.decode"]["status"], "ready")
        self.assertEqual(result["operations"]["encoding.xor_one"]["status"], "ready")
        self.assertEqual(result["operations"]["encoding.rsa_literals"]["status"], "ready")
        self.assertEqual(result["operations"]["encoding.aes_declared"]["status"], "ready")
        self.assertEqual(result["engines"]["stdlib"]["functional_probe"], "passed")
        self.assertIsNone(result["engines"]["rsa"]["found"])
        self.assertEqual(result["engines"]["rsa"]["status"], "unavailable")
        json.dumps(result)

    def test_setup_installs_nothing_and_rejects_unknown_profile(self):
        with mock.patch.object(capabilities.shutil, "which", return_value=None), \
             mock.patch.object(capabilities.subprocess, "run") as run:
            result = capabilities.setup(["encoding"])
        self.assertEqual(result["installed"], [])
        run.assert_not_called()
        with self.assertRaisesRegex(ValueError, "Unknown autosolve profile"):
            capabilities.doctor(["made_up"])

    def test_document_zip_probe_checks_real_extraction(self):
        result = capabilities.doctor(["documents"], self_test=True)
        self.assertEqual(result['operations']['documents.zip']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['documents.zip']['status'], 'ready')
        self.assertEqual(result['operations']['documents.mime']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['documents.pdf']['functional_probe'], 'passed')

    @unittest.skipUnless(capabilities.shutil.which('7z') or capabilities.shutil.which('7zz'),
                         '7-Zip unavailable')
    def test_document_sevenzip_probe_checks_encrypted_stream_and_public_doctor(self):
        result = capabilities.doctor(['documents'], self_test=True)
        self.assertEqual(result['operations']['documents.7z']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['documents.7z']['status'], 'ready')
        self.assertEqual(result['engines']['archive']['status'], 'ready')
        self.assertTrue(result['engines']['archive']['options_compatible'])
        command = [sys.executable, '-m', 'scripts.autosolve', '--json', 'doctor',
                   '--profiles', 'documents', '--self-test']
        completed = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                   capture_output=True, text=True)
        self.assertIn(completed.returncode, (0, 3), completed.stderr)
        public = json.loads(completed.stdout)
        self.assertEqual(public['operations']['documents.7z']['functional_probe'], 'passed')
        self.assertEqual(public['engines']['archive']['status'], 'ready')

    def test_document_missing_sevenzip_isolated_from_zip(self):
        original_which = capabilities.shutil.which
        with mock.patch.object(capabilities.shutil, 'which',
                               side_effect=lambda name: None if name in ('7z', '7zz')
                               else original_which(name)):
            result = capabilities.doctor(['documents'], self_test=True)
        self.assertEqual(result['operations']['documents.7z']['status'], 'unavailable')
        self.assertEqual(result['operations']['documents.7z']['functional_probe'], 'not_run')
        self.assertEqual(result['engines']['archive']['found'], False)
        self.assertEqual(result['operations']['documents.zip']['status'], 'ready')

    def test_image_tail_probe_checks_real_png_and_zip(self):
        result = capabilities.doctor(['images'], self_test=True)
        self.assertEqual(result['operations']['images.png_tail']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['images.jpeg_tail']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['images.metadata']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['images.views']['functional_probe'], 'passed')
        self.assertEqual(result['engines']['exif']['status'], 'ready')
        self.assertEqual(result['engines']['image']['status'], 'ready')

    def test_jpeg_tail_probe_reports_missing_pillow(self):
        with mock.patch.object(capabilities.importlib.util, 'find_spec', return_value=None):
            result = capabilities._jpeg_probe(False)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['reason'], 'pillow_missing')

    def test_jpeg_tail_probe_handles_broken_pillow_import(self):
        import builtins
        original_import = builtins.__import__

        def broken_pillow(name, *args, **kwargs):
            if name == 'PIL':
                raise ImportError('broken native wheel')
            return original_import(name, *args, **kwargs)

        with mock.patch.object(capabilities.importlib.util, 'find_spec', return_value=object()), \
             mock.patch('builtins.__import__', side_effect=broken_pillow):
            result = capabilities._jpeg_probe(False)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['reason'], 'pillow_unusable')

    def test_can_log_probe_checks_actual_frame(self):
        result = capabilities.doctor(['can_misc'], self_test=True)
        self.assertEqual(result['operations']['can_misc.log']['functional_probe'], 'passed')

    def test_packet_probe_runs_offline_capture(self):
        result = capabilities.doctor(['packets'], self_test=True)
        self.assertEqual(result['operations']['packets.metadata']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['packets.objects']['functional_probe'], 'passed')
        self.assertEqual(result['engines']['tshark']['status'], 'ready')

    def test_sqlite_probe_checks_row_from_private_copy(self):
        result = capabilities.doctor(['memory'], self_test=True)
        self.assertEqual(result['operations']['disk_memory.sqlite']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['disk_memory.disk_image']['functional_probe'], 'passed')
        self.assertEqual(result['engines']['tsk']['status'], 'ready')

    @unittest.skipUnless(capabilities.shutil.which('gcc') and ANGR_IMPORT_READY,
                         'gcc and an importable angr are needed for the REV07 functional probe')
    def test_checker_probe_solves_and_replays_temporary_elf(self):
        result = capabilities.doctor(['reversing'], self_test=True)
        operation = result['operations']['malware_reversing.checker']
        self.assertTrue(operation['implemented'])
        self.assertEqual(operation['functional_probe'], 'passed', operation)
        self.assertEqual(result['engines']['angr']['functional_probe'], 'passed')

    @unittest.skipUnless(capabilities.shutil.which('gcc') and
                         capabilities.importlib.util.find_spec('angr'),
                         'gcc and angr are needed for the REV07 diagnostic probe')
    def test_checker_probe_reports_bounded_failure_cause(self):
        from autosolve_lib.profiles import checker
        timeout = {'status': 'timeout', 'reason': 'symbolic worker timed out',
                   'replay': {'attempted': False}}
        with mock.patch.object(checker, 'inspect_checker', return_value=(timeout, [])):
            operation, _ = capabilities._checker_probe(True)
        self.assertEqual(operation['functional_probe'], 'failed')
        self.assertEqual(operation['probe_detail'], 'checker_timeout: symbolic worker timed out')

    @unittest.skipUnless(capabilities.shutil.which('gcc') and ANGR_IMPORT_READY,
                         'gcc and an importable angr are needed for the REV07 parent mapping probe')
    def test_checker_probe_works_with_large_untouched_parent_mapping(self):
        try:
            mapping = mmap.mmap(-1, 3 * 1024**3,
                                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except (OSError, ValueError) as error:
            self.skipTest(f'untouched virtual mapping unavailable: {type(error).__name__}')
        with mapping:
            operation, _ = capabilities._checker_probe(True)
        self.assertEqual(operation['functional_probe'], 'passed', operation)

    @unittest.skipUnless(capabilities.shutil.which('gcc') and not ANGR_IMPORT_READY and
                         capabilities.importlib.util.find_spec('angr'),
                         'requires an installed but unimportable angr runtime')
    def test_checker_probe_reports_unusable_installed_angr(self):
        operation, engine = capabilities._checker_probe(True)
        self.assertEqual(operation['functional_probe'], 'failed', operation)
        self.assertIn('checker_incomplete:', operation.get('probe_detail', ''))
        self.assertEqual(engine['status'], 'partial')


if __name__ == "__main__":
    unittest.main()
