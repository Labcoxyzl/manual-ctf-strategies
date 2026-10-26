import json
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


class SetupTests(unittest.TestCase):
    def test_missing_file_tool_is_partial_and_does_not_run_a_command(self):
        with mock.patch.object(capabilities.shutil, "which", return_value=None), \
             mock.patch.object(capabilities.subprocess, "run") as run:
            result = capabilities.doctor(["malware_reversing"], self_test=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["engines"]["file"]["found"], False)
        self.assertEqual(result["engines"]["file"]["functional_probe"], "not_run")
        self.assertEqual(result["engines"]["capa"]["reason"], "adapter_not_implemented")
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
                 mock.patch.object(capabilities.shutil, "which", return_value="/fake/file") as which, \
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
        which.assert_called_once_with("/fake/file")
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

    def test_image_tail_probe_checks_real_png_and_zip(self):
        result = capabilities.doctor(['images'], self_test=True)
        self.assertEqual(result['operations']['images.png_tail']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['images.metadata']['functional_probe'], 'passed')
        self.assertEqual(result['operations']['images.views']['functional_probe'], 'passed')
        self.assertEqual(result['engines']['exif']['status'], 'ready')
        self.assertEqual(result['engines']['image']['status'], 'ready')

    def test_can_log_probe_checks_actual_frame(self):
        result = capabilities.doctor(['can_misc'], self_test=True)
        self.assertEqual(result['operations']['can_misc.log']['functional_probe'], 'passed')

    def test_packet_probe_runs_offline_capture(self):
        result = capabilities.doctor(['packets'], self_test=True)
        self.assertEqual(result['operations']['packets.metadata']['functional_probe'], 'passed')
        self.assertEqual(result['engines']['tshark']['status'], 'ready')

    def test_sqlite_probe_checks_row_from_private_copy(self):
        result = capabilities.doctor(['memory'], self_test=True)
        self.assertEqual(result['operations']['disk_memory.sqlite']['functional_probe'], 'passed')


if __name__ == "__main__":
    unittest.main()
