import json
import mmap
import os
import subprocess
import sys
import tempfile
import types
import unittest
import stat
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from autosolve_lib import setup as capabilities
from autosolve_lib.profiles import tones
from test_autosolve_checker import ANGR_IMPORT_READY


class SetupTests(unittest.TestCase):
    def test_doctor_probe_scratch_is_private_and_local_without_tmpdir(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'export'
            root.mkdir()
            source = root / 'scripts/autosolve_lib/setup.py'
            with mock.patch.object(capabilities, '__file__', str(source)), \
                 mock.patch.dict(os.environ, {}, clear=False):
                with capabilities._probe_directory() as probe:
                    path = Path(probe)
                    self.assertEqual(path.parent, root / '.autosolve/tmp')
                    self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                    (path / 'sentinel').write_text('local')
                self.assertFalse(path.exists())

    def test_doctor_probe_rejects_symlinked_scratch_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'export'
            outside = Path(directory) / 'outside'
            root.mkdir()
            outside.mkdir()
            (root / '.autosolve').symlink_to(outside, target_is_directory=True)
            source = root / 'scripts/autosolve_lib/setup.py'
            with mock.patch.object(capabilities, '__file__', str(source)):
                with self.assertRaises(OSError):
                    with capabilities._probe_directory():
                        pass
            self.assertEqual(list(outside.iterdir()), [])

    def test_doctor_probe_closes_world_writable_parent_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'export'
            parent = root / '.autosolve'
            parent.mkdir(parents=True)
            parent.chmod(0o777)
            source = root / 'scripts/autosolve_lib/setup.py'
            with mock.patch.object(capabilities, '__file__', str(source)):
                with capabilities._probe_directory() as probe:
                    self.assertTrue(Path(probe).is_relative_to(parent / 'tmp'))
                    self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)

    def test_setup_child_doctor_uses_task_local_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'export'
            root.mkdir()
            source = root / 'scripts/autosolve_lib/setup.py'
            prepared = {'status': 'ready', 'python': '/fake/python', 'installed': ['core']}
            observed = {'status': 'partial', 'engines': {}, 'operations': {}}
            completed = subprocess.CompletedProcess([], 3, json.dumps(observed).encode(), b'')
            with mock.patch.object(capabilities, '__file__', str(source)), \
                 mock.patch('autosolve_lib.setup_env.prepare', return_value=prepared), \
                 mock.patch.object(capabilities.subprocess, 'run', return_value=completed) as run:
                result = capabilities.setup(['encoding'])
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(run.call_args.kwargs['env']['TMPDIR'],
                             str(root / '.autosolve/tmp'))
            self.assertEqual((root / '.autosolve/tmp').stat().st_mode & 0o777, 0o700)

    def test_doctor_tool_command_uses_clean_local_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'export'
            root.mkdir()
            source = root / 'scripts/autosolve_lib/setup.py'
            completed = subprocess.CompletedProcess([], 0, b'ok', b'')
            with mock.patch.object(capabilities, '__file__', str(source)), \
                 mock.patch.object(capabilities.subprocess, 'run', return_value=completed) as run:
                self.assertIs(capabilities._command(['/fake/tool', '--version']), completed)
            env = run.call_args.kwargs['env']
            self.assertEqual(env['TMPDIR'], env['XDG_CACHE_HOME'])
            self.assertEqual(env['HOME'], env['TMPDIR'])
            self.assertTrue(Path(env['TMPDIR']).is_relative_to(root / '.autosolve/tmp'))
            self.assertFalse(Path(env['TMPDIR']).exists())

    def test_pwn_offset_doctor_reports_missing_trusted_gdb_without_running(self):
        with mock.patch.object(capabilities.shutil, 'which', return_value=None) as which, \
             mock.patch.object(capabilities.subprocess, 'run') as run:
            operation, engine = capabilities._pwn_offset_probe(True)
        self.assertEqual(which.call_args, mock.call('gdb', path='/usr/bin:/bin'))
        run.assert_not_called()
        self.assertEqual(operation['status'], 'partial')
        self.assertEqual(operation['reason'], 'gdb_missing')
        self.assertFalse(engine['found'])
        self.assertEqual(engine['status'], 'unavailable')

    def test_pwn_offset_doctor_checks_ptrace_with_clean_environment(self):
        def which(name, path=None):
            self.assertEqual(path, '/usr/bin:/bin')
            return f'/usr/bin/{name}'

        completed = subprocess.CompletedProcess([], 0,
                                                b'rip 0x401000\nrsp 0x7fff0000\n'
                                                b'[Inferior 1 exited normally]\n', b'')
        with mock.patch.object(capabilities.shutil, 'which', side_effect=which), \
             mock.patch.object(capabilities.subprocess, 'run', return_value=completed) as run:
            operation, engine = capabilities._pwn_offset_probe(True)
        self.assertEqual(operation['status'], 'ready')
        self.assertEqual(operation['functional_probe'], 'passed')
        self.assertEqual(engine['status'], 'ready')
        command = run.call_args.args[0]
        self.assertIn('-batch', command)
        self.assertEqual(command[command.index('set auto-load off') - 1], '-iex')
        self.assertIn('starti', command)
        self.assertIn('info registers rip rsp', command)
        self.assertTrue(any(item.startswith('set inferior-tty /dev/pts/') for item in command))
        self.assertIn('/usr/bin/true', command)
        scratch = run.call_args.kwargs['cwd']
        self.assertEqual(run.call_args.kwargs['env'], {'LC_ALL': 'C',
                                                      'PYTHONDONTWRITEBYTECODE': '1',
                                                      'TMPDIR': scratch, 'TMP': scratch,
                                                      'TEMP': scratch,
                                                      'XDG_CACHE_HOME': scratch})
        self.assertEqual(run.call_args.kwargs['timeout'], 5)

    def test_pwn_offset_doctor_reports_ptrace_failure_as_partial(self):
        denied = subprocess.CompletedProcess([], 1, b'', b'ptrace: Operation not permitted')
        with mock.patch.object(capabilities.shutil, 'which',
                               side_effect=lambda name, path=None: f'/usr/bin/{name}'), \
             mock.patch.object(capabilities.subprocess, 'run', return_value=denied):
            operation, engine = capabilities._pwn_offset_probe(True)
        self.assertEqual(operation['status'], 'partial')
        self.assertEqual(operation['reason'], 'gdb_ptrace_probe_failed')
        self.assertEqual(engine['functional_probe'], 'failed')
        self.assertEqual(engine['status'], 'partial')

    def test_pwn_offset_doctor_reports_pty_failure_as_partial(self):
        with mock.patch.object(capabilities.shutil, 'which',
                               side_effect=lambda name, path=None: f'/usr/bin/{name}'), \
             mock.patch.object(capabilities.pty, 'openpty', side_effect=OSError('no ptmx')), \
             mock.patch.object(capabilities.subprocess, 'run') as run:
            operation, engine = capabilities._pwn_offset_probe(True)
        run.assert_not_called()
        self.assertEqual(operation['status'], 'partial')
        self.assertEqual(operation['reason'], 'pty_unavailable')
        self.assertEqual(engine['functional_probe'], 'failed')

    def test_pwn_offset_doctor_row_is_separate_from_static_elf(self):
        static = {'implemented': True, 'functional_probe': 'passed', 'status': 'ready'}
        with mock.patch.object(capabilities, '_elf_probe', return_value=static), \
             mock.patch.object(capabilities.shutil, 'which', return_value=None):
            result = capabilities.doctor(['pwn_services'], self_test=False)
        self.assertIn('gdb', result['engines'])
        self.assertIn('pwn_services.offset', result['operations'])
        self.assertEqual(result['operations']['pwn_services.offset']['status'], 'partial')
        self.assertEqual(result['operations']['pwn_services.offset']['reason'], 'gdb_missing')
        self.assertEqual(result['operations']['pwn_services.elf_static']['status'], 'ready')

    @unittest.skipUnless(capabilities.shutil.which('multimon-ng') and
                         capabilities.shutil.which('ffmpeg'),
                         'approved multimon-ng and ffmpeg required for the AV03 functional probe')
    def test_tone_doctor_decodes_exact_morse_and_afsk_fixtures(self):
        dtmf, av03, engine = capabilities._tone_probe(True)
        self.assertEqual(dtmf['functional_probe'], 'passed', dtmf)
        self.assertEqual(av03['functional_probe'], 'passed', av03)
        self.assertEqual(av03['status'], 'ready', av03)
        self.assertEqual(engine['status'], 'ready', engine)

    @unittest.skipUnless(capabilities.shutil.which('ffmpeg'), 'ffmpeg required')
    def test_tone_doctor_rejects_mode_list_and_one_mode_only_output(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'multimon-ng'
            fake.write_text('#!/usr/bin/env python3\n'
                            'import sys\n'
                            'mode = sys.argv[sys.argv.index("-a") + 1]\n'
                            'if mode == "DTMF": print("DTMF: 1\\nDTMF: 2")\n'
                            'elif mode == "MORSE_CW": print("SOS")\n'
                            'else: print("AFSK1200: fm AE4WA-0 to HB9JNX-0 UI  pid=F0\\nWRONG")\n')
            fake.chmod(0o700)
            with mock.patch.object(tones, 'MULTIMON', str(fake)):
                _, av03, engine = capabilities._tone_probe(True)
            self.assertEqual(av03['status'], 'partial', av03)
            self.assertEqual(av03['functional_probe'], 'failed', av03)
            self.assertEqual(engine['status'], 'partial', engine)

            fake.write_text('#!/usr/bin/env python3\n'
                            'print("Enabled demodulators: DTMF MORSE_CW AFSK1200")\n')
            fake.chmod(0o700)
            with mock.patch.object(tones, 'MULTIMON', str(fake)):
                _, av03, _ = capabilities._tone_probe(True)
            self.assertEqual(av03['status'], 'partial', av03)
            self.assertEqual(av03['functional_probe'], 'failed', av03)

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

    @unittest.skipUnless(capabilities.importlib.util.find_spec('can'),
                         'python-can is optional outside core setup')
    def test_can_log_probe_checks_genuine_blf_frame(self):
        result = capabilities._can_probe(True)
        self.assertEqual(result['blf_probe'], 'passed')
        self.assertEqual(result['status'], 'ready')

    def test_can_log_probe_reports_missing_blf_parser(self):
        import builtins
        original_import = builtins.__import__

        def without_can(name, *args, **kwargs):
            if name == 'can':
                raise ImportError('python-can missing')
            return original_import(name, *args, **kwargs)

        with mock.patch.object(builtins, '__import__', side_effect=without_can):
            result = capabilities._can_probe(True)
        self.assertEqual(result['functional_probe'], 'passed')
        self.assertEqual(result['blf_probe'], 'unavailable')
        self.assertEqual(result['status'], 'partial')

    @unittest.skipUnless(capabilities.importlib.util.find_spec('can'),
                         'python-can is optional outside core setup')
    def test_can_log_probe_reports_old_blf_parser(self):
        import can
        with mock.patch.object(can, '__version__', '4.5.0'):
            result = capabilities._can_probe(True)
        self.assertEqual(result['blf_probe'], 'unsupported_version')
        self.assertEqual(result['status'], 'partial')

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
