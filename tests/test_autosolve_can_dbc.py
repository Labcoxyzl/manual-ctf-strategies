import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles.can_dbc import decode_can_frames
from scripts.autosolve_lib.profiles.canlog import parse_can_log
from scripts.autosolve_lib import core
from scripts.autosolve_lib import setup as autosolve_setup


ROOT = Path(__file__).resolve().parents[1]


DBC = '''VERSION ""
NS_ :
BS_:
BU_: Node
BO_ 291 Telemetry: 8 Node
 SG_ Mode M : 0|4@1+ (1,0) [0|15] "" Node
 SG_ Temperature m1 : 8|16@1- (0.5,-40) [-100|100] "degC" Node
 SG_ Speed m2 : 15|12@0+ (0.25,1) [1|700] "m/s" Node
 SG_ Counter : 32|8@1+ (1,0) [0|10] "" Node
BO_ 292 Other: 2 Node
 SG_ Value : 0|16@1+ (1,0) [0|100] "" Node
'''


class CanDbcTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.database = self.root / 'signals.dbc'
        self.database.write_text(DBC)
        self.capture = self.root / 'capture.log'

    def frames(self, contents):
        self.capture.write_text(contents)
        frames, warnings = parse_can_log(self.capture, max_frames=100, max_bytes=4096)
        self.assertEqual(warnings, [])
        return frames

    def decode(self, frames, **kwargs):
        return decode_can_frames(frames, self.database, max_frames=100,
                                 max_db_bytes=4096, max_output_bytes=65536,
                                 timeout=5, **kwargs)

    def test_missing_database_postworker_identity_preserves_skipped_prerequisite(self):
        self.capture.write_text('(1.0) can0 123#01ECFF0007000000\n')
        missing = self.root / 'missing.dbc'
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'dbc': str(missing)}))
        with patch.object(core, '_run_can_dbc', return_value=(
                [{'status': 'unavailable'}], ['database unavailable'])):
            run, _ = core.analyze(self.capture, category='can_misc', hints_path=hints,
                                  budget=5, runs_root=self.root / 'runs')
        manifest = json.loads((run / 'manifest.json').read_text())
        job = next(item for item in manifest['jobs'] if item['adapter_id'] == 'can-dbc')
        self.assertEqual(job['status'], 'complete')
        self.assertEqual(manifest['coverage']['CAN02']['status'], 'skipped prerequisite')

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_signed_scaled_and_multiplexed_values_preserve_raw_provenance(self):
        # Bytes are independently constructed: little endian signed -20 = EC FF;
        # big endian ABC occupies the first twelve bits of bytes AB C0.
        frames = self.frames('(1.0) can0 123#01ECFF0007000000\n'
                             '(1.1) can0 123#02ABC00009000000\n')
        rows, warnings = self.decode(frames)
        self.assertEqual(warnings, [])
        self.assertEqual([row['status'] for row in rows], ['decoded', 'decoded'])
        self.assertEqual([row['frame'] for row in rows], frames)
        self.assertEqual(rows[0]['message'], 'Telemetry')
        first = {signal['name']: signal for signal in rows[0]['signals']}
        self.assertEqual((first['Temperature']['raw'], first['Temperature']['value'],
                          first['Temperature']['unit']), (-20, -50, 'degC'))
        self.assertEqual((first['Temperature']['multiplexer_signal'],
                          first['Temperature']['multiplexer_value'],
                          first['Temperature']['multiplexer_ids']), ('Mode', 1, [1]))
        self.assertNotIn('Speed', first)
        second = {signal['name']: signal for signal in rows[1]['signals']}
        self.assertEqual((second['Speed']['raw'], second['Speed']['value']), (0xABC, 688))
        self.assertEqual(second['Speed']['multiplexer_value'], 2)
        self.assertNotIn('Temperature', second)
        self.assertEqual(rows[1]['frame']['source_line'], 2)

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_unknown_length_remote_and_out_of_range_are_distinct(self):
        frames = self.frames('(1.0) can0 321#01\n'
                             '(1.1) can0 124#010000\n'
                             '(1.2) can0 123#0102\n'
                             '(1.3) can0 123#R8\n'
                             '(1.4) can0 123#01ECFF00FF000000\n')
        rows, warnings = self.decode(frames)
        self.assertEqual([row['status'] for row in rows],
                         ['unknown_id', 'length_mismatch', 'length_mismatch',
                          'remote', 'out_of_range'])
        self.assertEqual([row['frame'] for row in rows], frames)
        self.assertTrue(any('unknown ID' in warning for warning in warnings))
        self.assertTrue(any('length mismatch' in warning for warning in warnings))
        self.assertTrue(any('out of range' in warning for warning in warnings))

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_wrong_database_does_not_invent_values_and_limits_are_reported(self):
        frames = self.frames('(1.0) can0 123#01ECFF0007000000\n'
                             '(1.1) can0 123#02ABC00009000000\n')
        self.database.write_text(DBC.replace('BO_ 291 Telemetry', 'BO_ 300 Telemetry'))
        rows, warnings = self.decode(frames)
        self.assertEqual([row['status'] for row in rows], ['unknown_id', 'unknown_id'])
        self.assertEqual([row['signals'] for row in rows], [[], []])
        limited, notes = decode_can_frames(frames, self.database, max_frames=1,
                                           max_db_bytes=4096, max_output_bytes=65536,
                                           timeout=5)
        self.assertEqual(len(limited), 1)
        self.assertTrue(any('frame limit' in note for note in notes))
        tiny, notes = decode_can_frames(frames, self.database, max_frames=100,
                                        max_db_bytes=4096, max_output_bytes=1,
                                        timeout=5)
        self.assertEqual(tiny, [])
        self.assertTrue(any('output byte limit' in note for note in notes))

    def test_unavailable_parser_and_unsafe_database_keep_frames(self):
        frames = self.frames('(1.0) can0 123#01ECFF0007000000\n')
        with patch.dict('sys.modules', {'cantools': None}):
            rows, warnings = self.decode(frames)
        self.assertEqual(rows[0]['frame'], frames[0])
        self.assertEqual(rows[0]['status'], 'unavailable')
        self.assertTrue(any('cantools unavailable' in warning for warning in warnings))
        link = self.root / 'link.dbc'
        link.symlink_to(self.database)
        rows, warnings = decode_can_frames(frames, link, max_frames=100,
                                           max_db_bytes=4096, max_output_bytes=65536,
                                           timeout=5)
        self.assertEqual(rows[0]['status'], 'database_error')
        self.assertTrue(any('regular file' in warning for warning in warnings))
        with self.assertRaisesRegex(ValueError, 'nonnegative'):
            decode_can_frames(frames, self.database, max_frames=-1,
                              max_db_bytes=4096, max_output_bytes=65536,
                              timeout=5)

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_extended_id_requires_matching_frame_format(self):
        extended = 0x1ABCDEFF
        self.database.write_text(DBC + f'BO_ {0x80000000 + extended} Extended: 1 Node\n'
                                 ' SG_ Byte : 0|8@1+ (1,0) [0|255] "" Node\n')
        frames = self.frames('(1.0) can0 1ABCDEFF#A5\n')
        rows, warnings = self.decode(frames)
        self.assertEqual(warnings, [])
        self.assertEqual(rows[0]['status'], 'decoded')
        self.assertEqual(rows[0]['signals'][0]['raw'], 0xA5)
        wrong_format = dict(frames[0], extended=False)
        rows, warnings = self.decode([wrong_format])
        self.assertEqual(rows[0]['status'], 'invalid_frame')
        self.assertTrue(any('invalid normalized CAN frame' in warning for warning in warnings))

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_malformed_normalized_frame_is_not_misreported_as_unknown_id(self):
        frame = self.frames('(1.0) can0 123#01ECFF0007000000\n')[0]
        frame.pop('extended')
        rows, warnings = self.decode([frame])
        self.assertEqual(rows[0]['frame'], frame)
        self.assertEqual(rows[0]['status'], 'invalid_frame')
        self.assertTrue(any('invalid normalized CAN frame' in warning for warning in warnings))

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_nonfinite_float_signal_keeps_raw_frame_without_invalid_json(self):
        self.database.write_text('VERSION ""\nNS_ :\nBS_:\nBU_: Node\n'
                                 'BO_ 500 Floating: 4 Node\n'
                                 ' SG_ F : 0|32@1+ (1,0) [0|100] "" Node\n'
                                 'SIG_VALTYPE_ 500 F : 1;\n')
        frames = self.frames('(1.0) can0 1F4#0000C07F\n')
        rows, warnings = self.decode(frames)
        self.assertEqual(rows[0]['frame'], frames[0])
        self.assertEqual(rows[0]['status'], 'decode_error')
        self.assertTrue(any('nonfinite' in warning for warning in warnings))

    @unittest.skipUnless(importlib.util.find_spec('cantools'), 'optional cantools unavailable')
    def test_public_cli_decodes_supplied_dbc_and_retires_changed_schema(self):
        self.capture.write_text('(1.0) can0 123#01ECFF0007000000\n')
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'dbc': 'signals.dbc'}))
        runs = self.root / 'runs'

        def cli(*args):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/autosolve.py'),
                                     '--json', *map(str, args)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=30,
                                    env=os.environ.copy())
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        run = Path(cli('analyze', self.capture, '--category', 'can', '--hints', hints,
                       '--runs-root', runs)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        raw = next(job for job in manifest['jobs'] if job['adapter_id'] == 'can-log')
        signal = next(job for job in manifest['jobs'] if job['adapter_id'] == 'can-dbc')
        self.assertEqual(json.loads(Path(raw['frames_path']).read_text())[0]['payload_hex'],
                         '01ECFF0007000000')
        first = json.loads(Path(signal['records_path']).read_text())
        self.assertEqual(first[0]['status'], 'decoded')
        self.assertEqual(next(item['value'] for item in first[0]['signals']
                              if item['name'] == 'Temperature'), -50)
        self.assertEqual(manifest['coverage']['CAN02']['status'], 'ran')
        self.assertTrue(any(item['tag'] == 'CAN signal' and
                            item['source_locator']['line'] == 1
                            for item in manifest['intelligence']))

        self.database.write_text(DBC.replace('(0.5,-40)', '(1,-40)'))
        cli('resume', run, '--budget', '30', '--hints', hints)
        changed = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in changed['jobs'] if job['adapter_id'] == 'can-dbc']
        self.assertEqual(len(jobs), 2)
        current = [item for item in changed['intelligence']
                   if item['tag'] == 'CAN signal' and item['current']]
        self.assertTrue(current)
        self.assertTrue(all(item['job_id'] == jobs[-1]['id'] for item in current))
        self.assertEqual(json.loads(Path(jobs[-1]['records_path']).read_text())[0]
                         ['signals'][1]['value'], -60)

    def test_doctor_reports_cantools_readiness_truthfully(self):
        result = autosolve_setup.doctor(['can'], self_test=True)
        operation = result['operations']['can_misc.dbc']
        if importlib.util.find_spec('cantools'):
            self.assertEqual(operation['functional_probe'], 'passed')
            self.assertEqual(operation['status'], 'ready')
            self.assertEqual(result['engines']['can']['status'], 'ready')
        else:
            self.assertEqual(operation['status'], 'unavailable')
            self.assertEqual(result['engines']['can']['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
