"""Public offline AI artifact and wrapper checks with independent small inputs."""

import base64
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/ai_model.py'


class AIModelTests(unittest.TestCase):
    def command(self, root, *args, code=0):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--runs-root', str(Path(root) / 'runs'),
                                 *map(str, args)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_inspects_npy_safetensors_and_pickle_without_loading_code(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            header = b"{'descr': '<f8', 'fortran_order': False, 'shape': (2,)}"
            header += b' ' * ((-(10 + len(header) + 1)) % 16) + b'\n'
            npy = root / 'array.npy'
            npy.write_bytes(b'\x93NUMPY\x01\x00' + len(header).to_bytes(2, 'little') + header + struct.pack('<dd', 1, 2))
            result = self.command(root, 'inspect', npy)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(record['entries'][0]['shape'], [2])
            self.assertEqual(record['kind'], 'npy')

            metadata = json.dumps({'weights': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 8]}}).encode()
            safe = root / 'weights.safetensors'
            safe.write_bytes(len(metadata).to_bytes(8, 'little') + metadata + b'\x00' * 8)
            result = self.command(root, 'inspect', safe)
            self.assertEqual(json.loads(Path(result['report']).read_text())['entries'][0]['shape'], [2])

            artifact = root / 'untrusted.pkl'
            artifact.write_bytes(b'cposix\nsystem\n.')
            result = self.command(root, 'inspect', artifact)
            record = json.loads(Path(result['report']).read_text())
            self.assertIn('posix system', record['pickle_globals'])
            self.assertFalse((root / 'side_effect').exists())

    def test_rejects_malformed_safetensors_metadata_without_traceback(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'bad.safetensors'
            metadata = json.dumps({'weights': ['not a tensor record']}).encode()
            source.write_bytes(len(metadata).to_bytes(8, 'little') + metadata)
            result = self.command(root, 'inspect', source, code=2)
            self.assertEqual(result['status'], 'invalid_input')

    def test_compare_small_npz_and_reject_other_formats(self):
        try:
            import numpy as np
        except ImportError:
            self.skipTest('numpy not installed')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            left, right = root / 'left.npz', root / 'right.npz'
            np.savez(left, weights=np.array([1, 2], dtype='int32'))
            np.savez(right, weights=np.array([1, 4], dtype='int32'))
            result = self.command(root, 'compare', left, right)
            tensor = json.loads(Path(result['report']).read_text())['tensors'][0]
            self.assertEqual(tensor['changed'], 1)
            self.assertEqual(tensor['max_abs_delta_approx'], 2)
            other = root / 'other.txt'
            other.write_text('x')
            self.assertIn('accepts two', self.command(root, 'compare', left, other, code=2)['reason'])
            huge = root / 'expanded.npz'
            np.savez_compressed(huge, weights=np.zeros(2_100_000, dtype='float64'))
            self.assertIn('expanded tensor size', self.command(root, 'compare', huge, huge, code=2)['reason'])

    def test_parity_requires_opt_in_and_reports_exact_case_mismatches(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            reference = root / 'reference.py'
            candidate = root / 'candidate.py'
            reference.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\n'
                                 'print(json.dumps({"tokens":[x,x+1],"mask":[1,1],"rendered_prompt":"toy prompt"}))\n')
            candidate.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\n'
                                 'print(json.dumps({"tokens":[x,x+1 if x==1 else x+2],'
                                 '"mask":[1,1],"rendered_prompt":"toy prompt"}))\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(reference)],
                                          'candidate': [sys.executable, str(candidate)],
                                          'cases': [{'x': 1}, {'x': 2}], 'timeout': 2, 'budget': 10}))
            self.assertIn('execute-local', self.command(root, 'parity', config, code=2)['reason'])
            result = self.command(root, 'parity', config, '--execute-local')
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in record['cases']], [True, False])
            self.assertFalse(record['equal'])
            evidence = Path(record['evidence_file'])
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            rows = [json.loads(line) for line in evidence.read_text().splitlines()]
            self.assertEqual([row['input'] for row in rows], [{'x': 1}, {'x': 2}])
            reference = json.loads(base64.b64decode(rows[1]['reference_raw_b64']))
            candidate = json.loads(base64.b64decode(rows[1]['candidate_raw_b64']))
            self.assertEqual(reference['tokens'], [2, 3])
            self.assertEqual(candidate['tokens'], [2, 4])
            self.assertEqual(reference['mask'], [1, 1])
            self.assertEqual(reference['rendered_prompt'], 'toy prompt')
            self.assertNotIn('toy prompt', json.dumps(result))

    def test_parity_timeout_stops_the_child(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sleeper = root / 'sleeper.py'
            sleeper.write_text('import json,sys,time\nx=json.load(sys.stdin)["x"]\n'
                               'if x==2: time.sleep(3)\nprint(json.dumps({"tokens":[x]}))\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(sleeper)],
                                          'candidate': [sys.executable, str(sleeper)],
                                          'cases': [{'x': 1}, {'x': 2}], 'timeout': .8, 'budget': 3}))
            result = self.command(root, 'parity', config, '--execute-local', code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertIn('timed out', report['limits'][0])
            self.assertEqual(len(report['cases']), 1)
            rows = [json.loads(line) for line in Path(report['evidence_file']).read_text().splitlines()]
            self.assertEqual([row['input'] for row in rows], [{'x': 1}, {'x': 2}])
            self.assertEqual(rows[1]['phase'], 'reference')
            self.assertEqual(base64.b64decode(rows[1]['stdout_raw_b64']), b'')

    def test_parity_evidence_limit_retains_only_complete_canaries(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            wrapper = root / 'echo.py'
            wrapper.write_text('import json,sys\nx=json.load(sys.stdin)\n'
                               'print(json.dumps({"tokens":[x["x"]],"mask":[1]}))\n')
            config = root / 'parity.json'
            plan = {'reference': [sys.executable, str(wrapper)],
                    'candidate': [sys.executable, str(wrapper)],
                    'cases': [{'x': 1}], 'timeout': 2, 'budget': 10}
            config.write_text(json.dumps(plan))
            spec = importlib.util.spec_from_file_location('ai_model_under_test', SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            first_run = root / 'first'
            first_run.mkdir(mode=0o700)
            one = module.parity(config, first_run)
            plan['cases'].append({'x': 2})
            config.write_text(json.dumps(plan))
            limited_run = root / 'limited'
            limited_run.mkdir(mode=0o700)
            with patch.object(module, 'MAX_PARITY_EVIDENCE', one['evidence_bytes'] + 1):
                limited = module.parity(config, limited_run)
            self.assertEqual(len(limited['cases']), 1)
            self.assertIn('evidence limit', limited['limits'][0])
            self.assertEqual(len(Path(limited['evidence_file']).read_text().splitlines()), 1)

    def test_parity_rejects_bool_and_decimal_token_type_mismatches(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            reference = root / 'reference.py'
            candidate = root / 'candidate.py'
            reference.write_text('import json,sys\njson.load(sys.stdin)\n'
                                 'print(json.dumps({"tokens":[1],"mask":[1]}))\n')
            candidate.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\n'
                                 'print(json.dumps({"tokens":[True if x==1 else 1.0],"mask":[1]}))\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(reference)],
                                          'candidate': [sys.executable, str(candidate)],
                                          'cases': [{'x': 1}, {'x': 2}], 'timeout': 2, 'budget': 10}))
            result = self.command(root, 'parity', config, '--execute-local')
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in report['cases']], [False, False])

    def test_parity_keeps_escaped_unicode_boundary_canary(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            wrapper = root / 'echo.py'
            wrapper.write_text('import json,sys\nx=json.load(sys.stdin)\n'
                               'print(json.dumps({"input":x}))\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(wrapper)],
                                          'candidate': [sys.executable, str(wrapper)],
                                          'cases': ['\ud800'], 'timeout': 2, 'budget': 10}))
            result = self.command(root, 'parity', config, '--execute-local')
            report = json.loads(Path(result['report']).read_text())
            self.assertTrue(report['equal'])
            row = json.loads(Path(report['evidence_file']).read_text().splitlines()[0])
            self.assertEqual(row['input'], '\ud800')
            self.assertEqual(json.loads(base64.b64decode(row['reference_raw_b64']))['input'], '\ud800')

    def test_parity_keeps_private_wrapper_failure_bytes(self):
        for mode in ('malformed', 'exit', 'nonstandard'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                reference = root / 'reference.py'
                candidate = root / 'candidate.py'
                reference.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\n'
                                     'print(json.dumps({"tokens":[x]}))\n')
                payload = ('{"tokens":[2]}\ndebug' if mode == 'malformed' else
                           '{"tokens":[' if mode == 'exit' else '{"tokens":[NaN]}')
                candidate.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\n'
                                     'if x==2:\n'
                                     ' print(' + repr(payload) + ')\n'
                                     ' print("toy diagnostic",file=sys.stderr)\n'
                                     ' sys.exit(' + ('2' if mode == 'exit' else '0') + ')\n'
                                     'print(json.dumps({"tokens":[x]}))\n')
                config = root / 'parity.json'
                config.write_text(json.dumps({'reference': [sys.executable, str(reference)],
                                              'candidate': [sys.executable, str(candidate)],
                                              'cases': [{'x': 1}, {'x': 2}], 'timeout': 2, 'budget': 10}))
                result = self.command(root, 'parity', config, '--execute-local', code=3)
                report = json.loads(Path(result['report']).read_text())
                self.assertEqual(len(report['cases']), 1)
                lines = [json.loads(line) for line in Path(report['evidence_file']).read_text().splitlines()]
                self.assertEqual(len(lines), 2)
                self.assertEqual(lines[1]['phase'], 'candidate')
                self.assertIn(b'tokens', base64.b64decode(lines[1]['stdout_raw_b64']))
                self.assertIn(b'toy diagnostic', base64.b64decode(lines[1]['stderr_raw_b64']))
                self.assertNotIn('toy diagnostic', json.dumps(result))

    def test_calibrated_search_scores_controls_and_candidates_without_claiming_identity(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            scorer = root / 'scorer.py'
            scorer.write_text('import json,sys\nx=json.load(sys.stdin)\n'
                              'scores={"known":"9.0000000000000001","plain":"0",'
                              '"candidate":"9.0000000000000001","decoy":"9.0"}\n'
                              'print(scores[x])\n')
            config = root / 'search.json'
            plan = {'wrapper': [sys.executable, str(scorer)],
                    'cases': [{'role': role, 'input': value} for role, value in (
                        ('positive', 'known'), ('negative', 'plain'),
                        ('candidate', 'candidate'), ('candidate', 'decoy'))],
                    'direction': 'higher', 'timeout': 2, 'budget': 10}
            config.write_text(json.dumps(plan))
            self.assertIn('execute-local', self.command(root, 'calibrated-search', config, code=2)['reason'])
            result = self.command(root, 'calibrated-search', config, '--execute-local')
            record = json.loads(Path(result['report']).read_text())
            self.assertTrue(record['control_ranges_separate'])
            self.assertEqual(record['candidate_order'], [2, 3])
            self.assertEqual(record['observations'][0]['score'], '9.0000000000000001')
            self.assertEqual(record['observations'][2]['score'], '9.0000000000000001')
            self.assertEqual(record['state'], 'exploratory_ranking')
            self.assertNotIn('known', Path(result['report']).read_text())
            plan['direction'] = 'lower'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local')
            record = json.loads(Path(result['report']).read_text())
            self.assertFalse(record['control_ranges_separate'])
            self.assertEqual(record['candidate_order'], [3, 2])

    def test_calibrated_search_rejects_unsafe_plan_and_keeps_partial_scores(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            scorer = root / 'scorer.py'
            scorer.write_text('import json,sys,time\nx=json.load(sys.stdin)\n'
                              'if x=="slow": time.sleep(2)\n'
                              'print("["*10000+"0"+"]"*10000 if x=="deep" else '
                              '"1e99999999999999999999" if x=="huge" else '
                              'json.dumps("1" if x=="ok" else "NaN"))\n')
            config = root / 'search.json'
            plan = {'wrapper': [sys.executable, str(scorer)],
                    'cases': [{'role': 'negative', 'input': 'ok'},
                              {'role': 'candidate', 'input': 'slow'}],
                    'direction': 'higher', 'timeout': .8, 'budget': 3}
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(len(record['observations']), 1)
            self.assertIn('timed out', record['limits'][0])
            self.assertIsNone(record['control_ranges_separate'])
            plan['cases'][1]['input'] = 'ok'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertIn('no positive control', record['limits'][0])
            self.assertEqual(record['candidate_order'], [1])
            plan['cases'][1]['input'] = 'bad'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertIn('finite scalar', record['limits'][0])
            plan['cases'][1]['input'] = 'huge'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(len(record['observations']), 1)
            self.assertIn('one JSON result', record['limits'][0])
            plan['cases'][1]['input'] = 'deep'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(len(record['observations']), 1)
            self.assertIn('one JSON result', record['limits'][0])
            plan['cases'] *= 26
            config.write_text(json.dumps(plan))
            self.assertIn('1-50 cases', self.command(root, 'calibrated-search', config, '--execute-local', code=2)['reason'])

    def test_calibrated_search_hashes_exact_wrapper_input_order(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            scorer = root / 'ordered.py'
            scorer.write_text('import json,sys\nx=json.load(sys.stdin)\n'
                              'print(0 if isinstance(x,str) else 2 if next(iter(x))=="a" else 1)\n')
            plan = {'wrapper': [sys.executable, str(scorer)], 'direction': 'higher',
                    'cases': [{'role': 'positive', 'input': {'a': 0, 'b': 0}},
                              {'role': 'negative', 'input': 'plain'},
                              {'role': 'candidate', 'input': {'a': 1, 'b': 2}},
                              {'role': 'candidate', 'input': {'b': 2, 'a': 1}}],
                    'timeout': 2, 'budget': 10}
            config = root / 'ordered.json'
            config.write_text(json.dumps(plan))
            result = self.command(root, 'calibrated-search', config, '--execute-local')
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(record['candidate_order'], [2, 3])
            self.assertNotEqual(record['observations'][2]['input_sha256'],
                                record['observations'][3]['input_sha256'])
            self.assertEqual([row['score'] for row in record['observations'][2:]], ['2', '1'])

    def test_calibrated_search_keeps_scores_if_wrapper_disappears(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            scorer = root / 'one_use.py'
            scorer.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                              'x=json.load(sys.stdin)\n'
                              'if x=="first": os.unlink(__file__)\nprint(1)\n')
            scorer.chmod(0o700)
            config = root / 'search.json'
            config.write_text(json.dumps({'wrapper': [str(scorer)],
                                          'cases': [{'role': 'negative', 'input': 'first'},
                                                    {'role': 'candidate', 'input': 'second'}],
                                          'direction': 'higher', 'timeout': 2, 'budget': 10}))
            result = self.command(root, 'calibrated-search', config, '--execute-local', code=3)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(len(record['observations']), 1)
            self.assertIn('wrapper start failed', record['limits'][0])

    def test_svm_parameters_reconstruct_primal_and_slack(self):
        with tempfile.TemporaryDirectory() as root:
            params = Path(root) / 'svm.json'
            params.write_text(json.dumps({'support_vectors': [[1, 0], [0, 1]],
                                          'dual_coef': [[1, -1]], 'intercept': [0]}))
            result = self.command(root, 'svm', params)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(record['weight'], [1, -1])
            self.assertEqual(record['margins'], [1, 1])
            self.assertEqual(record['slack'], [0, 0])

    def test_sign_gates_find_bounded_candidate_and_expose_ambiguity(self):
        try:
            import z3
        except ImportError:
            self.skipTest('z3-solver not installed')
        with tempfile.TemporaryDirectory() as root:
            plan = Path(root) / 'gates.json'
            plan.write_text(json.dumps({'variables': {'byte': [0, 255]},
                                        'gates': [{'name': 'above_a', 'terms': {'byte': 1}, 'bias': -65},
                                                  {'name': 'below_z', 'terms': {'byte': -1}, 'bias': 90}],
                                        'requirements': {'above_a': 1, 'below_z': 1}}))
            result = self.command(root, 'sign-gates', plan)
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(record['satisfiability'], 'sat')
            self.assertGreaterEqual(record['witness']['byte'], 65)
            self.assertLessEqual(record['witness']['byte'], 90)
            self.assertFalse(record['unique_under_declared_constraints'])

            incompatible = json.loads(plan.read_text())
            incompatible['requirements']['above_a'] = 0
            incompatible['requirements']['below_z'] = 0
            plan.write_text(json.dumps(incompatible))
            result = self.command(root, 'sign-gates', plan)
            self.assertEqual(json.loads(Path(result['report']).read_text())['satisfiability'], 'unsat')

    def test_suppression_inverse_is_candidate_with_float64_arithmetic(self):
        try:
            import numpy as np
        except ImportError:
            self.skipTest('numpy not installed')
        with tempfile.TemporaryDirectory() as root:
            base, changed = Path(root) / 'base.npz', Path(root) / 'changed.npz'
            np.savez(base, weight=np.array([1, 2], dtype='float32'))
            np.savez(changed, weight=np.array([.5, 3], dtype='float32'))
            result = self.command(root, 'suppression', base, changed)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['state'], 'candidate')
            with np.load(report['candidate_file'], allow_pickle=False) as candidate:
                self.assertEqual(candidate['weight'].tolist(), [1.5, 1.0])
            np.savez(changed, weight=np.array([1, 3], dtype='int32'))
            self.assertIn('floating arrays', self.command(root, 'suppression', base, changed, code=2)['reason'])


if __name__ == '__main__':
    unittest.main()
