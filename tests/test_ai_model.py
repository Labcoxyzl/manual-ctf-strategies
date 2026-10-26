"""Public offline AI artifact and wrapper checks with independent small inputs."""

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
            reference.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\nprint(json.dumps({"tokens":[x,x+1]}))\n')
            candidate.write_text('import json,sys\nx=json.load(sys.stdin)["x"]\nprint(json.dumps({"tokens":[x,x+1 if x==1 else x+2]}))\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(reference)],
                                          'candidate': [sys.executable, str(candidate)],
                                          'cases': [{'x': 1}, {'x': 2}], 'timeout': 2, 'budget': 10}))
            self.assertIn('execute-local', self.command(root, 'parity', config, code=2)['reason'])
            result = self.command(root, 'parity', config, '--execute-local')
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual([row['equal'] for row in record['cases']], [True, False])
            self.assertFalse(record['equal'])

    def test_parity_timeout_stops_the_child(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sleeper = root / 'sleeper.py'
            sleeper.write_text('import time\ntime.sleep(1)\n')
            config = root / 'parity.json'
            config.write_text(json.dumps({'reference': [sys.executable, str(sleeper)],
                                          'candidate': [sys.executable, str(sleeper)],
                                          'cases': [{'x': 1}], 'timeout': .05, 'budget': 1}))
            result = self.command(root, 'parity', config, '--execute-local', code=2)
            self.assertIn('timed out', result['reason'])

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


if __name__ == '__main__':
    unittest.main()
