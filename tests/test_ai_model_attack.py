"""Generic model attack mechanics are checked against independent toy adapters."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/ai_model_attack.py'


class ModelAttackTests(unittest.TestCase):
    def command(self, root, *args, code=0):
        process = subprocess.run([sys.executable, '-B', str(SCRIPT), '--runs-root', str(Path(root) / 'runs'),
                                  *map(str, args)], capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, code, process.stderr + process.stdout)
        return json.loads(process.stdout)

    def test_gradient_projection_and_explicit_execution(self):
        try:
            import numpy as np
            import torch
        except ImportError:
            self.skipTest('numpy or torch unavailable')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import numpy as np\nimport torch\n'
                               'def load_model(path): return torch.nn.Identity()\n'
                               'def load_input(path): return torch.from_numpy(np.load(path)).float()\n'
                               'def loss(model,x,target): return model(x).sum()\n')
            source = root / 'input.npy'
            np.save(source, np.array([.2, .3], dtype='float32'))
            model = root / 'model.bin'
            model.write_bytes(b'toy')
            args = ['--adapter', adapter, 'gradient', '--model', model, '--input', source,
                    '--target', 'up', '--epsilon', '.2', '--step-size', '.1', '--steps', '2']
            denied = self.command(root, *args, code=2)
            self.assertIn('execute-local', denied['reason'])
            result = self.command(root, '--adapter', adapter, '--execute-local', *args[2:])
            record = json.loads(Path(result['report']).read_text())
            self.assertEqual(record['state'], 'candidate')
            self.assertGreater(record['candidate_objective'], record['clean_objective'])
            self.assertLessEqual(record['max_abs_change'], .200001)
            self.assertTrue(np.allclose(np.load(result['candidate_file']), [.4, .5]))

    def test_gradient_rejects_input_outside_configured_bounds(self):
        try:
            import numpy as np
            import torch
        except ImportError:
            self.skipTest('numpy or torch unavailable')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import numpy as np\nimport torch\n'
                               'def load_model(path): return torch.nn.Identity()\n'
                               'def load_input(path): return torch.from_numpy(np.load(path)).float()\n'
                               'def loss(model,x,target): return model(x).sum()\n')
            source = root / 'input.npy'
            np.save(source, np.array([2.0], dtype='float32'))
            model = root / 'model.bin'
            model.write_bytes(b'toy')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'gradient',
                                  '--model', model, '--input', source, '--target', 'up',
                                  '--epsilon', '.1', '--step-size', '.1', '--steps', '1', code=2)
            self.assertEqual(result['status'], 'invalid_input')

    def test_gradient_rejects_non_tensor_loss_without_traceback(self):
        try:
            import numpy as np
            import torch
        except ImportError:
            self.skipTest('numpy or torch unavailable')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import numpy as np\nimport torch\n'
                               'def load_model(path): return torch.nn.Identity()\n'
                               'def load_input(path): return torch.from_numpy(np.load(path)).float()\n'
                               'def loss(model,x,target): return 1\n')
            source = root / 'input.npy'
            np.save(source, np.array([.5], dtype='float32'))
            model = root / 'model.bin'
            model.write_bytes(b'toy')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'gradient',
                                  '--model', model, '--input', source, '--target', 'up',
                                  '--epsilon', '.1', '--step-size', '.1', '--steps', '1', code=2)
            self.assertEqual(result['status'], 'invalid_input')

    def test_gradient_rejects_nonfinite_candidate_objective(self):
        try:
            import numpy as np
            import torch
        except ImportError:
            self.skipTest('numpy or torch unavailable')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import numpy as np\nimport torch\n'
                               'def load_model(path): return torch.nn.Identity()\n'
                               'def load_input(path): return torch.from_numpy(np.load(path)).float()\n'
                               'def loss(model,x,target):\n'
                               ' if x.detach().max().item() > .5: return torch.tensor(float("nan"))\n'
                               ' return model(x).sum()\n')
            source = root / 'input.npy'
            np.save(source, np.array([.5], dtype='float32'))
            model = root / 'model.bin'
            model.write_bytes(b'toy')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'gradient',
                                  '--model', model, '--input', source, '--target', 'up',
                                  '--epsilon', '.1', '--step-size', '.1', '--steps', '1', code=2)
            self.assertEqual(result['status'], 'invalid_input')

    def test_recurrent_trace_uses_one_policy_call_per_observed_state(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('state=0\n'
                               'def reset(seed):\n global state\n state=0\n return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs,hidden],hidden+1\n'
                               'def env_step(action):\n global state\n state+=action\n return state\n')
            actions = root / 'actions.json'
            actions.write_text('[1,2]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            report = json.loads(Path(result['report']).read_text())
            trace = [json.loads(line) for line in Path(result['trace_file']).read_text().splitlines()]
            self.assertEqual(report['policy_calls'], 3)
            self.assertEqual([(row['pre_aux'], row['post_aux']) for row in trace],
                             [([0, 0], [1, 1]), ([1, 1], [3, 2])])

    def test_recurrent_trace_snapshots_mutated_auxiliary_vector(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('aux=[0]\nstate=0\n'
                               'def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden):\n aux[0]=obs\n return aux,hidden+1\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text('[7]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            trace = json.loads(Path(result['trace_file']).read_text())
            self.assertEqual(trace['pre_aux'], [0])
            self.assertEqual(trace['post_aux'], [7])


if __name__ == '__main__':
    unittest.main()
