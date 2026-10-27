"""Generic model attack mechanics are checked against independent toy adapters."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
            self.assertEqual([row['pre_state'] for row in trace],
                             [{'observation': 0, 'previous_action': 0, 'hidden_in': 0, 'hidden_out': 1},
                              {'observation': 1, 'previous_action': 1, 'hidden_in': 1, 'hidden_out': 2}])
            self.assertEqual([row['post_state'] for row in trace],
                             [{'observation': 1, 'previous_action': 1, 'hidden_in': 1, 'hidden_out': 2},
                              {'observation': 3, 'previous_action': 2, 'hidden_in': 2, 'hidden_out': 3}])
            self.assertEqual(Path(result['trace_file']).stat().st_mode & 0o777, 0o600)

    def test_recurrent_trace_snapshots_mutated_auxiliary_vector(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('aux=[0]\nstate=[0]\n'
                               'def reset(seed):\n state[0]=0\n return state,[0],0\n'
                               'def policy_step(obs,prev,hidden):\n aux[0]=obs[0]\n hidden[0]+=1\n return aux,hidden\n'
                               'def env_step(action):\n state[0]=action\n return state\n')
            actions = root / 'actions.json'
            actions.write_text('[7]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            trace = json.loads(Path(result['trace_file']).read_text())
            self.assertEqual(trace['pre_aux'], [0])
            self.assertEqual(trace['post_aux'], [7])
            self.assertEqual(trace['pre_state'],
                             {'observation': [0], 'previous_action': 0, 'hidden_in': [0], 'hidden_out': [1]})
            self.assertEqual(trace['post_state'],
                             {'observation': [7], 'previous_action': 7, 'hidden_in': [1], 'hidden_out': [2]})

    def test_recurrent_trace_limit_keeps_completed_state_rows(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return "x"*40000,hidden+1\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text(json.dumps(list(range(30))))
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions, code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertLess(report['actions'], report['planned_actions'])
            self.assertIn('trace limit', report['limits'][0])
            self.assertEqual(report['attempted_actions'], report['actions'] + 1)
            trace = Path(result['trace_file'])
            self.assertLessEqual(trace.stat().st_size, 2 * 1024 * 1024)
            self.assertEqual(len(trace.read_text().splitlines()), report['actions'])
            attempts = [json.loads(line) for line in Path(report['attempts_file']).read_text().splitlines()]
            self.assertEqual(len(attempts), report['attempted_actions'])
            self.assertEqual(attempts[-1]['index'], report['actions'])

    def test_recurrent_timeout_keeps_completed_state_rows(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import time\n'
                               'def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden):\n'
                               ' if obs==2: time.sleep(3)\n'
                               ' return [obs,hidden],hidden+1\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text('[1,2]')
            result = self.command(root, '--adapter', adapter, '--execute-local', '--budget', '1',
                                  'recurrent', '--actions', actions, code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['actions'], 1)
            self.assertEqual(report['attempted_actions'], 2)
            self.assertIn('budget exhausted', report['limits'][0])
            self.assertEqual(len(Path(result['trace_file']).read_text().splitlines()), 1)

    def test_recurrent_initial_timeout_keeps_empty_private_trace(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('import time\n'
                               'def reset(seed): time.sleep(3); return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs],hidden\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text('[1]')
            result = self.command(root, '--adapter', adapter, '--execute-local', '--budget', '1',
                                  'recurrent', '--actions', actions, code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['actions'], 0)
            self.assertEqual(report['attempted_actions'], 0)
            self.assertEqual(report['policy_calls'], 0)
            self.assertIn('before first observation', report['limits'][0])
            self.assertEqual(Path(result['trace_file']).read_text(), '')
            self.assertEqual(Path(report['attempts_file']).read_text(), '')

    def test_recurrent_trace_preserves_submitted_action_before_adapter_mutates_it(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs,prev],hidden+1\n'
                               'def env_step(action):\n action.append(9)\n return len(action)\n')
            actions = root / 'actions.json'
            actions.write_text('[[1]]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            report = json.loads(Path(result['report']).read_text())
            row = json.loads(Path(result['trace_file']).read_text())
            self.assertEqual(row['action'], [1])
            self.assertEqual(row['post_state']['previous_action'], [1, 9])
            attempt = json.loads(Path(report['attempts_file']).read_text())
            self.assertEqual(attempt['action_sha256'], hashlib.sha256(b'[1]').hexdigest())

    def test_recurrent_invalid_later_state_keeps_completed_rows(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden):\n'
                               ' return [float("nan") if obs==2 else obs],hidden+1\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text('[1,2]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions, code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual((report['actions'], report['attempted_actions']), (1, 2))
            self.assertIn('ValueError', report['limits'][0])
            self.assertEqual(len(Path(result['trace_file']).read_text().splitlines()), 1)

    def test_recurrent_adapter_key_error_keeps_completed_rows(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs],hidden+1\n'
                               'def env_step(action): return {1:1}[action]\n')
            actions = root / 'actions.json'
            actions.write_text('[1,2]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions, code=3)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual((report['actions'], report['attempted_actions']), (1, 2))
            self.assertIn('KeyError', report['limits'][0])
            self.assertEqual(len(Path(result['trace_file']).read_text().splitlines()), 1)

    def test_recurrent_report_hashes_actions_loaded_before_adapter_rewrites_file(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            actions = root / 'actions.json'
            actions.write_text('[1,2]')
            original = actions.read_bytes()
            adapter = root / 'adapter.py'
            adapter.write_text('from pathlib import Path\n'
                               'def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs],hidden+1\n'
                               'def env_step(action):\n'
                               ' Path(' + repr(str(actions)) + ').write_text("[99]")\n'
                               ' return action\n')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['actions_sha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual([json.loads(line)['action'] for line in Path(result['trace_file']).read_text().splitlines()],
                             [1, 2])
            self.assertEqual(actions.read_text(), '[99]')

    def test_recurrent_report_hashes_executed_adapter_source(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            adapter = root / 'adapter.py'
            adapter.write_text('from pathlib import Path\n'
                               'Path(__file__).write_text("# rewritten after execution began\\n")\n'
                               'def reset(seed): return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs],hidden+1\n'
                               'def env_step(action): return action\n')
            original = adapter.read_bytes()
            actions = root / 'actions.json'
            actions.write_text('[1]')
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions)
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['adapter_sha256'], hashlib.sha256(original).hexdigest())
            self.assertNotEqual(adapter.read_bytes(), original)

    def test_recurrent_state_preflight_rejects_large_converters_and_key_collisions(self):
        spec = importlib.util.spec_from_file_location('ai_model_attack_under_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class HugeTensor:
            def numel(self):
                return 1_000_000
            def detach(self):
                raise AssertionError('oversized tensor was copied')
            def tolist(self):
                raise AssertionError('oversized tensor was converted')

        class SmallTensor:
            size = 2
            def tolist(self):
                return [1, 2]

        with self.assertRaisesRegex(ValueError, 'element limit'):
            module._jsonable(HugeTensor())
        self.assertEqual(module._jsonable((SmallTensor(), {'h': SmallTensor()})),
                         [[1, 2], {'h': [1, 2]}])
        with self.assertRaisesRegex(ValueError, 'keys must be strings'):
            module._jsonable({1: 'first', '1': 'second'})
        with patch.object(module.json, 'dumps', side_effect=AssertionError('oversized state reached encoder')):
            with self.assertRaisesRegex(ValueError, '64 KiB'):
                module._jsonable('x' * 70_000)
            with self.assertRaisesRegex(ValueError, '64 KiB'):
                module._jsonable({'x' * 70_000: 1})
            with self.assertRaisesRegex(ValueError, '64 KiB'):
                module._jsonable(['x' * 100] * 700)

    def test_recurrent_rejects_deep_actions_before_adapter_reset(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sentinel = root / 'reset_called'
            adapter = root / 'adapter.py'
            adapter.write_text('from pathlib import Path\n'
                               'def reset(seed):\n Path(' + repr(str(sentinel)) + ').write_text("called")\n return 0,0,0\n'
                               'def policy_step(obs,prev,hidden): return [obs],hidden\n'
                               'def env_step(action): return action\n')
            actions = root / 'actions.json'
            actions.write_text('[' * 10000 + '0' + ']' * 10000)
            result = self.command(root, '--adapter', adapter, '--execute-local', 'recurrent',
                                  '--actions', actions, code=2)
            self.assertIn('too deeply nested', result['reason'])
            self.assertFalse(sentinel.exists())


if __name__ == '__main__':
    unittest.main()
