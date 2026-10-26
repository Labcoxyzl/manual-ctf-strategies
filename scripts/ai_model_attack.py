#!/usr/bin/env python3
"""Bounded model-wrapper adapters for gradient probes and recurrent state traces."""

import argparse
import hashlib
import importlib.util
import json
import signal
import uuid
from pathlib import Path


def _regular(path, limit):
    source = Path(path).absolute()
    if source.is_symlink() or not source.is_file() or source.stat().st_size > limit:
        raise ValueError('input must be a regular file within the declared size limit')
    return source


def _adapter(path):
    source = _regular(path, 64 * 1024)
    spec = importlib.util.spec_from_file_location('ctf_model_adapter', source)
    if spec is None or spec.loader is None:
        raise ValueError('adapter is not importable Python')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # Explicit --execute-local authorizes this challenge-specific code.
    return module, hashlib.sha256(source.read_bytes()).hexdigest()


def _jsonable(value):
    if hasattr(value, 'detach'):
        value = value.detach().cpu()
    if hasattr(value, 'tolist'):
        value = value.tolist()
    encoded = json.dumps(value, allow_nan=False)
    if len(encoded.encode()) > 64 * 1024:
        raise ValueError('model vector exceeds 64 KiB')
    return json.loads(encoded)


def gradient(adapter, args, run):
    try:
        import numpy as np
        import torch
    except ImportError as error:
        raise ValueError('gradient mode needs installed numpy and torch') from error
    for function in ('load_model', 'load_input', 'loss'):
        if not callable(getattr(adapter, function, None)):
            raise ValueError(f'gradient adapter needs {function}()')
    model_path = _regular(args.model, 256 * 1024 * 1024)
    input_path = _regular(args.input, 64 * 1024 * 1024)
    model = adapter.load_model(str(model_path))
    if hasattr(model, 'eval'):
        model.eval()
    original = adapter.load_input(str(input_path))
    if not isinstance(original, torch.Tensor) or not original.is_floating_point() or not 1 <= original.numel() <= 1_000_000 or not bool(torch.isfinite(original).all()):
        raise ValueError('gradient input must be a finite floating tensor of 1-1000000 elements')
    if not bool(((original >= args.lower) & (original <= args.upper)).all()):
        raise ValueError('gradient input lies outside configured bounds')
    original = original.detach()
    current = original.clone().requires_grad_(True)
    clean_objective = adapter.loss(model, original, args.target)
    if not isinstance(clean_objective, torch.Tensor) or clean_objective.numel() != 1 or not bool(torch.isfinite(clean_objective)):
        raise ValueError('adapter loss must be one finite torch scalar')
    clean = float(clean_objective.detach())
    for _ in range(args.steps):
        objective = adapter.loss(model, current, args.target)
        if not isinstance(objective, torch.Tensor) or objective.numel() != 1 or not bool(torch.isfinite(objective)):
            raise ValueError('adapter loss must be one finite torch scalar')
        derivative = torch.autograd.grad(objective, current)[0]
        if derivative is None or not bool(torch.isfinite(derivative).all()):
            raise ValueError('adapter loss has no finite input gradient')
        with torch.no_grad():
            current = (current + args.step_size * derivative.sign()).clamp(original - args.epsilon,
                                                                            original + args.epsilon)
            current = current.clamp(args.lower, args.upper).detach().requires_grad_(True)
    with torch.no_grad():
        changed_objective = adapter.loss(model, current, args.target)
        if not isinstance(changed_objective, torch.Tensor) or changed_objective.numel() != 1 or not bool(torch.isfinite(changed_objective)):
            raise ValueError('adapter loss must be one finite torch scalar')
        changed = float(changed_objective)
    output = run / 'candidate.npy'
    np.save(output, current.detach().cpu().numpy(), allow_pickle=False)
    return {'state': 'candidate', 'clean_objective': clean, 'candidate_objective': changed,
            'max_abs_change': float((current.detach() - original).abs().max()),
            'candidate_file': str(output), 'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
            'limit': 'objective change is not checker acceptance; adapter supplies the loss and serialization contract'}


def recurrent(adapter, args, run):
    for function in ('reset', 'policy_step', 'env_step'):
        if not callable(getattr(adapter, function, None)):
            raise ValueError(f'recurrent adapter needs {function}()')
    action_path = _regular(args.actions, 64 * 1024)
    actions = json.loads(action_path.read_text())
    if not isinstance(actions, list) or not 1 <= len(actions) <= 100:
        raise ValueError('actions must be a JSON list of 1-100 explicit actions')
    observation, hidden, previous_action = adapter.reset(args.seed)
    auxiliary, hidden = adapter.policy_step(observation, previous_action, hidden)
    trace = run / 'trace.jsonl'
    calls = 1
    with trace.open('w') as stream:
        for index, action in enumerate(actions):
            before = _jsonable(auxiliary)
            observation = adapter.env_step(action)
            auxiliary, hidden = adapter.policy_step(observation, action, hidden)
            calls += 1
            line = json.dumps({'index': index, 'action': action, 'pre_aux': before,
                               'post_aux': _jsonable(auxiliary)}, allow_nan=False) + '\n'
            if stream.tell() + len(line.encode()) > 2 * 1024 * 1024:
                raise ValueError('recurrent trace exceeds 2 MiB')
            stream.write(line)
    return {'state': 'trace', 'actions': len(actions), 'policy_calls': calls,
            'trace_file': str(trace), 'actions_sha256': hashlib.sha256(action_path.read_bytes()).hexdigest(),
            'limit': 'pre/post alignment is a trace; decoding and checker validation remain target-specific'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root')
    parser.add_argument('--adapter', required=True)
    parser.add_argument('--execute-local', action='store_true')
    parser.add_argument('--budget', type=float, default=120)
    modes = parser.add_subparsers(dest='mode', required=True)
    grad = modes.add_parser('gradient')
    grad.add_argument('--model', required=True)
    grad.add_argument('--input', required=True)
    grad.add_argument('--target', required=True)
    grad.add_argument('--epsilon', type=float, required=True)
    grad.add_argument('--step-size', type=float, required=True)
    grad.add_argument('--steps', type=int, default=10)
    grad.add_argument('--lower', type=float, default=0)
    grad.add_argument('--upper', type=float, default=1)
    trace = modes.add_parser('recurrent')
    trace.add_argument('--actions', required=True)
    trace.add_argument('--seed', type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if not args.execute_local:
            raise ValueError('adapter code executes locally; pass --execute-local')
        if not 0 < args.budget <= 600:
            raise ValueError('budget must be 0-600 seconds')
        if args.mode == 'gradient' and not (0 < args.epsilon <= 255 and 0 < args.step_size <= args.epsilon and 1 <= args.steps <= 100 and args.lower < args.upper):
            raise ValueError('gradient requires bounded epsilon, step size, steps, and input bounds')
        run = Path(args.runs_root or '.autosolve/runs') / f'ai-attack-{uuid.uuid4().hex[:12]}'
        run.mkdir(parents=True, mode=0o700)
        old_handler = signal.getsignal(signal.SIGALRM)
        def expired(*_):
            raise TimeoutError('model adapter budget exhausted')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, args.budget)
        try:
            adapter, digest = _adapter(args.adapter)
            result = gradient(adapter, args, run) if args.mode == 'gradient' else recurrent(adapter, args, run)
            result['adapter_sha256'] = digest
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
        report = run / 'result.json'
        report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': 'complete', 'report': str(report),
                          'candidate_file': result.get('candidate_file'), 'trace_file': result.get('trace_file')}))
        return 0
    except TimeoutError as error:
        print(json.dumps({'status': 'partial', 'reason': str(error)}))
        return 3
    except (OSError, ValueError, ImportError, TypeError, RuntimeError, NotImplementedError) as error:
        print(json.dumps({'status': 'invalid_input', 'reason': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
