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
    source_bytes = source.read_bytes()
    if len(source_bytes) > 64 * 1024:
        raise ValueError('adapter source exceeds 64 KiB')
    spec = importlib.util.spec_from_file_location('ctf_model_adapter', source)
    if spec is None or spec.loader is None:
        raise ValueError('adapter is not importable Python')
    module = importlib.util.module_from_spec(spec)
    exec(compile(source_bytes, str(source), 'exec'), module.__dict__)  # Explicit --execute-local authorizes this code.
    return module, hashlib.sha256(source_bytes).hexdigest()


def _jsonable(value):
    nodes = 0
    size_hint = 0

    def charge(size):
        nonlocal size_hint
        size_hint += size
        if size_hint > 64 * 1024:
            raise ValueError('model state exceeds 64 KiB')

    def convert(item, depth):
        nonlocal nodes
        nodes += 1
        charge(2)
        if depth > 16 or nodes > 10_000:
            raise ValueError('model state exceeds nesting or element limit')
        if hasattr(item, 'detach') or hasattr(item, 'tolist'):
            size = item.numel() if callable(getattr(item, 'numel', None)) else getattr(item, 'size', None)
            if not isinstance(size, int) or not 0 <= size <= 10_000:
                raise ValueError('model state converter exceeds element limit or has unknown size')
        if hasattr(item, 'detach'):
            item = item.detach().cpu()
        if hasattr(item, 'tolist'):
            item = item.tolist()
        if isinstance(item, dict):
            if any(type(key) is not str for key in item):
                raise ValueError('model state dictionary keys must be strings')
            for key in item:
                charge(len(key) + 4)
            return {key: convert(part, depth + 1) for key, part in item.items()}
        if isinstance(item, (list, tuple)):
            return [convert(part, depth + 1) for part in item]
        if isinstance(item, str):
            charge(len(item) + 2)
        elif type(item) in (int, float, bool) or item is None:
            charge(len(str(item)))
        else:
            raise ValueError('model state must be bounded JSON')
        return item

    try:
        encoded = json.dumps(convert(value, 0), allow_nan=False)
    except (TypeError, RecursionError) as error:
        raise ValueError('model state must be bounded JSON') from error
    if len(encoded.encode()) > 64 * 1024:
        raise ValueError('model state exceeds 64 KiB')
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
    action_bytes = action_path.read_bytes()
    if len(action_bytes) > 64 * 1024:
        raise ValueError('actions file exceeds 64 KiB')
    try:
        actions = json.loads(action_bytes)
    except RecursionError as error:
        raise ValueError('actions JSON is too deeply nested') from error
    if not isinstance(actions, list) or not 1 <= len(actions) <= 100:
        raise ValueError('actions must be a JSON list of 1-100 explicit actions')
    trace = run / 'trace.jsonl'
    trace.touch(mode=0o600)
    attempts = run / 'attempts.jsonl'
    attempts.touch(mode=0o600)
    calls = 0
    written_bytes = 0
    completed = 0
    attempted = 0
    limits = []

    def outcome():
        return {'state': 'trace', 'actions': completed, 'attempted_actions': attempted,
                'planned_actions': len(actions), 'policy_calls': calls,
                'trace_file': str(trace), 'attempts_file': str(attempts),
                'actions_sha256': hashlib.sha256(action_bytes).hexdigest(),
                'limits': limits,
                'limit': 'pre/post alignment is a trace; decoding and checker validation remain target-specific'}

    try:
        observation, hidden, previous_action = adapter.reset(args.seed)
        pre_state = {'observation': _jsonable(observation), 'previous_action': _jsonable(previous_action),
                     'hidden_in': _jsonable(hidden)}
        auxiliary, hidden = adapter.policy_step(observation, previous_action, hidden)
        calls = 1
        pre_state['hidden_out'] = _jsonable(hidden)
        pre_aux = _jsonable(auxiliary)
    except TimeoutError:
        limits.append('adapter budget exhausted before first observation')
        return outcome()
    except Exception as error:
        limits.append(f'adapter initialization failed: {type(error).__name__}')
        return outcome()
    with trace.open('w') as stream, attempts.open('w') as attempt_stream:
        for index, action in enumerate(actions):
            try:
                submitted_action = _jsonable(action)
            except TimeoutError:
                limits.append(f'adapter budget exhausted before action {index}')
                break
            except Exception as error:
                limits.append(f'action {index} is not bounded JSON ({type(error).__name__}); not dispatched')
                break
            attempt_stream.write(json.dumps({'index': index, 'action_sha256': hashlib.sha256(
                json.dumps(submitted_action).encode()).hexdigest()}) + '\n')
            attempt_stream.flush()
            attempted += 1
            try:
                observation = adapter.env_step(action)
                post_state = {'observation': _jsonable(observation), 'previous_action': _jsonable(action),
                              'hidden_in': _jsonable(hidden)}
                auxiliary, hidden = adapter.policy_step(observation, action, hidden)
                calls += 1
                post_state['hidden_out'] = _jsonable(hidden)
                post_aux = _jsonable(auxiliary)
                line = json.dumps({'index': index, 'action': submitted_action, 'pre_aux': pre_aux, 'post_aux': post_aux,
                                   'pre_state': pre_state, 'post_state': post_state}, allow_nan=False) + '\n'
            except TimeoutError:
                limits.append(f'adapter budget exhausted during action {index}')
                break
            except Exception as error:
                limits.append(f'adapter state failed during action {index}: {type(error).__name__}')
                break
            if written_bytes + len(line.encode()) > 2 * 1024 * 1024:
                limits.append(f'trace limit reached after attempted action {index}')
                break
            stream.write(line)
            written_bytes += len(line.encode())
            completed += 1
            pre_state, pre_aux = post_state, post_aux
    return outcome()


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
        print(json.dumps({'status': 'partial' if result.get('limits') else 'complete', 'report': str(report),
                          'candidate_file': result.get('candidate_file'), 'trace_file': result.get('trace_file')}))
        return 3 if result.get('limits') else 0
    except TimeoutError as error:
        print(json.dumps({'status': 'partial', 'reason': str(error)}))
        return 3
    except (OSError, ValueError, ImportError, TypeError, RuntimeError, NotImplementedError, SyntaxError) as error:
        print(json.dumps({'status': 'invalid_input', 'reason': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
