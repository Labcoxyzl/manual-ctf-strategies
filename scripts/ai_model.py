#!/usr/bin/env python3
"""Safe AI artifact triage, bounded tensor comparison, and explicit wrapper parity."""

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import pickletools
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path


MAX_HEADER = 8 * 1024 * 1024
MAX_ENTRIES = 1000


def _private_run(root):
    run = Path(root or '.autosolve/runs') / f'ai-model-{uuid.uuid4().hex[:12]}'
    run.mkdir(parents=True, mode=0o700)
    return run


def _regular(path):
    source = Path(path).absolute()
    if source.is_symlink() or not source.is_file():
        raise ValueError('input must be a regular file, not a symlink')
    return source


def _sha256(path, max_bytes):
    if path.stat().st_size > max_bytes:
        return None
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _pickle_globals(data):
    names = []
    try:
        for op, value, _ in pickletools.genops(data):
            if op.name == 'GLOBAL':
                names.append(value)
            elif op.name == 'STACK_GLOBAL':
                names.append('<stack global>')
            if len(names) >= 100:
                break
    except (EOFError, ValueError, IndexError):
        return names, 'truncated or malformed pickle; no deserialization attempted'
    return names, None


def _npy_header(stream):
    magic = stream.read(8)
    if magic[:6] != b'\x93NUMPY':
        return None
    size_width = 2 if magic[6] == 1 else 4
    if magic[6] not in (1, 2, 3):
        return None
    size = int.from_bytes(stream.read(size_width), 'little')
    if size > 4096:
        return {'header': 'over 4096 bytes'}
    import ast
    value = ast.literal_eval(stream.read(size).decode('latin1'))
    if not isinstance(value, dict):
        raise ValueError('invalid npy header')
    return {key: value.get(key) for key in ('descr', 'fortran_order', 'shape')}


def inspect(path, max_bytes):
    source = _regular(path)
    record = {'path': str(source), 'size': source.stat().st_size, 'sha256': _sha256(source, max_bytes),
              'kind': 'unknown', 'entries': [], 'limits': []}
    with source.open('rb') as stream:
        head = stream.read(8)
    if head.startswith(b'\x93NUMPY'):
        with source.open('rb') as stream:
            record['entries'].append({'name': '<array>', **(_npy_header(stream) or {})})
        record['kind'] = 'npy'
    elif source.suffix == '.safetensors':
        header_size = int.from_bytes(head, 'little')
        if header_size > MAX_HEADER or header_size + 8 > source.stat().st_size:
            record['limits'].append('safetensors header too large or incomplete')
        else:
            with source.open('rb') as stream:
                stream.seek(8)
                header = json.loads(stream.read(header_size))
            if not isinstance(header, dict):
                raise ValueError('invalid safetensors header')
            record['kind'] = 'safetensors'
            for name, meta in list(header.items())[:MAX_ENTRIES]:
                if not isinstance(meta, dict):
                    raise ValueError('invalid safetensors tensor metadata')
                record['entries'].append({'name': name, 'shape': meta.get('shape'), 'dtype': meta.get('dtype')})
            if len(header) > MAX_ENTRIES:
                record['limits'].append('tensor entry cap reached')
    elif zipfile.is_zipfile(source):
        record['kind'] = 'zip-backed model or npz'
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist()[:MAX_ENTRIES]:
                entry = {'name': info.filename, 'compressed_size': info.compress_size, 'size': info.file_size}
                if info.filename.endswith('.npy') and info.file_size <= max_bytes:
                    with archive.open(info) as stream:
                        entry.update(_npy_header(stream) or {})
                elif info.filename.endswith('data.pkl') and info.file_size <= MAX_HEADER:
                    with archive.open(info) as stream:
                        entry['pickle_globals'], warning = _pickle_globals(stream.read(MAX_HEADER + 1))
                    if warning:
                        record['limits'].append(warning)
                record['entries'].append(entry)
            if len(archive.infolist()) > MAX_ENTRIES:
                record['limits'].append('archive member cap reached')
    elif source.suffix in ('.pkl', '.pickle', '.joblib'):
        record['kind'] = 'pickle-like'
        with source.open('rb') as stream:
            record['pickle_globals'], warning = _pickle_globals(stream.read(MAX_HEADER + 1))
        if source.stat().st_size > MAX_HEADER or warning:
            record['limits'].append(warning or 'pickle preview limited to 8 MiB')
    else:
        record['limits'].append('format-specific parser unavailable; no model code executed')
    if record['sha256'] is None:
        record['limits'].append('whole-file hash skipped at max-bytes limit')
    return record


def _npz_preflight(source, max_bytes):
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) > MAX_ENTRIES or any(item.file_size > 16 * 1024 * 1024 for item in members) or sum(item.file_size for item in members) > max_bytes:
            raise ValueError('NPZ expanded tensor size or member count exceeds comparison limit')


def compare(left, right, max_bytes):
    first, second = _regular(left), _regular(right)
    if first.stat().st_size > max_bytes or second.stat().st_size > max_bytes:
        raise ValueError('tensor files exceed max-bytes')
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError('tensor comparison needs installed numpy') from error
    if first.suffix == second.suffix == '.safetensors':
        try:
            from safetensors.numpy import load_file
        except ImportError as error:
            raise ValueError('safetensors comparison needs installed safetensors') from error
        a, b = load_file(str(first)), load_file(str(second))
    elif first.suffix == second.suffix == '.npz':
        for source in (first, second):
            _npz_preflight(source, max_bytes)
        a, b = np.load(first, allow_pickle=False), np.load(second, allow_pickle=False)
    else:
        raise ValueError('compare accepts two .npz or two .safetensors files')
    result = {'left_sha256': _sha256(first, max_bytes), 'right_sha256': _sha256(second, max_bytes),
              'only_left': sorted(set(a) - set(b)), 'only_right': sorted(set(b) - set(a)), 'tensors': [], 'limits': []}
    for name in sorted(set(a) & set(b))[:MAX_ENTRIES]:
        x, y = a[name], b[name]
        entry = {'name': name, 'shape_left': list(x.shape), 'shape_right': list(y.shape),
                 'dtype_left': str(x.dtype), 'dtype_right': str(y.dtype)}
        if x.shape == y.shape and x.size <= 1_000_000 and np.issubdtype(x.dtype, np.number) and np.issubdtype(y.dtype, np.number) and not np.iscomplexobj(x) and not np.iscomplexobj(y) and np.all(np.isfinite(x)) and np.all(np.isfinite(y)):
            diff = x.astype('float64') - y.astype('float64')
            entry.update({'changed': int(np.count_nonzero(x != y)), 'max_abs_delta_approx': float(np.max(np.abs(diff))) if diff.size else 0.0})
        else:
            entry['limit'] = 'shape, dtype, or million-element comparison limit'
        result['tensors'].append(entry)
    if len(set(a) & set(b)) > MAX_ENTRIES:
        result['limits'].append('tensor entry cap reached')
    if hasattr(a, 'close'):
        a.close()
    if hasattr(b, 'close'):
        b.close()
    return result


def suppress(base_path, challenge_path, max_bytes, run):
    base, challenge = _regular(base_path), _regular(challenge_path)
    if base.suffix != '.npz' or challenge.suffix != '.npz' or base.stat().st_size > max_bytes or challenge.stat().st_size > max_bytes:
        raise ValueError('suppression hypothesis accepts two bounded NPZ files')
    for source in (base, challenge):
        _npz_preflight(source, max_bytes)
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError('suppression hypothesis needs installed numpy') from error
    recovered = {}
    elements = 0
    with np.load(base, allow_pickle=False) as original, np.load(challenge, allow_pickle=False) as modified:
        if set(original) != set(modified) or len(original) > MAX_ENTRIES:
            raise ValueError('suppression tensors must have identical names')
        for name in original:
            left, right = original[name], modified[name]
            if (left.shape != right.shape or left.size > 1_000_000 or
                    not np.issubdtype(left.dtype, np.floating) or not np.issubdtype(right.dtype, np.floating) or
                    not np.all(np.isfinite(left)) or not np.all(np.isfinite(right))):
                raise ValueError('suppression tensors need finite matching floating arrays within size limits')
            elements += left.size
            if elements > 5_000_000:
                raise ValueError('suppression candidate exceeds five million elements')
            recovered[name] = 2 * left.astype('float64') - right.astype('float64')
    candidate = run / 'suppression_candidate.npz'
    np.savez(candidate, **recovered)
    return {'state': 'candidate', 'candidate_file': str(candidate), 'tensors': len(recovered),
            'base_sha256': _sha256(base, max_bytes), 'challenge_sha256': _sha256(challenge, max_bytes),
            'limit': '2*base-challenge in float64 is one explicit hypothesis, not identified historical weights or accepted behavior'}


def svm(path):
    source = _regular(path)
    if source.stat().st_size > 1024 * 1024:
        raise ValueError('SVM parameter JSON exceeds 1 MiB')
    params = json.loads(source.read_text())
    if not isinstance(params, dict) or set(params) - {'support_vectors', 'dual_coef', 'intercept'} or set(params) != {'support_vectors', 'dual_coef', 'intercept'}:
        raise ValueError('SVM JSON needs support_vectors, dual_coef, intercept')
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError('SVM analysis needs installed numpy') from error
    vectors = np.asarray(params['support_vectors'], dtype='float64')
    dual = np.asarray(params['dual_coef'], dtype='float64')
    intercept = np.asarray(params['intercept'], dtype='float64')
    if (vectors.ndim != 2 or not 1 <= vectors.shape[0] <= 10000 or not 1 <= vectors.shape[1] <= 10000 or
            vectors.size > 1_000_000 or dual.shape != (1, vectors.shape[0]) or intercept.shape != (1,) or
            not np.all(np.isfinite(vectors)) or not np.all(np.isfinite(dual)) or not np.all(np.isfinite(intercept))):
        raise ValueError('SVM arrays must be finite binary-class parameters within size limits')
    weight = dual[0] @ vectors
    labels = np.sign(dual[0])
    margins = labels * (vectors @ weight + intercept[0])
    slack = np.maximum(0, 1 - margins)
    return {'weight': weight.tolist(), 'intercept': float(intercept[0]),
            'support_labels': labels.astype('int8').tolist(),
            'margins': margins.tolist(), 'slack': slack.tolist(),
            'zero_dual_indices': np.flatnonzero(labels == 0).tolist(),
            'limit': 'parameter-level hypotheses only; verify any decoded candidate through the supplied checker'}


def sign_gates(path, timeout):
    source = _regular(path)
    if source.stat().st_size > 64 * 1024:
        raise ValueError('sign-gate description exceeds 64 KiB')
    plan = json.loads(source.read_text())
    if not isinstance(plan, dict) or set(plan) != {'variables', 'gates', 'requirements'}:
        raise ValueError('sign-gate JSON needs variables, gates, requirements')
    try:
        import z3
    except ImportError as error:
        raise ValueError('sign-gate constraints need installed z3-solver') from error
    variables, gates, required = plan['variables'], plan['gates'], plan['requirements']
    if not isinstance(variables, dict) or not 1 <= len(variables) <= 128 or not isinstance(gates, list) or len(gates) > 512 or not isinstance(required, dict) or not required:
        raise ValueError('sign-gate description exceeds variable or gate limits')
    solver = z3.Solver()
    solver.set(timeout=max(1, int(timeout * 1000)))
    symbols = {}
    for name, bounds in variables.items():
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) or not isinstance(bounds, list) or len(bounds) != 2 or any(type(x) is not int for x in bounds) or not 0 <= bounds[0] <= bounds[1] <= 65535:
            raise ValueError('invalid sign-gate variable or bounds')
        value = z3.Int(name)
        solver.add(value >= bounds[0], value <= bounds[1])
        symbols[name] = value
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) - {'name', 'terms', 'bias', 'strict'} or not isinstance(gate.get('name'), str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', gate['name']) or gate['name'] in symbols or not isinstance(gate.get('terms'), dict) or not gate['terms'] or len(gate['terms']) > 128 or type(gate.get('bias', 0)) is not int or abs(gate.get('bias', 0)) > 1_000_000_000 or type(gate.get('strict', False)) is not bool:
            raise ValueError('invalid sign gate')
        if any(name not in symbols or type(coefficient) is not int or abs(coefficient) > 1_000_000 for name, coefficient in gate['terms'].items()):
            raise ValueError('sign gate refers to an unknown or future input')
        affine = z3.Sum([coefficient * symbols[name] for name, coefficient in gate['terms'].items()]) + gate.get('bias', 0)
        value = z3.Int(gate['name'])
        solver.add(value == z3.If(affine > 0 if gate.get('strict', False) else affine >= 0, 1, 0))
        symbols[gate['name']] = value
    for name, bit in required.items():
        if name not in symbols or type(bit) is not int or bit not in (0, 1):
            raise ValueError('requirements must name known gates or Boolean variables')
        solver.add(symbols[name] == bit)
    status = solver.check()
    result = {'satisfiability': str(status), 'variables': len(variables), 'gates': len(gates),
              'limit': 'a satisfying assignment is only a candidate until the supplied verifier accepts it'}
    if status == z3.unknown:
        result['limits'] = ['solver returned unknown or timed out']
    if status == z3.sat:
        model = solver.model()
        witness = {name: model.evaluate(symbols[name]).as_long() for name in variables}
        result['witness'] = witness
        solver.add(z3.Or([symbols[name] != value for name, value in witness.items()]))
        alternate = solver.check()
        result['unique_under_declared_constraints'] = alternate == z3.unsat if alternate != z3.unknown else None
        if alternate == z3.unknown:
            result['limits'] = ['alternate-solution check timed out']
    return result


def _child(argv, value, timeout, run, *, exact_decimal=False):
    def cap_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024, 64 * 1024))

    with tempfile.TemporaryFile(dir=run) as stdout, tempfile.TemporaryFile(dir=run) as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   start_new_session=True, preexec_fn=cap_output)
        try:
            process.communicate(json.dumps(value).encode() + b'\n', timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ValueError('wrapper timed out; run incomplete') from error
        if process.returncode:
            raise ValueError(f'wrapper exited {process.returncode}; run incomplete')
        if stdout.tell() > 64 * 1024 or stderr.tell() > 64 * 1024:
            raise ValueError('wrapper output exceeded 64 KiB')
        stdout.seek(0)
        try:
            return json.load(stdout, parse_float=Decimal) if exact_decimal else json.load(stdout)
        except (ValueError, UnicodeError, InvalidOperation, RecursionError) as error:
            raise ValueError('wrapper did not return one JSON result') from error


def parity(config_path, run):
    path = _regular(config_path)
    if path.stat().st_size > 64 * 1024:
        raise ValueError('parity config exceeds 64 KiB')
    config = json.loads(path.read_text())
    if not isinstance(config, dict) or set(config) != {'reference', 'candidate', 'cases', 'timeout', 'budget'}:
        raise ValueError('parity config needs reference, candidate, cases, timeout, budget')
    for key in ('reference', 'candidate'):
        argv = config[key]
        if not isinstance(argv, list) or not 1 <= len(argv) <= 16 or any(not isinstance(x, str) or not x or len(x) > 1024 for x in argv):
            raise ValueError(f'{key} must be an argv array')
    if not isinstance(config['cases'], list) or not 1 <= len(config['cases']) <= 20 or not isinstance(config['timeout'], (int, float)) or not 0 < config['timeout'] <= 30 or not isinstance(config['budget'], (int, float)) or not 0 < config['budget'] <= 600:
        raise ValueError('parity needs 1-20 cases, per-call timeout 0-30s, and total budget 0-600s')
    deadline = time.monotonic() + config['budget']
    rows = []
    for index, case in enumerate(config['cases']):
        if len(json.dumps(case, allow_nan=False).encode()) > 8192:
            raise ValueError('parity canary exceeds 8192 bytes')
        if time.monotonic() >= deadline:
            raise ValueError('parity budget exhausted; remaining canaries untested')
        reference = _child(config['reference'], case, min(config['timeout'], deadline - time.monotonic()), run)
        candidate = _child(config['candidate'], case, min(config['timeout'], max(.001, deadline - time.monotonic())), run)
        rows.append({'case': index, 'equal': reference == candidate,
                     'reference_sha256': hashlib.sha256(json.dumps(reference, sort_keys=True).encode()).hexdigest(),
                     'candidate_sha256': hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()})
    return {'cases': rows, 'equal': all(row['equal'] for row in rows),
            'limit': 'checks the declared canary cases only; local wrapper code is executed'}


def calibrated_search(config_path, run):
    path = _regular(config_path)
    if path.stat().st_size > 64 * 1024:
        raise ValueError('calibrated-search config exceeds 64 KiB')
    raw = path.read_bytes()
    try:
        config = json.loads(raw)
    except RecursionError as error:
        raise ValueError('calibrated-search config is too deeply nested') from error
    if not isinstance(config, dict) or set(config) != {'wrapper', 'cases', 'direction', 'timeout', 'budget'}:
        raise ValueError('calibrated-search needs wrapper, cases, direction, timeout, budget')
    argv = config['wrapper']
    cases = config['cases']
    if not isinstance(argv, list) or not 1 <= len(argv) <= 16 or any(not isinstance(x, str) or not x or len(x) > 1024 for x in argv):
        raise ValueError('wrapper must be an argv array')
    if not isinstance(cases, list) or not 1 <= len(cases) <= 50:
        raise ValueError('calibrated-search needs 1-50 cases')
    if (config['direction'] not in ('higher', 'lower') or type(config['timeout']) not in (int, float) or
            not 0 < config['timeout'] <= 30 or type(config['budget']) not in (int, float) or
            not 0 < config['budget'] <= 600):
        raise ValueError('calibrated-search needs higher/lower direction, timeout 0-30s and budget 0-600s')
    encoded = []
    roles = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {'role', 'input'} or case['role'] not in ('positive', 'negative', 'candidate'):
            raise ValueError('each case needs a role and input')
        try:
            value = json.dumps(case['input'], allow_nan=False).encode() + b'\n'
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError('case input must be bounded JSON') from error
        if len(value) > 8192:
            raise ValueError('case input exceeds 8192 bytes')
        encoded.append(value)
        roles.append(case['role'])
    if 'negative' not in roles or 'candidate' not in roles:
        raise ValueError('calibrated-search needs negative and candidate cases')
    deadline = time.monotonic() + config['budget']
    observations, scores, limits = [], [], []
    for index, case in enumerate(cases):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            limits.append(f'budget exhausted before case {index}')
            break
        try:
            output = _child(argv, case['input'], min(config['timeout'], remaining), run, exact_decimal=True)
            if type(output) not in (str, int, float, Decimal):
                raise ValueError('wrapper score must be a finite scalar')
            if len(str(output)) > 512:
                raise ValueError('wrapper score exceeds 512 characters')
            try:
                score = Decimal(str(output))
            except InvalidOperation as error:
                raise ValueError('wrapper score must be a finite scalar') from error
            if not score.is_finite():
                raise ValueError('wrapper score must be a finite scalar')
        except ValueError as error:
            limits.append(f'case {index}: {error}')
            break
        except OSError:
            limits.append(f'case {index}: wrapper start failed; run incomplete')
            break
        scores.append(score)
        observations.append({'case': index, 'role': case['role'], 'input_sha256': hashlib.sha256(encoded[index]).hexdigest(),
                             'score': str(score)})
    positive = [score for row, score in zip(observations, scores) if row['role'] == 'positive']
    negative = [score for row, score in zip(observations, scores) if row['role'] == 'negative']
    complete = len(observations) == len(cases)
    separated = None
    if complete and positive and negative:
        separated = min(positive) > max(negative) if config['direction'] == 'higher' else max(positive) < min(negative)
    if complete and not positive:
        limits.append('no positive control; ranking is uncalibrated')
    ranked = [row['case'] for row, score in sorted(zip(observations, scores),
              key=lambda pair: pair[1], reverse=config['direction'] == 'higher') if row['role'] == 'candidate']
    return {'state': 'exploratory_ranking', 'cases': len(cases), 'observations': observations,
            'candidate_order': ranked, 'control_ranges_separate': separated, 'limits': limits,
            'config_sha256': hashlib.sha256(raw).hexdigest(),
            'limit': 'scores are exploratory; model behavior and identity require the supplied checker'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root')
    modes = parser.add_subparsers(dest='mode', required=True)
    for name, count in (('inspect', 1), ('compare', 2)):
        command = modes.add_parser(name)
        command.add_argument('paths', nargs=count)
        command.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    check = modes.add_parser('parity')
    check.add_argument('config')
    check.add_argument('--execute-local', action='store_true')
    search = modes.add_parser('calibrated-search')
    search.add_argument('config')
    search.add_argument('--execute-local', action='store_true')
    svm_mode = modes.add_parser('svm')
    svm_mode.add_argument('parameters', help='JSON exported from the supplied binary-class SVM wrapper')
    gates_mode = modes.add_parser('sign-gates')
    gates_mode.add_argument('description', help='JSON affine sign-gate network exported from the wrapper')
    gates_mode.add_argument('--timeout', type=float, default=10)
    suppression = modes.add_parser('suppression')
    suppression.add_argument('base')
    suppression.add_argument('challenge')
    suppression.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    args = parser.parse_args(argv)
    try:
        if args.mode in ('inspect', 'compare', 'suppression') and not 0 < args.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError('max-bytes must be 1 to 1073741824')
        if args.mode in ('parity', 'calibrated-search') and not args.execute_local:
            raise ValueError(f'{args.mode} executes a supplied wrapper; pass --execute-local')
        if args.mode == 'sign-gates' and not 0 < args.timeout <= 30:
            raise ValueError('sign-gate timeout must be 0-30 seconds')
        run = _private_run(args.runs_root)
        if args.mode == 'inspect':
            result = inspect(args.paths[0], args.max_bytes)
        elif args.mode == 'compare':
            result = compare(*args.paths, args.max_bytes)
        elif args.mode == 'svm':
            result = svm(args.parameters)
        elif args.mode == 'sign-gates':
            result = sign_gates(args.description, args.timeout)
        elif args.mode == 'suppression':
            result = suppress(args.base, args.challenge, args.max_bytes, run)
        elif args.mode == 'calibrated-search':
            result = calibrated_search(args.config, run)
        else:
            result = parity(args.config, run)
        (run / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        entries = result.get('entries', result.get('tensors', result.get('cases', [])))
        print(json.dumps({'status': 'complete' if not result.get('limits') else 'partial',
                          'report': str(run / 'result.json'), 'entries': entries if isinstance(entries, int) else len(entries)}))
        return 0 if not result.get('limits') else 3
    except (OSError, ValueError, zipfile.BadZipFile, SyntaxError) as error:
        print(json.dumps({'status': 'invalid_input', 'reason': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
