"""Private bounded selected web checks."""

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import resource
import stat
import time
from urllib.parse import parse_qsl, urlsplit
import uuid

from . import core
from .profiles.web_discovery import _validate, discover_web
from .profiles.web_leads import _validate as _validate_leads, probe_web_leads
from .profiles.web_static import _origin


def _regular_bytes(path, limit, label):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular file of at most {limit} bytes") from exc
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"{label} must be a regular file of at most {limit} bytes")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return data


def _request(raw, origin):
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    header, marker, body = raw.partition(separator)
    if not marker:
        raise ValueError("request needs a complete HTTP header block")
    if b"\r" in header.replace(b"\r\n", b""):
        raise ValueError("request has unsupported line endings")
    try:
        lines = header.replace(b"\r\n", b"\n").decode("ascii").split("\n")
    except UnicodeError as exc:
        raise ValueError("request headers must be ASCII") from exc
    first = lines[0].split(" ")
    if (len(first) != 3 or not re.fullmatch(r"[A-Z]{1,12}", first[0]) or
            first[2] not in ("HTTP/1.0", "HTTP/1.1")):
        raise ValueError("request needs an HTTP/1.x method and target")
    method, target, _ = first
    parts = urlsplit(target)
    if (not target.startswith("/") or target.startswith("//") or parts.scheme or
            parts.netloc or parts.fragment or len(target) > 2048 or
            any(ord(char) < 33 or ord(char) > 126 for char in target)):
        raise ValueError("request target must be one same-origin path")
    entries = []
    for line in lines[1:]:
        if not line or line.startswith((" ", "\t")) or ":" not in line:
            raise ValueError("request has an invalid or folded header")
        key, value = line.split(":", 1)
        value = value.lstrip(" ")
        if (not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key) or len(value) > 2048 or
                any(ord(char) < 32 or ord(char) > 126 for char in value)):
            raise ValueError("request has an invalid header")
        entries.append((key, value))
    if len(entries) > 20:
        raise ValueError("request header count exceeds 20")
    if len({key.lower() for key, _ in entries}) != len(entries):
        raise ValueError("request header names must be unique")
    hosts = [value for key, value in entries if key.lower() == "host"]
    if len(hosts) != 1 or _origin(f"{urlsplit(origin).scheme}://{hosts[0]}") != _origin(origin):
        raise ValueError("request Host must exactly match --scope-origin")
    if any(key.lower() == "transfer-encoding" for key, _ in entries):
        raise ValueError("chunked request bodies are not supported")
    lengths = [value for key, value in entries if key.lower() == "content-length"]
    if len(lengths) > 1 or (lengths and (not lengths[0].isdecimal() or int(lengths[0]) != len(body))):
        raise ValueError("request Content-Length does not match its body")
    if body and not lengths:
        raise ValueError("request body needs one exact Content-Length")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValueError("request query must contain named key/value pairs") from exc
    if len(pairs) > 16 or len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("request query must contain at most 16 unique parameters")
    forbidden = {"host", "content-length", "transfer-encoding", "connection"}
    headers = {key: value for key, value in entries if key.lower() not in forbidden}
    return {"method": method, "path": parts.path or "/", "query": dict(pairs),
            "headers": headers}, body


def _wordlist(path):
    if path is None:
        return None, None
    raw = _regular_bytes(path, 4096, "wordlist")
    try:
        words = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    except UnicodeError as exc:
        raise ValueError("wordlist must be UTF-8 text") from exc
    if not 0 < len(words) <= 32:
        raise ValueError("wordlist needs 1 to 32 nonempty lines")
    return words, hashlib.sha256(raw).hexdigest()


def _worker(scope, timeout, max_requests, rate, lead, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        profile = probe_web_leads if lead else discover_web
        report, warnings = profile(scope, timeout=timeout,
                                   max_requests=max_requests, rate=rate)
        pipe.send((report, warnings))
    except Exception as exc:
        pipe.send((None, [f"web profile failed: {type(exc).__name__}"]))
    finally:
        pipe.close()


def _run(scope, timeout, max_requests, rate, lead=False):
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=core._worker_entry,
                                     args=(_worker, scope, timeout, max_requests, rate, lead, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .1):
            return None, ["web profile hard deadline reached; request count may be incomplete"]
        return parent.recv()
    except EOFError:
        return None, ["web profile exited without a result"]
    finally:
        core._stop_worker(worker)
        parent.close()


def _sql_worker(raw, origin, parameter, options, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        from .profiles.web_sql import assess_sql
        pipe.send(assess_sql(raw, origin, parameter, authorized=True,
                             test_mode=True, **options))
    except Exception as exc:
        pipe.send((None, [f"WEB03 profile failed: {type(exc).__name__}"]))
    finally:
        pipe.close()


def _run_sql(raw, origin, parameter, options):
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=core._worker_entry,
                                     args=(_sql_worker, raw, origin, parameter, options, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(options['timeout'] + .1):
            return None, ["WEB03 hard deadline reached; request count may be incomplete"]
        return parent.recv()
    except EOFError:
        return None, ["WEB03 worker exited without a result"]
    finally:
        core._stop_worker(worker)
        parent.close()


def _workflow_worker(fixtures, origin, timeout, max_requests, rate, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        from .profiles.web_workflows import replay_workflows
        pipe.send(replay_workflows(fixtures, origin=origin, timeout=timeout,
                                   max_requests=max_requests, rate=rate))
    except Exception as exc:
        pipe.send((None, [f"WEB08 profile failed: {type(exc).__name__}"]))
    finally:
        pipe.close()


def _run_workflow(fixtures, origin, timeout, max_requests, rate):
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=core._worker_entry,
                                     args=(_workflow_worker, fixtures, origin, timeout,
                                           max_requests, rate, child))
    worker.start()
    child.close()
    try:
        if not parent.poll(timeout + .1):
            return None, ["WEB08 hard deadline reached; request count may be incomplete"]
        return parent.recv()
    except EOFError:
        return None, ["WEB08 worker exited without a result"]
    finally:
        core._stop_worker(worker)
        parent.close()


def _manifest(run):
    if run.is_symlink():
        raise ValueError("web run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or manifest.get("category") != "web"
            or manifest.get("run_type") not in ("web_discovery", "web_sql", "web_leads",
                                                "web_workflow")):
        raise ValueError("not a compatible web run")
    return manifest


def _render(run, manifest):
    if manifest['run_type'] == 'web_workflow':
        lines = ['# Autosolve web workflow comparison', '',
                 'Status: partial. Challenge acceptance: unverified.',
                 f"WEB08: {manifest['profile_status']}; "
                 f"{manifest['requests_used']} requests recorded.",
                 f"Assessment: {manifest['assessment']}.",
                 'The assessment is an observed workflow clue, not proof of an authorization flaw.',
                 'The supplied sessions, response bodies and state evidence are private in this run.',
                 'Resume and report only render stored evidence; neither sends another request.']
        if manifest['warnings']:
            lines += ['', 'Warnings: ' + '; '.join(manifest['warnings'])]
        core._write_text(run / 'report.md', '\n'.join(lines) + '\n')
        return
    if manifest['run_type'] == 'web_sql':
        lines = ['# Autosolve web SQL assessment', '',
                 'Status: partial. Challenge acceptance: unverified.',
                 f"WEB03: {manifest['profile_status']}; {manifest['requests_used']} requests recorded.",
                 f"Assessment: {manifest['classification']}.",
                 'The differential is a lead; server acceptance is unverified.',
                 'The raw request, response bodies and selected comparison are private in this run.',
                 'Resume and report only render stored evidence; neither sends another request.']
        if manifest['warnings']:
            lines += ['', 'Warnings: ' + '; '.join(manifest['warnings'])]
        core._write_text(run / 'report.md', '\n'.join(lines) + '\n')
        return
    lead = manifest["run_type"] == "web_leads"
    family = "WEB05" if lead else "WEB02"
    lines = ["# Autosolve web leads" if lead else "# Autosolve web discovery", "",
             "Status: partial. Challenge acceptance: unverified.",
             f"{family}: {manifest['profile_status']}; {manifest['requests_used']} requests recorded.",
             f"Calibration: {manifest['calibration']}.",
             f"Candidates: {manifest['candidate_count']}; ambiguous: {manifest['ambiguous_count']}."]
    if manifest["warnings"]:
        lines += ["", "Warnings: " + "; ".join(manifest["warnings"])]
    lines += ["", ("The raw request and differential responses are private in this run."
                    if lead else
                    "The raw request, dictionary results and response fingerprints are private in this run."),
              "Resume and report only render stored evidence; neither sends another request.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(request_path, scope_origin, budget, wordlist_path=None, kind="path",
          max_requests=34, rate=5, runs_root=None, *, lead_kind=None, parameter=None,
          probe_value=None, expected=None, syntax=None, sql_parameter=None,
          sql_test=False, sql_location='query', sql_context='text', sql_table=None,
          sql_column=None, sql_candidates=None, workflow_path=None, workflow_test=False):
    if not isinstance(budget, (int, float)) or isinstance(budget, bool) or not 0 < budget <= 180:
        raise ValueError("web budget must be positive and at most 180 seconds")
    _origin(scope_origin)
    if workflow_path is not None or workflow_test:
        if not workflow_path or not workflow_test:
            raise ValueError('WEB08 requires --workflow-file and --workflow-test')
        if (request_path is not None or wordlist_path is not None or kind != 'path' or
                lead_kind is not None or sql_parameter is not None or sql_test or
                any(value is not None for value in (parameter, probe_value, expected,
                                                   syntax, sql_table, sql_column,
                                                   sql_candidates)) or
                sql_location != 'query' or sql_context != 'text'):
            raise ValueError('WEB08 cannot be combined with WEB02/03/05 options')
        if (type(max_requests) is not int or max_requests < 2 or
                type(rate) not in (int, float) or not 0 < rate <= 5):
            raise ValueError('WEB08 supports two to eight requests at at most five per second')
        raw_fixture = _regular_bytes(workflow_path, 256 * 1024, 'workflow fixture')
        try:
            fixtures = json.loads(raw_fixture)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('workflow fixture must be JSON') from exc
        from .profiles.web_workflows import _validated
        active_requests = min(max_requests, 8)
        _validated(fixtures, scope_origin, active_requests)
        timeout = min(budget, 30)
        root = Path(runs_root) if runs_root else core.ROOT / '.autosolve' / 'runs'
        run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        run.mkdir(parents=True, mode=0o700)
        descriptor = os.open(run / 'fixture.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw_fixture)
        profile, warnings = _run_workflow(fixtures, scope_origin, timeout, active_requests, rate)
        if budget > 30:
            warnings.insert(0, 'WEB08 profile caps active replay at 30 seconds')
        if profile is None:
            profile = {'assessment': 'inconclusive: incomplete workflow', 'responses': [],
                       'invariant_holds': None, 'baselines': []}
            requests_used = None
        else:
            requests_used = len(profile['responses'])
        complete = (requests_used == sum(len(flow['steps']) for flow in fixtures['workflows'])
                    and not warnings)
        manifest = {'schema_version': core.SCHEMA, 'category': 'web',
                    'run_type': 'web_workflow', 'status': 'partial',
                    'profile_status': 'complete' if complete else 'partial',
                    'scope_origin': scope_origin,
                    'fixture_sha256': hashlib.sha256(raw_fixture).hexdigest(),
                    'requests_used': requests_used, 'assessment': profile['assessment'],
                    'warnings': warnings, 'challenge_accepted': False,
                    'coverage': {'WEB08': {'status': 'ran' if complete else 'partial',
                                           'note': 'explicit bounded workflow comparison only'}}}
        core._write_json(run / 'manifest.json', manifest)
        core._write_json(run / 'transcript.json', profile)
        _render(run, manifest)
        return run, 'partial'
    if request_path is None:
        raise ValueError('web --request-file is required unless WEB08 is selected')
    raw = _regular_bytes(request_path, 64 * 1024, "request file")
    request, body = _request(raw, scope_origin)
    lead = lead_kind is not None
    sql = sql_parameter is not None
    if sql and (lead or wordlist_path is not None or kind != 'path' or
                any(value is not None for value in (parameter, probe_value, expected, syntax))):
        raise ValueError('WEB03 cannot be combined with WEB02/WEB05 options')
    if not sql and (sql_test or sql_location != 'query' or sql_context != 'text' or
                    any(value is not None for value in (sql_table, sql_column, sql_candidates))):
        raise ValueError('WEB03 options require --sql-parameter')
    if lead and wordlist_path is not None:
        raise ValueError("WEB05 selected leads cannot be combined with a discovery wordlist")
    if lead and kind != "path":
        raise ValueError("--kind applies only to WEB02 discovery")
    if not lead and any(value is not None for value in (parameter, probe_value, expected, syntax)):
        raise ValueError("WEB05 options require --lead-kind")
    words, wordlist_hash = _wordlist(wordlist_path)
    if kind not in ("path", "parameter", "vhost"):
        raise ValueError("web kind must be path, parameter or vhost")
    timeout = min(budget, 30)
    supported = request["method"] == "GET" and not body
    if sql:
        from .profiles.web_sql import _validate as _validate_sql
        active_requests = min(max_requests, 14)
        sql_options = {'location': sql_location, 'context': sql_context,
                       'table': sql_table, 'column': sql_column,
                       'candidates': sql_candidates, 'timeout': timeout,
                       'max_requests': active_requests, 'rate': rate}
        _validate_sql(raw, scope_origin, sql_parameter, sql_location, sql_context,
                      True, sql_test, sql_table, sql_column, sql_candidates,
                      timeout, active_requests, rate)
    elif lead:
        if not supported:
            raise ValueError("WEB05 requires a bodyless GET request")
        if type(max_requests) is not int or not 1 <= max_requests <= 64:
            raise ValueError("WEB05 needs a bounded request limit")
        scope = {"origin": scope_origin, "request": request, "kind": lead_kind,
                 "parameter": parameter, "expected": expected}
        if probe_value is not None:
            scope["probe_value"] = probe_value
        if syntax is not None:
            scope["syntax"] = syntax
        active_requests = min(max_requests, 4)
        _validate_leads(scope, timeout, active_requests, rate)
    else:
        scope = {"origin": scope_origin, "request": request, "dictionary": words,
                 "kind": kind} if words is not None else None
        active_requests = max_requests
        if scope and supported:
            _validate(scope, timeout, active_requests, rate)
        elif (type(max_requests) is not int or not 3 <= max_requests <= 64 or
              not isinstance(rate, (int, float)) or isinstance(rate, bool) or not 0 < rate <= 20):
            raise ValueError("web discovery requires bounded request and rate budgets")
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    descriptor = os.open(run / "request.http", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    warnings = []
    if sql:
        if budget > 30:
            warnings.append('WEB03 profile caps active probing at 30 seconds')
        profile, operation_warnings = _run_sql(raw, scope_origin, sql_parameter, sql_options)
        warnings.extend(operation_warnings)
        if profile is None:
            profile = {'status': 'partial', 'classification': 'inconclusive',
                       'origin': scope_origin, 'parameter': sql_parameter,
                       'requests_used': None, 'probes': [], 'selected_value': None,
                       'budget': {'timeout': timeout, 'max_requests': active_requests,
                                  'rate': rate}}
        classification = profile['classification']
        manifest = {'schema_version': core.SCHEMA, 'category': 'web',
                    'run_type': 'web_sql', 'status': 'partial',
                    'profile_status': profile['status'], 'scope_origin': scope_origin,
                    'request_sha256': hashlib.sha256(raw).hexdigest(),
                    'requests_used': profile['requests_used'],
                    'classification': classification,
                    'candidate_count': int(classification == 'differential_candidate'),
                    'ambiguous_count': int(classification == 'inconclusive'),
                    'warnings': warnings, 'challenge_accepted': False,
                    'coverage': {'WEB03': {'status': 'ran' if profile['status'] == 'complete'
                                          else 'partial',
                                          'note': 'explicit bounded selected SQL comparison'}}}
        core._write_json(run / 'manifest.json', manifest)
        core._write_json(run / 'transcript.json', profile)
        _render(run, manifest)
        return run, 'partial'
    if not lead and not words:
        warnings.append("no wordlist supplied; no discovery requests sent")
    elif not lead and not supported:
        warnings.append("this WEB02 profile currently supports bodyless GET requests only; no requests sent")
    if budget > 30:
        warnings.append(("WEB05" if lead else "WEB02") + " profile caps active probing at 30 seconds")
    profile, operation_warnings = (_run(scope, timeout, active_requests, rate, lead)
                                   if scope and supported else (None, []))
    warnings.extend(operation_warnings)
    if profile is None:
        profile = {"status": "partial", "kind": lead_kind if lead else kind,
                   "origin": scope_origin, "calibration": "not_run",
                   "requests_used": None if scope and supported else 0,
                   "budget": {"timeout": timeout,
                              "max_requests": active_requests, "rate": rate}}
        profile.update({"requests": [], "classification": "ambiguous"} if lead else
                       {"controls": [], "results": []})
    candidate_count = (int(profile["classification"] == "candidate") if lead else
                       sum(row["classification"] == "candidate" for row in profile["results"]))
    ambiguous_count = (int(profile["classification"] == "ambiguous") if lead else
                       sum(row["classification"] in ("ambiguous", "error")
                           for row in profile["results"]))
    family = "WEB05" if lead else "WEB02"
    manifest = {"schema_version": core.SCHEMA, "category": "web",
                "run_type": "web_leads" if lead else "web_discovery",
                "status": "partial", "profile_status": profile["status"],
                "scope_origin": scope_origin, "request_sha256": hashlib.sha256(raw).hexdigest(),
                "wordlist_sha256": wordlist_hash, "requests_used": profile["requests_used"],
                "calibration": profile["calibration"],
                "candidate_count": candidate_count, "ambiguous_count": ambiguous_count,
                "warnings": warnings, "challenge_accepted": False,
                "coverage": {family: {"status": "ran" if profile["status"] == "complete"
                                      else "partial", "note": "explicit bounded selected lead only"
                                      if lead else "explicit bounded discovery only"}}}
    core._write_json(run / "manifest.json", manifest)
    core._write_json(run / "transcript.json", profile)
    _render(run, manifest)
    return run, "partial"


def resume(run_path):
    run = Path(run_path).absolute()
    _render(run, _manifest(run))
    return run, "partial"


def report(run_path):
    run = Path(run_path).absolute()
    _render(run, _manifest(run))
    return run / "report.md"
