"""Private WEB02 runs from a bounded raw HTTP request and explicit dictionary."""

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


def _worker(scope, timeout, max_requests, rate, pipe):
    resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    try:
        report, warnings = discover_web(scope, timeout=timeout,
                                        max_requests=max_requests, rate=rate)
        pipe.send((report, warnings))
    except Exception as exc:
        pipe.send((None, [f"web profile failed: {type(exc).__name__}"]))
    finally:
        pipe.close()


def _run(scope, timeout, max_requests, rate):
    parent, child = multiprocessing.Pipe(duplex=False)
    worker = multiprocessing.Process(target=core._worker_entry,
                                     args=(_worker, scope, timeout, max_requests, rate, child))
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


def _manifest(run):
    if run.is_symlink():
        raise ValueError("web run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or manifest.get("category") != "web"
            or manifest.get("run_type") != "web_discovery"):
        raise ValueError("not a compatible web discovery run")
    return manifest


def _render(run, manifest):
    lines = ["# Autosolve web discovery", "", "Status: partial. Challenge acceptance: unverified.",
             f"WEB02: {manifest['profile_status']}; {manifest['requests_used']} requests recorded.",
             f"Calibration: {manifest['calibration']}.",
             f"Candidates: {manifest['candidate_count']}; ambiguous: {manifest['ambiguous_count']}."]
    if manifest["warnings"]:
        lines += ["", "Warnings: " + "; ".join(manifest["warnings"])]
    lines += ["", "The raw request, dictionary results and response fingerprints are private in this run.",
              "Resume and report only render stored evidence; neither sends another request.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(request_path, scope_origin, budget, wordlist_path=None, kind="path",
          max_requests=34, rate=5, runs_root=None):
    if not isinstance(budget, (int, float)) or isinstance(budget, bool) or not 0 < budget <= 180:
        raise ValueError("web budget must be positive and at most 180 seconds")
    _origin(scope_origin)
    raw = _regular_bytes(request_path, 64 * 1024, "request file")
    request, body = _request(raw, scope_origin)
    words, wordlist_hash = _wordlist(wordlist_path)
    if kind not in ("path", "parameter", "vhost"):
        raise ValueError("web kind must be path, parameter or vhost")
    timeout = min(budget, 30)
    scope = {"origin": scope_origin, "request": request, "dictionary": words,
             "kind": kind} if words is not None else None
    supported = request["method"] == "GET" and not body
    if scope and supported:
        _validate(scope, timeout, max_requests, rate)
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
    if not words:
        warnings.append("no wordlist supplied; no discovery requests sent")
    elif not supported:
        warnings.append("this WEB02 profile currently supports bodyless GET requests only; no requests sent")
    if budget > 30:
        warnings.append("WEB02 profile caps active probing at 30 seconds")
    profile, operation_warnings = _run(scope, timeout, max_requests, rate) if scope and supported else (None, [])
    warnings.extend(operation_warnings)
    if profile is None:
        profile = {"status": "partial", "kind": kind, "origin": scope_origin,
                   "calibration": "not_run", "controls": [], "results": [],
                   "requests_used": None if scope and supported else 0,
                   "budget": {"timeout": timeout,
                                                      "max_requests": max_requests, "rate": rate}}
    manifest = {"schema_version": core.SCHEMA, "category": "web", "run_type": "web_discovery",
                "status": "partial", "profile_status": profile["status"],
                "scope_origin": scope_origin, "request_sha256": hashlib.sha256(raw).hexdigest(),
                "wordlist_sha256": wordlist_hash, "requests_used": profile["requests_used"],
                "calibration": profile["calibration"],
                "candidate_count": sum(row["classification"] == "candidate" for row in profile["results"]),
                "ambiguous_count": sum(row["classification"] in ("ambiguous", "error")
                                       for row in profile["results"]),
                "warnings": warnings, "challenge_accepted": False,
                "coverage": {"WEB02": {"status": "ran" if profile["status"] == "complete"
                                       else "partial", "note": "explicit bounded discovery only"}}}
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
