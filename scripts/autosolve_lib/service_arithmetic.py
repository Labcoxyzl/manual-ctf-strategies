"""Private run records for an explicitly scoped MISC01 arithmetic service."""

import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path

from . import core
from .profiles.arithmetic_protocol import _validate, run_arithmetic


def _protocol(path):
    if path is None:
        raise ValueError("arithmetic service requires --arithmetic-protocol")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("arithmetic protocol must be a regular JSON file of at most 1 MiB") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("arithmetic protocol must be a regular JSON file of at most 1 MiB")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("arithmetic protocol must be a regular JSON file of at most 1 MiB")
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("arithmetic protocol must contain valid UTF-8 JSON") from exc
    if not isinstance(config, dict) or set(config) != {
            "framing", "question", "completion", "response"}:
        raise ValueError("arithmetic protocol may declare only framing, question, completion and response; endpoint comes from CLI")
    return config, hashlib.sha256(raw).hexdigest()


def _manifest(run):
    if run.is_symlink():
        raise ValueError("arithmetic run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("category") != "can_misc" or
            manifest.get("run_type") != "service_arithmetic"):
        raise ValueError("not a compatible arithmetic service run")
    return manifest


def _render(run, manifest):
    lines = ["# Autosolve arithmetic service", "",
             f"Status: {manifest['status']}. Challenge acceptance: unverified.",
             f"Explicit endpoint: {manifest['host']}:{manifest['port']}.",
             f"MISC01 protocol: {manifest['protocol_status']}; "
             f"{manifest['round_count']} answered rounds; "
             f"terminal condition observed: {manifest['completion_observed']}; "
             f"{manifest['bytes_received']} bytes received; "
             f"{manifest['bytes_sent']} bytes sent."]
    if manifest.get("error"):
        lines.append(f"Stop reason: {manifest['error']}.")
    if manifest.get("warnings"):
        lines.append("Warnings: " + "; ".join(manifest["warnings"]))
    lines += ["", "Raw bytes, expressions and answers are private: transcript.jsonl, frames.json and rounds.json.",
              "Resume does not replay answers; start a new explicit service command for a new exchange.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(host, port, protocol_path, budget, max_rounds=100, runs_root=None):
    config, digest = _protocol(protocol_path)
    protocol = {**config, "transport": {"host": host, "port": port}}
    _validate(protocol, budget, max_rounds, 65536, 1024, 10 ** 30)
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    operation, warnings = run_arithmetic(protocol, timeout=budget, max_rounds=max_rounds)
    manifest = {"schema_version": core.SCHEMA, "category": "can_misc",
                "run_type": "service_arithmetic", "status": "partial", "host": host,
                "port": port, "protocol_sha256": digest,
                "protocol_status": operation["status"], "error": operation["error"],
                "round_count": len(operation["rounds"]),
                "completion_observed": operation["status"] == "complete",
                "bytes_received": operation["bytes_received"],
                "bytes_sent": operation["bytes_sent"], "warnings": warnings,
                "challenge_accepted": False,
                "coverage": {"MISC01": {"status": "ran" if operation["status"] == "complete"
                                        else "partial", "note": "explicit bounded arithmetic protocol"}}}
    core._write_json(run / "manifest.json", manifest)
    core._write_json(run / "frames.json", operation["frames"])
    core._write_json(run / "rounds.json", operation["rounds"])
    core._write_text(run / "transcript.jsonl", "".join(
        json.dumps(row, sort_keys=True) + "\n" for row in operation["transcript"]))
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
