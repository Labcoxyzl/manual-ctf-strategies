"""Private run records for explicitly scoped PWN01 service framing."""

import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path

from . import core
from .profiles.service_transport import _validate, run_service


def _protocol(path):
    if path is None:
        raise ValueError("service requires --protocol with explicit finite steps")
    source = Path(path)
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("protocol must be a regular JSON file of at most 1 MiB") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("protocol must be a regular JSON file of at most 1 MiB")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("protocol must be a regular JSON file of at most 1 MiB")
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("protocol must contain valid UTF-8 JSON") from exc
    if not isinstance(config, dict) or set(config) - {"steps", "tls", "ca_file", "server_hostname"}:
        raise ValueError("service protocol may contain only steps and TLS options; endpoint comes from CLI")
    return config, hashlib.sha256(raw).hexdigest()


def _manifest(run):
    if run.is_symlink():
        raise ValueError("service run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("category") != "pwn_services" or
            manifest.get("run_type") != "service"):
        raise ValueError("not a compatible service run")
    return manifest


def _render(run, manifest):
    lines = ["# Autosolve service transport", "",
             f"Status: {manifest['status']}. Challenge acceptance: unverified.",
             f"Explicit endpoint: {manifest['host']}:{manifest['port']}.",
             f"PWN01 framing: {manifest['transport_status']}; "
             f"{manifest['frame_count']} completed read frames; "
             f"{manifest['bytes_received']} bytes received; "
             f"{manifest['bytes_sent']} bytes sent."]
    if manifest.get("error"):
        lines.append(f"Stop reason: {manifest['error']}.")
    if manifest.get("warnings"):
        lines.append("Warnings: " + "; ".join(manifest["warnings"]))
    lines += ["", "Raw bytes and timing are private: transcript.jsonl and frames.json.",
              "Resume does not replay service writes; start a new explicit service command for more steps.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(host, port, protocol_path, budget, runs_root=None):
    if not isinstance(budget, (int, float)) or isinstance(budget, bool) or not 0 < budget <= 120:
        raise ValueError("service budget must be positive and at most 120 seconds")
    config, digest = _protocol(protocol_path)
    transport = {"host": host, "port": port}
    for key in ("tls", "ca_file", "server_hostname"):
        if key in config:
            transport[key] = config[key]
    protocol = {"transport": transport, "steps": config["steps"]} if "steps" in config else {
        "transport": transport, "steps": []}
    _validate(protocol, timeout=budget, max_bytes=1024 * 1024, max_steps=32,
              allow_local=False)
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    operation, warnings = run_service(protocol, timeout=budget)
    manifest = {"schema_version": core.SCHEMA, "category": "pwn_services",
                "run_type": "service", "status": "partial", "host": host, "port": port,
                "protocol_sha256": digest, "transport_status": operation["status"],
                "error": operation["error"], "frame_count": len(operation["frames"]),
                "bytes_received": operation["bytes_received"],
                "bytes_sent": operation["bytes_sent"], "warnings": warnings,
                "challenge_accepted": False,
                "coverage": {"PWN01": {"status": "ran" if operation["status"] == "complete"
                                       else "partial", "note": "explicit transport and framing only"}}}
    core._write_json(run / "manifest.json", manifest)
    core._write_json(run / "frames.json", operation["frames"])
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
