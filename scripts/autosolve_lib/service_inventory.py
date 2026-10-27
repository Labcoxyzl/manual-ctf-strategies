"""Private run records for explicit PWN07 TCP inventory."""

import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path

from . import core
from .profiles.service_inventory import _validate, run_inventory


def _ports(value):
    if not isinstance(value, str) or not value:
        raise ValueError("--ports requires comma-separated TCP port numbers")
    parts = value.split(",")
    if any(not part.isascii() or not part.isdecimal() for part in parts):
        raise ValueError("--ports requires comma-separated TCP port numbers, not ranges")
    return [int(part) for part in parts]


def _probes(path, ports):
    if path is None:
        return {}, None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("inventory protocol must be a regular JSON file of at most 64 KiB") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("inventory protocol must be a regular JSON file of at most 64 KiB")
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("inventory protocol must be a regular JSON file of at most 64 KiB")
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("inventory protocol must contain valid UTF-8 JSON") from exc
    if (not isinstance(config, dict) or set(config) != {"probes"} or
            not isinstance(config["probes"], dict) or
            any(key not in {str(port) for port in ports} or not isinstance(value, str)
                for key, value in config["probes"].items())):
        raise ValueError("inventory protocol needs only probes keyed by assigned port")
    return config["probes"], hashlib.sha256(raw).hexdigest()


def _manifest(run):
    if run.is_symlink():
        raise ValueError("service inventory run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("category") != "pwn_services" or
            manifest.get("run_type") != "service_inventory"):
        raise ValueError("not a compatible service inventory run")
    return manifest


def _render(run, manifest):
    lines = ["# Autosolve assigned-service inventory", "",
             "Status: partial. Challenge acceptance: unverified.",
             f"Assigned host: {manifest['host']}.",
             f"PWN07 inventory: {manifest['inventory_status']}.", ""]
    for row in manifest["observations"]:
        lines.append(f"- TCP {row['port']}: {row['state']}; response: {row['response_status']}.")
    if manifest["warnings"]:
        lines.extend(["", "Warnings: " + "; ".join(manifest["warnings"])])
    lines.extend(["", "Raw responses and declared probes are private in inventory.json.",
                  "Resume renders the stored result without reconnecting.", ""])
    core._write_text(run / "report.md", "\n".join(lines))


def start(host, ports, budget, runs_root=None, protocol_path=None):
    if not isinstance(budget, (int, float)) or isinstance(budget, bool) or not 0 < budget <= 120:
        raise ValueError("service budget must be positive and at most 120 seconds")
    selected = _ports(ports)
    probes, digest = _probes(protocol_path, selected)
    scope = {"host": host, "ports": [{"port": port, "probe_hex": probes[str(port)]}
                                       if str(port) in probes else port for port in selected]}
    timeout = min(budget, 10)
    _validate(scope, timeout)
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    inventory, warnings = run_inventory(scope, timeout=timeout)
    manifest = {"schema_version": core.SCHEMA, "category": "pwn_services",
                "run_type": "service_inventory", "status": "partial", "host": host,
                "ports": selected, "protocol_sha256": digest,
                "inventory_status": inventory["status"],
                "observations": [{"port": row["port"], "state": row["state"],
                                  "response_status": row["response_status"]}
                                 for row in inventory["ports"]],
                "warnings": warnings, "challenge_accepted": False,
                "coverage": {"PWN07": {"status": "ran" if inventory["status"] == "complete"
                                       else "partial", "note": "assigned TCP ports only"}}}
    core._write_json(run / "manifest.json", manifest)
    core._write_json(run / "inventory.json", inventory)
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
