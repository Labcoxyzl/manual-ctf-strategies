"""Opt-in, bounded x86-64 crash offset discovery using local GDB evidence."""

from itertools import islice
import json
import os
from pathlib import Path
import pty
import re
import resource
import select
import shutil
import signal
import subprocess
import time
import uuid

from . import core
from .pwn_ret2win import _source, _source_current


def _pattern(alphabet, length):
    if (not isinstance(alphabet, str) or not re.fullmatch(r"[A-Za-z0-9]{3,62}", alphabet)
            or len(set(alphabet)) != len(alphabet)):
        raise ValueError("alphabet needs 3 to 62 distinct ASCII letters or digits")
    if type(length) is not int or not 8 <= length <= 2048:
        raise ValueError("cyclic length must be 8 to 2048 bytes")
    symbols = alphabet.encode("ascii")
    order = 8
    state = [0] * (order + 1)

    def words(depth, period):
        if depth > order:
            if order % period == 0:
                yield from (symbols[state[index]] for index in range(1, period + 1))
            return
        state[depth] = state[depth - period]
        yield from words(depth + 1, period)
        for value in range(state[depth - period] + 1, len(symbols)):
            state[depth] = value
            yield from words(depth + 1, depth)

    return bytes(islice(words(1, 1), length))


def _private_bytes(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _libraries(directory, deadline):
    directory = Path(directory).absolute()
    if (directory.is_symlink() or not directory.is_dir() or
            any(character in str(directory) for character in ":;\r\n$")):
        raise ValueError("library path must be a real directory without loader separators or tokens")
    entries = sorted(directory.iterdir())
    if len(entries) > 64:
        raise ValueError("library path exceeds 64 shared-library entries")
    records = []
    for entry in entries:
        target = entry.resolve()
        if not target.is_file() or target.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("library entry must resolve to a regular file under 32 MiB")
        digest = core._hash(target, deadline)
        if digest is None:
            raise ValueError("library identity could not be verified")
        records.append({"name": entry.name, "path": str(target), "sha256": digest})
    return directory, records


def _libraries_current(directory, records, deadline):
    if directory is None:
        return True
    try:
        if (directory.is_symlink() or
                sorted(entry.name for entry in directory.iterdir()) !=
                [record["name"] for record in records]):
            return False
        for record in records:
            entry = directory / record["name"]
            if not entry.exists() or str(entry.resolve()) != record["path"]:
                return False
            current = core._identity_matches(Path(record["path"]), record["sha256"], deadline)
            if current is not True:
                return current
        return True
    except OSError:
        return False


def _debugger(binary, channel, payload, run, label, deadline, executable, library=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return "budget_exhausted", None
    master, slave = pty.openpty()
    trace = run / f"{label}-gdb.txt"
    command = [executable, "-q", "-nx", "-nh", "-batch",
               "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
               "-ex", "set pagination off", "-ex", "set confirm off",
               "-ex", "set startup-with-shell off",
               "-ex", "set detach-on-fork off", "-ex", "set follow-fork-mode parent",
               "-ex", f"set inferior-tty {os.ttyname(slave)}"]
    if library is not None:
        command.extend(("-ex", f"set environment LD_LIBRARY_PATH {library}"))
    command.extend(("-ex", "run", "-ex", "info registers rip rsp",
                    "-ex", "x/i $rip", "-ex", "x/8bx $rsp", "--args", str(binary)))
    if channel == "argv":
        command.append(payload.decode("ascii"))

    def limit_trace():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (min(62, int(remaining) + 2),
                                                min(62, int(remaining) + 2)))

    process = None
    try:
        fd = os.open(trace, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        inferior_path = run / f"{label}-inferior.txt"
        inferior_fd = os.open(inferior_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600)
        with os.fdopen(fd, "wb") as output, os.fdopen(inferior_fd, "wb") as inferior:
            process = subprocess.Popen(command, cwd=run,
                                       stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=limit_trace,
                                       env={"LC_ALL": "C"})
            if channel == "stdin":
                os.write(master, payload + b"\n\x04")
            os.set_blocking(master, False)
            saved = 0
            while process.poll() is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    return "timeout", None
                if select.select([master], [], [], min(0.05, left))[0]:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        chunk = b""
                    if chunk and saved < 65536:
                        piece = chunk[:65536 - saved]
                        inferior.write(piece)
                        saved += len(piece)
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk or saved >= 65536:
                    break
                piece = chunk[:65536 - saved]
                inferior.write(piece)
                saved += len(piece)
            process.wait()
        raw = trace.read_bytes()
        inferior_raw = inferior_path.read_bytes()
        if b"Program received signal SIGSEGV" not in raw:
            if b"error while loading shared libraries" in inferior_raw or b"ld.so:" in inferior_raw:
                return "loader_failure", None
            if b"exited normally" in raw or b"exited with code" in raw:
                return "no_crash", None
            return ("other_crash" if b"Program received signal" in raw
                    else "debugger_unavailable"), None
        if not re.search(rb"=>\s*0x[0-9a-f]+[^\n]*:\s*retq?\b", raw):
            return "crash_not_at_return", None
        match = re.search(rb"(?m)^0x[0-9a-f]+:\s*((?:0x[0-9a-f]{1,2}\s*){8})$", raw)
        if match is None:
            return "stack_unavailable", None
        stack = bytes(int(value, 16) for value in re.findall(rb"0x[0-9a-f]{1,2}", match[1]))
        return "return_crash", stack
    except (OSError, subprocess.SubprocessError):
        return "debugger_unavailable", None
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        os.close(master)
        os.close(slave)


def _render(run, manifest, current):
    lines = ["# Autosolve local crash offset", "",
             "PWN03: " + manifest["verification"] + ". Challenge acceptance: unverified.",
             "Source identity current: " + ("yes" if current else "no") + ".",
             "Selected input channel: " + manifest["channel"] + ".",
             "Recovered offset: " + (str(manifest["offset"]) + " bytes" if manifest["offset"] is not None
                                     else "unavailable") + ".",
             "Stop reason: " + manifest["stop_reason"] + ".",
             "Controls: " + ", ".join(row["name"] + " " + row["status"]
                                       for row in manifest["controls"]) + ".", "",
             "Raw debugger and inferior output and input bytes remain in private run files.",
             "Resume checks source identity and redraws this report without executing the ELF.", ""]
    core._write_text(run / "report.md", "\n".join(lines))


def start(binary_path, channel, alphabet, length, budget, runs_root=None, library_path=None):
    if channel not in ("stdin", "argv"):
        raise ValueError("input channel must be stdin or argv")
    if type(budget) not in (int, float) or not 0 < budget <= 60:
        raise ValueError("offset budget must be positive and at most 60 seconds")
    pattern = _pattern(alphabet, length)
    deadline = time.monotonic() + budget
    binary, digest = _source(binary_path, deadline)
    if not os.access(binary, os.X_OK):
        raise ValueError("local ELF must be executable")
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (len(header) < 20 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01"
            or header[18:20] != b"\x3e\x00"):
        raise ValueError("offset probe supports local little-endian x86-64 ELF only")
    library, libraries = (_libraries(library_path, deadline) if library_path is not None
                          else (None, []))

    def identity_issue():
        source = _source_current(binary, digest, deadline)
        loader = _libraries_current(library, libraries, deadline)
        if source is False:
            return "source_changed"
        if loader is False:
            return "library_changed"
        if source is None or loader is None:
            return "identity_unverified"
        return None

    root = Path(runs_root) if runs_root else core.ROOT / ".autosolve" / "runs"
    run = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True, mode=0o700)
    _private_bytes(run / "pattern.bin", pattern)
    debugger = shutil.which("gdb", path="/usr/bin:/bin")
    controls = []
    offset = None
    issue = identity_issue()
    stop = "debugger_unavailable" if debugger is None else issue
    if debugger is not None and issue is None:
        stop, stack = _debugger(binary, channel, pattern, run, "probe", deadline, debugger,
                                library)
        if stop == "return_crash" and stack is not None:
            first = pattern.find(stack)
            if first < 0 or first != pattern.rfind(stack):
                stop = "pattern_not_unique_at_return"
            elif first == 0:
                stop = "zero_offset_unsupported"
            else:
                offset = first
                replay = b"A" * offset + b"B" * 8
                _private_bytes(run / "replay.bin", replay)
                issue = identity_issue()
                if issue is not None:
                    stop = issue
                else:
                    replay_status, replay_stack = _debugger(
                        binary, channel, replay, run, "replay", deadline, debugger, library)
                    controls.append({"name": "changed return bytes", "status":
                                     "matched" if replay_status == "return_crash" and
                                     replay_stack == b"B" * 8 else replay_status})
                    if replay_stack != b"B" * 8 or replay_status != "return_crash":
                        stop = "replay_mismatch"
                    else:
                        issue = identity_issue()
                        if issue is not None:
                            stop = issue
                        else:
                            short_status, _ = _debugger(binary, channel, b"A" * max(0, offset - 16),
                                                        run, "short", deadline, debugger, library)
                            controls.append({"name": "short input", "status":
                                             "no crash" if short_status == "no_crash" else short_status})
                            stop = ("verified" if short_status == "no_crash"
                                    else "short_control_crashed")
    issue = identity_issue()
    if issue in ("source_changed", "library_changed") or issue is not None and stop == "verified":
        stop = issue
    verified = stop == "verified"
    manifest = {"schema_version": core.SCHEMA, "category": "pwn_services",
                "run_type": "pwn_offset", "status": "partial", "verification":
                "controlled local replay" if verified else "unverified",
                "challenge_accepted": False, "source": str(binary), "source_sha256": digest,
                "channel": channel, "alphabet": alphabet, "pattern_length": length,
                "offset": offset if verified else None,
                "candidate_offset": offset if issue is None else None,
                "stop_reason": stop, "controls": controls,
                "library_path": str(library) if library is not None else None,
                "libraries": libraries,
                "coverage": {"PWN03": {"status": "ran" if verified else "partial",
                                       "note": "local debugger return-address offset only"}}}
    core._write_json(run / "manifest.json", manifest)
    _render(run, manifest, _source_current(binary, digest, deadline) is True)
    return run, "partial"


def _manifest(run):
    if run.is_symlink():
        raise ValueError("offset run directory must not be a symlink")
    manifest = json.loads((run / "manifest.json").read_text())
    if (manifest.get("schema_version") != core.SCHEMA or
            manifest.get("run_type") != "pwn_offset" or
            manifest.get("category") != "pwn_services"):
        raise ValueError("not a compatible offset run")
    return manifest


def resume(run_path):
    run = Path(run_path).absolute()
    manifest = _manifest(run)
    current = _source_current(Path(manifest["source"]), manifest["source_sha256"],
                              time.monotonic() + 10)
    _render(run, manifest, current is True)
    return run, "partial"


def report(run_path):
    return resume(run_path)[0] / "report.md"
