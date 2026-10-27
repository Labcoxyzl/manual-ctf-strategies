"""Bounded extraction of steghide-compatible payloads with supplied passwords."""

import hashlib
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


STEGSEEK = (shutil.which(os.environ.get("AUTOSOLVE_STEGSEEK", "stegseek"))
            or os.environ.get("AUTOSOLVE_STEGSEEK") or "stegseek")
_MAX_SOURCE = 16 * 1024 * 1024


def _seed_limits() -> None:
    _limit_output(_MAX_SOURCE)
    for kind, limit in ((resource.RLIMIT_CPU, 250),
                        (resource.RLIMIT_AS, 768 * 1024 * 1024)):
        _, hard = resource.getrlimit(kind)
        resource.setrlimit(kind, (min(limit, hard) if hard != resource.RLIM_INFINITY else limit,
                                 hard))


def probe_seed(path: Path, output_dir: Path, *, timeout: float) -> str:
    """Return structural StegSeek 0.6 evidence; discard any extracted bytes."""
    if timeout <= 0:
        raise ValueError("Stegseek seed timeout must be positive")
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_SOURCE
            or not _carrier(path)):
        return "inconclusive"
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("Stegseek output directory must be separate from the source and not a symlink")
    if not shutil.which(STEGSEEK):
        return "unsupported"

    deadline = time.monotonic() + min(timeout, 30)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".stegseek-seed-", dir=output_dir) as scratch:
        version_path = Path(scratch) / "version"
        try:
            with version_path.open("wb") as stream:
                version = subprocess.run(
                    [STEGSEEK, "--version"], cwd=scratch, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.DEVNULL,
                    timeout=min(2, max(.01, deadline - time.monotonic())),
                    preexec_fn=lambda: _limit_output(4096))
        except subprocess.TimeoutExpired:
            return "timed_out"
        except OSError:
            return "unsupported"
        # shortcut: only 0.6 exit semantics are verified; extend after checking newer releases.
        if (version.returncode != 0 or
                not re.match(rb"StegSeek 0\.6(?:\s|$)", version_path.read_bytes()[:128])):
            return "unsupported"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timed_out"
        error_path = Path(scratch) / "stderr"
        with error_path.open("wb") as errors:
            try:
                process = subprocess.Popen(
                    [STEGSEEK, "--seed", "-q", "-n", "-t", "8", str(path.resolve()),
                     str(Path(scratch) / "discarded-payload")],
                    cwd=scratch, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=errors, start_new_session=True, preexec_fn=_seed_limits)
            except OSError:
                return "inconclusive"
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                return "timed_out"
        if status == 0:
            return "possible_seed"
        if status == 1 and error_path.read_bytes().strip().lower() == b"error: could not find a valid seed.":
            return "no_seed"
        return "timed_out" if status in (-signal.SIGXCPU, -signal.SIGKILL) else "inconclusive"


def _carrier(path: Path) -> bool:
    with path.open("rb") as source:
        header = source.read(12)
    return (header.startswith(b"\xff\xd8\xff") or header.startswith(b"BM") or
            header.startswith(b"RIFF") and header[8:12] == b"WAVE" or
            header.startswith(b".snd"))


def _limit_output(limit: int) -> None:
    _, inherited_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if inherited_hard != resource.RLIM_INFINITY:
        limit = min(limit, inherited_hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def extract_steghide(path: Path, output_dir: Path, *, passwords: list[bytes],
                     max_total_bytes: int, timeout: float,
                     supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Stage verified tool output; password_index refers to the supplied private list."""
    if max_total_bytes < 0 or timeout <= 0:
        raise ValueError("Stegseek limits must be nonnegative bytes and positive time")
    if len(passwords) > 8 or any(not isinstance(value, bytes) or len(value) > 128 or
                                 b"\n" in value or b"\r" in value or b"\0" in value
                                 for value in passwords):
        raise ValueError("Stegseek permits at most eight line-safe passwords of 128 bytes")
    if path.is_symlink() or not path.is_file():
        return [], ["Stegseek source must be a regular file"]
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("Stegseek output directory must be separate from the source and not a symlink")
    if path.stat().st_size > _MAX_SOURCE:
        return [], ["Stegseek source limit is 16 MiB"]
    if not _carrier(path):
        return [], ["Stegseek supports JPEG, BMP, WAV and AU carriers only"]
    if not passwords:
        return [], ["Stegseek requires a supplied password candidate file"]
    if not max_total_bytes:
        return [], ["Stegseek derived byte limit reached"]
    max_total_bytes = min(max_total_bytes, _MAX_SOURCE)
    if not shutil.which(STEGSEEK):
        return [], ["Stegseek unavailable"]

    deadline = time.monotonic() + timeout
    source = str(path.resolve())
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for index, password in enumerate(passwords):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], ["Stegseek timed out; password search incomplete"]
        with tempfile.TemporaryDirectory(prefix=".stegseek-", dir=output_dir) as scratch:
            wordlist = Path(scratch) / "words"
            wordlist.write_bytes(password + b"\n")
            wordlist.chmod(0o600)
            extracted = Path(scratch) / "payload"
            argv = [STEGSEEK, "--crack", "-q", "-s", "-n", "-t", "1",
                    source, str(wordlist), str(extracted)]
            try:
                process = subprocess.Popen(
                    argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=not supervised,
                    preexec_fn=lambda: _limit_output(max_total_bytes))
            except OSError as error:
                return [], [f"Stegseek unavailable: {type(error).__name__}"]
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                if supervised:
                    process.kill()
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                return [], ["Stegseek timed out; password search incomplete"]
            if status and extracted.exists():
                return [], ["Stegseek extracted byte limit reached or output failed"]
            if status or not extracted.is_file():
                continue
            size = extracted.stat().st_size
            if not 0 < size <= max_total_bytes:
                return [], ["Stegseek extracted byte limit reached or empty payload"]
            digest = hashlib.sha256(extracted.read_bytes()).hexdigest()
            target = output_dir / f"stegseek-{digest[:16]}-{index}"
            if target.exists():
                target = output_dir / f"stegseek-{digest[:16]}-{index}-{os.urandom(4).hex()}"
            os.replace(extracted, target)
            return [{"path": target, "size": size, "sha256": digest,
                     "password_index": index, "source": source}], []
    return [], ["no supplied passphrase validated; carrier may contain no supported payload"]
