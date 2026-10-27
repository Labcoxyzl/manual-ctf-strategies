"""Bounded, offline SSTV decode with the colaclanth command-line decoder."""

import fcntl
import hashlib
import os
import pty
import re
import resource
import selectors
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time
import wave
from pathlib import Path


SSTV = os.environ.get("AUTOSOLVE_SSTV", "sstv")
FFMPEG = os.environ.get("AUTOSOLVE_FFMPEG", "ffmpeg")
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_DURATION = 300
MAX_IMAGE_BYTES = 8 * 1024 * 1024
_PCM_BYTES = 2 * 11025 * MAX_DURATION + 44
_MODES = ("Robot 36", "Robot 72", "Martin 2", "Martin 1",
          "Scottie 2", "Scottie 1", "Scottie DX")
_MODE = re.compile(r"\[sstv\] Detected SSTV mode (Robot 36|Robot 72|Martin 2|Martin 1|Scottie 2|Scottie 1|Scottie DX)\b")


def _file_limit(limit):
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (min(limit, hard) if hard != resource.RLIM_INFINITY else limit, hard))


def _stop(process, supervised):
    if process.poll() is None:
        try:
            if supervised:
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def _invoke(argv, deadline, file_limit, supervised, terminal=False):
    """Return bounded decoder output; the upstream progress UI requires a real TTY."""
    master = slave = None
    try:
        if terminal:
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL,
            stdout=slave if terminal else subprocess.DEVNULL,
            stderr=slave if terminal else subprocess.DEVNULL,
            start_new_session=not supervised,
            preexec_fn=lambda: _file_limit(file_limit))
        if slave is not None:
            os.close(slave)
            slave = None
        output = bytearray()
        if terminal:
            selector = selectors.DefaultSelector()
            try:
                selector.register(master, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return b"", "SSTV decoder timed out"
                    for _, _ in selector.select(remaining):
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:  # PTY returns EIO after child closes the slave.
                            chunk = b""
                        if not chunk:
                            selector.unregister(master)
                            break
                        if len(output) + len(chunk) > 128 * 1024:
                            return b"", "SSTV decoder log limit reached"
                        output.extend(chunk)
            finally:
                selector.close()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b"", "SSTV normalization timed out"
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                return b"", "SSTV normalization timed out"
        if process.returncode:
            return bytes(output), f"{Path(argv[0]).name} exited {process.returncode}"
        return bytes(output), None
    except OSError as error:
        return b"", f"tool unavailable: {type(error).__name__}: {error}"
    finally:
        if 'process' in locals():
            _stop(process, supervised)
        if master is not None:
            os.close(master)
        if slave is not None:
            os.close(slave)


def decoder_available(path=None):
    """Require the documented mode-list contract, not an unrelated sstv package."""
    tool = shutil.which(path or SSTV)
    if not tool:
        return False
    try:
        process = subprocess.Popen([tool, "--list-modes"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
    except OSError:
        return False
    output = bytearray()
    deadline = time.monotonic() + 3
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map() and time.monotonic() < deadline:
            for key, _ in selector.select(max(0, deadline - time.monotonic())):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                if len(output) + len(chunk) > 4096:
                    return False
                output.extend(chunk)
        return (not selector.get_map() and process.wait(timeout=max(.01, deadline - time.monotonic())) == 0
                and bytes(output).strip() == ("Supported modes: " + ", ".join(_MODES)).encode())
    except subprocess.TimeoutExpired:
        return False
    finally:
        selector.close()
        _stop(process, supervised=False)
        process.stdout.close()


def decode_sstv(path: Path, output_dir: Path, *, timeout: float,
                max_bytes: int, supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Stage complete image candidates with source, mode and recording-time evidence."""
    if timeout <= 0 or max_bytes < 0:
        raise ValueError("SSTV limits must have positive time and nonnegative bytes")
    path, output_dir = Path(path), Path(output_dir)
    if path.is_symlink() or not path.is_file():
        return [], ["SSTV source must be a regular file"]
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("SSTV output directory must be separate and not a symlink")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        return [], ["SSTV source byte limit reached"]
    if not max_bytes:
        return [], ["SSTV derived byte limit reached"]
    if not shutil.which(FFMPEG):
        return [], ["FFmpeg unavailable; SSTV normalization not attempted"]
    if not decoder_available():
        return [], ["approved colaclanth SSTV decoder unavailable or wrong package identity"]

    deadline = time.monotonic() + timeout
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".sstv-", dir=output_dir) as scratch:
        wav = Path(scratch) / "audio.wav"
        png = Path(scratch) / "image.png"
        _, warning = _invoke(
            [shutil.which(FFMPEG), "-nostdin", "-hide_banner", "-loglevel", "error",
             "-threads", "1", "-protocol_whitelist", "file,pipe", "-i", str(path.resolve()),
             "-map", "0:a:0", "-t", str(MAX_DURATION), "-ac", "1", "-ar", "11025",
             "-c:a", "pcm_s16le", "-y", str(wav)],
            deadline, _PCM_BYTES, supervised)
        if warning:
            return [], [f"SSTV FFmpeg: {warning}"]
        if not wav.is_file() or wav.stat().st_size > _PCM_BYTES:
            return [], ["SSTV normalized PCM missing or over limit"]
        try:
            with wave.open(str(wav), "rb") as source:
                if source.getnchannels() != 1 or source.getframerate() != 11025 or source.getsampwidth() != 2:
                    raise ValueError("unexpected PCM format")
                duration = source.getnframes() / source.getframerate()
        except (OSError, wave.Error, ValueError) as error:
            return [], [f"SSTV normalized WAV rejected: {error}"]
        if duration >= MAX_DURATION - .1:
            return [], ["SSTV recording reaches duration limit; decode incomplete"]
        if duration < 1:
            return [], ["SSTV recording too short for a supported transmission"]

        log, warning = _invoke([shutil.which(SSTV), "-d", str(wav), "-o", str(png)],
                               deadline, min(max_bytes, MAX_IMAGE_BYTES), supervised,
                               terminal=True)
        decoded = log.decode("utf-8", "replace")
        if warning:
            return [], [f"SSTV decoder: {warning}"]
        mode = _MODE.search(decoded)
        if not mode:
            return [], ["no supported SSTV VIS header or mode detected"]
        if "Reached end of audio whilst decoding" in decoded or "...Done!" not in decoded:
            return [], [f"{mode.group(1)} transmission truncated; partial image withheld"]
        if not png.is_file() or not 0 < png.stat().st_size <= min(max_bytes, MAX_IMAGE_BYTES):
            return [], ["SSTV image missing or derived byte limit reached"]
        from PIL import Image
        try:
            with Image.open(png) as image:
                if image.format != "PNG" or image.width * image.height > 1024 * 1024:
                    raise ValueError("unexpected or oversized decoded image")
                width, height = image.size
                image.verify()
        except (OSError, ValueError, Image.DecompressionBombError) as error:
            return [], [f"SSTV decoded image rejected: {error}"]
        payload = png.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        target = output_dir / f"sstv-{digest[:16]}.png"
        if target.exists():
            target = output_dir / f"sstv-{digest[:16]}-{os.urandom(4).hex()}.png"
        os.replace(png, target)
        return [{"path": target, "size": len(payload), "sha256": digest,
                 "source": str(path.resolve()), "mode": mode.group(1),
                 "start_seconds": 0.0, "end_seconds": duration,
                 "time_basis": "whole recording; decoder does not expose exact header time",
                 "locator": f"{mode.group(1)} VIS, recording 0-{duration:.3f}s",
                 "media_type": "image/png", "width": width, "height": height}], []
