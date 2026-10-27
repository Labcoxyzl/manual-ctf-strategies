"""Bounded DTMF, Morse, and AFSK evidence from PCM WAV recordings."""

import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
import wave
from pathlib import Path


FFMPEG = (shutil.which(os.environ.get("AUTOSOLVE_FFMPEG", "ffmpeg"))
          or os.environ.get("AUTOSOLVE_FFMPEG") or "ffmpeg")
MULTIMON = (shutil.which(os.environ.get("AUTOSOLVE_MULTIMON", "multimon-ng"))
            or os.environ.get("AUTOSOLVE_MULTIMON") or "multimon-ng")
MODES = ("DTMF", "MORSE_CW", "AFSK1200")
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_DURATION = 30
MAX_CHANNELS = 2
MAX_EVENTS = 256
MAX_DECODER_OUTPUT = 64 * 1024
_DTMF = re.compile(r"^DTMF:\s*([0-9A-D*#])\s*$")


def _run(argv: list[str], *, deadline: float, max_output: int,
         supervised: bool = False) -> tuple[bytes, str | None]:
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=not supervised)
    except OSError as error:
        return b"", f"tool unavailable: {error}"
    output = bytearray()
    errors = bytearray()
    warning = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = "tool timed out; tone inspection incomplete"
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max_output - len(output) - len(errors)
                if len(chunk) > room:
                    key.data.extend(chunk[:max(room, 0)])
                    warning = "tool output limit reached; tone inspection incomplete"
                    break
                key.data.extend(chunk)
            if warning:
                break
    finally:
        selector.close()
        if process.poll() is None:
            if supervised:
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if process.returncode and not warning:
        detail = errors.decode("utf-8", "replace").strip().splitlines()
        warning = f"tool exited {process.returncode}: {(detail[0] if detail else 'unknown error')[:200]}"
    return bytes(output), warning


def inspect_tones(path: Path, *, timeout: float, max_output: int,
                  modes: tuple[str, ...] = MODES,
                  supervised: bool = False,
                  scratch_dir: Path | None = None) -> tuple[list[dict], list[str]]:
    """Return source-linked decoder output; decoded text is candidate evidence only."""
    if timeout <= 0 or max_output <= 0 or not modes or any(mode not in MODES for mode in modes):
        raise ValueError("positive tone limits and supported modes required")
    path = Path(path)
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return [], ["WAV source byte limit reached"]
        with wave.open(str(path), "rb") as source:
            channels = source.getnchannels()
            rate = source.getframerate()
            frames = source.getnframes()
            if source.getcomptype() != "NONE" or not 1 <= channels <= MAX_CHANNELS or rate <= 0:
                return [], ["unsupported WAV encoding or channel count"]
            if frames / rate > MAX_DURATION:
                return [], ["WAV duration limit reached"]
            duration = frames / rate
    except (OSError, EOFError, wave.Error, ValueError, ZeroDivisionError) as error:
        return [], [f"WAV rejected: {error}"]
    if not shutil.which(MULTIMON):
        return [], ["multimon-ng unavailable; tone decode not attempted"]
    if not shutil.which(FFMPEG):
        return [], ["ffmpeg unavailable; WAV normalization not attempted"]

    deadline = time.monotonic() + timeout
    source_path = str(path.resolve())
    records: list[dict] = []
    notices: list[str] = []
    with tempfile.TemporaryDirectory(prefix="autosolve-tones-",
                                     dir=str(scratch_dir) if scratch_dir else None) as temporary:
        for channel in range(channels):
            raw = Path(temporary) / f"channel-{channel}.raw"
            argv = [FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-i",
                    source_path, "-map", "0:a:0", "-t", str(duration),
                    "-af", f"pan=mono|c0=c{channel}",
                    "-ar", "22050", "-acodec", "pcm_s16le", "-f", "s16le", "-y", str(raw)]
            _, warning = _run(argv, deadline=deadline, max_output=4096,
                              supervised=supervised)
            if warning:
                notices.append(f"channel {channel}: ffmpeg {warning}")
                continue
            if not raw.is_file() or raw.stat().st_size > 2 * 22050 * (duration + 1):
                notices.append(f"channel {channel}: normalized PCM missing or over limit")
                continue
            for mode in modes:
                if time.monotonic() >= deadline:
                    notices.append("tone time limit reached; inspection incomplete")
                    return records, notices
                output, warning = _run([MULTIMON, "-q", "-c", "-t", "raw", "-a", mode,
                                        str(raw)], deadline=deadline,
                                       max_output=min(max_output, MAX_DECODER_OUTPUT),
                                       supervised=supervised)
                if warning:
                    notices.append(f"channel {channel} {mode}: {warning}")
                    continue
                decoded = output.decode("utf-8", "replace")
                lines = decoded.splitlines() if mode == "DTMF" else [decoded]
                for number, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    if mode == "DTMF":
                        match = _DTMF.fullmatch(line.strip())
                        if not match:
                            continue
                        symbol = match.group(1)
                    elif mode == "AFSK1200":
                        if not any(row.startswith("AFSK1200:") for row in line.splitlines()):
                            continue
                        symbol = None
                    else:
                        symbol = None
                    locator = (f"channel {channel} decoder line {number}" if mode == "DTMF"
                               else f"channel {channel} {mode} decoder output")
                    records.append({"source": source_path, "locator": locator,
                                    "channel": channel, "mode": mode, "symbol": symbol,
                                    "raw_output": line if mode != "DTMF" else line.strip(), "sample_rate": rate,
                                    "duration_seconds": duration, "event_time_seconds": None,
                                    "time_basis": "not supplied by decoder", "tool": MULTIMON,
                                    "certainty": "decoder_candidate"})
                    if len(records) >= MAX_EVENTS:
                        notices.append("tone event limit reached; inspection incomplete")
                        return records, notices
    if not records:
        notices.append("no supported tone decoder output")
    return records, notices
