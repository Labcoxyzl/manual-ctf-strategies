"""Bounded zsteg inspection of PNG/BMP LSB candidates."""

import hashlib
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


ZSTEG = (shutil.which(os.environ.get("AUTOSOLVE_ZSTEG", "zsteg"))
         or os.environ.get("AUTOSOLVE_ZSTEG") or "zsteg")
_SELECTOR = re.compile(rb"^((?:b1|b2|b10)p?,[A-Za-z0-9,]+)\s+\.\.\s+(text|file|zlib):\s+(.+)$")
_CHANNELS = "r,g,b,a,rgb,bgr,rgba,abgr"
_ORDERS = "xy,yx,XY,YX"
_MAX_SCAN_OUTPUT = 1024 * 1024
_MAX_CANDIDATES = 16


def _run(argv: list[str], deadline: float, output_limit: int,
         supervised: bool) -> tuple[bytes, str | None]:
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=not supervised)
    except OSError as error:
        return b"", f"zsteg unavailable: {error}"

    output = bytearray()
    errors = bytearray()
    selector = selectors.DefaultSelector()
    warning = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = "zsteg timed out; inspection incomplete"
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > output_limit:
                    room = max(0, output_limit - len(output) - len(errors))
                    key.data.extend(chunk[:room])
                    warning = "zsteg output limit reached; inspection incomplete"
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
        warning = f"zsteg exited {process.returncode}: {(detail[0] if detail else 'unknown error')[:200]}"
    return bytes(output), warning


def inspect_lsb(path: Path, output_dir: Path, *, max_pixels: int,
                max_total_bytes: int, timeout: float,
                supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Stage at most 16 selected zsteg outputs, preserving selectors and tool bytes."""
    from PIL import Image

    if max_pixels <= 0 or max_total_bytes < 0 or timeout <= 0:
        raise ValueError("zsteg limits must be positive pixels/time and nonnegative bytes")
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("zsteg output directory must be separate from the source and not a symlink")
    try:
        with Image.open(path) as image:
            if image.format not in ("PNG", "BMP"):
                return [], ["zsteg supports PNG/BMP only"]
            if image.width * image.height > max_pixels:
                return [], ["zsteg image pixel limit reached"]
    except (OSError, ValueError) as error:
        return [], [f"zsteg image rejected: {error}"]

    deadline = time.monotonic() + timeout
    source = str(path.resolve())
    scan, warning = _run([ZSTEG, "-b", "1-2,0x02", "-c", _CHANNELS, "-o", _ORDERS,
                          "-l", "256", "--no-color", source],
                         deadline, _MAX_SCAN_OUTPUT, supervised)
    warnings = [warning] if warning else []
    if warning and (warning.startswith("zsteg unavailable") or warning.startswith("zsteg exited")):
        return [], warnings

    candidates = []
    seen = set()
    for line in scan.replace(b"\r", b"\n").splitlines():
        match = _SELECTOR.match(line.strip())
        if not match:
            continue
        selector, kind, description = match.groups()
        if selector in seen or description.lower() == b"data":
            continue
        seen.add(selector)
        candidates.append((kind != b"text", selector.decode("ascii"),
                           kind.decode("ascii"), description.decode("utf-8", "replace")[:256]))
    candidates.sort()
    if len(candidates) > _MAX_CANDIDATES:
        warnings.append(f"zsteg candidate limit reached; selected {_MAX_CANDIDATES} of {len(candidates)}")

    records = []
    used = 0
    for _, selector, kind, description in candidates[:_MAX_CANDIDATES]:
        remaining = max_total_bytes - used
        if remaining <= 0:
            warnings.append("zsteg derived byte limit reached")
            break
        payload, extraction_warning = _run([ZSTEG, "-E", selector, source],
                                           deadline, remaining, supervised)
        if extraction_warning:
            warnings.append(f"selector {selector}: {extraction_warning}")
            if "timed out" in extraction_warning:
                break
            continue
        if not payload:
            continue
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix="zsteg-", dir=output_dir)
        target = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
            records.append({"path": target, "size": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "selector": selector, "finding_kind": kind,
                            "finding": description, "source": source})
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        used += len(payload)
    return records, warnings
