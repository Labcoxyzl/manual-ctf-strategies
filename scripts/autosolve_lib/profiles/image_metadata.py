"""Bounded image metadata and inspection views."""

import json
import hashlib
import os
import selectors
import shutil
import tempfile
import time
import uuid
import warnings
from pathlib import Path


_EXIFTOOL = (shutil.which(os.environ.get('AUTOSOLVE_EXIFTOOL', 'exiftool'))
             or os.environ.get('AUTOSOLVE_EXIFTOOL') or '/usr/bin/exiftool')
_MAX_METADATA_OUTPUT = 1024 * 1024
_MAX_FRAMES = 8


def read_metadata(path: Path, *, timeout: float = 10) -> tuple[list[dict], list[str]]:
    """Read ExifTool's grouped JSON without allowing unbounded process output."""
    import subprocess

    if timeout <= 0:
        raise ValueError("metadata timeout must be positive")
    source = str(path.resolve())
    try:
        process = subprocess.Popen(
            [_EXIFTOOL, "-j", "-G1:4", "-s", "-n", "--", source],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as error:
        return [], [f"ExifTool unavailable: {error}"]

    output = bytearray()
    errors = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return [], ["ExifTool timed out"]
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > _MAX_METADATA_OUTPUT:
                    return [], ["ExifTool output limit reached"]
                key.data.extend(chunk)
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return [], ["ExifTool timed out"]
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()

    try:
        documents = json.loads(output)
        if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
            raise ValueError("unexpected ExifTool JSON shape")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return [], [f"invalid ExifTool output: {error}"]

    findings = []
    for key, value in documents[0].items():
        if key == "SourceFile":
            continue
        group, _, tag = key.rpartition(":")
        findings.append({"tag": tag or key, "group": group or None,
                         "value": value, "source": source, "source_tag": key})
    messages = []
    if process.returncode:
        messages.append(f"ExifTool exited {process.returncode}")
    if errors:
        messages.append(errors.decode("utf-8", "replace").strip())
    return findings, [message for message in messages if message]


class _OutputLimit(ValueError):
    pass


class _LimitedWriter:
    def __init__(self, target, limit: int):
        self.target = target
        self.limit = limit
        self.size = 0

    def write(self, data: bytes) -> int:
        if self.size + len(data) > self.limit:
            raise _OutputLimit("image preview byte limit reached")
        written = self.target.write(data)
        self.size += written
        return written

    def flush(self) -> None:
        self.target.flush()

    def tell(self) -> int:
        return self.target.tell()


def channel_views(path: Path, output_dir: Path, *, max_pixels: int,
                  max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Stage PNG views of selected frames and original sample channels for manual inspection."""
    from PIL import Image

    if max_pixels < 1 or max_total_bytes < 0:
        raise ValueError("image limits must be positive pixels and nonnegative bytes")
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("image output directory must be separate from the source and not a symlink")
    if not max_total_bytes:
        return [], ["image preview byte limit reached"]

    staged: list[tuple[Path, dict]] = []
    published: list[Path] = []
    warnings_out: list[str] = []
    total = 0
    source = str(path.resolve())
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def stage(view, *, frame: int, duration_ms: int | None, source_mode: str,
              channel: str, bit: int | None = None) -> None:
        nonlocal total
        fd, name = tempfile.mkstemp(prefix=".image-stage-", dir=output_dir)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as target:
                writer = _LimitedWriter(target, max_total_bytes - total)
                view.save(writer, format="PNG")
            total += writer.size
            staged.append((temporary, {"frame": frame, "duration_ms": duration_ms,
                                       "source_mode": source_mode, "channel": channel,
                                       "bit": bit, "width": view.width, "height": view.height,
                                       "size": writer.size, "source": source}))
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                if image.width * image.height > max_pixels:
                    raise ValueError("image pixel limit reached")
                count = getattr(image, "n_frames", 1)
                selected = (list(range(count)) if count <= _MAX_FRAMES else
                            sorted({round(index * (count - 1) / (_MAX_FRAMES - 1))
                                    for index in range(_MAX_FRAMES)}))
                if count > len(selected):
                    warnings_out.append(f"sampled {len(selected)} of {count} image frames")
                for frame in selected:
                    image.seek(frame)
                    image.load()
                    if image.width * image.height > max_pixels:
                        raise ValueError("image pixel limit reached")
                    mode = image.mode
                    duration = image.info.get("duration")
                    duration_ms = duration if isinstance(duration, int) and duration >= 0 else None
                    if mode in ("RGB", "RGBA", "L", "LA", "P", "1"):
                        rendered = image.convert("RGB")
                        if mode == "P":
                            samples = {"palette-index": Image.frombytes("L", image.size, image.tobytes())}
                        elif mode == "1":
                            samples = {"binary": image.convert("L")}
                        else:
                            samples = dict(zip({"RGB": ("red", "green", "blue"),
                                                "RGBA": ("red", "green", "blue", "alpha"),
                                                "L": ("luminance",),
                                                "LA": ("luminance", "alpha")}[mode], image.split()))
                    elif mode in ("I;16", "I;16L", "I;16B"):
                        raw = image.tobytes()
                        high, low = (raw[0::2], raw[1::2]) if mode == "I;16B" else (raw[1::2], raw[0::2])
                        samples = {"sample-high": Image.frombytes("L", image.size, high),
                                   "sample-low": Image.frombytes("L", image.size, low)}
                        rendered = samples["sample-high"].convert("RGB")
                    else:
                        raise ValueError(f"unsupported image mode {mode}")
                    stage(rendered, frame=frame, duration_ms=duration_ms,
                          source_mode=mode, channel="rendered-rgb")
                    for channel, plane in samples.items():
                        stage(plane, frame=frame, duration_ms=duration_ms,
                              source_mode=mode, channel=channel)
                    for bit in range(8):
                        for channel, plane in samples.items():
                            stage(plane.point([255 if value & (1 << bit) else 0
                                               for value in range(256)]),
                                  frame=frame, duration_ms=duration_ms,
                                  source_mode=mode, channel=channel, bit=bit)
    except _OutputLimit as error:
        warnings_out.append(str(error))
    except (OSError, EOFError, SyntaxError, ValueError, Image.DecompressionBombWarning,
            Image.DecompressionBombError) as error:
        warnings_out.append(f"image inspection rejected: {error}")
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        return [], warnings_out

    try:
        results = []
        for temporary, record in staged:
            target = output_dir / f"{uuid.uuid4().hex}.png"
            os.link(temporary, target)
            published.append(target)
            results.append({"path": target, **record})
            results[-1]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        return results, warnings_out
    except OSError:
        for target in published:
            target.unlink(missing_ok=True)
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
