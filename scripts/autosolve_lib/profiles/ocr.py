"""Bounded printed-text OCR for complete SSTV-derived images."""

import base64
import ctypes
import os
import re
import resource
import shutil
import subprocess
import warnings
from pathlib import Path


TESSERACT = os.environ.get("AUTOSOLVE_TESSERACT", "tesseract")
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_TEXT_BYTES = 8192
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}\Z")


def _limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TEXT_BYTES + 1, MAX_TEXT_BYTES + 1))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _output_file():
    try:
        # Linux MFD_CLOEXEC is 1 even when Python omits the os binding.
        creator = getattr(os, "memfd_create", None)
        if creator is not None:
            fd = creator("autosolve-ocr", 1)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            memfd_create = libc.memfd_create
            memfd_create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
            memfd_create.restype = ctypes.c_int
            fd = memfd_create(b"autosolve-ocr", 1)
            if fd < 0:
                raise OSError(ctypes.get_errno(), "anonymous OCR output unavailable")
        return os.fdopen(fd, "w+b")
    except AttributeError as error:
        raise OSError("anonymous OCR output unavailable") from error


def english_traineddata_path() -> Path | None:
    """Resolve the English model reported by the selected Tesseract executable."""
    tool = shutil.which(TESSERACT)
    if not tool:
        return None
    try:
        with _output_file() as output:
            result = subprocess.run([tool, "--list-langs"], stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=3,
                                    check=False, preexec_fn=_limit_output)
            output.seek(0)
            raw = output.read(MAX_TEXT_BYTES + 1)
        if result.returncode or len(raw) > MAX_TEXT_BYTES:
            return None
        lines = raw.decode("utf-8", "replace").splitlines()
        match = re.fullmatch(r'List of available languages in "([^"\n]+)" \(\d+\):',
                             lines[0]) if lines else None
        if not match or "eng" not in lines[1:]:
            return None
        path = (Path(match[1]) / "eng.traineddata").resolve(strict=True)
        return path if path.is_file() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def extract_printed_text(path: Path, *, timeout: float = 8,
                         max_bytes: int = MAX_TEXT_BYTES) -> tuple[list[dict], list[str]]:
    """Return OCR text and a tentative, explicitly labeled Base64 block, if any."""
    from PIL import Image

    if timeout <= 0 or max_bytes < 0:
        raise ValueError("OCR limits require positive time and nonnegative bytes")
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            return [], ["OCR source missing, linked, or exceeds byte limit"]
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                if image.width * image.height > MAX_PIXELS or getattr(image, "n_frames", 1) != 1:
                    return [], ["OCR image pixel/frame limit reached"]
                image.load()
    except (OSError, ValueError, Image.DecompressionBombWarning,
            Image.DecompressionBombError) as error:
        return [], [f"OCR image rejected: {error}"]
    tool = shutil.which(TESSERACT)
    if not tool:
        return [], ["Tesseract unavailable; printed-text OCR skipped"]
    try:
        with _output_file() as output:
            result = subprocess.run([tool, str(path), "stdout", "-l", "eng", "--psm", "6"],
                                    stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False, preexec_fn=_limit_output)
            output.seek(0)
            raw = output.read(min(max_bytes, MAX_TEXT_BYTES) + 1)
    except subprocess.TimeoutExpired:
        return [], ["Tesseract time limit reached; OCR withheld"]
    except OSError as error:
        return [], [f"Tesseract failed: {error}"]
    if len(raw) > min(max_bytes, MAX_TEXT_BYTES):
        return [], ["OCR output byte limit reached; text withheld"]
    if result.returncode != 0:
        return [], [f"Tesseract exited {result.returncode}; OCR withheld"]
    lines = [line.strip() for line in raw.decode("utf-8", "replace").splitlines()]
    if not any(lines):
        return [], []
    records = [{"data": raw, "kind": "printed text", "line_start": 1,
                "line_end": len(lines)}]
    for index, line in enumerate(lines):
        if not re.search(r"\bBASE\s*64\b", line, re.IGNORECASE):
            continue
        block = []
        for candidate in lines[index + 1:index + 5]:
            # shortcut: only padded lines tolerate OCR spaces; inspect unpadded spaced codes manually.
            if (" " in candidate or "\t" in candidate) and (
                    candidate.count(" ") + candidate.count("\t") > 2 or
                    not candidate.endswith("=")):
                break
            normalized = candidate.replace(" ", "").replace("\t", "")
            if not _BASE64_LINE.fullmatch(normalized):
                break
            block.append(normalized)
        for count in range(len(block), 0, -1):
            joined = "".join(block[:count])
            if len(joined) < 12 or len(joined) % 4:
                continue
            try:
                decoded = base64.b64decode(joined, validate=True)
            except ValueError:
                continue
            if base64.b64encode(decoded).decode("ascii") == joined:
                records.append({"data": joined.encode("ascii"), "kind": "OCR Base64 candidate",
                                "line_start": index + 2,
                                "line_end": index + count + 1})
                break
        break
    return records, []
