"""Bounded, source-linked QR and barcode decoding from still or animated images."""

import time
import warnings
from pathlib import Path


MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SYMBOLS = 32
MAX_FRAMES = 8


def _decoder():
    try:
        import zxingcpp
    except (ImportError, OSError):
        try:
            from pyzbar.pyzbar import decode
        except (ImportError, OSError):
            return None, None
        return "pyzbar", decode
    return "zxingcpp", zxingcpp.read_barcodes


def _points(symbol, decoder):
    if decoder == "zxingcpp":
        position = symbol.position
        return [(getattr(position, corner).x, getattr(position, corner).y)
                for corner in ("top_left", "top_right", "bottom_right", "bottom_left")]
    return [(point.x, point.y) for point in symbol.polygon]


def _original_points(points, width, height, rotation):
    if rotation == 90:
        return [(width - 1 - y, x) for x, y in points]
    if rotation == 180:
        return [(width - 1 - x, height - 1 - y) for x, y in points]
    if rotation == 270:
        return [(y, height - 1 - x) for x, y in points]
    return points


def _same_symbol(left, right):
    if left["payload"] != right["payload"] or left["format"] != right["format"] or left["frame"] != right["frame"]:
        return False
    ax = [point[0] for point in left["position"]]
    ay = [point[1] for point in left["position"]]
    bx = [point[0] for point in right["position"]]
    by = [point[1] for point in right["position"]]
    overlap = max(0, min(max(ax), max(bx)) - max(min(ax), min(bx))) * max(
        0, min(max(ay), max(by)) - max(min(ay), min(by)))
    area = min((max(ax) - min(ax)) * (max(ay) - min(ay)),
               (max(bx) - min(bx)) * (max(by) - min(by)))
    return bool(area and overlap * 2 >= area)


def decode_symbols(path: Path, *, max_pixels: int, max_total_bytes: int,
                   timeout: float) -> tuple[list[dict], list[str]]:
    """Return exact symbol bytes with original-frame coordinates and transform evidence.

    The caller must enforce the timeout outside this function too: a native decoder
    call cannot be interrupted safely within the process.
    """
    from PIL import Image, ImageOps

    if max_pixels <= 0 or max_total_bytes < 0 or timeout <= 0:
        raise ValueError("QR limits must be positive pixels/time and nonnegative bytes")
    path = Path(path)
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return [], ["QR source byte limit reached"]
    except OSError as error:
        return [], [f"QR image rejected: {error}"]
    decoder_name, decoder = _decoder()
    if decoder is None:
        return [], ["QR decoder unavailable (zxing-cpp or pyzbar required)"]

    deadline = time.monotonic() + timeout
    records: list[dict] = []
    notices: list[str] = []
    if decoder_name == "pyzbar":
        notices.append("DataMatrix decoding unavailable without zxing-cpp")
    total = 0
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as source:
                frames = getattr(source, "n_frames", 1)
                selected = (list(range(frames)) if frames <= MAX_FRAMES else
                            sorted({round(index * (frames - 1) / (MAX_FRAMES - 1))
                                    for index in range(MAX_FRAMES)}))
                if frames > len(selected):
                    notices.append(f"sampled {len(selected)} of {frames} image frames")
                for frame in selected:
                    if time.monotonic() >= deadline:
                        notices.append("QR time limit reached; inspection incomplete")
                        return records, notices
                    source.seek(frame)
                    if source.width * source.height > max_pixels:
                        notices.append("QR image pixel limit reached; inspection incomplete")
                        break
                    image = source.convert("L")
                    width, height = image.size
                    duration = source.info.get("duration")
                    duration_ms = duration if isinstance(duration, int) and duration >= 0 else None
                    for inverted in (False, True):
                        base = ImageOps.invert(image) if inverted else image
                        for rotation in (0, 90, 180, 270):
                            if time.monotonic() >= deadline:
                                notices.append("QR time limit reached; inspection incomplete")
                                return records, notices
                            view = base.rotate(rotation, expand=True) if rotation else base
                            symbols = (decoder(view, try_rotate=False, try_invert=False,
                                               try_downscale=False) if decoder_name == "zxingcpp"
                                       else decoder(view))
                            for symbol in symbols:
                                if decoder_name == "zxingcpp" and not symbol.valid:
                                    continue
                                payload = symbol.bytes if decoder_name == "zxingcpp" else symbol.data
                                if not isinstance(payload, bytes) or not payload:
                                    continue
                                points = _original_points(_points(symbol, decoder_name),
                                                          width, height, rotation)
                                if not points:
                                    continue
                                row = {"payload": payload, "format": str(symbol.format) if decoder_name == "zxingcpp" else symbol.type,
                                       "position": points, "frame": frame,
                                       "duration_ms": duration_ms, "source_mode": source.mode,
                                       "rotation_degrees": rotation, "inverted": inverted,
                                       "decoder": decoder_name, "source": str(path.resolve())}
                                if any(_same_symbol(row, existing) for existing in records):
                                    continue
                                if len(records) >= MAX_SYMBOLS or total + len(payload) > max_total_bytes:
                                    notices.append("QR symbol or output byte limit reached; inspection incomplete")
                                    return records, notices
                                records.append(row)
                                total += len(payload)
    except (OSError, EOFError, SyntaxError, ValueError, Image.DecompressionBombWarning,
            Image.DecompressionBombError) as error:
        notices.append(f"QR image rejected: {error}")
    return records, notices
