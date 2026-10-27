"""Offline, bounded audio and video inspection with source-linked previews."""

import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import struct
import subprocess
import tempfile
import time
from pathlib import Path


FFPROBE = (shutil.which(os.environ.get("AUTOSOLVE_FFPROBE", "ffprobe"))
           or os.environ.get("AUTOSOLVE_FFPROBE") or "ffprobe")
FFMPEG = (shutil.which(os.environ.get("AUTOSOLVE_FFMPEG", "ffmpeg"))
          or os.environ.get("AUTOSOLVE_FFMPEG") or "ffmpeg")
_PROBE_LIMIT = 1024 * 1024
_ERROR_LIMIT = 64 * 1024
_AUDIO_SECONDS = 20.0
_MAX_FRAMES = 32
_PTS = re.compile(rb"\bpts_time:([+-]?(?:\d+\.?\d*|\.\d+))")


def _run(argv: list[str], deadline: float, limit: int,
         supervised: bool = False) -> tuple[bytes, bytes, str | None]:
    """Read both pipes with a byte and wall limit; kill the process group on abort."""
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=not supervised,
                                   stdin=subprocess.DEVNULL)
    except OSError as error:
        return b"", b"", f"{Path(argv[0]).name} unavailable: {error}"
    output, errors = bytearray(), bytearray()
    warning = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = f"{Path(argv[0]).name} timed out; inspection incomplete"
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                cap = limit if key.data is output else _ERROR_LIMIT
                if len(key.data) + len(chunk) > cap:
                    key.data.extend(chunk[:max(0, cap - len(key.data))])
                    warning = f"{Path(argv[0]).name} output limit reached; inspection incomplete"
                    break
                key.data.extend(chunk)
            if warning:
                break
    finally:
        selector.close()
        if process.poll() is None:
            try:
                if supervised:
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if process.returncode and not warning:
        detail = errors.decode("utf-8", "replace").strip().splitlines()
        warning = f"{Path(argv[0]).name} exited {process.returncode}: {(detail[-1] if detail else 'unknown error')[:200]}"
    return bytes(output), bytes(errors), warning


def _seconds(value) -> float | None:
    try:
        result = float(value)
    except (ValueError, TypeError):
        return None
    return result if math.isfinite(result) and result >= 0 else None


def _tag_duration(tags) -> float | None:
    value = tags.get("DURATION") if isinstance(tags, dict) else None
    match = (re.fullmatch(r"(\d{1,4}):([0-5]\d):([0-5]\d(?:\.\d{1,9})?)", value)
             if isinstance(value, str) and len(value) <= 32 else None)
    if match is None:
        return None
    return _seconds(int(match[1]) * 3600 + int(match[2]) * 60 + float(match[3]))


def _known_stream_duration(stream: dict, container_duration: float | None,
                           container_start: float | None) -> float | None:
    value = _seconds(stream.get("duration"))
    if value is not None:
        return value
    value = _tag_duration(stream.get("tags"))
    start = _seconds(stream.get("start_time")) or container_start or 0.0
    if value is not None and (container_duration is None or
                              value <= container_duration - start + .05):
        return value
    return None


def _frame_times(path: str, stream_index: int, deadline: float,
                 limit: int, max_frames: int,
                 supervised: bool) -> tuple[list[float], str | None]:
    raw, _, warning = _run(
        [FFPROBE, "-v", "error", "-protocol_whitelist", "file,pipe",
         "-select_streams", f"v:{stream_index}", "-read_intervals",
         f"0%+#{max_frames + 2}", "-show_frames", "-show_entries",
         "frame=best_effort_timestamp_time", "-of", "json", path],
        deadline, limit, supervised)
    if warning:
        return [], warning
    try:
        frames = json.loads(raw)["frames"]
        if not isinstance(frames, list) or any(not isinstance(row, dict) for row in frames):
            raise ValueError("invalid frame records")
        times = [_seconds(row.get("best_effort_timestamp_time")) for row in frames]
        if any(value is None for value in times):
            raise ValueError("missing frame timestamp")
        return times, None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return [], "frame timestamps unavailable; exact full-frame inventory incomplete"


def inspect_media(path: Path, output_dir: Path, *, timeout: float,
                  max_bytes: int, max_frames: int = 8,
                  full_frames: bool = False,
                  supervised: bool = False) -> tuple[list[dict], list[str]]:
    """Return stream facts and staged views; never infer spoken or visual text."""
    if timeout <= 0 or max_bytes < 0 or max_frames < 1:
        raise ValueError("media limits must use positive time/frames and nonnegative bytes")
    if path.is_symlink() or not path.is_file():
        raise ValueError("media source must be a regular non-symlink file")
    if output_dir.is_symlink() or output_dir.resolve() == path.resolve().parent:
        raise ValueError("media output directory must be separate and not a symlink")
    source = str(path.resolve())
    deadline = time.monotonic() + timeout
    warnings: list[str] = []
    records: list[dict] = []
    used = 0
    ffmpeg_args = [FFMPEG, "-nostdin", "-hide_banner", "-threads", "1",
                   "-filter_threads", "1", "-filter_complex_threads", "1"]
    if max_frames > _MAX_FRAMES:
        warnings.append(f"video frame limit capped at {_MAX_FRAMES}")
        max_frames = _MAX_FRAMES

    raw, _, warning = _run(
        [FFPROBE, "-v", "error", "-protocol_whitelist", "file,pipe",
         "-show_format", "-show_streams", "-of", "json", source],
        deadline, _PROBE_LIMIT, supervised)
    if warning:
        return [], warnings + [warning]
    try:
        probe = json.loads(raw)
        streams = probe["streams"]
        if not isinstance(streams, list) or not isinstance(probe.get("format"), dict):
            raise ValueError("invalid stream metadata")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return [], warnings + ["invalid FFprobe JSON; media inspection incomplete"]

    duration = _seconds(probe["format"].get("duration"))
    container_start = _seconds(probe["format"].get("start_time"))
    audio_streams, video_streams, subtitle_streams = [], [], []
    for stream in streams[:64]:
        if not isinstance(stream, dict):
            warnings.append("invalid stream metadata row skipped")
            continue
        kind = stream.get("codec_type")
        index = stream.get("index")
        if kind not in ("audio", "video", "subtitle") or not isinstance(index, int):
            continue
        fields = ("codec_name", "start_time", "duration", "sample_rate", "channels", "channel_layout",
                  "width", "height", "avg_frame_rate", "nb_frames")
        details = {name: stream[name] for name in fields
                   if name in stream and isinstance(stream[name], (str, int, float))}
        tags = stream.get("tags", {})
        if isinstance(tags, dict):
            details["tags"] = {key: value[:256] for key, value in tags.items()
                               if key in ("language", "title") and isinstance(value, str)}
        known_duration = _known_stream_duration(stream, duration, container_start)
        records.append({"kind": "stream", "stream_type": kind, "stream_index": index,
                        "locator": f"stream {index}", "source": source,
                        "duration_seconds": known_duration if known_duration is not None else
                                            (duration if len(streams) == 1 else None),
                        "metadata": details})
        {"audio": audio_streams, "video": video_streams,
         "subtitle": subtitle_streams}[kind].append(stream)
    if len(streams) > 64:
        warnings.append("stream inventory limited to first 64 streams")
    if not records:
        return [], warnings + ["no supported audio, video or subtitle streams"]

    def stage(payload: bytes, kind: str, locator: str, **details) -> bool:
        nonlocal used
        if not payload:
            return False
        if len(payload) > max_bytes - used:
            warnings.append(f"{locator}: derived byte limit reached")
            return False
        if details.get("media_type") == "image/png":
            if len(payload) < 24 or not payload.startswith(b"\x89PNG\r\n\x1a\n"):
                warnings.append(f"{locator}: invalid PNG preview")
                return False
            details["width"], details["height"] = struct.unpack(">II", payload[16:24])
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix="media-", dir=output_dir)
        target = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
            records.append({"kind": kind, "path": target, "size": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "locator": locator, "source": source, **details})
            used += len(payload)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return True

    if audio_streams:
        stream = audio_streams[0]
        index = stream["index"]
        channels = stream.get("channels", 1)
        if not isinstance(channels, int) or channels < 1:
            channels = 1
        if len(audio_streams) > 1:
            warnings.append(f"audio views inspect stream {index} only; {len(audio_streams) - 1} other audio streams omitted")
        if channels > 2:
            warnings.append(f"audio views inspect first 2 of {channels} channels")
        window = min(duration or _AUDIO_SECONDS, _AUDIO_SECONDS)
        if duration is None:
            warnings.append(f"audio duration unknown; inspected at most first {_AUDIO_SECONDS:g} seconds")
        elif duration > window:
            warnings.append(f"audio views sample 0-{window:g}s of {duration:g}s; later audio uninspected")
        for channel in range(min(channels, 2)):
            if time.monotonic() >= deadline or used >= max_bytes:
                warnings.append("audio inspection budget reached")
                break
            base = ffmpeg_args + ["-loglevel", "error",
                    "-protocol_whitelist", "file,pipe", "-t", f"{window:.6f}",
                    "-i", source]
            pan = f"pan=mono|c0=c{channel}" if channels > 1 else "anull"
            locator = f"audio stream {index} channel {channel} time 0-{window:g}s"
            for view in ("channel", "reversed", "waveform", "spectrogram"):
                if used >= max_bytes or time.monotonic() >= deadline:
                    warnings.append("audio inspection budget reached")
                    break
                if view in ("channel", "reversed"):
                    filters = pan + (",areverse" if view == "reversed" else "")
                    argv = base + ["-map", f"0:{index}", "-af", filters,
                                   "-ac", "1", "-ar", "32000", "-c:a", "pcm_s16le",
                                   "-f", "wav", "pipe:1"]
                    media_type = "audio/wav"
                else:
                    picture = ("showwavespic=s=1024x256" if view == "waveform" else
                               "showspectrumpic=s=1024x512:legend=1")
                    argv = base + ["-filter_complex", f"[0:{index}]{pan},{picture}[v]",
                                   "-map", "[v]", "-frames:v", "1", "-c:v", "png",
                                   "-f", "image2pipe", "pipe:1"]
                    media_type = "image/png"
                payload, _, error = _run(argv, deadline, max_bytes - used, supervised)
                if error:
                    warnings.append(f"{locator} {view}: {error}")
                    if "timed out" in error:
                        return records, warnings
                    continue
                stage(payload, "audio_view", f"{locator} {view}", stream_index=index,
                      channel=channel, view=view, start_seconds=0.0,
                      end_seconds=window, media_type=media_type,
                      output_sample_rate=32000 if media_type == "audio/wav" else None)

    for relative_index, stream in enumerate(video_streams[:1]):
        index = stream["index"]
        stream_start = (_seconds(stream.get("start_time")) or
                        container_start or 0.0)
        stream_duration = _known_stream_duration(stream, duration, container_start)
        video_duration = (stream_duration or
                          (max(0.0, duration - stream_start) if duration is not None else None))
        frame_count = stream.get("nb_frames")
        try:
            frame_count = int(frame_count)
        except (ValueError, TypeError):
            frame_count = None
        if len(video_streams) > 1:
            warnings.append(f"video frames inspect stream {index} only; {len(video_streams) - 1} other video streams omitted")
        exact = (frame_count is None and (full_frames or stream_duration is None) or
                 frame_count is not None and 0 < frame_count <= max_frames)
        times = []
        if exact:
            times, error = _frame_times(source, relative_index, deadline,
                                        _PROBE_LIMIT, max_frames, supervised)
            if error:
                warnings.append(error)
        if times and len(times) <= max_frames:
            mode = "full-frame"
        else:
            mode = "sampled"
            count = min(max_frames, frame_count or max_frames)
            if len(times) == max_frames + 1:
                frame_count = len(times)
                times = [times[round(i * (frame_count - 1) / max(1, count - 1))]
                         for i in range(count)]
            elif times and stream_duration is None:
                observed = len(times)
                times = [times[round(i * (observed - 1) / max(1, count - 1))]
                         for i in range(count)]
                warnings.append(f"video duration unknown; sampled first {observed} timestamped frames only; later frames may be missed")
            elif video_duration is None:
                times = [0.0]
                warnings.append("video duration unknown; sampled first frame only")
            else:
                times = [stream_start + i * video_duration / count for i in range(count)]
            if frame_count is not None and frame_count > len(times):
                warnings.append(f"video sampled {len(times)} of {frame_count} frames; brief frames may be missed")
            elif frame_count is None:
                warnings.append(f"video sampled {len(times)} requested times; total frame count unknown")
            if full_frames:
                warnings.append("full-frame request exceeded frame or probe budget; output is sampled")
        for ordinal, requested in enumerate(times):
            if used >= max_bytes or time.monotonic() >= deadline:
                warnings.append("video inspection budget reached")
                break
            argv = ffmpeg_args + ["-loglevel", "info",
                    "-copyts", "-protocol_whitelist", "file,pipe",
                    "-ss", f"{max(0.0, requested - stream_start):.6f}",
                    "-i", source, "-map", f"0:{index}",
                    "-vf", r"scale=w=min(iw\,1024):h=min(ih\,1024):force_original_aspect_ratio=decrease,showinfo",
                    "-frames:v", "1", "-c:v", "png", "-f", "image2pipe", "pipe:1"]
            payload, stderr, error = _run(argv, deadline, max_bytes - used, supervised)
            locator = f"video stream {index} frame sample {ordinal} requested {requested:.6f}s"
            if error:
                warnings.append(f"{locator}: {error}")
                if "timed out" in error:
                    return records, warnings
                continue
            timestamps = _PTS.findall(stderr)
            sampled = _seconds(timestamps[0]) if timestamps else None
            if sampled is None:
                warnings.append(f"{locator}: decoded frame timestamp unavailable")
            stage(payload, "video_frame", locator, stream_index=index,
                  frame_sample=ordinal, requested_seconds=requested,
                  sampled_seconds=sampled, sampling_mode=mode, media_type="image/png")

    for stream in subtitle_streams[:4]:
        if used >= max_bytes or time.monotonic() >= deadline:
            warnings.append("subtitle inspection budget reached")
            break
        index = stream["index"]
        codec = stream.get("codec_name", "")
        if codec not in ("subrip", "ass", "ssa", "mov_text", "webvtt", "text"):
            warnings.append(f"subtitle stream {index}: unsupported text codec {codec}; no OCR attempted")
            continue
        argv = ffmpeg_args + ["-loglevel", "error",
                "-protocol_whitelist", "file,pipe", "-i", source,
                "-map", f"0:{index}", "-c:s", "srt", "-f", "srt", "pipe:1"]
        payload, _, error = _run(argv, deadline, max_bytes - used, supervised)
        if error:
            warnings.append(f"subtitle stream {index}: {error}")
            continue
        stage(payload, "subtitle_text", f"subtitle stream {index} cues",
              stream_index=index, media_type="application/x-subrip",
              start_seconds=0.0, end_seconds=duration)
    if len(subtitle_streams) > 4:
        warnings.append("subtitle inspection limited to first 4 streams")
    return records, warnings
