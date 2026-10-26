"""Bounded static extraction of Office embedded parts and VBA source."""

import hashlib
import io
import os
import stat
import tempfile
import uuid
import zipfile
from pathlib import Path

from .documents import _safe_file


MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 2048
MAX_RTF_BYTES = 8 * 1024 * 1024


def inspect_office(path: Path, output_dir: Path, *, max_parts: int,
                   max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Stage OOXML/OLE embedded data and static VBA source with source locators."""
    if max_parts < 0 or max_total_bytes < 0:
        raise ValueError("Office limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("Office output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("Office output directory must differ from source directory")

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Office source must be a regular file")
        if before.st_size > MAX_SOURCE_BYTES:
            return [], [f"Office source byte limit reached ({MAX_SOURCE_BYTES})"]
        raw = source.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(source.fileno())
    if len(raw) > MAX_SOURCE_BYTES:
        return [], [f"Office source byte limit reached ({MAX_SOURCE_BYTES})"]
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return [], ["Office source changed during reading"]

    records: list[dict] = []
    warnings: list[str] = []
    total = 0

    def stage(data: bytes, kind: str, locator: str, **details) -> None:
        nonlocal total
        if len(records) >= max_parts:
            warnings.append(f"{locator}: part limit reached")
            return
        if len(data) > max_total_bytes - total:
            warnings.append(f"{locator}: decoded byte limit reached")
            return
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".office-stage-", dir=output_dir)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
            published = output_dir / f"{len(records):06d}-{uuid.uuid4().hex}"
            os.link(temporary, published)
            records.append({"path": published, "kind": kind, "locator": locator,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "size": len(data), **details})
            total += len(data)
        finally:
            os.unlink(temporary)

    def macros(data: bytes, locator: str) -> None:
        try:
            from oletools.olevba import VBA_Parser
        except ImportError:
            warnings.append(f"{locator}: VBA parser unavailable: oletools is not installed")
            return
        parser = None
        try:
            parser = VBA_Parser(locator, data=data)
            for filename, stream_path, module, code in parser.extract_macros():
                macro_locator = f"{locator} stream {stream_path} module {module}"
                if not isinstance(code, (str, bytes)):
                    warnings.append(f"{macro_locator}: unsupported macro source")
                    continue
                encoded = code.encode("utf-8") if isinstance(code, str) else code
                stage(encoded, "macro_source", macro_locator,
                      stream=stream_path, module=module, container=filename)
                if len(records) >= max_parts or total >= max_total_bytes:
                    break
        except Exception as error:
            warnings.append(f"{locator}: VBA extraction failed: {type(error).__name__}")
        finally:
            if parser is not None:
                parser.close()

    if zipfile.is_zipfile(io.BytesIO(raw)):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                if not any(info.filename == "[Content_Types].xml" for info in entries):
                    return [], []
                for index, info in enumerate(entries):
                    if index >= MAX_ENTRIES:
                        warnings.append(f"member {index}: entry limit reached")
                        break
                    name = info.filename.lower()
                    kind = ("vba_project" if name.endswith("/vbaproject.bin") else
                            "embedded_object" if any(name.startswith(prefix) for prefix in
                                ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/"))
                            else None)
                    if kind is None:
                        continue
                    locator = f"member {index} ({info.filename!r})"
                    if not _safe_file(info):
                        warnings.append(f"{locator}: unsafe path or file type")
                        continue
                    if info.flag_bits & 1:
                        warnings.append(f"{locator}: password required")
                        continue
                    if info.file_size > max_total_bytes - total:
                        warnings.append(f"{locator}: decoded byte limit reached")
                        continue
                    try:
                        with archive.open(info) as source:
                            data = source.read(max_total_bytes - total + 1)
                        if len(data) != info.file_size:
                            warnings.append(f"{locator}: member size mismatch")
                            continue
                        stage(data, kind, locator, member=info.filename, index=index)
                        if kind == "vba_project":
                            if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                                macros(data, locator)
                            else:
                                warnings.append(f"{locator}: VBA project is not an OLE container")
                    except (zipfile.BadZipFile, RuntimeError, NotImplementedError,
                            EOFError, ValueError) as error:
                        warnings.append(f"{locator}: extraction failed: {type(error).__name__}")
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            warnings.append(f"Office ZIP parse failed: {type(error).__name__}")
        return records, warnings

    if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        try:
            import olefile
        except ImportError:
            return [], ["OLE parser unavailable: olefile is not installed"]
        try:
            with olefile.OleFileIO(io.BytesIO(raw)) as ole:
                streams = ole.listdir()
                if any(parts[-1].lower() == "encryptedpackage" for parts in streams):
                    return [], ["encrypted Office file: password required"]
                for index, parts in enumerate(streams):
                    if index >= MAX_ENTRIES:
                        warnings.append(f"stream {index}: entry limit reached")
                        break
                    if parts[-1].lower() != "\x01ole10native":
                        continue
                    locator = f"stream {index} ({'/'.join(parts)!r})"
                    try:
                        stream = ole.openstream(parts)
                        if stream.size > max_total_bytes - total:
                            warnings.append(f"{locator}: decoded byte limit reached")
                            continue
                        from oletools.oleobj import OleNativeStream
                        native = OleNativeStream(stream.read(max_total_bytes - total + 1))
                        if native.is_link or native.data is None:
                            warnings.append(f"{locator}: linked object, no embedded bytes")
                            continue
                        if len(native.data) != native.actual_size:
                            warnings.append(f"{locator}: embedded size mismatch")
                            continue
                        stage(native.data, "embedded_object", locator,
                              stream="/".join(parts), name=native.filename)
                    except Exception as error:
                        warnings.append(f"{locator}: extraction failed: {type(error).__name__}")
            macros(raw, "OLE document")
        except Exception as error:
            warnings.append(f"OLE parse failed: {type(error).__name__}")
        return records, warnings

    if raw.lstrip().startswith(b"{\\rtf"):
        if len(raw) > MAX_RTF_BYTES:
            return [], [f"RTF parser byte limit reached ({MAX_RTF_BYTES})"]
        try:
            from oletools.rtfobj import RtfObjParser
            parser = RtfObjParser(raw)
            parser.parse()
            for index, obj in enumerate(parser.objects):
                if index >= MAX_ENTRIES:
                    warnings.append(f"RTF object {index}: entry limit reached")
                    break
                locator = f"RTF object {index} offset {obj.start}:{obj.end}"
                data = (obj.olepkgdata if obj.is_package else
                        obj.oledata if obj.is_ole else obj.rawdata)
                if data is None:
                    warnings.append(f"{locator}: object bytes unavailable")
                    continue
                stage(data, "embedded_object", locator,
                      index=index, offset=obj.start, end=obj.end)
                if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                    macros(data, locator)
        except ImportError:
            warnings.append("RTF parser unavailable: oletools is not installed")
        except Exception as error:
            warnings.append(f"RTF parse failed: {type(error).__name__}")
        return records, warnings
    return [], []
