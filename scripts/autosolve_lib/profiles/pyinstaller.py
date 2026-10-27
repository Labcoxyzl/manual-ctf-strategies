"""Bounded static extraction of PyInstaller CArchive and embedded PYZ resources."""

import hashlib
import importlib.util
import io
import marshal
import os
import stat
import struct
import sys
import tempfile
import uuid
import zlib
from pathlib import Path


MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE = struct.Struct("!8sIIII64s")
ENTRY = struct.Struct("!IIIIBc")
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_COOKIE_SEARCH = 8 * 1024 * 1024
MAX_TOC_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 4096


def _safe_name(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return (bool(name) and len(name) <= 4096 and "\x00" not in name
            and not name.startswith(("/", "\\"))
            and not (len(name) > 1 and name[1] == ":")
            and all(part not in ("", ".", "..") for part in parts))


def _inflate(source, offset: int, length: int, limit: int) -> bytes:
    source.seek(offset)
    decoder = zlib.decompressobj()
    output = io.BytesIO()
    remaining = length
    while remaining:
        chunk = source.read(min(65536, remaining))
        if not chunk:
            raise ValueError("truncated compressed member")
        remaining -= len(chunk)
        data = decoder.decompress(chunk, limit - output.tell() + 1)
        if len(data) > limit - output.tell() or decoder.unconsumed_tail:
            raise ValueError("decoded byte limit reached")
        output.write(data)
    data = decoder.flush(limit - output.tell() + 1)
    if len(data) > limit - output.tell():
        raise ValueError("decoded byte limit reached")
    output.write(data)
    if not decoder.eof or decoder.unused_data:
        raise ValueError("invalid compressed member")
    return output.getvalue()


def inspect_pyinstaller(path: Path, output_dir: Path, *, max_members: int,
                        max_total_bytes: int) -> tuple[list[dict], list[str], dict]:
    """Stage exact archive resources and marshalled code; never execute/decompile code."""
    if max_members < 0 or max_total_bytes < 0:
        raise ValueError("PyInstaller limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("PyInstaller output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("PyInstaller output directory must differ from source directory")

    records: list[dict] = []
    warnings: list[str] = []
    inventory = {"carchive": {"complete": False, "entries": []}, "pyz": []}
    total = 0

    def stage(data: bytes, kind: str, locator: str, **details) -> bool:
        nonlocal total
        if len(records) >= max_members:
            warnings.append(f"{locator}: member limit reached")
            return False
        if len(data) > max_total_bytes - total:
            warnings.append(f"{locator}: decoded byte limit reached")
            return False
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".pyi-stage-", dir=output_dir)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
            published = output_dir / f"{len(records):06d}-{uuid.uuid4().hex}"
            os.link(temporary, published)
            records.append({"path": published, "kind": kind, "locator": locator,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "size": len(data), **details})
            total += len(data)
            return True
        finally:
            os.unlink(temporary)

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("PyInstaller source must be a regular file")
        size = before.st_size
        if size > MAX_SOURCE_BYTES:
            return [], [f"PyInstaller source byte limit reached ({MAX_SOURCE_BYTES})"], inventory
        source.seek(max(0, size - MAX_COOKIE_SEARCH))
        tail = source.read(MAX_COOKIE_SEARCH)
        relative = tail.rfind(MAGIC)
        if relative < 0:
            return [], [], inventory
        cookie_offset = size - len(tail) + relative
        if cookie_offset + COOKIE.size > size:
            return [], ["corrupt PyInstaller cookie"], inventory
        _, archive_length, toc_offset, toc_length, pyvers, pylib = COOKIE.unpack_from(tail, relative)
        archive_end = cookie_offset + COOKIE.size
        archive_start = archive_end - archive_length
        if (archive_start < 0 or archive_length < COOKIE.size or
                toc_length > MAX_TOC_BYTES or
                toc_offset > archive_length - COOKIE.size or
                toc_length > archive_length - COOKIE.size - toc_offset or
                archive_start + toc_offset + toc_length > cookie_offset or
                not pylib.strip(b"\x00")):
            return [], ["corrupt PyInstaller archive boundaries"], inventory
        py_version = f"{pyvers // 100}.{pyvers % 100}"
        source.seek(archive_start + toc_offset)
        toc = source.read(toc_length)
        if len(toc) != toc_length:
            return [], ["truncated PyInstaller table of contents"], inventory
        cursor = 0
        entries = []
        entry_indices = []
        toc_index = 0
        while cursor < len(toc):
            if toc_index >= MAX_ENTRIES:
                warnings.append("PyInstaller table of contents entry limit reached")
                break
            if len(toc) - cursor < ENTRY.size:
                warnings.append("corrupt PyInstaller table of contents")
                break
            entry_size, offset, length, decoded_length, compressed, raw_type = ENTRY.unpack_from(toc, cursor)
            if entry_size <= ENTRY.size or entry_size > len(toc) - cursor:
                warnings.append("corrupt PyInstaller table of contents")
                break
            raw_name = toc[cursor + ENTRY.size:cursor + entry_size].split(b"\x00", 1)[0]
            try:
                name = raw_name.decode("utf-8")
                typecode = raw_type.decode("ascii")
            except UnicodeError:
                warnings.append(f"CArchive entry {toc_index}: invalid name or type")
                cursor += entry_size
                toc_index += 1
                continue
            entries.append((name, typecode, offset, length, decoded_length, compressed))
            entry_indices.append(toc_index)
            inventory["carchive"]["entries"].append({
                "index": toc_index, "name": name, "typecode": typecode,
                "offset": archive_start + offset, "compressed_size": length,
                "decoded_size": decoded_length, "compressed": bool(compressed)})
            cursor += entry_size
            toc_index += 1
        if cursor != len(toc):
            warnings.append("incomplete PyInstaller table of contents")
        inventory["carchive"]["complete"] = (cursor == len(toc) and not any(
            "invalid name or type" in warning for warning in warnings))
        inventory["carchive"]["entry_count"] = toc_index
        metadata_remaining = MAX_ENTRIES - toc_index

        def pyz_members(base: int, length: int, parent_name: str, parent_index: int) -> None:
            nonlocal metadata_remaining
            pyz_inventory = {"carchive_index": parent_index, "name": parent_name,
                             "complete": False, "entry_count": 0, "entries": []}
            inventory["pyz"].append(pyz_inventory)
            if length < 12:
                warnings.append(f"CArchive member {parent_index}: truncated PYZ header")
                return
            source.seek(base)
            header = source.read(12)
            if header[:4] != b"PYZ\x00":
                warnings.append(f"CArchive member {parent_index}: invalid PYZ header")
                return
            bytecode_magic = header[4:8]
            same_version = bytecode_magic == importlib.util.MAGIC_NUMBER
            if not same_version:
                warnings.append(f"CArchive member {parent_index}: PYZ bytecode {bytecode_magic.hex()} is unsupported by Python {sys.version_info.major}.{sys.version_info.minor}; raw code retained, no decompilation attempted")
            pyz_toc_offset = struct.unpack("!I", header[8:12])[0]
            if pyz_toc_offset < 12 or pyz_toc_offset >= length or length - pyz_toc_offset > MAX_TOC_BYTES:
                warnings.append(f"CArchive member {parent_index}: invalid PYZ table offset or size")
                return
            source.seek(base + pyz_toc_offset)
            # shortcut: encrypted PYZ members need a version-aware key workflow.
            try:
                raw_table = source.read(length - pyz_toc_offset)
                table_stream = io.BytesIO(raw_table)
                table = marshal.load(table_stream)
                if table_stream.tell() != len(raw_table):
                    raise ValueError("trailing PYZ table bytes")
            except (EOFError, ValueError, TypeError):
                warnings.append(f"CArchive member {parent_index}: unsupported or corrupt PYZ table")
                return
            if isinstance(table, dict):
                table = list(table.items())
            if not isinstance(table, (tuple, list)) or len(table) > MAX_ENTRIES:
                warnings.append(f"CArchive member {parent_index}: unsupported PYZ table")
                return
            pyz_inventory["entry_count"] = len(table)
            metadata_complete = len(table) <= metadata_remaining
            if not metadata_complete:
                warnings.append(f"CArchive member {parent_index}: PYZ metadata entry limit reached")
            for pyz_index, item in enumerate(table):
                if pyz_index >= metadata_remaining:
                    break
                locator = f"CArchive member {parent_index} ({parent_name!r}) PYZ member {pyz_index}"
                if (not isinstance(item, (tuple, list)) or len(item) != 2 or
                        not isinstance(item[0], str) or not _safe_name(item[0]) or
                        not isinstance(item[1], (tuple, list)) or len(item[1]) != 3):
                    warnings.append(f"{locator}: unsafe or unsupported PYZ entry")
                    metadata_complete = False
                    continue
                name, (kind_code, member_offset, member_length) = item
                locator += f" ({name!r}) offset {base + member_offset}"
                if not isinstance(kind_code, int) or not all(
                        isinstance(value, int) and not isinstance(value, bool)
                        for value in (member_offset, member_length)):
                    warnings.append(f"{locator}: invalid PYZ member descriptor")
                    metadata_complete = False
                    continue
                pyz_inventory["entries"].append({
                    "index": pyz_index, "name": name, "kind_code": kind_code,
                    "offset": base + member_offset, "compressed_size": member_length})
                if member_length == 0 and kind_code == 2:
                    continue  # Namespace package, no resource bytes.
                if (member_offset < 12 or member_length <= 0 or
                        member_offset + member_length > pyz_toc_offset):
                    warnings.append(f"{locator}: PYZ member outside data region")
                    metadata_complete = False
                    continue
                if len(records) >= max_members:
                    if not any("member limit reached" in warning for warning in warnings):
                        warnings.append(f"{locator}: member limit reached")
                    continue
                try:
                    data = _inflate(source, base + member_offset, member_length,
                                    max_total_bytes - total)
                except zlib.error:
                    warnings.append(f"{locator}: encrypted or corrupt PYZ member; decryption unavailable")
                    continue
                except ValueError as error:
                    warnings.append(f"{locator}: {error}")
                    continue
                stage(data, "pyz_bytecode", locator, member=name, index=pyz_index,
                      carchive_index=parent_index, offset=base + member_offset,
                      compressed_size=member_length, python_version=py_version,
                      bytecode_magic=bytecode_magic.hex(),
                      bytecode_inspection=("same-version marshal; no decompilation" if same_version
                                           else "unsupported version; raw marshal only"))
            metadata_remaining -= min(len(table), metadata_remaining)
            pyz_inventory["complete"] = metadata_complete

        order = sorted(range(len(entries)),
                       key=lambda index: {"x": 0, "s": 1, "m": 1, "M": 1, "z": 2}.get(entries[index][1], 3))
        for position in order:
            index = entry_indices[position]
            name, typecode, offset, length, decoded_length, compressed = entries[position]
            locator = f"CArchive member {index} ({name!r}) offset {archive_start + offset}"
            if not _safe_name(name) or typecode == "n":
                warnings.append(f"{locator}: unsafe path or symbolic link")
                continue
            if typecode in ("o", "d"):
                continue
            if (offset < 0 or length < 0 or offset + length > toc_offset or
                    compressed not in (0, 1)):
                warnings.append(f"{locator}: member outside data region or invalid compression")
                continue
            if typecode == "z" and compressed == 0:
                pyz_members(archive_start + offset, length, name, index)
                continue
            if len(records) >= max_members:
                if not any("member limit reached" in warning for warning in warnings):
                    warnings.append(f"{locator}: member limit reached")
                continue
            if decoded_length > max_total_bytes - total:
                warnings.append(f"{locator}: decoded byte limit reached")
                continue
            try:
                if compressed:
                    data = _inflate(source, archive_start + offset, length,
                                    max_total_bytes - total)
                else:
                    source.seek(archive_start + offset)
                    data = source.read(length)
                    if len(data) != length:
                        raise ValueError("truncated member")
                if len(data) != decoded_length:
                    raise ValueError("decoded length mismatch")
            except (ValueError, zlib.error) as error:
                warnings.append(f"{locator}: {error}")
                continue
            kind = "bytecode" if typecode in ("s", "m", "M") else "resource"
            stage(data, kind, locator, member=name, index=index,
                  offset=archive_start + offset, compressed_size=length,
                  typecode=typecode, python_version=py_version,
                  bytecode_inspection=("marshalled code; no decompilation" if kind == "bytecode"
                                       else None))
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            for record in records:
                record["path"].unlink()
            return [], ["PyInstaller source changed during reading"], {
                "carchive": {"complete": False, "entries": []}, "pyz": []}
    return records, warnings, inventory
