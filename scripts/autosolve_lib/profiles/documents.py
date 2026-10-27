"""Bounded ZIP extraction into a private autosolve staging directory."""

import hashlib
import os
import stat
import tempfile
import uuid
import zipfile
import zlib
from pathlib import Path


def _safe_file(info: zipfile.ZipInfo) -> bool:
    name = info.orig_filename
    parts = name.split("/")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    return (not info.is_dir() and "\x00" not in name and "\\" not in name
            and all(part not in ("", ".", "..") for part in parts)
            and not (len(name) > 1 and name[1] == ":")
            and kind in (0, stat.S_IFREG))


def extract_zip(path: Path, output_dir: Path, *, max_members: int,
                max_total_bytes: int, password: bytes | None = None,
                encrypted_only: bool = False) -> tuple[list[dict], list[str]]:
    """Stage verified regular members; record each central-directory occurrence separately."""
    if max_members < 0 or max_total_bytes < 0:
        raise ValueError("ZIP limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("ZIP output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("ZIP output directory must differ from source directory")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    results: list[dict] = []
    warnings: list[str] = []
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.infolist()):
                if index >= max_members:
                    warnings.append(f"member {index} ({info.filename!r}): member limit reached")
                    break
                if info.is_dir():
                    if stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFDIR):
                        warnings.append(f"member {index} ({info.filename!r}): unsafe path or file type")
                    continue
                if encrypted_only and not info.flag_bits & 1:
                    continue
                if not _safe_file(info):
                    warnings.append(f"member {index} ({info.filename!r}): unsafe path or file type")
                    continue
                remaining = max_total_bytes - total
                if info.file_size > remaining:
                    warnings.append(f"member {index} ({info.filename!r}): expanded byte limit reached")
                    continue
                if info.flag_bits & 1 and password is None:
                    warnings.append(f"member {index} ({info.filename!r}): password required")
                    continue
                fd, stage = tempfile.mkstemp(prefix=".zip-stage-", dir=output_dir)
                try:
                    digest = hashlib.sha256()
                    size = 0
                    with os.fdopen(fd, "wb") as target, archive.open(info, pwd=password) as source:
                        while chunk := source.read(min(65536, remaining - size + 1)):
                            if size + len(chunk) > remaining:
                                raise ValueError("expanded byte limit reached")
                            target.write(chunk)
                            digest.update(chunk)
                            size += len(chunk)
                    published = output_dir / f"{index:06d}-{uuid.uuid4().hex}"
                    os.link(stage, published)
                    total += size
                    results.append({"path": published, "member": info.filename, "index": index,
                                    "sha256": digest.hexdigest(), "size": size,
                                    "encrypted": bool(info.flag_bits & 1)})
                except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError,
                        zlib.error, ValueError) as error:
                    # zipfile checks these local headers before it checks the password.
                    if isinstance(error, zipfile.BadZipFile) and str(error).startswith((
                            "Truncated file header", "Bad magic number for file header",
                            "File name in directory", "Overlapped entries")):
                        warnings.append(f"member {index}: corrupt ZIP local header")
                    else:
                        warnings.append(f"member {index} ({info.filename!r}): {error}")
                finally:
                    os.unlink(stage)
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        warnings.append(f"invalid ZIP archive: {error}")
    return results, warnings
