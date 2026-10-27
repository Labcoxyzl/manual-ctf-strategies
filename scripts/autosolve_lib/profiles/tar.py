"""Bounded tar extraction into a private autosolve staging directory."""

import bz2
import gzip
import hashlib
import lzma
import os
import tarfile
import tempfile
import uuid
from contextlib import closing, nullcontext
from pathlib import Path


def _safe_file(info: tarfile.TarInfo) -> bool:
    name = info.name
    if name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    return (info.isfile() and "\x00" not in name and "\\" not in name
            and all(part not in ("", ".", "..") for part in parts)
            and not (len(name) > 1 and name[1] == ":"))


class _BoundedReader:
    def __init__(self, source, limit: int):
        self.source = source
        self.limit = limit
        self.total = 0

    def read(self, size: int) -> bytes:
        chunk = self.source.read(min(size, self.limit - self.total + 1))
        self.total += len(chunk)
        if self.total > self.limit:
            raise ValueError("archive expanded byte limit reached")
        return chunk


def extract_tar(path: Path, output_dir: Path, *, max_members: int,
                max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Stage regular members separately, retaining original names and archive indices."""
    if max_members < 0 or max_total_bytes < 0:
        raise ValueError("TAR limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("TAR output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("TAR output directory must differ from source directory")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    records: list[dict] = []
    warnings: list[str] = []
    total = 0
    try:
        with path.open("rb") as raw:
            magic = raw.read(6)
            raw.seek(0)
            if magic.startswith(b"\x1f\x8b"):
                decoded = gzip.GzipFile(fileobj=raw)
            elif magic.startswith(b"BZh"):
                decoded = bz2.BZ2File(raw)
            elif magic.startswith(b"\xfd7zXZ\x00"):
                decoded = lzma.LZMAFile(raw)
            else:
                decoded = raw
            with closing(decoded) if decoded is not raw else nullcontext(raw):
                # Include bounded header/PAX overhead and usual tar end padding.
                source = _BoundedReader(decoded, max_total_bytes + 1024 * 1024
                                        + min(max_members, 1024) * 4096)
                with tarfile.open(fileobj=source, mode="r|") as archive:
                    for index, info in enumerate(archive):
                        locator = f"member {index} ({info.name!r})"
                        if index >= max_members:
                            warnings.append(f"{locator}: member limit reached")
                            break
                        remaining = max_total_bytes - total
                        if info.size < 0 or info.size > remaining:
                            warnings.append(f"{locator}: expanded byte limit reached")
                            break
                        if info.isdir():
                            continue
                        if not _safe_file(info):
                            warnings.append(f"{locator}: unsafe path or file type")
                            continue
                        fd, stage = tempfile.mkstemp(prefix=".tar-stage-", dir=output_dir)
                        try:
                            digest = hashlib.sha256()
                            size = 0
                            with os.fdopen(fd, "wb") as target, archive.extractfile(info) as member:
                                while chunk := member.read(min(65536, remaining - size + 1)):
                                    if size + len(chunk) > remaining:
                                        raise ValueError("expanded byte limit reached")
                                    target.write(chunk)
                                    digest.update(chunk)
                                    size += len(chunk)
                            if size != info.size:
                                raise ValueError("truncated member")
                            published = output_dir / f"{index:06d}-{uuid.uuid4().hex}"
                            os.link(stage, published)
                            total += size
                            records.append({"path": published, "member": info.name, "index": index,
                                            "sha256": digest.hexdigest(), "size": size})
                        except (tarfile.TarError, EOFError, lzma.LZMAError,
                                ValueError, OSError) as error:
                            warnings.append(f"{locator}: invalid or truncated member: {error}")
                            break
                        finally:
                            os.unlink(stage)
                    else:
                        while archive.fileobj.read(65536):
                            pass
    except (tarfile.TarError, EOFError, lzma.LZMAError, ValueError, OSError) as error:
        warnings.append(f"invalid TAR archive: {error}")
    return records, warnings
