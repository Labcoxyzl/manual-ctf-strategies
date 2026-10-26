"""Read bounded SQLite evidence from a private copy of a database and its WAL."""

import base64
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import uuid
from contextlib import closing
from pathlib import Path


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _value(value):
    if isinstance(value, bytes):
        return {"type": "blob", "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, float) and not (-float("inf") < value < float("inf")):
        return {"type": "real", "value": str(value)}
    return value


def _text(value: bytes):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return {"type": "text", "base64": base64.b64encode(value).decode("ascii")}


def inspect_sqlite(path: Path, output_dir: Path, *, max_rows: int,
                   max_bytes: int) -> tuple[list[dict], list[str]]:
    """Stage schema and row JSON with source table and row identity metadata."""
    if max_rows < 0 or max_bytes < 0:
        raise ValueError("SQLite limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("SQLite output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("SQLite output directory must differ from source directory")

    records: list[dict] = []
    warnings: list[str] = []
    sources = [path]
    for suffix in ("-wal", "-shm"):
        companion = path.with_name(path.name + suffix)
        if companion.exists() or companion.is_symlink():
            sources.append(companion)
    try:
        if any(not stat.S_ISREG(source.lstat().st_mode) for source in sources):
            return records, ["SQLite input or companion is not a regular file"]
        if sum(source.stat().st_size for source in sources) > max_bytes:
            return records, ["SQLite input byte limit reached"]
    except FileNotFoundError:
        return records, ["SQLite database or companion missing"]
    wal = path.with_name(path.name + "-wal")

    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    total = 0
    rows_seen = 0
    output_limited = False

    def stage(item: dict, kind: str, locator: str, **details) -> bool:
        nonlocal total, output_limited
        data = (json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                           allow_nan=False) + "\n").encode("utf-8")
        if len(data) > max_bytes - total:
            if not output_limited:
                warnings.append(f"{locator}: evidence byte limit reached")
                output_limited = True
            return False
        fd, temporary = tempfile.mkstemp(prefix=".sqlite-stage-", dir=output_dir)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
            published = output_dir / f"{len(records):06d}-{uuid.uuid4().hex}"
            os.link(temporary, published)
            records.append({"path": published, "kind": kind, "locator": locator,
                            "media_type": "application/json", "sha256": hashlib.sha256(data).hexdigest(),
                            "size": len(data), **details})
            total += len(data)
            return True
        finally:
            os.unlink(temporary)

    with tempfile.TemporaryDirectory(prefix=".sqlite-copy-", dir=output_dir) as directory:
        copied = Path(directory) / path.name
        hashes = {}
        copied_bytes = 0
        try:
            for source in sources:
                digest = hashlib.sha256()
                destination = Path(directory) / source.name
                descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as original, destination.open("xb") as target:
                    if not stat.S_ISREG(os.fstat(original.fileno()).st_mode):
                        return records, warnings + ["SQLite input or companion is not a regular file"]
                    while chunk := original.read(65536):
                        copied_bytes += len(chunk)
                        if copied_bytes > max_bytes:
                            return records, warnings + ["SQLite input byte limit reached"]
                        target.write(chunk)
                        digest.update(chunk)
                hashes[source] = digest.digest()
            changed = False
            for source, digest in hashes.items():
                check = hashlib.sha256()
                checked_bytes = 0
                descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as original:
                    while chunk := original.read(65536):
                        checked_bytes += len(chunk)
                        if checked_bytes > max_bytes:
                            return records, warnings + ["SQLite source or companions changed during snapshot"]
                        check.update(chunk)
                changed |= check.digest() != digest
            changed |= any(companion.exists() != (companion in sources)
                           for companion in (wal, path.with_name(path.name + "-shm")))
            if changed:
                return records, warnings + ["SQLite source or companions changed during snapshot"]
        except OSError as error:
            return records, warnings + [f"SQLite snapshot failed: {type(error).__name__}"]
        with copied.open("rb") as source:
            header = source.read(100)
        if header[:16] == b"SQLite format 3\x00" and header[18:20] == b"\x02\x02" and wal not in sources:
            warnings.append("WAL-mode database has no -wal companion; recent rows may be missing")
        if wal in sources and path.with_name(path.name + "-shm") not in sources:
            warnings.append("-shm companion missing; SQLite will rebuild the WAL index on the copy")

        try:
            with closing(sqlite3.connect(copied.as_uri() + "?mode=ro", uri=True, timeout=0.1)) as connection:
                connection.text_factory = _text
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max(1024, max_bytes))
                steps = 0

                def progress():
                    nonlocal steps
                    steps += 1
                    return steps > 10000

                connection.set_progress_handler(progress, 1000)
                for kind, name, table, rootpage, sql in connection.execute(
                        "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema ORDER BY rowid"):
                    locator = f"schema {kind} {name}"
                    stage({"type": kind, "name": name, "table": table,
                           "rootpage": rootpage, "sql": sql}, "schema", locator,
                          source_table=name if kind == "table" and isinstance(name, str) else None)
                for (name,) in connection.execute(
                        "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY rowid"):
                    if not isinstance(name, str):
                        warnings.append("SQLite table name has invalid text encoding")
                        continue
                    if name.startswith("sqlite_"):
                        continue
                    quoted = _quote(name)
                    try:
                        columns = connection.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
                        names = [column[1] for column in columns if column[6] != 1]
                        rowid_name = next((alias for alias in ("rowid", "_rowid_", "oid")
                                           if alias.lower() not in {str(column[1]).lower() for column in columns}), None)
                        identity = f"{rowid_name},*" if rowid_name else "*"
                        try:
                            cursor = connection.execute(
                                f"SELECT {identity} FROM {quoted} LIMIT ?",
                                (min(max_rows - rows_seen + 1, max_bytes + 1, 2**63 - 1),))
                        except sqlite3.OperationalError as error:
                            if rowid_name is None or "no such column" not in str(error):
                                raise
                            rowid_name = None  # WITHOUT ROWID tables have primary-key identity instead.
                            cursor = connection.execute(
                                f"SELECT * FROM {quoted} LIMIT ?",
                                (min(max_rows - rows_seen + 1, max_bytes + 1, 2**63 - 1),))
                        if rowid_name is None and not any(column[5] for column in columns):
                            warnings.append(f"table {name!r}: rowid unavailable; row locator is ordinal")
                        for row in cursor:
                            if rows_seen >= max_rows:
                                warnings.append(f"table {name!r}: row limit reached")
                                break
                            rows_seen += 1
                            rowid = row[0] if rowid_name else None
                            values = row[1:] if rowid_name else row
                            fields = {column: _value(value) for column, value in zip(names, values)}
                            primary_key = {column[1]: fields[column[1]] for column in columns if column[5]}
                            locator = f"table {name} rowid {rowid}" if rowid is not None else f"table {name} row {rows_seen}"
                            stage({"table": name, "rowid": rowid,
                                   "primary_key": primary_key if rowid is None else None,
                                   "values": fields}, "row", locator, source_table=name,
                                  rowid=rowid)
                    except sqlite3.Error as error:
                        warnings.append(f"table {name!r}: {type(error).__name__}: {error}")
        except sqlite3.Error as error:
            warnings.append(f"SQLite parse failed: {type(error).__name__}: {error}")
    return records, warnings
