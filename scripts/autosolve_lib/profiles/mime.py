"""Bounded MIME part extraction into a private staging directory."""

import base64
import binascii
import hashlib
import os
import quopri
import re
import stat
import tempfile
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path


MAX_NESTING = 16


def _base64_bytes(encoded):
    if isinstance(encoded, str):
        try:
            encoded = encoded.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("non-ASCII encoded payload") from error
    try:
        return base64.b64decode(re.sub(rb"[ \t\r\n]", b"", encoded), validate=True)
    except binascii.Error as error:
        raise ValueError(f"invalid base64 payload: {error}") from error


def _decoded(part):
    encoding = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    if encoding in ("7bit", "8bit", "binary"):
        return part.get_payload(decode=True)
    if encoding not in ("base64", "quoted-printable"):
        raise ValueError(f"unsupported transfer encoding {encoding!r}")
    payload = part.get_payload(decode=False)
    if not isinstance(payload, str):
        raise ValueError("malformed encoded payload")
    if encoding == "base64":
        return _base64_bytes(payload)
    try:
        encoded = payload.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("non-ASCII encoded payload") from error
    if re.search(rb"=(?![0-9A-Fa-f]{2}|\r?\n)", encoded):
        raise ValueError("invalid quoted-printable payload")
    return quopri.decodestring(encoded)


def parse_mime(path: Path, output_dir: Path, *, max_parts: int,
               max_total_bytes: int) -> tuple[list[dict], list[str]]:
    """Stage decoded leaf parts, retaining MIME location and source metadata."""
    if max_parts < 0 or max_total_bytes < 0:
        raise ValueError("MIME limits must be nonnegative")
    if output_dir.is_symlink():
        raise ValueError("MIME output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("MIME output directory must differ from source directory")

    # MIME headers and transfer encodings may be larger than the decoded parts.
    source_limit = max_total_bytes * 4 + 1024 * 1024
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("MIME source must be a regular file")
        if before.st_size > source_limit:
            return [], [f"MIME source byte limit reached ({source_limit})"]
        raw = source.read(source_limit + 1)
        after = os.fstat(source.fileno())
    if len(raw) > source_limit:
        return [], [f"MIME source byte limit reached ({source_limit})"]
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return [], ["MIME source changed during reading"]
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (RecursionError, ValueError) as error:
        return [], [f"MIME parse failed: {error}"]

    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    records: list[dict] = []
    warnings: list[str] = []
    total = 0
    seen = 0
    stack = [(message, "0", 0)]
    while stack:
        part, locator, depth = stack.pop()
        if seen >= max_parts:
            warnings.append(f"part {locator}: part limit reached")
            break
        index = seen
        seen += 1
        for defect in part.defects:
            warnings.append(f"part {locator}: malformed MIME: {type(defect).__name__}")
        encoding = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
        encoded_message = part.get_content_type() == "message/rfc822" and encoding not in (
            "7bit", "8bit", "binary")
        nested = None
        if encoded_message:
            if encoding != "base64" or not part.is_multipart() or len(part.get_payload()) != 1:
                warnings.append(f"part {locator}: encoded message container unsupported")
                continue
            child = part.get_payload(0)
            if child.keys() or not isinstance(child.get_payload(), str):
                warnings.append(f"part {locator}: malformed encoded message container")
                continue
            try:
                data = _base64_bytes(child.get_payload())
            except ValueError as error:
                warnings.append(f"part {locator}: {error}")
                continue
            if len(data) > max_total_bytes - total:
                warnings.append(f"part {locator}: decoded byte limit reached")
                continue
            if depth >= MAX_NESTING:
                warnings.append(f"part {locator}: nesting limit reached")
                continue
            try:
                nested = BytesParser(policy=policy.default).parsebytes(data)
            except (RecursionError, ValueError) as error:
                warnings.append(f"part {locator}: nested MIME parse failed: {error}")
                continue
        if part.is_multipart():
            if nested is None:
                children = part.get_payload()
                if depth >= MAX_NESTING:
                    warnings.append(f"part {locator}: nesting limit reached")
                    continue
                stack.extend((child, f"{locator}.{child_index}", depth + 1)
                             for child_index, child in reversed(list(enumerate(children))))
                continue
        if part.get_content_maintype() == "multipart":
            warnings.append(f"part {locator}: malformed multipart container")
            continue
        if part.get_content_maintype() == "message" and nested is None:
            warnings.append(f"part {locator}: opaque message payload")
            continue
        if nested is None:
            try:
                data = _decoded(part)
            except ValueError as error:
                warnings.append(f"part {locator}: {error}")
                continue
        if data is None:
            warnings.append(f"part {locator}: payload unavailable")
            continue
        if len(data) > max_total_bytes - total:
            warnings.append(f"part {locator}: decoded byte limit reached")
            continue
        fd, stage = tempfile.mkstemp(prefix=".mime-stage-", dir=output_dir)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
            published = output_dir / f"{index:06d}-{uuid.uuid4().hex}"
            os.link(stage, published)
            total += len(data)
            records.append({"path": published, "index": index, "part_path": locator,
                            "filename": part.get_filename(),
                            "media_type": part.get_content_type(),
                            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
            if nested is not None:
                stack.append((nested, f"{locator}.0", depth + 1))
        finally:
            os.unlink(stage)
    return records, warnings
