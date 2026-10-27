"""Extract bounded PDF evidence without rendering or executing document actions."""

import hashlib
import os
import tempfile
import uuid
from pathlib import Path


MAX_ATTACHMENTS = 512
MAX_OBJECTS = 4096


def extract_pdf(path: Path, output_dir: Path, *, max_pages: int,
                max_total_bytes: int, passwords: tuple[bytes, ...] | list[bytes] = ()) -> tuple[list[dict], list[str]]:
    """Stage page text, attachments, and decoded nonimage streams with PDF locators."""
    if max_pages < 0 or max_total_bytes < 0:
        raise ValueError("PDF limits must be nonnegative")
    if len(passwords) > 8 or any(not isinstance(value, bytes) or len(value) > 128
                                  for value in passwords):
        raise ValueError("PDF permits at most eight passwords of 128 bytes")
    if output_dir.is_symlink():
        raise ValueError("PDF output directory must not be a symlink")
    if output_dir.resolve() == path.resolve().parent:
        raise ValueError("PDF output directory must differ from source directory")
    try:
        from pypdf import PdfReader
        from pypdf.generic import IndirectObject, StreamObject
    except ImportError:
        return [], ["PDF parser unavailable: pypdf is not installed"]

    records: list[dict] = []
    warnings: list[str] = []
    total = 0

    def stage(data: bytes, kind: str, locator: str, **details) -> None:
        nonlocal total
        if len(data) > max_total_bytes - total:
            warnings.append(f"{locator}: decoded byte limit reached")
            return
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".pdf-stage-", dir=output_dir)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
            published = output_dir / f"{len(records):06d}-{uuid.uuid4().hex}"
            os.link(temporary, published)
            records.append({"path": published, "kind": kind, "locator": locator,
                            "media_type": ("text/plain; charset=utf-8" if kind == "text"
                                           else "application/octet-stream"),
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "size": len(data), **details})
            total += len(data)
        finally:
            os.unlink(temporary)

    try:
        with path.open("rb") as source:
            reader = PdfReader(source, strict=False)
            if reader.is_encrypted:
                if not passwords:
                    return [], ["encrypted PDF: password required"]
                try:
                    unlocked = any(reader.decrypt(password) for password in passwords)
                except Exception as error:
                    return [], [f"encrypted PDF: decryption failed ({type(error).__name__})"]
                if not unlocked:
                    return [], ["encrypted PDF: supplied passwords did not validate"]

            page_count = len(reader.pages)
            if page_count > max_pages:
                warnings.append(f"page {max_pages + 1}: page limit reached")
            for index in range(min(page_count, max_pages)):
                locator = f"page {index + 1}"
                try:
                    page = reader.pages[index]
                    reference = page.indirect_reference
                    if reference is not None:
                        locator += f" object {reference.idnum} {reference.generation}"
                    contents = page.get_contents()
                    if contents is not None and len(contents.get_data()) > max_total_bytes:
                        warnings.append(f"{locator}: decoded page stream limit reached")
                        continue
                    value = page.extract_text() or ""
                    if value.strip():
                        stage(value.encode("utf-8"), "text", locator,
                              page=index + 1,
                              object_id=reference.idnum if reference is not None else None)
                    else:
                        warnings.append(f"{locator}: no extractable text (empty or scanned page)")
                except Exception as error:
                    warnings.append(f"{locator}: text extraction failed: {type(error).__name__}")

            for index, attachment in enumerate(reader.attachment_list):
                if index >= MAX_ATTACHMENTS:
                    warnings.append(f"attachment {index}: attachment limit reached")
                    break
                locator = f"attachment {index}"
                try:
                    stream = attachment._embedded_file
                    reference = stream.indirect_reference
                    if reference is not None:
                        locator += f" object {reference.idnum} {reference.generation}"
                    stage(attachment.content, "attachment", locator,
                          index=index, name=attachment.name,
                          object_id=reference.idnum if reference is not None else None)
                except Exception as error:
                    warnings.append(f"{locator}: attachment extraction failed: {type(error).__name__}")

            inspected = 0
            for generation, offsets in sorted(reader.xref.items()):
                for object_id in sorted(offsets):
                    if object_id == 0:
                        continue
                    if inspected >= MAX_OBJECTS:
                        warnings.append(f"object {object_id} {generation}: object limit reached")
                        return records, warnings
                    inspected += 1
                    locator = f"object {object_id} {generation}"
                    try:
                        obj = reader.get_object(IndirectObject(object_id, generation, reader))
                        if (not isinstance(obj, StreamObject) or
                                obj.get("/Type") == "/EmbeddedFile" or
                                obj.get("/Subtype") == "/Image"):
                            continue
                        data = obj.get_data()
                        if data:
                            stage(data, "stream", locator,
                                  object_id=object_id, generation=generation)
                    except Exception as error:
                        warnings.append(f"{locator}: stream extraction failed: {type(error).__name__}")
    except Exception as error:
        warnings.append(f"PDF parse failed: {type(error).__name__}")
    return records, warnings
