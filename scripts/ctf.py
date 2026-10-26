#!/usr/bin/env python3
"""Bounded, offline conveniences for approved CTF tool workflows (Linux CPython 3.10+)."""
import argparse
import hashlib
import io
import json
import os
import platform
import re
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

CHUNK = 65536
SOURCE_LIMIT = 256 * 1024 * 1024
KEY_LIMIT = 65536
PREVIEW = 64
TOOL_LIMIT = 1024 * 1024
TOOL_TIMEOUT = 10
DEADLINE = 30
ZIP_BYTES = 8 * 1024 * 1024
ZIP_MEMBERS = 10000
ZIP_ROWS = 100
ASCII_SPACE = b" \t\r\n\v\f"
ARCHIVE_ROUTE = "Use approved 7-Zip (kali-2): 7z l -- /absolute/path/to/archive. No members were extracted."
BYTE_ROUTE = "Use CyberChef (windows-1) or approved Python (windows-7) for the explicit byte operation."


class Problem(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


class WorkLimit(Problem):
    pass


class DeclaredZipLimit(WorkLimit):
    pass


class Budget:
    def __init__(self):
        self.end = time.monotonic() + DEADLINE
        self.read_bytes = 0

    def check(self):
        if time.monotonic() >= self.end:
            raise WorkLimit("30-second overall work deadline exceeded; no incomplete output was published.")

    def read(self, stream, size=CHUNK):
        self.check()
        data = stream.read(min(size, CHUNK, max(1, SOURCE_LIMIT - self.read_bytes + 1)))
        self.read_bytes += len(data)
        if self.read_bytes > SOURCE_LIMIT:
            raise WorkLimit("256 MiB source-byte limit exceeded; use the approved manual workflow.")
        return data

    def read_exact(self, stream, size):
        chunks = []
        while size:
            data = self.read(stream, size)
            if not data:
                break
            chunks.append(data)
            size -= len(data)
        return b"".join(chunks)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_input(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except (FileNotFoundError, NotADirectoryError):
        raise Problem("Input does not exist or is not a regular file.", 2)
    except OSError:
        raise Problem("Cannot open input; check its permissions and availability.")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Problem("Input must be a regular local file; directories/devices/pipes are not accepted.", 2)
        return os.fdopen(fd, "rb"), info
    except BaseException:
        os.close(fd)
        raise


def unchanged(stream, path, original):
    try:
        if identity(os.fstat(stream.fileno())) != identity(original) or identity(os.stat(path)) != identity(original):
            raise Problem("Input changed during the operation; the result was not committed.")
    except OSError:
        raise Problem("Input became unavailable during the operation; the result was not committed.")


class Output:
    """A private sibling file is linked into place only after full validation."""
    def __init__(self, path, source=None):
        if path == "":
            raise Problem("Output path must not be empty.", 2)
        self.path = os.path.abspath(path) if path is not None else None
        self.stage = None
        self.stream = None
        self.count = 0
        self.preview = bytearray()
        if self.path:
            if os.path.lexists(self.path):
                raise Problem("Output already exists (including aliases or symlinks); choose a new destination.", 2)
            if source and os.path.realpath(self.path) == os.path.realpath(source):
                raise Problem("Output must not alias the input.", 2)
            fd = None
            try:
                fd, self.stage = tempfile.mkstemp(prefix=".ctf-", dir=os.path.dirname(self.path))
                self.stream = os.fdopen(fd, "wb")
            except BaseException as error:
                if fd is not None:
                    os.close(fd)
                if self.stage:
                    os.unlink(self.stage)
                if isinstance(error, OSError):
                    raise Problem("Cannot create private output staging file; check destination directory permissions.") from None
                raise

    def write(self, data):
        self.count += len(data)
        self.preview.extend(data[:max(0, PREVIEW - len(self.preview))])
        if self.stream:
            self.stream.write(data)

    def publish(self, validate=None):
        if self.stream:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()
            self.stream = None
            if validate:
                validate()
            try:
                os.link(self.stage, self.path)
            except FileExistsError:
                raise Problem("Output appeared during processing; existing destination was preserved.", 2)
            except OSError:
                raise Problem("Could not publish output without overwriting; no destination was replaced.")

    def close(self):
        if self.stream:
            self.stream.close()
        if self.stage:
            try:
                os.unlink(self.stage)
            except FileNotFoundError:
                pass

    def facts(self):
        return {"output_bytes": self.count, "output_length": "fully validated",
                "preview_hex": bytes(self.preview).hex(), "preview_bytes": len(self.preview),
                "preview_truncated": self.count > PREVIEW, "saved": bool(self.path),
                "source": "whole selected input transform"}


def run_tool(argv, budget, data=None):
    """Drain both pipes while running; never accumulate unlimited tool output."""
    budget.check()
    end = min(budget.end, time.monotonic() + TOOL_TIMEOUT)
    collected = {"stdout": bytearray(), "stderr": bytearray()}
    with tempfile.TemporaryFile() as incoming:
        if data is not None:
            incoming.write(data)
            incoming.seek(0)
        try:
            process = subprocess.Popen(argv, stdin=incoming, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
        except FileNotFoundError:
            raise Problem("Required executable is missing.", 3)
        except OSError:
            raise Problem("Required executable could not be started.")
        try:
            with selectors.DefaultSelector() as selector:
                for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                total = 0
                while selector.get_map() or process.poll() is None:
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise WorkLimit("Tool timeout (10 seconds maximum), or overall command deadline, exceeded. stderr: " + stderr_excerpt(collected["stderr"]))
                    for key, _ in selector.select(min(remaining, 0.1)):
                        block = os.read(key.fileobj.fileno(), CHUNK)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(block)
                        if total > TOOL_LIMIT:
                            raise WorkLimit("Tool output truncated at the 1 MiB capture limit; check did not complete. stderr: " + stderr_excerpt(collected["stderr"]))
                        collected[key.data].extend(block)
                return process.returncode, bytes(collected["stdout"]), bytes(collected["stderr"])
        finally:
            import signal
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()


def stderr_excerpt(data):
    # Tool stderr can contain private paths or environment values: retain only bounded generic diagnostics.
    text = data[:4096].decode("utf-8", "replace")
    for key, value in os.environ.items():
        if value and len(value) >= 4 and any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL", "HOME", "USER")):
            text = text.replace(value, "[redacted]")
    text = re.sub(r"(?i)(token|password|secret|api[_-]?key)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    return "".join(char if char.isprintable() or char in "\n\t" else "?" for char in text[:512])


def checked_tool(argv, budget, data=None):
    code, out, err = run_tool(argv, budget, data)
    if code:
        text = err.decode("utf-8", "replace").lower()
        unsupported = any(term in text for term in ("unknown option", "unrecognized option", "invalid option", "not supported", "unknown argument"))
        raise Problem("Tool invocation unsupported." if unsupported else "Tool invocation failed; stderr: " + stderr_excerpt(err), 3 if unsupported else 1)
    return out


def file_classification(prefix, budget):
    executable = shutil.which("file")
    if not executable:
        raise Problem("file (kali-42) is missing; classification is unknown.", 3)
    output = checked_tool([executable, "--brief", "--mime-type", "-P", "bytes=65536", "-"], budget, prefix)
    mime = output.decode("ascii", "replace").strip()
    if not re.fullmatch(r"[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+", mime):
        raise Problem("file did not return the required MIME classification capability.", 3)
    return mime


IMAGE_ARGS = ["-j", "-n", "-FileType", "-ImageWidth", "-ImageHeight", "-GPSLatitude", "-GPSLongitude", "-GPSAltitude", "-Orientation"]


def image_metadata(path, budget):
    executable = shutil.which("exiftool")
    if not executable:
        raise Problem("ExifTool (windows-14) is missing; selected image metadata was not checked.", 3)
    raw = checked_tool([executable] + IMAGE_ARGS + ["--", os.path.abspath(path)], budget)
    try:
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError()
        metadata = rows[0]
    except (ValueError, UnicodeDecodeError):
        raise Problem("ExifTool did not provide its required JSON metadata capability.", 3)
    if "Error" in metadata:
        raise Problem("ExifTool could not read image metadata.")
    if metadata.get("FileType") not in ("JPEG", "PNG"):
        raise Problem("ExifTool did not return the required JPEG/PNG metadata capability.", 3)
    tags = {key: metadata[key] for key in ("FileType", "ImageWidth", "ImageHeight", "GPSLatitude", "GPSLongitude", "GPSAltitude", "Orientation") if key in metadata}
    return {"tags": tags, "gps_present": any(key.startswith("GPS") for key in tags),
            "source": "ExifTool selected tags", "coverage": "selected metadata only; absent GPS is not absence of all metadata"}


def png_probe():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\0\0\0\0")) + chunk(b"IEND", b"")


def add_issue(result, problem):
    result["notices"].append(str(problem))
    result["_codes"].append(problem.code)


def finalize_partial(result):
    codes = result.pop("_codes", [])
    if codes:
        result["status"] = "partial"
        return 1 if 1 in codes else 3
    return 0


def zip_metadata(stream, size, prefix, budget):
    tail_size = min(size, 65557)
    stream.seek(size - tail_size)
    tail = budget.read_exact(stream, tail_size)
    budget.check()
    candidates = []
    position = tail.find(b"PK\x05\x06")
    while position != -1:
        if position + 22 <= len(tail):
            fields = struct.unpack_from("<4s4H2IH", tail, position)
            if position + 22 + fields[-1] == len(tail):
                candidates.append((position, fields))
        position = tail.find(b"PK\x05\x06", position + 1)
    if not candidates:
        raise Problem("Malformed ZIP: no complete end-of-directory record reaches EOF.", 2)
    first_error = None
    for position, fields in candidates:
        try:
            # A signature inside member data is not an EOCD until its directory validates.
            return zip_directory(stream, size, prefix, budget, size - tail_size + position, fields)
        except Problem as problem:
            if isinstance(problem, WorkLimit) and not isinstance(problem, DeclaredZipLimit):
                raise
            if first_error is None:
                first_error = problem
    raise first_error


def zip_directory(stream, size, prefix, budget, end_offset, fields):
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, _ = fields
    if disk or cd_disk or disk_count == 0xffff or count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise Problem("ZIP64 or multidisk ZIP is unsupported; directory was not inspected. " + ARCHIVE_ROUTE, 3)
    if disk_count != count:
        raise Problem("Malformed ZIP: inconsistent entry counts.", 2)
    if end_offset >= 20:
        stream.seek(end_offset - 20)
        if budget.read(stream, 4) == b"PK\x06\x07":
            raise Problem("ZIP64 locator is unsupported. " + ARCHIVE_ROUTE, 3)
    if not prefix.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        raise Problem("Prepended/SFX ZIP is unsupported; directory was not inspected. " + ARCHIVE_ROUTE, 3)
    if cd_offset + cd_size > end_offset or cd_offset > size:
        raise Problem("Malformed ZIP: central directory falls outside its file bounds.", 2)
    if cd_offset + cd_size != end_offset:
        raise Problem("Unrecognized ZIP directory layout is unsupported. " + ARCHIVE_ROUTE, 3)
    if cd_size > ZIP_BYTES or count > ZIP_MEMBERS:
        # Candidate claims are untrusted; only actual read/deadline exhaustion stops candidate search.
        raise DeclaredZipLimit("ZIP metadata/member budget exceeded (8 MiB / 10,000 members); directory was not inspected.")
    stream.seek(cd_offset)
    directory = budget.read_exact(stream, cd_size)
    if len(directory) != cd_size:
        raise Problem("Malformed ZIP: truncated central directory.", 2)
    offset = 0
    actual = 0
    while offset < len(directory):
        budget.check()
        if len(directory) - offset < 4:
            raise Problem("Malformed ZIP: truncated directory signature.", 2)
        if directory[offset:offset + 4] != b"PK\x01\x02":
            raise Problem("Unrecognized ZIP directory record is unsupported. " + ARCHIVE_ROUTE, 3)
        if len(directory) - offset < 46:
            raise Problem("Malformed ZIP: truncated ordinary directory record.", 2)
        name_len, extra_len, comment_len, start_disk = struct.unpack_from("<4H", directory, offset + 28)
        compressed, expanded = struct.unpack_from("<II", directory, offset + 20)
        local_offset = struct.unpack_from("<I", directory, offset + 42)[0]
        if start_disk or compressed == 0xffffffff or expanded == 0xffffffff or local_offset == 0xffffffff:
            raise Problem("ZIP64/multidisk entry is unsupported. " + ARCHIVE_ROUTE, 3)
        if local_offset + 30 > cd_offset or compressed > cd_offset - local_offset - 30:
            raise Problem("Malformed ZIP: member local header/data falls outside the pre-directory bounds.", 2)
        next_offset = offset + 46 + name_len + extra_len + comment_len
        if next_offset > len(directory):
            raise Problem("Malformed ZIP: truncated entry name/extra/comment.", 2)
        extra = directory[offset + 46 + name_len:offset + 46 + name_len + extra_len]
        extra_pos = 0
        while extra_pos < len(extra):
            if extra_pos + 4 > len(extra):
                raise Problem("Malformed ZIP: truncated extra field.", 2)
            tag, length = struct.unpack_from("<HH", extra, extra_pos)
            extra_pos += 4 + length
            if extra_pos > len(extra):
                raise Problem("Malformed ZIP: extra field exceeds record.", 2)
            if tag == 1:
                raise Problem("ZIP64 entry is unsupported. " + ARCHIVE_ROUTE, 3)
        actual += 1
        if actual > ZIP_MEMBERS:
            raise WorkLimit("ZIP member budget exceeded (10,000 members).")
        offset = next_offset
    if actual != count:
        raise Problem("Malformed ZIP: declared member count differs from actual directory records.", 2)
    # Give zipfile only verified, bounded metadata, and an unambiguous synthetic EOCD.
    eocd = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, count, count, cd_size, 0, 0)
    try:
        with zipfile.ZipFile(io.BytesIO(directory + eocd)) as archive:
            entries = archive.infolist()
    except (zipfile.BadZipFile, ValueError, UnicodeError, NotImplementedError):
        raise Problem("Malformed ZIP central-directory metadata.", 2)
    budget.check()
    return {"source": "validated classic ZIP central directory", "coverage": "all directory metadata; member contents not read or extracted",
            "member_count": count, "encrypted_members": sum(bool(entry.flag_bits & 1) for entry in entries),
            "expanded_bytes": sum(entry.file_size for entry in entries),
            "compressed_bytes": sum(entry.compress_size for entry in entries),
            "rows": [{"name": entry.filename, "bytes": entry.file_size, "compressed_bytes": entry.compress_size,
                      "encrypted": bool(entry.flag_bits & 1)} for entry in entries[:ZIP_ROWS]],
            "rows_truncated": count > ZIP_ROWS}


def inspect_file(args, result, budget):
    stream, original = open_input(args.file)
    with stream:
        prefix = budget.read(stream)
        result["facts"]["input"] = {"size_bytes": original.st_size, "source": "regular-file stat"}
        result["scope"].append("Classification covers at most the first 64 KiB; inspection never extracts or executes content.")
        result["facts"]["classification"] = {"value": "unknown", "source": "file", "covered_bytes": len(prefix)}
        mime = "unknown"
        try:
            mime = file_classification(prefix, budget)
            result["facts"]["classification"]["value"] = mime
        except Problem as problem:
            add_issue(result, problem)
            if isinstance(problem, WorkLimit):
                return finalize_partial(result)
        if prefix.lstrip().startswith((b"<?php", b"<?=")) or mime in ("text/x-php", "application/x-php"):
            markers = [{"name": match[1].decode("ascii"), "offset": match.start(1)}
                       for match in re.finditer(rb"\b(eval|hex2bin|base64_decode|gzinflate|gzuncompress|str_rot13|unserialize)\s*\(", prefix)]
            result["facts"]["php_markers"] = {"source": "lexical byte matches, not evaluated code",
                "covered_bytes": len(prefix), "matches": markers[:20], "truncated": len(markers) > 20}
            result["next_actions"].append("Inspect PHP literals and decode only evidenced transforms into new files with per-layer size limits; do not eval the source or unserialize objects. Markers can also occur in comments or strings.")
        is_zip = prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or mime in ("application/zip", "application/x-zip")
        if not is_zip:
            stream.seek(max(0, original.st_size - 65557))
            tail = budget.read_exact(stream, 65557)
            position = tail.find(b"PK\x05\x06")
            while position != -1:
                if position + 22 <= len(tail) and position + 22 + struct.unpack_from("<H", tail, position + 20)[0] == len(tail):
                    is_zip = True
                    break
                position = tail.find(b"PK\x05\x06", position + 1)
        if is_zip:
            try:
                result["facts"]["zip"] = zip_metadata(stream, original.st_size, prefix, budget)
                if result["facts"]["zip"]["rows_truncated"]:
                    result["notices"].append("Archive display truncated to 100 rows; all directory metadata was checked.")
            except Problem as problem:
                if problem.code == 2:
                    raise
                add_issue(result, problem)
                if isinstance(problem, WorkLimit):
                    result["next_actions"].append(ARCHIVE_ROUTE)
                    return finalize_partial(result)
            result["next_actions"].append(ARCHIVE_ROUTE)
        is_image = prefix.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n")) or mime in ("image/jpeg", "image/png")
        if is_image:
            try:
                if original.st_size > SOURCE_LIMIT:
                    raise WorkLimit("Image exceeds the 256 MiB source limit; selected metadata was not read.")
                result["facts"]["image"] = image_metadata(args.file, budget)
            except Problem as problem:
                add_issue(result, problem)
                if isinstance(problem, WorkLimit):
                    return finalize_partial(result)
            result["next_actions"].append("Use approved ExifTool (windows-14) to review further tags; selected GPS absence does not rule out other metadata.")
        if not is_zip and not is_image:
            result["scope"].append("Format-specific content was not examined; use the matching approved-tool guide route.")
            if mime in ("application/vnd.microsoft.portable-executable", "application/x-dosexec",
                        "application/x-executable", "application/x-pie-executable", "application/x-sharedlib"):
                result["next_actions"].append("Inspect executable headers, sections, imports and strings with approved Detect It Easy or Ghidra; test a packer only when evidence supports it. Do not execute a file to identify it.")
            if mime in ("application/x-tar", "application/x-7z-compressed", "application/vnd.rar",
                        "application/x-rar", "application/x-rar-compressed", "application/gzip",
                        "application/x-gzip", "application/x-bzip2", "application/x-xz",
                        "application/x-lzma", "application/x-lzip", "application/x-compress",
                        "application/zstd", "application/x-cpio", "application/x-archive", "application/x-lz4"):
                result["scope"].append("Recognized archive/compression format; its structure was not inspected.")
                result["next_actions"].append(ARCHIVE_ROUTE)
        if args.sha256:
            try:
                if original.st_size > SOURCE_LIMIT:
                    raise WorkLimit("Full SHA-256 exceeds the 256 MiB source-byte limit; no file digest was computed.")
                stream.seek(len(prefix))
                digest = hashlib.sha256(prefix)
                while True:
                    chunk = budget.read(stream)
                    if not chunk:
                        break
                    digest.update(chunk)
                result["facts"]["sha256"] = {"value": digest.hexdigest(), "source": "whole-file read"}
            except Problem as problem:
                add_issue(result, problem)
        try:
            budget.check()
            unchanged(stream, args.file, original)
        except Problem as problem:
            result["facts"].pop("sha256", None)
            add_issue(result, problem)
    return finalize_partial(result)


def parse_lines(value):
    if value is None:
        return None
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", value)
    if not match:
        raise Problem("--lines must be a one-based inclusive START:END range.", 2)
    try:
        start, end = map(int, match.groups())
    except ValueError:
        raise Problem("Selected line numbers are too large.", 2)
    if start > end:
        raise Problem("--lines START must not exceed END.", 2)
    return start, end


def bits(args, result, budget):
    selection = parse_lines(args.lines)
    if args.text is not None:
        try:
            raw = args.text.encode("ascii")
        except UnicodeEncodeError:
            raise Problem("Bit text must contain only binary digits and ASCII whitespace.", 2)
        stream, original = io.BytesIO(raw), None
    else:
        stream, original = open_input(args.file)
    output = None
    try:
        if original and original.st_size > SOURCE_LIMIT:
            raise WorkLimit("256 MiB source-byte limit exceeded; use the approved manual workflow.")
        output = Output(args.out, args.file)
        line, column, source_offset, bit_count, group_bits, value = 1, 0, 0, 0, 0, 0
        last_line = 0
        while True:
            chunk = budget.read(stream)
            if not chunk:
                break
            decoded = bytearray()
            for byte in chunk:
                source_offset += 1
                column += 1
                last_line = line
                chosen = selection is None or selection[0] <= line <= selection[1]
                if chosen:
                    if byte in (48, 49):
                        bit = byte - 48
                        value = (value << 1) | bit if args.order == "msb" else value | (bit << group_bits)
                        group_bits += 1
                        bit_count += 1
                        if group_bits == args.width:
                            decoded.append(value)
                            group_bits, value = 0, 0
                    elif byte not in ASCII_SPACE:
                        raise Problem("Invalid bit-text byte at source byte {}, line {}, column {}; only 0, 1 and ASCII whitespace are allowed in selected lines.".format(source_offset, line, column), 2)
                if byte == 10:
                    line += 1
                    column = 0
            output.write(decoded)
        if selection and selection[1] > last_line:
            raise Problem("Selected line range extends beyond the input ({} lines).".format(last_line), 2)
        if not bit_count:
            raise Problem("Selected input contains no binary digits.", 2)
        if group_bits:
            raise Problem("Incomplete group: {} remainder bits for width {}; no padding or truncation was applied.".format(group_bits, args.width), 2)
        def validate():
            budget.check()
            if original:
                unchanged(stream, args.file, original)
        validate()
        output.publish(validate)
        result["facts"]["transform"] = output.facts()
        result["facts"]["transform"].update({"selected_bits": bit_count, "groups": output.count,
                                                   "selected_lines": list(selection) if selection else "all"})
        result["scope"].append("All selected bit text validated; selected rows concatenated; bit order applies within each group; widths below 8 are zero-extended.")
        if output.count > PREVIEW:
            result["notices"].append("Rendered preview truncated to 64 bytes; the entire selected input was validated.")
        return 0
    finally:
        stream.close()
        if output:
            output.close()


def parse_key(value):
    digits = bytearray()
    for char in value:
        if char in " \t\r\n\v\f":
            continue
        if char not in "0123456789abcdefABCDEF":
            raise Problem("Hex key contains a nonhex character; only ASCII whitespace is ignored.", 2)
        digits.append(ord(char))
        if len(digits) > KEY_LIMIT * 2:
            raise Problem("Decoded XOR key exceeds the 64 KiB limit.", 2)
    if not digits or len(digits) % 2:
        raise Problem("Hex key must contain a nonempty even number of hex digits.", 2)
    return bytes.fromhex(digits.decode("ascii"))


def xor(args, result, budget):
    key = parse_key(args.key_hex)
    result["parameters"]["key_bytes"] = len(key)
    stream, original = open_input(args.file)
    output = None
    try:
        if original.st_size > SOURCE_LIMIT:
            raise WorkLimit("256 MiB source-byte limit exceeded; use the approved manual workflow.")
        output = Output(args.out, args.file)
        offset = 0
        while True:
            chunk = budget.read(stream)
            if not chunk:
                break
            transformed = bytes(byte ^ key[(offset + index) % len(key)] for index, byte in enumerate(chunk))
            output.write(transformed)
            offset += len(chunk)
        def validate():
            budget.check()
            unchanged(stream, args.file, original)
        validate()
        output.publish(validate)
        result["facts"]["transform"] = output.facts()
        result["scope"].append("Whole-file bytes XORed unchanged in length; key cycles from offset zero. Key contents are omitted from reports.")
        if not output.count:
            result["notices"].append("Input is empty; the complete result is empty.")
        elif output.count > PREVIEW:
            result["notices"].append("Rendered preview truncated to 64 bytes; the entire file was transformed.")
        return 0
    finally:
        stream.close()
        if output:
            output.close()


def doctor(args, result, budget):
    result["facts"]["runtime"] = {"implementation": platform.python_implementation(), "python": platform.python_version(),
                                   "platform": sys.platform, "eligible": True, "source": "running interpreter"}
    result["scope"].append("Readiness for the selected workflow only; no installation, network access, or all-tool scan.")
    if args.workflow == "bytes":
        result["facts"]["usable_branches"] = ["bits", "xor"]
        return finalize_partial(result)
    tools = {}
    for name in ("file", "exiftool"):
        executable = shutil.which(name)
        probe = {"present": bool(executable), "version_query": False, "needed_feature": False}
        tools[name] = probe
        try:
            budget.check()
            if not executable:
                raise Problem(name + " executable is missing.", 3)
            version = checked_tool([executable, "--version" if name == "file" else "-ver"], budget)
            if not version.strip():
                raise Problem(name + " safe version query is unsupported.", 3)
            probe["version_query"] = True
            if name == "file":
                mime = file_classification(b"toolkit readiness probe\n", budget)
                if mime != "text/plain":
                    raise Problem("file could not classify the known plain-text probe.", 3)
            else:
                with tempfile.TemporaryDirectory(prefix="ctf-probe-") as directory:
                    path = os.path.join(directory, "probe.png")
                    with open(path, "wb") as output:
                        output.write(png_probe())
                    metadata = image_metadata(path, budget)
                    if metadata["tags"].get("ImageWidth") != 1 or metadata["tags"].get("ImageHeight") != 1:
                        raise Problem("ExifTool lacks required selected-image-tag capability.", 3)
            probe["needed_feature"] = True
        except Problem as problem:
            probe["status"] = "unsupported" if problem.code == 3 else "failed"
            add_issue(result, problem)
            if isinstance(problem, WorkLimit):
                for pending in ("file", "exiftool"):
                    tools.setdefault(pending, {"present": bool(shutil.which(pending)), "version_query": False,
                                               "needed_feature": False, "status": "not_checked"})
                break
        else:
            probe["status"] = "complete"
    result["facts"]["tools"] = tools
    branches = ["basic stat/prefix", "classic ZIP directory"]
    if tools["file"]["needed_feature"]:
        branches.append("file classification")
    if tools["exiftool"]["needed_feature"]:
        branches.append("selected JPEG/PNG metadata")
    result["facts"]["usable_branches"] = branches
    result["next_actions"] = ["Use file (kali-42) and ExifTool (windows-14) in their approved environments when local capabilities are unavailable.", ARCHIVE_ROUTE]
    return finalize_partial(result)


def parser():
    cli = argparse.ArgumentParser(description=__doc__, epilog="Linux/WSL paths follow the interpreter: /mnt/c/input.bin. Native Windows is unsupported. Use --file=-name for dash-leading paths; no implicit stdin. Example: python scripts/ctf.py bits --text '01000001' --json")
    cli.add_argument("--json", action="store_true", help="emit one structured JSON result")
    commands = cli.add_subparsers(dest="operation", required=True)
    for name, description in (("bits", "Convert explicit binary text (CyberChef From Binary / approved Python)."),
                              ("xor", "Repeat known-key file XOR (CyberChef XOR / approved Python)."),
                              ("inspect", "Bounded file evidence (file / ExifTool / 7-Zip)."),
                              ("doctor", "Probe bytes or inspect readiness without installing tools.")):
        sub = commands.add_parser(name, description=description, help=description)
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="emit one structured JSON result")
        if name == "doctor":
            sub.add_argument("--workflow", choices=("bytes", "inspect"), required=True)
        elif name == "bits":
            source = sub.add_mutually_exclusive_group(required=True)
            source.add_argument("--file", help="regular local bit-text file; use --file=PATH for dash-leading paths")
            source.add_argument("--text", help="short synthetic binary text (ASCII whitespace allowed)")
            sub.add_argument("--lines", metavar="START:END", help="one-based inclusive payload lines; headers require explicit selection")
            sub.add_argument("--width", type=int, choices=range(1, 9), default=8)
            sub.add_argument("--order", choices=("msb", "lsb"), default="msb", help="significance within each group")
            sub.add_argument("--out", help="new destination; omitted means a bounded hex preview")
        else:
            sub.add_argument("--file", required=True, help="regular local file; use --file=PATH for dash-leading paths")
            if name == "xor":
                sub.add_argument("--key-hex", required=True, help="nonempty hex bytes; ASCII whitespace allowed; never recorded in results")
                sub.add_argument("--out", help="new destination; existing files/symlinks are refused")
            else:
                sub.add_argument("--sha256", action="store_true", help="opt in to a bounded full-file SHA-256 read")
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    parameters = {key: value for key, value in vars(args).items() if key not in ("json", "operation", "key_hex", "text") and value is not None}
    if getattr(args, "text", None) is not None:
        parameters["input"] = "explicit text"
    result = {"operation": args.operation, "status": "complete", "parameters": parameters,
              "facts": {}, "scope": [], "notices": [], "next_actions": [], "_codes": []}
    budget = Budget()
    try:
        if sys.version_info < (3, 10) or sys.platform != "linux" or platform.python_implementation() != "CPython":
            raise Problem("Unsupported runtime: use CPython 3.10+ on Linux/WSL. From Windows, launch WSL Python with /mnt/c/... paths.", 3)
        code = {"bits": bits, "xor": xor, "inspect": inspect_file, "doctor": doctor}[args.operation](args, result, budget)
    except Problem as problem:
        code = problem.code
        result["status"] = {1: "failed", 2: "invalid_input", 3: "unsupported"}[code]
        result["notices"].append(str(problem))
        if args.operation == "inspect" and result["facts"].get("input") and code != 2:
            result["status"] = "partial"
            if 1 in result["_codes"]:
                code = 1
        if args.operation in ("bits", "xor"):
            result["next_actions"] = [BYTE_ROUTE]
    except (OSError, ValueError, OverflowError) as error:
        code = 1
        result["status"] = "partial" if args.operation == "inspect" and result["facts"].get("input") else "failed"
        result["notices"].append("Operation failed ({0}); check local file permissions/availability and arguments. No incomplete output was published.".format(type(error).__name__))
    except KeyboardInterrupt:
        code = 130
        result["status"] = "failed"
        result["notices"].append("Interrupted; no incomplete output was published.")
    result.pop("_codes", None)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    else:
        print("{}: {}".format(result["operation"], result["status"]))
        print("Parameters: " + json.dumps(result["parameters"], ensure_ascii=True, sort_keys=True))
        for name, fact in result["facts"].items():
            print(name + ": " + json.dumps(fact, ensure_ascii=True, sort_keys=True))
        for scope in result["scope"]:
            print("Scope: " + scope)
        for notice in result["notices"]:
            print("Notice: " + notice, file=sys.stderr)
        for action in result["next_actions"][:2]:
            print("Next: " + action)
    return code


if __name__ == "__main__":
    sys.exit(main())
