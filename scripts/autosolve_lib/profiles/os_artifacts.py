"""Bounded, read-only browser, registry and Windows event-log records."""

import base64
import hashlib
import io
import os
import sqlite3
import stat
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path


_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FIREFOX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _browser(path, descriptor, max_records):
    records, warnings = [], []
    # Immutable mode prevents SQLite from creating a lock or SHM beside evidence.
    with sqlite3.connect(f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        names = {name for (name,) in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        if {'urls', 'visits'} <= names:
            browser, places, visits, link, time_column = ('Chromium', 'urls', 'visits',
                                                          'url', 'visit_time')
            epoch = _CHROME_EPOCH
        elif {'moz_places', 'moz_historyvisits'} <= names:
            browser, places, visits, link, time_column = ('Firefox', 'moz_places',
                                                          'moz_historyvisits', 'place_id', 'visit_date')
            epoch = _FIREFOX_EPOCH
        elif names & {'moz_places', 'moz_historyvisits'}:
            return [], ["unsupported Firefox History schema: moz_places/moz_historyvisits table absent"]
        else:
            return [], ["unsupported SQLite OS artifact: Chromium urls/visits tables absent"]
        columns = {name: {row[1] for row in db.execute(f"PRAGMA table_info({name})")}
                   for name in (places, visits)}
        if not {'id', 'url'} <= columns[places] or not {'id', link, time_column} <= columns[visits]:
            return [], [f"unsupported {browser} History schema: required columns absent"]
        title = 'u.title' if 'title' in columns[places] else 'NULL'
        cursor = db.execute(
            f"SELECT v.id, v.{link}, v.{time_column}, u.url, {title} "
            f"FROM {visits} v LEFT JOIN {places} u ON v.{link}=u.id ORDER BY v.id LIMIT ?",
            (max_records + 1,))
        for row in cursor:
            if len(records) == max_records:
                warnings.append("browser visit record limit reached")
                break
            visit_id, url_id, raw_time, url, page_title = row
            when = None
            if isinstance(raw_time, int):
                try:
                    when = _utc(epoch + timedelta(microseconds=raw_time))
                except (OverflowError, ValueError):
                    pass
            if when is None:
                warnings.append(f"{visits} id {visit_id}: unsupported {time_column}")
            url_truncated = isinstance(url, str) and len(url) > 2048
            if url_truncated:
                warnings.append(f"{visits} id {visit_id}: browser URL truncated at 2048 characters")
            title_truncated = isinstance(page_title, str) and len(page_title) > 512
            if title_truncated:
                warnings.append(f"{visits} id {visit_id}: browser title truncated at 512 characters")
            records.append({"kind": "browser_visit", "source": str(path),
                            "locator": f"{visits} id {visit_id}", "visit_id": visit_id,
                            "url_id": url_id, "url": url[:2048] if isinstance(url, str) else None,
                            "url_truncated": url_truncated,
                            "title": page_title[:512] if isinstance(page_title, str) else None,
                            "title_truncated": title_truncated,
                            "timestamp": when,
                            "timestamp_basis": f"{browser} microseconds since {epoch.year} UTC"})
    if path.with_name(path.name + '-wal').exists():
        warnings.append("browser WAL not read; recent visits may be missing")
    return records, warnings


def _registry(data, path, max_records):
    try:
        from Registry import Registry
    except ImportError:
        return [], ["python-registry unavailable; Windows registry hive unsupported"]
    hive = Registry.Registry(io.BytesIO(data))
    records, warnings = [], []
    if len(data) >= 12 and data[4:8] != data[8:12]:
        warnings.append("registry hive sequence mismatch; transaction logs may contain unapplied records")
    pending = [hive.root()]
    while pending:
        key = pending.pop()
        if len(records) == max_records:
            warnings.append("registry key record limit reached")
            break
        key_path = key.path()
        values = []
        for item in key.values()[:32]:
            value = item.value()
            if isinstance(value, bytes):
                shown = {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                         "prefix_base64": base64.b64encode(value[:256]).decode('ascii'),
                         "truncated": len(value) > 256}
            elif isinstance(value, str):
                shown = value[:512]
            elif isinstance(value, (int, float, bool)) or value is None:
                shown = value
            elif isinstance(value, (list, tuple)):
                shown = [part[:512] if isinstance(part, str) else str(part)[:512]
                         for part in value[:16]]
            else:
                shown = str(value)[:512]
            values.append({"name": item.name(), "type": item.value_type_str(), "value": shown})
        if key.values_number() > len(values):
            warnings.append(f"{key_path}: registry value limit reached")
        records.append({"kind": "registry_key", "source": str(path),
                        "locator": key_path, "timestamp": _utc(key.timestamp()),
                        "timestamp_basis": "registry key last-write FILETIME UTC",
                        "values": values})
        pending.extend(reversed(key.subkeys()))
    return records, warnings


def _evtx_boundaries(source, size):
    if size < 4096:
        return ["EVTX truncated file header"]
    source.seek(0x2a)
    declared_chunks = int.from_bytes(source.read(2), 'little')
    full_chunks, partial = divmod(size - 4096, 65536)
    warnings = []
    if declared_chunks > full_chunks:
        warnings.append(f"EVTX truncated: {declared_chunks} declared chunks, {full_chunks} complete")
    if partial:
        chunk_start = 4096 + full_chunks * 65536
        source.seek(chunk_start)
        if source.read(8) == b'ElfChnk\x00':
            offset = 512
            while offset + 8 <= partial:
                source.seek(chunk_start + offset)
                record_header = source.read(8)
                if record_header[:4] != b'\x2a\x2a\x00\x00':
                    break
                length = int.from_bytes(record_header[4:8], 'little')
                if length < 24 or length > 65536 - offset:
                    warnings.append(f"EVTX corrupt record length at offset {chunk_start + offset}")
                    break
                if length > partial - offset:
                    warnings.append(f"EVTX truncated record at offset {chunk_start + offset}: "
                                    f"declared {length} bytes, {partial - offset} available")
                    break
                offset += length
        warnings.append(f"EVTX truncated chunk at offset {chunk_start}: {partial} of 65536 bytes")
    return warnings


def _evtx(path, max_records, boundary_warnings=()):
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return [], list(boundary_warnings) + ["python-evtx unavailable; EVTX records unsupported"]
    records, warnings = [], list(boundary_warnings)
    namespace = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    with Evtx(str(path)) as log:
        for entry in log.records():
            if len(records) == max_records:
                warnings.append("EVTX record limit reached")
                break
            root = ET.fromstring(entry.xml())
            system = root.find(namespace + 'System')
            event_id = system.findtext(namespace + 'EventID') if system is not None else None
            provider = system.find(namespace + 'Provider') if system is not None else None
            raw_id = system.findtext(namespace + 'EventRecordID') if system is not None else None
            event_record_id = (int(raw_id) if raw_id and len(raw_id) <= 20 and
                               raw_id.isascii() and raw_id.isdecimal() else None)
            raw_time = system.find(namespace + 'TimeCreated') if system is not None else None
            raw_time = raw_time.get('SystemTime') if raw_time is not None else None
            xml_time = None
            if raw_time:
                try:
                    if len(raw_time) > 80:
                        raise ValueError('oversized SystemTime')
                    parsed = datetime.fromisoformat(raw_time.replace('Z', '+00:00'))
                    if parsed.tzinfo is not None:
                        xml_time = _utc(parsed)
                except (ValueError, OverflowError):
                    pass
                if xml_time is None:
                    warnings.append(f"record {entry.record_num()}: invalid System TimeCreated")
            header_time = _utc(entry.timestamp())
            records.append({"kind": "evtx_event", "source": str(path),
                            "locator": f"record {entry.record_num()} offset {entry.offset()}",
                            "record_number": entry.record_num(), "offset": entry.offset(),
                            "record_number_basis": "EVTX record header",
                            "event_record_id": event_record_id,
                            "event_id": event_id,
                            "provider": provider.get('Name') if provider is not None else None,
                            "header_timestamp": header_time,
                            "header_timestamp_basis": "EVTX record FILETIME UTC",
                            "system_time_raw": raw_time[:80] if raw_time else None,
                            "xml_timestamp": xml_time,
                            "xml_timestamp_basis": ("Event.System.TimeCreated.SystemTime UTC" if xml_time else None),
                            "timestamp": header_time,
                            "timestamp_basis": "EVTX record FILETIME UTC"})
    return records, warnings


def inspect_os_artifact(path: Path, *, max_records: int = 100,
                        max_bytes: int = 64 * 1024 * 1024) -> tuple[list[dict], list[str]]:
    """Return source-linked records; unsupported/corrupt inputs are explicit warnings."""
    if not 0 < max_records <= 1000 or not 0 < max_bytes <= 64 * 1024 * 1024:
        raise ValueError("OS artifact limits must be positive and bounded")
    path = Path(path)
    boundary_warnings = []
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                return [], ["OS artifact input is not a regular file"]
            if info.st_size > max_bytes:
                return [], ["OS artifact input byte limit reached"]
            prefix = source.read(16)
            if prefix == b'SQLite format 3\x00':
                try:
                    return _browser(path, source.fileno(), max_records)
                except sqlite3.Error as error:
                    return [], [f"OS artifact parse failed: {type(error).__name__}: {error}"]
            if prefix.startswith(b'regf'):
                source.seek(0)
                data = source.read(max_bytes + 1)
                if len(data) > max_bytes:
                    return [], ["OS artifact input byte limit reached"]
            elif prefix.startswith(b'ElfFile\x00'):
                boundary_warnings = _evtx_boundaries(source, info.st_size)
    except OSError as error:
        return [], [f"OS artifact input unavailable: {type(error).__name__}"]
    try:
        if prefix.startswith(b'regf'):
            return _registry(data, path, max_records)
        if prefix.startswith(b'ElfFile\x00'):
            return _evtx(path, max_records, boundary_warnings)
    except (sqlite3.Error, ET.ParseError, ValueError, OSError) as error:
        return [], boundary_warnings + [f"OS artifact parse failed: {type(error).__name__}: {error}"]
    except Exception as error:
        # Optional parsers raise their own format exceptions on corrupt evidence.
        return [], boundary_warnings + [f"OS artifact parse failed: {type(error).__name__}: {error}"]
    return [], ["unsupported OS artifact format"]
