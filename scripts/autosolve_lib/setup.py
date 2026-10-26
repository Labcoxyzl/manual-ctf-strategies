"""Read-only capability discovery for the autosolve command."""

import base64
import hashlib
import importlib
import importlib.metadata
import importlib.util
from email.message import EmailMessage
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import zipfile
import zlib


PROFILE_ENGINES = {
    "encoding": ("crypto-attacks", "cryptolib", "passwords", "refinery", "rsa", "stdlib", "xortool"),
    "images": ("archive", "binwalk", "exif", "ghidra", "image", "stegseek", "zsteg"),
    "documents": ("archive", "binwalk", "bkcrack", "office", "passwords", "pdf", "refinery", "stdlib"),
    "audio_video": ("ffmpeg", "image", "multimon", "sstv", "stegolsb"),
    "packets": ("archive", "hcxtools", "passwords", "scapy", "stdlib", "tshark", "zeek"),
    "disk_memory": ("binwalk", "dissect", "stdlib", "tsk", "volatility"),
    "malware_reversing": ("angr", "binwalk", "capa", "file", "floss", "ghidra", "jadx", "pwntools", "pyinstaller", "refinery", "stdlib", "upx", "yara"),
    "pwn_services": ("ghidra", "nmap", "pwntools", "ropgadget"),
    "web": ("arjun", "ffuf", "http", "jwt", "sqlmap", "stdlib"),
    "osint": ("exif", "http", "image", "pywhat", "stdlib"),
    "can_misc": ("can", "image", "pwntools", "scapy", "stdlib"),
}

ALIASES = {
    "crypto": "encoding", "audio": "audio_video", "video": "audio_video",
    "archives": "documents", "disk": "disk_memory", "memory": "disk_memory",
    "malware": "malware_reversing", "reversing": "malware_reversing",
    "pwn": "pwn_services", "service": "pwn_services", "services": "pwn_services",
    "can": "can_misc", "misc": "can_misc",
}


def _profiles(requested):
    if not requested or "all" in requested:
        if requested and len(requested) != 1:
            raise ValueError("'all' cannot be combined with other profiles")
        return list(PROFILE_ENGINES)
    selected = []
    for name in requested:
        domain = ALIASES.get(name, name)
        if domain not in PROFILE_ENGINES:
            raise ValueError(f"Unknown autosolve profile: {name}")
        if domain not in selected:
            selected.append(domain)
    return selected


def _command(argv, data=None):
    try:
        return subprocess.run(argv, input=data, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _stdlib(self_test):
    compatible = sys.version_info >= (3, 12)
    probe = "not_run"
    if self_test:
        try:
            probe = "passed" if (
                base64.b64decode(b"YXV0b3NvbHZl", validate=True) == b"autosolve"
                and zlib.decompress(zlib.compress(b"probe")) == b"probe"
                and hashlib.sha256(b"").hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ) else "failed"
        except Exception:
            probe = "failed"
    return {
        "found": True, "path": sys.executable, "version": sys.version.split()[0],
        "options_compatible": compatible,
        "required_data": "not_required", "functional_probe": probe,
        "status": "ready" if compatible and probe == "passed" else "partial",
    }


def _file(self_test):
    override = os.environ.get("AUTOSOLVE_FILE")
    path = shutil.which(override if override else "file")
    result = {
        "found": bool(path), "path": path, "version": None,
        "discovery_source": "override" if override else "PATH",
        "options_compatible": None, "required_data": "not_checked",
        "functional_probe": "not_run", "status": "partial",
    }
    if not path:
        result["required_data"] = "unavailable"
        return result
    version = _command([path, "--version"])
    if version and version.returncode == 0:
        lines = version.stdout.decode("utf-8", "replace").splitlines()
        result["version"] = lines[0][:120] if lines else None
    help_result = _command([path, "--help"])
    if help_result and help_result.returncode == 0:
        help_text = help_result.stdout.decode("utf-8", "replace")
        result["options_compatible"] = "--mime-type" in help_text and "--brief" in help_text
    else:
        result["options_compatible"] = False
    if self_test and result["options_compatible"]:
        # A PNG signature checks the installed magic database, not just argument parsing.
        probe = _command([path, "--brief", "--mime-type", "-"], b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        passed = bool(probe and probe.returncode == 0 and probe.stdout.strip() == b"image/png")
        result["functional_probe"] = "passed" if passed else "failed"
        result["required_data"] = "present" if passed else "unknown"
    if result["options_compatible"] and result["functional_probe"] == "passed":
        result["status"] = "ready"
    return result


def _planned():
    return {
        "found": None, "path": None, "version": None,
        "options_compatible": None, "required_data": "not_checked",
        "functional_probe": "not_run", "status": "unavailable",
        "reason": "adapter_not_implemented",
    }


def _encoding_probe(self_test):
    try:
        module = importlib.import_module(".profiles.encoding", __package__)
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable",
                "reason": "adapter_not_implemented"}
    decode = getattr(module, "decode", None)
    if not callable(decode):
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable",
                "reason": "adapter_not_implemented"}
    probe = "not_run"
    if self_test:
        try:
            probe = "passed" if any(data == b"probe" for data, _ in decode(b"cHJvYmU=", 64)) else "failed"
        except Exception:
            probe = "failed"
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial",
            "reason": None if probe == "passed" else "adapter_function_not_probed" if not self_test else "adapter_probe_failed"}


def _xor_probe(self_test):
    try:
        from .profiles.xor import recover_single_byte
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        plaintext = b'The key is in the file and the message is in this text.'
        encoded = bytes(byte ^ 0xA7 for byte in plaintext)
        try:
            probe = 'passed' if any(item['data'] == plaintext and item['key_hex'] == 'a7'
                                    for item in recover_single_byte(encoded)) else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _rsa_probe(self_test):
    try:
        from .profiles.rsa import inspect_rsa
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        n = 10007 * 10009
        try:
            result = inspect_rsa([{'n': n, 'e': 3, 'c': 123 ** 3}])
            probe = 'passed' if any(item['plaintext_int'] == '123' and
                                    item['evidence']['reencryption_verified'] for item in result) else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _symmetric_probe(self_test):
    try:
        from .profiles.symmetric import decrypt_declared
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    if importlib.util.find_spec('cryptography') is None:
        return {"implemented": True, "functional_probe": "not_run", "status": "unavailable",
                "reason": "cryptography_missing"}
    probe = "not_run"
    if self_test:
        try:
            record = {'algorithm': 'AES', 'mode': 'GCM', 'key': '00' * 16,
                      'nonce': '00' * 12, 'ciphertext': '0388dace60b6a392f328c2b971b2fe78',
                      'tag': 'ab6e47d42cec13bdf53a67b21257bddf'}
            rows = decrypt_declared([record], max_output=16)
            probe = 'passed' if len(rows) == 1 and rows[0]['plaintext'] == bytes(16) and (
                rows[0]['status'] == 'validated_transform') else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _zip_probe(self_test):
    try:
        from .profiles.documents import extract_zip
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with zipfile.ZipFile(root / 'probe.zip', 'w') as archive:
                    archive.writestr('probe.txt', b'probe')
                records, warnings = extract_zip(root / 'probe.zip', root / 'out',
                                                max_members=2, max_total_bytes=64)
                probe = 'passed' if not warnings and len(records) == 1 and records[0]['path'].read_bytes() == b'probe' else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _mime_probe(self_test):
    try:
        from .profiles.mime import parse_mime
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                message = EmailMessage()
                message.set_content('probe')
                message.add_attachment(b'proof\x00', maintype='application', subtype='octet-stream')
                (root / 'mail.eml').write_bytes(message.as_bytes())
                records, warnings = parse_mime(root / 'mail.eml', root / 'parts',
                                               max_parts=4, max_total_bytes=64)
                probe = ('passed' if not warnings and any(
                    record['path'].read_bytes() == b'proof\x00' for record in records) else 'failed')
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _pdf_probe(self_test):
    try:
        from .profiles.pdf import extract_pdf
        from pypdf import PdfWriter
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                writer = PdfWriter()
                writer.add_blank_page(width=72, height=72)
                writer.add_attachment(filename='probe', data=b'proof\x00')
                with (root / 'probe.pdf').open('wb') as target:
                    writer.write(target)
                records, _ = extract_pdf(root / 'probe.pdf', root / 'parts',
                                         max_pages=2, max_total_bytes=64)
                probe = 'passed' if any(record['kind'] == 'attachment' and
                                        record['path'].read_bytes() == b'proof\x00'
                                        for record in records) else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _office_probe(self_test):
    try:
        from .profiles.office import inspect_office
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with zipfile.ZipFile(root / 'probe.docx', 'w') as archive:
                    archive.writestr('[Content_Types].xml', b'<Types/>')
                    archive.writestr('word/embeddings/probe.bin', b'proof\x00')
                records, warnings = inspect_office(root / 'probe.docx', root / 'parts',
                                                    max_parts=4, max_total_bytes=64)
                probe = ('passed' if not warnings and len(records) == 1 and
                         records[0]['path'].read_bytes() == b'proof\x00' else 'failed')
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _png_probe(self_test):
    try:
        from .profiles.images import extract_png_tail
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            def chunk(kind, data):
                return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
            png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
                   + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00')) + chunk(b'IEND', b''))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with zipfile.ZipFile(root / 'tail.zip', 'w') as archive:
                    archive.writestr('probe', b'probe')
                tail = (root / 'tail.zip').read_bytes()
                (root / 'image.png').write_bytes(png + tail)
                result = extract_png_tail(root / 'image.png', len(tail))
                probe = 'passed' if result and result[0] == tail and result[1]['offset'] == len(png) else 'failed'
        except Exception:
            probe = 'failed'
    return {"implemented": True, "functional_probe": probe,
            "status": "ready" if probe == "passed" else "partial"}


def _image_metadata_probe(self_test):
    from .profiles.image_metadata import _EXIFTOOL, channel_views, read_metadata
    path = shutil.which(_EXIFTOOL)
    exif_version = _command([path, '-ver']) if path else None
    image_spec = importlib.util.find_spec('PIL')
    metadata_probe = views_probe = 'not_run'
    if self_test:
        try:
            def chunk(kind, data):
                return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
            png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
                   + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00')) + chunk(b'IEND', b''))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'probe.png').write_bytes(png)
                tags, notes = read_metadata(root / 'probe.png', timeout=3)
                metadata_probe = 'passed' if not notes and any(
                    tag['tag'] == 'ImageWidth' and tag['value'] == 1 for tag in tags) else 'failed'
                if image_spec is not None:
                    views, view_notes = channel_views(root / 'probe.png', root / 'views',
                                                      max_pixels=1, max_total_bytes=100000)
                    views_probe = 'passed' if views and not view_notes else 'failed'
        except Exception:
            metadata_probe = 'failed' if path else 'not_run'
            views_probe = 'failed' if image_spec else 'not_run'
    metadata = {'implemented': True, 'functional_probe': metadata_probe,
                'status': 'ready' if metadata_probe == 'passed' else 'partial' if path else 'unavailable'}
    views = {'implemented': True, 'functional_probe': views_probe,
             'status': 'ready' if views_probe == 'passed' else 'partial' if image_spec else 'unavailable'}
    exif_engine = {'found': bool(path), 'path': path,
                   'version': exif_version.stdout.decode('utf-8', 'replace').strip()[:80]
                   if exif_version and exif_version.returncode == 0 else None,
                   'options_compatible': bool(path), 'required_data': 'not_required',
                   'functional_probe': metadata_probe, 'status': metadata['status']}
    image_engine = {'found': image_spec is not None, 'path': image_spec.origin if image_spec else None,
                    'version': importlib.metadata.version('Pillow') if image_spec else None,
                    'options_compatible': image_spec is not None, 'required_data': 'not_required',
                    'functional_probe': views_probe, 'status': views['status']}
    return metadata, views, exif_engine, image_engine


def _can_probe(self_test):
    from .profiles.canlog import parse_can_log
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'capture.log'
                path.write_text('(1.0) can0 123#0102\n')
                frames, warnings = parse_can_log(path, max_frames=2, max_bytes=128)
                probe = ('passed' if not warnings and len(frames) == 1 and
                         frames[0]['payload_hex'] == '0102' else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _packet_probe(self_test):
    from .profiles.packets import TSHARK, inspect_pcap
    path = shutil.which(TSHARK)
    version = _command([path, '--version']) if path else None
    probe = 'not_run'
    if self_test and path:
        try:
            sample = Path(__file__).resolve().parents[2] / 'examples/core/http.pcap'
            rows, warnings = inspect_pcap(sample, timeout=5, max_output=1024 * 1024)
            probe = ('passed' if not warnings and any(
                row.get('http', {}).get('uri') == '/report.txt' and row['packet'] == 4
                for row in rows) else 'failed')
        except Exception:
            probe = 'failed'
    operation = {'implemented': True, 'functional_probe': probe,
                 'status': 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'}
    engine = {'found': bool(path), 'path': path,
              'version': version.stdout.decode('utf-8', 'replace').splitlines()[0][:120]
              if version and version.returncode == 0 else None,
              'options_compatible': bool(path), 'required_data': 'not_required',
              'functional_probe': probe, 'status': operation['status']}
    return operation, engine


def _zsteg_probe(self_test):
    from .profiles.zsteg import ZSTEG, inspect_lsb
    path = shutil.which(ZSTEG)
    pillow = importlib.util.find_spec('PIL') is not None
    version = _command([path, '--version']) if path else None
    probe = 'not_run'
    if self_test and path and pillow:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sample = Path(__file__).resolve().parents[2] / 'examples/core/carrier.png'
                records, warnings = inspect_lsb(sample, root / 'out', max_pixels=1000,
                                                  max_total_bytes=65536, timeout=5)
                probe = ('passed' if not warnings and any(
                    row['selector'] == 'b1,r,lsb,xy' and
                    row['path'].read_bytes() == b'TRAINING-LSB\n' for row in records)
                    else 'failed')
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if path and pillow else 'unavailable'
    operation = {'implemented': True, 'functional_probe': probe, 'status': status}
    engine = {'found': bool(path), 'path': path,
              'version': version.stdout.decode('utf-8', 'replace').splitlines()[0][:120]
              if version and version.returncode == 0 and version.stdout else None,
              'options_compatible': bool(path), 'required_data': 'Pillow',
              'functional_probe': probe, 'status': status}
    return operation, engine


def _sqlite_probe(self_test):
    from .profiles.sqlite import inspect_sqlite
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'probe.db'
                with sqlite3.connect(source) as connection:
                    connection.execute('CREATE TABLE evidence (value TEXT)')
                    connection.execute('INSERT INTO evidence VALUES (?)', ('probe',))
                records, warnings = inspect_sqlite(source, root / 'out',
                                                   max_rows=2, max_bytes=65536)
                probe = ('passed' if not warnings and any(record['kind'] == 'row' and
                         b'"probe"' in record['path'].read_bytes() for record in records)
                         else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def doctor(profiles: list[str], self_test: bool = False) -> dict:
    """Inspect only integrated engines; planned engines remain explicitly unavailable."""
    selected = _profiles(profiles)
    planned = sorted({engine for profile in selected for engine in PROFILE_ENGINES[profile]})
    engines = {engine: _planned() for engine in planned
               if engine not in ("stdlib", "file", "cryptolib", "exif", "image", "tshark", "zsteg")}
    if "stdlib" in planned or "encoding" in selected:
        engines["stdlib"] = _stdlib(self_test)
    if "file" in planned:
        engines["file"] = _file(self_test)
    if "cryptolib" in planned:
        operation = _symmetric_probe(self_test)
        spec = importlib.util.find_spec('cryptography')
        engines['cryptolib'] = {
            'found': spec is not None, 'path': spec.origin if spec else None,
            'version': importlib.metadata.version('cryptography') if spec else None,
            'options_compatible': operation['implemented'], 'required_data': 'not_required',
            'functional_probe': operation['functional_probe'], 'status': operation['status']}
    image_probes = _image_metadata_probe(self_test) if 'exif' in planned or 'image' in planned else None
    if 'exif' in planned:
        engines['exif'] = image_probes[2]
    if 'image' in planned:
        engines['image'] = image_probes[3]
    packet_probes = _packet_probe(self_test) if 'tshark' in planned else None
    if 'tshark' in planned:
        engines['tshark'] = packet_probes[1]
    if 'office' in planned:
        spec = importlib.util.find_spec('oletools')
        operation = _office_probe(self_test)
        engines['office'] = {
            'found': spec is not None, 'path': spec.origin if spec else None,
            'version': importlib.metadata.version('oletools') if spec else None,
            'options_compatible': operation['implemented'],
            'required_data': 'not_required',
            'functional_probe': operation['functional_probe'],
            'status': 'ready' if spec and operation['status'] == 'ready' else 'partial'}
    zsteg_probes = _zsteg_probe(self_test) if 'zsteg' in planned else None
    if 'zsteg' in planned:
        engines['zsteg'] = zsteg_probes[1]
    operations = {}
    if "encoding" in selected:
        operations["encoding.decode"] = _encoding_probe(self_test)
        operations["encoding.xor_one"] = _xor_probe(self_test)
        operations["encoding.rsa_literals"] = _rsa_probe(self_test)
        operations["encoding.aes_declared"] = _symmetric_probe(self_test)
    if "documents" in selected:
        operations["documents.zip"] = _zip_probe(self_test)
        operations["documents.mime"] = _mime_probe(self_test)
        operations["documents.pdf"] = _pdf_probe(self_test)
        operations["documents.office"] = _office_probe(self_test)
    if "images" in selected:
        operations["images.png_tail"] = _png_probe(self_test)
        operations["images.metadata"] = image_probes[0]
        operations["images.views"] = image_probes[1]
        operations["images.zsteg"] = zsteg_probes[0]
    if "osint" in selected:
        operations["osint.metadata"] = image_probes[0]
    if "can_misc" in selected:
        operations['can_misc.log'] = _can_probe(self_test)
    if "packets" in selected:
        operations['packets.metadata'] = packet_probes[0]
    if "disk_memory" in selected:
        operations['disk_memory.sqlite'] = _sqlite_probe(self_test)
    status = "partial" if any(value["status"] != "ready" for value in engines.values()) or any(
        value["status"] != "ready" for value in operations.values()
    ) else "ready"
    return {"status": status, "profiles": selected, "engines": engines, "operations": operations}


def setup(profiles: list[str]) -> dict:
    """Explicit rootless setup; currently integrated operations need no packages."""
    result = doctor(profiles, self_test=True)
    result["installed"] = []
    result["message"] = "No packages installed; unavailable operations remain partial."
    return result
