"""Capability discovery and explicit rootless setup for autosolve."""

import base64
import gzip
import hashlib
import hmac
import importlib
import importlib.metadata
import importlib.util
import io
import json
from email.message import EmailMessage
import math
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import wave
from pathlib import Path
import zipfile
import zlib


PROFILE_ENGINES = {
    "encoding": ("crypto-attacks", "cryptolib", "passwords", "refinery", "rsa", "stdlib", "xortool"),
    "images": ("archive", "binwalk", "exif", "ghidra", "image", "qr", "stegseek", "zsteg"),
    "documents": ("archive", "binwalk", "bkcrack", "office", "passwords", "pdf", "refinery", "stdlib"),
    "audio_video": ("ffmpeg", "image", "multimon", "sstv", "stegolsb", "tesseract"),
    "packets": ("archive", "hcxtools", "passwords", "scapy", "stdlib", "tshark", "zeek"),
    "disk_memory": ("binwalk", "dissect", "stdlib", "tsk", "volatility"),
    "malware_reversing": ("angr", "binwalk", "capa", "file", "floss", "ghidra", "jadx", "java", "javap", "pefile", "pwntools", "pyelftools", "pyinstaller", "refinery", "stdlib", "upx", "yara"),
    "pwn_services": ("ghidra", "nmap", "pwntools", "pyelftools", "ropgadget"),
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


def _osint_ids_probe(self_test):
    from .profiles.osint_ids import extract_identifiers
    probe = 'not_run'
    if self_test:
        try:
            data = b'Visit https://example.org/map, then @guide_9'
            records, warnings = extract_identifiers(data)
            probe = ('passed' if not warnings and
                     [(row['kind'], row['byte_offset']) for row in records] ==
                     [('url', 6), ('handle', 36)] and
                     all(data[row['byte_offset']:row['byte_offset'] + row['byte_length']]
                         .decode() == row['value'] for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _osint_snapshot_probe(self_test):
    from .profiles.osint_snapshots import build_snapshot_trail
    from .profiles.web_static import inspect_web_static
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                page = root / 'index.html'
                target = root / 'notice.txt'
                page.write_text('<a href="notice.txt">Notice 2025-01-01</a>')
                target.write_text('Issued 2025-01-02')
                web_records, _ = inspect_web_static(page)
                sources = [{'artifact_id': 'page', 'source_name': 'index.html', 'path': page,
                            'sha256': hashlib.sha256(page.read_bytes()).hexdigest(),
                            'web_records': web_records},
                           {'artifact_id': 'target', 'source_name': 'notice.txt', 'path': target,
                            'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}]
                records, warnings = build_snapshot_trail(sources)
                probe = ('passed' if not warnings and any(row['kind'] == 'local_link' and
                         row['target_artifact_id'] == 'target' for row in records) and
                         any(row['kind'] == 'date_conflict' for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


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


def _hash_probe(self_test):
    try:
        from .profiles.passwords import inspect_password_hashes
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            rows = inspect_password_hashes([
                {'algorithm': 'sha256', 'digest': hashlib.sha256(b'probe').hexdigest()}
            ], [b'wrong', b'probe'])
            probe = 'passed' if len(rows) == 1 and rows[0]['password'] == b'probe' else 'failed'
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


def _sevenzip_probe(self_test):
    path = shutil.which('7z') or shutil.which('7zz')
    help_result = _command([path, '-h']) if path else None
    help_text = (help_result.stdout + help_result.stderr).decode('utf-8', 'replace') if help_result else ''
    compatible = bool(help_result and help_result.returncode == 0 and
                      all(option in help_text for option in ('-slt', '-so', '-spd', '-scc', '-p{Password}')))
    version = next((line.strip()[:120] for line in help_text.splitlines() if '7-Zip' in line), None)
    probe = 'not_run'
    if self_test and compatible:
        try:
            from .profiles.sevenzip import extract_7z
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'probe.txt').write_bytes(b'7z-doctor-probe')
                source = root / 'probe.7z'
                created = _command([path, 'a', '-t7z', '-mx=1', '-pautosolve-doctor-probe',
                                    '-mhe=on', str(source), str(root / 'probe.txt')])
                if created and created.returncode == 0:
                    records, warnings = extract_7z(
                        source, root / 'out', max_members=2, max_total_bytes=64,
                        max_member_bytes=64, passwords=[b'autosolve-doctor-probe'], executable=path)
                    probe = ('passed' if not warnings and len(records) == 1 and
                             records[0]['member'] == 'probe.txt' and records[0]['encrypted'] and
                             records[0]['path'].read_bytes() == b'7z-doctor-probe' else 'failed')
                else:
                    probe = 'failed'
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'
    operation = {'implemented': True, 'functional_probe': probe, 'status': status}
    engine = {'found': bool(path), 'path': path, 'version': version,
              'options_compatible': compatible, 'required_data': 'private password_file for encrypted archives',
              'functional_probe': probe, 'status': status}
    return operation, engine


def _tar_probe(self_test):
    try:
        from .profiles.tar import extract_tar
    except ImportError:
        return {"implemented": False, "functional_probe": "not_run", "status": "unavailable"}
    probe = "not_run"
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with tarfile.open(root / 'probe.tar.gz', 'w:gz') as archive:
                    info = tarfile.TarInfo('probe.txt')
                    info.size = 5
                    archive.addfile(info, io.BytesIO(b'probe'))
                records, warnings = extract_tar(root / 'probe.tar.gz', root / 'out',
                                                max_members=2, max_total_bytes=64)
                probe = ('passed' if not warnings and len(records) == 1 and
                         records[0]['path'].read_bytes() == b'probe' else 'failed')
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


def _jpeg_probe(self_test):
    if importlib.util.find_spec('PIL') is None:
        return {'implemented': True, 'functional_probe': 'not_run',
                'status': 'unavailable', 'reason': 'pillow_missing'}
    try:
        from PIL import Image
        from .profiles.images import extract_jpeg_tail
    except (ImportError, OSError):
        return {'implemented': True, 'functional_probe': 'not_run',
                'status': 'unavailable', 'reason': 'pillow_unusable'}
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = io.BytesIO()
                Image.new('RGB', (2, 2), (20, 80, 140)).save(image, format='JPEG')
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, 'w') as writer:
                    writer.writestr('probe', b'probe')
                tail = archive.getvalue()
                (root / 'image.jpg').write_bytes(image.getvalue() + b'\x00' + tail)
                result = extract_jpeg_tail(root / 'image.jpg', len(tail))
                probe = ('passed' if result and result[0] == tail and
                         result[1]['offset'] == len(image.getvalue()) + 1 else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


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


def _can_dbc_probe(self_test):
    spec = importlib.util.find_spec('cantools')
    if spec is None:
        return ({'implemented': True, 'functional_probe': 'not_run',
                 'status': 'unavailable', 'reason': 'cantools_missing'}, None)
    from .profiles.can_dbc import decode_can_frames
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'probe.dbc'
                path.write_text('VERSION ""\nNS_ :\nBS_:\nBU_: Node\n'
                                'BO_ 291 Demo: 2 Node\n'
                                ' SG_ Value : 0|16@1- (0.5,1) [-100|100] "u" Node\n')
                frames = [{'can_id': '123', 'extended': False, 'payload_hex': 'FCFF',
                           'payload_length': 2, 'frame_type': 'data', 'source_line': 1}]
                rows, warnings = decode_can_frames(frames, path, max_frames=2,
                                                   max_db_bytes=512,
                                                   max_output_bytes=4096, timeout=5)
                probe = ('passed' if not warnings and len(rows) == 1 and
                         rows[0]['signals'][0]['raw'] == -4 and
                         rows[0]['signals'][0]['value'] == -1 else 'failed')
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial'
    return ({'implemented': True, 'functional_probe': probe, 'status': status},
            {'found': True, 'path': spec.origin,
             'version': importlib.metadata.version('cantools'),
             'options_compatible': True, 'required_data': 'supplied_dbc_or_arxml',
             'functional_probe': probe, 'status': status})


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


def _packet_object_probe(self_test):
    from .profiles.packet_objects import TSHARK, export_http_objects
    path = shutil.which(TSHARK)
    probe = 'not_run'
    if self_test and path:
        try:
            with tempfile.TemporaryDirectory() as directory:
                sample = Path(__file__).resolve().parents[2] / 'examples/core/http.pcap'
                rows, warnings = export_http_objects(sample, Path(directory) / 'objects', timeout=5)
                probe = ('passed' if not warnings and len(rows) == 1 and
                         rows[0]['path'].read_bytes() == b'Synthetic local tool exercise\nLayer order matters.\n'
                         and rows[0]['packet'] == 8 and rows[0]['tcp_stream'] == 0 else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'}


def _packet_tls_probe(self_test):
    from .profiles.packet_tls import TSHARK
    path = shutil.which(TSHARK)
    preferences = _command([path, '-G', 'currentprefs']) if self_test and path else None
    compatible = bool(preferences and preferences.returncode == 0 and
                      b'tls.keylog_file:' in preferences.stdout and
                      b'http.decompress_body:' in preferences.stdout)
    return {'implemented': True, 'functional_probe': 'not_run',
            'options_compatible': compatible if self_test else None,
            'required_data': 'supplied matching tls_keylog',
            'status': 'partial' if path else 'unavailable',
            'reason': 'matching TLS capture and key log required for functional probe'
                      if path else 'tshark_missing'}


def _packet_stream_probe(self_test):
    from .profiles.packet_streams import TSHARK, reassemble_tcp
    path = shutil.which(TSHARK)
    probe = 'not_run'
    if self_test and path:
        try:
            sample = Path(__file__).resolve().parents[2] / 'examples/core/http.pcap'
            rows, warnings = reassemble_tcp(sample, timeout=5, max_output=1024 * 1024,
                                            max_streams=4, max_bytes=1024 * 1024)
            probe = ('passed' if not warnings and len(rows) == 2 and
                     rows[0]['stream'] == 0 and rows[0]['sequence_start'] == 1001 and
                     rows[0]['segments'][0]['frame'] == 4 and
                     not rows[0]['complete'] and 'FIN not captured' in rows[0]['reasons']
                     and 'data' not in rows[0] else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'}


def _media_probe(self_test):
    from .profiles.media import FFMPEG, FFPROBE, inspect_media
    ffmpeg = shutil.which(FFMPEG)
    ffprobe = shutil.which(FFPROBE)
    probe = 'not_run'
    if self_test and ffmpeg and ffprobe:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'silent.wav'
                with wave.open(str(source), 'wb') as writer:
                    writer.setnchannels(1)
                    writer.setsampwidth(2)
                    writer.setframerate(8000)
                    writer.writeframes(b'\x00\x00' * 800)
                records, warnings = inspect_media(source, root / 'stage',
                                                  timeout=5, max_bytes=512 * 1024)
                probe = ('passed' if not warnings and any(
                    row['kind'] == 'audio_view' and row['view'] == 'spectrogram'
                    for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if ffmpeg and ffprobe else 'unavailable'
    operation = {'implemented': True, 'functional_probe': probe, 'status': status}
    version = _command([ffmpeg, '-version']) if ffmpeg else None
    engine = {'found': bool(ffmpeg and ffprobe), 'path': ffmpeg, 'ffprobe_path': ffprobe,
              'version': version.stdout.decode('utf-8', 'replace').splitlines()[0][:120]
              if version and version.returncode == 0 else None,
              'options_compatible': bool(ffmpeg and ffprobe), 'required_data': 'not_required',
              'functional_probe': probe, 'status': status}
    return operation, engine


def _tone_probe(self_test):
    from .profiles.tones import FFMPEG, MULTIMON, inspect_tones
    multimon = shutil.which(MULTIMON)
    ffmpeg = shutil.which(FFMPEG)
    probe = 'not_run'
    if self_test and multimon and ffmpeg:
        try:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'dtmf.wav'
                rate = 22050
                samples = bytearray(b'\0\0' * (rate // 10))
                for low, high in ((697, 1209), (697, 1336)):
                    for index in range(rate // 5):
                        value = int(5000 * (math.sin(2 * math.pi * low * index / rate) +
                                            math.sin(2 * math.pi * high * index / rate)))
                        samples.extend(struct.pack('<h', value))
                    samples.extend(b'\0\0' * (rate // 5))
                with wave.open(str(source), 'wb') as writer:
                    writer.setparams((1, 2, rate, 0, 'NONE', 'not compressed'))
                    writer.writeframes(samples)
                rows, warnings = inspect_tones(source, timeout=5, max_output=4096,
                                               modes=('DTMF',))
                probe = ('passed' if not warnings and
                         ''.join(row['symbol'] for row in rows) == '12' else 'failed')
        except Exception:
            probe = 'failed'
    narrow_probe = 'not_run'
    narrow_reason = 'self_test_required'
    if self_test and multimon and ffmpeg:
        fixtures = Path(__file__).resolve().parents[2] / 'tests/fixtures/toolkit/audio'
        morse = fixtures / 'morse-sos.wav'
        afsk = fixtures / 'afsk-hello.wav'
        expected = ((morse, 92648, '04f836645344e118a7f16fbda5baebdc350de889e286dd47fc229ed85112a64a'),
                    (afsk, 57088, 'e27fa45d5b51830bcc13cd0207ee8d0a6992e3652f689fe1e36c8ea1f23b3e21'))
        try:
            if any(path.stat().st_size != size or
                   hashlib.sha256(path.read_bytes()).hexdigest() != digest
                   for path, size, digest in expected):
                narrow_probe, narrow_reason = 'failed', 'fixture_missing_or_changed'
            else:
                morse_rows, morse_warnings = inspect_tones(morse, timeout=5, max_output=4096,
                                                          modes=('MORSE_CW',))
                afsk_rows, afsk_warnings = inspect_tones(afsk, timeout=5, max_output=4096,
                                                       modes=('AFSK1200',))
                morse_ok = (not morse_warnings and len(morse_rows) == 1 and
                            morse_rows[0]['mode'] == 'MORSE_CW' and
                            morse_rows[0]['raw_output'].strip() == 'SOS')
                afsk_ok = (not afsk_warnings and len(afsk_rows) == 1 and
                           afsk_rows[0]['mode'] == 'AFSK1200' and
                           afsk_rows[0]['raw_output'].splitlines() == [
                               'AFSK1200: fm AE4WA-0 to HB9JNX-0 UI  pid=F0',
                               'AFSK_PROBE_20261027'])
                narrow_probe = 'passed' if morse_ok and afsk_ok else 'failed'
                narrow_reason = None if narrow_probe == 'passed' else 'morse_or_afsk_output_mismatch'
        except (OSError, ValueError):
            narrow_probe, narrow_reason = 'failed', 'fixture_missing_or_changed'
    status = 'ready' if probe == 'passed' else 'partial' if multimon and ffmpeg else 'unavailable'
    dtmf = {'implemented': True, 'functional_probe': probe, 'status': status,
            'reason': 'multimon-ng_or_ffmpeg_missing' if status == 'unavailable' else None}
    narrow_status = ('ready' if narrow_probe == 'passed' else 'partial' if multimon and ffmpeg
                     else 'unavailable')
    narrow = {'implemented': True, 'functional_probe': narrow_probe,
              'status': narrow_status,
              'reason': 'multimon-ng_or_ffmpeg_missing' if narrow_status == 'unavailable'
              else narrow_reason}
    engine_status = ('ready' if status == narrow_status == 'ready' else
                     'partial' if multimon and ffmpeg else 'unavailable')
    engine = {'found': bool(multimon), 'path': multimon, 'version': None,
              'options_compatible': bool(multimon and ffmpeg),
              'required_data': 'ffmpeg',
              'functional_probe': 'passed' if engine_status == 'ready' else
                                  'failed' if self_test and multimon and ffmpeg else 'not_run',
              'status': engine_status}
    return dtmf, narrow, engine


def _sstv_probe(self_test):
    from .profiles.sstv import FFMPEG, SSTV, decode_sstv, decoder_available
    tool = shutil.which(SSTV)
    ffmpeg = shutil.which(FFMPEG)
    compatible = bool(tool and ffmpeg and decoder_available(tool))
    probe = 'not_run'
    fixture = Path(__file__).resolve().parents[2] / 'tests/fixtures/toolkit/audio/robot36.ogg'
    if self_test and compatible and fixture.is_file():
        try:
            with tempfile.TemporaryDirectory() as directory:
                records, warnings = decode_sstv(fixture, Path(directory) / 'stage',
                                                timeout=15, max_bytes=1024 * 1024)
                if not warnings and len(records) == 1 and records[0]['mode'] == 'Robot 36' and \
                        (records[0]['width'], records[0]['height']) == (320, 240):
                    from PIL import Image, ImageStat
                    with Image.open(records[0]['path']) as image:
                        image = image.convert('RGB')
                        boxes = ((100, 5, 220, 25), (40, 105, 65, 130),
                                 (120, 105, 200, 130), (255, 105, 280, 130),
                                 (100, 220, 220, 237))
                        white_top, red_left, blue, red_right, white_bottom = (
                            ImageStat.Stat(image.crop(box)).mean for box in boxes)
                    probe = ('passed' if all(min(rgb) > 170 for rgb in (white_top, white_bottom))
                             and all(red > 150 and red > green + 80 and red > blue_channel + 80
                                     for red, green, blue_channel in (red_left, red_right))
                             and blue[2] > 100 and blue[2] > blue[0] + 60 and blue[2] > blue[1] + 60
                             else 'failed')
                else:
                    probe = 'failed'
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if compatible else 'unavailable'
    reason = ('approved_sstv_decoder_or_ffmpeg_missing' if not compatible else
              'sstv_probe_fixture_missing' if self_test and not fixture.is_file() else
              'sstv_probe_failed' if self_test and probe != 'passed' else None)
    operation = {'implemented': True, 'functional_probe': probe, 'status': status,
                 'reason': reason}
    engine = {'found': bool(tool), 'path': tool, 'version': None,
              'options_compatible': compatible,
              'required_data': 'Martin/Robot recording with supported VIS header',
              'functional_probe': probe, 'status': status}
    return operation, engine


def _ocr_probe(self_test):
    from .profiles.ocr import TESSERACT, english_traineddata_path, extract_printed_text
    path = shutil.which(TESSERACT)
    model = english_traineddata_path() if path else None
    probe = 'not_run'
    if self_test and model and importlib.util.find_spec('PIL'):
        try:
            from PIL import Image, ImageDraw, ImageFont
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'printed.png'
                image = Image.new('RGB', (410, 90), 'white')
                ImageDraw.Draw(image).text((15, 18), 'OCR PROBE 2468', fill='black',
                                           font=ImageFont.load_default(size=30))
                image.save(source)
                records, warnings = extract_printed_text(source, timeout=5)
                probe = ('passed' if not warnings and any(
                    b'OCR PROBE 2468' in row['data'] for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'
    version = _command([path, '--version']) if path else None
    operation = {'implemented': True, 'functional_probe': probe, 'status': status,
                 'reason': 'English traineddata identity unavailable' if path and not model else
                           None if path else 'tesseract_missing'}
    engine = {'found': bool(path), 'path': path,
              'version': version.stdout.decode('utf-8', 'replace').splitlines()[0][:80]
              if version and version.returncode == 0 else None,
              'options_compatible': bool(model),
              'required_data': str(model) if model else 'English traineddata identity unavailable',
              'functional_probe': probe, 'status': status}
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


def _stegseek_probe(self_test):
    from .profiles.stegseek import STEGSEEK, extract_steghide
    path = shutil.which(STEGSEEK)
    version = _command([path, '--help']) if path else None
    probe = 'not_run'
    if self_test and path and shutil.which('steghide'):
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cover = root / 'cover.wav'
                with wave.open(str(cover), 'wb') as output:
                    output.setnchannels(1)
                    output.setsampwidth(2)
                    output.setframerate(8000)
                    output.writeframes(hashlib.shake_256(b'stegseek-probe').digest(32000))
                payload = root / 'payload'
                payload.write_bytes(b'stegseek-probe-payload')
                stego = root / 'stego.wav'
                result = _command(['steghide', 'embed', '-cf', str(cover), '-ef', str(payload),
                                   '-sf', str(stego), '-p', 'probe-password', '-f', '-q'])
                if result and result.returncode == 0:
                    records, warnings = extract_steghide(
                        stego, root / 'out', passwords=[b'probe-password'],
                        max_total_bytes=1024, timeout=5)
                    probe = ('passed' if not warnings and len(records) == 1 and
                             records[0]['path'].read_bytes() == b'stegseek-probe-payload'
                             else 'failed')
                else:
                    probe = 'failed'
        except Exception:
            probe = 'failed'
    status = 'ready' if probe == 'passed' else 'partial' if path else 'unavailable'
    operation = {'implemented': True, 'functional_probe': probe, 'status': status}
    engine = {'found': bool(path), 'path': path,
              'version': version.stdout.decode('utf-8', 'replace').splitlines()[0][:120]
              if version and version.returncode == 0 and version.stdout else None,
              'options_compatible': bool(version and version.returncode == 0),
              'required_data': 'private password_file; steghide only for self-test',
              'functional_probe': probe, 'status': status}
    return operation, engine


def _qr_probe(self_test):
    pillow = importlib.util.find_spec('PIL')
    if pillow:
        from .profiles.qr import _decoder
        backend_name, _ = _decoder()
    else:
        backend_name = None
    backend = importlib.util.find_spec(backend_name) if backend_name else None
    try:
        version = importlib.metadata.version('zxing-cpp' if backend_name == 'zxingcpp'
                                             else 'pyzbar') if backend else None
    except (importlib.metadata.PackageNotFoundError, KeyError, OSError, ValueError):
        version = None
    probe = 'not_run'
    zxing_functional = False
    if self_test and backend:
        try:
            from PIL import Image
            from .core import _run_qr
            # OpenCV encoded this fixed QR matrix; the tested reader does not generate it.
            matrix = bytes.fromhex(
                'ffffff80ffffff80c0410180df6b7d80d1674580d1634580d1754580df797d80'
                'c0550180ffc1ff80c9657d80d9cc4980c11e2b80d8d22d80d206f380ffc83980'
                'c065ad80df71f780d1491980d151c780d1662980df462380c0428380ffffff80ffffff80')
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'probe.png'
                Image.frombytes('1', (25, 25), matrix).resize(
                    (250, 250), Image.Resampling.NEAREST).save(source)
                rows, _ = _run_qr(source, 100_000, 1024, 3)
                qr_functional = any(row['payload'] == b'QR-ORACLE-123' for row in rows)
                zxing_functional = any(row['payload'] == b'QR-ORACLE-123' and
                                       row['decoder'] == 'zxingcpp' for row in rows)
                if zxing_functional:
                    import zxingcpp
                    symbol = zxingcpp.create_barcode('DM-ORACLE-123',
                                                     zxingcpp.BarcodeFormat.DataMatrix)
                    Image.fromarray(symbol.to_image(scale=8)).save(source)
                    rows, _ = _run_qr(source, 100_000, 1024, 3)
                    zxing_functional = any(row['payload'] == b'DM-ORACLE-123' and
                                           row['format'] == 'Data Matrix' and
                                           row['decoder'] == 'zxingcpp' for row in rows)
                probe = ('passed' if qr_functional and
                         (backend_name != 'zxingcpp' or zxing_functional) else 'failed')
        except Exception:
            probe = 'failed'
    status = ('ready' if zxing_functional and version else
              'partial' if backend else 'unavailable')
    operation = {'implemented': True, 'functional_probe': probe, 'status': status,
                 'note': 'QR and DataMatrix enabled' if status == 'ready' else
                         'decoder package metadata unavailable' if backend and not version else
                         'DataMatrix requires functional zxing-cpp'}
    engine = {'found': bool(backend), 'path': backend.origin if backend else None,
              'version': version,
              'options_compatible': bool(backend), 'required_data': 'Pillow; zxing-cpp for DataMatrix',
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


def _os_artifact_probe(self_test):
    from .profiles.os_artifacts import inspect_os_artifact
    parsers = {'browser_history': True,
               'registry': importlib.util.find_spec('Registry') is not None,
               'evtx': importlib.util.find_spec('Evtx') is not None}
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'renamed-history'
                with sqlite3.connect(source) as db:
                    db.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)')
                    db.execute('CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)')
                    db.execute('INSERT INTO urls VALUES(1, ?)', ('https://example.test/probe',))
                    db.execute('INSERT INTO visits VALUES(2, 1, 13253760000000000)')
                records, warnings = inspect_os_artifact(source, max_records=2, max_bytes=65536)
                probe = ('passed' if not warnings and len(records) == 1 and
                         records[0]['timestamp'] == '2020-12-30T00:00:00Z' and
                         records[0]['url'] == 'https://example.test/probe' else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe, 'status': 'partial',
            'parsers': parsers,
            'reason': 'registry and EVTX require compatible optional parsers and real artifact validation'}


def _web_static_probe(self_test):
    from .profiles.web_static import inspect_web_static
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'page.html'
                source.write_text('<form action="/submit"></form><script>fetch("/api/probe")</script>')
                records, warnings = inspect_web_static(source, origin='https://example.test')
                probe = ('passed' if not warnings and any(
                    row['kind'] == 'form' and row['value'] == '/submit' and row['offset'] == 14
                    for row in records) and any(
                    row['kind'] == 'literal_endpoint' and row['value'] == '/api/probe' and
                    row['scope'] == 'same_origin' for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _web_jwt_probe(self_test):
    probe = 'not_run'
    if self_test:
        try:
            from .profiles.jwt import inspect_jwt
            signing_input = b'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm9iZSJ9'
            signature = hmac.digest(b'probe-secret', signing_input, hashlib.sha256)
            token = signing_input + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')
            good, warnings = inspect_jwt(token, keys=[{'alg': 'HS256', 'key': b'probe-secret'}])
            bad, _ = inspect_jwt(token, keys=[{'alg': 'HS256', 'key': b'wrong'}])
            probe = ('passed' if not warnings and len(good) == len(bad) == 1 and
                     good[0]['signature_verified'] and good[0]['server_accepted'] is None and
                     not bad[0]['signature_verified'] else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _web_discovery_probe(self_test):
    from .profiles.web_discovery import discover_web
    probe = 'not_run'
    if self_test:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                found = self.path == '/probe'
                body = b'found' if found else b'missing'
                self.send_response(200 if found else 404)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = None
        thread = None
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Site)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f'http://127.0.0.1:{server.server_port}'
            result, warnings = discover_web({'origin': origin, 'kind': 'path',
                                             'request': {'method': 'GET', 'path': '/'},
                                             'dictionary': ['probe']}, timeout=2,
                                            max_requests=3, rate=20)
            probe = ('passed' if not warnings and result['calibration'] == 'stable' and
                     result['requests_used'] == 3 and
                     result['results'][0]['classification'] == 'candidate' else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            if server:
                server.shutdown()
                server.server_close()
            if thread:
                thread.join(2)
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _web_leads_probe(self_test):
    from .profiles.web_leads import probe_web_leads
    probe = 'not_run'
    if self_test:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import parse_qs, urlsplit

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                value = parse_qs(urlsplit(self.path).query).get('file', [''])[0]
                body = b'private-marker' if value == '../selected.txt' else b'missing'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = None
        thread = None
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Site)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f'http://127.0.0.1:{server.server_port}'
            result, warnings = probe_web_leads(
                {'origin': origin, 'kind': 'traversal', 'parameter': 'file',
                 'request': {'method': 'GET', 'path': '/', 'query': {'file': 'ordinary'}},
                 'probe_value': '../selected.txt', 'expected': 'private-marker'},
                timeout=2, max_requests=4, rate=20)
            probe = ('passed' if not warnings and result['requests_used'] == 4 and
                     result['classification'] == 'candidate' else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            if server:
                server.shutdown()
                server.server_close()
            if thread:
                thread.join(2)
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _web_sql_probe(self_test):
    from .profiles.web_sql import assess_sql
    probe = 'not_run'
    if self_test:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import parse_qs, urlsplit

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                value = parse_qs(urlsplit(self.path).query).get('id', [''])[0]
                database = sqlite3.connect(':memory:')
                database.execute('CREATE TABLE users (id TEXT)')
                database.execute("INSERT INTO users VALUES ('1')")
                try:
                    found = database.execute(
                        "SELECT id FROM users WHERE id = '" + value + "'").fetchone()
                    body = b'found' if found else b'missing'
                    status = 200
                except sqlite3.Error:
                    body, status = b'error', 500
                finally:
                    database.close()
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = thread = None
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Site)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f'http://127.0.0.1:{server.server_port}'
            raw = (f'GET /?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n\r\n').encode()
            result, warnings = assess_sql(raw, origin, 'id', authorized=True,
                                          test_mode=True, timeout=2, max_requests=6,
                                          rate=20)
            probe = ('passed' if not warnings and result['requests_used'] == 6 and
                     result['classification'] == 'differential_candidate' else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            if server:
                server.shutdown()
                server.server_close()
            if thread:
                thread.join(2)
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _web_workflow_probe(self_test):
    from .profiles.web_workflows import replay_workflows
    probe = 'not_run'
    if self_test:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                status = 200 if self.headers.get('X-Role') == 'owner' else 403
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b'allowed' if status == 200 else b'denied')

            def log_message(self, *args):
                pass

        server = thread = None
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Site)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f'http://127.0.0.1:{server.server_port}'
            fixture = {'expected_invariant': {
                'left': {'role': 'owner', 'step': 'read'},
                'right': {'role': 'guest', 'step': 'read'},
                'relation': 'different_status'},
                'workflows': [
                    {'role': role, 'steps': [{'id': 'read', 'method': 'GET', 'path': '/',
                                               'headers': {'X-Role': role},
                                               'safe_to_replay': True}]}
                    for role in ('owner', 'guest')]}
            result, warnings = replay_workflows(fixture, origin=origin, timeout=2)
            probe = ('passed' if not warnings and result['assessment'] == 'invariant held'
                     and [row['status'] for row in result['responses']] == [200, 403]
                     else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            if server:
                server.shutdown()
                server.server_close()
            if thread:
                thread.join(2)
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _memory_probe(self_test):
    from .profiles import memory
    path = memory.VOL
    found = Path(path).is_file()
    help_result = _command([path, '--help']) if found else None
    help_text = help_result.stdout.decode('utf-8', 'replace') if help_result else ''
    compatible = bool(help_result and help_result.returncode == 0 and
                      all(value in help_text for value in
                          ('--offline', '--cache-path', 'windows.info.Info',
                           'windows.dumpfiles.DumpFiles')))
    probe = 'not_run'
    if self_test and compatible:
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = root / 'invalid.raw'
                image.write_bytes(b'not a Windows memory image')
                records, warnings = memory.inspect_memory(
                    image, root / 'output', timeout=4, max_output=65536,
                    max_files=0, max_total_bytes=0)
                probe = ('passed_negative' if records and
                         records[0]['plugin'] == 'windows.info' and
                         records[0]['status'] == 'skipped' and warnings else 'failed')
        except Exception:
            probe = 'failed'
    try:
        installed = importlib.metadata.version('volatility3') if found else None
    except importlib.metadata.PackageNotFoundError:
        installed = None
    status = 'partial' if found else 'unavailable'
    engine = {'found': found, 'path': path if found else None,
              'version': installed, 'options_compatible': compatible,
              'required_data': 'matching_windows_image_and_symbols',
              'functional_probe': probe, 'status': status}
    operation = {'implemented': True, 'functional_probe': probe, 'status': status,
                 'reason': 'positive_memory_fixture_not_supplied' if found else 'volatility_unavailable'}
    return operation, engine


def _disk_probe(self_test):
    from .profiles.disk import ICAT, FLS, MMLS, inspect_disk
    from .profiles.disk_recovery import BINWALK, recover_disk
    tools = [shutil.which(path) for path in (MMLS, FLS, ICAT)]
    binwalk = shutil.which(BINWALK)
    probe = 'not_run'
    recovery_probe = 'not_run'
    if self_test and all(tools):
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                filesystem = bytearray(2880 * 512)
                filesystem[:3] = b'\xeb\x3c\x90'
                filesystem[3:11] = b'MSDOS5.0'
                struct.pack_into('<HBHBHHBHHHII', filesystem, 11, 512, 1, 1, 2, 224,
                                 2880, 0xf0, 9, 18, 2, 0, 0)
                filesystem[510:512] = b'\x55\xaa'
                for sector in (1, 10):
                    filesystem[sector * 512:sector * 512 + 5] = b'\xf0\xff\xff\xff\x0f'
                base = 19 * 512
                filesystem[base:base + 11] = b'PROBE   TXT'
                filesystem[base + 11] = 0x20
                struct.pack_into('<HI', filesystem, base + 26, 2, 5)
                filesystem[33 * 512:33 * 512 + 5] = b'probe'
                header = bytearray(64 * 512)
                struct.pack_into('<B3sB3sII', header, 446, 0, b'\0' * 3, 1,
                                 b'\0' * 3, 64, 2880)
                header[510:512] = b'\x55\xaa'
                source = root / 'probe.img'
                source.write_bytes(header + filesystem)
                records, warnings = inspect_disk(source, root / 'out',
                                                 target_paths=['PROBE.TXT'], timeout=5,
                                                 max_output=65536, max_files=1,
                                                 max_total_bytes=64)
                probe = ('passed' if not warnings and any(
                    row['kind'] == 'file' and row['offset_sectors'] == 64 and
                    row['path'].read_bytes() == b'probe' for row in records) else 'failed')
                if binwalk:
                    data = bytearray(source.read_bytes())
                    data[len(header) + base] = 0xe5
                    archive = io.BytesIO()
                    with zipfile.ZipFile(archive, 'w') as writer:
                        writer.writestr('probe.txt', b'carved probe')
                    source.write_bytes(data + archive.getvalue())
                    recovered, recovery_warnings = recover_disk(
                        source, root / 'recovery', timeout=5, max_output=65536,
                        max_files=2, max_total_bytes=65536)
                    recovery_probe = ('passed' if not recovery_warnings and
                                      any(row['kind'] == 'deleted_file' and
                                          row['path'].read_bytes() == b'probe' for row in recovered) and
                                      any(row['kind'] == 'carved_file' and row['format'] == 'zip' and
                                          row['path'].read_bytes() == archive.getvalue()
                                          for row in recovered) else 'failed')
        except Exception:
            probe = 'failed'
            recovery_probe = 'failed' if binwalk else 'not_run'
    status = 'ready' if probe == 'passed' else 'partial' if all(tools) else 'unavailable'
    operation = {'implemented': True, 'functional_probe': probe, 'status': status}
    version = _command([MMLS, '-V']) if tools[0] else None
    engine = {'found': all(tools), 'path': MMLS, 'fls_path': FLS, 'icat_path': ICAT,
              'version': version.stdout.decode('utf-8', 'replace').strip()[:120]
              if version and version.returncode == 0 else None,
              'options_compatible': all(tools), 'required_data': 'not_required',
              'functional_probe': probe, 'status': status}
    recovery = {'implemented': True, 'functional_probe': recovery_probe,
                'status': 'ready' if recovery_probe == 'passed' else
                          'partial' if all(tools) else 'unavailable'}
    binwalk_version = _command([BINWALK, '--version']) if binwalk else None
    binwalk_engine = {'found': bool(binwalk), 'path': BINWALK if binwalk else None,
                      'version': binwalk_version.stdout.decode('utf-8', 'replace').strip()[:120]
                      if binwalk_version and binwalk_version.returncode == 0 else None,
                      'options_compatible': bool(binwalk), 'required_data': 'not_required',
                      'functional_probe': recovery_probe,
                      'status': 'ready' if recovery_probe == 'passed' else
                                'partial' if binwalk else 'unavailable'}
    return operation, engine, recovery, binwalk_engine


def _elf_probe(self_test):
    if importlib.util.find_spec('elftools') is None:
        return {'implemented': True, 'functional_probe': 'not_run', 'status': 'unavailable',
                'reason': 'pyelftools_missing'}
    from .profiles.elf import inspect_elf
    probe = 'not_run'
    if self_test:
        report, _ = inspect_elf(Path(sys.executable).resolve())
        probe = 'passed' if report and report['architecture'] in ('x86-32', 'x86-64') else 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _binary_probe(self_test):
    if importlib.util.find_spec('elftools') is None or importlib.util.find_spec('pefile') is None:
        return {'implemented': True, 'functional_probe': 'not_run', 'status': 'unavailable',
                'reason': 'pyelftools_or_pefile_missing'}
    probe = 'not_run'
    if self_test:
        from .profiles.binary_static import inspect_binary
        sample = bytearray(512)
        sample[:2] = b'MZ'
        struct.pack_into('<I', sample, 0x3c, 0x80)
        sample[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HHIIIHH', sample, 0x84, 0x14c, 0, 0, 0, 0, 0xe0, 0x102)
        optional = 0x98
        for offset, format_, value in ((0, '<H', 0x10b), (28, '<I', 0x400000),
                                       (32, '<I', 0x1000), (36, '<I', 0x200),
                                       (56, '<I', 0x1000), (60, '<I', 0x200),
                                       (68, '<H', 3), (70, '<H', 0x100),
                                       (92, '<I', 16)):
            struct.pack_into(format_, sample, optional + offset, value)
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'probe.exe'
                target.write_bytes(sample)
                elf_report, _ = inspect_binary(Path(sys.executable).resolve())
                pe_report, _ = inspect_binary(target)
            probe = ('passed' if elf_report and pe_report and
                     elf_report['format'] == 'ELF' and pe_report['format'] == 'PE'
                     else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _rev_strings_probe(self_test):
    static = (importlib.util.find_spec('elftools') is not None and
              importlib.util.find_spec('capstone') is not None)
    executable = shutil.which('floss')
    help_result = _command([executable, '--help']) if executable else None
    json_mode = bool(help_result and help_result.returncode == 0 and
                     (b'--json' in help_result.stdout or b'-j' in help_result.stdout))
    probe = 'not_run'
    if self_test and static:
        try:
            from .profiles.rev_strings import _floss_records
            records, warnings = _floss_records({'strings': {'stack_strings': [
                {'string': 'probe', 'encoding': 'ASCII', 'function': 1,
                 'program_counter': 2, 'frame_offset': 3}]}}, 1)
            probe = 'passed' if not warnings and records[0]['data'] == b'probe' else 'failed'
        except Exception:
            probe = 'failed'
    engine = {'found': bool(executable), 'path': executable, 'version': None,
              'options_compatible': json_mode if executable else False,
              'required_data': 'embedded_signature_state_unverified' if executable else 'unavailable',
              'functional_probe': 'not_run',
              'status': 'partial' if executable and json_mode else 'unavailable',
              'reason': None if executable and json_mode else 'floss_missing_or_incompatible'}
    status = ('partial' if static or executable and json_mode else 'unavailable')
    operation = {'implemented': True, 'functional_probe': probe, 'status': status,
                 'reason': 'floss_missing; static_elf_fallback_available' if static and not executable
                           else 'backend_not_functionally_probed' if executable else
                           'static_and_floss_backends_missing'}
    return operation, engine


def _rev_powershell_probe(self_test):
    probe = 'not_run'
    if self_test:
        try:
            from .profiles.powershell import inspect_powershell
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'probe.ps1'
                source.write_text("'REV' + '11_PROBE'")
                records, warnings = inspect_powershell(source)
            probe = ('passed' if not warnings and any(
                row['data'] == b'REV11_PROBE' and row['state'] == 'candidate'
                for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe, 'status': 'partial',
            'reason': 'finite_literal_forms_only; dynamic_PowerShell_not_evaluated'}


def _rev_rules_probe(self_test):
    engines = {}
    for name, required, options, version_arg in (
            ('capa', 'explicit_compatible_rules_and_signatures', ('-j', '-r', '-s'), '--version'),
            ('yara', 'explicit_source_rules', ('-s', '-L', '-e'), '-v')):
        path = shutil.which(name)
        help_result = _command([path, '--help']) if path else None
        help_text = (help_result.stdout + help_result.stderr) if help_result else b''
        compatible = bool(path and help_result and help_result.returncode == 0 and
                          all(option.encode() in help_text for option in options))
        version_result = _command([path, version_arg]) if path else None
        version_lines = ((version_result.stdout + version_result.stderr).decode('utf-8', 'replace')
                         .splitlines() if version_result and version_result.returncode == 0 else [])
        engines[name] = {'found': bool(path), 'path': path,
                         'version': version_lines[0][:128] if version_lines else None,
                         'options_compatible': compatible, 'required_data': required,
                         'functional_probe': 'not_run',
                         'status': 'partial' if compatible and version_lines else 'unavailable',
                         'reason': 'rule_data_not_supplied' if compatible and version_lines else
                                   'tool_missing_or_incompatible'}
    operation = {'implemented': True, 'functional_probe': 'not_run',
                 'status': 'partial' if any(row['status'] == 'partial' for row in engines.values())
                           else 'unavailable',
                 'reason': 'explicit_compatible_rule_data_required'}
    return operation, engines


def _rev_packers_probe(self_test):
    upx, binwalk = shutil.which('upx'), shutil.which('binwalk')
    upx_help = _command([upx, '--help']) if upx else None
    options = ((upx_help.stdout + upx_help.stderr) if upx_help else b'')
    upx_compatible = bool(upx_help and upx_help.returncode == 0 and
                          all(flag in options for flag in (b'-t', b'-d', b'-o')))
    upx_version = _command([upx, '--version']) if upx else None
    upx_lines = ((upx_version.stdout + upx_version.stderr).decode('utf-8', 'replace').splitlines()
                 if upx_version and upx_version.returncode == 0 else [])
    probe = 'not_run'
    if self_test and binwalk:
        try:
            from .profiles.rev_packers import inspect_packers
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'nested.bin'
                source.write_bytes(b'HEADER' + gzip.compress(b'REV04_PROBE', mtime=0))
                records, _ = inspect_packers(source, Path(directory) / 'stage', timeout=5,
                                              binwalk_path=binwalk)
            probe = ('passed' if any(row['kind'] == 'signature-lead' and
                                    row['source_locator']['file_offset'] == 6 and
                                    not row['validated'] for row in records) else 'failed')
        except Exception:
            probe = 'failed'
    operation = {'implemented': True, 'functional_probe': probe,
                 'status': 'partial' if upx or binwalk else 'unavailable',
                 'reason': 'upx_missing; signature_leads_only' if not upx else
                           'real_upx_roundtrip_not_probed; signature_leads_only'}
    upx_engine = {'found': bool(upx), 'path': upx,
                  'version': upx_lines[0][:128] if upx_lines else None,
                  'options_compatible': upx_compatible,
                  'required_data': 'supported_packed_executable',
                  'functional_probe': 'not_run',
                  'status': 'partial' if upx_compatible else 'unavailable'}
    binwalk_engine = {'found': bool(binwalk), 'path': binwalk,
                      'version': None, 'options_compatible': bool(binwalk),
                      'required_data': 'not_required', 'functional_probe': probe,
                      'status': 'partial' if binwalk else 'unavailable',
                      'reason': 'signature_leads_only' if binwalk else 'binwalk_missing'}
    return operation, upx_engine, binwalk_engine


def _pyinstaller_probe(self_test):
    from .profiles.pyinstaller import COOKIE, ENTRY, MAGIC, inspect_pyinstaller
    probe = 'not_run'
    if self_test:
        try:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'probe.exe'
                payload = b'REV05_PROBE'
                name = b'probe.txt\0'
                entry_size = ENTRY.size + len(name)
                entry_size += -entry_size % 16
                toc = (ENTRY.pack(entry_size, 0, len(payload), len(payload), 0, b'x') +
                       name.ljust(entry_size - ENTRY.size, b'\0'))
                body = payload + toc
                source.write_bytes(b'MZ' + body + COOKIE.pack(
                    MAGIC, len(body) + COOKIE.size, len(payload), len(toc), 312,
                    b'libpython3.12.so'))
                records, warnings, inventory = inspect_pyinstaller(
                    source, Path(directory) / 'stage', max_members=2,
                    max_total_bytes=1024)
                probe = ('passed' if not warnings and len(records) == 1 and
                         records[0]['path'].read_bytes() == payload and
                         records[0]['offset'] == 2 and
                         inventory['carchive']['complete'] and
                         inventory['carchive']['entry_count'] == 1 else 'failed')
        except Exception:
            probe = 'failed'
    operation = {'implemented': True, 'functional_probe': probe, 'status': 'partial',
                 'reason': 'older_encrypted_pyz_and_foreign_bytecode_inspection_unsupported'}
    engine = {'found': True, 'path': inspect_pyinstaller.__code__.co_filename,
              'version': 'CArchive/PYZ static', 'options_compatible': True,
              'required_data': 'not_required', 'functional_probe': probe,
              'status': 'partial'}
    return operation, engine


def _java_android_probe(self_test):
    from .profiles.java_android import inspect_java_android
    java, javap, javac, jadx = (shutil.which(name) for name in
                                 ('java', 'javap', 'javac', 'jadx'))
    version = _command([java, '-XX:-UsePerfData', '-version']) if java else None
    javap_version = _command([javap, '-J-XX:-UsePerfData', '-version']) if javap else None
    java_ok = bool(version and version.returncode == 0)
    javap_ok = bool(javap_version and javap_version.returncode == 0)
    probe = 'not_run'
    if self_test:
        probe = 'failed'
        if java_ok and javap_ok and javac:
            try:
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / 'Probe.java'
                    source.write_text('public class Probe { static String clue() '
                                      '{ return "REV06_PROBE"; } }')
                    compiled = _command([javac, '-J-XX:-UsePerfData',
                                         '--release', '17', str(source)])
                    if compiled and compiled.returncode == 0:
                        archive = root / 'probe.jar'
                        with zipfile.ZipFile(archive, 'w') as jar:
                            jar.write(root / 'Probe.class', 'Probe.class')
                            jar.writestr('assets/probe.txt', b'REV06_RESOURCE')
                        rows, _ = inspect_java_android(archive, root / 'stage', timeout=5)
                        if (any(row['kind'] == 'resource' and
                                row['path'].read_bytes() == b'REV06_RESOURCE' for row in rows)
                                and any(row['kind'] == 'bytecode_listing' and
                                        b'REV06_PROBE' in row['path'].read_bytes() for row in rows)):
                            probe = 'passed'
            except Exception:
                pass
    java_lines = ((version.stdout + version.stderr).decode('utf-8', 'replace').splitlines()
                  if java_ok else [])
    javap_lines = ((javap_version.stdout + javap_version.stderr).decode('utf-8', 'replace').splitlines()
                   if javap_ok else [])
    operation = {'implemented': True, 'functional_probe': probe,
                 'status': 'partial',
                 'reason': ('dex_source_decompilation_unavailable' if java_ok and javap_ok else
                            'java_runtime_or_javap_unavailable; resources_only')}
    runtime = {'found': bool(java), 'path': java,
               'version': java_lines[0][:100] if java_lines else None,
               'options_compatible': java_ok, 'required_data': 'not_required',
               'functional_probe': probe, 'status': 'ready' if probe == 'passed' else 'partial'}
    disassembler = {'found': bool(javap), 'path': javap,
                    'version': javap_lines[0][:100] if javap_lines else None,
                    'options_compatible': javap_ok, 'required_data': 'supported_class_file',
                    'functional_probe': probe,
                    'status': 'ready' if probe == 'passed' else 'partial'}
    decompiler = {'found': bool(jadx), 'path': jadx, 'version': None,
                  'options_compatible': None, 'required_data': 'supported_dex',
                  'functional_probe': 'not_run', 'status': 'partial' if jadx else 'unavailable',
                  'reason': 'source_decompilation_not_configured' if jadx else 'tool_missing'}
    return operation, runtime, disassembler, decompiler


def _checker_probe(self_test):
    from .profiles.checker import inspect_checker
    spec = importlib.util.find_spec('angr')
    compiler = shutil.which('gcc')
    probe = 'not_run'
    detail = None
    if self_test and spec and compiler:
        probe = 'failed'
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'checker.c'
                binary = root / 'checker'
                source.write_text('''#include <stdio.h>
int main(int argc, char **argv) {
  if (argc == 2 && argv[1][0] == 'Q' && argv[1][1] == '\\0') {
    puts("REV07_PROBE"); return 0;
  }
  puts("REV07_FAIL"); return 1;
}''')
                built = _command([compiler, '-O0', '-fno-pie', '-no-pie',
                                  '-o', str(binary), str(source)])
                if built and built.returncode == 0:
                    report, warnings = inspect_checker(
                        binary, {'channel': 'argv', 'length': 1,
                                 'find': {'stdout': 'REV07_PROBE'},
                                 'avoid': {'stdout': 'REV07_FAIL'}},
                        execute_local=True, replay=True, timeout=30, max_steps=2500)
                    if (not warnings and report['status'] == 'validated_input' and
                            bytes.fromhex(report['candidate_hex']) == b'Q' and
                            report['replay']['returncode'] == 0):
                        probe = 'passed'
                    else:
                        detail = f"checker_{report['status']}: {report.get('reason') or report['replay'].get('problem') or 'unexpected_candidate'}"[:160]
                else:
                    detail = 'compiler_failed_or_timed_out'
        except Exception as error:
            detail = f'{type(error).__name__}_during_probe'
    operation = {'implemented': True, 'functional_probe': probe,
                 'status': 'partial' if spec else 'unavailable',
                 'reason': ('angr_missing' if not spec else
                            'compiler_missing_for_probe' if self_test and not compiler else
                            'functional_probe_failed' if probe == 'failed' else
                            'bounded_x86_elf_checker_only')}
    if detail:
        operation['probe_detail'] = detail
    engine = {'found': bool(spec), 'path': spec.origin if spec else None,
              'version': importlib.metadata.version('angr') if spec else None,
              'options_compatible': bool(spec),
              'required_data': 'selected_executable_linux_x86_elf_and_checker_hints',
              'functional_probe': probe,
              'status': 'ready' if probe == 'passed' else 'partial' if spec else 'unavailable'}
    return operation, engine


def _service_probe(self_test):
    from .profiles.service_transport import run_service
    probe = 'not_run'
    if self_test:
        script = ("import sys; sys.stdout.buffer.write(b'ready>'); "
                  "sys.stdout.buffer.flush(); "
                  "reply=sys.stdin.buffer.readline(); "
                  "sys.stdout.buffer.write(b'ACK:'+reply); sys.stdout.buffer.flush()")
        try:
            report, warnings = run_service({'transport': {'argv': [sys.executable, '-c', script]},
                                            'steps': [{'read': {'delimiter_hex': '3e'}},
                                                      {'write_hex': '676f0a'},
                                                      {'read': {'delimiter_hex': '0a'}}]},
                                           timeout=3, max_bytes=64, allow_local=True)
            probe = 'passed' if not warnings and report['status'] == 'complete' and (
                report['frames'][-1]['wire_hex'] == b'ACK:go\n'.hex()) else 'failed'
        except (OSError, ValueError):
            probe = 'failed'
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _arithmetic_probe(self_test):
    from .profiles.arithmetic_protocol import run_arithmetic
    probe = 'not_run'
    if self_test:
        listener = socket.socket()
        observed = []
        try:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(2)

            def serve():
                try:
                    with listener:
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(2)
                            conn.sendall(b'Q 1: (2 + 3) * 4\n')
                            reply = bytearray()
                            while len(reply) < 3:
                                chunk = conn.recv(3 - len(reply))
                                if not chunk:
                                    break
                                reply.extend(chunk)
                            observed.append(bytes(reply))
                            if observed[-1] == b'20\n':
                                conn.sendall(b'DONE probe\n')
                except OSError:
                    pass

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            protocol = {'transport': {'host': '127.0.0.1', 'port': listener.getsockname()[1]},
                        'framing': {'delimiter_hex': '0a'},
                        'question': {'prefix_ascii': 'Q ', 'separator_ascii': ': ',
                                     'suffix_ascii': '', 'first_id': 1, 'id_step': 1},
                        'completion': {'prefix_ascii': 'DONE ', 'min_suffix_bytes': 1},
                        'response': {'encoding': 'ascii_decimal', 'prefix_hex': '',
                                     'suffix_hex': '0a'}}
            report, warnings = run_arithmetic(protocol, timeout=2, max_rounds=1,
                                              max_bytes=128, max_frame_bytes=128)
            thread.join(2)
            probe = ('passed' if not warnings and not thread.is_alive() and
                     report['status'] == 'complete' and observed == [b'20\n'] else 'failed')
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            listener.close()
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def _service_inventory_probe(self_test):
    from .profiles.service_inventory import run_inventory
    probe = 'not_run'
    if self_test:
        listener = socket.socket()
        try:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)

            def serve():
                try:
                    with listener:
                        conn, _ = listener.accept()
                        with conn:
                            conn.sendall(b'inventory-probe\n')
                except OSError:
                    pass

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            report, warnings = run_inventory({'host': '127.0.0.1',
                                              'ports': [listener.getsockname()[1]]}, timeout=2)
            thread.join(2)
            probe = 'passed' if not warnings and not thread.is_alive() and (
                report['ports'][0]['response_hex'] == b'inventory-probe\n'.hex()) else 'failed'
        except (OSError, ValueError):
            probe = 'failed'
        finally:
            listener.close()
    return {'implemented': True, 'functional_probe': probe,
            'status': 'ready' if probe == 'passed' else 'partial'}


def doctor(profiles: list[str], self_test: bool = False) -> dict:
    """Inspect only integrated engines; planned engines remain explicitly unavailable."""
    selected = _profiles(profiles)
    planned = sorted({engine for profile in selected for engine in PROFILE_ENGINES[profile]})
    engines = {engine: _planned() for engine in planned
               if engine not in ("stdlib", "file", "cryptolib", "exif", "image", "qr", "tshark", "tsk", "zsteg", "stegseek", "pyelftools", "pefile", "ffmpeg", "multimon", "can", "volatility", "tesseract")}
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
    qr_probes = _qr_probe(self_test) if 'qr' in planned else None
    if 'qr' in planned:
        engines['qr'] = qr_probes[1]
    packet_probes = _packet_probe(self_test) if 'tshark' in planned else None
    if 'tshark' in planned:
        engines['tshark'] = packet_probes[1]
    disk_probes = _disk_probe(self_test) if 'tsk' in planned else None
    if 'tsk' in planned:
        engines['tsk'] = disk_probes[1]
    memory_probes = _memory_probe(self_test) if 'volatility' in planned else None
    if memory_probes:
        engines['volatility'] = memory_probes[1]
    if 'binwalk' in planned and disk_probes:
        engines['binwalk'] = disk_probes[3]
    media_probes = _media_probe(self_test) if 'ffmpeg' in planned else None
    if 'ffmpeg' in planned:
        engines['ffmpeg'] = media_probes[1]
    tone_probes = _tone_probe(self_test) if 'multimon' in planned else None
    if 'multimon' in planned:
        engines['multimon'] = tone_probes[2]
    sstv_probes = _sstv_probe(self_test) if 'sstv' in planned else None
    if 'sstv' in planned:
        engines['sstv'] = sstv_probes[1]
    ocr_probes = _ocr_probe(self_test) if 'tesseract' in planned else None
    if ocr_probes:
        engines['tesseract'] = ocr_probes[1]
    elf_probe = _elf_probe(self_test) if 'pyelftools' in planned else None
    if 'pyelftools' in planned:
        spec = importlib.util.find_spec('elftools')
        engines['pyelftools'] = {
            'found': spec is not None, 'path': spec.origin if spec else None,
            'version': importlib.metadata.version('pyelftools') if spec else None,
            'options_compatible': bool(spec), 'required_data': 'not_required',
            'functional_probe': elf_probe['functional_probe'], 'status': elf_probe['status']}
    binary_probe = _binary_probe(self_test) if 'malware_reversing' in selected else None
    rev_strings_probe = _rev_strings_probe(self_test) if 'malware_reversing' in selected else None
    rev_powershell_probe = _rev_powershell_probe(self_test) if 'malware_reversing' in selected else None
    rev_rules_probe = _rev_rules_probe(self_test) if 'malware_reversing' in selected else None
    rev_packers_probe = _rev_packers_probe(self_test) if 'malware_reversing' in selected else None
    pyinstaller_probe = _pyinstaller_probe(self_test) if 'malware_reversing' in selected else None
    java_android_probe = _java_android_probe(self_test) if 'malware_reversing' in selected else None
    checker_probe = _checker_probe(self_test) if 'malware_reversing' in selected else None
    if 'floss' in planned:
        engines['floss'] = rev_strings_probe[1]
    if rev_rules_probe:
        engines.update(rev_rules_probe[1])
    if rev_packers_probe:
        engines['upx'] = rev_packers_probe[1]
        if not disk_probes:
            engines['binwalk'] = rev_packers_probe[2]
    if pyinstaller_probe:
        engines['pyinstaller'] = pyinstaller_probe[1]
    if java_android_probe:
        engines['java'] = java_android_probe[1]
        engines['javap'] = java_android_probe[2]
        engines['jadx'] = java_android_probe[3]
    if checker_probe:
        engines['angr'] = checker_probe[1]
    if 'pefile' in planned:
        spec = importlib.util.find_spec('pefile')
        engines['pefile'] = {
            'found': spec is not None, 'path': spec.origin if spec else None,
            'version': importlib.metadata.version('pefile') if spec else None,
            'options_compatible': bool(spec), 'required_data': 'not_required',
            'functional_probe': binary_probe['functional_probe'],
            'status': 'ready' if spec and binary_probe['status'] == 'ready' else
                      'partial' if spec else 'unavailable'}
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
    sevenzip_probe = _sevenzip_probe(self_test) if 'documents' in selected else None
    if sevenzip_probe:
        engines['archive'] = sevenzip_probe[1]
    zsteg_probes = _zsteg_probe(self_test) if 'zsteg' in planned else None
    if 'zsteg' in planned:
        engines['zsteg'] = zsteg_probes[1]
    stegseek_probes = _stegseek_probe(self_test) if 'stegseek' in planned else None
    if 'stegseek' in planned:
        engines['stegseek'] = stegseek_probes[1]
    operations = {}
    if "encoding" in selected:
        operations["encoding.decode"] = _encoding_probe(self_test)
        operations["encoding.xor_one"] = _xor_probe(self_test)
        operations["encoding.rsa_literals"] = _rsa_probe(self_test)
        operations["encoding.aes_declared"] = _symmetric_probe(self_test)
        operations["encoding.password_hashes"] = _hash_probe(self_test)
    if "documents" in selected:
        operations["documents.zip"] = _zip_probe(self_test)
        operations["documents.7z"] = sevenzip_probe[0]
        operations["documents.tar"] = _tar_probe(self_test)
        operations["documents.mime"] = _mime_probe(self_test)
        operations["documents.pdf"] = _pdf_probe(self_test)
        operations["documents.office"] = _office_probe(self_test)
    if "images" in selected:
        operations["images.png_tail"] = _png_probe(self_test)
        operations["images.jpeg_tail"] = _jpeg_probe(self_test)
        operations["images.metadata"] = image_probes[0]
        operations["images.views"] = image_probes[1]
        operations["images.zsteg"] = zsteg_probes[0]
        operations["images.stegseek"] = stegseek_probes[0]
        operations["images.qr"] = qr_probes[0]
    if "osint" in selected:
        operations["osint.metadata"] = image_probes[0]
        operations["osint.identifiers"] = _osint_ids_probe(self_test)
        operations["osint.snapshot_trail"] = _osint_snapshot_probe(self_test)
    if "can_misc" in selected:
        operations['can_misc.log'] = _can_probe(self_test)
        operations['can_misc.dbc'], engine = _can_dbc_probe(self_test)
        operations['can_misc.arithmetic_protocol'] = _arithmetic_probe(self_test)
        engines['can'] = engine or {
            'found': False, 'path': None, 'version': None,
            'options_compatible': False, 'required_data': 'supplied_dbc_or_arxml',
            'functional_probe': 'not_run', 'status': 'unavailable',
            'reason': 'cantools_missing'}
    if "packets" in selected:
        operations['packets.metadata'] = packet_probes[0]
        operations['packets.objects'] = _packet_object_probe(self_test)
        operations['packets.streams'] = _packet_stream_probe(self_test)
        operations['packets.tls_keylog'] = _packet_tls_probe(self_test)
    if "audio_video" in selected:
        operations['audio_video.media'] = media_probes[0]
        operations['audio_video.dtmf'] = tone_probes[0]
        operations['audio_video.morse_afsk'] = tone_probes[1]
        operations['audio_video.sstv'] = sstv_probes[0]
        operations['audio_video.ocr'] = ocr_probes[0]
    if "disk_memory" in selected:
        operations['disk_memory.disk_image'] = disk_probes[0]
        operations['disk_memory.recovery'] = disk_probes[2]
        operations['disk_memory.sqlite'] = _sqlite_probe(self_test)
        operations['disk_memory.os_artifacts'] = _os_artifact_probe(self_test)
        operations['disk_memory.windows_memory'] = memory_probes[0]
    if "pwn_services" in selected:
        operations['pwn_services.elf_static'] = elf_probe
        operations['pwn_services.service_transport'] = _service_probe(self_test)
        operations['pwn_services.service_inventory'] = _service_inventory_probe(self_test)
    if "malware_reversing" in selected:
        operations['malware_reversing.binary_static'] = binary_probe
        operations['malware_reversing.obfuscated_strings'] = rev_strings_probe[0]
        operations['malware_reversing.powershell_constants'] = rev_powershell_probe
        operations['malware_reversing.rule_matching'] = rev_rules_probe[0]
        operations['malware_reversing.packers'] = rev_packers_probe[0]
        operations['malware_reversing.pyinstaller'] = pyinstaller_probe[0]
        operations['malware_reversing.java_android'] = java_android_probe[0]
        operations['malware_reversing.checker'] = checker_probe[0]
    if "web" in selected:
        operations['web.static_inventory'] = _web_static_probe(self_test)
        operations['web.jwt_local'] = _web_jwt_probe(self_test)
        operations['web.discovery'] = _web_discovery_probe(self_test)
        operations['web.sql_assessment'] = _web_sql_probe(self_test)
        operations['web.selected_leads'] = _web_leads_probe(self_test)
        operations['web.workflow_comparison'] = _web_workflow_probe(self_test)
    status = "partial" if any(value["status"] != "ready" for value in engines.values()) or any(
        value["status"] != "ready" for value in operations.values()
    ) else "ready"
    return {"status": status, "profiles": selected, "engines": engines, "operations": operations}


def setup(profiles: list[str]) -> dict:
    """Install the Python core locally and probe requested operations inside it."""
    selected = _profiles(profiles)
    from .setup_env import prepare
    prepared = prepare()
    if prepared['status'] != 'ready':
        return {**prepared, 'profiles': selected}
    command = [prepared['python'], str(Path(__file__).resolve().parents[1] / 'autosolve.py'),
               '--json', 'doctor', '--profiles', *selected, '--self-test']
    try:
        run = subprocess.run(command, capture_output=True, timeout=180, check=False)
        result = json.loads(run.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {**prepared, 'status': 'partial', 'profiles': selected,
                'reason': 'installed_environment_doctor_failed'}
    if run.returncode not in (0, 3) or result.get('status') not in ('ready', 'partial'):
        return {**prepared, 'status': 'partial', 'profiles': selected,
                'reason': 'installed_environment_doctor_failed'}
    return {**result, 'setup': prepared, 'installed': prepared['installed'],
            'python': prepared['python']}
