import gzip
import hashlib
import io
import os
import socket
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import packet_objects


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    words = struct.unpack(f'!{len(data) // 2}H', data)
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(src, dst, sport, dport, seq, ack, flags, payload=b''):
    source, target = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack('!HHIIHHHH', sport, dport, seq, ack, 0x5000 | flags, 8192, 0, 0)
    pseudo = source + target + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp + payload)) + tcp[18:] + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp),
                     1, 0, 64, 6, 0, source, target)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return b'\0\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\0' + ip + tcp


def pcap(frames):
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, item in enumerate(frames):
        result += struct.pack('<IIII', 1700000000 + index, 0, len(item), len(item)) + item
    return bytes(result)


def transaction(client_port, body, *, filename='bundle.zip', encoding=None,
                declared_length=None, omit_tail=False):
    client, server, port = '198.51.100.10', '198.51.100.20', 19091
    request = f'GET /{filename} HTTP/1.1\r\nHost: example.invalid\r\n\r\n'.encode()
    length = len(body) if declared_length is None else declared_length
    header = (f'HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n'
              + (f'Content-Encoding: {encoding}\r\n' if encoding else '')
              + '\r\n').encode()
    payload = header + body
    midpoint = len(header) + max(1, len(body) // 2)
    pieces = [payload[:midpoint]] + ([] if omit_tail else [payload[midpoint:]])
    rows = [frame(client, server, client_port, port, 1000, 0, 2),
            frame(server, client, port, client_port, 2000, 1001, 18),
            frame(client, server, client_port, port, 1001, 2001, 16),
            frame(client, server, client_port, port, 1001, 2001, 24, request)]
    seq = 2001
    for piece in pieces:
        rows.append(frame(server, client, port, client_port, seq,
                          1001 + len(request), 24, piece))
        seq += len(piece)
    return rows


class PacketObjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'input.pcap'
        self.output = self.root / 'private' / 'objects'

    def export(self, **limits):
        return packet_objects.export_http_objects(self.source, self.output,
                                                  timeout=5, **limits)

    def test_complete_chunked_archive_has_exact_bytes_and_response_reference(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as writer:
            writer.writestr('note.txt', b'INDEPENDENT-FIXTURE\x00\xff')
        body = archive.getvalue()
        self.source.write_bytes(pcap(transaction(41000, body)))
        identity = hashlib.sha256(self.source.read_bytes()).hexdigest()
        records, warnings = self.export()
        self.assertEqual(warnings, [])
        self.assertEqual(len(records), 1)
        row = records[0]
        self.assertEqual(row['path'].read_bytes(), body)
        self.assertEqual(row['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(row['packet'], 6)
        self.assertEqual(row['tcp_stream'], 0)
        self.assertEqual(row['source_locator']['request_packet'], 4)
        self.assertEqual(row['source_locator']['uri'], 'http://example.invalid/bundle.zip')
        self.assertTrue(row['length_verified'])
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), identity)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_held_out_gzip_and_duplicate_filenames_keep_exact_distinct_bodies(self):
        first = b'A' * 40 + b'\0\xff'
        second = b'B' * 55 + b'\0\xfe'
        frames = transaction(41000, gzip.compress(first, mtime=0), filename='same.bin',
                             encoding='gzip') + transaction(41001, second, filename='same.bin')
        self.source.write_bytes(pcap(frames))
        rows, warnings = self.export()
        self.assertEqual(len(rows), 2, warnings)
        self.assertEqual({row['path'].read_bytes() for row in rows}, {first, second})
        self.assertEqual({row['tcp_stream'] for row in rows}, {0, 1})
        self.assertEqual({row['source_locator']['uri'] for row in rows},
                         {'http://example.invalid/same.bin'})
        self.assertEqual(len({row['name'] for row in rows}), 2)
        self.assertTrue(any('wire completeness' in warning for warning in warnings))

    def test_missing_tail_and_invalid_content_length_are_never_published(self):
        for case, frames in enumerate((transaction(41000, b'WILL-NOT-FINISH', omit_tail=True),
                                       transaction(41000, b'BAD-LENGTH', declared_length='invalid'))):
            with self.subTest(case=case):
                self.output = self.root / f'out-{case}'
                self.source.write_bytes(pcap(frames))
                rows, warnings = self.export()
                self.assertEqual(rows, [])
                self.assertTrue(warnings)

    def test_limits_and_unsafe_output_are_rejected(self):
        self.source.write_bytes(pcap(transaction(41000, b'1234567890')))
        rows, warnings = self.export(max_total_bytes=5)
        self.assertEqual(rows, [])
        self.assertTrue(any('limit' in warning for warning in warnings))
        self.output = self.root / 'nonempty'
        self.output.mkdir()
        (self.output / 'existing').write_bytes(b'do not overwrite')
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual((self.output / 'existing').read_bytes(), b'do not overwrite')
        self.output = self.root / 'linked'
        self.output.symlink_to(self.root)
        with self.assertRaises(ValueError):
            self.export()
        self.output.unlink()
        self.output = self.root / 'fresh'
        with mock.patch.object(packet_objects, 'TSHARK', str(self.root / 'missing')):
            rows, warnings = self.export()
        self.assertEqual(rows, [])
        self.assertTrue(any('unavailable' in warning for warning in warnings))

    def test_symlinked_export_is_never_published_or_followed(self):
        self.source.write_bytes(pcap(transaction(41000, b'SAFE-BODY')))
        outside = self.root / 'outside'
        outside.write_bytes(b'outside stays private')
        real_run = packet_objects._run

        def fake_export(*args, **kwargs):
            if '--export-objects' in args[0]:
                (self.output / 'objects' / 'linked').symlink_to(outside)
                return b'', None
            return real_run(*args, **kwargs)

        with mock.patch.object(packet_objects, '_run', side_effect=fake_export):
            rows, warnings = self.export()
        self.assertEqual(rows, [])
        self.assertTrue(any('unsafe' in warning for warning in warnings))
        self.assertEqual(outside.read_bytes(), b'outside stays private')

    def test_source_output_and_object_count_limits_are_explicit(self):
        self.source.write_bytes(pcap(transaction(41000, b'FIRST') +
                                     transaction(41001, b'SECOND', filename='other.bin')))
        for index, limits in enumerate(({'max_source_bytes': 10},
                                        {'max_output': 100},
                                        {'max_objects': 1})):
            with self.subTest(limits=limits):
                self.output = self.root / f'limited-{index}'
                rows, warnings = self.export(**limits)
                self.assertEqual(rows, [])
                self.assertTrue(any('limit' in warning for warning in warnings), warnings)

    def test_timeout_stops_tshark(self):
        self.source.write_bytes(pcap([]))
        marker = self.root / 'pid'
        slow = self.root / 'slow-tshark'
        slow.write_text('#!/usr/bin/python3\nimport os,time\n'
                        + f'open({str(marker)!r}, "w").write(str(os.getpid()))\n'
                        + 'time.sleep(10)\n')
        slow.chmod(0o700)
        with mock.patch.object(packet_objects, 'TSHARK', str(slow)):
            rows, warnings = packet_objects.export_http_objects(
                self.source, self.output, timeout=.2)
        self.assertEqual(rows, [])
        self.assertTrue(any('timed out' in warning for warning in warnings))
        if marker.exists():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
