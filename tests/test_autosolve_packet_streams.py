"""Independent wire fixtures for bounded TCP stream reconstruction."""

import json
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import packet_streams


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    words = struct.unpack(f'!{len(data) // 2}H', data)
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(src, dst, src_port, dst_port, seq, ack, flags, payload=b''):
    source, target = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack('!HHIIHHHH', src_port, dst_port, seq, ack, 0x5000 | flags,
                      8192, 0, 0) + payload
    tcp = tcp[:16] + struct.pack('!H', checksum(source + target
          + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6,
                     0, source, target)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800') + ip + tcp


def pcap(frames):
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for number, item in enumerate(frames):
        result += struct.pack('<IIII', 1700000000 + number, 0, len(item), len(item)) + item
    return bytes(result)


class TcpStreamTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'wire.pcap'
        self.client, self.server = '192.0.2.31', '192.0.2.32'

    def packet(self, seq, flags=0x18, payload=b'', *, reverse=False, src_port=40123):
        if reverse:
            return frame(self.server, self.client, 8080, src_port, seq, 0,
                         flags, payload)
        return frame(self.client, self.server, src_port, 8080, seq, 0,
                     flags, payload)

    def inspect(self, **limits):
        settings = {'timeout': 5, 'max_output': 1000000,
                    'max_streams': 8, 'max_bytes': 100000}
        settings.update(limits)
        return packet_streams.reassemble_tcp(self.source, **settings)

    def test_out_of_order_and_identical_retransmission_yield_exact_bytes(self):
        self.source.write_bytes(pcap([
            self.packet(100, 0x02),
            self.packet(900, 0x12, reverse=True),
            self.packet(105, payload=b'EF'),
            self.packet(101, payload=b'AB'),
            self.packet(103, payload=b'CD'),
            self.packet(101, payload=b'AB'),
            self.packet(107, 0x11),
        ]))
        rows, warnings = self.inspect()
        direction = next(row for row in rows if row['src_address'] == self.client)
        self.assertEqual(warnings, [])
        self.assertEqual(direction['data'], b'ABCDEF')
        self.assertTrue(direction['complete'])
        self.assertEqual(direction['stream'], 0)
        self.assertEqual(direction['direction'], 0)
        self.assertEqual(direction['frames'], [1, 3, 4, 5, 6, 7])
        self.assertEqual(direction['retransmissions'], [6])
        self.assertEqual(direction['gaps'], [])
        self.assertEqual(direction['conflicts'], [])
        self.assertEqual(direction['sequence_start'], 101)
        self.assertEqual(direction['sequence_end'], 107)

    def test_different_boundaries_and_reused_ports_stay_in_separate_streams(self):
        self.source.write_bytes(pcap([
            self.packet(10, 0x02), self.packet(100, 0x12, reverse=True),
            self.packet(11, payload=b'ONE'), self.packet(14, 0x11),
            self.packet(1000, 0x02), self.packet(2000, 0x12, reverse=True),
            self.packet(1001, payload=b'T'), self.packet(1002, payload=b'WO'),
            self.packet(1004, 0x11),
        ]))
        rows, warnings = self.inspect()
        complete = [row for row in rows if row['complete'] and row['src_address'] == self.client]
        self.assertEqual([(row['stream'], row['data']) for row in complete],
                         [(0, b'ONE'), (1, b'TWO')])
        self.assertEqual(warnings, [])

    def test_reset_connection_does_not_claim_complete_and_new_session_isolated(self):
        self.source.write_bytes(pcap([
            self.packet(10, 0x02), self.packet(11, payload=b'OLD'),
            self.packet(14, 0x14),
            self.packet(100, 0x02), self.packet(101, payload=b'NEW'),
            self.packet(104, 0x11),
        ]))
        rows, _ = self.inspect()
        client_rows = [row for row in rows if row['src_address'] == self.client]
        self.assertEqual([(row['stream'], row['complete']) for row in client_rows],
                         [(0, False), (1, True)])
        self.assertNotIn('data', client_rows[0])
        self.assertEqual(client_rows[1]['data'], b'NEW')

    def test_missing_segment_and_conflicting_retransmission_never_publish_bytes(self):
        self.source.write_bytes(pcap([
            self.packet(100, 0x02), self.packet(101, payload=b'AB'),
            self.packet(105, payload=b'EF'), self.packet(107, 0x11),
            self.packet(101, payload=b'XY'),
        ]))
        rows, warnings = self.inspect()
        direction = next(row for row in rows if row['src_address'] == self.client)
        self.assertFalse(direction['complete'])
        self.assertNotIn('data', direction)
        self.assertEqual(direction['gaps'], [{'start': 103, 'end': 105}])
        self.assertEqual(direction['conflicts'], [5])
        self.assertTrue(any('incomplete' in item for item in warnings))

    def test_capture_without_syn_is_partial_even_if_payload_reaches_fin(self):
        self.source.write_bytes(pcap([self.packet(101, payload=b'BODY'),
                                      self.packet(105, 0x11)]))
        rows, _ = self.inspect()
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]['complete'])
        self.assertIn('SYN not captured', rows[0]['reasons'])
        self.assertNotIn('data', rows[0])

    def test_byte_budget_applies_across_directions(self):
        self.source.write_bytes(pcap([
            self.packet(100, 0x02), self.packet(900, 0x12, reverse=True),
            self.packet(101, payload=b'ABC'), self.packet(104, 0x11),
            self.packet(901, payload=b'XYZ', reverse=True),
            self.packet(904, 0x11, reverse=True),
        ]))
        rows, warnings = self.inspect(max_bytes=4)
        self.assertEqual(rows[0]['data'], b'ABC')
        self.assertFalse(rows[1]['complete'])
        self.assertNotIn('data', rows[1])
        self.assertTrue(any('limit' in item for item in warnings))

    def test_ambiguous_endpoint_binding_never_joins_bytes(self):
        common = {'stream': 0, 'endpoint': (self.client, 40123),
                  'seq': 100, 'syn': False, 'fin': False, 'rst': False,
                  'truncated': False}
        rows = [{**common, 'frame': 1, 'target': (self.server, 8080),
                 'payload': b'AB'},
                {**common, 'frame': 2, 'target': ('192.0.2.99', 8080),
                 'seq': 102, 'payload': b'CD'}]
        with mock.patch.object(packet_streams, '_tshark_rows', return_value=(rows, [])):
            result, warnings = self.inspect()
        self.assertEqual(result, [])
        self.assertTrue(any('inconsistent endpoints' in item for item in warnings))

    def test_bounds_and_missing_engine_fail_closed(self):
        self.source.write_bytes(pcap([self.packet(100, 0x02),
                                      self.packet(101, payload=b'ABC'),
                                      self.packet(104, 0x11)]))
        rows, warnings = packet_streams.reassemble_tcp(
            self.source, timeout=5, max_output=1000000, max_streams=8, max_bytes=2)
        self.assertFalse(any(row.get('complete') for row in rows))
        self.assertTrue(any('limit' in item for item in warnings))
        with mock.patch.object(packet_streams, 'TSHARK', '/no/such/tshark'):
            self.assertIn('unavailable', self.inspect()[1][0])

    def test_public_cli_publishes_only_complete_stream_and_reuses_job(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'

        def command(*args):
            result = subprocess.run([sys.executable, '-B', str(script), '--json', *map(str, args)],
                                    text=True, capture_output=True, timeout=60)
            self.assertIn(result.returncode, (0, 3), result.stderr + result.stdout)
            return json.loads(result.stdout)

        payload = b'flag{NET03_CLI_EXACT}'
        self.source.write_bytes(pcap([self.packet(100, 0x02),
                                      self.packet(101, payload=payload),
                                      self.packet(101 + len(payload), 0x11)]))
        run = Path(command('analyze', self.source, '--category', 'packets',
                           '--budget', 30, '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'packet-streams']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(manifest['coverage']['NET03']['status'], 'ran')
        child = next(item for item in manifest['artifacts']
                     if (item.get('source_locator') or {}).get('tcp_stream') == 0)
        self.assertEqual(Path(child['path']).read_bytes(), payload)
        self.assertEqual(child['source_locator']['sequence_start'], 101)
        self.assertTrue(any(item['tag'] == 'TCP stream' and item['current']
                            for item in manifest['intelligence']))

        command('resume', run, '--budget', 30)
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in resumed['jobs']
                              if job['adapter_id'] == 'packet-streams']), 1)
        self.assertTrue(next(item for item in resumed['artifacts']
                             if item['id'] == child['id'])['current'])

        self.source.write_bytes(pcap([self.packet(100, 0x02),
                                      self.packet(101, payload=b'AB'),
                                      self.packet(105, payload=b'EF'),
                                      self.packet(107, 0x11)]))
        partial = Path(command('analyze', self.source, '--category', 'packets',
                               '--budget', 30, '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((partial / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['NET03']['status'], 'truncated')
        self.assertFalse(any((item.get('source_locator') or {}).get('tcp_stream') == 0
                             for item in manifest['artifacts']))
        job = next(job for job in manifest['jobs'] if job['adapter_id'] == 'packet-streams')
        evidence = json.loads(Path(job['records_path']).read_text())
        self.assertEqual(evidence[0]['gaps'], [{'start': 103, 'end': 105}])
        self.assertNotIn('data', evidence[0])

        command('resume', run, '--budget', 30)
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(item for item in changed['artifacts']
                              if item['id'] == child['id'])['current'])
        self.assertFalse(any(item['job_id'] == jobs[0]['id'] and item['current']
                             for item in changed['intelligence']))


if __name__ == '__main__':
    unittest.main()
