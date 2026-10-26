import hashlib
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import packets


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "core"


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv4(src, dst, protocol, payload):
    source, target = (socket.inet_aton(address) for address in (src, dst))
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                         64, protocol, 0, source, target)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + header + payload


def udp(src_port, dst_port, payload):
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def tcp(src, dst, src_port, dst_port, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack,
                         0x5000 | flags, 8192, 0, 0)
    source, target = (socket.inet_aton(address) for address in (src, dst))
    pseudo = source + target + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    code = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", code) + header[18:] + payload


def pcap(frames, linktype=1):
    capture = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
    for index, frame in enumerate(frames):
        capture += struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame
    return bytes(capture)


def pcapng(frame):
    section = struct.pack("<IIIHHqI", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    padded = frame + b"\0" * (-len(frame) % 4)
    length = 32 + len(padded)
    enhanced = struct.pack("<IIIIIII", 6, length, 0, 0, 1, len(frame), len(frame))
    return section + interface + enhanced + padded + struct.pack("<I", length)


class PacketInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.pcap"

    def inspect(self, limit=100000):
        return packets.inspect_pcap(self.source, timeout=5, max_output=limit)

    def test_independent_dns_http_and_unrelated_packets_keep_frame_oracles(self):
        client, server = "198.51.100.10", "198.51.100.20"
        domain = b"\x07fixture\x07invalid\0"
        question = domain + struct.pack("!HH", 1, 1)
        query = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + question
        answer = (struct.pack("!HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + question
                  + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
                  + socket.inet_aton("203.0.113.9"))
        request = b"GET /alpha HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        frames = [
            ipv4(client, server, 17, udp(53000, 53, query)),
            ipv4(server, client, 17, udp(53, 53000, answer)),
            ipv4(client, server, 6, tcp(client, server, 41000, 80, 100, 0, 2)),
            ipv4(server, client, 6, tcp(server, client, 80, 41000, 500, 101, 18)),
            ipv4(client, server, 6, tcp(client, server, 41000, 80, 101, 501, 16)),
            ipv4(client, server, 6, tcp(client, server, 41000, 80, 101, 501, 24, request)),
            ipv4(server, client, 6, tcp(server, client, 80, 41000, 501,
                                      101 + len(request), 24, response)),
            ipv4(client, "198.51.100.30", 1, b"\x08\x00\x00\x00\0\0\0\0"),
        ]
        self.source.write_bytes(pcap(frames))
        original = hashlib.sha256(self.source.read_bytes()).hexdigest()
        rows, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual([row["packet"] for row in rows], list(range(1, 9)))
        self.assertEqual(rows[0]["dns"], {"queries": ["fixture.invalid"]})
        self.assertEqual(rows[1]["dns"], {"queries": ["fixture.invalid"],
                                          "a": ["203.0.113.9"]})
        self.assertEqual(rows[5]["http"], {"method": "GET", "host": "fixture.invalid",
                                           "uri": "/alpha"})
        self.assertEqual(rows[6]["http"]["status"], "200")
        self.assertEqual((rows[5]["src_address"], rows[5]["dst_address"],
                          rows[5]["src_port"], rows[5]["dst_port"], rows[5]["tcp_stream"]),
                         (client, server, 41000, 80, 0))
        self.assertEqual(rows[7]["locator"], "frame 8")
        self.assertNotIn("http", rows[7])
        self.assertTrue(all(row["source"] == str(self.source) and
                            row["tool"] == "/usr/bin/tshark" for row in rows))
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), original)

    def test_held_out_core_capture_and_nonstandard_port_keep_exact_references(self):
        for filename in ("http.pcap", "http-port19091.pcap"):
            with self.subTest(filename=filename):
                self.source.write_bytes((EXAMPLES / filename).read_bytes())
                rows, warnings = self.inspect()
                self.assertEqual(warnings, [])
                request = next(row for row in rows if row.get("http", {}).get("method") == "GET")
                self.assertEqual(request["http"]["uri"], "/report.txt" if filename == "http.pcap"
                                 else "/payload.bin")
                self.assertEqual(request["locator"], "frame 4")
                self.assertEqual(request["tcp_stream"], 0)
                self.assertEqual(request["dst_port"], 80 if filename == "http.pcap" else 19091)
                self.assertEqual(request["src_address"],
                                 "192.0.2.1" if filename == "http.pcap" else "192.0.2.11")

    def test_ipv6_pcapng_interface_keeps_packet_and_endpoint(self):
        src, dst = "2001:db8::10", "2001:db8::53"
        name = b"\x04ipv6\x07example\0"
        dns = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 28, 1)
        udp_packet = udp(53001, 53, dns)
        source, target = (socket.inet_pton(socket.AF_INET6, address) for address in (src, dst))
        pseudo = source + target + struct.pack("!I3xB", len(udp_packet), 17)
        udp_packet = udp_packet[:6] + struct.pack("!H", checksum(pseudo + udp_packet)) + dns
        ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(udp_packet), 17, 64, source, target)
        frame = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x86\xdd" + ipv6 + udp_packet
        self.source.write_bytes(pcapng(frame))
        rows, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["locator"], rows[0]["src_address"], rows[0]["dst_address"]),
                         ("frame 1", src, dst))
        self.assertEqual(rows[0]["dns"], {"queries": ["ipv6.example"]})

    def test_missing_tcp_segment_and_physically_truncated_capture_are_labeled(self):
        self.source.write_bytes((EXAMPLES / "http-incomplete.pcap").read_bytes())
        rows, warnings = self.inspect()
        self.assertEqual(rows[3]["http"]["uri"], "/report.txt")
        self.assertTrue(any("frame 7 TCP stream 0" in warning and "incomplete" in warning
                            for warning in warnings))
        self.assertIn("lost_segment", rows[6]["tcp_analysis"])
        self.assertFalse(any(row.get("http", {}).get("status") == "200" for row in rows))

        self.source.write_bytes((EXAMPLES / "http.pcap").read_bytes()[:-15])
        rows, warnings = self.inspect()
        self.assertEqual(rows[-1]["locator"], "frame 8")
        self.assertTrue(any("capture may be incomplete" in warning for warning in warnings))

        frame = ipv4("198.51.100.10", "198.51.100.20", 17, udp(1000, 1001, b"test"))
        clipped = bytearray(pcap([frame]))
        struct.pack_into("<I", clipped, 24 + 12, len(frame) + 10)
        self.source.write_bytes(clipped)
        rows, warnings = self.inspect()
        self.assertEqual((rows[0]["captured_length"], rows[0]["wire_length"]),
                         (len(frame), len(frame) + 10))
        self.assertIn("frame 1: packet data truncated by capture", warnings)

    def test_unsupported_link_type_and_output_limit_do_not_claim_complete_inventory(self):
        self.source.write_bytes(pcap([b"opaque bytes"], linktype=999))
        rows, warnings = self.inspect()
        self.assertEqual(rows, [])
        self.assertTrue(any("unsupported capture" in warning for warning in warnings))
        self.source.write_bytes((EXAMPLES / "http.pcap").read_bytes())
        rows, warnings = self.inspect(limit=200)
        self.assertTrue(any("output limit" in warning and "incomplete" in warning
                            for warning in warnings))
        self.assertLess(len(rows), 9)
        with self.assertRaises(ValueError):
            self.inspect(limit=0)

    def test_missing_engine_and_timeout_have_explicit_warnings(self):
        self.source.write_bytes(pcap([]))
        with mock.patch.object(packets, "TSHARK", str(self.root / "absent")):
            self.assertIn("TShark unavailable", self.inspect()[1][0])
        slow = self.root / "slow"
        slow.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(2)\n")
        slow.chmod(0o700)
        with mock.patch.object(packets, "TSHARK", str(slow)):
            rows, warnings = packets.inspect_pcap(self.source, timeout=0.05, max_output=1000)
        self.assertEqual(rows, [])
        self.assertTrue(any("timed out" in warning for warning in warnings))

    def test_literal_pipe_txt_and_nested_ip_addresses_preserve_occurrences(self):
        question = b'\x07example\x04test\x00' + struct.pack('!HH', 16, 1)
        answer = (struct.pack('!HHHHHH', 1, 0x8180, 1, 1, 0, 0) + question
                  + b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 30, 4) + b'\x03A|B')
        dns_frame = ipv4('192.0.2.53', '192.0.2.1', 17, udp(53, 12345, answer))
        inner = ipv4('203.0.113.1', '203.0.113.2', 6,
                     tcp('203.0.113.1', '203.0.113.2', 12345, 80, 0, 0, 2))[14:]
        tunnel = ipv4('198.51.100.1', '198.51.100.2', 4, inner)
        self.source.write_bytes(pcap([dns_frame, tunnel]))
        rows, warnings = self.inspect()
        self.assertEqual(rows[0]['dns']['txt'], ['A|B'])
        self.assertEqual(rows[1]['src_address'], '203.0.113.1')
        self.assertEqual(rows[1]['dst_address'], '203.0.113.2')
        self.assertEqual(rows[1]['src_addresses'], ['198.51.100.1', '203.0.113.1'])
        self.assertTrue(any('nested IP endpoints' in warning for warning in warnings))

    def test_mixed_ipv4_ipv6_tunnel_keeps_inner_endpoint(self):
        source = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        target = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        segment = struct.pack('!HHIIHHHH', 12345, 80, 0, 0, 0x5002, 8192, 0, 0)
        inner = struct.pack('!IHBB16s16s', 6 << 28, len(segment), 6, 64, source, target) + segment
        self.source.write_bytes(pcap([ipv4('198.51.100.1', '198.51.100.2', 41, inner)]))
        rows, warnings = self.inspect()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['src_address'], '2001:db8::1')
        self.assertEqual(rows[0]['dst_address'], '2001:db8::2')
        self.assertEqual(rows[0]['src_addresses'], ['198.51.100.1', '2001:db8::1'])
        self.assertTrue(any('nested IP endpoints' in warning for warning in warnings))

    def test_multiple_http_messages_in_one_frame_keep_all_values(self):
        body = (b'GET /first HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n'
                b'GET /second HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
        frame = ipv4('198.51.100.10', '198.51.100.20', 6,
                     tcp('198.51.100.10', '198.51.100.20', 41000, 80, 100, 0, 24, body))
        self.source.write_bytes(pcap([frame]))
        rows, warnings = self.inspect()
        self.assertEqual(rows[0]['http']['uri'], '/first')
        self.assertEqual(rows[0]['http_fields']['uri'], ['/first', '/second'])
        self.assertTrue(any('multiple HTTP field occurrences' in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
