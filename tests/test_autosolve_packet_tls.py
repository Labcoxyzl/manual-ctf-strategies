import gzip
import hashlib
import io
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.autosolve_lib.profiles import packet_tls
from scripts.autosolve_lib import setup as autosolve_setup
from test_autosolve_packet_objects import frame, pcap, transaction


def tls_capture(root, version, body, *, resumed=False, encoding=None):
    """Generate a local TLS exchange and its genuine SSLKEYLOGFILE independently."""
    cert, key, log = root / 'cert.pem', root / 'key.pem', root / 'secrets.log'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=example.invalid',
                    '-days', '1'], check=True, capture_output=True)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.minimum_version = client_context.maximum_version = version
    client_context.keylog_filename = str(log)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = server_context.maximum_version = version
    server_context.load_cert_chain(cert, key)
    client, server = '198.51.100.10', '198.51.100.20'
    rows, session = [], None
    for connection in range(2 if resumed else 1):
        incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        peers = [client_context.wrap_bio(incoming[0], outgoing[0], server_side=False,
                                         server_hostname='example.invalid', session=session),
                 server_context.wrap_bio(incoming[1], outgoing[1], server_side=True)]
        client_port = 41000 + connection
        rows.extend([frame(client, server, client_port, 443, 1000, 0, 2),
                     frame(server, client, 443, client_port, 2000, 1001, 18),
                     frame(client, server, client_port, 443, 1001, 2001, 16)])
        sequences = [1001, 2001]

        def drain(who):
            while data := outgoing[who].read():
                incoming[1 - who].write(data)
                src, dst, sport, dport = ((client, server, client_port, 443) if who == 0 else
                                          (server, client, 443, client_port))
                rows.append(frame(src, dst, sport, dport, sequences[who], sequences[1 - who],
                                  24, data))
                sequences[who] += len(data)

        done = [False, False]
        for _ in range(30):
            for who, peer in enumerate(peers):
                if not done[who]:
                    try:
                        peer.do_handshake()
                        done[who] = True
                    except ssl.SSLWantReadError:
                        pass
                drain(who)
            if all(done):
                break
        if not all(done):
            raise AssertionError('fixture TLS handshake stalled')
        if connection and not peers[0].session_reused:
            raise AssertionError('fixture TLS session was not resumed')
        request = b'GET /secret.bin HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
        peers[0].write(request)
        drain(0)
        assert peers[1].read(4096) == request
        response = (b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
                    + b'\r\n' + (b'Content-Encoding: ' + encoding.encode() + b'\r\n'
                                 if encoding else b'') + b'\r\n' + body)
        peers[1].write(response)
        drain(1)
        assert peers[0].read(65536) == response
        session = peers[0].session
    capture = root / 'wire.pcap'
    capture.write_bytes(pcap(rows))
    return capture, log


@unittest.skipUnless(shutil.which('openssl') and Path(packet_tls.TSHARK).is_file(),
                     'OpenSSL and TShark required for TLS integration fixture')
class PacketTlsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def decrypt(self, source, log, name='out', **limits):
        return packet_tls.decrypt_tls_http(source, log, self.root / name,
                                           timeout=5, **limits)

    def test_doctor_reports_keylog_requirement_and_option_support(self):
        operation = autosolve_setup.doctor(['packets'], self_test=True)['operations'][
            'packets.tls_keylog']
        self.assertTrue(operation['implemented'])
        self.assertTrue(operation['options_compatible'])
        self.assertIn('tls_keylog', operation['required_data'])
        self.assertEqual(operation['functional_probe'], 'not_run')

    def test_tls12_and_tls13_recover_exact_body_and_frame_stream(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(version=version):
                folder = self.root / version.name
                folder.mkdir()
                body = b'NET05-EXACT-SECRET\x00\xff' + version.name.encode()
                capture, log = tls_capture(folder, version, body)
                source_hash = hashlib.sha256(capture.read_bytes()).hexdigest()
                rows, warnings = self.decrypt(capture, log, f'out-{version.name}')
                self.assertEqual(len(rows), 1, warnings)
                row = rows[0]
                self.assertEqual(row['path'].read_bytes(), body)
                self.assertEqual(row['sha256'], hashlib.sha256(body).hexdigest())
                self.assertEqual(row['tcp_stream'], 0)
                self.assertGreater(row['packet'], 3)
                self.assertEqual(row['source_locator']['uri'],
                                 'https://example.invalid/secret.bin')
                self.assertTrue(row['length_verified'])
                self.assertEqual(row['decrypted_fields']['http.response.code'], '200')
                self.assertEqual(hashlib.sha256(capture.read_bytes()).hexdigest(), source_hash)
                self.assertEqual((self.root / f'out-{version.name}').stat().st_mode & 0o777,
                                 0o700)

    def test_wrong_missing_and_private_key_are_distinct_and_never_publish(self):
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_3, b'NEVER-CIPHERTEXT')
        rows, warnings = self.decrypt(capture, None, 'missing')
        self.assertEqual(rows, [])
        self.assertTrue(any('missing' in note for note in warnings))
        wrong = self.root / 'wrong.log'
        wrong.write_text('\n'.join(line[:-64] + '0' * 64 if line and not line.startswith('#')
                                   else line for line in log.read_text().splitlines()) + '\n')
        rows, warnings = self.decrypt(capture, wrong, 'wrong')
        self.assertEqual(rows, [])
        self.assertTrue(any('no matching' in note for note in warnings), warnings)
        rows, warnings = self.decrypt(capture, self.root / 'key.pem', 'private-key')
        self.assertEqual(rows, [])
        self.assertTrue(any('forward-secret' in note for note in warnings))

    def test_tls12_resumed_session_remains_a_separate_stream(self):
        body = b'RESUMED-SESSION-BODY\x00\xfd'
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_2, body, resumed=True)
        rows, warnings = self.decrypt(capture, log)
        self.assertEqual(len(rows), 2, warnings)
        self.assertEqual({row['tcp_stream'] for row in rows}, {0, 1})
        self.assertEqual([row['path'].read_bytes() for row in rows], [body, body])
        self.assertEqual(len({row['packet'] for row in rows}), 2)

    def test_plain_http_in_same_capture_is_not_labeled_decrypted(self):
        body = b'ACTUAL-TLS-BODY'
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_3, body)
        capture.write_bytes(capture.read_bytes() + pcap(transaction(42000, b'PLAIN-HTTP'))[24:])
        rows, warnings = self.decrypt(capture, log)
        self.assertEqual(len(rows), 1, warnings)
        self.assertEqual(rows[0]['path'].read_bytes(), body)
        self.assertEqual({item.name for item in (self.root / 'out').iterdir()},
                         {rows[0]['name']})

    def test_content_encoded_body_remains_the_exact_sent_bytes(self):
        body = gzip.compress(b'ENCODED-BODY-ORACLE', mtime=0)
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_3, body,
                                   encoding='gzip')
        rows, warnings = self.decrypt(capture, log)
        self.assertEqual(len(rows), 1, warnings)
        self.assertEqual(rows[0]['path'].read_bytes(), body)
        self.assertTrue(rows[0]['length_verified'])

    def test_public_cli_private_hint_recursion_and_changed_keylog_resume(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as writer:
            writer.writestr('inside.txt', b'TLS-RECURSION-ORACLE')
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_3, archive.getvalue())
        (self.root / 'cert.pem').unlink()
        (self.root / 'key.pem').unlink()
        hints = self.root / 'hints.json'
        hints.write_text(json.dumps({'tls_keylog': log.name}))
        original_log = log.read_text()
        command = [sys.executable, '-B', str(Path(__file__).resolve().parents[1] /
                                              'scripts/autosolve.py'), '--json']

        def invoke(*args):
            process = subprocess.run([*command, *map(str, args)], capture_output=True,
                                     text=True, timeout=30)
            self.assertEqual(process.returncode, 3, process.stderr + process.stdout)
            return json.loads(process.stdout)

        run = Path(invoke('analyze', self.root, '--category', 'packets',
                          '--budget', '12', '--hints', hints,
                          '--runs-root', self.root / 'runs')['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['NET05']['status'], 'ran')
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'packet-tls']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(jobs[0]['child_ids']), 1)
        child = next(item for item in manifest['artifacts']
                     if item['id'] == jobs[0]['child_ids'][0])
        self.assertEqual(Path(child['path']).read_bytes(), archive.getvalue())
        self.assertEqual(child['source_locator']['protocol'], 'https')
        self.assertEqual(child['source_locator']['tcp_stream'], 0)
        self.assertTrue(any(item['depth'] == 2 and
                            Path(item['path']).read_bytes() == b'TLS-RECURSION-ORACLE'
                            for item in manifest['artifacts']))
        roots = {item['path'] for item in manifest['artifacts'] if item['depth'] == 0}
        self.assertEqual(roots, {str(capture)})
        self.assertNotIn(original_log.splitlines()[-1], (run / 'report.md').read_text())

        log.write_text('\n'.join(line[:-64] + '0' * 64 if line and not line.startswith('#')
                                   else line for line in original_log.splitlines()) + '\n')
        invoke('resume', run, '--budget', '12', '--hints', hints)
        changed = json.loads((run / 'manifest.json').read_text())
        old = next(item for item in changed['artifacts'] if item['id'] == child['id'])
        self.assertFalse(old['current'])
        self.assertEqual(changed['coverage']['NET05']['status'], 'no finding')
        self.assertEqual(len([job for job in changed['jobs'] if job['adapter_id'] == 'packet-tls']), 2)

        log.write_text(original_log)
        invoke('resume', run, '--budget', '12', '--hints', hints)
        restored = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(next(item for item in restored['artifacts']
                             if item['id'] == child['id'])['current'])
        self.assertEqual(len([job for job in restored['jobs'] if job['adapter_id'] == 'packet-tls']), 2)

        linked = self.root / 'linked.log'
        linked.symlink_to(log)
        hints.write_text(json.dumps({'tls_keylog': linked.name}))
        invoke('resume', run, '--budget', '12', '--hints', hints)
        rejected = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(rejected['coverage']['NET05']['status'], 'skipped prerequisite')
        self.assertFalse(next(item for item in rejected['artifacts']
                              if item['id'] == child['id'])['current'])
        hints.write_text('{}')
        invoke('resume', run, '--budget', '12', '--hints', hints)
        no_hint = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(no_hint['coverage']['NET05']['status'], 'skipped prerequisite')
        self.assertEqual(len([job for job in no_hint['jobs'] if job['adapter_id'] == 'packet-tls']), 2)
        self.assertEqual({item['path'] for item in no_hint['artifacts'] if item['depth'] == 0},
                         {str(capture)})

    def test_one_matching_capture_keeps_family_coverage_when_another_has_no_tls(self):
        folder = self.root / 'bundle'
        folder.mkdir()
        _, log = tls_capture(folder, ssl.TLSVersion.TLSv1_2, b'MATCHED-BODY')
        (folder / 'cert.pem').unlink()
        (folder / 'key.pem').unlink()
        (folder / 'z-plain.pcap').write_bytes(pcap(transaction(42000, b'PLAIN')))
        hints = folder / 'hints.json'
        hints.write_text(json.dumps({'tls_keylog': log.name}))
        result = subprocess.run([sys.executable, '-B',
                                 str(Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'),
                                 '--json', 'analyze', str(folder), '--category', 'packets',
                                 '--budget', '15', '--hints', str(hints),
                                 '--runs-root', str(self.root / 'runs')],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        manifest = json.loads((Path(json.loads(result.stdout)['run']) / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['NET05']['status'], 'ran')
        self.assertEqual(len([job for job in manifest['jobs'] if job['adapter_id'] == 'packet-tls']), 2)

    def test_limits_and_output_safety(self):
        capture, log = tls_capture(self.root, ssl.TLSVersion.TLSv1_2, b'1234567890')
        for index, limits in enumerate(({'max_source_bytes': 10},
                                        {'max_keylog_bytes': 10},
                                        {'max_total_bytes': 5},
                                        {'max_output': 10})):
            rows, warnings = self.decrypt(capture, log, f'limit-{index}', **limits)
            self.assertEqual(rows, [])
            self.assertTrue(any('limit' in note for note in warnings), warnings)
        linked = self.root / 'linked'
        linked.symlink_to(self.root)
        with self.assertRaises(ValueError):
            self.decrypt(capture, log, 'linked')
        existing = self.root / 'existing'
        existing.mkdir()
        (existing / 'keep').write_text('untouched')
        with self.assertRaises(ValueError):
            self.decrypt(capture, log, 'existing')
        self.assertEqual((existing / 'keep').read_text(), 'untouched')

    def test_malformed_metadata_preserves_existing_empty_output_directory(self):
        capture, log = self.root / 'capture.pcap', self.root / 'secrets.log'
        capture.write_bytes(b'capture')
        log.write_bytes(b'secrets')
        output = self.root / 'existing-empty'
        output.mkdir()
        valid = {'layers': {'frame_protocols': ['eth:ip:tcp:tls:http'],
                            'http_file_data': ['41'], 'frame_number': ['1'],
                            'http_response_code': ['200'], 'frame_cap_len': ['1'],
                            'frame_len': ['1']}}
        raw = json.dumps(valid) + '\n{"layers": []}\n'
        with patch.object(packet_tls, '_run', return_value=(raw, None)):
            rows, warnings = self.decrypt(capture, log, output.name)
        self.assertEqual(rows, [])
        self.assertTrue(any('invalid TShark TLS output' in note for note in warnings), warnings)
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
