import hashlib
import importlib.util
import marshal
import json
import subprocess
import sys
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from scripts.autosolve_lib.profiles.pyinstaller import inspect_pyinstaller, MAGIC
from scripts.autosolve_lib import setup as autosolve_setup


COOKIE = struct.Struct('!8sIIII64s')
ENTRY = struct.Struct('!IIIIBc')


def make_pyz(magic, modules):
    body = bytearray(b'PYZ\0' + magic + b'\0' * 4)
    toc = []
    for name, data in modules:
        position = len(body)
        payload = zlib.compress(data)
        body += payload
        toc.append((name, (0, position, len(payload))))
    struct.pack_into('!I', body, 8, len(body))
    body += marshal.dumps(toc)
    return bytes(body)


def make_bundle(members, *, pyvers=312, prefix=b'MZ fake bootloader\n'):
    body = bytearray()
    toc = bytearray()
    for name, data, typecode, compress in members:
        offset = len(body)
        encoded = zlib.compress(data) if compress else data
        body += encoded
        name = name.encode() + b'\0'
        entry_size = ENTRY.size + len(name)
        entry_size += -entry_size % 16
        toc += ENTRY.pack(entry_size, offset, len(encoded), len(data),
                          int(compress), typecode.encode())
        toc += name.ljust(entry_size - ENTRY.size, b'\0')
    toc_offset = len(body)
    body += toc
    body += COOKIE.pack(MAGIC, len(body) + COOKIE.size, toc_offset,
                        len(toc), pyvers, b'libpython3.12.so')
    return prefix + bytes(body)


class PyInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'renamed.bin'
        self.staging = self.root / 'stage'

    def inspect(self, max_members=16, max_total_bytes=4096):
        return inspect_pyinstaller(self.source, self.staging,
                                   max_members=max_members,
                                   max_total_bytes=max_total_bytes)

    def test_public_cli_extracts_and_resumes_with_lineage(self):
        payload = b'REV05{RESOURCE}'
        self.source.write_bytes(make_bundle([('assets/clue.txt', payload, 'x', True)],
                                            prefix=b'\x7fELF fake bootloader\n'))
        original = self.source.read_bytes()
        script = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'
        run_root = self.root / 'runs'
        command = [sys.executable, '-B', str(script), '--json', 'analyze', str(self.source),
                   '--category', 'malware_reversing', '--runs-root', str(run_root),
                   '--budget', '15']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV05']['status'], 'ran')
        children = [r for r in manifest['artifacts'] if r['depth'] > 0 and r['current']
                    and Path(r['path']).read_bytes() == payload]
        self.assertEqual(len(children), 1)
        job = next(j for j in manifest['jobs'] if j['adapter_id'] == 'pyinstaller')
        self.assertEqual(job['status'], 'complete')
        self.assertTrue(any(edge.get('job_key') == job['key']
                            for edge in children[0]['parents']))
        self.assertEqual(children[0]['source_locator']['offset'],
                         len(b'\x7fELF fake bootloader\n'))
        self.assertEqual(self.source.read_bytes(), original)
        resumed = subprocess.run([sys.executable, '-B', str(script), '--json', 'resume',
                                  str(run), '--budget', '15'],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(resumed.returncode, 3, resumed.stderr + resumed.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([j for j in after['jobs'] if j['adapter_id'] == 'pyinstaller']), 1)
        self.source.write_bytes(b'changed source')
        changed = subprocess.run([sys.executable, '-B', str(script), '--json', 'resume',
                                  str(run), '--budget', '5'],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(changed.returncode, 3, changed.stderr + changed.stdout)
        retired = json.loads((run / 'manifest.json').read_text())
        self.assertFalse(next(a for a in retired['artifacts']
                              if a['id'] == children[0]['id'])['current'])

    def test_doctor_reports_functional_but_partial_scope(self):
        result = autosolve_setup.doctor(['malware_reversing'], self_test=True)
        operation = result['operations']['malware_reversing.pyinstaller']
        self.assertEqual(operation['functional_probe'], 'passed')
        self.assertEqual(operation['status'], 'partial')
        self.assertTrue(result['engines']['pyinstaller']['found'])

    def test_auto_routes_elf_bundle_to_rev05(self):
        payload = b'\x00\x01\x02\x03REV05{AUTO}'
        self.source.write_bytes(make_bundle([('clue.txt', payload, 'x', False)],
                                            prefix=b'\x7fELF fake bootloader\n'))
        script = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'
        result = subprocess.run(
            [sys.executable, '-B', str(script), '--json', 'analyze', str(self.source),
             '--category', 'auto', '--runs-root', str(self.root / 'auto-runs'),
             '--budget', '15'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
        run = Path(json.loads(result.stdout)['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV05']['status'], 'ran')
        self.assertEqual(len([j for j in manifest['jobs']
                              if j['adapter_id'] == 'pyinstaller']), 1)
        self.assertTrue(any(a['current'] and a['depth'] > 0 and
                            Path(a['path']).read_bytes() == payload
                            for a in manifest['artifacts']))

    def test_carchive_resources_and_pyz_offsets_are_exact(self):
        code = marshal.dumps(compile('answer = 42', 'demo.py', 'exec'))
        pyz = make_pyz(importlib.util.MAGIC_NUMBER, [('demo', code)])
        bundle = make_bundle([('payload/data.txt', b'HELLO TEST', 'x', True),
                              ('PYZ-00.pyz', pyz, 'z', False)])
        self.source.write_bytes(bundle)
        records, warnings = self.inspect()
        self.assertEqual(warnings, [])
        self.assertEqual([r['kind'] for r in records], ['resource', 'pyz_bytecode'])
        self.assertEqual([r['path'].read_bytes() for r in records], [b'HELLO TEST', code])
        self.assertEqual([r['offset'] for r in records],
                         [len(b'MZ fake bootloader\n'),
                          len(b'MZ fake bootloader\n') + len(zlib.compress(b'HELLO TEST')) + 12])
        self.assertEqual(records[1]['python_version'], '3.12')
        self.assertEqual(records[1]['bytecode_magic'], importlib.util.MAGIC_NUMBER.hex())
        self.assertEqual(self.source.read_bytes(), bundle)
        self.assertEqual({r['path'] for r in records}, set(self.staging.iterdir()))
        self.assertEqual(records[0]['sha256'], hashlib.sha256(b'HELLO TEST').hexdigest())

    def test_foreign_bytecode_retains_raw_code_with_warning(self):
        raw = b'foreign marshal payload'
        pyz = make_pyz(b'\xff\xff\r\n', [('heldout', raw)])
        self.source.write_bytes(make_bundle([('resource.bin', b'EXACT', 'x', False),
                                             ('PYZ-00.pyz', pyz, 'z', False)], pyvers=310))
        records, warnings = self.inspect()
        self.assertEqual([r['path'].read_bytes() for r in records], [b'EXACT', raw])
        self.assertEqual(records[1]['python_version'], '3.10')
        self.assertIn('unsupported version', records[1]['bytecode_inspection'])
        self.assertTrue(any('unsupported' in warning and 'no decompilation' in warning
                            for warning in warnings))

    def test_encrypted_or_corrupt_pyz_member_is_reported(self):
        pyz = bytearray(make_pyz(importlib.util.MAGIC_NUMBER,
                                 [('secret', b'marshalled code')]))
        pyz[12:16] = b'NOPE'
        self.source.write_bytes(make_bundle([('PYZ-00.pyz', bytes(pyz), 'z', False)]))
        records, warnings = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('encrypted or corrupt' in warning for warning in warnings))

    def test_unsafe_link_and_oversize_are_skipped(self):
        self.source.write_bytes(make_bundle([('../escape', b'bad', 'x', False),
                                             ('link', b'elsewhere\0', 'n', False),
                                             ('huge', b'A' * 100, 'x', True),
                                             ('small', b'ok', 'x', False)]))
        records, warnings = self.inspect(max_total_bytes=8)
        self.assertEqual([(r['member'], r['path'].read_bytes()) for r in records],
                         [('small', b'ok')])
        self.assertTrue(any('unsafe path' in warning for warning in warnings))
        self.assertTrue(any('decoded byte limit' in warning for warning in warnings))
        self.assertFalse((self.root / 'escape').exists())

    def test_corrupt_archive_and_non_archive_do_not_stage(self):
        self.source.write_bytes(b'MZ ordinary')
        self.assertEqual(self.inspect(), ([], []))
        bundle = bytearray(make_bundle([('data', b'ok', 'x', False)]))
        cookie = len(bundle) - COOKIE.size
        struct.pack_into('!I', bundle, cookie + 8, 0xffffffff)
        self.source.write_bytes(bundle)
        records, warnings = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('corrupt' in warning for warning in warnings))
        self.assertFalse(self.staging.exists())

    def test_data_resources_precede_runtime_binaries_under_budget(self):
        self.source.write_bytes(make_bundle([('libpython.so', b'B' * 100, 'b', False),
                                             ('assets/clue.txt', b'CLUE', 'x', False)]))
        records, warnings = self.inspect(max_total_bytes=8)
        self.assertEqual([(r['member'], r['path'].read_bytes()) for r in records],
                         [('assets/clue.txt', b'CLUE')])
        self.assertTrue(any('decoded byte limit' in warning for warning in warnings))

    def test_budget_and_symlink_source(self):
        self.source.write_bytes(make_bundle([('one', b'1', 'x', False),
                                             ('two', b'2', 'x', False)]))
        records, warnings = self.inspect(max_members=1)
        self.assertEqual([r['member'] for r in records], ['one'])
        self.assertTrue(any('member limit' in warning for warning in warnings))
        link = self.root / 'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            inspect_pyinstaller(link, self.staging, max_members=1, max_total_bytes=8)
