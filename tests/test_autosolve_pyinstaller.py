import hashlib
import importlib.util
import marshal
import json
import subprocess
import sys
import struct
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

from scripts.autosolve_lib.profiles.pyinstaller import inspect_pyinstaller, MAGIC
from scripts.autosolve_lib import setup as autosolve_setup
from scripts.autosolve_lib import core


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


def make_encrypted_pyz(modules, key, *, ivs=None):
    body = bytearray(b'PYZ\0\x6f\x0d\x0d\x0a' + b'\0' * 4)
    toc = []
    for index, (name, data) in enumerate(modules):
        iv = ivs[index] if ivs and index in ivs else bytes([index + 1]) * 16
        payload = iv + AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv).encrypt(
            zlib.compress(data))
        position = len(body)
        body += payload
        toc.append((name, (0, position, len(payload))))
    struct.pack_into('!I', body, 8, len(body))
    body += marshal.dumps(toc)
    return bytes(body)


def make_key_module(key, *, interned=False):
    tag = b'\xda\x10' if interned else b'z\x10'
    return (b'\xe3' + b'\0' * 24 + b'\x64\x00\x5a\x00\x64\x01\x53\x00\x29\x02' + tag
            + key + b'N\x29\x01\xda\x03key')


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

    def test_inventory_continues_after_staging_cap(self):
        pyz = make_pyz(importlib.util.MAGIC_NUMBER,
                       [(f'module_{index}', b'code') for index in range(4)])
        self.source.write_bytes(make_bundle([
            ('first', b'one', 'x', False), ('PYZ.pyz', pyz, 'z', False),
            ('last', b'three', 'x', False)]))
        records, warnings, inventory = self.inspect(max_members=1)
        self.assertEqual([record['member'] for record in records], ['first'])
        self.assertTrue(any('member limit reached' in warning for warning in warnings))
        self.assertTrue(inventory['carchive']['complete'])
        self.assertEqual([item['name'] for item in inventory['carchive']['entries']],
                         ['first', 'PYZ.pyz', 'last'])
        self.assertEqual(inventory['pyz'][0]['entry_count'], 4)
        self.assertTrue(inventory['pyz'][0]['complete'])
        self.assertEqual([item['name'] for item in inventory['pyz'][0]['entries']],
                         [f'module_{index}' for index in range(4)])
        self.assertEqual(len(list(self.staging.iterdir())), 1)

    def test_corrupt_toc_inventory_is_incomplete(self):
        bundle = bytearray(make_bundle([('one', b'1', 'x', False)]))
        toc_start = len(bundle) - COOKIE.size - 32
        struct.pack_into('!I', bundle, toc_start, 0xffffffff)
        self.source.write_bytes(bundle)
        records, warnings, inventory = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('corrupt PyInstaller table' in warning for warning in warnings))
        self.assertFalse(inventory['carchive']['complete'])
        self.assertEqual(inventory['carchive']['entries'], [])

    def test_undecodable_toc_entry_preserves_later_original_index(self):
        bundle = bytearray(make_bundle([('broken', b'bad', 'x', False),
                                        ('valid', b'good', 'x', False)]))
        _, archive_length, toc_offset, _, _, _ = COOKIE.unpack_from(bundle,
                                                                     len(bundle) - COOKIE.size)
        archive_start = len(bundle) - archive_length
        bundle[archive_start + toc_offset + ENTRY.size] = 0xff
        self.source.write_bytes(bundle)
        records, warnings, inventory = self.inspect()
        self.assertEqual([(record['index'], record['member'], record['path'].read_bytes())
                          for record in records], [(1, 'valid', b'good')])
        self.assertIn('CArchive entry 0: invalid name or type', warnings)
        self.assertFalse(inventory['carchive']['complete'])
        self.assertEqual(inventory['carchive']['entry_count'], 2)
        self.assertEqual([(entry['index'], entry['name'])
                          for entry in inventory['carchive']['entries']], [(1, 'valid')])

    def test_trailing_pyz_table_bytes_do_not_claim_complete_metadata(self):
        pyz = make_pyz(importlib.util.MAGIC_NUMBER, [('module', b'code')]) + b'TRAIL'
        self.source.write_bytes(make_bundle([('clue.txt', b'CLUE', 'x', False),
                                             ('PYZ.pyz', pyz, 'z', False)]))
        records, warnings, inventory = self.inspect()
        self.assertEqual([(record['member'], record['path'].read_bytes())
                          for record in records], [('clue.txt', b'CLUE')])
        self.assertTrue(any('unsupported or corrupt PYZ table' in warning
                            for warning in warnings))
        self.assertTrue(inventory['carchive']['complete'])
        self.assertFalse(inventory['pyz'][0]['complete'])
        self.assertEqual(inventory['pyz'][0]['entries'], [])

    def test_metadata_entry_cap_is_reported_separately(self):
        pyz = make_pyz(importlib.util.MAGIC_NUMBER,
                       [(f'm{index}', b'x') for index in range(4096)])
        self.source.write_bytes(make_bundle([('clue', b'ok', 'x', False),
                                             ('PYZ.pyz', pyz, 'z', False)]))
        records, warnings, inventory = self.inspect(max_members=0)
        self.assertEqual(records, [])
        self.assertTrue(inventory['carchive']['complete'])
        self.assertEqual(inventory['pyz'][0]['entry_count'], 4096)
        self.assertEqual(len(inventory['pyz'][0]['entries']), 4094)
        self.assertFalse(inventory['pyz'][0]['complete'])
        self.assertTrue(any('PYZ metadata entry limit reached' in warning
                            for warning in warnings))

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
        self.assertTrue(job['inventory']['carchive']['complete'])
        self.assertEqual([(item['index'], item['name']) for item in
                          job['inventory']['carchive']['entries']],
                         [(0, 'assets/clue.txt')])
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
        self.assertEqual(next(j for j in after['jobs'] if j['adapter_id'] == 'pyinstaller')['inventory'],
                         job['inventory'])
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
        records, warnings, _ = self.inspect()
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
        records, warnings, _ = self.inspect()
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
        records, warnings, _ = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('encrypted or corrupt' in warning for warning in warnings))

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_encrypted_pyz_requires_two_distinct_validated_members(self):
        key = b'fresh-16-key-abc'
        modules = [('first', b'FIRST MARSHAL'), ('second', b'SECOND MARSHAL')]
        pyz = make_encrypted_pyz(modules, key)
        self.source.write_bytes(make_bundle([
            ('pyimod00_crypto_key', make_key_module(key, interned=True), 'm', True),
            ('PYZ-00.pyz', pyz, 'z', False)], pyvers=310))
        records, warnings, inventory = self.inspect()
        self.assertTrue(all('unsupported by Python' in warning for warning in warnings))
        self.assertEqual([r['path'].read_bytes() for r in records],
                         [b'FIRST MARSHAL', b'SECOND MARSHAL'])
        self.assertEqual([r['kind'] for r in records], ['pyz_bytecode'] * 2)
        self.assertTrue(all('AES-CTR' in r['bytecode_inspection'] for r in records))
        self.assertTrue(inventory['pyz'][0]['complete'])
        self.assertFalse(any(key in r['path'].read_bytes() for r in records))

        self.staging = self.root / 'one-stage'
        one_pyz = make_encrypted_pyz(modules[:1], key)
        self.source.write_bytes(make_bundle([
            ('pyimod00_crypto_key', make_key_module(key), 'm', True),
            ('PYZ-00.pyz', one_pyz, 'z', False)], pyvers=310))
        records, warnings, _ = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('two distinct' in w for w in warnings))

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_wrong_ambiguous_and_corrupt_encrypted_key_withhold_output(self):
        key = b'fresh-16-key-abc'
        pyz = make_encrypted_pyz([('first', b'FIRST'), ('second', b'SECOND')], key)
        cases = [
            [('pyimod00_crypto_key', make_key_module(b'wrong-16-key-xyz'), 'm', True),
             ('PYZ-00.pyz', pyz, 'z', False)],
            [('pyimod00_crypto_key', make_key_module(key), 'm', True),
             ('pyimod00_crypto_key', make_key_module(key), 'm', True),
             ('PYZ-00.pyz', pyz, 'z', False)],
            [('pyimod00_crypto_key', make_key_module(key)[:-5], 'm', True),
             ('PYZ-00.pyz', pyz, 'z', False)],
        ]
        for index, members in enumerate(cases):
            with self.subTest(index=index):
                self.staging = self.root / f'bad-stage-{index}'
                self.source.write_bytes(make_bundle(members, pyvers=310))
                records, warnings, _ = self.inspect()
                self.assertEqual(records, [])
                self.assertTrue(any('encrypted or corrupt' in w for w in warnings))

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_zlib_looking_iv_does_not_block_valid_encrypted_member(self):
        key = b'fresh-16-key-abc'
        modules = [('first', b'first'), ('second', b'second'), ('third', b'good')]
        iv = zlib.compress(b'X' * 1000)[:16]
        pyz = make_encrypted_pyz(modules, key, ivs={2: iv})
        self.source.write_bytes(make_bundle([
            ('pyimod00_crypto_key', make_key_module(key), 'm', True),
            ('PYZ-00.pyz', pyz, 'z', False)], pyvers=310))
        records, warnings, _ = self.inspect(max_total_bytes=64)
        self.assertEqual([r['path'].read_bytes() for r in records],
                         [b'first', b'second', b'good'])
        self.assertFalse(any('decoded byte limit' in warning for warning in warnings))

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_pyz_alias_cannot_validate_one_ciphertext_twice(self):
        key = b'fresh-16-key-abc'
        pyz = bytearray(make_encrypted_pyz([('first', b'FIRST')], key))
        toc_offset = struct.unpack('!I', pyz[8:12])[0]
        table = marshal.loads(pyz[toc_offset:])
        table.append(('alias', table[0][1]))
        del pyz[toc_offset:]
        pyz += marshal.dumps(table)
        self.source.write_bytes(make_bundle([
            ('pyimod00_crypto_key', make_key_module(key), 'm', True),
            ('PYZ-00.pyz', bytes(pyz), 'z', False)], pyvers=310))
        records, warnings, _ = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('two distinct' in warning for warning in warnings))

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_distinct_encrypted_spans_can_share_iv(self):
        key = b'fresh-16-key-abc'
        iv = b'0123456789abcdef'
        pyz = make_encrypted_pyz([('first', b'FIRST'), ('second', b'SECOND')], key,
                                 ivs={0: iv, 1: iv})
        self.source.write_bytes(make_bundle([
            ('pyimod00_crypto_key', make_key_module(key), 'm', True),
            ('PYZ-00.pyz', pyz, 'z', False)], pyvers=310))
        records, _, _ = self.inspect()
        self.assertEqual([record['path'].read_bytes() for record in records],
                         [b'FIRST', b'SECOND'])

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_pyinstaller_fingerprint_changes_with_aes_availability(self):
        ready = core._pyinstaller_fingerprint(time.monotonic() + 10)
        original_import = core.importlib.import_module

        def unavailable(name, *args, **kwargs):
            if name == 'Crypto.Cipher.AES':
                raise ModuleNotFoundError(name)
            return original_import(name, *args, **kwargs)

        with mock.patch.object(core.importlib, 'import_module', side_effect=unavailable):
            missing = core._pyinstaller_fingerprint(time.monotonic() + 10)
        self.assertNotEqual(ready, missing)

    @unittest.skipUnless(AES is not None, 'pycryptodome unavailable')
    def test_resume_invalidates_encrypted_children_when_aes_disappears(self):
        key = b'fresh-16-key-abc'
        pyz = make_encrypted_pyz([('first', b'FIRST'), ('second', b'SECOND')], key)
        self.source.write_bytes(make_bundle([
            ('data.bin', b'RESOURCE', 'x', False),
            ('pyimod00_crypto_key', make_key_module(key), 'm', True),
            ('PYZ-00.pyz', pyz, 'z', False)], pyvers=310))
        script = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'
        analyzed = subprocess.run(
            [sys.executable, '-B', str(script), '--json', 'analyze', str(self.source),
             '--category', 'reversing', '--budget', '20', '--runs-root', str(self.root / 'runs')],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(analyzed.returncode, 3, analyzed.stderr + analyzed.stdout)
        run = Path(json.loads(analyzed.stdout)['run'])
        before = json.loads((run / 'manifest.json').read_text())
        self.assertEqual({a['source_locator'].get('member') for a in before['artifacts']
                          if a['depth'] > 0 and a['current'] and
                          a['source_locator'].get('pyinstaller_kind') == 'pyz_bytecode'},
                         {'first', 'second'})
        missing = subprocess.run([sys.executable, '-S', '-B', str(script), '--json',
                                  'resume', str(run), '--budget', '20'],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(missing.returncode, 3, missing.stderr + missing.stdout)
        after = json.loads((run / 'manifest.json').read_text())
        self.assertNotEqual(before['current_adapter_fingerprints']['pyinstaller'],
                            after['current_adapter_fingerprints']['pyinstaller'])
        self.assertFalse(any(a['depth'] > 0 and a['current'] and
                             a['source_locator'].get('pyinstaller_kind') == 'pyz_bytecode'
                             for a in after['artifacts']))
        self.assertTrue(any('AES-CTR support unavailable' in warning
                            for job in after['jobs'] if job['adapter_id'] == 'pyinstaller'
                            for warning in job.get('warnings', [])))
        restored = subprocess.run([sys.executable, '-B', str(script), '--json',
                                   'resume', str(run), '--budget', '20'],
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(restored.returncode, 3, restored.stderr + restored.stdout)
        final = json.loads((run / 'manifest.json').read_text())
        self.assertEqual({a['source_locator'].get('member') for a in final['artifacts']
                          if a['depth'] > 0 and a['current'] and
                          a['source_locator'].get('pyinstaller_kind') == 'pyz_bytecode'},
                         {'first', 'second'})
        missing_first = subprocess.run(
            [sys.executable, '-S', '-B', str(script), '--json', 'analyze', str(self.source),
             '--category', 'reversing', '--budget', '20', '--runs-root',
             str(self.root / 'missing-runs')], capture_output=True, text=True, timeout=30)
        self.assertEqual(missing_first.returncode, 3,
                         missing_first.stderr + missing_first.stdout)
        missing_run = Path(json.loads(missing_first.stdout)['run'])
        missing_manifest = json.loads((missing_run / 'manifest.json').read_text())
        self.assertFalse(any(a['depth'] > 0 and a['current'] and
                             a['source_locator'].get('pyinstaller_kind') == 'pyz_bytecode'
                             for a in missing_manifest['artifacts']))
        installed = subprocess.run([sys.executable, '-B', str(script), '--json',
                                    'resume', str(missing_run), '--budget', '20'],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(installed.returncode, 3, installed.stderr + installed.stdout)
        installed_manifest = json.loads((missing_run / 'manifest.json').read_text())
        self.assertNotEqual(missing_manifest['current_adapter_fingerprints']['pyinstaller'],
                            installed_manifest['current_adapter_fingerprints']['pyinstaller'])
        self.assertEqual({a['source_locator'].get('member') for a in installed_manifest['artifacts']
                          if a['depth'] > 0 and a['current'] and
                          a['source_locator'].get('pyinstaller_kind') == 'pyz_bytecode'},
                         {'first', 'second'})

    def test_unsafe_link_and_oversize_are_skipped(self):
        self.source.write_bytes(make_bundle([('../escape', b'bad', 'x', False),
                                             ('link', b'elsewhere\0', 'n', False),
                                             ('huge', b'A' * 100, 'x', True),
                                             ('small', b'ok', 'x', False)]))
        records, warnings, _ = self.inspect(max_total_bytes=8)
        self.assertEqual([(r['member'], r['path'].read_bytes()) for r in records],
                         [('small', b'ok')])
        self.assertTrue(any('unsafe path' in warning for warning in warnings))
        self.assertTrue(any('decoded byte limit' in warning for warning in warnings))
        self.assertFalse((self.root / 'escape').exists())

    def test_corrupt_archive_and_non_archive_do_not_stage(self):
        self.source.write_bytes(b'MZ ordinary')
        records, warnings, inventory = self.inspect()
        self.assertEqual((records, warnings), ([], []))
        self.assertFalse(inventory['carchive']['complete'])
        bundle = bytearray(make_bundle([('data', b'ok', 'x', False)]))
        cookie = len(bundle) - COOKIE.size
        struct.pack_into('!I', bundle, cookie + 8, 0xffffffff)
        self.source.write_bytes(bundle)
        records, warnings, _ = self.inspect()
        self.assertEqual(records, [])
        self.assertTrue(any('corrupt' in warning for warning in warnings))
        self.assertFalse(self.staging.exists())

    def test_data_resources_precede_runtime_binaries_under_budget(self):
        self.source.write_bytes(make_bundle([('libpython.so', b'B' * 100, 'b', False),
                                             ('assets/clue.txt', b'CLUE', 'x', False)]))
        records, warnings, _ = self.inspect(max_total_bytes=8)
        self.assertEqual([(r['member'], r['path'].read_bytes()) for r in records],
                         [('assets/clue.txt', b'CLUE')])
        self.assertTrue(any('decoded byte limit' in warning for warning in warnings))

    def test_budget_and_symlink_source(self):
        self.source.write_bytes(make_bundle([('one', b'1', 'x', False),
                                             ('two', b'2', 'x', False)]))
        records, warnings, _ = self.inspect(max_members=1)
        self.assertEqual([r['member'] for r in records], ['one'])
        self.assertTrue(any('member limit' in warning for warning in warnings))
        link = self.root / 'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            inspect_pyinstaller(link, self.staging, max_members=1, max_total_bytes=8)
